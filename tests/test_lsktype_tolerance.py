"""Read-side tolerance for the newer tdata map keys (lskType 0x17-0x1E).

Newer Telegram Desktop (5.x-6.x, upstream issue #120) writes map entries
our parser used to reject or truncate:

* 0x17 lskCustomEmojiKeys, 0x18 lskSearchSuggestions — already known;
* 0x19 lskWebviewTokens — our old branch treated it as an END marker
  (``is_finished = True``), silently discarding every map entry after
  the tokens; the real payload is two QByteArrays (bots, other);
* 0x1A lskRoundPlaceholder, 0x1B lskInlineBotsDownloads,
  0x1C lskMediaLastPlaybackPositions — plain uint64 keys;
* 0x1D lskBotStorages — a PeerId -> FileKey map (uint32 count + pairs),
  with a parser-DoS cap like the mtp-authorization key-count check;
* 0x1E lskPrefs — plain uint64 key.

Ported from opentele-ng's fixtures (tests/test_account_new_lskTypes_read.py,
tests/test_configs_lskType.py), adapted to unittest + this fork: their
stream-level primitive checks and source-structure assertions are kept,
plus full save -> load round-trips through the REAL encrypted map reader
(MapData.read over an actual tdata folder on disk).

Security invariants asserted alongside (CHANGELOG [Unreleased] Security):
the per-instance random ``_settingsKey`` survives and the bot-storage
count cap rejects implausible counts.
"""
import inspect
import logging
import os
import tempfile
import unittest

from tgmint.td import TDesktop
from tgmint.td.account import Account, MapData
from tgmint.td.auth import AuthKey, AuthKeyType
from tgmint.td.configs import (
    QByteArray,
    QDataStream,
    QIODevice,
    lskType,
)
from tgmint.td.shared import Storage
from tgmint.td.configs import DcId, PeerId, FileKey
from tgmint.api import API
from tgmint.exception import OpenTeleException, TDataBadConfigData

USER_ID = 12345
DC_ID = 2


def _build_tdesktop():
    td = TDesktop()
    acct = Account(owner=td, api=API.TelegramDesktop)
    acct._setMtpAuthorizationCustom(
        DcId(DC_ID),
        USER_ID,
        [AuthKey(os.urandom(256), AuthKeyType.ReadFromFile, DcId(DC_ID))],
    )
    td._addSingleAccount(acct)
    return td


def _map_dir(base_path):
    # where the per-account map file lives for the default "data" key file
    data_name_key = Storage.ComputeDataNameKey("data")
    return os.path.join(base_path, Storage.ToFilePart(data_name_key))


def _rewrite_map(base_path, local_key, map_data):
    """Write a map file exactly like StorageAccount.writeMap, but with the
    caller's MapData (so tests can inject arbitrary key combinations)."""
    map_dir = _map_dir(base_path)
    writer = Storage.FileWriteDescriptor("map", map_dir)
    # tdesktop writes two empty (null) QByteArrays before the encrypted map
    writer.writeData(QByteArray())
    writer.writeData(QByteArray())
    writer.writeEncrypted(map_data.prepareToWrite(), local_key)
    writer.finish()


def _write_raw_map(base_path, local_key, payload):
    """Write a map whose decrypted content is the exact raw ``payload``
    bytes — for feeding the reader hand-crafted/garbage wire data."""
    map_dir = _map_dir(base_path)
    enc = Storage.EncryptedDescriptor(payload.size())
    enc.stream.writeRawData(payload)
    writer = Storage.FileWriteDescriptor("map", map_dir)
    writer.writeData(QByteArray())
    writer.writeData(QByteArray())
    writer.writeEncrypted(enc, local_key)
    writer.finish()


class TestLskTypeConstants(unittest.TestCase):
    """Ported from opentele-ng tests/test_configs_lskType.py."""

    def test_new_constants(self):
        self.assertEqual(lskType.lskRoundPlaceholder, 0x1A)
        self.assertEqual(lskType.lskInlineBotsDownloads, 0x1B)
        self.assertEqual(lskType.lskMediaLastPlaybackPositions, 0x1C)
        self.assertEqual(lskType.lskBotStorages, 0x1D)
        self.assertEqual(lskType.lskPrefs, 0x1E)

    def test_existing_constants_did_not_shift(self):
        self.assertEqual(lskType.lskCustomEmojiKeys, 0x17)
        self.assertEqual(lskType.lskSearchSuggestions, 0x18)
        self.assertEqual(lskType.lskWebviewTokens, 0x19)

    def test_new_constants_are_ints(self):
        for name in (
            "lskRoundPlaceholder",
            "lskInlineBotsDownloads",
            "lskMediaLastPlaybackPositions",
            "lskBotStorages",
            "lskPrefs",
        ):
            self.assertIsInstance(getattr(lskType, name), int)


class TestStreamLevelPrimitives(unittest.TestCase):
    """Ported from opentele-ng tests/test_account_new_lskTypes_read.py
    (stream-level sanity for the uint32-key + uint64-value shape)."""

    def test_uint32_key_plus_uint64_value_roundtrip(self):
        expected = 0xCAFEBABEDEADBEEF
        data = QByteArray()
        stream = QDataStream(data, QIODevice.OpenModeFlag.WriteOnly)
        stream.setVersion(QDataStream.Version.Qt_5_1)
        stream.writeUInt32(lskType.lskRoundPlaceholder)
        stream.writeUInt64(expected)

        reader = QDataStream(data)
        reader.setVersion(QDataStream.Version.Qt_5_1)
        self.assertEqual(reader.readUInt32(), lskType.lskRoundPlaceholder)
        self.assertEqual(reader.readUInt64(), expected)

    def test_account_module_has_read_branch_for_new_lsktypes(self):
        from tgmint.td import account as account_module

        src = inspect.getsource(account_module)
        for name in (
            "lskRoundPlaceholder",
            "lskInlineBotsDownloads",
            "lskMediaLastPlaybackPositions",
            "lskBotStorages",
            "lskPrefs",
        ):
            self.assertIn(
                f"lskType.{name}",
                src,
                f"account.py has no read branch for {name}",
            )

    def test_lskwebviewtokens_branch_does_not_stop_the_loop(self):
        # the old branch set is_finished = True, truncating the map read
        from tgmint.td import account as account_module

        src = inspect.getsource(account_module)
        idx = src.find("elif keyType == lskType.lskWebviewTokens")  # the read branch (comments mention the name earlier)
        self.assertGreaterEqual(idx, 0)
        snippet = src[idx : idx + 800]  # window covers comment + both read statements
        self.assertNotIn("is_finished = True", snippet)
        self.assertIn(">> webviewStorageToken", snippet)


class TestFullMapRoundtrip(unittest.TestCase):
    """New keys survive a real encrypted save -> load through MapData.read."""

    def _load_mapdata(self, tmp):
        loaded = TDesktop(tmp)
        self.assertTrue(loaded.isLoaded())
        return loaded.mainAccount.MapData

    def test_new_uint64_keys_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp)

            md = MapData(_map_dir(tmp))
            md._settingsKey = FileKey(0x111)
            md._searchSuggestionsKey = FileKey(0x222)
            md._roundPlaceholder = FileKey(0xAAAA111)
            md._inlineBotsDownloads = FileKey(0xBBBB222)
            md._mediaLastPlaybackPositions = FileKey(0xCCCC333)
            md._prefsKey = FileKey(0xDDDD444)
            _rewrite_map(tmp, td.localKey, md)

            got = self._load_mapdata(tmp)
            self.assertEqual(got._settingsKey, 0x111)
            self.assertEqual(got._searchSuggestionsKey, 0x222)
            self.assertEqual(got._roundPlaceholder, 0xAAAA111)
            self.assertEqual(got._inlineBotsDownloads, 0xBBBB222)
            self.assertEqual(got._mediaLastPlaybackPositions, 0xCCCC333)
            self.assertEqual(got._prefsKey, 0xDDDD444)

    def test_bot_storages_map_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp)

            md = MapData(_map_dir(tmp))
            md._botStoragesMap[PeerId(999)] = FileKey(777)
            md._botStoragesMap[PeerId(1234)] = FileKey(888)
            _rewrite_map(tmp, td.localKey, md)

            got = self._load_mapdata(tmp)
            self.assertEqual(
                {int(k): int(v) for k, v in got._botStoragesMap.items()},
                {999: 777, 1234: 888},
            )
            self.assertTrue(all(got._botStoragesNotReadMap.values()))

    def test_webview_tokens_do_not_truncate_later_keys(self):
        # regression: the old lskWebviewTokens branch (is_finished = True)
        # dropped every entry after the tokens when reading, and wrote the
        # tokens as two uint64s instead of two QByteArrays
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp)

            md = MapData(_map_dir(tmp))
            md._webviewStorageTokenBots = QByteArray(b"bots-token")
            md._webviewStorageTokenOther = QByteArray(b"other-token")
            md._settingsKey = FileKey(0x5E77E75)  # written AFTER the tokens
            _rewrite_map(tmp, td.localKey, md)

            got = self._load_mapdata(tmp)
            self.assertEqual(bytes(got._webviewStorageTokenBots.data()), b"bots-token")
            self.assertEqual(bytes(got._webviewStorageTokenOther.data()), b"other-token")
            # the key following the tokens must still be read
            self.assertEqual(got._settingsKey, 0x5E77E75)

    def test_settings_key_still_random_per_instance(self):
        # the fork's Security fix must survive the tolerance port
        with tempfile.TemporaryDirectory() as tmp:
            keys = {MapData(os.path.join(tmp, f"m{i}"))._settingsKey for i in range(8)}
            self.assertGreater(len(keys), 1)
            self.assertNotIn(1851671142505648812, keys)


class TestUnknownKeyTolerance(unittest.TestCase):
    def _run_with_payload(self, tmp, td, payload):
        _write_raw_map(tmp, td.localKey, payload)
        md = MapData(_map_dir(tmp))
        md.read(td.localKey, QByteArray())
        return md

    def test_unknown_keytype_warns_and_continues(self):
        # our (pre-existing) tolerance for unknown keys is warn-and-continue:
        # an unknown key with no payload must not abort the map read
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp)

            data = QByteArray()
            stream = QDataStream(data, QIODevice.OpenModeFlag.WriteOnly)
            stream.writeUInt32(0x7E)  # unknown key type, no payload
            stream.writeUInt32(lskType.lskUserSettings)
            stream.writeUInt64(0x1234)

            with self.assertLogs(level=logging.WARNING):
                md = self._run_with_payload(tmp, td, data)
            self.assertEqual(md._settingsKey, 0x1234)

    def test_bot_storages_implausible_count_rejected(self):
        # parser-DoS cap in the spirit of the mtp-authorization key-count
        # check (CHANGELOG [Unreleased] Security) — a hostile count must
        # fail fast instead of spinning the loop
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp)

            data = QByteArray()
            stream = QDataStream(data, QIODevice.OpenModeFlag.WriteOnly)
            stream.writeUInt32(lskType.lskBotStorages)
            stream.writeUInt32(0xFFFFFFFF)  # ~4G pairs declared, none present

            with self.assertRaises(TDataBadConfigData):
                self._run_with_payload(tmp, td, data)

    def test_truncated_map_raises_opentele_exception(self):
        # a stream that ends mid-entry must fail, not return garbage
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp)

            data = QByteArray()
            stream = QDataStream(data, QIODevice.OpenModeFlag.WriteOnly)
            stream.writeUInt32(lskType.lskLocations)
            stream.writeUInt32(0xDEAD)  # uint64 declared, only 4 bytes

            with self.assertRaises(OpenTeleException):
                self._run_with_payload(tmp, td, data)


class TestMaxAccounts(unittest.TestCase):
    def test_kmaxaccounts_is_six(self):
        # real Telegram Desktop (Premium) account cap
        self.assertEqual(TDesktop.kMaxAccounts, 6)


if __name__ == "__main__":
    unittest.main()
