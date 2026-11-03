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

    def test_unknown_keytype_fails_the_map_read(self):
        # tdesktop has no default-consume path: an unknown key type makes
        # the whole map read fail (`default: return ReadMapResult::Failed`
        # in storage_account.cpp) because the payload length is unknowable.
        # The old fork behaviour (log a warning, keep going) left the stream
        # 8+ bytes behind the real entry boundary and parsed every
        # following entry out of the middle of a payload — silent garbage
        # instead of an error. Wallet keys 0x1F-0x21, which used to hit
        # that path, are consumed explicitly now (see
        # TestWalletKeysRoundtrip), so what is left here really is unknown.
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp)

            data = QByteArray()
            stream = QDataStream(data, QIODevice.OpenModeFlag.WriteOnly)
            stream.writeUInt32(0x7E)  # unknown key type, no payload
            stream.writeUInt32(lskType.lskUserSettings)
            stream.writeUInt64(0x1234)

            with self.assertRaises(TDataBadConfigData):
                self._run_with_payload(tmp, td, data)

    def test_implausible_draft_count_rejected(self):
        # parser-DoS cap: a declared count of ~4G drafts used to spin the
        # per-entry loop (the stream status is only checked once per key
        # TYPE, i.e. after the loop) instead of failing fast
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp)

            data = QByteArray()
            stream = QDataStream(data, QIODevice.OpenModeFlag.WriteOnly)
            stream.writeUInt32(lskType.lskDraft)
            stream.writeUInt32(0xFFFFFFFF)

            with self.assertRaises(TDataBadConfigData):
                self._run_with_payload(tmp, td, data)

    def test_implausible_legacy_images_count_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp)

            data = QByteArray()
            stream = QDataStream(data, QIODevice.OpenModeFlag.WriteOnly)
            stream.writeUInt32(lskType.lskLegacyImages)
            stream.writeUInt32(0x7FFFFFFF)

            with self.assertRaises(TDataBadConfigData):
                self._run_with_payload(tmp, td, data)

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


class TestLegacyBackgroundKeyOldOld(unittest.TestCase):
    """lskBackgroundOldOld (0x08) — review finding 'old map key 0x08
    -> TypeError'.

    tdesktop reads ONE quint64 here (storage_account.cpp: `stream >>
    (Window::Theme::IsNightMode() ? legacyBackgroundKeyNight :
    legacyBackgroundKeyDay)`). The fork did `map.stream >>
    legacyBackgroundKeyDay`, the QByteArray operator, so the int raised
    TypeError — which is NOT an OpenTeleException and therefore escaped
    every handler on the tdata load path.
    """

    def _read_raw(self, tmp, td, payload):
        _write_raw_map(tmp, td.localKey, payload)
        md = MapData(_map_dir(tmp))
        md.read(td.localKey, QByteArray())
        return md

    def test_single_key_is_consumed_without_typeerror(self):
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp)

            data = QByteArray()
            stream = QDataStream(data, QIODevice.OpenModeFlag.WriteOnly)
            stream.writeUInt32(lskType.lskBackgroundOldOld)
            stream.writeUInt64(0xABCDEF)
            stream.writeUInt32(lskType.lskUserSettings)
            stream.writeUInt64(0x5E77E75)  # written AFTER the 0x08 entry

            md = self._read_raw(tmp, td, data)
            self.assertEqual(md._legacyBackgroundKeyDay, 0xABCDEF)
            # the entry after it must still be readable (no desync)
            self.assertEqual(md._settingsKey, 0x5E77E75)

    def test_background_old_reads_two_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp)

            data = QByteArray()
            stream = QDataStream(data, QIODevice.OpenModeFlag.WriteOnly)
            stream.writeUInt32(lskType.lskBackgroundOld)
            stream.writeUInt64(0x1111)
            stream.writeUInt64(0x2222)

            md = self._read_raw(tmp, td, data)
            self.assertEqual(md._legacyBackgroundKeyDay, 0x1111)
            self.assertEqual(md._legacyBackgroundKeyNight, 0x2222)


class TestWalletKeysRoundtrip(unittest.TestCase):
    """lskWalletKey (0x1F), lskWalletEngineKey (0x20) and
    lskWalletEngineStorages (0x21) — review finding 'unknown map keys
    (wallet 0x1F/0x20/0x21) not consumed -> whole map desyncs'.

    Payloads per tdesktop storage_account.cpp: 0x1F/0x20 carry one quint64
    FileKey; 0x21 carries a quint32 count of (FileKey quint64, QString)
    entries.
    """

    def test_wallet_keys_are_consumed_and_map_survives(self):
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp)

            data = QByteArray()
            stream = QDataStream(data, QIODevice.OpenModeFlag.WriteOnly)
            stream.writeUInt32(lskType.lskWalletKey)
            stream.writeUInt64(0x1234)
            stream.writeUInt32(lskType.lskWalletEngineKey)
            stream.writeUInt64(0x5678)
            stream.writeUInt32(lskType.lskWalletEngineStorages)
            stream.writeUInt32(2)
            stream.writeUInt64(0xAAA)
            stream.writeQString("wallet:secrets")
            stream.writeUInt64(0xBBB)
            stream.writeQString("wallet:journal")
            # every entry after the wallet block must still be readable
            stream.writeUInt32(lskType.lskUserSettings)
            stream.writeUInt64(0x5E77E75)

            _write_raw_map(tmp, td.localKey, data)
            md = MapData(_map_dir(tmp))
            md.read(td.localKey, QByteArray())

            self.assertEqual(md._settingsKey, 0x5E77E75)
            self.assertEqual(
                {k: int(v) for k, v in md._walletEngineStoragesMap.items()},
                {"wallet:secrets": 0xAAA, "wallet:journal": 0xBBB},
            )

    def test_wallet_engine_storages_survive_save(self):
        # re-saving must not drop the wallet map (tdesktop writes it just
        # before lskBotStorages)
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp)

            md = MapData(_map_dir(tmp))
            md._walletEngineStoragesMap["wallet:secrets"] = FileKey(0xAAA)
            _rewrite_map(tmp, td.localKey, md)

            got = TDesktop(tmp).mainAccount.MapData
            self.assertEqual(
                {k: int(v) for k, v in got._walletEngineStoragesMap.items()},
                {"wallet:secrets": 0xAAA},
            )


class TestSelfSerializedRoundtrip(unittest.TestCase):
    """lskSelfSerialized (0x15) — review finding 'lskSelfSerialized
    parsed and discarded'.

    The own-user record was read into a local, thrown away, and never
    written back, so load -> save silently dropped it. tdesktop keeps it
    and writes it as the FIRST map entry.
    """

    def test_self_record_survives_a_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp)

            payload = QByteArray(b"\x00\x00\x00\x02\x08\x01\x00\x00\x07test")
            md = MapData(_map_dir(tmp))
            md._selfSerialized = payload
            _rewrite_map(tmp, td.localKey, md)

            got = TDesktop(tmp).mainAccount.MapData
            self.assertEqual(bytes(got._selfSerialized), bytes(payload))

    def test_self_record_is_the_first_entry(self):
        # tdesktop: `if (!self.isEmpty()) mapData.stream <<
        # quint32(lskSelfSerialized) << self;` comes before every other key
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp)

            md = MapData(_map_dir(tmp))
            md._selfSerialized = QByteArray(b"self-record")
            md._settingsKey = FileKey(0x99)
            descriptor = md.prepareToWrite()
            raw = bytes(descriptor.data)
            # data layout: [uint32 len][payload]; payload starts after it
            payload = raw[4:]
            import struct as _struct

            self.assertEqual(
                _struct.unpack(">I", payload[:4])[0], lskType.lskSelfSerialized
            )


if __name__ == "__main__":
    unittest.main()
