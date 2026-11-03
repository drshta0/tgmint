"""Fully-offline tdata write/read round-trip tests.

Exercises the fork's key-generation fixes:

* every written tdata folder gets its OWN random master key (upstream
  installed a hardcoded constant localKey/passcodeKey when performance
  mode was on — one public master key shared by every folder);
* MapData._settingsKey is random per instance instead of the shared
  hardcoded 1851671142505648812;
* MTP.DcOptions.applyOneGuarded actually dedups (ip, port) and keeps the
  passed secret (upstream appended duplicates and dropped the secret).

Also covers the review's "td/" findings that live in storage.py /
mtp.py: the DcOptions.Serialize -> constructFromSerialized round-trip
(`port` was never written), the ReadFile candidate policy, the truncated
file guard, CreateLegacyLocalKey's SHA-1/4000 derivation, ComposeDataString
and an empty EncryptedDescriptor.

Skips cleanly when PyQt5 is not installed.
"""
import os
import struct
import tempfile
import unittest

try:
    from tgmint.td import TDesktop
    from tgmint.td.account import Account
    from tgmint.td.auth import AuthKey, AuthKeyType
    from tgmint.td.configs import DcId, TDF_MAGIC
    from tgmint.td.shared import MTP
    from tgmint.api import API

    HAVE_QT = True
except ImportError:  # PyQt5 (or tgcrypto) not installed
    HAVE_QT = False

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


@unittest.skipUnless(HAVE_QT, "PyQt5 not installed — tdata tests skipped")
class TestTDataRoundtrip(unittest.TestCase):
    def test_save_then_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            self.assertTrue(td.SaveTData(tmp))

            loaded = TDesktop(tmp)
            self.assertTrue(loaded.isLoaded())
            self.assertEqual(loaded.accountsCount, 1)

            account = loaded.mainAccount
            self.assertIsNotNone(account)
            self.assertEqual(account.UserId, USER_ID)
            self.assertEqual(account.MainDcId, DC_ID)
            self.assertIsNotNone(account.authKey)
            self.assertEqual(len(account.authKey.key), 256)

    def test_each_folder_gets_its_own_master_key(self):
        # two independent TDesktop instances must never share key
        # material — the old constant-key performance mode produced
        # byte-identical key_datas for every folder ever written
        with tempfile.TemporaryDirectory() as tmp:
            folder_a = os.path.join(tmp, "a")
            folder_b = os.path.join(tmp, "b")

            td_a = _build_tdesktop()
            td_b = _build_tdesktop()
            td_a.SaveTData(folder_a)
            td_b.SaveTData(folder_b)

            self.assertNotEqual(td_a.localKey.key, td_b.localKey.key)

            with open(os.path.join(folder_a, "key_datas"), "rb") as fp:
                key_a = fp.read()
            with open(os.path.join(folder_b, "key_datas"), "rb") as fp:
                key_b = fp.read()
            self.assertNotEqual(key_a, key_b)

    def test_settings_key_is_random_per_instance(self):
        from tgmint.td.account import MapData

        with tempfile.TemporaryDirectory() as tmp:
            keys = {
                MapData(os.path.join(tmp, f"map{i}"))._settingsKey
                for i in range(8)
            }
            # the old implementation returned the same hardcoded
            # 1851671142505648812 for every instance
            self.assertGreater(len(keys), 1)
            self.assertNotIn(1851671142505648812, keys)

    def test_passcode_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            td = _build_tdesktop()
            td.SaveTData(tmp, passcode="s3cret passcode")

            loaded = TDesktop(tmp, passcode="s3cret passcode")
            self.assertTrue(loaded.isLoaded())
            self.assertEqual(loaded.mainAccount.UserId, USER_ID)


@unittest.skipUnless(HAVE_QT, "PyQt5 not installed — mtp tests skipped")
class TestDcOptionsSerialization(unittest.TestCase):
    """DcOptions.Serialize -> constructFromSerialized.

    Regression for review finding 'DcOptions.Serialize omits port':
    the writer emitted id/flags/ipSize/ip/secretSize/secret while both our
    own reader and tdesktop (mtproto_dc_options.cpp, DcOptions::serialize:
    `<< id << flags << port << ipSize`, then raw ip, `<< secretSize`, raw
    secret) expect `port` right after `flags`. Every config blob we wrote
    was therefore unreadable — 4 bytes short per endpoint — and nothing
    exercised the write direction.
    """

    def test_roundtrip_preserves_endpoints(self):
        original = MTP.DcOptions(MTP.Environment.Production)
        serialized = original.Serialize()

        restored = MTP.DcOptions(MTP.Environment.Production)
        restored.constructFromSerialized(serialized)

        def as_set(options):
            return sorted(
                (
                    int(dc_id),
                    sorted((ep.ip, ep.port, bytes(ep.secret)) for ep in endpoints),
                )
                for dc_id, endpoints in options._data.items()
            )

        self.assertEqual(as_set(restored), as_set(original))
        self.assertTrue(len(restored._data) > 0)

    def test_port_is_written_after_flags(self):
        options = MTP.DcOptions(MTP.Environment.Production)
        options._data.clear()
        options.constructAddOne(
            DcId(2), MTP.DcOptions.Flag(0), "10.1.2.3", 8443, b"\xaa\xbb"
        )

        raw = bytes(options.Serialize())
        # qint32(-kVersion), qint32(count), then per endpoint:
        # id, flags, port, ipSize, ip..., secretSize, secret...
        head = struct.unpack(">iiiiii", raw[:24])
        self.assertEqual(head[0], -MTP.DcOptions.kVersion)
        self.assertEqual(head[1], 1)  # one endpoint
        self.assertEqual(head[2], 2)  # dc id
        self.assertEqual(head[3], 0)  # flags
        self.assertEqual(head[4], 8443)  # port — the field that was missing
        self.assertEqual(head[5], len("10.1.2.3"))  # ipSize

    def test_roundtrip_keeps_secret(self):
        options = MTP.DcOptions(MTP.Environment.Production)
        options._data.clear()
        secret = os.urandom(16)
        options.constructAddOne(
            DcId(4),
            MTP.DcOptions.Flag(MTP.DcOptions.Flag.f_secret),
            "10.9.9.9",
            443,
            secret,
        )

        restored = MTP.DcOptions(MTP.Environment.Production)
        restored.constructFromSerialized(options.Serialize())

        endpoints = restored._data[DcId(4)]
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0].secret, secret)
        self.assertEqual(endpoints[0].port, 443)


@unittest.skipUnless(HAVE_QT, "PyQt5 not installed — storage tests skipped")
class TestStorageFileCandidates(unittest.TestCase):
    """Storage.ReadFile candidate policy (review finding 'ReadFile
    candidate policy diverges from tdesktop').

    tdesktop (storage_file_utilities.cpp, ReadFile) tries "<base>s" when it
    exists, otherwise the NEWER (by mtime) of "<base>0"/"<base>1", and only
    the one that exists when just one does. The fork tried s,1,0
    unconditionally.
    """

    def _write(self, directory, name, payload=b"hello"):
        # a well-formed tdata record: magic, app version, payload, md5 of
        # (payload, dataSize, version, magic)
        import hashlib

        from tgmint.td.configs import APP_VERSION

        version = APP_VERSION
        dataSize = len(payload)
        md5 = hashlib.md5(
            payload
            + dataSize.to_bytes(4, "little")
            + version.to_bytes(4, "little")
            + TDF_MAGIC
        ).digest()
        with open(os.path.join(directory, name), "wb") as fp:
            fp.write(TDF_MAGIC + version.to_bytes(4, "little") + payload + md5)

    def test_modern_s_wins_over_legacy(self):
        from tgmint.td.storage import Storage

        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, "items", b"modern")
            # a legacy copy with a NEWER mtime must still lose
            self._write(tmp, "item0", b"legacy")
            os.utime(os.path.join(tmp, "item0"), (9_000_000_000, 9_000_000_000))

            result = Storage.ReadFile("item", tmp)
            self.assertEqual(bytes(result.data), b"modern")

    def test_legacy_0_and_1_only(self):
        from tgmint.td.storage import Storage

        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, "item0", b"zero")
            self._write(tmp, "item1", b"one")
            # "1" is newer -> it is tried first
            os.utime(os.path.join(tmp, "item0"), (1000, 1000))
            os.utime(os.path.join(tmp, "item1"), (2000, 2000))

            result = Storage.ReadFile("item", tmp)
            self.assertEqual(bytes(result.data), b"one")

    def test_legacy_newer_0_wins(self):
        from tgmint.td.storage import Storage

        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, "item0", b"zero")
            self._write(tmp, "item1", b"one")
            os.utime(os.path.join(tmp, "item0"), (3000, 3000))
            os.utime(os.path.join(tmp, "item1"), (1000, 1000))

            result = Storage.ReadFile("item", tmp)
            self.assertEqual(bytes(result.data), b"zero")

    def test_only_legacy_1_present(self):
        from tgmint.td.storage import Storage

        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, "item1", b"only-one")

            result = Storage.ReadFile("item", tmp)
            self.assertEqual(bytes(result.data), b"only-one")

    def test_truncated_file_raises_tdata_exception(self):
        # review finding 'missing dataSize < 0 guard': a file too short
        # to carry the 16-byte md5 trailer raised a bare OverflowError
        # instead of a TData* exception
        from tgmint.exception import OpenTeleException
        from tgmint.td.storage import Storage

        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "items"), "wb") as fp:
                fp.write(TDF_MAGIC + b"\x00" * 4)  # magic + version, no body

            with self.assertRaises(OpenTeleException):
                Storage.ReadFile("item", tmp)


@unittest.skipUnless(HAVE_QT, "PyQt5 not installed — key tests skipped")
class TestLegacyLocalKey(unittest.TestCase):
    """Storage.CreateLegacyLocalKey / ComposeDataString / an empty
    EncryptedDescriptor — review td findings 4, 8 and 9."""

    def test_legacy_key_is_pbkdf2_sha1_4000(self):
        import hashlib

        from tgmint.td.configs import QByteArray
        from tgmint.td.storage import Storage

        salt = QByteArray(b"s" * 32)
        passcode = QByteArray(b"passcode")

        # tdesktop: PKCS5_PBKDF2_HMAC_SHA1(passcode, salt,
        #   passcode.isEmpty() ? LocalEncryptNoPwdIterCount(4)
        #                      : LocalEncryptIterCount(4000), 256)
        expected = hashlib.pbkdf2_hmac("sha1", passcode.data(), salt.data(), 4000, 256)
        self.assertEqual(Storage.CreateLegacyLocalKey(salt, passcode).key, expected)

        no_pwd = hashlib.pbkdf2_hmac("sha1", b"", salt.data(), 4, 256)
        self.assertEqual(
            Storage.CreateLegacyLocalKey(salt, QByteArray()).key, no_pwd
        )

    def test_legacy_key_is_not_the_modern_key(self):
        from tgmint.td.configs import QByteArray
        from tgmint.td.storage import Storage

        salt = QByteArray(b"s" * 32)
        passcode = QByteArray(b"passcode")
        # the legacy map key is a different KDF family from CreateLocalKey
        self.assertNotEqual(
            Storage.CreateLegacyLocalKey(salt, passcode).key,
            Storage.CreateLocalKey(salt, passcode).key,
        )

    def test_legacy_key_no_pwd_differs_from_passcode_key(self):
        from tgmint.td.configs import QByteArray
        from tgmint.td.storage import Storage

        salt = QByteArray(b"s" * 32)
        self.assertNotEqual(
            Storage.CreateLegacyLocalKey(salt, QByteArray()).key,
            Storage.CreateLegacyLocalKey(salt, QByteArray(b"x")).key,
        )

    def test_compose_data_string_strips_existing_hashes(self):
        from tgmint.td.storage import Storage

        self.assertEqual(Storage.ComposeDataString("data", 0), "data")
        self.assertEqual(Storage.ComposeDataString("data", 1), "data#2")
        self.assertEqual(Storage.ComposeDataString("data", 2), "data#3")
        # tdesktop strips every '#' from the base name first
        self.assertEqual(Storage.ComposeDataString("da#ta", 1), "data#2")

    def test_zero_sized_encrypted_descriptor_is_usable(self):
        # an empty record (size 0) used to leave the descriptor
        # uninitialised: writes silently vanished and PrepareEncrypted
        # produced a record that could not be decrypted back
        from tgmint.td.configs import QByteArray
        from tgmint.td.storage import Storage

        key = AuthKey(os.urandom(256), AuthKeyType.Generated, DcId(0))
        descriptor = Storage.EncryptedDescriptor(0)
        self.assertIsNotNone(descriptor.stream.device())

        encrypted = Storage.PrepareEncrypted(descriptor, key)
        self.assertEqual(encrypted.size(), 0x10 + 0x10)

        decrypted = Storage.DecryptLocal(encrypted, key)
        # the only content is the 4-byte length prefix, which records a
        # payload length of 4 ("" here) -- and the read cursor sits at the
        # end of it
        self.assertEqual(bytes(decrypted.data), (4).to_bytes(4, "little"))
        self.assertTrue(decrypted.stream.atEnd())


@unittest.skipUnless(HAVE_QT, "PyQt5 not installed — mtp tests skipped")
class TestDcOptionsDedup(unittest.TestCase):
    def test_duplicate_endpoints_added_once_with_secret(self):
        opts = MTP.DcOptions(MTP.Environment.Production)
        # constructFromBuiltIn() already added the static endpoints —
        # compare before/after counts for DcId(1)
        before = len(opts._data[DcId(1)])

        for _ in range(3):
            opts.constructAddOne(
                DcId(1), MTP.DcOptions.Flag(0), "10.0.0.1", 443, b"\x01\x02"
            )

        after = len(opts._data[DcId(1)])
        self.assertEqual(after, before + 1)  # dedup, not 3 duplicate appends

        added = [e for e in opts._data[DcId(1)] if e.ip == "10.0.0.1"]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0].port, 443)
        # the passed secret must be kept, not replaced by bytes()
        self.assertEqual(added[0].secret, b"\x01\x02")


if __name__ == "__main__":
    unittest.main()
