"""Fully-offline tdata write/read round-trip tests.

Exercises the fork's key-generation fixes:

* every written tdata folder gets its OWN random master key (upstream
  installed a hardcoded constant localKey/passcodeKey when performance
  mode was on — one public master key shared by every folder);
* MapData._settingsKey is random per instance instead of the shared
  hardcoded 1851671142505648812;
* MTP.DcOptions.applyOneGuarded actually dedups (ip, port) and keeps the
  passed secret (upstream appended duplicates and dropped the secret).

Skips cleanly when PyQt5 is not installed.
"""
import os
import tempfile
import unittest

try:
    from tgmint.td import TDesktop
    from tgmint.td.account import Account
    from tgmint.td.auth import AuthKey, AuthKeyType
    from tgmint.td.configs import DcId
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
