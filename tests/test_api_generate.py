"""Offline tests for API.TelegramDesktop.Generate(system=...) validation.

Upstream checked `system not in validList` BEFORE lowercasing, so
"Windows"/"MacOS"/"LINUX" were silently replaced by a hash-derived pick.
Normalization now happens first, and unknown systems raise ValueError.
"""
import unittest

from tgmint.api import API


def _fingerprint(api):
    return (api.device_model, api.system_version, api.app_version)


class TestGenerateCaseInsensitive(unittest.TestCase):
    def test_windows(self):
        for uid in ("w", "old.session", "12345"):
            self.assertEqual(
                _fingerprint(API.TelegramDesktop.Generate(system="Windows", unique_id=uid)),
                _fingerprint(API.TelegramDesktop.Generate(system="windows", unique_id=uid)),
            )

    def test_macos(self):
        for uid in ("m", "old.session"):
            self.assertEqual(
                _fingerprint(API.TelegramDesktop.Generate(system="MacOS", unique_id=uid)),
                _fingerprint(API.TelegramDesktop.Generate(system="macos", unique_id=uid)),
            )
        api = API.TelegramDesktop.Generate(system="MacOS", unique_id="m")
        self.assertTrue(api.system_version.startswith("macOS "))

    def test_linux(self):
        for uid in ("l", "old.session"):
            self.assertEqual(
                _fingerprint(API.TelegramDesktop.Generate(system="LINUX", unique_id=uid)),
                _fingerprint(API.TelegramDesktop.Generate(system="linux", unique_id=uid)),
            )
        api = API.TelegramDesktop.Generate(system="LINUX", unique_id="l")
        self.assertTrue(api.system_version.startswith("Linux"))

    def test_whitespace_tolerated(self):
        self.assertEqual(
            _fingerprint(API.TelegramDesktop.Generate(system="  Windows ", unique_id="w")),
            _fingerprint(API.TelegramDesktop.Generate(system="windows", unique_id="w")),
        )

    def test_case_insensitive_matches_explicit_lowercase(self):
        # "Windows" must actually BE windows, not a silently swapped pick
        api = API.TelegramDesktop.Generate(system="Windows", unique_id="w")
        self.assertIn(" x64", api.system_version)

    def test_unknown_system_raises(self):
        for bad in ("templeos", "TempleOS", "windows98", "android", ""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                API.TelegramDesktop.Generate(system=bad, unique_id="w")

    def test_none_still_picks_deterministically(self):
        a = API.TelegramDesktop.Generate(unique_id="stable-id")
        b = API.TelegramDesktop.Generate(unique_id="stable-id")
        self.assertEqual(_fingerprint(a), _fingerprint(b))
        self.assertIn(a.system_version.split(" ")[0].lower(), ("windows", "macos", "linux"))


if __name__ == "__main__":
    unittest.main()
