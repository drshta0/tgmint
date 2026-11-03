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


class TestGenerateRandom(unittest.TestCase):
    """`system="random"` is advertised by the overloads — it must work."""

    def test_random_equals_the_none_default(self):
        for uid in ("r1", "random-check", "42"):
            self.assertEqual(
                _fingerprint(API.TelegramDesktop.Generate(system="random", unique_id=uid)),
                _fingerprint(API.TelegramDesktop.Generate(unique_id=uid)),
            )

    def test_random_is_deterministic_per_unique_id(self):
        for uid in ("r1", "r2"):
            a = API.TelegramDesktop.Generate(system="random", unique_id=uid)
            b = API.TelegramDesktop.Generate(system="random", unique_id=uid)
            self.assertEqual(_fingerprint(a), _fingerprint(b))

    def test_random_is_case_insensitive(self):
        self.assertEqual(
            _fingerprint(API.TelegramDesktop.Generate(system="RANDOM", unique_id="r1")),
            _fingerprint(API.TelegramDesktop.Generate(system="random", unique_id="r1")),
        )


class TestCopyKeepsIdentity(unittest.TestCase):
    """APIData.copy() must be identity-preserving — tz_zone included.

    tz_zone is the value of initConnection's params.tz_offset, so a copy
    that dropped it silently demoted a minted identity back to "sends no
    timezone" (tdesktop.py / heal.py both copy before converting).
    """

    def test_copy_preserves_tz_zone(self):
        for preset in (
            API.TelegramDesktop,
            API.TelegramAndroid,
            API.TelegramAndroidX,
            API.TelegramIOS,
            API.TelegramMacOS,
        ):
            api = preset.Generate(unique_id="copy-tz", locale="ru")
            self.assertIsNotNone(api.tz_zone, preset.__name__)
            self.assertEqual(api.copy().tz_zone, api.tz_zone, preset.__name__)

    def test_copy_preserves_every_fingerprint_field(self):
        api = API.TelegramAndroid.Generate(unique_id="copy-all", locale="ru")
        clone = api.copy()
        for field in (
            "api_id",
            "api_hash",
            "device_model",
            "system_version",
            "app_version",
            "lang_code",
            "system_lang_code",
            "lang_pack",
            "tz_zone",
        ):
            self.assertEqual(getattr(clone, field), getattr(api, field), field)
        self.assertEqual(clone, api)
        self.assertEqual(hash(clone), hash(api))

    def test_equality_sees_tz_zone(self):
        api = API.TelegramIOS.Generate(unique_id="eq-tz", locale="ru")
        other = api.copy()
        other.tz_zone = "Asia/Tokyo" if api.tz_zone != "Asia/Tokyo" else "Europe/Berlin"
        self.assertNotEqual(api, other)
        self.assertNotEqual(hash(api), hash(other))

    def test_constructor_accepts_tz_zone(self):
        api = API.TelegramAndroid(6, "eb06d4abfb49dc3eeb1aeb98ae0f581e", tz_zone="Europe/Berlin")
        self.assertEqual(api.tz_zone, "Europe/Berlin")
        self.assertEqual(api.copy().tz_zone, "Europe/Berlin")


if __name__ == "__main__":
    unittest.main()
