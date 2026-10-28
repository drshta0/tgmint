"""Tests for the core data modules: Fingerprint, locales, layers,
and their integration into API.Generate."""

import unittest
from datetime import datetime

from tgmint.api import API
from tgmint.fingerprint import Fingerprint
from tgmint.layers import TD_LAYERS, pick_app_version, telethon_layer, tdesktop_version_for_layer
from tgmint.locales import LOCALES, known_locale_pairs, pick_locale


def _td_fingerprint(**overrides) -> Fingerprint:
    base = dict(
        api_id=2040,
        api_hash="b18441a1ff607e10a989891a5462e627",
        device_model="Desktop",
        system_version="Windows 11 x64",
        app_version="6.7.8 x64",
        lang_code="en",
        system_lang_code="en-US",
        lang_pack="tdesktop",
        tz_zone="America/New_York",
        origin="tdesktop",
    )
    base.update(overrides)
    return Fingerprint(**base)


class FingerprintTest(unittest.TestCase):
    def test_frozen(self):
        fp = _td_fingerprint()
        with self.assertRaises(Exception):
            fp.device_model = "Desktop 2"

    def test_tz_offset_dst(self):
        # New York: UTC-5 in January, UTC-4 in July (DST)
        fp = _td_fingerprint(tz_zone="America/New_York")
        self.assertEqual(fp.tz_offset(datetime(2026, 1, 15, 12, 0)), -18000)
        self.assertEqual(fp.tz_offset(datetime(2026, 7, 15, 12, 0)), -14400)

    def test_tz_offset_half_hour_zone(self):
        fp = _td_fingerprint(tz_zone="Asia/Kolkata")
        self.assertEqual(fp.tz_offset(datetime(2026, 3, 1, 12, 0)), 19800)

    def test_tz_offset_none_and_unknown(self):
        self.assertIsNone(_td_fingerprint(tz_zone=None).tz_offset())
        self.assertIsNone(_td_fingerprint(tz_zone="Not/AZone").tz_offset())

    def test_tz_offset_aware_datetime_is_an_instant(self):
        # aware datetimes name an INSTANT — Berlin's 2026-03-29 switch
        # happens at 01:00 UTC; at that exact instant the offset is +7200
        # (CEST), while the naive wall-clock reading 01:00 is still before
        # the local 02:00->03:00 jump (+3600)
        from datetime import timezone

        fp = _td_fingerprint(tz_zone="Europe/Berlin")
        self.assertEqual(
            fp.tz_offset(datetime(2026, 3, 29, 1, 0, tzinfo=timezone.utc)), 7200
        )
        # the naive reading of the same clock digits stays pre-switch
        self.assertEqual(fp.tz_offset(datetime(2026, 3, 29, 1, 0)), 3600)

    def test_tz_offset_bad_at_type_raises(self):
        # a wrong-typed `at` is a caller bug and must raise, not silently
        # return None (which would mean "send no timezone" for a typo)
        with self.assertRaises(TypeError):
            _td_fingerprint(tz_zone="Europe/Berlin").tz_offset("2026-01-01")

    def test_dict_roundtrip(self):
        fp = _td_fingerprint()
        self.assertEqual(Fingerprint.from_dict(fp.to_dict()), fp)

    def test_from_dict_rejects_bad_schema(self):
        bad = _td_fingerprint().to_dict()
        bad["schema_version"] = 99
        with self.assertRaises(ValueError):
            Fingerprint.from_dict(bad)
        with self.assertRaises(ValueError):
            Fingerprint.from_dict({"schema_version": 1})

    def test_validate_good(self):
        self.assertEqual(_td_fingerprint().validate(), [])

    def test_validate_flags_bad_api_hash(self):
        problems = _td_fingerprint(api_hash="NOTAHASH").validate()
        self.assertTrue(any("api_hash" in p for p in problems))

    def test_validate_flags_unknown_locale(self):
        problems = _td_fingerprint(lang_code="xx", system_lang_code="xx-XX").validate()
        self.assertTrue(any("locale pair" in p for p in problems))

    def test_validate_flags_cross_platform_system(self):
        problems = _td_fingerprint(system_version="SDK 35").validate()
        self.assertTrue(any("system_version" in p for p in problems))

    def test_from_apidata(self):
        api = API.TelegramDesktop.Generate(
            system="windows", unique_id="fp-bridge", layer=224
        )
        fp = Fingerprint.from_apidata(api)
        self.assertEqual(fp.lang_pack, "tdesktop")
        self.assertEqual(fp.origin, "tdesktop")
        self.assertEqual(fp.app_version, api.app_version)
        self.assertEqual(fp.tz_zone, api.tz_zone)

    def test_from_apidata_rejects_non_api(self):
        with self.assertRaises(TypeError):
            Fingerprint.from_apidata("nope")

    def test_sidecar_roundtrip(self):
        import os
        import tempfile

        fp = _td_fingerprint()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "acc.fingerprint.json")
            fp.save(path)
            self.assertEqual(Fingerprint.load(path), fp)
            # atomic-private write discipline (same as passkey files)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


class LocalesTest(unittest.TestCase):
    def test_deterministic(self):
        for uid in ("alpha", "beta", "gamma-session"):
            self.assertEqual(pick_locale(uid), pick_locale(uid))

    def test_pick_none_returns_member(self):
        for _ in range(5):
            self.assertIn(pick_locale(None), LOCALES)

    def test_empty_pool_degrades_instead_of_crashing(self):
        # a container with no usable tzdata drops every triple; picking
        # must fall back to the zone-less en/en-US default (no timezone
        # is sent), never raise ZeroDivisionError
        from unittest import mock

        import tgmint.locales as locales_module

        with mock.patch.object(locales_module, "LOCALES", ()):
            for uid in (None, "some-account"):
                triple = locales_module.pick_locale(uid)
                self.assertEqual(
                    (triple.lang_code, triple.system_lang_code), ("en", "en-US")
                )
                self.assertFalse(triple.tz_zone)  # falsy -> tz never sent

    def test_weights_sum_to_one(self):
        total = sum(t.weight for t in LOCALES)
        self.assertLess(abs(total - 1.0), 0.1, f"weights sum to {total}")

    def test_all_zones_load(self):
        from zoneinfo import ZoneInfo

        for triple in LOCALES:
            ZoneInfo(triple.tz_zone)  # must not raise

    def test_known_pairs(self):
        pairs = known_locale_pairs()
        self.assertIn(("en", "en-US"), pairs)
        self.assertIn(("ru", "ru-RU"), pairs)

    def test_triples_internally_coherent(self):
        # lang_code must be the lowercase prefix of system_lang_code
        for triple in LOCALES:
            self.assertTrue(triple.system_lang_code.lower().startswith(triple.lang_code))


class LayersTest(unittest.TestCase):
    def test_exact_lookups(self):
        self.assertEqual(tdesktop_version_for_layer(224), "6.7.8")
        self.assertEqual(tdesktop_version_for_layer(232), "7.3.3")

    def test_unknown_layer_none(self):
        self.assertIsNone(tdesktop_version_for_layer(999))
        self.assertIsNone(tdesktop_version_for_layer(212))  # gap: tdesktop never shipped it

    def test_pick_gap_resolves_closest_lower(self):
        # 223 is a gap -> closest lower known layer is 221 -> 6.4.4
        self.assertEqual(pick_app_version("tdesktop", 223, "7.2.8"), "6.4.4")

    def test_pick_unknown_falls_back(self):
        self.assertEqual(pick_app_version("tdesktop", 999, "7.2.8"), "7.2.8")

    def test_pick_non_tdesktop_unchanged(self):
        for origin in ("android", "ios", "macos", "web"):
            self.assertEqual(pick_app_version(origin, 224, "12.10.1 (70382)"), "12.10.1 (70382)")

    def test_telethon_layer(self):
        try:
            import telethon  # noqa: F401
        except ImportError:
            self.skipTest("telethon not installed")
        self.assertEqual(telethon_layer(), 224)

    def test_every_version_wellformed(self):
        import re

        for layer, version in TD_LAYERS.items():
            self.assertRegex(version, r"^\d+\.\d+(\.\d+)?$")
            self.assertIsInstance(layer, int)


class GenerateIntegrationTest(unittest.TestCase):
    def test_locale_auto_is_coherent(self):
        api = API.TelegramDesktop.Generate(system="windows", unique_id="gen-a")
        pair = (api.lang_code, api.system_lang_code)
        self.assertIn(pair, known_locale_pairs() | {("en", "en-US")})
        # a zone from the pool is set (tz actually sent on the wire)
        self.assertIsNotNone(api.tz_zone)
        self.assertIn((api.lang_code, api.system_lang_code), known_locale_pairs())

    def test_locale_none_is_legacy(self):
        api = API.TelegramDesktop.Generate(system="linux", unique_id="gen-b", locale=None)
        self.assertEqual((api.lang_code, api.system_lang_code), ("en", "en-US"))
        self.assertIsNone(api.tz_zone)

    def test_locale_explicit(self):
        api = API.TelegramAndroid.Generate(unique_id="gen-c", locale="ru")
        self.assertEqual(api.lang_code, "ru")
        self.assertEqual(api.system_lang_code, "ru-RU")
        self.assertEqual(api.tz_zone, "Europe/Moscow")

    def test_locale_unknown_raises(self):
        with self.assertRaises(ValueError):
            API.TelegramIOS.Generate(unique_id="gen-d", locale="klingon")

    def test_locale_numeric_raises_not_silently_coerced(self):
        # in Python 1 == True and 0 == False: numeric locale values must
        # NOT silently take the auto/legacy paths — they are caller bugs
        for bad in (1, 0, 1.0):
            with self.assertRaises(ValueError):
                API.TelegramDesktop.Generate(system="linux", unique_id="gen-num", locale=bad)

    def test_locale_deterministic(self):
        a = API.TelegramDesktop.Generate(system="macos", unique_id="same-id")
        b = API.TelegramDesktop.Generate(system="macos", unique_id="same-id")
        self.assertEqual((a.lang_code, a.system_lang_code, a.tz_zone), (b.lang_code, b.system_lang_code, b.tz_zone))

    def test_layer_coherent_version(self):
        api = API.TelegramDesktop.Generate(system="windows", unique_id="gen-e", layer=224)
        self.assertEqual(api.app_version, "6.7.8 x64")  # arch suffix kept

    def test_layer_none_keeps_default(self):
        api = API.TelegramDesktop.Generate(system="windows", unique_id="gen-f")
        self.assertTrue(api.app_version.startswith("7.3.3"))

    def test_full_stack_wire_coherence(self):
        """Mint with the wire layer, build a client: version+lang_pack+tz all on _init_request."""
        try:
            from telethon.sessions import MemorySession
            from telethon.tl.alltlobjects import LAYER
        except ImportError:
            self.skipTest("telethon not installed")

        from tgmint.tl import TelegramClient

        api = API.TelegramDesktop.Generate(
            system="windows", unique_id="gold-coherence", layer=LAYER
        )
        client = TelegramClient(MemorySession(), api=api)
        request = client._init_request

        self.assertEqual(request.lang_pack, "tdesktop")
        # the app_version on the wire matches the version that really
        # speaks this wire layer
        self.assertTrue(request.app_version.startswith(TD_LAYERS[LAYER]))
        # the timezone blob is attached and coherent with the locale
        self.assertIsNotNone(request.params)
        self.assertIsNotNone(api.tz_zone)
        problems = Fingerprint.from_apidata(api).validate()
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
