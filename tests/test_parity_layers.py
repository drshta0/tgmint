"""Offline tests for mobile layer coherence + parity.py.

Covers:
- Generate(layer=N) on TelegramAndroid / TelegramAndroidX / TelegramIOS
  resolves app_version by closest-lower against the verified tables in
  tgmint.layers (minted version's true layer <= N, and strictly newer
  than the next-lower table entry);
- layers below the verified table floor are REFUSED (ValueError) rather
  than silently minting an impossible (new-version, old-layer) pair;
- layer=None keeps the pinned-current behaviour, locale wiring intact;
- every table row in layers.py carries provenance (sha/URL comment);
- parity.PING_PRESETS / describe_envelope shape (bootstrap summary
  included since F5 shipped tgmint.bootstrap);
- the web presets are gone (F9).
"""
import re
import unittest
from pathlib import Path

from tgmint import layers
from tgmint.api import API
from tgmint.parity import PING_PRESETS, describe_envelope

TABLES = {
    API.TelegramAndroid: layers.ANDROID_LAYERS,
    API.TelegramAndroidX: layers.ANDROID_LAYERS,
    API.TelegramIOS: layers.IOS_LAYERS,
}


class TestClosestLowerSemantics(unittest.TestCase):
    """For every mobile preset and a spread of layers around the table."""

    def test_closest_lower_resolution(self):
        for preset, table in TABLES.items():
            known = sorted(table)
            floor, ceiling = known[0], known[-1]

            for n in range(floor - 3, ceiling + 3):
                if n < floor:
                    with self.assertRaises(ValueError, msg=f"{preset.__name__} layer={n}"):
                        preset.Generate(unique_id="cl", layer=n)
                    continue

                api = preset.Generate(unique_id="cl", layer=n)

                if n > ceiling:
                    # future layer: the pinned-current release stays coherent
                    self.assertEqual(
                        api.app_version, preset.app_version,
                        f"{preset.__name__} layer={n}",
                    )
                    continue

                expected_layer = max(k for k in known if k <= n)

                # exact row, or the closest lower one
                self.assertEqual(
                    api.app_version,
                    table[expected_layer],
                    f"{preset.__name__} layer={n}",
                )
                # the minted version's true layer never exceeds the wire layer
                self.assertLessEqual(expected_layer, n)
                # and it beats the next-lower table entry (closest-lower, not
                # any-lower): otherwise a newer coherent row was skipped
                lower_entries = [k for k in known if k < expected_layer]
                if lower_entries:
                    self.assertGreater(expected_layer, max(lower_entries))

    def test_layer_224_android_is_12_3_0(self):
        # Telethon 1.43.2 speaks 224; no Android release ever spoke
        # 222-226 (12.4-12.7 shipped 221, 12.8.0 jumped to 227), so the
        # newest coherent Android version is 12.3.0 — NOT the current
        # 13.1.0, which speaks 232.
        for preset in (API.TelegramAndroid, API.TelegramAndroidX):
            api = preset.Generate(unique_id="telethon-1.43.2", layer=224)
            self.assertEqual(api.app_version, "12.3.0 (6377)")
            self.assertNotEqual(api.app_version, API.TelegramAndroid.app_version)

    def test_future_layer_keeps_pin(self):
        for preset, table in TABLES.items():
            api = preset.Generate(unique_id="f", layer=max(table) + 5)
            self.assertEqual(api.app_version, preset.app_version)

    def test_layer_none_keeps_pin(self):
        for preset in TABLES:
            for uid in ("a", "b"):
                api = preset.Generate(unique_id=uid)
                self.assertEqual(api.app_version, preset.app_version)

    def test_layer_does_not_touch_device_or_locale_defaults(self):
        for preset in TABLES:
            with_layer = preset.Generate(unique_id="loc", layer=max(TABLES[preset]))
            without = preset.Generate(unique_id="loc")
            self.assertEqual(with_layer.device_model, without.device_model)
            self.assertEqual(with_layer.system_version, without.system_version)
            self.assertEqual(with_layer.lang_code, without.lang_code)
            self.assertEqual(with_layer.system_lang_code, without.system_lang_code)
            self.assertEqual(with_layer.tz_zone, without.tz_zone)

    def test_locale_still_applies_with_layer(self):
        api = API.TelegramAndroid.Generate(unique_id="ru-user", layer=224, locale="ru")
        self.assertEqual(api.app_version, "12.3.0 (6377)")
        self.assertEqual(api.lang_code, "ru")
        self.assertTrue(api.tz_zone)

        legacy = API.TelegramIOS.Generate(unique_id="x", locale=None)
        self.assertEqual((legacy.lang_code, legacy.system_lang_code), ("en", "en-US"))
        self.assertIsNone(legacy.tz_zone)

    def test_deterministic_with_layer(self):
        for preset, table in TABLES.items():
            layer = max(table)  # a layer every table resolves
            a = preset.Generate(unique_id="stable", layer=layer)
            b = preset.Generate(unique_id="stable", layer=layer)
            self.assertEqual(
                (a.device_model, a.system_version, a.app_version),
                (b.device_model, b.system_version, b.app_version),
            )

    def test_macos_has_no_layer_support_yet(self):
        # macOS stays pin-only (raw pbxproj URL 404s — documented);
        # the base Generate must not have grown a layer= passthrough.
        with self.assertRaises(TypeError):
            API.TelegramMacOS.Generate(unique_id="m", layer=224)


class TestProvenanceDiscipline(unittest.TestCase):
    """Every row of every layer table cites a sha or URL."""

    SOURCE = Path(layers.__file__).read_text()

    def test_every_row_has_provenance(self):
        for block in ("_TD_LAYERS", "_ANDROID_LAYERS", "_IOS_LAYERS_TABLE"):
            match = re.search(rf"{block}\s*:\s*[Dd]ict\[int, tuple\]\s*=\s*\{{(.*?)\}}", self.SOURCE, re.S)
            self.assertIsNotNone(match, f"{block} not found in layers.py")
            rows = [
                line for line in match.group(1).splitlines()
                if re.match(r"\s+\d+:\s+\(", line)
            ]
            self.assertTrue(rows, f"{block} has no rows")
            for line in rows:
                self.assertRegex(
                    line,
                    r"([0-9a-f]{40}|https?://)",
                    f"row without provenance in {block}: {line.strip()!r}",
                )

    def test_android_rows_are_first_hand(self):
        # each provenance note is a full commit sha (raw TLRPC.java was
        # fetched at that sha and LAYER read directly)
        for sha in layers._ANDROID_LAYERS.values():
            self.assertRegex(sha[1], r"^[0-9a-f]{40}$")

    def test_tables_exported(self):
        # closest-lower coverage sanity: android table spans the Telethon layer
        self.assertTrue(min(layers.ANDROID_LAYERS) <= 224 <= max(layers.ANDROID_LAYERS))
        self.assertEqual(layers.android_version_for_layer(227), "12.8.0 (6913)")
        self.assertIsNone(layers.android_version_for_layer(225))  # gap
        self.assertIsNone(layers.ios_version_for_layer(224))  # sparse by design


class TestParityHelpers(unittest.TestCase):
    def test_ping_presets_are_inert_data(self):
        self.assertIsInstance(PING_PRESETS, dict)
        self.assertEqual(
            set(PING_PRESETS),
            {"tdesktop", "android", "android_x", "ios", "macos"},
        )
        for preset, kwargs in PING_PRESETS.items():
            self.assertIn("ping_interval", kwargs)
            self.assertGreater(kwargs["ping_interval"], 0)

    def test_describe_envelope_shape(self):
        env = describe_envelope("android")
        self.assertEqual(
            set(env),
            {
                "api_id", "api_hash", "device_model", "system_version",
                "app_version", "system_lang_code", "lang_pack", "lang_code",
                "params", "layer", "bootstrap",
            },
        )
        self.assertEqual(env["api_id"], 6)
        self.assertEqual(env["lang_pack"], "android")
        self.assertEqual(env["params"], {})

    def test_describe_envelope_instance_with_layer(self):
        api = API.TelegramAndroid.Generate(unique_id="env", layer=224)
        env = describe_envelope(api, layer=224)
        self.assertEqual(env["app_version"], "12.3.0 (6377)")
        self.assertEqual(env["layer"], 224)  # explicit argument wins

    def test_describe_envelope_reverse_lookup(self):
        api = API.TelegramAndroid.Generate(unique_id="env2", layer=227)
        env = describe_envelope(api)  # no explicit layer
        self.assertEqual(env["app_version"], "12.8.0 (6913)")
        self.assertEqual(env["layer"], 227)

    def test_describe_envelope_tdesktop_pin_reverse(self):
        env = describe_envelope("tdesktop")
        self.assertEqual(env["app_version"], "7.3.3")
        self.assertEqual(env["layer"], 232)  # reverse lookup from TD_LAYERS

    def test_describe_envelope_tz_offset(self):
        api = API.TelegramIOS.Generate(unique_id="tz", layer=232)
        env = describe_envelope(api)
        # locale default ("auto") mints a zone -> params carries int seconds
        self.assertIn("tz_offset", env["params"])
        self.assertIsInstance(env["params"]["tz_offset"], int)

    def test_describe_envelope_rejects_junk(self):
        with self.assertRaises(ValueError):
            describe_envelope("web_z")  # removed with the web presets (F9)
        with self.assertRaises(TypeError):
            describe_envelope(42)


class TestWebPresetsRemoved(unittest.TestCase):
    def test_web_presets_gone(self):
        for gone in ("TelegramWeb_Z", "TelegramWeb_K", "Webogram"):
            self.assertFalse(
                hasattr(API, gone), f"{gone} must be removed"
            )
        self.assertTrue(hasattr(API, "TelegramMacOS"))  # the rest kept


class TestPinMatchesVerifiedTable(unittest.TestCase):
    """The current-version pin must be the string the official app PRINTS.

    Telegram's APK ships an ABI-split versionCode (13.1.0 -> 72291) while
    `app_version` on the wire carries the DrKLO build code (7229). The pin
    used to carry the split code, so the reverse layer lookup missed and
    parity reported `layer: None` for every pinned-current Android identity.
    """

    def test_android_pin_equals_the_verified_layer_row(self):
        # layers.py rows are first-hand from DrKLO TLRPC.java at a pinned sha
        self.assertEqual(API.TelegramAndroid.app_version, layers.ANDROID_LAYERS[232])
        self.assertEqual(API.TelegramAndroid.app_version, "13.1.0 (7229)")

    def test_pinned_table_agrees_with_the_presets(self):
        from tgmint.versions import PINNED

        self.assertEqual(PINNED["android"], API.TelegramAndroid.app_version)
        self.assertEqual(PINNED["android_x"], API.TelegramAndroidX.app_version)
        self.assertEqual(PINNED["ios"], API.TelegramIOS.app_version)
        self.assertEqual(PINNED["macos"], API.TelegramMacOS.app_version)
        self.assertEqual(PINNED["tdesktop"], API.TelegramDesktop.app_version)

    def test_no_pin_carries_a_split_version_code(self):
        # 5+ digit build codes are APK versionCodes, never printed strings
        from tgmint.versions import PINNED

        for app, version in PINNED.items():
            if "(" in version:
                code = version.split("(")[1].rstrip(")")
                self.assertLess(len(code), 5, f"{app}: split code leaked: {version!r}")

    def test_describe_envelope_reverse_lookup_of_the_pin(self):
        env = describe_envelope("android")
        self.assertEqual(env["app_version"], "13.1.0 (7229)")
        self.assertEqual(env["layer"], 232)  # reverse lookup now resolves
        # and the instance form agrees
        api = API.TelegramAndroid.Generate(unique_id="pin-env")
        self.assertEqual(describe_envelope(api)["layer"], 232)


class TestPresetDefaultsAreInTheirPools(unittest.TestCase):
    """A preset's (device_model, system_version) must exist in its own pool.

    The old class defaults were pairs the generator excludes — an iOS
    18.5 pair on a model that only ever ran 26.x, an Android model with no
    SDK-35 rows, a Windows board name the junk filter drops — so `API.X`
    (without Generate()) advertised an identity the pool says is impossible.
    """

    def test_mobile_defaults_exist_in_the_pool(self):
        from tgmint.devices import AndroidDevice, iOSDeivce

        AndroidDevice.__gen__()
        iOSDeivce.__gen__()

        android_rows = {(d.model, d.version) for d in AndroidDevice.deviceList}
        for preset in (API.TelegramAndroid, API.TelegramAndroidX):
            pair = (preset.device_model, preset.system_version)
            self.assertIn(pair, android_rows, preset.__name__)

        ios_rows = {(d.model, d.version) for d in iOSDeivce.deviceList}
        self.assertIn(
            (API.TelegramIOS.device_model, API.TelegramIOS.system_version), ios_rows
        )

    def test_desktop_default_device_is_a_real_board(self):
        from tgmint.devices import WindowsDevice

        WindowsDevice.__gen__()
        models = {d.model for d in WindowsDevice.deviceList}
        self.assertIn(API.TelegramDesktop.device_model, models)
        # and it is not one of the junk placeholders the pool filters out
        self.assertNotIn(
            API.TelegramDesktop.device_model, ("Desktop", "INVALID", "OEM")
        )
        self.assertIn(
            API.TelegramDesktop.system_version,
            {d.version for d in WindowsDevice.deviceList},
        )


if __name__ == "__main__":
    unittest.main()
