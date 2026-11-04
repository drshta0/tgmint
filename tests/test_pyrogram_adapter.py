"""Tests for tgmint.adapters.pyrogram.

Anti-tautology policy: every assertion compares the adapter's output
against fields of a Fingerprint *minted by tgmint's own* ``API.<Preset>``
pools at test time — never against constants copied from opentele-ng
fixtures (the bridge concept is credited in the module docstring, but the
proof obligations here are "kwargs == fingerprint", per-field, per preset).

The optional real-client test at the bottom runs only when a distribution
providing ``pyrogram`` (kurigram/pyrofork/hydrogram/…) is importable;
under a bare interpreter it skips, keeping the suite green.

References:
- https://docs.pyrogram.org/api/client (Client constructor kwargs)
- https://docs.pyrogram.org/telegram/functions/init-connection
- https://github.com/stufently/opentele — src/tl/pyrogram_bridge.py (concept)
"""

import unittest

from tgmint.adapters import (
    PYROGRAM_KWARGS_FIELDS,
    TDLIB_PARAMS,
    client_kwargs,
    installed_layer,
    pyrogram_kwargs,
    tdlib_params,
)
from tgmint.api import API
from tgmint.fingerprint import Fingerprint

try:  # optional real-client verification target
    import pyrogram  # noqa: F401
    from pyrogram import Client  # noqa: F401

    PYROGRAM_AVAILABLE = True
except Exception:  # nocov - environment dependent
    PYROGRAM_AVAILABLE = False


# The four preset families this adapter must serve.
PRESETS = (
    ("TelegramDesktop", {"system": "windows"}),
    ("TelegramAndroid", {}),
    ("TelegramAndroidX", {}),
    ("TelegramIOS", {}),
)


def _mint(preset: str, unique_id: str, **kwargs):
    """Mint via tgmint's own pools; returns (APIData, Fingerprint)."""
    api = getattr(API, preset).Generate(unique_id=unique_id, **kwargs)
    return api, Fingerprint.from_apidata(api)


class CoercionTest(unittest.TestCase):
    """Fingerprint (preferred) and legacy APIData paths agree exactly."""

    def test_apidata_instance_and_fingerprint_agree(self):
        for preset, extra in PRESETS:
            with self.subTest(preset=preset):
                api, fp = _mint(preset, "coerce-" + preset, **extra)
                self.assertEqual(
                    pyrogram_kwargs(api),
                    pyrogram_kwargs(fp),
                    f"{preset}: APIData path and Fingerprint path differ",
                )

    def test_apidata_class_uses_class_defaults(self):
        # preset classes (no Generate) carry the pinned 2026-10 defaults
        fp = Fingerprint.from_apidata(API.TelegramIOS)
        self.assertEqual(
            pyrogram_kwargs(API.TelegramIOS),
            {name: getattr(fp, name) for name in PYROGRAM_KWARGS_FIELDS},
        )

    def test_rejects_foreign_types(self):
        for bad in (None, "pyrogram", 2040, object()):
            with self.assertRaises(TypeError):
                pyrogram_kwargs(bad)


class KwargsEqualityTest(unittest.TestCase):
    """kwargs == fingerprint, per preset, per mint variant (anti-tautology)."""

    def test_kwargs_equal_fingerprint_fields_every_preset(self):
        for preset, extra in PRESETS:
            with self.subTest(preset=preset):
                api, fp = _mint(preset, "fields-" + preset, **extra)
                kwargs = pyrogram_kwargs(api)
                self.assertEqual(set(kwargs), set(PYROGRAM_KWARGS_FIELDS))
                for name in PYROGRAM_KWARGS_FIELDS:
                    self.assertEqual(
                        kwargs[name],
                        getattr(fp, name),
                        f"{preset}.{name}: kwargs != minted fingerprint",
                    )

    def test_locale_variants_flow_through(self):
        # legacy locale=None keeps en/en-US; explicit "ru" overrides — both
        # must surface verbatim in the kwargs, not normalized away
        cases = [
            ("TelegramDesktop", {"system": "linux", "locale": None}, ("en", "en-US")),
            ("TelegramDesktop", {"system": "linux", "locale": "ru"}, ("ru", "ru-RU")),
            ("TelegramAndroid", {"locale": "ru"}, ("ru", "ru-RU")),
            ("TelegramAndroidX", {"locale": None}, ("en", "en-US")),
            ("TelegramIOS", {"locale": "ru"}, ("ru", "ru-RU")),
        ]
        for preset, extra, expected_pair in cases:
            with self.subTest(preset=preset, extra=extra):
                api, fp = _mint(preset, "locale-" + preset, **extra)
                kwargs = pyrogram_kwargs(api)
                self.assertEqual((kwargs["lang_code"], fp.system_lang_code), expected_pair)
                self.assertEqual(kwargs["lang_code"], fp.lang_code)

    def test_layer_variant_supported_on_desktop(self):
        # layer= is a Generate() argument here; layer=224 -> tdesktop
        # 6.7.8 with the Windows arch suffix — and the kwargs must carry it.
        api, fp = _mint(
            "TelegramDesktop", "layer-desktop", system="windows", layer=224
        )
        self.assertEqual(api.app_version, "6.7.8 x64")
        self.assertEqual(pyrogram_kwargs(api)["app_version"], "6.7.8 x64")
        self.assertEqual(pyrogram_kwargs(api)["app_version"], fp.app_version)

    def test_deterministic_mint_gives_deterministic_kwargs(self):
        for preset, extra in PRESETS:
            with self.subTest(preset=preset):
                _, fp1 = _mint(preset, "stable-id", **extra)
                _, fp2 = _mint(preset, "stable-id", **extra)
                self.assertEqual(
                    pyrogram_kwargs(fp1), pyrogram_kwargs(fp2)
                )

    def test_kwargs_are_not_framework_defaults(self):
        # the adapter must present the MINTED device, never fall back to
        # pyrogram's own defaults (e.g. "Pyrogram 2.x" / the host machine)
        _, fp = _mint("TelegramDesktop", "not-defaults", system="windows")
        kwargs = pyrogram_kwargs(fp)
        self.assertEqual(kwargs["device_model"], fp.device_model)
        self.assertNotIn("Pyrogram", kwargs["app_version"])
        self.assertNotIn("api_id", kwargs)  # presentation kwargs stay pure


class ClientKwargsTest(unittest.TestCase):
    """client_kwargs = pyrogram_kwargs + credential passthrough."""

    def test_api_credentials_passthrough(self):
        for preset, extra in PRESETS:
            with self.subTest(preset=preset):
                api, fp = _mint(preset, "creds-" + preset, **extra)
                full = client_kwargs(api)
                self.assertEqual(full["api_id"], fp.api_id)
                self.assertEqual(full["api_hash"], fp.api_hash)
                for name in PYROGRAM_KWARGS_FIELDS:
                    self.assertEqual(full[name], getattr(fp, name))
                self.assertEqual(set(full) - {"api_id", "api_hash"}, set(PYROGRAM_KWARGS_FIELDS))

    def test_system_lang_code_opt_in(self):
        _, fp = _mint("TelegramAndroid", "slc", locale="ru")
        base = client_kwargs(fp)
        self.assertNotIn("system_lang_code", base)  # vanilla-pyrogram-safe
        extended = client_kwargs(fp, system_lang_code=True)
        self.assertEqual(extended["system_lang_code"], fp.system_lang_code)

    def test_tz_params_opt_in_shape(self):
        # locale=None is the legacy mint: no zone -> nothing added even if asked
        _, fp = _mint("TelegramDesktop", "tzp", system="windows", locale=None)
        self.assertIsNone(fp.tz_zone)
        legacy = client_kwargs(fp, tz_params=True)
        self.assertNotIn("init_connection_params", legacy)
        # an auto-locale mint carries a zone -> a single int tz_offset
        _, zone_fp = _mint("TelegramDesktop", "tzp2", system="windows", locale="auto")
        kwargs = client_kwargs(zone_fp, tz_params=True)
        self.assertIn("init_connection_params", kwargs)
        params = kwargs["init_connection_params"]
        self.assertEqual(set(params), {"tz_offset"})
        self.assertIsInstance(params["tz_offset"], int)
        self.assertLessEqual(abs(params["tz_offset"]), 14 * 3600)

    def test_overrides_pin_values(self):
        _, fp = _mint("TelegramIOS", "ovr")
        pinned = client_kwargs(fp, app_version="13.1.1")
        self.assertEqual(pinned["app_version"], "13.1.1")

    def test_init_connection_params_override_is_accepted(self):
        # #66: the key ``tz_params=True`` injects is also a legitimate
        # explicit override (pin or replace the dict); it used to be rejected
        # as an unknown fingerprint field name
        _, fp = _mint("TelegramIOS", "icp")
        pinned = client_kwargs(fp, init_connection_params={"tz_offset": 3600})
        self.assertEqual(pinned["init_connection_params"], {"tz_offset": 3600})
        # ... and it wins over what tz_params would inject
        _, zone_fp = _mint("TelegramDesktop", "icp2", system="windows", locale="auto")
        combined = client_kwargs(
            zone_fp, tz_params=True, init_connection_params={"tz_offset": -7200}
        )
        self.assertEqual(combined["init_connection_params"], {"tz_offset": -7200})

    def test_unknown_override_raises(self):
        _, fp = _mint("TelegramIOS", "typo")
        with self.assertRaises(TypeError):
            client_kwargs(fp, device_modle="typo")


class TDLibParamsTest(unittest.TestCase):
    """The TDLib exporter: exactly three strings."""

    def test_bundle_shape_and_values(self):
        for preset, extra in PRESETS:
            with self.subTest(preset=preset):
                _, fp = _mint(preset, "tdlib-" + preset, **extra)
                params = tdlib_params(fp)
                self.assertEqual(set(params), set(TDLIB_PARAMS))
                self.assertEqual(
                    sorted(params), ["app_version", "device_model", "system_version"]
                )
                for name in TDLIB_PARAMS:
                    self.assertEqual(params[name], getattr(fp, name))

    def test_tdlib_params_override(self):
        _, fp = _mint("TelegramDesktop", "tdlib-ovr", system="macos")
        self.assertEqual(
            tdlib_params(fp, app_version="x"),
            {name: ("x" if name == "app_version" else getattr(fp, name)) for name in TDLIB_PARAMS},
        )
        with self.assertRaises(TypeError):
            tdlib_params(fp, lang_code="x")  # not a TDLib parameter

    def test_apidata_path_supported(self):
        api = API.TelegramAndroid.Generate(unique_id="tdlib-apidata")
        self.assertEqual(tdlib_params(api)["device_model"], api.device_model)


class InstalledLayerTest(unittest.TestCase):
    def test_layer_is_none_or_positive_int(self):
        # without a pyrogram distribution: None; with one (kurigram in the
        # verification venv): the layer its raw schema announces
        value = installed_layer()
        self.assertTrue(value is None or (isinstance(value, int) and value > 0))


@unittest.skipUnless(
    PYROGRAM_AVAILABLE, "no pyrogram-family distribution installed (kurigram et al.)"
)
class RealKurigramClientTest(unittest.TestCase):
    """Construct a REAL Client offline (never .start()) and match attrs.

    Runs under the verification venv (kurigram installed); skips under a
    bare interpreter. Construction with ``in_memory=True`` touches no
    network and no disk session file.
    """

    def _mint_for_installed_layer(self):
        layer = installed_layer()
        if layer is None:  # nocov - only if pyrogram broke mid-session
            self.skipTest("layer unreadable")
        # mint with the layer the client will actually speak
        return Fingerprint.from_apidata(
            API.TelegramDesktop.Generate(
                system="windows", unique_id="kurigram-real", layer=layer
            )
        )

    def test_client_attributes_match_fingerprint(self):
        from pyrogram import Client

        fp = self._mint_for_installed_layer()
        client = Client("x", **client_kwargs(fp), in_memory=True)
        self.assertEqual(client.device_model, fp.device_model)
        self.assertEqual(client.system_version, fp.system_version)
        self.assertEqual(client.app_version, fp.app_version)
        self.assertEqual(client.lang_code, fp.lang_code)
        self.assertEqual(client.lang_pack, fp.lang_pack)
        self.assertEqual(client.api_id, fp.api_id)
        self.assertEqual(client.api_hash, fp.api_hash)
        self.assertFalse(client.is_initialized)  # constructed, never started

    def test_client_takes_extended_kwargs(self):
        # kurigram ≥2.x also accepts system_lang_code and the tz blob;
        # mint locale="ru" -> Europe/Moscow, DST-free since 2014, so the
        # now-based tz_offset() is deterministic for the comparison.
        import inspect

        from pyrogram import Client

        layer = installed_layer()
        if layer is None:  # nocov - only if pyrogram broke mid-session
            self.skipTest("layer unreadable")
        fp = Fingerprint.from_apidata(
            API.TelegramDesktop.Generate(
                system="windows", unique_id="kurigram-ext", layer=layer, locale="ru"
            )
        )
        signature = inspect.signature(Client.__init__).parameters
        if "system_lang_code" in signature and "init_connection_params" in signature:
            kwargs = client_kwargs(fp, system_lang_code=True, tz_params=True)
            client = Client("x", **kwargs, in_memory=True)
            # kurigram quirk (verified 2.2.26): Client.__init__ lowercases
            # every language field, so "ru-RU" arrives on the attrs as
            # "ru-ru". tgmint hands over the fingerprint verbatim; the
            # case-folding happens inside the framework.
            self.assertEqual(client.system_lang_code, fp.system_lang_code.lower())
            self.assertEqual(client.lang_code, "ru")
            self.assertEqual(
                client.init_connection_params, {"tz_offset": fp.tz_offset()}
            )
        else:  # nocov - vanilla pyrogram distribution installed instead
            self.skipTest("distribution lacks extended kwargs")


if __name__ == "__main__":
    unittest.main()
