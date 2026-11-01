"""TelegramDesktopFlatpak preset — values + inheritance (2026-11-01).

Provenance: flathub org.telegram.desktop stable 7444df4f (tdesktop commit
668a91bd); embedded build manifest passes -DTDESKTOP_API_ID=611335
-TDTESKTOP_API_HASH=d524b414d21f4d37f08684c1df41ac9c.
"""

import unittest

from tgmint.api import API


class TelegramDesktopFlatpakTest(unittest.TestCase):
    def test_values(self):
        self.assertEqual(API.TelegramDesktopFlatpak.api_id, 611335)
        self.assertEqual(
            API.TelegramDesktopFlatpak.api_hash,
            "d524b414d21f4d37f08684c1df41ac9c",
        )

    def test_distinct_from_classic_desktop(self):
        # the whole point: a second, current, verifiable official desktop id
        self.assertNotEqual(
            API.TelegramDesktopFlatpak.api_id, API.TelegramDesktop.api_id
        )
        self.assertNotEqual(
            API.TelegramDesktopFlatpak.api_hash, API.TelegramDesktop.api_hash
        )

    def test_shares_desktop_identity_fields(self):
        for field in (
            "device_model",
            "system_version",
            "app_version",
            "lang_code",
            "system_lang_code",
            "lang_pack",
        ):
            self.assertEqual(
                getattr(API.TelegramDesktopFlatpak, field),
                getattr(API.TelegramDesktop, field),
                field,
            )

    def test_generate_inherited_and_coherent(self):
        api = API.TelegramDesktopFlatpak.Generate(
            system="linux", unique_id="flatpak-1"
        )
        self.assertEqual(api.api_id, 611335)
        self.assertEqual(api.lang_pack, "tdesktop")
        # deterministic like every Generate()
        again = API.TelegramDesktopFlatpak.Generate(
            system="linux", unique_id="flatpak-1"
        )
        self.assertEqual(
            (api.device_model, api.system_version, api.app_version),
            (again.device_model, again.system_version, again.app_version),
        )

    def test_generate_keeps_flatpak_credentials(self):
        for system in ("windows", "macos", "linux"):
            api = API.TelegramDesktopFlatpak.Generate(system=system, unique_id="fp")
            self.assertEqual(api.api_id, 611335)
            self.assertEqual(api.api_hash, "d524b414d21f4d37f08684c1df41ac9c")


if __name__ == "__main__":
    unittest.main()
