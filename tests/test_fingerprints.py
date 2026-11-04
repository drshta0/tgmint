"""Offline tests for tgmint fingerprint realism — no network, no account.

Verifies the device pools only contain plausible device <-> OS pairings
(per-model Android SDK windows, per-identifier macOS ranges, per-model iOS
ranges), that junk board names are filtered, and that
``API.TelegramDesktop.Generate()`` picks a platform-coherent app_version.
"""
import unittest

from tgmint.api import API
from tgmint.devices import (
    AndroidDevice,
    iOSDeivce,
    LinuxDevice,
    macOSDevice,
    WindowsDevice,
)

# F8 deny set — placeholder strings that must never appear as a board name
JUNK_BOARD_MODELS = {
    "INVALID",
    "Default string",
    "Not Applicable",
    "OEM",
    "Desktop",
    "Notebook PC",
    "Portable PC",
    "0000000000",
}

ALL_POOLS = (WindowsDevice, LinuxDevice, macOSDevice, AndroidDevice, iOSDeivce)


def _macos_version_tuple(version: str):
    numbers = version.replace("macOS ", "").split(".")
    return (int(numbers[0]), int(numbers[1]))


class TestAndroidPool(unittest.TestCase):
    def setUp(self):
        AndroidDevice.__gen__()

    def test_android_pool_only_capable_models(self):
        for info in AndroidDevice.deviceList:
            matches = [
                (lo, hi)
                for pattern, lo, hi in AndroidDevice._SDK_RANGES
                if pattern.search(info.model)
            ]
            self.assertEqual(
                len(matches), 1, f"{info.model!r} must match exactly one rule"
            )
            lo, hi = matches[0]
            sdk = int(info.version.split()[1])
            self.assertTrue(
                lo <= sdk <= hi, f"{info.model} on {info.version} is impossible"
            )

        models = {d.model for d in AndroidDevice.deviceList}
        for forbidden in ("Huawei", "HTC", "Samsung GT-", "Xiaomi Redmi"):
            for model in models:
                self.assertNotIn(
                    forbidden, model, f"excluded vendor leaked: {model!r}"
                )

        pairs = [(d.model, d.version) for d in AndroidDevice.deviceList]
        self.assertEqual(len(pairs), len(set(pairs)), "duplicate (model, version)")

    def test_android_pool_contains_verified_flagships(self):
        models = {d.model for d in AndroidDevice.deviceList}
        self.assertIn("Samsung SM-S928B", models)
        self.assertIn("Google Pixel 9", models)
        by_model = {
            m: sorted(
                int(d.version.split()[1])
                for d in AndroidDevice.deviceList
                if d.model == m
            )
            for m in ("Samsung SM-G973F", "Google Pixel 9")
        }
        # S10 2019: max Android 12 -> SDK 31 only
        self.assertEqual(by_model["Samsung SM-G973F"], [31])
        # Pixel 9: ships Android 14 -> SDK 34..36
        self.assertEqual(by_model["Google Pixel 9"], [34, 35, 36])


class TestWindowsPool(unittest.TestCase):
    def setUp(self):
        WindowsDevice.__gen__()

    def test_windows_pool(self):
        versions = {d.version for d in WindowsDevice.deviceList}
        self.assertEqual(versions, {"Windows 11 x64", "Windows 10 x64"})

        for info in WindowsDevice.deviceList:
            self.assertEqual(info.suffix, "x64")
            self.assertNotIn(info.model, JUNK_BOARD_MODELS)
            self.assertNotIn("&#", info.model)
            self.assertNotIn("\\", info.model)

    def test_linux_pool_has_no_junk_names(self):
        LinuxDevice.__gen__()
        for info in LinuxDevice.deviceList:
            self.assertNotIn(info.model, JUNK_BOARD_MODELS)
            self.assertNotIn("&#", info.model)
            self.assertNotIn("\\", info.model)


class TestIOSPool(unittest.TestCase):
    def setUp(self):
        iOSDeivce.__gen__()

    def test_ios_pool(self):
        expected_names = {name for name, _, _ in iOSDeivce.device_models}
        ranges = {name: (lo, hi) for name, lo, hi in iOSDeivce.device_models}

        for info in iOSDeivce.deviceList:
            self.assertIn(info.model, expected_names)
            major = int(info.version.split(".")[0])
            lo, hi = ranges[info.model]
            self.assertTrue(
                lo <= major <= hi, f"{info.model} on iOS {info.version} impossible"
            )

        names = {d.model for d in iOSDeivce.deviceList}
        self.assertEqual(names, expected_names)
        for name in names:
            self.assertNotIn("17 Air", name, "'iPhone 17 Air' does not exist")
            self.assertNotIn("6S", name)
            self.assertNotIn("13 Mini", name)

        self.assertIn("iPhone Air", names)
        self.assertIn("iPhone 13 mini", names)

        # every supported model actually produced at least one row
        self.assertEqual(len(ranges), len(iOSDeivce.device_models))


class TestMacOSPool(unittest.TestCase):
    def setUp(self):
        macOSDevice.__gen__()

    def test_macos_pool(self):
        # re-derive the allowed (name, version, arch) rows straight from the
        # per-identifier table, using the same FromIdentifier helper
        allowed = set()
        for identifier, (min_ver, max_ver, arch) in macOSDevice._IDENTIFIER_INFO.items():
            name = macOSDevice.FromIdentifier(identifier)
            for version in macOSDevice.system_versions:
                ver = _macos_version_tuple(version)
                # same semantics as macOSDevice.__gen__: exact lower bound,
                # major-only upper bound ("through this major")
                if ver >= min_ver and ver[0] <= max_ver[0]:
                    allowed.add((name, version, arch))

        for info in macOSDevice.deviceList:
            self.assertIn(
                (info.model, info.version, info.suffix),
                allowed,
                f"impossible mac row: {info.model} / {info.version} / {info.suffix!r}",
            )

        # Mac Studio shipped on 12.3 — must never pair with 12.0.1/12.1
        for info in macOSDevice.deviceList:
            if info.model == "Mac Studio":
                self.assertNotIn(info.version, ("macOS 12.0.1", "macOS 12.1"))

        names = {d.model for d in macOSDevice.deviceList}
        self.assertIn("Mac mini", names)

        # the 12" MacBook line died on Ventura — nothing above macOS 13
        for info in macOSDevice.deviceList:
            if info.model == "MacBook":
                self.assertLessEqual(
                    _macos_version_tuple(info.version)[0], 13,
                    f"MacBook past Ventura: {info.version}",
                )

        # arm64 suffix only on Apple-Silicon identifiers' rows
        arm64_names = {
            macOSDevice.FromIdentifier(identifier)
            for identifier, (_, _, arch) in macOSDevice._IDENTIFIER_INFO.items()
            if arch == "arm64"
        }
        for info in macOSDevice.deviceList:
            if info.suffix == "arm64":
                self.assertIn(info.model, arm64_names)
            elif info.model not in arm64_names:
                self.assertEqual(info.suffix, "")
            else:
                # a name shared by Intel and Apple-Silicon siblings may be ""
                self.assertIn(info.suffix, ("", "arm64"))


class TestDesktopGenerate(unittest.TestCase):
    def test_desktop_generate_coherent(self):
        base = API.TelegramDesktop.app_version
        for system in ("windows", "macos", "linux"):
            for uid in ("k1", "k2", "old.session", "12345"):
                api = API.TelegramDesktop.Generate(system=system, unique_id=uid)
                self.assertIn(api.app_version, (base, f"{base} x64", f"{base} arm64"))
                if api.app_version != base:
                    self.assertTrue(api.app_version.startswith(base + " "))

        # windows rows carry x64 in both system_version and app_version
        for uid in ("w1", "w2", "w3"):
            api = API.TelegramDesktop.Generate(system="windows", unique_id=uid)
            self.assertIn(" x64", api.system_version)
            self.assertIn(" x64", api.app_version)

        # linux rows never carry an arch suffix
        for uid in ("l1", "l2", "l3"):
            api = API.TelegramDesktop.Generate(system="linux", unique_id=uid)
            self.assertEqual(api.app_version, base)
            self.assertTrue(api.system_version.startswith("Linux"))

        # macos rows are either bare (Intel) or arm64 (Apple Silicon)
        for uid in ("m1", "m2", "m3", "m4"):
            api = API.TelegramDesktop.Generate(system="macos", unique_id=uid)
            self.assertIn(api.app_version, (base, f"{base} arm64"))
            self.assertTrue(api.system_version.startswith("macOS "))

    def test_desktop_preset_matches_pool(self):
        self.assertEqual(API.TelegramDesktop.system_version, "Windows 11 x64")
        self.assertIn(API.TelegramDesktop.system_version, WindowsDevice.system_versions)


class TestDeterminism(unittest.TestCase):
    def test_random_device_deterministic(self):
        for pool in ALL_POOLS:
            for uid in ("abc", "old.session", "42"):
                a = pool.RandomDevice(uid)
                b = pool.RandomDevice(uid)
                self.assertEqual((a.model, a.version), (b.model, b.version))

    def test_generate_deterministic(self):
        presets = [
            API.TelegramAndroid,
            API.TelegramAndroidX,
            API.TelegramIOS,
            API.TelegramMacOS,
        ]
        for preset in presets:
            a = preset.Generate(unique_id="determinism-check")
            b = preset.Generate(unique_id="determinism-check")
            self.assertEqual(
                (a.device_model, a.system_version, a.app_version),
                (b.device_model, b.system_version, b.app_version),
            )

        for system in ("windows", "macos", "linux"):
            a = API.TelegramDesktop.Generate(system=system, unique_id="k")
            b = API.TelegramDesktop.Generate(system=system, unique_id="k")
            self.assertEqual(
                (a.device_model, a.system_version, a.app_version),
                (b.device_model, b.system_version, b.app_version),
            )


class TestNoDuplicates(unittest.TestCase):
    def test_no_duplicate_deviceinfo(self):
        for pool in ALL_POOLS:
            pool.__gen__()
            rows = [(d.model, d.version, d.suffix) for d in pool.deviceList]
            self.assertEqual(
                len(rows),
                len(set(rows)),
                f"duplicate DeviceInfo rows in {pool.__name__}",
            )


if __name__ == "__main__":
    unittest.main()


#: Board identifiers Apple lists as macOS 26 (Tahoe) compatible —
#: https://support.apple.com/en-us/122867 — i.e. every Apple-Silicon Mac
#: plus the four Intel holdovers 26 still supports. The per-identifier table
#: must cap exactly these at major 26 and nothing else (review finding #53).
MACOS_26_IDENTIFIERS = {
    # Apple Silicon
    "MacBookAir10,1",  # MacBook Air (M1, 2020)
    "MacBookPro17,1",  # MacBook Pro (13-inch, M1, 2020)
    "MacBookPro18,1",  # MacBook Pro (14-inch, M1 Pro, 2021)
    "MacBookPro18,2",
    "MacBookPro18,3",  # MacBook Pro (16-inch, M1 Pro/Max, 2021)
    "MacBookPro18,4",
    "iMac21,1",  # iMac (24-inch, M1, 2021)
    "iMac21,2",
    "Macmini9,1",  # Mac mini (M1, 2020)
    "MacStudio1,1",  # Mac Studio (2022)
    "MacStudio1,2",
    # Intel holdovers (26 is the last macOS with Intel support)
    "MacBookPro16,1",  # MacBook Pro (16-inch, 2019)
    "MacBookPro16,2",  # MacBook Pro (13-inch, 2020, four ports)
    "MacBookPro16,4",  # MacBook Pro (16-inch, 2019, 5600M SKU)
    "iMac20,1",  # iMac (27-inch, 2020)
    "iMac20,2",
    "MacPro7,1",  # Mac Pro (2019)
}


class TestMacOSCapConsistency(unittest.TestCase):
    """The mac version ceiling is one rule, not a per-entry guess (#53)."""

    def test_only_tahoe_supported_identifiers_cap_at_26(self):
        capped = {
            identifier
            for identifier, (_min_ver, max_ver, _arch) in macOSDevice._IDENTIFIER_INFO.items()
            if max_ver[0] == 26
        }
        self.assertEqual(capped, MACOS_26_IDENTIFIERS)

    def test_every_apple_silicon_identifier_runs_macos_26(self):
        # Apple ships 26 on every Apple-Silicon Mac — an arm64 row capped at
        # 15 was the inconsistency #53 reported (the 2020 M1 machines)
        for identifier, (_min_ver, max_ver, arch) in macOSDevice._IDENTIFIER_INFO.items():
            if arch != "arm64":
                continue
            with self.subTest(identifier=identifier):
                self.assertEqual(max_ver[0], 26)

    def test_the_m1_2020_machines_get_26_rows(self):
        macOSDevice.__gen__()
        rows = {(info.model, info.version, info.suffix) for info in macOSDevice.deviceList}
        for model in ("MacBook Air", "MacBook Pro", "iMac", "Mac mini"):
            with self.subTest(model=model):
                got = {version for name, version, _suffix in rows if name == model}
                self.assertTrue(
                    any(version.startswith("macOS 26.") for version in got),
                    f"{model} has no macOS 26 row: {sorted(got)}",
                )


class TestSystemVersionsDeclaration(unittest.TestCase):
    """No dead base default: every pool declares its own list (#47)."""

    def test_the_base_class_has_no_system_versions(self):
        from tgmint.devices import GeneralDesktopDevice, SystemInfo

        # the base default was inherited-but-never-read; a pool that forgets
        # its own list must fail loudly instead of generating nothing
        self.assertNotIn("system_versions", SystemInfo.__dict__)
        self.assertNotIn("system_versions", GeneralDesktopDevice.__dict__)

    def test_every_concrete_pool_declares_its_own_list(self):
        for pool in (WindowsDevice, LinuxDevice, macOSDevice, AndroidDevice, iOSDeivce):
            with self.subTest(pool=pool.__name__):
                self.assertIn("system_versions", pool.__dict__)


class TestDesktopBoardStringAgreement(unittest.TestCase):
    """Windows and Linux pools must agree on the wire board string (#58)."""

    def setUp(self):
        WindowsDevice.__gen__()
        LinuxDevice.__gen__()

    def test_the_two_desktop_pools_emit_the_same_model_set(self):
        windows = {info.model for info in WindowsDevice.deviceList}
        linux = {info.model for info in LinuxDevice.deviceList}
        self.assertTrue(windows)
        self.assertEqual(windows, linux)

    def test_no_pool_model_keeps_an_underscore(self):
        # tdesktop drops the underscores the SMBIOS product name carries
        # ("Z97_A" is reported as "Z97A"); Linux used to keep them
        for pool in (WindowsDevice, LinuxDevice):
            junk = [info.model for info in pool.deviceList if "_" in info.model]
            with self.subTest(pool=pool.__name__):
                self.assertEqual(junk, [])
