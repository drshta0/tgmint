"""Self-check for tgmint — prints what Generate() emits.

Install the package first (editable is fine), then run it from anywhere:

    pip install -e .
    python selfcheck.py

Confirms the refreshed pools are in effect: no 2022-era versions anywhere.
Exit code 1 if anything stale leaks through.
"""

import sys

import tgmint  # noqa: E402
from tgmint.api import API  # noqa: E402
from tgmint.devices import (  # noqa: E402
    AndroidDevice,
    LinuxDevice,
    WindowsDevice,
    iOSDeivce,
    macOSDevice,
)

print(f"tgmint loaded from: {tgmint.__file__}\n")

STALE_MARKERS = (
    "3.4.3", "8.4.1", "Windows 8", "Windows 7", "XWayland",
    "glibc 2.31", "glibc 2.32", "glibc 2.33", "glibc 2.34",
    "macOS 10.", "macOS 11.", "SDK 23", "SDK 30",
    "iPhone 17 Air", "iPhone 6S", "13 Mini",
)
# ("Chrome/96.0" was a web-preset UA marker; the web presets were removed
#  outright — so no Chrome UA can appear anywhere anymore.)


def stale_markers_in(value: str) -> list[str]:
    """Markers matched by value, ignoring hits glued onto a longer number.

    Needed so "8.4.1" (the 2022 Android app_version) still trips on a real
    "8.4.1" but NOT on the current iOS 18.4.1, where the hit is preceded
    by a digit.
    """
    hits = []
    for marker in STALE_MARKERS:
        pos = value.find(marker)
        if pos >= 0 and not (pos > 0 and value[pos - 1].isdigit()):
            hits.append(marker)
    return hits


def check(label: str, values: list[str], show: int = 12) -> list[str]:
    distinct = sorted(set(values))
    print(f"{label}: {len(values)} combos, {len(distinct)} distinct versions")
    for v in distinct[:show]:
        flag = "  <-- STALE" if stale_markers_in(v) else ""
        print(f"    {v}{flag}")
    if len(distinct) > show:
        print(f"    … (+{len(distinct) - show} more)")
    print()
    return distinct


# -- class defaults -------------------------------------------------------------

for name in ("TelegramDesktop", "TelegramDesktopFlatpak", "TelegramAndroid", "TelegramAndroidX",
             "TelegramIOS", "TelegramMacOS"):
    api = getattr(API, name)
    print(f"{name}: model={api.device_model!r} system={api.system_version!r} app={api.app_version!r}")

# web presets removed outright — none may come back
for gone in ("TelegramWeb_Z", "TelegramWeb_K", "Webogram"):
    assert not hasattr(API, gone), f"{gone} must stay removed (F9)"
print("web presets (Z/K/Webogram): absent, as intended (F9)\n")

# -- build the lazy pools, then inspect their distinct versions -------------------

WindowsDevice.__gen__()
LinuxDevice.__gen__()
macOSDevice.__gen__()
AndroidDevice.__gen__()
iOSDeivce.__gen__()

pools = {
    "win": check("Windows pool", [v.version for v in WindowsDevice.deviceList]),
    "linux": check("Linux pool", [v.version for v in LinuxDevice.deviceList]),
    "macos": check("macOS pool", list(macOSDevice.system_versions)),
    "android": check("Android SDK pool", list(AndroidDevice.system_versions)),
    "ios": check("iOS pool", [v.version for v in iOSDeivce.deviceList]),
}
models = sorted({v.model for v in iOSDeivce.deviceList})
print(f"iOS models ({len(models)}): {', '.join(models[:20])}"
      + (f" … (+{len(models) - 20})" if len(models) > 20 else "") + "\n")

# -- Generate() end-to-end --------------------------------------------------------

for _ in range(60):
    api = API.TelegramDesktop.Generate()
    line = f"{api.device_model!r} / {api.system_version!r} / {api.app_version!r}"
    if stale_markers_in(line):
        print("STALE LEAK:", line)

# -- sanity: determinism preserved -------------------------------------------------

a = API.TelegramDesktop.Generate(system="windows", unique_id="k1")
b = API.TelegramDesktop.Generate(system="windows", unique_id="k1")
assert (a.device_model, a.system_version) == (b.device_model, b.system_version), \
    "deterministic Generate(unique_id=…) broken"
print("deterministic Generate(unique_id=…): OK")

leaks = [(name, v) for name, values in pools.items()
         for v in values if stale_markers_in(v)]
if leaks:
    print(f"\nFAIL: {len(leaks)} stale values remain, e.g. {leaks[:5]}")
    sys.exit(1)
print("\nall pools fresh — no stale markers found")
