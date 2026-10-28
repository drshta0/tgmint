# Fork notes — what changed against upstream opentele 1.15.1

> Written 2026-09-12 for the vendored copy inside tgosint; moved here 2026-09-14
> when the fork became its own repository. Paths below refer to this repo.

Upstream [opentele](https://github.com/th3c0d3br3ak3r/Opentele) 1.15.1, with its
**fingerprint data refreshed to 2026** and a small set of audited code fixes
(below). Everything else (tdata conversion, session format, API machinery) is
upstream, MIT-licensed (see `LICENSE`).

## Why

opentele is semi-abandoned. The machinery works, but the data it uses to make an
account look like a real official client is frozen around 2022:

- `API.TelegramDesktop.app_version` defaulted to `"3.4.3 x64"` (2022).
- The Windows pool had **no Windows 11** and was 3-of-4 EOL systems (7/8/8.1).
- The Linux pool claimed glibc 2.31–2.34 (Ubuntu 20.04-era) and the wrong
  `XWayland` casing (tdesktop sends `Xwayland`).
- macOS topped out at 12.x with no Apple Silicon identifiers at all.
- Android/iOS pools ended at 2021 flagships and SDK 31 / iOS 15.

An account presenting a 2022 fingerprint from a "current" client is exactly the
staleness signal an anti-abuse system notices (tgosint KNOWLEDGEBASE R06).

## Code audit (2026-09-12, full source review)

Every file was read: `api.py`, `devices.py`, `exception.py`, `utils.py`,
`debug.py`, all of `td/`, all of `tl/`. Findings:

**Fixed in this fork (post2):** (plus, on moving to this repo: the lazy `opentele.td` shim defined `__dir__` twice and the second copy crashed — removed)

| # | Bug | Fix |
|---|---|---|
| 1 | `exception.py` imported `PyQt5.QDataStream` at module level — `import opentele.api` crashed without Qt | Lazy import inside the one helper that uses it |
| 2 | `td/__init__.py` eagerly imported the whole tdata stack, so `TelegramClient` (which imports `td`) required PyQt5 even for plain MTProto work | PEP 562 lazy loading: `API`/`Generate`/`TelegramClient` now run headless; Qt loads only for tdata APIs (with a helpful ImportError pointing at the `qt` extra) |
| 3 | `OpenTeleException` inherited from `BaseException`, so its errors escaped every `except Exception:` handler (asyncio, loggers, generic cleanup) | Now inherits `Exception` |
| 4 | `APIData.__eq__` compared `type(__o) != APIData`, always True for subclass instances → equality was **always False**; and defining `__eq__` without `__hash__` made instances unhashable | Compares the eight fingerprint fields; `__hash__` added |

**Verified working under Telethon 1.43.2** (the version tgosint pins):

- The core fingerprint trick — opentele monkey-patches telethon's
  `InitConnectionRequest` constructor and passes a registry PID as
  `device_model`; the patched constructor swaps in the real fingerprint.
  Tested constructing the request exactly as telethon 1.43.2 does: the swap
  fires, the wire shows the real device model / system / app version /
  `lang_pack=tdesktop` (something stock Telethon cannot send).
- `client.start()` path, `_switch_dc`, `_on_login`, `_self_id`, `qr_login`
  internals used by the conversion methods all still exist in 1.43.2.
- Determinism of `Generate(unique_id=…)` unchanged.

**Noted, deliberately not changed:**

- `APIData.CustomInitConnectionList` grows by one entry per instance (upstream
  disabled removal in `destroy()`). Bounded and tiny for mint-per-login usage;
  touching the registry risks the PID lookup the wire swap depends on.
- `Generate()` kept the class-default `app_version` regardless of chosen
  system until 2026-10; TelegramDesktop's `Generate()` now picks a
  platform-coherent one (see "Known limitation" below for the mobile side).
- No network calls exist anywhere in the library — nothing phones home
  (checked every module).

## What changed (every value verified 2026-09-12)

| Where | Before | After |
|---|---|---|
| `api.py` TelegramDesktop | 3.4.3 x64 / Windows 10 | **7.2.8 x64** / Windows 11 |
| `api.py` TelegramAndroid | 8.4.1 (2522) / SDK 31 / SM-G998B | **12.10.1 (70382)** / SDK 35 / SM-S928B |
| `api.py` TelegramAndroidX | 8.4.1 (2522) / SDK 31 | **0.28.10 (1791)** / SDK 35 |
| `api.py` TelegramIOS | 8.4 / 14.8.1 / iPhone 13 Pro Max | **12.9.3** / 18.5 / iPhone 16 Pro Max |
| `api.py` TelegramMacOS | 8.4 / macOS 12.0.1 | **11.14.1** / macOS 15.5 |
| `devices.py` WindowsDevice | 10, 8, 8.1, 7 | **11, 10** |
| `devices.py` LinuxDevice | 7 DEs (no KDE, dead Unity), glibc 2.31–2.34 | 6 DEs incl. **KDE**, glibc **2.35–2.41**, `Xwayland` casing |
| `devices.py` macOSDevice | macOS 10.12–12.1, Intel-only identifiers | **12.0.1–26.1** + Apple Silicon identifiers (M1/M2, Mac Studio) |
| `devices.py` AndroidDevice | SDK 23–31, 2021-era devices | SDK **31–36** + 2024–25 flagships (S24/S23, Pixel 8/9, OnePlus 12/11, Xiaomi 14/13T Pro) |
| `devices.py` iOSDeivce | iPhone ≤13, iOS ≤15 | iPhone ≤**17**, iOS ≤**26** |
| `api.py` Web K / Z / Webogram | Chrome/96 UA, versions unverified | Chrome/**157.0.8103.15** UA; Web Z `12.0.47` (verified via version.txt/package.json); Web K `1.0.1 K` left as-is (build-time injected, unverifiable) |

Sources for the version numbers (fetched 2026-09-12):

- **Telegram Desktop 7.2.8** — `api.github.com/repos/telegramdesktop/tdesktop/releases/latest`
- **Android 12.10.1 (70382)** — APKPure mirror of the official APK (version + versionCode)
- **iOS 12.9.3** — Apple iTunes lookup API (`itunes.apple.com/lookup?id=686449807`)
- **Telegram X 0.28.10 (1791)** — APKPure (`org.thunderdog.challegram`)
- **macOS (TelegramSwift) 11.14.1** — `Telegram.xcodeproj` `MARKETING_VERSION` in the repo

## Using it

This is a **static 2026 snapshot — it will age again.** For anything that can
touch the network, prefer resolving the current version live (that is what
tgosint does: `src/tgosint/sessions/td_version.py`, with cache + pin fallback).
This fork exists for standalone/air-gapped use and for other projects that
import opentele directly.

    # try it without installing
    pip install -e .
    python selfcheck.py

    # install as a drop-in replacement (replaces the PyPI opentele)
    pip install -e .

    # verify which one you're on
    python -c "import opentele; print(opentele.__file__)"

tgosint (the project this fork was born in) does **not** yet depend on this repo — the product keeps its live
resolver and per-account fingerprint engine (`src/tgosint/sessions/fingerprint.py`),
which composes fine with either this fork or upstream opentele.

Known limitation (partially lifted, 2026-10): `Generate()` randomizes
`device_model` / `system_version`; for **TelegramDesktop** it now also picks a
platform-coherent `app_version` — the bare version on Linux and Intel macs,
`… x64` on Windows, `… arm64` on Apple-Silicon macs (per identifier), the way
tdesktop's 64-bit builds report it. The mobile presets (`TelegramAndroid`,
`TelegramIOS`, `TelegramMacOS`, …) still keep their class-default
`app_version`, which is fine: those app versions don't vary by hardware.

## Maintenance

Re-check quarterly (same cadence as `tgosint`s tools/check-fingerprint-freshness.md`):
run `selfcheck.py`, compare against the live sources above, bump the pools.
The `# refreshed 2026-09` comments mark every touched block.
