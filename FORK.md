# What changed from opentele

tgmint continues [thedemons/opentele](https://github.com/thedemons/opentele)
1.15.1 (MIT) with its full git history. The tdata, session and API machinery
come from opentele. This page lists what tgmint changed and added.

## Why

opentele hasn't been updated since 2022, and its device data is frozen there:

- `API.TelegramDesktop.app_version` defaulted to `"3.4.3 x64"` (2022).
- The Windows pool had no Windows 11, and 3 of its 4 systems were end-of-life (7/8/8.1).
- The Linux pool claimed glibc 2.31–2.34 and the wrong `XWayland` casing
  (Telegram Desktop sends `Xwayland`).
- macOS stopped at 12.x, with no Apple Silicon identifiers.
- Android/iOS pools ended at 2021 flagships and SDK 31 / iOS 15.

A client that claims to be a current app while sending 2022 device data
doesn't look like the real app.

## Bugs fixed in opentele's code

| Bug | Fix |
|---|---|
| `exception.py` imported `PyQt5.QDataStream` at module level, so `import opentele.api` crashed without Qt | Lazy import in the one helper that uses it |
| `td/__init__.py` imported the whole tdata stack eagerly, so `TelegramClient` required PyQt5 even for plain MTProto | Lazy loading. tdata is now pure Python and Qt is an optional fallback |
| `OpenTeleException` inherited from `BaseException` and escaped every `except Exception:` | Now inherits `Exception` |
| `APIData.__eq__` was always `False` for subclass instances, and instances were unhashable | Compares the fingerprint fields; `__hash__` added |
| `Generate()` kept the class-default `app_version` whatever system it picked | Telegram Desktop picks a platform-correct version (`x64` on Windows, `arm64` on Apple Silicon, bare on Linux and Intel Macs) |

## Device data refreshed

Every pool was replaced with current, verifiable values. Each value in
`src/tgmint/api.py` and `src/tgmint/devices.py` has the source URL it was
checked against next to it, and `tgmint freshness` checks the app versions
against the official release channels. CI runs that check weekly.

| Where | opentele | tgmint |
|---|---|---|
| Telegram Desktop | 3.4.3 / Windows 10 | current release / Windows 11 |
| Telegram Android | 8.4.1 / SDK 31 | current release / SDK 31–36, 2024–25 flagships |
| Telegram iOS | 8.4 / iOS 14.8 / iPhone 13 Pro Max | current release / iOS up to 26 / iPhone up to 17 |
| Telegram macOS | 8.4 / macOS 12 | current release / macOS 12–26 with Apple Silicon |
| Linux | 7 desktops, glibc 2.31–2.34 | 6 desktops incl. KDE, glibc 2.35–2.41 |

The unverifiable Web K / Web Z / Webogram presets were removed.

## Added

Passkey login, Pyrogram-family support (kurigram, pyrofork, hydrogram),
session conversion between tdata, Telethon, Pyrogram and GramJS, Android app
import, QR login, the `.tgmint` backup file, `tgmint heal`, startup and ping
timing that match the official apps, and the `tgmint` CLI. See
[CHANGELOG.md](CHANGELOG.md) for the full list.

## Compatibility

The package is now `tgmint` (`from opentele.api import API` becomes
`from tgmint.api import API`). See
[Migration from opentele](docs/migration-from-opentele.md).
