# Migrating from opentele

tgmint is the continuation of
[opentele](https://github.com/thedemons/opentele) (the rename landed in
v1.15.1.post3). Most code moves with a one-line import change; the list below
covers everything that is not a pure rename.

## Import renames

Every `opentele.x` module is `tgmint.x`, and the names inside are unchanged:

| opentele (≤ 1.15.1.post2) | tgmint |
|---|---|
| `from opentele.api import API, CreateNewSession, UseCurrentSession` | `from tgmint.api import API, CreateNewSession, UseCurrentSession` |
| `from opentele.td import TDesktop` | `from tgmint.td import TDesktop` |
| `from opentele.tl import TelegramClient` | `from tgmint.tl import TelegramClient` |
| `from opentele.exception import OpenTeleException` | `from tgmint.exception import OpenTeleException` |

A project-wide `sed -i 's/opentele/tgmint/g'` over your sources is the whole
migration for typical use. Note that tgmint installs beside (not over) an
existing `opentele` package — if you have the old one installed, remove it or
adjust your imports, since both will keep resolving.

New modules have no opentele counterpart: `tgmint.fingerprint` (the
framework-neutral `Fingerprint` object), `tgmint.sidecar` (per-account sticky
identities), `tgmint.layers` (wire-layer ↔ app-version coherence),
`tgmint.versions` (offline-first version resolver), `tgmint.locales`, and
`tgmint.passkeys`.

## PyQt5 is gone from the default install

Upstream imported PyQt5 eagerly, so even Telethon-only use pulled ~50 MB of
wheels. tgmint first made the import lazy; the tdata codec is now **pure
Python** (its own `QDataStream` implementation) and PyQt5 is not a dependency
at all.

- If you only use `API`, `TelegramClient`, minting, passkeys, or the CLI:
  nothing to do — no Qt anywhere.
- If you want the old PyQt5-backed code path (e.g. as a cross-check), it
  remains available as a fallback extra:

  ```pip
  pip install tgmint[qt]
  ```

  Without it, touching tdata APIs with the pure parser unavailable raises an
  `ImportError` that names the `[qt]` extra.

## Extras

| Extra | Installs | Needed for |
|---|---|---|
| *(none)* | telethon, tgcrypto | everything below except the two rows here |
| `tgmint[qt]` | PyQt5 | optional legacy fallback for the tdata codec |
| `tgmint[passkeys]` | cryptography | `tgmint.passkeys` (key generation / signing) |

## The sidecar pattern — mint once, reload ever after

Telegram remembers the device that signed in, so an account whose
`device_model` / `app_version` changes on every login is exactly the anomaly
fingerprint minting exists to avoid. The discipline the library pushes:

1. **Mint once** per account — deterministically (`unique_id=...`) or at first
   run — and save the identity next to the session file:

   ```python
   from tgmint.fingerprint import Fingerprint
   from tgmint.sidecar import sidecar_path_for

   fp = Fingerprint.from_apidata(API.TelegramDesktop.Generate(unique_id="acc1"))
   fp.save(sidecar_path_for("acc1.session"))   # atomic write, mode 0600
   ```

2. **Reload ever after** — every later start of that session loads the
   sidecar instead of re-rolling:

   ```python
   fp = Fingerprint.load(sidecar_path_for("acc1.session"))
   ```

Sidecars are small JSON files (stamped with a `schema_version`) written with
the same atomic-and-private discipline as the passkey store. Treat them like
the session file itself: never commit them, never share them.

## API changes to review

- **Web presets removed.** `API.TelegramWeb_Z`, `API.TelegramWeb_K` and
  `API.Webogram` are gone: their version strings are injected at web-build
  time and cannot be verified from source, so shipping them as "official
  fingerprints" was a claim we could not back. Migrate to a desktop or mobile
  preset.
- **No global monkey-patch.** Upstream replaced Telethon's
  `InitConnectionRequest.__init__` process-wide. tgmint's
  `tgmint.tl.TelegramClient` scopes the override to itself — the wire result
  is identical, but two extended clients can now coexist in one process. If
  you *relied* on the patch applying to a stock
  `telethon.TelegramClient`, switch to `tgmint.tl.TelegramClient`.
- **`Generate()` is coherence-aware.** `API.TelegramDesktop.Generate()` picks
  a platform-coherent `app_version` suffix (`x64` / `arm64` / bare); all
  presets accept `layer=N` so the minted version genuinely spoke that wire
  layer (e.g. `layer=224` → a tdesktop release that actually ran layer 224,
  not the newest one); `locale="auto"` (the default) draws a coherent
  language triple instead of always `en` / `en-US`. Pass `locale=None` for the
  legacy behavior.
- **Exceptions are `Exception`s.** `OpenTeleException` inherits from
  `Exception` (it was `BaseException`, so its errors escaped every
  `except Exception:` handler). If you caught opentele errors with
  `except BaseException:`, tighten that to `except Exception:` — or better,
  catch `OpenTeleException` directly.
- **Fresh data.** All version/device pools were refreshed from cited live
  sources and a resolver keeps them current; code that hard-coded upstream's
  2022 values ("3.4.3 x64", SDK 31, …) should drop them and mint instead.

## Getting help

- Framework support matrix: [Frameworks](frameworks/index.md)
- What changed and why: [FORK.md](https://github.com/drshta0/tgmint/blob/main/FORK.md),
  [CHANGELOG.md](https://github.com/drshta0/tgmint/blob/main/CHANGELOG.md)
- Found a migration case this page misses? Open an
  [issue](https://github.com/drshta0/tgmint/issues).
