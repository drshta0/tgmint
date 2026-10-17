# Changelog
All notable changes to this project will be documented in this file.

## [v1.15.1.post5] - 2026-10-17

- passkeys: `login_with_passkey` sends `from_auth_key_id` as the signed long the TL field is. Telethon reads `key_id` unsigned, so half of all keys (>= 2**63) failed to serialize on the cross-DC hop (`struct.error: 'q' format requires ...`).

## [v1.15.1.post4] - 2026-10-09

### Fixed
- `tgmint/__init__.py` no longer imports `td` and `tl` eagerly (PEP 562
  lazy attributes). `tgmint.tl` extends Telethon's `TelegramClient` at
  import, and so does the pre-rename `opentele` build; loading both in one
  process raised `BaseException("err")` from `extend_class`. A caller that
  needs only `tgmint.passkeys` can now import it next to an installed
  `opentele` without touching `tgmint.tl`.

## [v1.15.1.post3] - 2026-10-08

### Changed
- **Import name is now `tgmint`** (distribution name `tgmint`, package `src/tgmint/`).
  `import opentele` no longer resolves from this wheel; install the
  `v1.15.1.post2` wheel beside it if you still need the old name.

### Added
- `tgmint.passkeys` — software passkeys for Telegram accounts, implemented
  from the official Android client source (TL layer 230):
  `register_passkey()` mints a WebAuthn credential (ES256/Ed25519, `fmt:none`
  attestation) on any account you hold an authorized session for and stores
  the private key locally; `login_with_passkey()` later logs an unauthorized
  client back in with just that file — no phone number, no OTP
  (handles home-datacenter switching and the 2FA cloud password path).
  Also `list_passkeys()` / `delete_passkey()` and the raw TL requests
  (`account.initPasskeyRegistration`, `account.registerPasskey`,
  `auth.initPasskeyLogin`, `auth.finishPasskeyLogin`, ...) usable directly
  with Telethon clients. Requires the optional `cryptography` package.
  Offline tests in `tests/test_passkeys.py` verify the WebAuthn bytes the
  way Telegram's server would (attestation parse, COSE key rebuild,
  signature verification). See `PASSKEYS.md`.

## [v1.15.1.post2] - 2026-09-14 (fork)

First release of the fork that is becoming **tgmint**. Import name is still `opentele`.

- Client fingerprint data refreshed to 2026-09 with cited sources (Telegram Desktop 7.2.8,
  Windows 11, glibc 2.35–2.41, macOS 12–26 + Apple Silicon, Android SDK 31–36, iOS ≤ 26).
- `OpenTeleException` now inherits `Exception` (was `BaseException`).
- `APIData.__eq__` compares the eight fingerprint fields (was always False); `__hash__` added.
- `opentele.td` loads lazily: PyQt5 is only required for tdata read/write (`[qt]` extra).
- Packaging: `pyproject.toml` (hatchling), `src/opentele/` layout, committed wheels removed.
- Includes upstream main's post-1.15.1 fixes (newer tdata map keys, awaitable `_on_login`).

## [v1.15](https://pypi.org/project/opentele/1.15/) - 2022-01-27

- Massive performance upgrade, UseCurrentSession is now 200x faster than before.
- `TDesktop` now has `PerformanceMode` which is enabled by default. It will now load and save tdata 200x faster.
- Huge performance boost when converting `TelegramClient` to `TDesktop`.
- Replace `inspect.stack()` with `inspect.currentframe()` in `OpenTeleException`. Using `inspect.stack()` is a stupid move, it's really slow.

## [v1.14](https://pypi.org/project/opentele/1.14/) - 2022-01-26

- `TelegramClient` will now use `TelegramDesktop` api by default.
- Fix a bug when saving tdata.

## [v1.13](https://pypi.org/project/opentele/1.13/) - 2022-01-21

- Fix `unique_id` not generated correctly in `API.Generate()`
- Added DC mismatched handling when authorizing a new client.

## [First Stable Release](https://pypi.org/project/opentele/1.13/) - 2022-01-20

- First stable release of opentele.