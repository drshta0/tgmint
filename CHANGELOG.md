# Changelog
All notable changes to this project will be documented in this file.

## [v1.16.0] - 2026-10-28

The "all frameworks" release — everything below was built, tested and
merged in one working session by a six-agent build council (see
ACKNOWLEDGMENTS.md for ported-code credit).

### Added
- **Mobile layer coherence**:
  first-hand-verified Android version↔layer table (214=12.0.0, 216=12.1.1,
  221=12.3.0, 227=12.8.0, 232=13.1.0 — each row verified by reading
  `LAYER` in DrKLO's TLRPC.java fetched at the release commit sha) and an
  iOS table (232=13.1.1, sparse by design). `API.TelegramAndroid/
  AndroidX/IOS.Generate(..., layer=N)` picks the release that genuinely
  spoke that layer (closest-lower; e.g. Telethon's layer 224 → Android
  `12.3.0 (6377)`, because no Android release ever spoke 222–226). Layers
  below the verified floor raise `ValueError` — refusing to mint an
  impossible (app_version, layer) pair beats lying. macOS stays pin-only
  (upstream raw URL 404s).
- **Session codec matrix** — `tgmint.codec` (stdlib-only,
  ported from TGConvertor with credit): readers Telethon SQLite+String,
  Pyrogram string (current + two 1.x layouts) + SQLite v3, kurigram
  SQLite v7 (schema-detected), GramJS string, tdata; writers Telethon
  SQLite (schema 7) + String (byte-identical to real `StringSession.save()`,
  padding kept), Pyrogram SQLite both variants + string, GramJS string.
  36 from→to cells round-trip offline with seeded auth keys; Telethon
  cells verified against real telethon; Pyrogram-family cells labeled
  self-consistent (no oracle installed); GramJS cross-checked against
  TGConvertor semantics.
- **Pyrogram-family adapter** — `tgmint.adapters.pyrogram`:
  `pyrogram_kwargs`/`client_kwargs` (Fingerprint or legacy APIData → the
  five native `Client` kwargs; no monkey-patching; kurigram ≥2.x opt-ins
  for `system_lang_code` and `init_connection_params={"tz_offset": …}`),
  `tdlib_params()` export, `installed_layer()` soft probe. Verified
  against a real kurigram 2.2.26 `Client` constructed offline (venv);
  framework quirk documented: kurigram lowercases language codes.
- **CLI v1** — `tgmint` / `python -m tgmint`:
  `mint | inspect | audit | freshness | parity | convert | doctor`, all
  `--json`-able, exit codes 0/1/2, zero new dependencies; `tgmint.audit`
  pure library (coherence, staleness vs pins — outdated-by-layer-coherence
  is a warning, unknown release is a problem).
- **Qt-free tdata** — pure-Python `QDataStream`
  (`tgmint.td.qdatastream`, ported from opentele-ng with credit;
  Qt_5_1 streams are BIG-ENDIAN, verified empirically against PyQt5).
  PyQt5 is now an opt-in fallback (`TGMINT_TDATA_QT=1`); tdata read/write
  verified with PyQt5 fully blocked.
- **`tgmint.parity`** — inert per-preset ping-cadence data +
  `describe_envelope()` (the exact initConnection field dict incl.
  `lang_pack`, `tz_offset`, wire layer) used by `tgmint parity`.
  Bootstrap-sequence parity deliberately NOT included: no live oracle
  exists, and a golden test over a hypothesis would only assert itself.
- **CI freshness watchdog** — weekly job: stale-marker
  selfcheck + live version drift vs `PINNED` (network failure degrades
  to pin, so only genuine drift fails), opens/updates a tracking issue.
- Docs: `docs/frameworks.md` (honest per-framework support matrix),
  `docs/migration-from-opentele.md`, `docs/bot-api.md` (PTB/aiogram:
  no fingerprint surface exists — documented, not papered over),
  `ACKNOWLEDGMENTS.md`, mkdocs rebrand + nav.

### Changed
- **Web presets removed** (`API.TelegramWeb_Z`, `TelegramWeb_K`,
  `Webogram`, and their `versions.py` pin/fetcher): their versions are
  injected at build time and unverifiable from source — a stale preset
  is worse than none.
- `tgmint.tl.TelegramClient` scoped wire patch (no more PID-through-
  `device_model` smuggling); `lang_pack` + `tz_offset` params reach the
  wire, asserted byte-level by golden tests.
- `kMaxAccounts` 3 → 6 (real Telegram Premium cap).
- tdata read tolerance for newer map keys (`lskType` 0x17–0x1E:
  RoundPlaceholder, InlineBotsDownloads, MediaLastPlaybackPositions,
  BotStorages, Prefs) ported from opentele-ng (read side only); the
  `lskWebviewTokens` branch no longer sets the finished flag and
  truncates every later map entry.
- `[qt]` extra is now the opt-in fallback path, not a requirement.
- `tgmint` console-script entry point (`[project.scripts]`).

### Security
- The upstream author's 2022 tdata test fixture (`tests/test_profile3.8/`,
  credential-shaped) is untracked from git; the dead live-network test
  runners that referenced it are removed (history purge deliberately NOT
  done — local main tracks origin; a solo follow-up event if ever).

## [v1.16.0] - 2026-10-28 (continued — earlier build-log notes)

### Added
- **Core data modules**: `tgmint.fingerprint`
  (`Fingerprint` frozen dataclass — the framework-neutral identity object
  with `tz_offset()` DST-aware, `validate()` coherence checks,
  `to_dict/from_dict`, `from_apidata()` bridge, and `save()/load()`
  sidecar persistence with the passkey-file write discipline),
  `tgmint.locales` (weighted, internally-coherent
  lang/system-lang/timezone triples, deterministic per `unique_id`),
  `tgmint.layers` (wire-layer → tdesktop-release table built from
  tdesktop's api.tl bump commits and verified via the compare API:
  Telethon 1.43.2 speaks layer 224, whose newest real tdesktop is
  **6.7.8**, not 7.x), and `tgmint.versions` /
  `tgmint.sidecar` (offline-first live version resolver — fresh cache →
  one network lookup → stale cache → pin, never blocks a login; atomic
  0600 sidecar store).
- `API.Generate(...)` gains `locale="auto"` (default): coherent locale
  triple + timezone on the minted identity (explicit codes like
  `locale="ru"` accepted; `locale=None` keeps the legacy `en`/`en-US`).
  `API.TelegramDesktop.Generate(...)` also gains `layer=N`: the
  app_version is picked from `tgmint.layers` so the identity claims a
  release that genuinely spoke the wire layer (e.g. `layer=224` →
  `6.7.8 x64`), with gap layers resolving to the closest lower release.

### Security
- tdata master key is per-instance again: `TDesktop.__generateLocalKey`'s
  performance-mode branch installed a hardcoded constant
  `localKey`/`passcodeKeySalt`/`passcodeKey`/`passcodeKeyEncrypted` — one
  PUBLIC master key shared by every tdata this library has ever written.
  Both the empty-passcode and set-passcode paths now mirror real tdesktop:
  a random 256-byte `localKey` (no KDF — that is what makes the fast path
  fast) wrapped in a `passcodeKey` derived from a fresh random salt.
  Reading old constant-key tdata still works (the read path derives
  everything from the salt stored in the file); only the write path
  changed. `kPerformanceMode` now only skips the `config` file
  read/write inside tdata.
- `MapData._settingsKey` is a random per-instance `FileKey` instead of the
  shared hardcoded `1851671142505648812` (which leaked into every folder
  this library wrote).
- `PasskeyStore.save` writes atomically and private from the first byte:
  temp file created `0600` via `os.open` in the same directory, `fsync`,
  `os.replace`, then a final `chmod 0600` that also covers pre-existing
  `0644` files. The old plain `open()` exposed the private key
  world-readable until a later `chmod`, and a crash mid-write left
  truncated JSON.
- `OpenTeleException` no longer retains caller frames: the old
  `self.frame = inspect.currentframe()` (and the `inspect.stack()` /
  synthetic-`TracebackType` dance in `Expects()`) pinned every caller
  local — passwords, keys, sessions — for the exception's lifetime.
  Caller class/method info is derived eagerly and only the derived
  strings are kept; `str()` output keeps the `Called by ...` format and
  `stack_index` is still accepted.
- `login_with_passkey` persists the bumped signature counter
  (`store.save()`) immediately after producing an assertion, before any
  network attempt — a failed login no longer leaves a reusable counter
  behind.

### Fixed
- No more `raise BaseException(...)`: `QRLoginToNewClient`'s connect
  failure now raises `OpenTeleException` (with the OSError chained);
  `@override` misuse raises `ValueError`; `extend_class` attribute
  conflicts raise `RuntimeError` naming the attribute (the old
  `BaseException("err")` plus a stray `print` is gone, and the fix-list
  catch-all in `utils.getattr` is narrowed to
  `AttributeError`/`Exception`). These were outright crashes on
  Python 3.13, which forbids `raise BaseException` style misuse from
  breaking `except Exception` handling.
- `MTP.DcOptions.applyOneGuarded` actually dedups: the old loop
  `continue`d past a matching endpoint and then appended anyway (the same
  endpoint added 3× grew DC1 from 2 to 5 entries) and silently discarded
  the passed `secret`, storing `bytes()`. Duplicate `(ip, port)` now
  returns early; new endpoints keep their secret.
- `API.TelegramDesktop.Generate` normalizes `system` (lowercase + strip)
  BEFORE validating, so `"Windows"`/`"MacOS"`/`"LINUX"` select that OS
  instead of being silently replaced by a hash-derived pick; unknown
  systems (`"templeos"`, ...) now raise `ValueError` instead of being
  silently substituted. Docstring no longer claims the default is
  `"windows"` (it is `None` = deterministic/random pick).
- `APIData` pid registry is bounded and O(1): the old
  `CustomInitConnectionList` grew +1 per instance forever (verified 10k
  growth) and `findData` was a linear scan. It is now an
  `OrderedDict` pid→entry with pinned class entries and FIFO eviction of
  instance entries above 4096; `CustomInitConnectionList()` remains
  available as a classmethod returning a snapshot list. `destroy()`
  intentionally does not deregister (live clients may still hold the
  pid) — documented in-code.
- `Account._setMtpAuthorization.readKeys` validates inside the loop: an
  implausible key count (< 0 or > 1024) raises `TDataBadConfigData`
  (parser-DoS cap) and each `AuthKey.FromStream` read is followed by a
  `QDataStream.Status` check that raises `QDataStreamFailed`.
- Misc cleanups: dead/broken `api`-argument branch in
  `TelegramClient.__init__` replaced with a clear `TypeError`;
  `QRLoginToNewClient` timeout uses `total_seconds()` instead of
  `.seconds`; `extend_class.__new__` checks `decorated_cls` (it tested
  `cls`, which is always a type); `Storage.WriteFile` raises a real
  message instead of `"what"`; `Storage.ReadFile`'s dead
  `except IOError: pass` removed (QFile signals via return value, real
  OSErrors propagate); `PrepareEncrypted` fills AES padding with
  `os.urandom` like tdesktop's `base::RandomFill` (zero-byte padding was
  a fingerprint; no-padding case byte-identical); unreachable lines
  after `raise` removed (`Account.start`, `TDesktop.AppVersionString`).
- `PasskeyStore` validates `user_handle` against `^\d+:\d+$` at
  construction/load, so a non-tgmint JSON file fails with a clear
  `PasskeyError` instead of a cryptic `ValueError` from `home_dc`.

### Changed
- Version pins refreshed to live values (2026-10-24, verified through the
  new `tgmint.versions` fetchers): Telegram Desktop **7.3.3** (was 7.2.8),
  Android **13.1.0 (72291)** (was 12.10.1), Telegram X **0.29.1 (1817)**
  (was 0.28.10), iOS **13.1.1** (was 12.9.3). macOS stays 11.14.1
  (pin-only: the TelegramSwift pbxproj raw URL 404s). `tgmint.versions`
  `PINNED` updated to match.
- **Scoped wire patch**: `tgmint.tl.TelegramClient` no longer smuggles a
  registry PID through telethon's `device_model` argument to trigger the
  globally-patched `InitConnectionRequest` constructor. It now passes the
  real fingerprint fields into telethon's base client and rewrites the
  stored `client._init_request` directly after construction: the eight
  identity fields, the official `lang_pack` (still impossible in stock
  telethon), and — when the fingerprint carries an IANA timezone — the
  `params` JSON blob with `tz_offset`, exactly like official clients.
  The global `CustomInitConnectionRequest` patch remains registered as a
  compatibility path for plain telethon clients; our own client simply no
  longer depends on it. New golden wire tests
  (`tests/test_wire_golden.py`) serialize the real
  `InvokeWithLayer(...)` envelope and assert the fingerprint, `lang_pack`
  and `tz_offset` actually reach the wire bytes.
- Fingerprint pairing made plausible — pools no longer cross-product every
  model with every OS version:
  - Android: per-model SDK range table (`AndroidDevice._SDK_RANGES`, first
    match wins); models without a verified window (all Huawei, all HTC,
    Samsung GT-/old SM-A codes, the 2012-2016 crawl, realme RMX3700) are
    excluded by design, and the raw `device_models` list is deduplicated
    (~420 duplicate strings, some x5).
  - macOS: per-identifier support table (`macOSDevice._IDENTIFIER_INFO`)
    with Intel/Apple-Silicon arch per identifier; Mac mini identifiers
    (Macmini8,1 / Macmini9,1) added, Mac Studio correctly starts at 12.3.
  - iOS: explicit per-model support table replaces the number-keyed dict;
    the buggy catch-all that paired an iPhone SE with iOS 13 is gone.
- Windows pool/system_version now carries the `x64` arch suffix
  (`"Windows 11 x64"`), matching tdesktop's lib_base.
- Junk board names (placeholders like `INVALID`/`Default string`,
  HTML-entity `&#160;` artifacts, backslash escapes) filtered out of the
  shared desktop board-name list.
- iPhone naming: "iPhone Air" (the 2025 device; "iPhone 17 Air" does not
  exist) and Apple casing ("6s", "13 mini") fixed.
- Data typo: two fused Huawei MediaPad strings were split into two entries.
- `API.TelegramDesktop.Generate()` now picks a platform-coherent
  `app_version`: bare on Linux and Intel macs, `7.2.8 x64` on Windows,
  `7.2.8 arm64` on Apple Silicon (class default is the bare `7.2.8`).

### Changed
- Web presets UA refreshed: Chrome/157.0.8103.15 in TelegramWeb_Z /
  TelegramWeb_K / Webogram device_model; Web Z `app_version` = `12.0.47`
  (verified against version.txt and package.json; the old `" Z"` suffix
  format was unverifiable). Web K's `1.0.1 K` left as-is with a comment
  (injected at build time, unverifiable from source).
- `selfcheck.py`: new stale markers (Chrome/96.0, "iPhone 17 Air",
  "iPhone 6S", "13 Mini") and digit-boundary-aware matching so `8.4.1`
  no longer false-positives on iOS 18.4.1.

### Repaired
- `tests/tdata_test.py` imports again after the `tgmint` rename (the old
  `src.*` imports and the debug.py-rewrite hack crashed collection);
  `test_random_api` passes offline.
- New offline test module `tests/test_fingerprints.py` covering all of
  the above.

### Project
- CI: `package.yml` matrix widened to Python 3.9–3.13 on
  checkout@v4/setup-python@v5, installing `-e .[qt,passkeys]` and running
  `python -m unittest discover` (pytest/codecov dropped — the token
  belongs to upstream); `pylint.yml` replaced by a minimal ruff smoke
  lint (`ruff check src tests --select E9,F63,F7`) since the legacy
  codebase is not pylint-clean.
- Metadata: `[project.urls]` Homepage now points at
  `drshta0/tgmint` (Upstream still thedemons/opentele);
  `tgmint.__version__` added (importlib.metadata with a literal
  `1.15.1.post5` fallback).
- Docs config repairs: `.coveragerc` omit paths fixed
  (`src/tgmint/debug.py`, `selfcheck.py`); `.readthedocs.yml` migrated to
  the current v2 schema (ubuntu-22.04, Python 3.12, requirements + pip
  install, mkdocs kept).
- README/examples re-targeted to `tgmint` imports: Installation now says
  `pip install tgmint` (with a git fallback until the first PyPI
  release), First Run imports `tgmint.td`/`tgmint.tl`/`tgmint.api`, and
  the three example files' python import lines changed from
  `opentele.*` to `tgmint.*` (prose untouched).
- New offline test modules `tests/test_tdata_roundtrip.py` (tdata
  save/load round-trip, per-folder master keys, random settings key,
  DcOptions dedup + secret) and `tests/test_api_generate.py`
  (case-insensitive `Generate` + ValueError on unknown system), plus
  `TestStoreValidation` in `tests/test_passkeys.py`.

### Project
- Version reset to **`1.16.0`** (SemVer): the inherited `1.15.1.postN`
  string signaled "rebuild of upstream"; the fork's next functional
  release continues development under its own version line. The
  `__version__` fallback literal in `src/tgmint/__init__.py` matches.
- `pyproject.toml` metadata: Python 3.9–3.13 classifiers (one per minor)
  plus `Intended Audience :: Developers`, `Topic :: Communications ::
  Chat`, `Topic :: Security`; `[project.urls]` gains `Repository`,
  `Issues`, and `Changelog` keys pointing at `drshta0/tgmint`
  (Homepage/Upstream unchanged).
- New `SECURITY.md` (GitHub-recommended format): private vulnerability
  reporting only, 14-day acknowledgment aim, latest release supported,
  and safe-handling rules for session/tdata/passkey files — all of which
  are account credentials.
- README retitled to `# tgmint`; the badge row now points at the
  `tgmint` PyPI project and this repo (PyPI version, Python versions,
  MIT license, last commit). The upstream codecov/workflow/readthedocs/
  installs badges — which rendered upstream's status — are gone; the
  logo block is kept.

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