# Changelog
All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Documentation site rebuilt** (`mkdocs.yml`, `docs/`): new Home,
  Getting started (three tested recipes) and Concepts pages; a CLI
  reference generated from the argparse parser at build time
  (`docs/hooks/cli_reference.py`, nothing generated is committed); and
  a 12-page API reference generated from docstrings by mkdocstrings.
  `mkdocs build --strict` is warning-free. New SVG logo
  (`docs/assets/logo.svg`).
- `CONTRIBUTING.md`: dev setup (venv + pytest/selfcheck/ruff), the
  offline-tests / golden-files rule, the own-account-only guardrail
  (PRs adding batch/farming features will be closed), the
  cite-a-source-URL rule for every data value, and a DCO-style
  "you wrote the code you submit" expectation.
- `CODE_OF_CONDUCT.md`: Contributor Covenant 2.1, verbatim; reports go
  via GitHub private vulnerability reporting / repo owner (no email).
- `.github/dependabot.yml`: weekly dependency bumps for `pip` (repo
  root) and `github-actions`.
- `.github/workflows/release.yml`: on tag push `v*` — build sdist+wheel
  with `python -m build`, `twine check`, then publish with
  pypa/gh-action-pypi-publish via PyPI Trusted Publishing
  (`permissions: id-token: write`, environment `pypi`). No API tokens
  anywhere; the one-time trusted-publisher setup is documented in the
  workflow header comment.
- **QR login, framework-neutral** (`tgmint.qrlogin_core` +
  `docs/qr-login.md`): `tgmint login-qr --to PATH --to-format FMT
  [--preset ...]` shows a `tg://login` QR in the terminal, waits until
  you confirm it from your own logged-in app, and writes the session in
  any format — born with a minted fingerprint. The ceremony is the
  passkey architecture again: a Telethon-free state machine
  (`auth.exportLoginToken` / `auth.importLoginToken`, the
  `auth.loginTokenMigrateTo` DC switch, expiry refresh, 2FA as the typed
  `QrPasswordNeeded` result — the core never prompts) over a duck-typed
  invoker, with thin Telethon (`tgmint.qrlogin`) and Pyrogram-family
  (`tgmint.qrlogin_pyrogram`) drivers. The DC-switch snapshot/rollback
  moved to a shared `tgmint.dcswitch` module both the passkey and QR
  drivers use (a failed migrate import restores the caller's session; a
  2FA stop intentionally keeps the home-DC session). Constructor ids are
  pinned against BOTH installed frameworks' generated layers (Telethon
  1.45.0 and kurigram 2.2.26, both layer 229) in
  `tests/test_wire_golden.py`, byte-for-byte. The terminal QR comes from
  tgmint's own pure-Python ISO/IEC 18004 encoder (`tgmint.qrrender`:
  byte mode, L/M, versions 1-10, all eight masks) — no new dependency
  and no `[qr]` extra: correctness is pinned offline by golden matrices
  recorded from the `qrcode` library (with `segno` second-checking
  version assignment) via `scripts/regen_qr_golden.py` into
  `tests/golden/qr/qr_vectors.json`; the suite imports neither. QR login
  itself is parity, not novelty (opentele2, Telethon's `client.qr_login`
  and kurigram's `pyrogram.qrlogin` ship it); tgmint's addition is the
  neutral ceremony, the shared rollback and the zero-dep renderer.
- **`tgmint verify <path>`**: open one session
  file, saved session string, tdata folder or `.tgmint` envelope
  completely offline and report the format (detected — a directory is
  tdata, `*.tgmint` an envelope, else a reader chain; `--from-format`
  overrides), `dc_id`, `user_id`/`api_id` when stored, the auth-key
  fingerprint as two hashes only (the MTProto `auth_key_id`
  `sha1(key)[-8:]` and a full SHA-256 — the key itself is never
  printed), codec placeholder values (user_id 777000 / api_id 2040), and
  file permissions (warns when group/other can access the credential —
  files should be 0600, a tdata tree 0700/0600; a stricter mode stays
  quiet, and the check is POSIX-only). A tdata passcode arrives via
  `--passcode-env` and a sealed envelope's passphrase via
  `--passphrase-env`/`--passphrase-stdin` — never argv. Exit codes
  (documented in `--help`): 0 ok | 1 unreadable | 2 readable, with
  warnings. `--json` failures print a machine-readable error object.
  String-format detection guards against the Telethon/GramJS shared
  `"1"` prefix: a GramJS body with a 14-byte hostname is structurally
  Telethon-IPv6-shaped, and the discriminator (the hostname-length
  field) keeps verify from reporting a wrong key hash for it.

- **Official Android app session import** —
  `tgmint convert --from-format android-dir DIR` reads a dump of your own
  rooted/emulated device's official Telegram storage
  (`tgnet.dat` + `userconfing.xml`; `src/tgmint/codec/android.py`) and
  converts the selected account to every destination of the matrix
  (Telethon SQLite + string, Pyrogram-family SQLite both variants +
  string, GramJS string, tdata, and the `.tgmint` envelope via
  `profile seal`). The binary layout is verified field-by-field against
  the official client source (DrKLO/Telegram pinned commit, cited per
  field in the module) and cross-checked against AndroidTelePorter (MIT,
  PyPI — prior art, credited in ACKNOWLEDGMENTS.md; tgmint claims no
  "first"). Details: `--account-index` selects one of the discovered
  account slots (no "convert all", own-account tooling only);
  `tgnet.dat.bak` is honored the way the app's own crash recovery
  promotes it; the user id is parsed best-effort from the prefs XML
  (three known `TL_user` constructors; unknown → unset, never guessed);
  truncated/garbage input raises the codec's typed
  `tgmint.codec.CodecError`, never a raw `struct.error`/`IndexError`.
  Pyrogram-family outputs carry the official app's own `api_id` (4,
  mirrored from `API.TelegramAndroid`) with the source recorded in the
  conversion report, instead of the demo placeholder. Tests: 38 new
  offline tests against fixtures synthesized by an independent in-test
  encoder (no real account data anywhere); acquisition recipes updated
  in `docs/android-acquisition.md`.

### Changed
- README rewritten as a short landing page (pitch, 3-command demo,
  feature table, framework matrix, docs index); the per-feature detail
  lives in the docs.
- Docs theme: stock Material (light/dark) replaces the `theme/` overrides
  copied from another project, which included that project's
  announcement banner and its own CSS/JS bundle. The stale 2022
  hand-written upstream API pages (`docs/documentation/`, duplicated in
  `docs-github/`) and the pydoc build scripts are removed; the examples
  link to the generated reference instead.
- CI (`package.yml`) runs `pytest` instead of `unittest discover`
  (which skipped the plain-function tests) and installs `kurigram`, so
  the Pyrogram-family passkey, cadence, QR and adapter tests run instead
  of silently skipping. It also triggers on `pyproject.toml` changes.
- Lint ratchet: CI lint is no longer smoke-only. `[tool.ruff]` in
  pyproject.toml (target py39, line-length 120) now selects
  E9/F63/F7 plus F401, F811, F841, B006, B008 and the UP (pyupgrade)
  rules, and `.github/workflows/pylint.yml` runs `ruff check src tests`
  off that config. UP007/UP045 (`Optional[X]`/`Union` → `X | Y`) are
  deliberately excluded: PEP 604 annotations raise TypeError when
  evaluated on Python 3.9, which we still support. All fixes are
  behavior-preserving: deprecated `typing.List`/`Dict`/`Tuple`/`Type`
  annotations became builtin generics (PEP 585, fine at runtime on
  3.9), mutable default arguments (`B006`) and call-in-default
  arguments (`B008`) got `None` sentinels, unused bindings and imports
  were dropped (import hubs like `td/configs.py` keep their re-export
  surface via per-file ignores), and stacked `@typing.overload`
  redefinitions now resolve because the three files that use them got
  an explicit `import typing` (ruff cannot see `typing` through
  star-imports).
- pyproject: `maintainers` is now `drshta0` (`authors` stays
  `thedemons` for MIT lineage); the `[project.scripts]` comment now
  lists all twelve CLI commands (mint | inspect | audit | freshness |
  parity | convert | login-passkey | profile | heal | bootstrap |
  cadence | doctor).
- Deduplicated the triple-copied examples: `docs/examples/` is the
  single canonical copy (it is what mkdocs / Read the Docs serves —
  `docs_dir: docs` in `mkdocs.yml`); the stale `examples/` and
  `docs-github/examples/` copies are deleted, and the surviving copy
  now uses `tgmint.*` imports instead of leftover `opentele.*` ones.
  `mkdocs build --strict` passes.

### Fixed
- **`API.TelegramAndroid` could not log in new sessions.** The pair it
  was rotated to in 1.18.x (`api_id` 4 / `014b35b6...`, what the shipped
  APK carries) is also in the public DrKLO source, and Telegram refuses it
  for new logins from anything but the real app: `auth.sendCode` and
  `auth.exportLoginToken` return `API_ID_PUBLISHED_FLOOD` (verified live
  2026-11-04), so `login-qr`, `login-passkey` and `heal` failed with
  `--preset android`. The preset is back on the official `6` /
  `eb06d4abfb49dc3eeb1aeb98ae0f581e`, which Telegram still accepts. The
  Android-app import (`android-dir`) still records 4, the id those
  sessions were really created under, now pinned in
  `tgmint.codec.android.OFFICIAL_APP_API_ID` instead of mirrored from the
  preset. `login-qr`, `login-passkey` and `heal` now say so when Telegram
  refuses an app id, and point at `--preset`.
- The 2040 placeholder app id is described as Telegram Desktop's official
  id (it was mislabelled "public web-demo") in `convert`/`verify`
  messages; `login-passkey --help` no longer claims to be the only
  network command.
- **Python 3.13: the Telethon layer failed at import** with
  `extend_class: attribute '__firstlineno__' already exists`. 3.13 adds
  `__firstlineno__` / `__static_attributes__` to every class `__dict__`;
  `extend_class` now skips them like `__module__` (`utils.py`), with a
  regression test that fails without the fix.
- Python 3.9 test suite (21 failures, pre-existing since v1.18.0): an
  autouse fixture (`tests/conftest.py`) guarantees a current event loop
  for the sync Telethon/Pyrogram constructors after an `asyncio.run()`;
  the QR wire-golden test no longer pins the installed kurigram layer
  (3.9 resolves 2.2.25 = layer 228).
- `mkdocs.yml` no longer loads `polyfill.io` (a domain that served
  malware after its 2024 sale), nor unused MathJax / Mermaid 8.13.

## [1.18.1] - 2026-11-03

The code-review fix release. A 6-way parallel review of all 26.7k lines
of `src/`
produced 72 findings; this wave fixes every high-impact item, nearly
every medium and most lows, and adds ~3.5k lines of regression tests.
No new features. Suite: 767 passed / 74 skipped / 226 subtests in a pristine
venv, offline (one extra cadence test runs where the vendored kurigram
checkout it reads is present, giving 768/73 on that machine).

### Fixed
- **tdata destinations no longer clobber a live folder** (finding 1,
  `codec/__init__.py`): `_write_tdata` refuses an existing folder or
  symlink with `FileExistsError`, exactly like every file writer in the
  matrix — `SaveTData` would otherwise overwrite `key_datas` inside a
  real Telegram Desktop data directory.
- **`DcOptions.Serialize` writes `port` again** (finding 2, `td/mtp.py`):
  the endpoint record is `id, flags, port, ip…` on the wire (tdesktop
  `mtproto_dc_options.cpp`); omitting `port` shifted every following
  field by 4 bytes, so every config blob written was unreadable even by
  our own reader. Round-trip test added.
- **Telethon passkey login rolls back a failed DC switch** (finding 3,
  `passkeys.py`): `client._switch_dc` permanently moves the caller's
  persistent session and erases its auth key; every failure path after
  the switch (expired challenge, bad signature, 2FA without a password)
  now restores the DC / address / port / auth key first, mirroring the
  rollback the Pyrogram-family driver already had.
- **`heal` refuses symlinked session paths** (finding 4, `heal.py`):
  `os.replace` onto a symlink replaces the *link*, so a heal through one
  reported success while the real session kept its dead auth key.
- **`login-passkey` converts with the real identity** (finding 5,
  `cli.py`): the flow knows the account's `user_id` and the preset's
  `api_id` at login time and passes both to `convert_session`, instead
  of letting destinations store the placeholders 777000 / 2040.
- **passkey registration is as atomic as the server allows** (finding 6,
  `passkeys_core.py`): the store path is preflighted (directory exists
  and is writable) before any network call, and a store save that fails
  after the server accepted the credential triggers a best-effort
  compensating `deletePasskey` — a retry registers a fresh passkey
  instead of orphaning one whose private key exists nowhere.
- **`heal` reports the placeholders it wrote** (finding 7, `heal.py`):
  the atomic rewrite keeps the codec's write result, so `filled`
  (777000 / 2040) and `notes` reach the report instead of it claiming
  `user_id: None`.
- Legacy tdata passcode KDF is tdesktop's, not an invention
  (`td/storage.py`): `CreateLegacyLocalKey` runs PBKDF2-HMAC-**SHA1**
  with 4000/4 iterations (config.h) — it was SHA-512/100k, a key no
  tdesktop build ever derived, so legacy passcode-protected map files
  could never decrypt.
- The encrypted-map reader is round-trip faithful and hostile-input
  safe (`td/account.py`, `td/configs.py`): `lskSelfSerialized` (the
  own-user record) is kept and written back first like tdesktop;
  wallet keys `0x1F`–`0x21` are consumed (`0x21` re-emitted) instead of
  desynchronizing the stream; an *unknown* key type now fails the map
  read (its payload length is unknowable — tdesktop fails too) instead
  of logging and parsing every later entry from the middle of a
  payload; the legacy `0x08` background key is read as the uint64 it is
  (was a `QByteArray` shift into an int → `TypeError` aborting the
  whole load); counted lists are bounded and length-checked before
  their loops (`kMaxMapListCount` + bytes-available).
- `readMtpData` loops over blocks like tdesktop (`td/account.py`): the
  single-block `blockId == 75` assumption discarded everything after
  the first block of a multi-block file and accepted a truncated stream
  without a status check.
- The wrapped local key is actually validated (`td/tdesktop.py`):
  exactly 256 bytes and a healthy stream, else a `TData*` error — a
  truncated key blob used to yield a short garbage `AuthKey`. The
  accounts `count` from the (craftable) key file is capped at
  `kMaxAccounts` (6), not an effective hang at ~4G iterations.
- `EncryptedDescriptor(0)` initialises (`td/storage.py`): `size is not
  None` replaces `if size:` — a legitimately empty record no longer
  produces a stream whose every write is a silent no-op. Also here:
  a truncated file raises a `TData*` error instead of `OverflowError`,
  `ReadFile`'s candidate order matches tdesktop's (modern `s` file,
  else the newer legacy `0`/`1` by mtime — it used to read a stale
  backup ahead of the live file), `ComposeDataString` actually strips
  `#` (the old `.replace` result was discarded), and four error
  messages lost their unf-stringed `{...}` placeholders.
- NULL rows are typed errors, not escapes (`codec/pyrogram.py`,
  `codec/telethon.py`, `codec/data.py`): a session row whose
  `auth_key`/`server_address` is NULL raises the codec's `CodecError`
  naming the column, instead of a bare `TypeError`/`ValueError`.
- The convert report is variant-aware and honest about defaults
  (`codec/__init__.py`): a kurigram SQLite write (storage v7 keeps
  `server_address`/`port`) no longer reports the endpoint as dropped,
  and `dropped` only lists values that genuinely differ from the
  destination's own default (an `is_bot=False` into a bot-columnless
  format loses nothing).
- `convert` grew the source options the matrix already supported
  (`cli.py`, `codec/__init__.py`): `--passcode-env VAR` (a tdata
  passcode is a secret — environment, never argv), `--account-index`
  (multi-account tdata folders), `--variant {pyrogram,kurigram}`.
  A passed-but-unusable `--passphrase-env`/`--passcode-env` (typo'd
  variable name) is now an explicit error instead of being silently
  ignored, and `convert --json` prints a JSON error object on failure
  (stdout used to be empty).
- `parity` no longer fabricates a wire layer (`cli.py`): without an
  explicit `--layer` it reports the layer the minted `app_version`
  genuinely speaks — the old fallback named Telethon's own layer (224)
  for iOS identities that speak 232+.
- `profile seal` round-trips sealed envelopes (`cli.py`): the
  passphrase is resolved before the read (re-sealing a sealed profile
  works, keeping its format, fingerprint and passkey), and an `OSError`
  is a JSON error, not a traceback.
- `heal` got the guardrails its report promised (`heal.py`, `cli.py`):
  `--out` for format changes (an in-place `--to-format` rewrite
  destroyed the original format while the filename kept claiming it),
  a staleness guard that refuses to overwrite a session that changed
  during the read→login→write window, a passphrase prompt only for
  sealed envelopes (plain sessions never asked), and exit codes where
  1 stays reserved for `audit` findings.
- `bootstrap` replays with the recorded identity (`bootstrap.py`,
  `cli.py`): the session's fingerprint sidecar wins over minting a
  fresh one (Telegram remembers the device a session signed in with),
  `--api-preset` is refused when it contradicts the replay platform,
  each replay step has a timeout, and a fatal step emits its partial
  report with the `--json` error instead of discarding it.
- Passkey ceremony edge cases (`passkeys_core.py`, `passkeys.py`,
  `passkeys_pyrogram.py`): the allow-list comparison decodes
  base64url ids (a padded server spelling of the same id was rejected);
  the signature counter is validated as the WebAuthn uint32 it is (a
  corrupt negative counter is refused, not silently rolled back to 1);
  an `alg=` override is checked against the algorithms the server
  actually offered; the Telethon driver translates `PASSKEY_*`/
  `SESSION_*` RPC errors into `PasskeyError` like the Pyrogram driver,
  lets `TwoFactorRequired` propagate unwrapped (it was re-wrapped as a
  `PasskeyError`, mixing "corrupt store" with "needs a password"), and
  accepts unsigned 64-bit auth-key ids (half of all key ids are ≥ 2⁶³);
  the store file is chmod'ed only after a successful save (the old
  chmod-in-`finally` touched paths it never wrote).
- `client_kwargs` accepts an explicit `init_connection_params=`
  override (it raised `TypeError` for the very key `tz_params=True`
  injects) (`adapters/pyrogram.py`).
- The last four open review findings (#42, #47, #53, #61), plus covering tests for the ten fixes that had none:
  - **#61 account-mixup guard** (`passkeys_core.check_finish_identity`,
    wired into both login drivers): the passkey's `user_handle`
    (`"<dc>:<user_id>"`) is the account the assertion was signed for,
    but nothing compared it to the account `auth.finishPasskeyLogin`
    answered with — a swapped credential or a store file copied from
    another account wrote one account's session from another's passkey.
    The guard runs before the store save / session write, on the finish
    result and again on the framework's own `user.id` (authoritative for
    layers whose `User` constructor the neutral parser does not know),
    and on the 2FA `sign_in`/`check_password` path too. An id that was
    never parsed (unknown constructor) is skipped rather than refused.
  - **#47** `SystemInfo.system_versions` base default deleted: every
    concrete pool declares its own list, so the inherited-but-never-read
    empty list only made a pool that forgot one generate nothing.
  - **#53** macOS version ceilings follow one rule: major 26 exactly for
    the models on Apple's macOS 26 compatibility list
    (https://support.apple.com/en-us/122867), i.e. every Apple-Silicon
    Mac and the four Intel holdovers — the 2020 M1 Air / 13" Pro /
    mini / 24" iMac were capped at 15 while their 2021-2022 siblings
    claimed 26.
  - **#42** `td.Serialize.stringSize` now returns what `writeQString`
    writes (`4 + len(utf-16-be)`, so an astral character counts twice)
    instead of `4 + len + 2`, and the dead five-line `size` prefetch in
    `MTP.Config.Serialize` — its only caller, whose sum was never read —
    is deleted with its now-unused import.
  - **Ten FIXED-but-untested rows now have tests** (#13, #31 bootstrap
    side, #33, #37, #41, #44, #45, #57, #58, #66), including crafted
    `key_datas` bodies for the short-wrapped-key and accounts-count
    guards and a two-block `mtp_data` file for the block loop.
- `tests/pytest.ini` no longer declares `asyncio_mode`: pytest-asyncio is
  not a dependency, so the line only produced an
  "Unknown config option: asyncio_mode" warning on every run (the suite
  drives coroutines through `IsolatedAsyncioTestCase`/`asyncio.run`).
- `Fingerprint.tz_offset()` converts the instant, not the clock digits
  (`fingerprint.py`): `datetime.now().astimezone(zone)` — the old
  naive-now-relabeled-as-zone was an hour wrong for the DST mismatch
  window. `from_dict` accepts defaulted fields (`tz_zone`, `origin`)
  and lenient legacy origins (a stored sidecar missing them used to be
  rejected as corrupt), and `macos` origins get a real
  `system_version` coherence check.
- Android version pin is the wire string (`versions.py`): `13.1.0
  (7229)` — DrKLO's own `TLRPC.java` `APP_VERSION_CODE` (the APK's
  ABI-split `versionCode` 72291 carries one extra digit; fetched
  5-digit codes are truncated by that split digit). The old pin could
  never resolve to a layer, so `parity` reported `layer: None` for
  every Android identity.
- Dead upstream code removed (`devices.py`, `utils.py`, `locales.py`):
  the crashing `object_hierarchy_getattr` helper, the dead `_hashtorange`
  and the typo'd `device_modesl` field, plus the `locales` docstring
  moved where Python requires it. (A later audit caught this entry
  overclaiming: the dead `system_versions` list was still there at
  v1.18.1 — it is gone now, see the review-findings entry below;
  `extend_class` stays on purpose, it is the Telethon-layer decorator.)

### Security
- tdata output is hardened to 0700/0600 (`codec/__init__.py`): the
  written folder (raw auth-key material in `key_datas` and the MTP data
  file) used to land umask-default — 0775 directories, 0664 files,
  world-readable; every file and directory of a fresh output is now
  0600/0700, matching the rest of the package.
- Passkey store saves chmod only the file they published
  (`passkeys_core.py`): the chmod moved out of the `finally` block, so
  a failed save (bad path, unwritable directory) no longer tightens the
  permissions of whatever happened to live at the destination path.

### Tests
- ~3.5k lines across 17 files, one or more per fix above: passkey
  DC-rollback/2FA/registration-compensation/sign-counter/allow-list/
  `alg` validation (`test_passkeys*.py`), heal symlink-refusal/
  staleness/`--out`/placeholder reporting (`test_heal.py`), DcOptions
  round-trip, truncated-input typed errors and the wallet map keys
  (`test_tdata_roundtrip.py`, `test_lsktype_tolerance.py`; the
  multi-block `readMtpData` loop is fixed in code but has no covering
  test — review finding #45), codec variant/NULL-row/
  `--account-index`/neutral-`dropped` behaviour
  (`test_codec_matrix.py`), bootstrap recorded identity / partial
  report / step timeout (`test_bootstrap.py`), fingerprint
  `from_dict`/DST `tz_offset`/origin lenience
  (`test_core_fingerprint.py`), the Android ABI-split versionCode
  truncation (`test_versions_sidecar.py`, `test_api_generate.py`),
  and CLI JSON error objects / `--passcode-env` semantics
  (`test_cli*.py`). Suite: 767 passed / 74 skipped / 226 subtests in a pristine venv,
  offline and deterministic.

## [1.18.0] - 2026-11-01

The "one file that is an account" release, part one. A session, the
fingerprint it was born with and the passkey that can recover it now travel
together in a single portable `.tgmint` envelope, optionally sealed with a
passphrase. Because it is registered as a codec **source**, everything that
already reads sessions reads envelopes too - and the new `heal` command can
sign a dead session back in with the bundled passkey and rewrite it in
place.

### Added
- `API.TelegramAndroid` ROTATED to the current official pair (`api_id` 4 /
  `014b35b6184100b085b0d0572f9b5103`), verified 2026-11-01 by
  disassembling the shipped official APK (13.1.1, telegram.org/dl/android/apk,
  `BuildVars.<clinit>` in classes.dex): the 2022 pair `6`/`eb06d4...`
  appears nowhere in the current APK. (Reverted to 6 — see [Unreleased]
  Fixed: Telegram refuses 4 for new logins.)
- `API.TelegramDesktopFlatpak` — the second, current official Desktop
  credential pair (`api_id` 611335 / `d524b414d21f4d37f08684c1df41ac9c`)
  extracted from the shipped flathub build (stable `7444df4f`, tdesktop
  `668a91bd`): the embedded build manifest injects it via
  `-DTDESKTOP_API_ID/HASH`, and the stripped binary whitelists
  `{2040, 611335, 17349}` as official ids — so classic `2040` is confirmed
  NOT rotated. Inherits device pools and `Generate()` from
  `TelegramDesktop`; selected explicitly, never as a default.
- `tgmint.profile` - the portable identity envelope (`tgmint-profile/1`):
  `seal`, `open_profile`, `write_profile`, `read_profile`, `inspect_profile`.
  The session is stored as its format family's session string (an
  authorization is `dc_id` + `auth_key`), the fingerprint sidecar and the
  passkey store ride along as JSON, and `meta` records `created` / `tgmint` /
  `note`. Files are written atomically, mode 0600, and an existing path is
  never overwritten.
- Sealed profiles: AES-256-GCM over the plaintext container bytes, keyed by
  PBKDF2-HMAC-SHA256 (600000 iterations, 16-byte salt, 12-byte nonce) with
  the format id as GCM associated data. `cryptography` is imported lazily, so
  an unsealed profile (and every other codec path) keeps working without the
  `[passkeys]` extra; a missing extra is a one-line "install tgmint[passkeys]"
  message, not an ImportError traceback.
- Cross-validation on open: a container whose session, fingerprint (optional
  `user_id`/`dc_id` keys) and passkey (`dc:user` handle) disagree about the
  account raises one `ProfileError` naming both sides. Wrong passphrase and
  tampered ciphertext are indistinguishable by construction and share that
  same exception.
- `tgmint profile seal | open | inspect` - bundle a session with its sidecar
  and passkey, unpack one into any codec format, or print a secret-free
  summary (formats, dc/user, has-fingerprint, has-passkey, sealed or locked).
  Passphrases are never taken from argv: `--passphrase-env VAR` or
  `--passphrase-stdin`, with a `getpass` prompt when neither is given and
  stdin is a terminal.
- `tgmint heal` / `tgmint.heal.heal_session` - repair ONE session with its
  passkey: read it (any source format, including an envelope), probe it with
  a single `get_me`, leave an alive session untouched, and when the server
  rejects the auth key, sign back in on a client minted from the *recorded*
  fingerprint (envelope or sidecar; a minted identity otherwise) and rewrite
  the session in place, atomically, in the same format. No batch mode, no
  glob, no daemon: one account, one session, invoked by its owner. Without
  `--live` nothing is probed and `--force` is required; an inconclusive probe
  (a network failure, not an auth rejection) refuses unless forced; another
  account's passkey is refused before any socket is opened.
- 85 new offline tests (43 envelope + 24 heal + 18 CLI), including plain and
  sealed round trips, wrong passphrase, tampered ciphertext/salt/nonce,
  cross-validation, the envelope as a `convert` source, and heal driven end
  to end through injected fake clients (alive -> no-op, dead -> rewrite,
  refusals, `.tgmint` repair keeping fingerprint and passkey).
- `tgmint.bootstrap` / `tgmint bootstrap` - an **opt-in post-auth startup
  replay**: the read-only batch the official client sends right after
  authorization, in the order its source proves, for the Android 12.10.6 and
  Desktop 7.3.3 presets (`BOOTSTRAP_SEQUENCES`, `Step`, `sequence()`,
  `describe()`, `replay_startup()`, `platform_for()`; each row cites the
  official client's source `file:line`).
  19 safe steps for Android (starting `help.getConfig`) and 13 for Desktop
  (starting `help.getConfig` then `updates.getState`), each tagged
  `session` / `account` / `dialogs` / `cosmetic`. Safety is an allowlist, not
  a denylist: a step may only send a method from `SAFE_METHODS` (plus
  `COSMETIC_METHODS` when `include_cosmetic=True`, 8 more on Android), and
  `account.updateStatus`, `account.registerDevice`,
  `account.resetAuthorization` and `auth.*` are refused on every use
  (`BootstrapError`), so a sequence that drifts is rejected at runtime, not
  reviewed. `initConnection` is never touched: it is fixed at connect time
  by the client. A failing request is recorded and the replay continues;
  connection/auth failures are re-raised. `tgmint bootstrap --preset
  {auto,android,desktop} [--include-cosmetic] [--dry-run] [--json]` prints
  the plan without a session and never connects, or replays into ONE session
  you own (`--session`, `--from-format`, `--api-preset`), refusing with exit 2
  when live mode is asked for without a session; `--preset auto` derives the
  platform from the session's fingerprint sidecar and names why `ios` /
  `macos` have no verified sequence yet. `parity.describe_envelope()` now
  carries a `bootstrap` summary (`platform`, `steps`, `cosmetic_steps`), so
  `tgmint parity` shows what an identity would replay.
- 78 new offline tests (75 in `tests/test_bootstrap.py`, including the
  parity integration, plus 3 in `tests/test_cli.py`): the
  shipped order against the spec, the allowlist/forbidden gates, cosmetic
  filtering, the replay loop against a fake client (exact order, one failing
  request recorded while the rest continue, fatal errors re-raised, dry run
  sending nothing), the default builder producing real Telethon objects, and
  `import tgmint.bootstrap` with Telethon absent. Nothing here has been
  replayed against a live account yet, and the docs say so.

- `tgmint.cadence` - the official keepalive cadence as data, plus the smallest
  honest way to set it. `PING_CADENCE` carries Telegram Android 12.10.6
  (ping every 19 s, `disconnect_delay` 35) and Desktop 7.3.3 (every 30 s,
  60), each with the `file:line` it was read from; `target()` /
  `describe()` are pure (no framework import, no socket, no client) and
  `apply(client, platform=None, dry_run=False)` detects the client family and
  writes only what that family allows, reporting the rest as `unsupported`
  with the reason: Telethon gets its `_keepalive_loop` replaced **on the
  instance** (there is no interval attribute - 60 is a literal in
  `updates.py`, verified against the installed loop before patching) and its
  `disconnect_delay` is reported unsupported because Telethon only ever sends
  a plain `ping`; the Pyrogram family gets `PING_INTERVAL` as an instance
  attribute on every `Session` object (the worker re-reads it each tick, class
  default untouched) and keeps the derived `WAIT_TIMEOUT + 10` delay because
  `WAIT_TIMEOUT` is also the request/startup timeout. `platform=None` reads a
  fingerprint off the client and says to pass the platform when there is
  none; `dry_run=True` mutates nothing; `restore(client)` undoes the patch.
  `tgmint cadence [--preset {android,desktop}] [--json]` prints the official
  schedule next to the framework defaults it can fix - a pure plan that never
  connects, and the docs say plainly that matching a cadence is not ban
  evasion. `tgmint.parity.PING_PRESETS` stays the inert Telethon baseline it
  always was and now points at the verified table instead of promising it.
- 47 new offline tests in `tests/test_cadence.py`: the numbers and their
  sources, the framework defaults checked against the *installed* telethon and
  kurigram (so a bump that changes its own default fails the suite), the
  copied Telethon loop driven for several ticks, `apply`/`restore`/`dry_run`
  against a real `TelegramClient` and fake Pyrogram-family clients, and every
  refusal path (unknown platform, undetectable family, an unrecognised
  Telethon loop, a Pyrogram client with no Session yet).

### Fixed
- `tgmint.cadence` no longer caps the Pyrogram family at 9.5 s, because the
  reason for the cap was a bug in the framework, not a Telegram policy. A live
  transport-level investigation (2026-11-01, own accounts) showed the Pyrogram transport's hardcoded
  10 s socket-read timeout (`TCP.TIMEOUT`, `tcp.py:159`) closing its own
  connection via `recv_worker` whenever the next inbound packet was more than
  10 s away - a logging TCP proxy proved the server neither sends nor FINs at
  that point. `apply()` now installs a patient `_recv_from_socket`
  (`2 x interval + 7 s`, min 25 s) through the client's `connection_factory` so
  it lands before the first read of every connection (including reconnects),
  and wraps `Session.send` to rewrite the hardcoded `disconnect_delay = 25`
  to the official 35 s / 60 s (the server does enforce it). Verified live:
  one reconnect at apply time, then 100 s of pings at 19.0-19.1 s (Android)
  and 30 s (desktop) with no further reconnects. `describe()` and
  `tgmint cadence` now print the socket read timeout and the applied delay
  instead of a cap.
### Changed
- `tgmint.codec` gained `read_session` and `write_session` as public
  entrypoints (the reader/writer halves `convert_session` already had;
  `heal` needs the writer without a source format in the way), plus the
  `profile` source format, `.tgmint` suffix inference and format aliases
  (`profile`, `tgmint`, `tgmint-profile`). `convert_session` takes
  `passphrase=` for sealed envelopes and accepts `source_format=None`.
  Existing format strings are unchanged; `--from-format profile` is the only
  new CLI choice, and `profile` is a source, never a `convert` destination.
- `tgmint.parity.describe_envelope()` reports a `bootstrap` block
  (`platform`, `steps`, `cosmetic_steps`) instead of stating in its docstring
  that bootstrap parity is deliberately absent: the sequence now exists in
  `tgmint.bootstrap` as an opt-in replay. The envelope itself is unchanged
  otherwise, and `tgmint parity` stays offline.

## [v1.17.0] - 2026-10-30

The "passkeys everywhere they can physically be" release. Software
passkeys were Telethon-only because the ceremony logic lived inside the
Telethon client glue. They are now built on a framework-neutral core:
`tgmint.passkeys_core` (no telethon imports, offline-tested against a
simulated server) drives the Telethon driver, a new native Pyrogram-family
driver, and any future non-Python port through one JSON TL spec. The
handshake itself is now data: `PASSKEY_TL_SPEC` carries the constructor
ids and field orders, pinned byte-for-byte against the hand-written
classes and against kurigram's generated layer (layer 229 ships every
passkey constructor natively, proven by serializing both to identical
hex).

### Added
- `tgmint.passkeys_core` — framework-neutral passkey data + ceremony
  layer: credential engine and store (moved, single identity with
  `tgmint.passkeys`), a machine-readable TL wire spec
  (`PASSKEY_TL_SPEC`), a neutral writer/parser (`encode_request`,
  `parse_result`, `TLReader`), and the ceremony state machine
  (`register_passkey_core`, `login_passkey_assertion`,
  `finish_login`, `list_passkeys_core`, `delete_passkey_core`) with a
  documented driver contract (`PasskeyInvoker`: one async method,
  `request_bytes` or `native`). Zero telethon imports, asserted by test.
- `tgmint.passkeys_pyrogram` — native passkeys for the Pyrogram family:
  `register_passkey` / `login_with_passkey` / `list_passkeys` /
  `delete_passkey` on a connected kurigram client, including the
  cross-DC login (challenge-DC switch with from_dc_id/from_auth_key_id,
  snapshot/restore on failure) and 2FA via `check_password`. Constructor
  lookup is by TL id, so forks that ship the constructors work and forks
  that do not (hydrogram, layer 181) get a clear error.
- `tgmint login-passkey` CLI — the cross-framework bridge: sign in with
  only a passkey file (the one command that touches the network), written
  out in any session format (telethon/pyrogram/gramjs/tdata), on a client
  minted with a coherent tgmint fingerprint. Output is never overwritten.
- 111 new offline tests (51 core + 30 ceremony + 14 CLI + 61 Pyrogram
  driver, the Pyrogram ones skip cleanly without kurigram installed).

### Changed
- `tgmint.passkeys` is now a thin Telethon driver over the core: same
  public API, same behavior (27 legacy tests pass unchanged; the
  byte-identical wire bytes are pinned by the core tests). The signed
  int64 auth-key-id handling and the counter-before-network discipline
  moved into the core so every driver inherits them.

## [v1.16.1] - 2026-10-30

The "the convert command actually works" patch. v1.16.0 shipped a CLI
`convert` that was dead code: it probed for `tgmint.codec.convert_session`,
which did not exist anywhere in the tree, so every invocation exited 2
with "no convert_session entrypoint". Worse, the only CLI test covering
it skipped itself precisely when the codec was importable — the suite
stayed green while the advertised command was broken. Both are fixed,
and the replacement tests cannot skip.

### Fixed
- **`tgmint convert` was dead on arrival** (the bug this patch exists
  for): the codec package had all the readers and writers but no
  orchestrator, and the CLI's defensive "optional module" probe turned
  that into a silent exit-2 for every user who tried the command the
  README documents. The self-skipping test was not a victim of bad luck
  — it asserted the skip condition backwards, skipping when the codec
  was *present*. It is replaced by unconditional end-to-end tests that
  run real conversions through the CLI handler.

### Added
- `tgmint.codec.convert_session()` — the entrypoint the CLI was probing
  for: every documented from→to cell via the existing readers/writers,
  stdlib-only, offline, no login. String destinations are written to the
  output path as mode-0600 files (never echoed); existing outputs are
  never overwritten; tdata destinations route through `tgmint.td`'s
  `SaveTData`. When the destination needs a field the source format
  cannot store (Telethon/GramJS carry no `user_id`/`api_id`), a labelled
  placeholder is written and reported in the result — not hidden. For
  string formats, `--from` accepts the session string itself or a path to
  a file containing it (a saved `StringSession`).
- `gramjs-string` as a CLI convert format (`--from-format`/`--to-format`),
  wired end to end.
- `macos` as a `mint`/`parity` preset (the existing `API.TelegramMacOS`
  pool). `--layer` is refused with a clear error there: macOS stays
  pin-only because no verified macOS layer table exists (the
  TelegramSwift source URL 404s — see `tgmint.layers`), and refusing
  beats inventing layer data.
- Non-skippable end-to-end CLI convert tests: a fixed 256-byte auth_key
  round-trips telethon-string → pyrogram-string, pyrogram-string →
  gramjs-string, sqlite→string and string→sqlite cells, a tdata
  destination, and a `python -m tgmint` subprocess run — every output
  parsed back and compared against the seed key.
- Hydrogram rows in the framework tables in `README.md` and
  `docs/frameworks.md` (same release; the Pyrogram-family adapter and
  codec cover it like kurigram/pyrofork).

### Changed
- CLI `convert` human output now prints dc_id, the output path/kind and
  any placeholder-fill notes (the JSON shape is unchanged);
  `--help` lists `gramjs-string` and the `macos` preset.

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