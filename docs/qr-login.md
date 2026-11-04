# QR login — `tgmint login-qr`

Acquire a Telegram session by showing a `tg://login` QR code and confirming
it from **your own** logged-in Telegram app (*Settings → Devices → Link
Desktop Device*). The new session is born with a minted official-client
fingerprint and can be written in any format tgmint converts to. Single
account, interactive, own-device only — there is no batch mode and there
will not be one.

```console
$ tgmint login-qr --to me.session --to-format telethon-session
Scan with the Telegram app on your phone:
  Settings > Devices > Link Desktop Device
(or open tg://login?token=…)

▄▄▄▄▄▄▄█ ▀▀ ▄▀▄█▀▀▀█ ▀█▀▀█ ▀▄█▀
█ ▀▀▀ █ ▀█▄▄▀▄▀█ ▀▄▄▀ ▄█▀▄ ▀▄█ █
…
(valid for 900s; a fresh code follows expiry)
logged in with the scanned QR (user_id 424242, dc_id 2)
wrote me.session (telethon-session)
```

`--timeout SECONDS` bounds the overall wait (default 300; an expired code
is refreshed inside it), `--invert` renders light-on-dark for terminals
that scan better inverted, `--password 2FA` supplies a cloud password (or
you are prompted on a terminal), and `--preset/--system/...` mint the
fingerprint like every other tgmint command. The output path is never
overwritten.

## The wire

TL layer 229 (verified against the generated layers of **Telethon 1.45.0**
and **kurigram 2.2.26** in this repo's venvs; both distributions ship these
constructors — pinned per release in `tests/test_wire_golden.py`, the same
drift-guard the passkey constructors use; schema reference:
<https://core.telegram.org/schema>):

| constructor | id |
|---|---|
| `auth.exportLoginToken` | `#b7e085fe` |
| `auth.importLoginToken` | `#95ac5ce4` |
| `auth.loginToken` | `#629f1980` |
| `auth.loginTokenMigrateTo` | `#068e9916` |
| `auth.loginTokenSuccess` | `#390d5c5e` |
| `updateLoginToken` (the update) | `#564fe691` |

The ceremony (`src/tgmint/qrlogin_core.py` — framework-neutral, no
telethon import):

1. `auth.exportLoginToken(api_id, api_hash, except_ids=[])` on the current
   **unauthorized** connection → `auth.loginToken(expires_in, token)` —
   render `tg://login?token=<base64url>` (no padding).
2. Wait for `updateLoginToken` (the QR was scanned + confirmed) until the
   token's server-side deadline; an expired unscanned token is refreshed by
   exporting again.
3. Re-export: `auth.loginTokenSuccess` (same DC — done) or
   `auth.loginTokenMigrateTo(dc_id, token)` (the account lives on another
   DC).
4. Migrate: the **driver** moves the client to `dc_id` and then
   `auth.importLoginToken(token)` there → `auth.loginTokenSuccess`.
5. `SESSION_PASSWORD_NEEDED` from either call is surfaced as the typed
   result `QrPasswordNeeded` — the core never prompts; the driver runs the
   framework's password step on the connection the ceremony ended on.

`except_ids` exists in the wire API for "don't offer accounts already
logged in on this device"; a single-account tool leaves it empty.

## Architecture — the passkey pattern, again

Mirrors `passkeys_core.py` deliberately, so the two ceremonies share every
rule they can:

* **`qrlogin_core.py`** — TL spec as JSON-serializable data, a neutral
  writer/reader, the state machine (`QrLoginMachine`:
  `start/refresh/poll/import_token` + `seconds_left/expired`), and the
  interactive loop (`run_ceremony`). All framework I/O goes through a
  duck-typed invoker (`request_bytes(name, fields) -> bytes`); the
  embedded `auth.Authorization` is parsed by the exact reader the passkey
  ceremony uses (`passkeys_core._read_authorization`), so the two cannot
  disagree about that response.
* **`qrlogin.py`** (Telethon) / **`qrlogin_pyrogram.py`** (kurigram &
  family) — thin drivers: the invoker, the `updateLoginToken` wait, the
  migrate handoff and the post-login bookkeeping (`client._on_login` /
  `storage.user_id` + `is_bot`).
* **`dcswitch.py`** — the DC-switch snapshot/rollback, **shared** with the
  passkey drivers (refactored out of `passkeys.py` /
  `passkeys_pyrogram.py`): Telethon's `client._switch_dc` rewrites the
  caller's session and erases its auth key, so a failed import rolls the
  session back (DC, address, port, key) and re-connects on the restored
  DC; the Pyrogram side is kurigram's own migration recipe
  (`get_session(temporary=True)` + storage swap). A 2FA stop intentionally
  keeps the migrated session — the password step belongs on the account's
  home DC, where a wrong password stays retryable.

Library use:

```python
from tgmint import qrlogin, qrlogin_core

machine = qrlogin.qr_login(client)            # connected, unauthorized
result = await machine.start()                # QrLoginToken -> render .url
...
me = await qrlogin.login_with_qr(client, render=show, timeout=300)
```

The Pyrogram-family driver has the same surface (`tgmint.qrlogin_pyrogram`)
for kurigram/pyrofork clients connected with `await client.connect()`.

## The QR in the terminal — no new dependency

The QR is encoded and rendered by `src/tgmint/qrrender.py`, tgmint's own
pure-Python implementation of the ISO/IEC 18004 slice this needs: byte
mode, levels L and M, versions 1–10 (a login URL is version 3–4), all
eight masks with the ISO penalty rules. Two terminal rows share one line
via the half blocks `▀ ▄ █`, with a four-module quiet zone. Payloads beyond
version 10 raise and the CLI prints the URL alone — never a truncated code.

Correctness is pinned offline, not assumed:
`scripts/regen_qr_golden.py` (run by hand with `pip install qrcode segno`)
records the **qrcode library's** matrices — every version/level at its
exact capacity boundary, realistic login URLs, and all eight masks — into
`tests/golden/qr/qr_vectors.json`, and `tests/test_qrrender.py` asserts
this encoder reproduces them module for module; **segno** second-checks
which version each payload length maps to. (segno's own matrices are not
pinned: it adds an extra zero pad codeword after a byte-aligned terminator
— decodable, but not the ISO/IEC 18004 form the `qrcode` library and this
encoder emit.) The test suite imports neither library; the recorded
fixtures run in CI. No `[qr]` extra exists because nothing external is
needed.

## What tgmint adds

Telethon and kurigram can already log in by QR. tgmint adds one login flow
that works the same in both, a shared DC-switch with rollback, an official
identity for the new session, and a terminal QR code with no extra
dependencies.
