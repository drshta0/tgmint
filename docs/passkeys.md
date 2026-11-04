# Passkeys

Register a passkey on your account once. After that you can log in with
just the passkey file: no phone number, no SMS code. The private key is
created on your machine and never leaves it.

```bash
pip install "tgmint[passkeys]"
```

!!! warning "The file is the login"
    Anyone with the passkey file (plus your 2FA password, if you have one)
    can log in. Back it up, never commit it, never share it.

## Which libraries support it

| Library | Support |
|---|---|
| Telethon | full |
| kurigram ≥ 2.2 | full |
| pyrofork | works, except when the account lives on a different data center than the one you connect to |
| Pyrogram 2.0, Hydrogram | no (too old); use the CLI below and convert |
| GramJS, MadelineProto, anything else | through the CLI |
| Bot API | never; bots don't have passkeys |

## 1. Register

You need a session that's already logged in and **at least about 24 hours
old**. Telegram refuses passkey registration from a fresh login.

=== "Telethon"

    ```python
    from tgmint.passkeys import register_passkey

    info, store = await register_passkey(client, path="me.passkey")
    print(info.id, info.created_on)
    ```

=== "kurigram / pyrofork"

    ```python
    from tgmint.passkeys_pyrogram import register_passkey

    await app.connect()
    info, store = await register_passkey(app, path="me.passkey")
    ```

The passkey now shows up in *Settings → Privacy and Security → Passkeys*.
An account can hold at most 5, and every call creates a new one, so
register once and reuse the file.

## 2. Log in with the file

Use a fresh client that is connected but **not** started (`start()` would
ask for a phone number).

=== "Telethon"

    ```python
    from tgmint.api import API
    from tgmint.tl import TelegramClient
    from tgmint.passkeys import login_with_passkey

    client = TelegramClient("new.session", api=API.TelegramAndroid.Generate())
    await client.connect()
    me = await login_with_passkey(client, path="me.passkey")
    ```

=== "kurigram / pyrofork"

    ```python
    from pyrogram import Client
    from tgmint.api import API
    from tgmint.adapters.pyrogram import client_kwargs
    from tgmint.passkeys_pyrogram import login_with_passkey

    app = Client("new", **client_kwargs(API.TelegramAndroid.Generate()))
    await app.connect()
    me = await login_with_passkey(app, path="me.passkey")
    await app.storage.save()
    ```

=== "CLI (any library)"

    ```bash
    tgmint login-passkey --passkey me.passkey --preset android \
                         --to me.gramjs --to-format gramjs-string
    ```

    `--to-format` can be any session format tgmint writes.

If the account has a 2FA password, pass `password="..."`. The passkey
replaces the SMS code, not the password.

## 3. Bring a dead session back

If Telegram has logged a session out, `heal` logs it back in with the
passkey and rewrites the file in place:

```bash
tgmint heal me.session --passkey me.passkey --live    # checks first, leaves a working session alone
tgmint heal me.session --passkey me.passkey --force   # skips the check
```

It reuses the session's saved identity, so the account sees the same
device as before. It refuses a passkey that belongs to a different account.

To keep everything for one account in one file, seal a profile:

```bash
export TGMINT_PASS='...'
tgmint profile seal --session me.session --from-format telethon-session \
                    --passkey me.passkey --passphrase-env TGMINT_PASS --out me.tgmint
tgmint heal me.tgmint --passkey me.passkey --passphrase-env TGMINT_PASS --live
```

## 4. List and delete

```python
from tgmint.passkeys import list_passkeys, delete_passkey

for pk in await list_passkeys(client):
    print(pk.id, pk.name, pk.last_usage_date)

await delete_passkey(client, pk.id)
```

Frozen accounts can't register passkeys, so set one up while the account
is healthy.

## How it works

Telegram passkeys are standard **WebAuthn** over MTProto (TL layer 230,
reverse-engineered from the official Android client — `PasskeysController.java`).

```
REGISTRATION (needs an authorized session)
  → account.initPasskeyRegistration#429547e8
  ← options JSON:  {"publicKey": {rp, user, challenge, pubKeyCredParams}}
  [we] generate ES256 keypair, build attestation (fmt "none")
  → account.registerPasskey#55b41fd6 (credential)
  ← account.passkey {id, name, date}

LOGIN (needs NOTHING — unauthorized connection)
  → auth.initPasskeyLogin#518ad0b7 {api_id, api_hash}
  ← options JSON:  {"publicKey": {challenge, rpId, allowCredentials}}
  [we] sign:  ES256( authenticatorData ‖ SHA-256(clientDataJSON) )
  → auth.finishPasskeyLogin#9857ad07 (credential, from_dc_id?, from_auth_key_id?)
  ← auth.Authorization {user}        = a normal, fully logged-in session
```

Key mechanics (all handled for you):

- **`user_handle` is `"dcId:userId"`** — the server hides the account's
  home datacenter and user id inside the WebAuthn user id. The login
  request must be sent to that home DC.
- **The login challenge is bound to the connection's auth key** — the
  challenge must be requested on connection X, and if we then switch to
  the home DC, `from_dc_id` + `from_auth_key_id` of X are passed along.
  Wrong order → `PASSKEY_CHALLENGE_EXPIRED`.
- **2FA** still applies after the passkey (`SESSION_PASSWORD_NEEDED`).
- The signature is over `authenticatorData ‖ SHA-256(clientDataJSON)` —
  in THAT order (backwards → `PASSKEY_SIGNATURE_INVALID`).

## The passkey file

```json
{
  "version": 1,
  "credential_id": "<base64url>",
  "rp_id": "telegram.org",
  "origin": "https://web.telegram.org",
  "alg": -7,
  "user_handle": "5:7807325441",
  "private_key": "-----BEGIN PRIVATE KEY-----…",
  "sign_count": 3,
  "telegram_passkey_id": "0erYRbpOq5-7KMhjJnLP5Fd5Fr2XBPFgDa-7lV9bw9s"
}
```

- **This file IS the login.** Treat it like a password: back it up, never
  commit it, never share it.
- `user_handle` gives you `store.home_dc` and `store.user_id`.
- `telegram_passkey_id` is what you pass to `delete_passkey()`.
- Max **5 passkeys per account** — every `register_passkey` call creates
  a NEW credential server-side, so reuse the file for logins instead of
  re-registering.

## API

| Function | Purpose |
|---|---|
| `register_passkey(client, *, path, origin=..., name=...)` | register + save file → `(PasskeyInfo, PasskeyStore)` |
| `login_with_passkey(client, *, path, origin=None, password=None)` | log an unauthorized connected client in → `me` |
| `list_passkeys(client)` | passkeys on the logged-in account |
| `delete_passkey(client, passkey_id)` | remove one server-side |
| `PasskeyStore.load/save` | the credential file |
| `SoftwareAuthenticator` | low-level WebAuthn create/sign |

Raw TL requests are also exported if you want to go manual:
`InitPasskeyRegistrationRequest`, `RegisterPasskeyRequest`,
`GetPasskeysRequest`, `DeletePasskeyRequest`, `InitPasskeyLoginRequest(api_id, api_hash)`,
`FinishPasskeyLoginRequest(credential, from_dc_id, from_auth_key_id)`.

## Verified live behavior

- Server sends `rp.id = "telegram.org"`, offers **ES256 + RS256** (we pick
  ES256), `attestation: "none"`, `residentKey: "required"`.
- Origin `https://web.telegram.org` accepted for registration and login.
- `"5:..."` accounts: login finished on DC 5 with `from_dc_id/from_auth_key_id`
  set when the fresh connection started on DC 2.
- Server tracks `last_usage_date` on passkey logins.
- **Frozen accounts cannot enroll** passkeys (`FrozenMethodInvalid`) —
  register while the account is healthy, not after.

## Errors

| Error | Fix |
|---|---|
| `FrozenMethodInvalidError` | account frozen — passkeys blocked for it |
| `PASSKEY_CHALLENGE_EXPIRED` | internal ordering bug (handled by the lib) |
| `PASSKEY_SIGNATURE_INVALID` | signature format/order mismatch (handled by the lib) |
| `SessionPasswordNeededError` | pass `password="..."` |
| `PasskeyRejectedError` | passkey deleted server-side, or wrong account's file |

## Sources

Official Android client (DrKLO/Telegram 12.10.6): `PasskeysController.java`,
`TL_account.java`, `LoginActivity.java`. Offline crypto tests:
`tests/test_passkeys.py` (23 tests, mock-server signature verification).
