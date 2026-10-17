# tgmint passkeys — log into Telegram without the phone number

`tgmint.passkeys` — register a passkey on any account you have a session
for, then log back in later with **just the passkey file**. No phone, no
SMS, no OTP, no tdata. The private key is generated on your machine and
never leaves it; Telegram only sees a public key and WebAuthn signatures,
exactly like a password manager or hardware key would produce.

Verified working live (two real accounts, full end-to-end).

---

## Install

```pip
pip install cryptography        # or: pip install tgmint[passkeys]
```

## Usage

### 1. Register — while you still have ANY authorized session

```python
from tgmint.passkeys import register_passkey

info, store = await register_passkey(client, path="acc1.passkey.json")
print(info.id, info.created_on)
```

`client` = any connected client authorized for the account (from tdata,
an existing .session, whatever). The account now shows a new passkey in
Settings → Privacy & Security → Passkeys, and `acc1.passkey.json`
(chmod 600) is the credential.

### 2. Log in later — with NOTHING but the file

```python
from tgmint.api import API
from tgmint.tl import TelegramClient
from tgmint.passkeys import login_with_passkey

client = TelegramClient("recovered.session", api=API.TelegramAndroid.Generate())
await client.connect()                    # connected, NOT authorized
me = await login_with_passkey(client, path="acc1.passkey.json")
# "recovered.session" is now a fully authorized session
```

No phone number involved anywhere. If the account has a 2FA cloud
password, pass `password="..."` (the passkey replaces the OTP, not the
password — by design).

### 3. Manage

```python
from tgmint.passkeys import list_passkeys, delete_passkey

for pk in await list_passkeys(client):
    print(pk.id, pk.name, "last used:", pk.last_usage_date)

await delete_passkey(client, pk.id)   # remove from the account
```

---

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
