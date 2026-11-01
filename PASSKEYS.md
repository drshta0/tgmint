# tgmint passkeys — log into Telegram without the phone number

`tgmint.passkeys` — register a passkey on any account you have a session
for, then log back in later with **just the passkey file**. No phone, no
SMS, no OTP, no tdata. The private key is generated on your machine and
never leaves it; Telegram only sees a public key and WebAuthn signatures,
exactly like a password manager or hardware key would produce.

Verified working live (two real accounts, full end-to-end).

## Which frameworks can use passkeys

The data and ceremony layer lives in `tgmint.passkeys_core`: it has no
Telethon imports and is driven through one small invoker contract, so each
framework only supplies TL plumbing. What each one gets today:

| Framework | Passkeys | How |
|---|---|---|
| Telethon | Full | `tgmint.passkeys` (`register_passkey`, `login_with_passkey`, same API as before) |
| Pyrogram family: kurigram | Full, including cross-DC logins | `tgmint.passkeys_pyrogram`, native. Needs kurigram >= 2.2 (TL layer 229), which ships all fourteen passkey constructors |
| Pyrogram family: pyrofork | Partial: register, list, delete and same-DC login | `tgmint.passkeys_pyrogram`; pyrofork has no cross-DC session move, so a login whose home DC differs raises an error that says so |
| Pyrogram family: hydrogram | Unsupported | hydrogram 0.2.0 is TL layer 181 and does not ship the passkey constructors; the driver reports that instead of failing obscurely |
| Any other framework (GramJS/Node, tdata, Go, Rust, ...) | Bridged through the CLI | `login-passkey` in (network, once), `convert` out (offline) |
| Bot API | Never | a different protocol with no MTProto surface, so there is nothing to present a passkey to |

The bridge is what makes a passkey-created session usable everywhere. The
`login-passkey` command logs in with only the passkey file over the network,
then writes the session in any codec format; the conversion step is offline.
The client is built from a minted fingerprint, so the session it creates
carries a real device identity rather than a default one.

```sh
# passkey in, session out in any format (offline conversion after one login)
python -m tgmint login-passkey --passkey acc1.passkey.json --preset android \
    --to out.session --to-format gramjs-string
```

For the Pyrogram family the driver is native, so no bridge is needed:

```python
from pyrogram import Client

from tgmint.adapters.pyrogram import client_kwargs
from tgmint.api import API
from tgmint.fingerprint import Fingerprint
from tgmint.passkeys_pyrogram import login_with_passkey, register_passkey

fp = Fingerprint.from_apidata(API.TelegramAndroid.Generate())

# once: an already authorized client registers the passkey
creator = Client("acct", **client_kwargs(fp), in_memory=True)
await creator.connect()
info, store = await register_passkey(creator, path="acc1.passkey.json")
await creator.disconnect()

# later: a fresh connected client, not authorized, plus only the file
client = Client("acc1", **client_kwargs(fp), in_memory=True)
await client.connect()                    # connected, NOT started
me = await login_with_passkey(client, path="acc1.passkey.json")
await client.storage.save()               # the framework owns its storage
```

Use `client.connect()`, never `client.start()`: start is interactive and
prompts for a phone number, which is exactly what a passkey login avoids.

**Own account only.** Registration needs a session you are already logged
into and login needs the passkey file you created there. tgmint never
registers a passkey on somebody else's account and never enables passkey
login for an account you cannot already access. Whoever holds the file (plus
the 2FA password, if one is set) can log in, so treat it like a password.

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

### 3. Recover a dead session (and keep the passkey with it)

A session the server has logged out cannot be repaired locally - which is
exactly when the passkey pays off. `heal` repairs ONE session you own:

```sh
# probe first; an alive session is left untouched
python -m tgmint heal myaccount.session --passkey acc1.passkey.json --live

# no probe, re-login anyway (e.g. you know the session is gone)
python -m tgmint heal myaccount.session --passkey acc1.passkey.json --force
```

It reads the session (any codec format), probes it with a single `get_me`,
and when the server rejects the auth key it signs back in with the passkey
on a client minted from the session's *recorded* fingerprint (a sidecar, or
the fingerprint inside a `.tgmint` envelope, else a freshly minted identity)
and rewrites the session file in place, atomically, in the same format. It
refuses when the passkey belongs to a different account than the session, and
there is deliberately no batch mode: one account, one session, per
invocation.

To make that pairing portable in the first place, put the session, its
fingerprint and the passkey into one envelope:

```sh
# needs the passkeys extra only to SEAL (cryptography)
TGMINT_PASS='...' python -m tgmint profile seal \
    --session myaccount.session --from-format telethon-session \
    --passkey acc1.passkey.json --passphrase-env TGMINT_PASS \
    --out myaccount.tgmint

python -m tgmint profile inspect myaccount.tgmint          # no secrets, no passphrase
TGMINT_PASS='...' python -m tgmint heal myaccount.tgmint --passkey acc1.passkey.json \
    --passphrase-env TGMINT_PASS --live
```

`heal` is verified offline only (fake clients, mocked ceremony, mocked
probe): the live "the dead session really came back" round trip needs an
account whose session you can afford to lose.

### 4. Manage

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
