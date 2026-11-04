# Getting started

## Install

```bash
pip install tgmint                # core: conversion, fingerprints, CLI
pip install "tgmint[passkeys]"    # + passkeys and sealed .tgmint envelopes
```

Requires Python 3.9+. The core dependencies are `telethon` and `tgcrypto`.
Qt isn't needed: tdata is read and written in pure Python. Run
`tgmint doctor` to see what's installed and what's optional.

## Recipe 1: move a session to another framework (CLI, offline)

```bash
# Telegram Desktop folder -> Telethon session
tgmint convert --from ~/.local/share/TelegramDesktop/tdata --from-format tdata \
               --to me.session --to-format telethon-session

# Telethon -> kurigram (Pyrogram-family SQLite schema)
tgmint convert --from me.session --from-format telethon-session \
               --to me_pyro.session --to-format pyrogram-session --variant kurigram

# Check any session without touching the network
tgmint verify me_pyro.session
```

Nothing goes over the network. Only the `auth_key` moves, and output files are
written with mode `0600`. If the tdata folder has a local passcode, pass
`--passcode-env VAR`. Secrets are never taken as command-line arguments.

## Recipe 2: give an account an official identity, and keep it

Mint the identity once, save it next to the session, and reload it every
time after. A real device doesn't change model between logins, so your
account shouldn't either.

=== "Telethon"

    ```python
    from tgmint.api import API
    from tgmint.tl import TelegramClient

    api = API.TelegramDesktop.Generate(unique_id="me.session")  # same id -> same identity
    client = TelegramClient("me.session", api=api)
    ```

=== "Pyrogram family"

    ```python
    from pyrogram import Client
    from tgmint.api import API
    from tgmint.fingerprint import Fingerprint
    from tgmint.sidecar import sidecar_path_for
    from tgmint.adapters.pyrogram import client_kwargs

    path = sidecar_path_for("me.session")
    try:
        fp = Fingerprint.load(path)                      # every later run
    except FileNotFoundError:
        fp = Fingerprint.from_apidata(API.TelegramAndroid.Generate())
        fp.save(path)                                    # first run only

    app = Client("me", **client_kwargs(fp))
    ```

=== "CLI / other languages"

    ```bash
    tgmint mint --preset android --unique-id me --save me.fingerprint.json
    tgmint mint --preset desktop --system linux --json   # feed GramJS / MadelineProto
    ```

## Recipe 3: make the account recoverable without SMS

```python
from tgmint.passkeys import register_passkey

# client: a logged-in tgmint/Telethon client. The private key is written to
# me.passkey (mode 0600). Keep that file safe: it's all you need to log back in.
info, store = await register_passkey(client, path="me.passkey")
```

Bundle the session, its fingerprint and the passkey into one file:

```bash
export TGMINT_PASS='…'
tgmint profile seal --session me.session --from-format telethon-session \
                    --passkey me.passkey --out me.tgmint --passphrase-env TGMINT_PASS
```

If the session ever dies, `tgmint heal` signs it back in with the bundled
passkey. See [Passkeys](passkeys.md) for server-side limits. Telegram
decides when a passkey login is accepted.

## Next

- [How it works](concepts.md): what Telegram sees and how tgmint makes it match the real app
- [CLI reference](cli.md): every command and flag
- [API reference](reference/index.md): every public class and function
