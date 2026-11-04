# Pyrogram, kurigram, pyrofork

```bash
pip install "tgmint[passkeys]" kurigram     # or pyrofork, or pyrogram
```

All three import as `pyrogram`. tgmint doesn't patch them. You build the
`Client` with tgmint's identity as keyword arguments.

## Log in as Telegram Android

=== "kurigram / pyrofork"

    ```python
    from pyrogram import Client
    from tgmint.api import API
    from tgmint.adapters.pyrogram import client_kwargs

    fp = API.TelegramAndroid.Generate()
    app = Client("me", **client_kwargs(fp, system_lang_code=True))

    async def main():
        async with app:
            me = await app.get_me()
            print(me.username)

    app.run(main())
    ```

=== "Pyrogram 2.0"

    ```python
    from pyrogram import Client
    from tgmint.api import API
    from tgmint.adapters.pyrogram import client_kwargs

    kwargs = client_kwargs(API.TelegramAndroid.Generate())
    kwargs.pop("lang_pack")          # Pyrogram 2.0 has no lang_pack argument
    app = Client("me", **kwargs)

    async def main():
        async with app:
            print(await app.get_me())

    app.run(main())
    ```

!!! note
    Vanilla Pyrogram can't send `lang_pack`, so it can't fully match an
    official app. Use kurigram if that matters to you.

kurigram also accepts `tz_params=True`, which sends the timezone the way
official apps do.

## Keep the same device on every run

```python
from pyrogram import Client
from tgmint.api import API
from tgmint.fingerprint import Fingerprint
from tgmint.sidecar import sidecar_path_for
from tgmint.adapters.pyrogram import client_kwargs

path = sidecar_path_for("me.session")        # me.fingerprint.json
try:
    fp = Fingerprint.load(path)
except FileNotFoundError:
    fp = Fingerprint.from_apidata(API.TelegramAndroid.Generate())
    fp.save(path)

app = Client("me", **client_kwargs(fp, system_lang_code=True))
```

## Bring a session from Telethon or Telegram Desktop

```bash
# Telethon -> kurigram
tgmint convert --from me.session --from-format telethon-session \
               --to me_pyro.session --to-format pyrogram-session --variant kurigram

# Telegram Desktop -> Pyrogram session string
tgmint convert --from ./tdata --from-format tdata \
               --to me.txt --to-format pyrogram-string
```

```python
app = Client("me", session_string=open("me.txt").read().strip(), **client_kwargs(fp))
```

Use `--variant kurigram` for kurigram and `--variant pyrogram` for
Pyrogram 2.0. For pyrofork, use the string session: its session file has a
newer layout that tgmint doesn't write yet.

## Passkeys

```python
from tgmint.passkeys_pyrogram import register_passkey, login_with_passkey

# once, on a logged-in client
async with app:
    await register_passkey(app, path="me.passkey")

# later: a fresh client, connected but not logged in
app = Client("new", **client_kwargs(fp))
await app.connect()
me = await login_with_passkey(app, path="me.passkey")
await app.storage.save()
```

| Fork | Passkeys |
|---|---|
| kurigram ≥ 2.2 | everything works |
| pyrofork | works, except logging in to an account on another data center |
| Pyrogram 2.0 | not supported (too old) |

## QR login

```python
from tgmint.qrlogin_pyrogram import login_with_qr

app = Client("me", **client_kwargs(fp))
await app.connect()
me = await login_with_qr(app, timeout=300)    # prints a tg://login URL
```
