# Telethon

```bash
pip install "tgmint[passkeys]"
```

`tgmint.tl.TelegramClient` is Telethon's `TelegramClient` with one change:
it sends the identity you give it instead of Telethon's defaults. Everything
else is plain Telethon.

## Log in as Telegram Desktop

```python
import asyncio
from tgmint.api import API
from tgmint.tl import TelegramClient

async def main():
    api = API.TelegramDesktop.Generate(unique_id="me")
    client = TelegramClient("me.session", api=api)
    await client.start()                 # asks for phone and code, as usual
    me = await client.get_me()
    print(me.username)

asyncio.run(main())
```

Other presets: `API.TelegramAndroid`, `API.TelegramAndroidX`,
`API.TelegramIOS`, `API.TelegramMacOS`, `API.TelegramDesktopFlatpak`.

## Keep the same device on every run

Save the identity once and load it after that. This survives tgmint
upgrades, which `unique_id` alone does not when device pools change.

```python
from tgmint.api import API, APIData
from tgmint.fingerprint import Fingerprint
from tgmint.sidecar import sidecar_path_for
from tgmint.tl import TelegramClient

def identity_for(session: str) -> APIData:
    path = sidecar_path_for(session)          # me.session -> me.fingerprint.json
    try:
        fp = Fingerprint.load(path)
    except FileNotFoundError:
        fp = Fingerprint.from_apidata(API.TelegramDesktop.Generate())
        fp.save(path)
    fields = fp.to_dict()
    del fields["origin"], fields["schema_version"]
    return APIData(**fields)

client = TelegramClient("me.session", api=identity_for("me.session"))
```

## Open a Telegram Desktop `tdata` folder

```python
import asyncio
from tgmint.td import TDesktop
from tgmint.api import UseCurrentSession

async def main():
    tdesk = TDesktop(r"C:\Users\me\AppData\Roaming\Telegram Desktop\tdata")
    assert tdesk.isLoaded()

    client = await tdesk.ToTelethon("me.session", flag=UseCurrentSession)
    await client.connect()
    print(await client.get_me())

asyncio.run(main())
```

`UseCurrentSession` reuses the desktop app's login. `CreateNewSession`
logs in a second device through the first one instead (slower, needs
`password=` if 2FA is on).

## Write a `tdata` folder from a Telethon session

```python
from tgmint.api import UseCurrentSession

client = TelegramClient("me.session")
tdesk = await client.ToTDesktop(flag=UseCurrentSession)
tdesk.SaveTData("./tdata")
```

Offline alternative, no login:

```bash
tgmint convert --from me.session --from-format telethon-session \
               --to ./tdata --to-format tdata
```

## Passkeys

```python
from tgmint.passkeys import register_passkey, login_with_passkey

# once, on a logged-in client
await register_passkey(client, path="me.passkey")

# later, on a fresh client that is connected but not logged in
client = TelegramClient("new.session", api=API.TelegramDesktop.Generate())
await client.connect()
me = await login_with_passkey(client, path="me.passkey")
```

See [Passkeys](../passkeys.md) for limits.

## QR login

```python
from tgmint.qrlogin import login_with_qr

client = TelegramClient("me.session", api=API.TelegramDesktop.Generate())
await client.connect()
me = await login_with_qr(client, timeout=300)   # prints a tg://login URL
```

Scan it from *Settings → Devices → Link Desktop Device* on your phone.
`tgmint login-qr` does the same with a QR code drawn in the terminal.
