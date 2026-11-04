# Hydrogram

```bash
pip install tgmint hydrogram
```

Hydrogram's `Client` takes the same identity arguments as Pyrogram except
`lang_pack`, so drop that one.

```python
from hydrogram import Client
from tgmint.api import API
from tgmint.fingerprint import Fingerprint
from tgmint.sidecar import sidecar_path_for
from tgmint.adapters.pyrogram import client_kwargs

path = sidecar_path_for("me.session")
try:
    fp = Fingerprint.load(path)
except FileNotFoundError:
    fp = Fingerprint.from_apidata(API.TelegramAndroid.Generate())
    fp.save(path)

kwargs = client_kwargs(fp)
kwargs.pop("lang_pack")               # Hydrogram has no lang_pack argument
app = Client("me", **kwargs)

async def main():
    async with app:
        print(await app.get_me())

app.run(main())
```

## Bring a session from another library

Hydrogram reads Pyrogram session strings:

```bash
tgmint convert --from me.session --from-format telethon-session \
               --to me.txt --to-format pyrogram-string
```

```python
app = Client("me", session_string=open("me.txt").read().strip(), **kwargs)
```

## Not supported

Passkeys and tgmint's QR login need TL constructors newer than the ones
Hydrogram ships. To get a Hydrogram session through a passkey, log in with
the CLI and convert:

```bash
tgmint login-passkey --passkey me.passkey --preset android \
                     --to me.txt --to-format pyrogram-string
```
