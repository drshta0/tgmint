# Bot API frameworks (python-telegram-bot, aiogram)

> The honest boundary first: **the Bot API has no client fingerprint surface.**
> python-telegram-bot and aiogram speak HTTPS to a Bot API server; there is
> no MTProto `initConnection`, no `device_model`, no `lang_pack`. Official
> Telegram apps never talk to the Bot API *as users*, so "looking like an
> official app" is not a meaningful goal there — nothing we mint changes
> what a Bot API server can observe about your bot (its token, your IP,
> and your HTTP client's headers).

What tgmint **does** offer Bot API users is the MTProto *side* of hybrid
setups — the part that does carry a fingerprint:

## 1. Self-hosted Bot API server with official credentials

A local [Bot API server](https://core.telegram.org/bots/api#using-a-local-bot-api-server)
is authorized with an `api_id`/`api_hash` pair. Use the pair you obtained
from [core.telegram.org](https://core.telegram.org/api/obtaining_api_id);
tgmint's preset table (`tgmint mint --preset desktop --json`) is a readable
reference of what official clients embed, including the `lang_pack` values
the official apps send — useful when you want your MTProto tooling to match.

```python
from tgmint.api import API

# readable reference of the official Telegram Desktop identity
print(API.TelegramDesktop().to_dict())  # api_id, api_hash, lang_pack, ...
```

```bash
# non-Python tooling: the same data as JSON
python -m tgmint mint --preset desktop --json
```

Point your framework at the local server:

```python
# python-telegram-bot
from telegram import Bot
bot = Bot(token, base_url="http://localhost:8081/bot")
```

```python
# aiogram 3
from aiogram.client.session.aiohttp import AiohttpSession
session = AiohttpSession(api="http://localhost:8081")
```

## 2. The userbot side of a bot+user hybrid

Most Bot-API-only setups eventually need an MTProto **user session** for
things bots cannot do (reading a channel as a member, voice-chat RTMP,
account management). That MTProto session is exactly where fingerprints
matter — mint it once, keep it forever:

```python
from tgmint.api import API

# mint once (sidecar = sticky identity; Telegram remembers the device
# a session signed in with)
api = API.TelegramAndroid.Generate(unique_id="my-helper", layer=224)
api_fingerprint = api  # see PASSKEYS.md / fingerprint sidecars for storage

# convert an existing session you already hold between formats
# (telethon <-> pyrogram-family <-> tdata <-> string sessions)
# python -m tgmint convert --from old.session --from-format telethon-session \
#     --to new.session --to-format pyrogram-session
```

The conversion matrix and the sticky-identity discipline are the same as
for any other framework — see [frameworks.md](frameworks.md).

## 3. What to NOT expect

- No library can make a Bot API bot present an official-client fingerprint;
  there is nothing on that wire to present.
- Telegram's [api_id policy](https://core.telegram.org/api/obtaining_api_id#using-the-api-id)
  applies to the `api_id` your server runs with — use your own credentials
  for servers you operate, and hold MTProto identities only for accounts
  you are entitled to.
