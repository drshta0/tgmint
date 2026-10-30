<!-- vim: syntax=Markdown -->

# tgmint

<p align="center">
<img src="opentele.png" alt="logo" width="180"/>
<br><br>
<a href="https://pypi.org/project/tgmint/"><img alt="pypi version" src="https://img.shields.io/pypi/v/tgmint?logo=pypi&logoColor=%232d93c1"/></a>
<a href="https://pypi.org/project/tgmint/"><img alt="python versions" src="https://img.shields.io/pypi/pyversions/tgmint?logo=python&logoColor=%23ffd845"/></a>
<a href="https://en.wikipedia.org/wiki/MIT_License"><img alt="pypi license" src="https://img.shields.io/pypi/l/tgmint?color=%2331c754&logo=gitbook&logoColor=white"/></a>
<a href="https://github.com/drshta0/tgmint/commits/main"><img alt="github last commit" src="https://img.shields.io/github/last-commit/drshta0/tgmint?color=%2331c754&logo=github"/></a>
</p>

<br>

A **Python Telegram API library** for converting between **tdata** and **Telethon** sessions — plus the **Pyrogram-family session codec**, a **CLI**, and **official-client fingerprints** minted from real, current data. [**Read the documentation**](./docs/documentation/README.md).

# This fork — becoming **tgmint**

This repository continues [thedemons/opentele](https://github.com/thedemons/opentele)
(MIT, 2022), whose author announced they can no longer maintain it. Its git
history is preserved here on purpose: every 2022 commit is theirs, and
everything since the `v1.15.1.post2` tag is ours. See
[ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md) for everything that was taken with
gratitude.

What is different so far (details, sources and the audit in [FORK.md](FORK.md)):

- **Fresh fingerprint data** — Telegram Desktop, Android, iOS and macOS pools
  refreshed from live sources; every value carries the URL it was verified
  against, and a resolver keeps pins from quietly rotting.
- **Qt-free tdata** — the tdata reader/writer is pure Python (its own
  `QDataStream` implementation). PyQt5 is no longer a dependency; it remains
  an optional fallback via `pip install tgmint[qt]`.
- **Session codec matrix** — Telethon (SQLite + string), Pyrogram-family
  (kurigram / pyrofork / vanilla / hydrogram) and GramJS session formats
  convert into each other and into tdata, offline, seeded only by the
  `auth_key`.
- **Pyrogram-family adapter** — a minted fingerprint expands to
  `pyrogram.Client` kwargs; no monkey-patching. TDLib gets a parameter
  bundle; the Bot API has **no fingerprint surface** and we say so instead of
  papering over it (see [Frameworks](#frameworks)).
- **CLI** — `python -m tgmint mint | inspect | audit | freshness | parity |
  convert | login-passkey | doctor`, every command `--json`-able for
  non-Python callers.
- **Layer coherence** — `Generate(layer=N)` picks an app version that
  genuinely spoke wire layer N (old version + old layer = plausible; new
  version + old layer = impossible — that mismatch is the tell it fixes).
  The unverifiable web presets (`TelegramWeb_Z`, `TelegramWeb_K`,
  `Webogram`) were removed rather than shipped stale.
- **Ping-cadence presets** — shipped as inert reference data (numbers from
  official-client source), with no behavioral claim attached.
- **Four audited bug fixes** — `OpenTeleException` was a `BaseException`;
  `APIData.__eq__` was always False and instances were unhashable; PyQt5 was
  imported even for Telethon-only use; the global `InitConnectionRequest`
  monkey-patch is now scoped to our own client.
- **Software passkeys** (`tgmint.passkeys`, `pip install tgmint[passkeys]`)
  — register a passkey on an account you hold a session for, then
  [log back in with just the passkey file](PASSKEYS.md):
  no phone number, no OTP. Wire format reverse-engineered from the official
  Android client (TL layer 230).

Sibling forks you may prefer today: [opentele2](https://github.com/DedInc/opentele2)
and [opentele-ng](https://github.com/stufently/opentele) both removed Qt early
and are actively maintained; both ship static (and by now stale) client
versions. This fork's direction — a live version resolver, layer-coherent
fingerprints minted once per account, and a freshness check in CI so the
package cannot quietly rot — is laid out in [PLAN.md](PLAN.md). The rename to
`tgmint` landed in v1.15.1.post3: the import name is now `tgmint` (it was
`opentele` through v1.15.1.post2; see
[docs/migration-from-opentele.md](./docs/migration-from-opentele.md)).

## Features
- Convert [Telegram Desktop](https://github.com/telegramdesktop/tdesktop) **tdata** sessions to [telethon](https://github.com/LonamiWebs/Telethon) sessions and vice versa — **Qt-free** (pure-Python tdata codec; PyQt5 optional).
- Convert **any supported session format** to any other — Telethon, Pyrogram-family (kurigram / pyrofork / hydrogram), GramJS, tdata — offline, from the `auth_key`.
- Use **telethon** with [official APIs](#authorization): a scoped client override puts the real fingerprint (and `lang_pack`) on the wire — no global monkey-patching.
- Randomize [device info](./docs/documentation/authorization/api.md) using real, current data recognized by the Telegram server — coherent per platform, deterministic per `unique_id`, and sticky per account via a sidecar file.
- Mint **layer-coherent** identities: `Generate(layer=N)` claims an app version that actually spoke wire layer N.
- Use the **Pyrogram family** with the same fingerprints — `Client` kwargs adapter, no monkey-patching — and export **TDLib** parameters.
- Drive everything from the **CLI**: `python -m tgmint mint | inspect | audit | freshness | parity | convert | login-passkey | doctor`, all `--json`-able.
- **Software passkeys** ([PASSKEYS.md](PASSKEYS.md)) — register once, then log in with just the passkey file: native in Telethon and in the Pyrogram family (full on kurigram, partial on pyrofork), and bridged to **any** session format through `python -m tgmint login-passkey`. The Bot API cannot use them and the docs say so.

## Frameworks

What "supported" means depends on the framework — this table is the honest
version (details and mechanisms: [docs/frameworks.md](./docs/frameworks.md)).

| Framework | What you get | Mechanism |
|---|---|---|
| [Telethon](https://github.com/LonamiWebs/Telethon) | Full: patched client + conversion + passkeys | `tgmint.tl.TelegramClient` (scoped `initConnection` override, `lang_pack=tdesktop` on the wire) |
| [Pyrogram](https://github.com/pyrogram/pyrogram) family — [kurigram](https://github.com/KurimuzonAkuma/pyrogram), [pyrofork](https://github.com/Mayuri-Chan/pyrofork), [hydrogram](https://github.com/hydrogram/hydrogram) | Fingerprint kwargs adapter + session codec + native passkeys (kurigram; pyrofork partial; hydrogram no) | `Client(**kwargs)` — Pyrogram's own `device_model` / `system_version` / `app_version` / `lang_code` / `lang_pack` parameters; no monkey-patching. Passkeys: `tgmint.passkeys_pyrogram` |
| [TDLib](https://github.com/tdlib/td) (python-tdlib, aiotdlib) | Parameters bundle | `device_model` / `system_version` / `app_version` exported for `setOption` and auth params |
| Bot API ([python-telegram-bot](https://github.com/python-telegram-bot/python-telegram-bot), aiogram) | Recipes and docs only | The Bot API has **no fingerprint surface** (HTTPS, no `initConnection`) — documented, not papered over |
| [GramJS](https://github.com/gram-js/gramjs) (Node), [MadelineProto](https://github.com/danog/MadelineProto) (PHP) | CLI `--json` + session codec | `python -m tgmint mint --json`; string-session conversion |

## Dependencies

- [telethon](https://github.com/LonamiWebs/Telethon) - Widely used Telegram's API library for Python.
- [tgcrypto](https://github.com/pyrogram/tgcrypto) - AES-256-IGE encryption to works with `tdata`.
- Optional: `pyqt5` (`pip install tgmint[qt]`) — legacy fallback for the tdata codec; `cryptography` (`pip install tgmint[passkeys]`) — for passkey create/sign.

## Installation
- Install from [PyPI](https://pypi.org/project/tgmint/):
```pip title="pip"
pip install --upgrade tgmint
```
- Until the first PyPI release:
```pip title="pip"
pip install git+https://github.com/drshta0/tgmint
```

## First Run
Load TDesktop from tdata folder and convert it to telethon, with a custom API:
```python
from tgmint.td import TDesktop
from tgmint.tl import TelegramClient
from tgmint.api import API, CreateNewSession, UseCurrentSession
import asyncio

async def main():
    
    # Load TDesktop client from tdata folder
    tdataFolder = r"C:\Users\<username>\AppData\Roaming\Telegram Desktop\tdata"
    tdesk = TDesktop(tdataFolder)

    # Using official iOS API with randomly generated device info
    # print(api) to see more
    api = API.TelegramIOS.Generate()

    # Convert TDesktop session to telethon client
    # CreateNewSession flag will use the current existing session to
    # authorize the new client by `Login via QR code`.
    client = await tdesk.ToTelethon("newSession.session", CreateNewSession, api)

    # Although Telegram Desktop doesn't let you authorize other
    # sessions via QR Code (or it doesn't have that feature),
    # it is still available across all platforms (APIs).

    # Connect and print all logged in devices
    await client.connect()
    await client.PrintSessions()

asyncio.run(main())
```

For the **Pyrogram family**, mint a fingerprint and pass it as client kwargs —
and mint once, then reload the sidecar ever after, so the account keeps the
identity it was born with:

```python
from tgmint.api import API
from tgmint.fingerprint import Fingerprint
from tgmint.sidecar import sidecar_path_for
from tgmint.adapters.pyrogram import client_kwargs
from pyrogram import Client

# once: mint and save next to the session file (0600, atomic)
fp = Fingerprint.from_apidata(API.TelegramAndroid.Generate(layer=224))
fp.save(sidecar_path_for("myaccount.session"))

# ever after: reload instead of re-rolling
fp = Fingerprint.load(sidecar_path_for("myaccount.session"))

app = Client("myaccount", **client_kwargs(fp))
```

## Authorization
**tgmint** offers the ability to use **official APIs**, which are used by official apps. You can check that out [here](./docs/documentation/authorization/api.md).
<br>

According to [Telegram TOS](https://core.telegram.org/api/obtaining_api_id#using-the-api-id): *all accounts that sign up or log in using unofficial Telegram API clients are automatically put under observation to avoid violations of the Terms of Service*.
<br>
<br>

It also uses the **[lang_pack](https://core.telegram.org/method/initConnection)** parameter, of which [telethon can't use](https://github.com/LonamiWebs/Telethon/blob/dd51aea4db90fd255a14e27192e221c70b45e105/telethon/_client/telegrambaseclient.py#L197) because it's for official apps only.
<br>
Therefore, the `initConnection` payload a tgmint client puts on the wire is the payload the official client would have sent.

Use tgmint only on accounts you own or are entitled to hold a session for: it keeps a session **consistent and current**, and it makes no anti-ban claims.

## Roadmap
- [x] Writing data to tdata for converting telethon sessions to tdesktop.
- [x] Random device information for [initConnection](https://core.telegram.org/method/initConnection) with coherent, cited data.
- [x] Support for the [pyrogram](https://github.com/pyrogram/pyrogram) family (kurigram / pyrofork / hydrogram) via the kwargs adapter — see [Frameworks](#frameworks).
- [ ] A tgmint TUI using [textual](https://github.com/Textualize/textual) for non-experienced users.

## Examples
The best way to learn anything is by looking at the examples. Am I right?

- Examples in this repo's [docs/examples](./docs/examples/README.md)
- Runnable examples on [github](./examples)

## Documentation
- Browse the documentation sources in [docs](./docs/documentation/README.md) — the same pages build the mkdocs site (see [mkdocs.yml](mkdocs.yml) and [.readthedocs.yml](.readthedocs.yml)).
- Framework support matrix: [docs/frameworks.md](./docs/frameworks.md)
- Migrating from opentele: [docs/migration-from-opentele.md](./docs/migration-from-opentele.md)
- Passkeys: [PASSKEYS.md](PASSKEYS.md) · Fork audit: [FORK.md](FORK.md) · Plan: [PLAN.md](PLAN.md)
