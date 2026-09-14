<!-- vim: syntax=Markdown -->

# opentele

<p align="center">
<img src="https://raw.githubusercontent.com/thedemons/opentele/main/opentele.png" alt="logo" width="180"/>
<br><br>
<a href="https://pypi.org/project/opentele/"><img alt="pypi version" src="https://img.shields.io/pypi/v/opentele?logo=pypi&logoColor=%232d93c1"/></a>
<a href="https://pypi.org/project/opentele/"><img alt="pypi status" src="https://img.shields.io/pypi/status/opentele?color=%2331c754&logo=pypi&logoColor=%232d93c1"/></a>
<a href="https://opentele.readthedocs.io/"><img alt="documentation" src="https://img.shields.io/readthedocs/opentele.svg?color=%2331c754&logo=readthedocs"/></a>
<a href="https://codecov.io/gh/thedemons/opentele">
<img src="https://img.shields.io/codecov/c/github/thedemons/opentele?color=%2331c754&label=codecov&logo=codecov&token=H2IWGEJ5LN"/>
</a>
<a href="https://github.com/thedemons/opentele/actions/workflows/package.yml"><img alt="workflow tests" src="https://img.shields.io/github/workflow/status/thedemons/opentele/package?logo=github&color=%2331c754"/></a>
<a href="https://github.com/thedemons/opentele/issues"><img alt="issues" src="https://img.shields.io/github/issues/thedemons/opentele?color=%2331c754&logo=github"/></a>
<a href="https://github.com/thedemons/opentele/commits/main"><img alt="github last commit" src="https://img.shields.io/github/last-commit/thedemons/opentele?color=%2331c754&logo=github"/></a>
<a href="https://github.com/thedemons/opentele/commits/main"><img alt="github commits" src="https://img.shields.io/github/commit-activity/m/thedemons/opentele?logo=github"/></a>
<a href="https://pypi.org/project/opentele/"><img alt="pypi installs" src="https://img.shields.io/pypi/dm/opentele?label=installs&logo=docusign&color=%2331c754"/></a>
<a href="https://en.wikipedia.org/wiki/MIT_License"><img alt="pypi license" src="https://img.shields.io/pypi/l/opentele?color=%2331c754&logo=gitbook&logoColor=white"/></a>
<a href="https://github.com/psf/black"><img alt="code format" src="https://img.shields.io/badge/code%20style-black-000000.svg?logo=python&logoColor=%232d93c1"/></a>
</p>

<br>

A **Python Telegram API Library** for converting between **tdata** and **telethon** sessions, with built-in **official Telegram APIs**. [**Read the documentation**](https://opentele.readthedocs.io/en/latest/documentation/telegram-desktop/tdesktop/).

# This fork — becoming **tgmint**

This repository continues [thedemons/opentele](https://github.com/thedemons/opentele)
(MIT, 2022), whose author announced they can no longer maintain it. Its git
history is preserved here on purpose: every 2022 commit is theirs, and
everything since the `v1.15.1.post2` tag is ours.

What is different so far (details, sources and the audit in [FORK.md](FORK.md)):

- **Fresh fingerprint data (2026-09)** — Telegram Desktop 7.2.8, Windows 11,
  current glibc / macOS / Apple Silicon / Android / iOS pools; every value
  carries the URL it was verified against.
- **Four audited bug fixes** — `OpenTeleException` was a `BaseException`;
  `APIData.__eq__` was always False and instances were unhashable; PyQt5 was
  imported even for Telethon-only use.
- **PyQt5 is optional** (`pip install opentele[qt]`) — needed only to read or
  write a `tdata` folder.

Sibling forks you may prefer today: [opentele2](https://github.com/DedInc/opentele2)
and [opentele-ng](https://github.com/stufently/opentele) both already removed
Qt and are actively maintained; both ship static (and by now stale) client
versions. This fork's direction — a live version resolver, platform-coherent
fingerprints minted once per account, and a freshness check in CI so the
package cannot quietly rot — is laid out in [PLAN.md](PLAN.md). The rename to
`tgmint` is the next step; until then the import name stays `opentele`.

## Features
- Convert [Telegram Desktop](https://github.com/telegramdesktop/tdesktop) **tdata** sessions to [telethon](https://github.com/LonamiWebs/Telethon) sessions and vice versa.
- Use **telethon** with [official APIs](#authorization) to avoid bot detection.
- Randomize [device info](https://opentele.readthedocs.io/en/latest/documentation/authorization/api/#generate) using real data that recognized by Telegram server.

## Dependencies

- [telethon](https://github.com/LonamiWebs/Telethon) - Widely used Telegram's API library for Python.
- [tgcrypto](https://github.com/pyrogram/tgcrypto) - AES-256-IGE encryption to works with `tdata`.
- [pyQt5](https://www.riverbankcomputing.com/software/pyqt/) - Used by Telegram Desktop to streams data from files.

## Installation
- Install from [PyPI](https://pypi.org/project/opentele/):
```pip title="pip"
pip install --upgrade opentele
```

## First Run
Load TDesktop from tdata folder and convert it to telethon, with a custom API:
```python
from opentele.td import TDesktop
from opentele.tl import TelegramClient
from opentele.api import API, CreateNewSession, UseCurrentSession
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

## Authorization
**opentele** offers the ability to use **official APIs**, which are used by official apps. You can check that out [here](https://opentele.readthedocs.io/en/latest/documentation/authorization/api/#class-api).
<br>

According to [Telegram TOS](https://core.telegram.org/api/obtaining_api_id#using-the-api-id): *all accounts that sign up or log in using unofficial Telegram API clients are automatically put under observation to avoid violations of the Terms of Service*.
<br>
<br>
It also uses the **[lang_pack](https://core.telegram.org/method/initConnection)** parameter, of which [telethon can't use](https://github.com/LonamiWebs/Telethon/blob/dd51aea4db90fd255a14e27192e221c70b45e105/telethon/_client/telegrambaseclient.py#L197) because it's for official apps only.
<br>
Therefore, **there are no differences** between using opentele and official apps, the server can't tell you apart.

## Incoming Features
- [x] Writing data to tdata for converting telethon sessions to tdesktop.
- [x] Random device information for [initConnection](https://core.telegram.org/method/initConnection) to avoid spam-detection.
- [ ] Add support for [pyrogram](https://github.com/pyrogram/pyrogram).
- [ ] Develop opentele-tui using [textual](https://github.com/Textualize/textual) for non-experience user.

## Examples
The best way to learn anything is by looking at the examples. Am I right?

- Example on [readthedocs](https://opentele.readthedocs.io/en/latest/examples/)
- Example on [github](./examples)

## Documentation [![documentation](https://readthedocs.org/projects/opentele/badge/?version=latest&style=flat)](https://opentele.readthedocs.io/)
- Read documentation on [readthedocs](https://opentele.readthedocs.io/en/latest/documentation/telegram-desktop/tdesktop/)
- Read documentation on [github](https://github.com/thedemons/opentele/tree/main/docs-github)
