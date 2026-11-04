<p align="center">
  <img src="docs/assets/logo.svg" alt="tgmint" width="100"/>
</p>

<h1 align="center">tgmint</h1>

<p align="center">
  <b>Make your Telegram scripts connect as the real Telegram app, and avoid bot detection.</b>
</p>

<p align="center">
  <a href="https://pypi.org/project/tgmint/"><img alt="PyPI" src="https://img.shields.io/pypi/v/tgmint?color=0f766e&label=pypi"></a>
  <a href="https://pypi.org/project/tgmint/"><img alt="Python" src="https://img.shields.io/pypi/pyversions/tgmint?color=0f766e"></a>
  <a href="https://github.com/drshta0/tgmint/actions/workflows/package.yml"><img alt="tests" src="https://github.com/drshta0/tgmint/actions/workflows/package.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-0f766e"></a>
</p>

- 🕵️ **Looks like the official app.** Telethon and Pyrogram connect with the official Telegram Desktop, Android or iOS identity instead of announcing themselves as a script.
- 🔑 **Passkey login.** Log in with a file instead of an SMS code. No other Telegram library supports this.
- 🔁 **Any session, any library.** Convert between tdata, Telethon, Pyrogram and GramJS, or import from the Android app. Offline.
- 🧩 **Works with every major framework.** Telethon, kurigram, pyrofork and hydrogram in Python; GramJS, MadelineProto and anything else through the CLI's `--json` output.

## Why it matters

Telegram [automatically puts accounts on unofficial API clients under observation](https://core.telegram.org/api/obtaining_api_id#using-the-api-id), and your library tells Telegram exactly what it is:

| Telegram sees | Telethon | Pyrogram | **tgmint** |
|---|---|---|---|
| App ID | your own | your own | **Telegram Desktop's official one** |
| Device | `PC 64bit` | `CPython 3.12.3` | **`ASUS MB`** |
| System | `6.17.9` | `Linux 6.17.9-76061709-generic` | **`Windows 11 x64`** |
| App version | `1.45.0` | `Pyrogram 2.2.26` | **`7.3.3 x64`** |

tgmint's identities are current (checked weekly against the official apps), consistent (no impossible device and version combinations), and stay the same on every login.

## Quick start

```bash
pip install "tgmint[passkeys]"
```

```python
from tgmint.api import API
from tgmint.tl import TelegramClient

client = TelegramClient("me.session", api=API.TelegramDesktop.Generate(unique_id="me"))
```

```python
from tgmint.passkeys import register_passkey, login_with_passkey

await register_passkey(client, path="me.passkey")             # once
me = await login_with_passkey(new_client, path="me.passkey")  # later: no phone, no SMS
```

```bash
tgmint convert --from tdata/ --from-format tdata --to me.session --to-format telethon-session
```

Also included: QR-code login, one-file encrypted account backups, automatic repair of logged-out sessions, and a CLI for everything.

## Docs

**[Getting started](docs/getting-started.md)** · [How it works](docs/concepts.md) · [Passkeys](docs/passkeys.md) · [CLI](docs/cli.md) · [API reference](docs/reference/index.md) · [Supported libraries](docs/frameworks.md)

## Responsible use

For **your own accounts** only. tgmint has no multi-account tools. It removes the signals that mark your client as a script, but it can't guarantee how Telegram treats an account.

---

MIT · Continues [thedemons/opentele](https://github.com/thedemons/opentele) ([what changed](FORK.md)) · [Contributing](CONTRIBUTING.md)
