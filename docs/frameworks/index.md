# Frameworks

tgmint works with the library you already use. Pick yours:

| Library | Language | Identity | Session conversion | Passkeys | QR login |
|---|---|---|---|---|---|
| [Telethon](telethon.md) | Python | ✔ built-in client | ✔ | ✔ | ✔ |
| [kurigram](pyrogram.md) | Python | ✔ `Client` kwargs | ✔ | ✔ | ✔ |
| [pyrofork](pyrogram.md) | Python | ✔ `Client` kwargs | ✔ | ✔ same-DC only | ✔ |
| [Pyrogram](pyrogram.md) | Python | ✔ `Client` kwargs (no `lang_pack`) | ✔ | ✘ | untested |
| [Hydrogram](hydrogram.md) | Python | ✔ `Client` kwargs (no `lang_pack`) | ✔ string session | ✘ | ✘ |
| [GramJS](gramjs.md) | Node.js | ✔ via CLI JSON | ✔ string session | via CLI | via CLI |
| [MadelineProto](madelineproto.md) | PHP | ✔ via CLI JSON | via Telethon/Pyrogram file | via CLI | via CLI |
| [TDLib](tdlib.md) | any | ✔ `setTdlibParameters` | ✘ | ✘ | ✘ |
| [Bot API](bot-api.md) (aiogram, python-telegram-bot) | any | ✘ nothing to set | ✘ | ✘ | ✘ |

"Via CLI" means tgmint logs in and writes the session in that library's
format; your code never imports tgmint.

## How it fits together

An **identity** (a `Fingerprint`) is a few strings: `api_id`, `api_hash`,
`device_model`, `system_version`, `app_version`, and the language fields.
Every MTProto library sends these when it connects. tgmint generates
realistic ones and saves them next to the session so the account always
shows up as the same device.

A **session** is the `auth_key` and data center. `tgmint convert` moves it
between formats offline:

| from \ to | Telethon file | Telethon string | Pyrogram file | Pyrogram string | tdata | GramJS string |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Telethon file | | ✔ | ✔ | ✔ | ✔ | ✔ |
| Pyrogram file | ✔ | ✔ | | ✔ | ✔ | ✔ |
| tdata | ✔ | ✔ | ✔ | ✔ | | ✔ |
| GramJS string | ✔ | ✔ | ✔ | ✔ | ✔ | |
| `.tgmint` profile | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| Android app data | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |

Use the same `api_id` / `api_hash` the identity carries when you open a
converted session.
