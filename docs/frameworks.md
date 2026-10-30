# Frameworks — what "supported" means

tgmint's core is framework-neutral: a minted identity is a
[`Fingerprint`](./documentation/authorization/api.md) — a handful of strings
(`api_id`, `api_hash`, `device_model`, `system_version`, `app_version`, the
language triple, optionally a timezone). Everything else is adapters: thin,
honest glue between that object and whatever client library you already use.
This page says exactly what each framework gets, and by what mechanism — no
framework is listed as "supported" without saying what that means.

| Framework | Level of support | Mechanism |
|---|---|---|
| **Telethon** | **Full** — patched client + conversion + passkeys | `tgmint.tl.TelegramClient` |
| **Pyrogram family** (kurigram, pyrofork, vanilla pyrogram, hydrogram) | **Fingerprint kwargs + session codec** | `Client(**client_kwargs(fingerprint))` — from `tgmint.adapters.pyrogram` |
| **TDLib** wrappers (python-tdlib, aiotdlib) | **Parameters bundle** | exported device/app strings for `setOption` / auth params |
| **Bot API** (python-telegram-bot, aiogram) | **Docs & recipes only** — no fingerprint surface exists | n/a (HTTPS API) |
| **GramJS** (Node) | **CLI `--json` + session codec** | `python -m tgmint mint --json`; string sessions |
| **MadelineProto** (PHP) | **CLI `--json` + session codec** | auth_key export/import |
| **Anything else / non-Python** | **CLI `--json` + sidecar JSON** | `python -m tgmint mint --json` |

## Telethon — full

The original home. `tgmint.tl.TelegramClient` subclasses Telethon's client and
overrides the point where `initConnection` is constructed, so the minted
fingerprint — including `lang_pack` (e.g. `tdesktop`), which stock Telethon
cannot send — reaches the wire. The override is **scoped to this client
class**: upstream opentele patched Telethon's `InitConnectionRequest`
constructor process-wide, which is why two extended clients could not coexist
in one process. On top of the client you get tdata ↔ Telethon conversion and
[`tgmint.passkeys`](https://github.com/drshta0/tgmint/blob/main/PASSKEYS.md).

*Support means:* you use our client class; conversion and passkeys work
end-to-end.

## Pyrogram family — kwargs adapter + session codec

kurigram (the active Pyrogram successor), pyrofork and vanilla pyrogram all
share the `pyrogram` import name, and their `Client` constructor already
accepts `device_model`, `system_version`, `app_version`, `lang_code` and
`lang_pack` as plain keyword arguments
([docs](https://docs.pyrogram.org/api/client)). So the adapter is exactly one
step: a `Fingerprint` expands to those kwargs. hydrogram imports as
`hydrogram` rather than `pyrogram`, but its `Client` mirrors the same
constructor, so the same kwargs apply.

```python
from tgmint.adapters.pyrogram import client_kwargs
from pyrogram import Client

app = Client("myaccount", **client_kwargs(fingerprint))
```

No monkey-patching is needed or done — your client stays stock Pyrogram; you
just construct it with our strings instead of the defaults. The session codec
(above) also reads and writes Pyrogram-family `.session` files and string
sessions, so accounts move between Telethon and the Pyrogram family offline.

*Support means:* you construct the `Client` yourself with our kwargs; session
files convert in both directions.

## TDLib — parameters bundle

TDLib does fingerprinting the same way everyone does (`initConnection`), but
wrappers configure it through options and authorization parameters rather
than a Python client object. tgmint exports the bundle —
`device_model` / `system_version` / `app_version` (plus the language fields)
— for TDLib's `setOption` calls and `authorization` parameters. TDLib's own
session storage (binlog) is a different format and is **not** converted.

*Support means:* you get the right strings to feed your TDLib wrapper; nothing
is injected for you.

## Bot API — no fingerprint surface, on purpose

The Bot API is plain HTTPS. There is no `initConnection`, no `device_model`,
nothing a client could present itself with — so there is nothing to mint, and
tgmint does not pretend otherwise. What the docs offer instead: API presets
for self-hosted [Bot API servers](https://core.telegram.org/bots/api#using-a-local-bot-api-server),
the sidecar pattern for the user-account (MTProto) side of such setups, and
the session codecs.

*Support means:* recipes and honest documentation — by definition, no
fingerprint support exists to have.

## GramJS / MadelineProto — CLI JSON + session codec

Not Python, so no import-level adapter. Two bridges cover them:

- `python -m tgmint mint --json` prints a minted fingerprint as stable JSON
  (same schema as the sidecar files) for any runtime to consume;
- the session codec converts GramJS string sessions (and, for MadelineProto,
  auth_key export/import is trivial JSON) to and from Telethon /
  Pyrogram-family / tdata.

*Support means:* you shell out to the CLI and/or convert session strings; your
process never imports tgmint.

## The CLI as the universal adapter

Every CLI command takes `--json`:

| Command | Purpose |
|---|---|
| `python -m tgmint mint` | mint a fingerprint (optionally `--layer N`, `--json`) |
| `python -m tgmint inspect` | show what a session/tdata folder contains |
| `python -m tgmint audit` | coherence + staleness report for an identity |
| `python -m tgmint freshness` | compare built-in pins against live versions |
| `python -m tgmint parity` | diff a preset against the official client's real parameters |
| `python -m tgmint convert` | convert sessions across the codec matrix |
| `python -m tgmint doctor` | environment and dependency diagnostics |

This is also the answer for frameworks with no row in the table above: mint
with `--json`, store the sidecar, feed your client of choice.

## Session conversion matrix

The codec is offline and stdlib-only: every conversion is seeded by the
`auth_key` found in the source session — no login, no network.

| from \ to | Telethon `.session` | Telethon string | Pyrogram `.session` | Pyrogram string | tdata | GramJS string |
|---|---|---|---|---|---|---|
| Telethon `.session` | — | ✔ | ✔ | ✔ | ✔ | ✔ |
| Pyrogram `.session` | ✔ | ✔ | — | ✔ | ✔ | ✔ |
| tdata | ✔ | ✔ | ✔ | ✔ | — | ✔ |
| GramJS string | ✔ | ✔ | ✔ | ✔ | ✔ | — |

See [migration-from-opentele.md](migration-from-opentele.md) for coming from
upstream opentele, and the [README](https://github.com/drshta0/tgmint#frameworks)
for the short version of this table.
