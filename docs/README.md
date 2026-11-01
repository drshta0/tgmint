# tgmint

A **Python Telegram API library** for converting between **tdata** and
**Telethon** sessions — plus the **Pyrogram-family session codec**, a
**CLI**, and **official-client fingerprints** minted from real, current data.

tgmint continues [thedemons/opentele](https://github.com/thedemons/opentele)
(MIT, 2022), whose author announced they can no longer maintain it. The git
history is preserved on purpose; see the repo's
[FORK.md](https://github.com/drshta0/tgmint/blob/main/FORK.md) and
[ACKNOWLEDGMENTS.md](https://github.com/drshta0/tgmint/blob/main/ACKNOWLEDGMENTS.md).

## Where to start

- **Using another framework?** Start with [Frameworks](frameworks.md) — it
  says exactly what "supported" means per library (Telethon, the Pyrogram
  family, TDLib, the Bot API, GramJS, MadelineProto).
- **Coming from opentele?** [Migration from opentele](migration-from-opentele.md)
  covers the import renames, the Qt-free tdata change, the extras, the
  sidecar pattern, and the API changes (web presets were removed).
- **Make a session behave like the app it claims to be:**
  [Post-auth bootstrap](bootstrap.md) replays the official startup batch
  (read-only only) for the Android or Desktop preset.
- **Log in without a phone number:** [Passkeys](passkeys.md) — register a
  passkey on an account you hold a session for, then log back in with just
  the passkey file.
- **Hands-on first:** [Examples](examples/README.md) — tdata ↔ Telethon
  conversion and official APIs.

## The library in one paragraph

A fingerprint is a handful of strings — `api_id`, `api_hash`,
`device_model`, `system_version`, `app_version`, a language triple, maybe a
timezone. tgmint mints them from **current, cited data** (a resolver keeps
the pins from rotting; a CI job re-checks them), keeps them **coherent**
(the claimed app version genuinely spoke the wire layer in use; the platform
suffixes match the hardware), and keeps them **sticky** (minted once per
account, then reloaded from a sidecar ever after). Thin adapters then carry
the same identity into Telethon (patched client), the Pyrogram family
(`Client` kwargs, no monkey-patching), TDLib (parameter bundle), or anything
else via the CLI's `--json` output. Session files convert between Telethon,
the Pyrogram family, GramJS and tdata — offline, seeded by the `auth_key`.

Use tgmint only on accounts you own or are entitled to hold a session for:
it keeps a session **consistent and current**, and it makes no anti-ban
claims.
