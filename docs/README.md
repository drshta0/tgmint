---
hide:
  - navigation
---

# tgmint

**Make your Telegram scripts connect as the real Telegram app, and avoid bot detection.**

Telegram's terms say accounts using unofficial API clients are
[automatically put under observation](https://core.telegram.org/api/obtaining_api_id#using-the-api-id),
and Telethon and Pyrogram identify themselves on every connection, as
`PC 64bit` or `CPython 3.12.3` running `Pyrogram 2.2.26`. tgmint makes them connect with
the same device, system, app version and language the official Telegram
Desktop, Android or iOS app sends. It also adds passkey login, which no
other library has, and converts sessions between every major library.

```bash
pip install "tgmint[passkeys]"
```

<div class="grid cards" markdown>

-   :material-cellphone-check: **Connects as the real app**

    ---

    Official app identity, current versions checked weekly, and no
    impossible combinations. The same device is reused on every login.

    [:octicons-arrow-right-24: How it works](concepts.md)

-   :material-key-variant: **Passkey login**

    ---

    Register once, then log in with just a file. No phone number, no SMS.
    Telethon and Pyrogram don't support this; tgmint does, for both.

    [:octicons-arrow-right-24: Passkeys](passkeys.md)

-   :material-swap-horizontal: **Move sessions anywhere**

    ---

    Telegram Desktop `tdata`, Telethon, Pyrogram, GramJS, and the official
    Android app's data folder. Any direction, offline.

    [:octicons-arrow-right-24: Getting started](getting-started.md)

-   :material-qrcode: **QR login**

    ---

    Scan a code from your phone and get a session in any format, already
    using an official identity.

    [:octicons-arrow-right-24: QR login](qr-login.md)

-   :material-backup-restore: **One-file backup, self-repair**

    ---

    Pack a session, its identity and its passkey into one optionally
    password-protected file. `tgmint heal` signs a logged-out session back
    in.

    [:octicons-arrow-right-24: Account backup](reference/profile.md)

-   :material-console: **A CLI for everything**

    ---

    14 commands with `--json` output. Node, PHP and shell scripts can use
    tgmint without writing any Python.

    [:octicons-arrow-right-24: CLI reference](cli.md)

</div>

## Where to start

- **New here?** [Getting started](getting-started.md) has three short
  recipes.
- **Which library?** [Frameworks](frameworks/index.md) has a working
  example for Telethon, Pyrogram, kurigram, Hydrogram, GramJS,
  MadelineProto and TDLib.
- **Coming from opentele?** See [Migration from opentele](migration-from-opentele.md).

!!! note "Your own accounts only"
    tgmint makes your client accurate. It has no tools for running many
    accounts at once, and it can't promise how Telegram treats an account.

tgmint continues [thedemons/opentele](https://github.com/thedemons/opentele)
(MIT, 2022) with its full history.
