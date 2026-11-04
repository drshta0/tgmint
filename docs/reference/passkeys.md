# Passkeys

Software passkeys for Telegram (TL layer 230). `passkeys_core` is
framework-neutral (wire spec + ceremony). `passkeys` is the Telethon
driver and `passkeys_pyrogram` is the Pyrogram-family driver. Requires
`pip install tgmint[passkeys]`. See the [Passkeys guide](../passkeys.md).

## Telethon driver

::: tgmint.passkeys
    options:
      show_root_heading: false

## Pyrogram-family driver

::: tgmint.passkeys_pyrogram
    options:
      show_root_heading: false

## Framework-neutral core

::: tgmint.passkeys_core
    options:
      show_root_heading: false
