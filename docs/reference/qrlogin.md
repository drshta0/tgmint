# QR login

Log in by scanning a code from a phone where you're already signed in.
Supports DC migration and 2FA. Same layout as passkeys: one
framework-neutral ceremony plus thin drivers. See the
[QR login guide](../qr-login.md).

## Telethon driver

::: tgmint.qrlogin
    options:
      show_root_heading: false

## Pyrogram-family driver

::: tgmint.qrlogin_pyrogram
    options:
      show_root_heading: false

## Framework-neutral core

::: tgmint.qrlogin_core
    options:
      show_root_heading: false
