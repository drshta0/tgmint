# Telethon client

A drop-in `telethon.TelegramClient` subclass that sends the official
client's `initConnection` (including `lang_pack`), scoped to this client
only. It does not monkey-patch Telethon globally.

::: tgmint.tl.telethon.TelegramClient
