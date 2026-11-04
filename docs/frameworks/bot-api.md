# Bot API (aiogram, python-telegram-bot)

Bot API libraries talk HTTPS to a Bot API server, not MTProto. There's no
device model, app version or language field to set, so tgmint has nothing
to change for a bot. Passkeys don't exist for bots either.

Where tgmint helps is a user account running next to your bot (to read
channels as a member, manage the account, and so on). That account uses an
MTProto library, so follow the page for that library:
[Telethon](telethon.md), [Pyrogram / kurigram](pyrogram.md),
[Hydrogram](hydrogram.md).

## Self-hosted Bot API server

A [local Bot API server](https://core.telegram.org/bots/api#using-a-local-bot-api-server)
needs an `api_id` and `api_hash`. Use your own from
[my.telegram.org](https://core.telegram.org/api/obtaining_api_id), then
point your library at it:

=== "aiogram 3"

    ```python
    from aiogram import Bot
    from aiogram.client.session.aiohttp import AiohttpSession
    from aiogram.client.telegram import TelegramAPIServer

    session = AiohttpSession(api=TelegramAPIServer.from_base("http://localhost:8081"))
    bot = Bot(token, session=session)
    ```

=== "python-telegram-bot"

    ```python
    from telegram.ext import ApplicationBuilder

    app = (
        ApplicationBuilder()
        .token(token)
        .base_url("http://localhost:8081/bot")
        .base_file_url("http://localhost:8081/file/bot")
        .build()
    )
    ```
