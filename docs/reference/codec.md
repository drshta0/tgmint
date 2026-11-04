# Session codec

Offline conversion between every supported session format, keyed only by
the `auth_key`. Formats: Telethon (SQLite + string), the Pyrogram family
(kurigram / pyrofork / pyrogram / hydrogram), GramJS string, tdata, the
`.tgmint` profile envelope (source) and the official Android app's data
directory (source).

::: tgmint.codec
    options:
      members:
        - SessionData
        - CodecError
        - convert_session
        - read_session
        - write_session
        - infer_source_format
        - PROFILE_FORMATS
        - SOURCE_FORMATS
