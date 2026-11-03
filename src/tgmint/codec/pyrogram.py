"""Pyrogram-family codec: session strings and SQLite files (pyrogram 2.x,
pyrofork, kurigram).

Ported from TGConvertor (MIT License, Copyright (c) 2020-2025 Nazar
Ihnatiuk):
https://github.com/nazar220160/TGConvertor/blob/master/TGConvertor/sessions/pyro/pyro.py
and its kurigram alias ``sessions/pyro/kuri.py``
— adapted to this namespace: plain functions instead of a session class,
explicit ``variant`` argument instead of importlib-metadata backend
sniffing, no asyncio, py3.9 typing.

VERIFICATION LABEL (honest): **self-consistent only** — the tests prove we
read back exactly what we write (plus TGConvertor's format tables), but no
pyrogram/kurigram client exists in this tree or CI as an external oracle.
Treat that as the current limit of the claim; the wire formats themselves
are documented below and mirror TGConvertor exactly.

Format facts:

* current string format (Pyrogram 2.x and its forks, incl. the kurigram
  "MEOW"-era string): unpadded urlsafe base64 of
  ``>BI?256sQ?`` = dc_id, api_id, test_mode, auth_key, user_id, is_bot;
* two legacy string formats (Pyrogram 1.x): ``>B?256sI?`` (32-bit
  user_id, no api_id) and ``>B?256sQ?`` (64-bit user_id, no api_id) —
  read for compatibility, never written;
* session strings never store a server address/port — clients derive the
  endpoint from dc_id, so reads return ``server_address=None``;
* vanilla Pyrogram 2.x SQLite: storage version 3, ``sessions`` table
  without address columns;
* kurigram SQLite: storage version 7, adds ``server_address``/``port`` to
  ``sessions`` plus ``usernames``/``update_state`` tables (the reader
  auto-detects the variant from the schema).
"""

from __future__ import annotations

import base64
import ipaddress
import struct
import typing
from pathlib import Path

from .data import CodecError, SessionData, decode_b64, read_sqlite_row, validate, write_sqlite_file
from .dcs import data_center

__all__ = [
    "read_string",
    "write_string",
    "read_sqlite",
    "write_sqlite",
    "PRESERVES",
    "PRESERVES_SQLITE_KURIGRAM",
    "VARIANT_PYROGRAM",
    "VARIANT_KURIGRAM",
]

#: fields of :class:`SessionData` preserved by the string formats (both
#: SQLite variants also preserve these; kurigram SQLite additionally
#: preserves the endpoint)
PRESERVES = frozenset({"dc_id", "auth_key", "user_id", "is_bot", "test_mode", "api_id"})
PRESERVES_SQLITE_KURIGRAM = PRESERVES | {"server_address", "port"}

VARIANT_PYROGRAM = "pyrogram"
VARIANT_KURIGRAM = "kurigram"

# current + legacy string layouts; distinguished by decoded length
_STRING_FORMAT = ">BI?256sQ?"  # Pyrogram 2.x (dc_id, api_id, test_mode, key, user_id, is_bot)
_LEGACY_FORMAT_32 = ">B?256sI?"  # Pyrogram 1.x, 32-bit user_id
_LEGACY_FORMAT_64 = ">B?256sQ?"  # Pyrogram 1.x, 64-bit user_id

_REQUIRED_COLUMNS = {"dc_id", "auth_key", "test_mode", "user_id", "is_bot", "date"}

# SQLite storage-engine version numbers (pyrogram's own sqlite storage
# writes 3; kurigram's writes 7)
VERSION_PYROGRAM = 3
VERSION_KURIGRAM = 7


def read_string(session_string: str) -> SessionData:
    """Parse a Pyrogram-family session string (current or legacy) into
    :class:`SessionData`."""
    raw = decode_b64(session_string)
    formats = {
        struct.calcsize(fmt): fmt
        for fmt in (_STRING_FORMAT, _LEGACY_FORMAT_32, _LEGACY_FORMAT_64)
    }
    fmt = formats.get(len(raw))
    if fmt is None:
        raise CodecError("Invalid Pyrogram session string length")
    mode_offset = 5 if fmt == _STRING_FORMAT else 1
    if raw[mode_offset] not in (0, 1) or raw[-1] not in (0, 1):
        raise CodecError("Invalid Pyrogram session boolean fields")
    fields = struct.unpack(fmt, raw)
    if fmt == _STRING_FORMAT:
        dc_id, api_id, test_mode, auth_key, user_id, is_bot = fields
    else:
        dc_id, test_mode, auth_key, user_id, is_bot = fields
        api_id = None
    validate(dc_id, auth_key)
    return SessionData(
        dc_id=dc_id,
        auth_key=auth_key,
        user_id=user_id or None,
        is_bot=bool(is_bot),
        test_mode=bool(test_mode),
        api_id=api_id or None,
    )


def write_string(data: SessionData) -> str:
    """Serialize :class:`SessionData` as a Pyrogram 2.x session string.

    Requires ``user_id`` and ``api_id`` (the format stores both); raises
    :class:`CodecError` when either is missing.  The endpoint is not
    representable in this format.
    """
    data.validated()
    if data.user_id is None:
        raise CodecError("Pyrogram session strings require user_id")
    if data.api_id is None:
        raise CodecError("Pyrogram session strings require api_id")
    packed = struct.pack(
        _STRING_FORMAT,
        data.dc_id,
        data.api_id,
        bool(data.test_mode),
        data.auth_key,
        data.user_id,
        bool(data.is_bot),
    )
    return base64.urlsafe_b64encode(packed).decode("ascii").rstrip("=")


def read_sqlite(path: typing.Union[str, Path]) -> SessionData:
    """Read one authorization from a Pyrogram/kurigram SQLite session file.

    The variant (vanilla vs kurigram) is auto-detected from the schema:
    kurigram files carry ``server_address``/``port`` columns and their
    ``version`` table says 7.  Additive columns from newer engines are
    tolerated.
    """
    row = read_sqlite_row(path, _REQUIRED_COLUMNS)
    auth_key = row["auth_key"]
    if auth_key is None:
        # `bytes(None)` would raise TypeError; a NULL key is a broken file
        raise CodecError(
            "Pyrogram session row has no auth_key; the file was never "
            "authorized (log in with the client once)"
        )
    if not isinstance(auth_key, bytes):
        try:  # e.g. stored as memoryview/str
            auth_key = bytes(auth_key)
        except (TypeError, ValueError):
            raise CodecError(
                "Pyrogram session row has an auth_key of the wrong type; "
                "expected a BLOB of 256 bytes"
            ) from None
    validate(row["dc_id"], auth_key, row["user_id"] or None)
    address: typing.Optional[str] = row.get("server_address")
    if address is not None:
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError:
            address = str(address)
    return SessionData(
        dc_id=row["dc_id"],
        auth_key=auth_key,
        user_id=row["user_id"] or None,
        is_bot=bool(row["is_bot"]),
        test_mode=bool(row["test_mode"]),
        api_id=row.get("api_id") or None,
        server_address=address,
        port=row.get("port"),
    )


def write_sqlite(
    data: SessionData,
    path: typing.Union[str, Path],
    *,
    variant: str = VARIANT_PYROGRAM,
) -> None:
    """Write a Pyrogram-family SQLite session file.

    ``variant`` selects the storage engine schema: ``"pyrogram"`` (vanilla
    2.x, storage version 3, endpoint derived from dc_id at runtime) or
    ``"kurigram"`` (storage version 7, endpoint stored explicitly — a
    production/test DC address for ``dc_id`` is filled in when
    ``server_address`` is None).

    Refuses to overwrite an existing file; output is created atomically
    with mode 0600.  Requires ``user_id`` and ``api_id``.
    """
    data.validated()
    if variant not in (VARIANT_PYROGRAM, VARIANT_KURIGRAM):
        raise CodecError("variant must be 'pyrogram' or 'kurigram'")
    if data.user_id is None:
        raise CodecError("Pyrogram session files require user_id")
    if data.api_id is None:
        raise CodecError("Pyrogram session files require api_id")

    extended = variant == VARIANT_KURIGRAM
    address: typing.Optional[str] = data.server_address
    port = data.port
    if extended:
        if address is None:
            address, default_port = data_center(data.dc_id, data.test_mode)
            port = default_port if port is None else port
        else:
            try:
                address = str(ipaddress.ip_address(address))
            except ValueError:
                raise CodecError("server_address must be an IPv4 or IPv6 address") from None
            port = (80 if data.test_mode else 443) if port is None else port
        if type(port) is not int or not 0 < port <= 65535:
            raise CodecError("port must be an integer between 1 and 65535")

    def populate(db) -> None:
        # (precomputed snippets keep this py3.9-parseable: nested quotes of
        # the same type inside f-strings are a 3.12+ luxury)
        endpoint_cols = ", server_address TEXT, port INTEGER" if extended else ""
        peers_name_col = "phone_number TEXT," if extended else "username TEXT, phone_number TEXT,"
        db.executescript(
            f"""
            CREATE TABLE sessions (
                dc_id INTEGER PRIMARY KEY{endpoint_cols},
                api_id INTEGER, test_mode INTEGER, auth_key BLOB, date INTEGER NOT NULL,
                user_id INTEGER, is_bot INTEGER);
            CREATE TABLE peers (
                id INTEGER PRIMARY KEY, access_hash INTEGER, type INTEGER NOT NULL,
                {peers_name_col}
                last_update_on INTEGER NOT NULL DEFAULT (CAST(STRFTIME('%s', 'now') AS INTEGER)));
            CREATE TABLE version (number INTEGER PRIMARY KEY);
            CREATE INDEX idx_peers_id ON peers (id);
            CREATE INDEX idx_peers_phone_number ON peers (phone_number);
            CREATE TRIGGER trg_peers_last_update_on AFTER UPDATE ON peers BEGIN
                UPDATE peers SET last_update_on = CAST(STRFTIME('%s', 'now') AS INTEGER)
                WHERE id = NEW.id;
            END;
            """
        )
        if extended:
            # kurigram storage v7: usernames moved to their own table,
            # update-state tracking added
            db.executescript(
                """
                CREATE TABLE usernames (
                    id INTEGER, username TEXT, FOREIGN KEY(id) REFERENCES peers(id));
                CREATE INDEX idx_usernames_id ON usernames (id);
                CREATE INDEX idx_usernames_username ON usernames (username);
                CREATE TABLE update_state (id INTEGER PRIMARY KEY, pts INTEGER, qts INTEGER,
                                           date INTEGER, seq INTEGER);
                """
            )
        else:
            db.execute("CREATE INDEX idx_peers_username ON peers (username)")

        values: typing.Tuple[typing.Any, ...] = (data.dc_id,)
        if extended:
            values += (address, port)
        values += (
            data.api_id,
            int(bool(data.test_mode)),
            data.auth_key,
            0,  # date: the owning client refreshes this on first run
            data.user_id,
            int(bool(data.is_bot)),
        )
        db.execute(
            f"INSERT INTO sessions VALUES ({','.join('?' for _ in values)})", values
        )
        db.execute(
            "INSERT INTO version VALUES (?)", (VERSION_KURIGRAM if extended else VERSION_PYROGRAM,)
        )

    write_sqlite_file(path, populate)
