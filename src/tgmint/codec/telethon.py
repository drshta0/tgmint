"""Telethon 1.x codec: SQLite ``.session`` files and StringSession (v1).

Ported from TGConvertor (MIT License, Copyright (c) 2020-2025 Nazar
Ihnatiuk):
https://github.com/nazar220160/TGConvertor/blob/master/TGConvertor/sessions/tele.py
— adapted to this namespace: plain functions instead of a session class,
no asyncio (callers that care can wrap in ``run_in_executor``), py3.9
typing.

VERIFICATION LABEL (honest): **fully verified offline against real
Telethon 1.43.2** — see ``tests/test_codec_matrix.py``:

* ``write_string`` output is byte-identical to what
  ``telethon.sessions.StringSession.save()`` produces for the same
  authorization (telethon emits *padded* urlsafe base64; so do we, and
  real telethon rejects unpadded strings, so padding is required for
  compatibility);
* ``write_sqlite`` output opens with ``telethon.sessions.SQLiteSession``
  (which upgrades our schema version 7 to its current 8 in memory/file)
  and yields the same dc_id/address/port/auth_key;
* files written by real Telethon (schema version 8, with the extra
  ``tmp_auth_key`` column) read back correctly here.

Format facts (from telethon's own ``sessions/string.py`` and
``sessions/sqlite.py``):

* string v1 = ``"1" + urlsafe_b64(>B dc_id, 4s|16s packed IP, H port,
  256s auth_key)`` — takeout id and user id are *not* representable;
* the SQLite schema we write is version 7 with the five-column
  ``sessions`` table — readable by older 1.x clients and auto-upgraded by
  newer ones (TGConvertor's compatibility choice, kept deliberately);
* ``user_id`` is never stored in the ``sessions`` table (cached entities
  include contacts, so none of them is a reliable owner) — reads return
  ``user_id=None``;
* ``dc_id`` is authoritative for the endpoint: Telethon packs a *binary*
  IP, so an absent address — and one it cannot represent, i.e. a hostname
  carried over from a GramJS session — resolves to the canonical address of
  that data center (``test_mode`` decides the test/production table).
  ``dc2.telegram.org`` therefore converts cleanly to a Telethon string or
  file; the dc's own address is written.  Writing still fails loudly when
  the ``dc_id`` itself is not a known data center (nothing to fall back to).
"""

from __future__ import annotations

import base64
import ipaddress
import struct
import typing
from pathlib import Path

from .data import (
    CodecError,
    SessionData,
    decode_b64,
    read_sqlite_row,
    validate,
    write_sqlite_file,
)
from .dcs import TEST_ADDRESSES, data_center

__all__ = ["read_string", "write_string", "read_sqlite", "write_sqlite", "PRESERVES"]

#: fields of :class:`SessionData` this format genuinely preserves
PRESERVES = frozenset({"dc_id", "auth_key", "server_address", "port"})

CURRENT_VERSION = "1"
_STRUCT_PREFORMAT = ">B{}sH256s"

_REQUIRED_COLUMNS = {"dc_id", "server_address", "port", "auth_key"}

# Schema version 7: readable by older 1.x clients and upgraded by newer
# clients (telethon 1.43 writes version 8 and adds tmp_auth_key itself).
SCHEMA = """
CREATE TABLE version (version INTEGER PRIMARY KEY);
CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, server_address TEXT, port INTEGER,
                       auth_key BLOB, takeout_id INTEGER);
CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL, username TEXT,
                       phone INTEGER, name TEXT, date INTEGER);
CREATE TABLE sent_files (md5_digest BLOB, file_size INTEGER, type INTEGER, id INTEGER,
                         hash INTEGER, PRIMARY KEY(md5_digest, file_size, type));
CREATE TABLE update_state (id INTEGER PRIMARY KEY, pts INTEGER, qts INTEGER, date INTEGER, seq INTEGER);
"""


def _is_ip(address: typing.Any) -> bool:
    """True when `address` is a real IPv4/IPv6 address (not a hostname)."""
    try:
        ipaddress.ip_address(address)
    except (ValueError, TypeError):
        return False
    return True


def _resolve_endpoint(data: SessionData) -> typing.Tuple[str, int, int]:
    """Resolve (address, port, packed-IP length) for a Telethon endpoint.

    ``dc_id`` is authoritative: Telethon packs a *binary* IP, so an absent
    address **and** an unrepresentable one (a hostname — GramJS sessions may
    carry ``dc2.telegram.org``) both resolve to the canonical address of the
    data center the auth key belongs to, honouring ``test_mode``.  Only a
    format that cannot name a dc at all still fails.
    """
    if data.server_address is not None and _is_ip(data.server_address):
        address: str = str(ipaddress.ip_address(data.server_address))
        default_port = 80 if data.test_mode else 443
    else:
        address, default_port = data_center(data.dc_id, data.test_mode, ipv6=False)
    port = default_port if data.port is None else data.port
    packed_host = ipaddress.ip_address(address).packed
    if type(port) is not int or not 0 < port <= 65535:
        raise CodecError("port must be an integer between 1 and 65535")
    return address, port, len(packed_host)


def _read_endpoint(dc_id: int, address: typing.Any) -> str:
    """Resolve a *stored* address to a usable IP, or fail clearly.

    A NULL/absent ``server_address`` is a broken row (the authorization was
    never completed): that is a :class:`CodecError`, not a raw
    ``ValueError`` out of :mod:`ipaddress`.  A hostname is tolerated — it
    cannot be packed into a v1 string, so the dc_id's own address stands in.
    """
    if address is None:
        raise CodecError(
            "Telethon session row has no server_address; the file was never "
            "authorized (log in with the client once)"
        )
    if _is_ip(address):
        return str(ipaddress.ip_address(address))
    try:
        return data_center(dc_id, False, ipv6=False)[0]
    except CodecError:
        raise CodecError(
            f"Telethon session row stores {address!r}, which is not an IP "
            f"address, and data center {dc_id} has no known address"
        ) from None


def read_string(string: str) -> SessionData:
    """Parse a Telethon StringSession (version 1) into :class:`SessionData`.

    Accepts padded and unpadded urlsafe base64 bodies; real telethon only
    emits the padded form.
    """
    if not isinstance(string, str) or not string.startswith(CURRENT_VERSION):
        raise CodecError("Unsupported Telethon string version (expected 1)")
    raw = decode_b64(string[1:])
    ip_len = len(raw) - 259
    if ip_len not in (4, 16):
        raise CodecError("Invalid Telethon session string length")
    dc_id, address, port, key = struct.unpack(_STRUCT_PREFORMAT.format(ip_len), raw)
    validate(dc_id, key)
    host = str(ipaddress.ip_address(address))
    return SessionData(
        dc_id=dc_id,
        auth_key=key,
        server_address=host,
        port=port,
        test_mode=host in TEST_ADDRESSES,
    )


def write_string(data: SessionData) -> str:
    """Serialize :class:`SessionData` as a Telethon StringSession (v1).

    Byte-identical to ``StringSession.save()`` for the same fields.
    ``user_id``/``is_bot``/``api_id`` are not representable and are
    dropped.  When ``server_address`` is None the production DC address
    for ``dc_id`` is used (test DC when ``test_mode``).
    """
    data.validated()
    address, port, ip_len = _resolve_endpoint(data)
    raw = struct.pack(
        _STRUCT_PREFORMAT.format(ip_len),
        data.dc_id,
        ipaddress.ip_address(address).packed,
        port,
        data.auth_key,
    )
    # telethon's StringSession.encode() keeps the base64 padding
    return CURRENT_VERSION + base64.urlsafe_b64encode(raw).decode("ascii")


def read_sqlite(path: typing.Union[str, Path]) -> SessionData:
    """Read one Telethon authorization from a SQLite ``.session`` file.

    Tolerates additive schema changes (e.g. the ``tmp_auth_key`` column of
    schema version 8).  ``user_id`` is not stored by Telethon and comes
    back ``None``; ``takeout_id`` is deliberately not preserved.
    """
    row = read_sqlite_row(path, _REQUIRED_COLUMNS)
    address = row["server_address"]
    port = row["port"]
    auth_key = row["auth_key"]
    if auth_key is None:
        # `bytes(None)` would raise TypeError; a NULL key is a broken file
        raise CodecError(
            "Telethon session row has no auth_key; the file was never "
            "authorized (log in with the client once)"
        )
    if not isinstance(auth_key, bytes):
        try:  # e.g. stored as memoryview/str
            auth_key = bytes(auth_key)
        except (TypeError, ValueError):
            raise CodecError(
                "Telethon session row has an auth_key of the wrong type; "
                "expected a BLOB of 256 bytes"
            ) from None
    validate(row["dc_id"], auth_key)
    host = _read_endpoint(row["dc_id"], address)
    return SessionData(
        dc_id=row["dc_id"],
        auth_key=auth_key,
        server_address=host,
        port=port,
        test_mode=host in TEST_ADDRESSES,
    )


def write_sqlite(data: SessionData, path: typing.Union[str, Path]) -> None:
    """Write a Telethon SQLite ``.session`` file (schema version 7).

    Refuses to overwrite an existing file; output is created atomically
    with mode 0600.
    """
    data.validated()
    address, port, _ = _resolve_endpoint(data)

    def populate(db) -> None:
        db.executescript(SCHEMA)
        db.execute("INSERT INTO version VALUES (7)")
        db.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
            (data.dc_id, address, port, data.auth_key, None),
        )

    write_sqlite_file(path, populate)
