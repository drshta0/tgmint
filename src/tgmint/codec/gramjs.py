"""GramJS (Telegram for Node.js) StringSession codec — string format only
(GramJS stores sessions either as this string or as a text file containing
the same string; there is no SQLite variant).

Ported from TGConvertor (MIT License, Copyright (c) 2020-2025 Nazar
Ihnatiuk):
https://github.com/nazar220160/TGConvertor/blob/master/TGConvertor/sessions/gramjs.py
— adapted to this namespace: plain functions instead of a session class,
no asyncio / text-file I/O, py3.9 typing.

VERIFICATION LABEL (honest): **cross-checked against TGConvertor's own
semantics only** — this tree has no GramJS/Node oracle; the layout below
mirrors TGConvertor (which validates against GramJS upstream) and our
tests pin documented vectors constructed straight from the layout.

Format facts:

* body = standard (``+``/``/``) base64 of
  ``>B dc_id, >h len(address), address ascii, >h port, 256s auth_key``,
  prefixed with ``"1"``;
* the address may be an IP *or* an ASCII hostname (4-100 bytes) — unlike
  Telethon, which packs binary IPs only;
* the port is a *signed* 16-bit field in both GramJS' writer and reader,
  hence capped at 32767;
* ``user_id``/``is_bot``/``api_id`` are not representable.
"""

from __future__ import annotations

import base64
import ipaddress
import re
import struct

from .data import CodecError, SessionData, decode_b64, validate
from .dcs import TEST_ADDRESSES, data_center
from . import telethon

__all__ = ["read_string", "write_string", "PRESERVES"]

#: fields of :class:`SessionData` this format genuinely preserves
PRESERVES = frozenset({"dc_id", "auth_key", "server_address", "port"})

CURRENT_VERSION = "1"
_HOSTNAME_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")


def _normalize_address(data: SessionData) -> tuple[str, int]:
    """Resolve (address, port) with GramJS defaults and validations."""
    if data.server_address is None:
        address, default_port = data_center(data.dc_id, data.test_mode, ipv6=False)
    else:
        address, default_port = data.server_address, 80 if data.test_mode else 443
    port = default_port if data.port is None else data.port
    if not isinstance(address, str):
        raise CodecError("GramJS server_address must be an IP address or ASCII hostname")
    try:
        parsed = ipaddress.ip_address(address)
        # GramJS round-trips the *exploded* form of very short IPv6 forms
        address = str(parsed) if len(str(parsed)) >= 4 else parsed.exploded
    except ValueError:
        labels = address.removesuffix(".").split(".")
        if not all(_HOSTNAME_LABEL.fullmatch(label) for label in labels):
            raise CodecError(
                "GramJS server_address must be an IP address or ASCII hostname"
            ) from None
    # GramJS serializes the address as raw bytes after a 16-bit length
    if not 4 <= len(address.encode("ascii", errors="strict")) <= 100:
        raise CodecError("GramJS server_address must contain 4 to 100 ASCII bytes")
    # GramJS uses a signed 16-bit port in both its writer and reader
    if type(port) is not int or not 0 < port <= 32767:
        raise CodecError("GramJS port must be an integer between 1 and 32767")
    return address, port


def read_string(string: str) -> SessionData:
    """Parse a GramJS StringSession (version 1) into :class:`SessionData`.

    Two cross-detection guards are ported from TGConvertor: a Telethon
    IPv4/IPv6 string body can decode to a length a GramJS parser would
    otherwise misread as a giant hostname; those shapes are re-parsed as
    Telethon instead of failing or returning garbage.
    """
    if not isinstance(string, str) or not string.startswith(CURRENT_VERSION):
        raise CodecError("Unsupported GramJS string version (expected 1)")
    raw = decode_b64(string[1:])
    if len(raw) == 263 and len(string[1:]) == 352:
        # padded Telethon IPv4 body — TGConvertor resolves this ambiguity
        # toward Telethon
        tele = telethon.read_string(string)
        return SessionData(
            dc_id=tele.dc_id,
            auth_key=tele.auth_key,
            server_address=tele.server_address,
            port=tele.port,
            test_mode=tele.test_mode,
        )
    if len(raw) < 262:
        raise CodecError("Invalid GramJS session string length")
    size = struct.unpack(">h", raw[1:3])[0]
    if size > 100 and len(raw) == 275:
        # padded Telethon IPv6 body (an address-length field > 100 is not
        # representable in GramJS, so this is unambiguous)
        tele = telethon.read_string(string)
        return SessionData(
            dc_id=tele.dc_id,
            auth_key=tele.auth_key,
            server_address=tele.server_address,
            port=tele.port,
            test_mode=tele.test_mode,
        )
    if not 1 <= size <= 100 or len(raw) != 261 + size:
        raise CodecError("Invalid GramJS session string length")
    try:
        address = raw[3 : 3 + size].decode("ascii")
    except UnicodeDecodeError:
        raise CodecError(
            "GramJS server_address must be an IP address or ASCII hostname"
        ) from None
    dc_id = raw[0]
    port = struct.unpack(">h", raw[3 + size : 5 + size])[0]
    auth_key = raw[5 + size :]
    validate(dc_id, auth_key)
    return SessionData(
        dc_id=dc_id,
        auth_key=auth_key,
        server_address=address,
        port=port,
        test_mode=address in TEST_ADDRESSES,
    )


def write_string(data: SessionData) -> str:
    """Serialize :class:`SessionData` as a GramJS StringSession (v1).

    ``user_id``/``is_bot``/``api_id`` are not representable and are
    dropped.  When ``server_address`` is None the production DC address
    for ``dc_id`` is used (test DC when ``test_mode``).
    """
    data.validated()
    address, port = _normalize_address(data)
    raw = (
        struct.pack(">Bh", data.dc_id, len(address.encode("ascii")))
        + address.encode("ascii")
        + struct.pack(">h", port)
        + data.auth_key
    )
    # GramJS emits standard (not urlsafe) base64, padding included
    return CURRENT_VERSION + base64.b64encode(raw).decode("ascii")
