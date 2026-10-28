"""Telegram data-center endpoints used when a session stores no address.

Ported from TGConvertor (MIT License, Copyright (c) 2020-2025 Nazar
Ihnatiuk):
https://github.com/nazar220160/TGConvertor/blob/master/TGConvertor/data_center.py

Vanilla Pyrogram SQLite/string formats do not store a server address at
all — the client derives it from ``dc_id`` — so converters need the same
static table to fill one in.  Values are the well-known production and
test DC addresses published by every MTProto client.

No external verification label applies here: these are constants, kept in
sync with TGConvertor upstream.
"""

from __future__ import annotations

import typing

from .data import CodecError

__all__ = ["data_center", "TEST_DC", "TEST_DC_IPV6", "PROD_DC", "PROD_DC_IPV6", "TEST_ADDRESSES"]

TEST_DC = {1: "149.154.175.10", 2: "149.154.167.40", 3: "149.154.175.117"}
PROD_DC = {
    1: "149.154.175.53",
    2: "149.154.167.51",
    3: "149.154.175.100",
    4: "149.154.167.91",
    5: "91.108.56.130",
    203: "91.105.192.100",
}
TEST_DC_IPV6 = {
    1: "2001:b28:f23d:f001::e",
    2: "2001:67c:4e8:f002::e",
    3: "2001:b28:f23d:f003::e",
}
PROD_DC_IPV6 = {
    1: "2001:b28:f23d:f001::a",
    2: "2001:67c:4e8:f002::a",
    3: "2001:b28:f23d:f003::a",
    4: "2001:67c:4e8:f004::a",
    5: "2001:b28:f23f:f005::a",
    203: "2a0a:f280:203:a:5000::100",
}

# every address that identifies a test DC (used to derive test_mode from a
# stored address, exactly like TGConvertor's TeleSession/GramSession do)
TEST_ADDRESSES = frozenset(TEST_DC.values()) | frozenset(TEST_DC_IPV6.values())


def data_center(
    dc_id: int, test_mode: bool = False, ipv6: bool = False
) -> typing.Tuple[str, int]:
    """Return the ``(address, port)`` used by clients for ``dc_id``.

    Raises :class:`CodecError` for unknown data centers — callers must then
    supply a server address explicitly.
    """
    table = (TEST_DC_IPV6 if ipv6 else TEST_DC) if test_mode else (PROD_DC_IPV6 if ipv6 else PROD_DC)
    try:
        return table[dc_id], 80 if test_mode else 443
    except KeyError:
        raise CodecError(
            f"Unknown data center {dc_id}; provide server_address explicitly"
        ) from None
