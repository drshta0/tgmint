"""Telegram Desktop ``tdata`` folder reader (read-only codec side).

tdata *writing* stays with :mod:`tgmint.td` (``TDesktop.SaveTData``) — it
is already covered by ``tests/test_tdata_roundtrip.py``; the codec only
needs the read direction to complete the conversion matrix.

Ported from TGConvertor (MIT License, Copyright (c) 2020-2025 Nazar
Ihnatiuk):
https://github.com/nazar220160/TGConvertor/blob/master/TGConvertor/sessions/tdata.py
— adapted to this namespace: reads through *this fork's own* Qt-based
``tgmint.td.TDesktop`` (TGConvertor delegates to a vendored opentele2
copy instead), imported lazily inside the function so that
``tgmint.codec`` stays importable without PyQt5.

VERIFICATION LABEL (honest): read path verified offline against synthetic
tdata folders written by ``tgmint.td``'s own ``SaveTData`` (see
``tests/test_codec_matrix.py``, skipped when PyQt5 is missing).  In this
tree tdata parsing still requires Qt — a parallel workstream is making
``tgmint.td`` Qt-free; until it lands, a missing PyQt5 surfaces as the
clear :class:`ImportError` below.

tdata stores no per-session endpoint (tdesktop resolves DCs from its own
config), so reads return ``server_address=None``; ``user_id`` and
``dc_id`` are always present, ``test_mode`` is False by construction.
"""

from __future__ import annotations

import typing
from pathlib import Path

from .data import CodecError, SessionData

__all__ = ["read", "PRESERVES"]

#: fields of :class:`SessionData` this format genuinely preserves
PRESERVES = frozenset({"dc_id", "auth_key", "user_id"})


def read(
    folder: typing.Union[str, Path],
    *,
    passcode: str = "",
    account_index: typing.Optional[int] = None,
) -> SessionData:
    """Read one account out of a ``tdata`` directory.

    Args:
        folder: path to the tdata directory (the one containing
            ``key_datas``/``map*``).
        passcode: the folder's local passcode, if it has one.
        account_index: select a specific account of a multi-account
            folder; ``None`` selects the main account.

    Raises:
        ImportError: PyQt5 (the ``tgmint[qt]`` extra) is not installed.
        FileNotFoundError: ``folder`` is not a directory.
        CodecError: no authorized account, bad passcode, or index out of
            range.
    """
    path = Path(folder)
    if not path.is_dir():
        raise FileNotFoundError(f"tdata directory does not exist: {path}")

    try:
        from ..td import TDesktop  # lazy: pulls PyQt5 only when needed
    except ImportError as exc:
        raise ImportError(
            "reading tdata requires the Qt-based parser — install the "
            "'qt' extra (pip install tgmint[qt]) or PyQt5 directly"
        ) from exc

    try:
        desktop = TDesktop(basePath=str(path), passcode=passcode or None)
        if not desktop.isLoaded() or not desktop.accounts:
            raise CodecError("No authorized accounts found in tdata")
        if account_index is None:
            account = desktop.mainAccount
        elif type(account_index) is int and 0 <= account_index < len(desktop.accounts):
            account = desktop.accounts[account_index]
        else:
            raise CodecError("account_index is out of range")
        if account is None or account.authKey is None:
            raise CodecError("Account has no authorization key")
        return SessionData(
            dc_id=int(account.MainDcId),
            auth_key=account.authKey.key,
            user_id=account.UserId,
        )
    except CodecError:
        raise
    except Exception:
        # tgmint.td raises its own exception hierarchy for corrupt files /
        # wrong passcodes; the codec normalizes that to CodecError so
        # callers need only catch ValueError + OSError
        raise CodecError(
            "Cannot read tdata; check the folder and local passcode"
        ) from None
