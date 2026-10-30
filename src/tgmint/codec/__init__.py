"""tgmint.codec — the offline session-format conversion matrix.

Readers (→ :class:`SessionData`):

============================  ==============================================
format                        function
============================  ==============================================
Telethon SQLite ``.session``  :func:`tgmint.codec.telethon.read_sqlite`
Telethon StringSession (v1)   :func:`tgmint.codec.telethon.read_string`
Pyrogram SQLite (vanilla)     :func:`tgmint.codec.pyrogram.read_sqlite`
kurigram SQLite (v7 schema)   :func:`tgmint.codec.pyrogram.read_sqlite`
Pyrogram-family string        :func:`tgmint.codec.pyrogram.read_string`
GramJS StringSession          :func:`tgmint.codec.gramjs.read_string`
tdata folder                  :func:`tgmint.codec.tdata.read`
============================  ==============================================

Writers (← :class:`SessionData`): Telethon SQLite + string, Pyrogram
SQLite (``variant="pyrogram" | "kurigram"``) + string, GramJS string.
tdata *writing* stays with :mod:`tgmint.td` (``SaveTData``).

:func:`convert_session` orchestrates those readers and writers — one
call covers every documented from→to cell (it is what the
``tgmint convert`` CLI drives; string destinations are written to the
output path as mode-0600 files, never echoed).

Honest verification status (details in each module docstring, pinned by
``tests/test_codec_matrix.py``):

* **Telethon** — fully verified offline against real Telethon 1.43.2
  (writer output byte-identical to ``StringSession.save()``; written
  ``.session`` files open with ``SQLiteSession``; telethon-written files
  read back).
* **GramJS** — cross-checked against TGConvertor's own semantics; no
  GramJS oracle in this tree.
* **Pyrogram / kurigram** — self-consistent only (we read back what we
  write); no external oracle today.

The whole package is stdlib-only (sqlite3/base64/struct/ipaddress);
PyQt5 is needed solely by the tdata reader and is imported lazily there.
The one exception is :func:`convert_session` with a tdata *destination*:
it routes through :mod:`tgmint.td`'s ``SaveTData``, which needs the base
package's tgcrypto (never Qt — the pure-Python QDataStream is the
default writer there).

Credit: the codecs are ported from TGConvertor by Nazar Ihnatiuk (MIT,
https://github.com/nazar220160/TGConvertor) — see each module's
docstring for the exact upstream file and the adaptations made.
"""

from __future__ import annotations

import os
from typing import Any, Dict, FrozenSet, Optional

from .data import CodecError, SessionData, write_text_file
from . import data, dcs, gramjs, pyrogram, telethon

try:  # tdata.py itself is importable without Qt (the guard is lazy)
    from . import tdata
except ImportError:  # pragma: no cover - defensive; tdata has no top-level Qt import
    tdata = None  # type: ignore[assignment]

__all__ = [
    "SessionData",
    "CodecError",
    "convert_session",
    "data",
    "dcs",
    "telethon",
    "pyrogram",
    "gramjs",
    "tdata",
]


# ---------------------------------------------------------------------------
# convert_session — the single entrypoint the CLI (and any caller) uses
# ---------------------------------------------------------------------------

#: CLI format name -> reader.  "*-string" formats take the session string
#: itself as `source` (or a path to a file containing it); "*-session" take
#: a SQLite file path; tdata a folder.
_READERS = {
    "telethon-session": telethon.read_sqlite,
    "telethon-string": telethon.read_string,
    "pyrogram-session": pyrogram.read_sqlite,
    "pyrogram-string": pyrogram.read_string,
    "gramjs-string": gramjs.read_string,
}

#: destination formats that store a user_id / api_id and therefore need one
#: supplied (see `_PLACEHOLDER_*` below for what happens when the source
#: format cannot carry the field)
_NEEDS_USER_ID = frozenset({"pyrogram-session", "pyrogram-string", "tdata"})
_NEEDS_API_ID = frozenset({"pyrogram-session", "pyrogram-string"})

#: filled when the destination format requires a field the source format
#: physically cannot store (e.g. Telethon strings carry no user_id).
#: 777000 is Telegram's service account, 2040 Telegram's public web-demo
#: app — recognisable placeholders, never a claim about the account.  The
#: destination client refreshes user_id from the server on first connect;
#: construct it with the account's real api_id.  Library callers override
#: both via the `convert_session` kwargs.
_PLACEHOLDER_USER_ID = 777000
_PLACEHOLDER_API_ID = 2040


def _read_source(
    source: str, source_format: str, passcode: str
) -> SessionData:
    """Dispatch on `source_format` and read one authorization."""
    if source_format == "tdata":
        if tdata is None:  # pragma: no cover - defensive import guard
            raise CodecError("tdata reader unavailable in this build")
        return tdata.read(source, passcode=passcode)
    reader = _READERS.get(source_format)
    if reader is None:
        raise CodecError(
            f"unknown source format {source_format!r}; expected one of "
            f"{sorted(_READERS) + ['tdata']}"
        )
    if source_format.endswith("-string") and os.path.isfile(source):
        # convenience: `--from` may name a file holding the session
        # string (a saved StringSession) rather than the string itself
        with open(source, encoding="utf-8") as fp:
            source = fp.read().strip()
    return reader(source)


def _write_tdata(data: SessionData, folder: str, passcode: str) -> None:
    """Write one authorization as a ``tdata`` folder.

    The codec itself is deliberately read-only for tdata; writing goes
    through :mod:`tgmint.td`'s own ``SaveTData`` (imported lazily — it
    needs the base package's tgcrypto, unlike the rest of the codec).
    """
    try:
        from ..api import API
        from ..td import TDesktop
        from ..td.account import Account
        from ..td.auth import AuthKey as TdAuthKey, AuthKeyType
        from ..td.configs import DcId
    except ImportError as exc:
        raise ImportError(
            "writing tdata requires tgmint.td (the tgcrypto dependency "
            "of the base package); convert to another format instead"
        ) from exc

    desktop = TDesktop()
    account = Account(owner=desktop, api=API.TelegramDesktop)
    account._setMtpAuthorizationCustom(
        DcId(data.dc_id),
        data.user_id,
        [TdAuthKey(data.auth_key, AuthKeyType.ReadFromFile, DcId(data.dc_id))],
    )
    desktop._addSingleAccount(account)
    if not desktop.SaveTData(str(folder), passcode=passcode or None):
        raise CodecError(f"SaveTData failed for {folder}")


def _write_destination(
    data: SessionData,
    destination: str,
    destination_format: str,
    passcode: str,
    variant: str,
) -> str:
    """Write `data` in `destination_format`; returns the output kind."""
    if destination_format == "telethon-session":
        telethon.write_sqlite(data, destination)
        return "sqlite-session"
    if destination_format == "telethon-string":
        write_text_file(destination, telethon.write_string(data))
        return "string-file"
    if destination_format == "pyrogram-session":
        # `variant` selects the storage engine schema; kurigram readers
        # auto-detect either file
        pyrogram.write_sqlite(data, destination, variant=variant)
        return "sqlite-session"
    if destination_format == "pyrogram-string":
        write_text_file(destination, pyrogram.write_string(data))
        return "string-file"
    if destination_format == "gramjs-string":
        write_text_file(destination, gramjs.write_string(data))
        return "string-file"
    if destination_format == "tdata":
        _write_tdata(data, destination, passcode)
        return "tdata-directory"
    raise CodecError(
        f"unknown destination format {destination_format!r}; expected one "
        f"of {sorted(_READERS) + ['tdata']}"
    )


def _preserves(destination_format: str) -> FrozenSet[str]:
    """Fields the destination format genuinely keeps (module PRESERVES)."""
    if destination_format.startswith("telethon-"):
        return telethon.PRESERVES
    if destination_format.startswith("pyrogram-"):
        return pyrogram.PRESERVES
    if destination_format == "gramjs-string":
        return gramjs.PRESERVES
    if destination_format == "tdata":
        return getattr(tdata, "PRESERVES", frozenset({"dc_id", "auth_key", "user_id"}))
    raise CodecError(f"unknown destination format {destination_format!r}")


def _fill_note(field: str, source_format: str, value: int) -> str:
    if field == "user_id":
        return (
            f"user_id: {source_format} stores none; wrote placeholder "
            f"{value} — the destination client learns the real id from "
            "the server on first connect"
        )
    return (
        f"api_id: {source_format} stores none; wrote {value} (Telegram's "
        "public demo app id) — construct the destination client with the "
        "account's real api_id"
    )


def convert_session(
    source: str,
    source_format: str,
    destination: str,
    destination_format: str,
    *,
    user_id: Optional[int] = None,
    api_id: Optional[int] = None,
    passcode: str = "",
    variant: str = "pyrogram",
) -> Dict[str, Any]:
    """Convert one session between any two formats of the matrix above.

    This is the entrypoint the ``tgmint convert`` CLI calls — and the one
    v1.16.0 shipped without: the command probed for it, it did not exist,
    and every invocation exited 2 (a self-skipping test kept the suite
    green over the dead command; fixed in v1.16.1).

    Args:
        source: the session string itself for ``*-string`` formats, the
            SQLite file path for ``*-session``, the folder for ``tdata``.
        source_format / destination_format: one of ``telethon-session``,
            ``telethon-string``, ``pyrogram-session``, ``pyrogram-string``,
            ``gramjs-string``, ``tdata``.
        destination: output path — a file for every format except
            ``tdata`` (a folder).  Existing outputs are never overwritten
            (:class:`FileExistsError`); string outputs are files written
            with mode 0600 (the string is never echoed to the caller).
        user_id / api_id: supplied only when the source format cannot
            carry a field the destination requires (Telethon, GramJS and
            tdata store no api_id; Telethon and GramJS strings store no
            user_id).  Without them a labelled placeholder is written and
            reported in the result's ``notes`` — the destination client
            refreshes ``user_id`` from the server on first connect.
        passcode: the local passcode of a source ``tdata`` folder (also
            used when writing one).
        variant: pyrogram SQLite variant for ``pyrogram-session``
            destinations (``"pyrogram"`` or ``"kurigram"``).

    Returns:
        a JSON-friendly dict describing what was written: ``dc_id``,
        ``user_id`` (``None`` when neither format represents one),
        ``test_mode``, ``output`` path, ``output_kind``, the fields
        ``preserved`` / ``dropped`` (per each codec module's honest
        ``PRESERVES`` table), and ``notes`` for any placeholder fills.

    Own-account guardrail: this moves an existing authorization between
    formats — use it only on sessions you own or are entitled to hold.
    It performs no login and touches no network; the auth_key is the
    only secret moved.
    """
    data = _read_source(source, source_format, passcode)

    filled: list = []
    if destination_format in _NEEDS_USER_ID and data.user_id is None:
        value = _PLACEHOLDER_USER_ID if user_id is None else user_id
        data = data._replace(user_id=value)
        filled.append(("user_id", value))
    if destination_format in _NEEDS_API_ID and data.api_id is None:
        value = _PLACEHOLDER_API_ID if api_id is None else api_id
        data = data._replace(api_id=value)
        filled.append(("api_id", value))

    output_kind = _write_destination(
        data, destination, destination_format, passcode, variant
    )

    keeps = _preserves(destination_format)
    dropped = sorted(
        field
        for field in SessionData._fields
        if field not in keeps
        and field not in ("dc_id", "auth_key")
        and getattr(data, field) is not None
    )
    result: Dict[str, Any] = {
        "source_format": source_format,
        "destination_format": destination_format,
        "dc_id": data.dc_id,
        "user_id": data.user_id if "user_id" in keeps else None,
        "test_mode": bool(data.test_mode),
        "output": str(destination),
        "output_kind": output_kind,
        "preserved": sorted(keeps),
        "dropped": dropped,
    }
    if filled:
        result["filled"] = [field for field, _ in filled]
        result["notes"] = [
            _fill_note(field, source_format, value) for field, value in filled
        ]
    return result
