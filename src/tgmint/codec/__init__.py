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
``.tgmint`` profile envelope  :func:`tgmint.profile.open_profile`
Android app data dir          :func:`tgmint.codec.android.read`
============================  ==============================================

Writers (← :class:`SessionData`): Telethon SQLite + string, Pyrogram
SQLite (``variant="pyrogram" | "kurigram"``) + string, GramJS string.
tdata *writing* stays with :mod:`tgmint.td` (``SaveTData``).

:func:`convert_session` orchestrates those readers and writers — one
call covers every documented from→to cell (it is what the
``tgmint convert`` CLI drives; string destinations are written to the
output path as mode-0600 files, never echoed).

The ``.tgmint`` envelope (:mod:`tgmint.profile`, ``"profile"``) is a
**source** format only: it is read here, never written — converting the
other way (session → envelope) is ``tgmint profile seal``, which also
carries the fingerprint and the passkey. The reader is imported lazily so
``tgmint.codec`` stays importable without touching the envelope module's
crypto path (an unsealed profile needs none).  The official Android app
data directory (``"android-dir"``) is source-only the same way and for a
stronger reason: writing into an app's private storage is how logins
die.  It reads the app's own ``tgnet.dat`` + ``userconfing.xml`` (no
crypto — the key is plaintext; the hard part is acquiring the files, see
``docs/android-acquisition.md``); the per-field spec with the pinned
DrKLO/Telegram commit lives in :mod:`tgmint.codec.android`.

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
* **Android** — the format spec is verified line-by-line against the
  official client source (DrKLO/Telegram, commit pinned in
  :mod:`tgmint.codec.android`) and cross-checked against AndroidTelePorter
  (MIT); the reader is exercised against synthetic fixtures built by an
  independent in-test encoder.  No real app dump has been read yet.

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
from pathlib import Path
from typing import Any, Optional

from .data import CodecError, SessionData, write_text_file
from . import android, data, dcs, gramjs, pyrogram, telethon

try:  # tdata.py itself is importable without Qt (the guard is lazy)
    from . import tdata
except ImportError:  # pragma: no cover - defensive; tdata has no top-level Qt import
    tdata = None  # type: ignore[assignment]

__all__ = [
    "SessionData",
    "CodecError",
    "convert_session",
    "read_session",
    "write_session",
    "infer_source_format",
    "PROFILE_FORMATS",
    "SOURCE_FORMATS",
    "data",
    "dcs",
    "telethon",
    "pyrogram",
    "gramjs",
    "android",
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

#: names that mean "a .tgmint envelope" (see tgmint.profile).  It is a
#: source-only format; the alias set exists so callers can say the obvious
#: thing (`profile`, `tgmint`, or the format id itself).
PROFILE_FORMATS = frozenset({"profile", "tgmint", "tgmint-profile", "tgmint-profile/1"})

#: formats `convert_session` accepts as a `source_format`
SOURCE_FORMATS = tuple(sorted(_READERS)) + ("android-dir", "tdata", "profile")


#: destination formats that store a user_id / api_id and therefore need one
#: supplied (see `_PLACEHOLDER_*` below for what happens when the source
#: format cannot carry the field)
_NEEDS_USER_ID = frozenset({"pyrogram-session", "pyrogram-string", "tdata"})
_NEEDS_API_ID = frozenset({"pyrogram-session", "pyrogram-string"})

#: filled when the destination format requires a field the source format
#: physically cannot store (e.g. Telethon strings carry no user_id).
#: 777000 is Telegram's service account, 2040 Telegram Desktop's official
#: app id — recognisable placeholders, never a claim about the account.  The
#: destination client refreshes user_id from the server on first connect;
#: construct it with the account's real api_id.  Library callers override
#: both via the `convert_session` kwargs.
_PLACEHOLDER_USER_ID = 777000
_PLACEHOLDER_API_ID = 2040


def _read_profile_source(source: str, passphrase: str) -> SessionData:
    """Read one ``.tgmint`` envelope as a source authorization.

    Delegates to :func:`tgmint.profile.open_profile` (imported lazily: the
    envelope module is not needed by the rest of the matrix, and its
    sealed path is the only one that wants ``cryptography``).  A
    :class:`tgmint.profile.ProfileError` is a
    :class:`~tgmint.codec.data.CodecError` already, so callers that catch
    the codec error keep working; the cross-validation messages
    (session vs fingerprint vs passkey) come through verbatim.
    """
    from ..profile import open_profile

    opened = open_profile(source, passphrase=passphrase or None)
    return opened.session


def infer_source_format(source: str) -> str:
    """Infer a source format from the path: ``.tgmint`` -> ``profile``.

    The fallback is ``telethon-session`` (the format this repository is
    centred on).  Both :func:`read_session` and :func:`convert_session`
    use it when the caller passes no format at all; an explicit format is
    never second-guessed.
    """
    if str(source).endswith(".tgmint"):
        return "profile"
    return "android-dir" if android.looks_like_dump(source) else "telethon-session"


def read_session(
    source: str,
    source_format: Optional[str] = None,
    *,
    passcode: str = "",
    passphrase: str = "",
    account_index: Optional[int] = None,
) -> SessionData:
    """Read one authorization from any source format (public entrypoint).

    The thin public wrapper around the reader dispatch that
    :func:`convert_session` uses — ``tgmint profile seal`` and
    ``tgmint heal`` both need exactly this and nothing more.

    Args:
        source: the session string (``*-string`` formats), a SQLite file
            path, a ``tdata`` folder, an Android app data dump directory
            (``android-dir``), or a ``.tgmint`` envelope file.
        source_format: one of the names in :data:`SOURCE_FORMATS`, or
            ``None`` to infer it (``.tgmint`` -> ``profile``, a dump
            directory with a ``tgnet.dat`` -> ``android-dir``, otherwise
            ``telethon-session``).
        passcode: the local passcode of a ``tdata`` folder.
        passphrase: the passphrase of a sealed ``.tgmint`` envelope
            (ignored by every other format).
        account_index: which account of a multi-account ``tdata`` folder or
            Android app dump to read; ``None`` selects its main/first
            account.  Ignored by every other format.
    """
    if source_format in (None, "", "auto"):
        source_format = infer_source_format(source)
    if source_format in PROFILE_FORMATS:
        return _read_profile_source(source, passphrase)
    return _read_source(source, source_format, passcode, account_index=account_index)


def _read_source(
    source: str,
    source_format: str,
    passcode: str,
    passphrase: str = "",
    account_index: Optional[int] = None,
) -> SessionData:
    """Dispatch on `source_format` and read one authorization."""
    if source_format in PROFILE_FORMATS:
        return _read_profile_source(source, passphrase)
    if source_format == "tdata":
        if tdata is None:  # pragma: no cover - defensive import guard
            raise CodecError("tdata reader unavailable in this build")
        return tdata.read(source, passcode=passcode, account_index=account_index)
    if source_format == "android-dir":
        return android.read(source, account_index=account_index)
    reader = _READERS.get(source_format)
    if reader is None:
        raise CodecError(
            f"unknown source format {source_format!r}; expected one of "
            f"{sorted(_READERS) + ['android-dir', 'tdata', 'profile']}"
        )
    if source_format.endswith("-string") and os.path.isfile(source):
        # convenience: `--from` may name a file holding the session
        # string (a saved StringSession) rather than the string itself
        with open(source, encoding="utf-8") as fp:
            source = fp.read().strip()
    return reader(source)


#: modes for a written ``tdata`` folder: it carries the raw auth key in
#: ``tdata/key_datas`` (and in the MTP data file), so it is a credential
#: directory like every session file in this package (0600 / 0700).
_TDATA_FILE_MODE = 0o600
_TDATA_DIR_MODE = 0o700


def _harden_tdata(folder: str) -> None:
    """chmod a freshly written ``tdata`` folder to 0700/0600.

    ``SaveTData`` (like tdesktop itself) honours the process umask, which
    routinely lands 0664 files inside a 0775 directory — world-readable
    auth-key material.  Walk the tree it just wrote and tighten every file
    and directory; symlinks are skipped (chmod would follow them).
    """
    for root, _directories, filenames in os.walk(folder):
        os.chmod(root, _TDATA_DIR_MODE)
        for name in filenames:
            path = os.path.join(root, name)
            if not os.path.islink(path):
                os.chmod(path, _TDATA_FILE_MODE)


def _write_tdata(data: SessionData, folder: str, passcode: str) -> None:
    """Write one authorization as a ``tdata`` folder.

    The codec itself is deliberately read-only for tdata; writing goes
    through :mod:`tgmint.td`'s own ``SaveTData`` (imported lazily — it
    needs the base package's tgcrypto, unlike the rest of the codec).

    An existing folder (or a symlink pointing anywhere) is refused with
    :class:`FileExistsError`, exactly like every file writer in this
    package: ``SaveTData`` would otherwise overwrite ``key_datas`` inside a
    live Telegram Desktop data directory and destroy that login.  The
    folder it creates is hardened to 0700/0600 afterwards.
    """
    target = Path(folder)
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"Output already exists: {target}")

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
    _harden_tdata(str(folder))


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


def _preserves(
    destination_format: str, variant: str = pyrogram.VARIANT_PYROGRAM
) -> frozenset[str]:
    """Fields the destination format genuinely keeps (module PRESERVES).

    ``variant`` matters for the Pyrogram family: the kurigram SQLite schema
    (storage v7) stores ``server_address``/``port`` while vanilla Pyrogram
    derives the endpoint from ``dc_id`` at connect time, so a kurigram write
    must not report the endpoint as dropped.
    """
    if destination_format.startswith("telethon-"):
        return telethon.PRESERVES
    if destination_format == "pyrogram-session":
        if variant == pyrogram.VARIANT_KURIGRAM:
            return pyrogram.PRESERVES_SQLITE_KURIGRAM
        if variant != pyrogram.VARIANT_PYROGRAM:
            raise CodecError("variant must be 'pyrogram' or 'kurigram'")
        return pyrogram.PRESERVES
    if destination_format == "pyrogram-string":
        # session strings never carry an endpoint, whichever variant wrote them
        return pyrogram.PRESERVES
    if destination_format == "gramjs-string":
        return gramjs.PRESERVES
    if destination_format == "tdata":
        return getattr(tdata, "PRESERVES", frozenset({"dc_id", "auth_key", "user_id"}))
    raise CodecError(f"unknown destination format {destination_format!r}")


#: values that carry no information a destination could lose — the implicit
#: default of the field.  ``is_bot=False`` stored into a format with no bot
#: column loses nothing (every client treats the account as a user), while
#: ``is_bot=True`` is genuine data that *is* lost.  A value equal to its
#: default therefore counts as effectively preserved, and a real ``False`` /
#: ``0`` is still never mistaken for "absent" (``None`` is the only "unset").
_NEUTRAL_VALUES: dict[str, Any] = {"is_bot": False, "test_mode": False, "port": 0}
_NO_DEFAULT = object()


def _loses(field: str, value: Any) -> bool:
    """True when `value` is information the destination genuinely drops."""
    if value is None:
        return False
    neutral = _NEUTRAL_VALUES.get(field, _NO_DEFAULT)
    return neutral is _NO_DEFAULT or value != neutral


def _fill_note(field: str, source_format: str, value: int) -> str:
    if field == "user_id":
        return (
            f"user_id: {source_format} stores none; wrote placeholder "
            f"{value} — the destination client learns the real id from "
            "the server on first connect"
        )
    return (
        f"api_id: {source_format} stores none; wrote {value} (Telegram "
        "Desktop's official app id, a placeholder) — construct the destination client with the "
        "account's real api_id"
    )


def _fill_for_destination(
    data: SessionData,
    destination_format: str,
    user_id: Optional[int],
    api_id: Optional[int],
) -> tuple:
    """Fill the fields a destination requires but the source cannot hold."""
    filled = []
    if destination_format in _NEEDS_USER_ID and data.user_id is None:
        value = _PLACEHOLDER_USER_ID if user_id is None else user_id
        data = data._replace(user_id=value)
        filled.append(("user_id", value))
    if destination_format in _NEEDS_API_ID and data.api_id is None:
        value = _PLACEHOLDER_API_ID if api_id is None else api_id
        data = data._replace(api_id=value)
        filled.append(("api_id", value))
    return data, filled


def write_session(
    data: SessionData,
    destination: str,
    destination_format: str,
    *,
    user_id: Optional[int] = None,
    api_id: Optional[int] = None,
    passcode: str = "",
    variant: str = "pyrogram",
    source_label: str = "an in-memory session",
) -> dict[str, Any]:
    """Write one in-memory :class:`SessionData` in a destination format.

    The writer half of :func:`convert_session`, public because callers
    that mint a session themselves (``tgmint heal`` after a passkey login)
    need exactly this: a format writer plus the documented placeholder
    policy, without a source format in the way.

    Existing outputs are refused (:class:`FileExistsError`) and every
    file is published with mode 0600, like the rest of the matrix
    (``tdata`` folders are hardened to 0700/0600).

    Returns:
        ``{"output", "output_kind", "dc_id", "user_id", "filled",
        "notes", "preserved", "dropped"}``.  ``dropped`` lists only fields
        the destination genuinely cannot reproduce *and* whose value differs
        from that destination's own default, so an unset field (``None``) or
        a ``False``/``0`` default is not reported as a loss.
    """
    data, filled = _fill_for_destination(data, destination_format, user_id, api_id)
    output_kind = _write_destination(
        data, destination, destination_format, passcode, variant
    )
    keeps = _preserves(destination_format, variant)
    result: dict[str, Any] = {
        "destination_format": destination_format,
        "dc_id": data.dc_id,
        "user_id": data.user_id if "user_id" in keeps else None,
        "output": str(destination),
        "output_kind": output_kind,
        "preserved": sorted(keeps),
        "dropped": sorted(
            field
            for field in SessionData._fields
            if field not in keeps
            and field not in ("dc_id", "auth_key")
            and _loses(field, getattr(data, field))
        ),
    }
    if filled:
        result["filled"] = [field for field, _ in filled]
        result["notes"] = [
            _fill_note(field, source_label, value) for field, value in filled
        ]
    return result


def convert_session(
    source: str,
    source_format: Optional[str],
    destination: str,
    destination_format: str,
    *,
    user_id: Optional[int] = None,
    api_id: Optional[int] = None,
    passcode: str = "",
    passphrase: str = "",
    variant: str = "pyrogram",
    account_index: Optional[int] = None,
) -> dict[str, Any]:
    """Convert one session between any two formats of the matrix above.

    This is the entrypoint the ``tgmint convert`` CLI calls — and the one
    v1.16.0 shipped without: the command probed for it, it did not exist,
    and every invocation exited 2 (a self-skipping test kept the suite
    green over the dead command; fixed in v1.16.1).

    Args:
        source: the session string itself for ``*-string`` formats, the
            SQLite file path for ``*-session``, the folder for ``tdata``.
        source_format: the format of ``source``. The sources are
            ``telethon-session``, ``telethon-string``, ``pyrogram-session``,
            ``pyrogram-string``, ``gramjs-string``, ``tdata``,
            ``android-dir`` (an official-Android-app data dump; see
            :mod:`tgmint.codec.android`) and ``profile`` (a ``.tgmint``
            envelope); the destinations are the same set minus
            ``profile`` (write that one with ``tgmint profile seal``)
            and minus ``android-dir`` (the app dir is read-only, never
            written).  ``source_format=None`` infers it from the path:
            ``.tgmint`` -> ``profile``, a directory with a ``tgnet.dat``
            -> ``android-dir``, anything else ``telethon-session``.
        destination_format: the format to write (see ``source_format``).
        destination: output path — a file for every format except
            ``tdata`` (a folder).  Existing outputs are never overwritten
            (:class:`FileExistsError`); string outputs are files written
            with mode 0600 (the string is never echoed to the caller).
        user_id: supplied only when the source format cannot
            carry a field the destination requires (Telethon, GramJS and
            tdata store no api_id; Telethon and GramJS strings store no
            user_id).  Without them a labelled placeholder is written and
            reported in the result's ``notes`` — the destination client
            refreshes ``user_id`` from the server on first connect.
        api_id: same rule as ``user_id``.
        passcode: the local passcode of a source ``tdata`` folder (also
            used when writing one).
        passphrase: the passphrase of a sealed ``profile`` source; every
            other source format ignores it.
        variant: pyrogram SQLite variant for ``pyrogram-session``
            destinations (``"pyrogram"`` or ``"kurigram"``).
        account_index: which account of a multi-account ``tdata`` or
            ``android-dir`` *source* to read; ``None`` selects its
            main/first account.  Ignored by every other source format.

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
    if source_format in (None, "", "auto"):
        source_format = infer_source_format(source)
    if source_format in PROFILE_FORMATS:
        data = _read_profile_source(source, passphrase)
        source_format = "profile"
    else:
        data = _read_source(
            source, source_format, passcode, account_index=account_index
        )

    written = write_session(
        data,
        destination,
        destination_format,
        user_id=user_id,
        api_id=api_id,
        passcode=passcode,
        variant=variant,
        source_label=source_format,
    )
    result: dict[str, Any] = {
        "source_format": source_format,
        "test_mode": bool(data.test_mode),
    }
    result.update(written)
    if source_format == "android-dir" and "api_id" in written.get("preserved", ()):
        # record where the destination's api_id came from: the Android
        # reader pins 4, the official app's own wire identity, so no
        # placeholder note fired — say so, so the report stays honest
        notes = list(written.get("notes", ()))
        notes.append(
            f"api_id: android-dir source carried {data.api_id} — the "
            "official Android app's own wire api_id "
            "(tgmint.codec.android.OFFICIAL_APP_API_ID), not a placeholder"
        )
        result["notes"] = notes
    return result
