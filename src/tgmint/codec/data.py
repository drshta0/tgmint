"""Neutral session model shared by every codec reader/writer.

The neutral representation is deliberately minimal: an authorization is a
(dc_id, 256-byte auth_key) pair plus whatever identity/connection metadata
the *source* format actually stored.  Formats differ in what they preserve
(see ``PRESERVES`` in each codec module and the matrix docstring in
``tgmint.codec``), so ``user_id`` / ``server_address`` / ``port`` /
``is_bot`` / ``api_id`` are all optional and may be ``None`` after a read.

Validation and safe I/O helpers here are ported from TGConvertor
(MIT License, Copyright (c) 2020-2025 Nazar Ihnatiuk) —
https://github.com/nazar220160/TGConvertor/blob/master/TGConvertor/sessions/_utils.py
— adapted to this namespace: plain ``ValueError`` subclass instead of
TGConvertor's ``ValidationError``, no asyncio, py3.9 typing.

VERIFICATION LABELS:

* **Telethon** (SQLite + StringSession v1) — *fully verified offline
  against real Telethon 1.43.2*: our writer's string output is
  byte-identical to ``telethon.sessions.StringSession.save()``, our
  written ``.session`` files open with ``telethon.sessions.SQLiteSession``
  (and upgrade cleanly), and files written by real Telethon read back
  correctly.  See ``tests/test_codec_matrix.py`` (skipped when telethon
  is not installed).
* **GramJS** — *cross-checked against TGConvertor's own semantics only*;
  no GramJS oracle exists in this tree.
* **Pyrogram / kurigram** — *self-consistent only*: we read back exactly
  what we write; there is no external oracle (pyrogram/kurigram are not
  installed in CI today).
"""

from __future__ import annotations

import base64
import binascii
import errno
import os
import shutil
import sqlite3
import tempfile
import typing
from contextlib import closing
from pathlib import Path

__all__ = [
    "SessionData",
    "CodecError",
    "validate",
    "decode_b64",
    "read_sqlite_row",
    "write_sqlite_file",
    "write_text_file",
]


class CodecError(ValueError):
    """A session string/file is malformed, or a SessionData field is invalid.

    Subclasses :class:`ValueError` so generic callers can catch it without
    importing anything from tgmint.
    """


class SessionData(typing.NamedTuple):
    """One Telegram authorization in a framework-neutral form.

    Attributes:
        dc_id: data-center id the auth_key belongs to (1-255).
        auth_key: the 256-byte MTProto authorization key (secret!).
        user_id: account id when the source format stored it (Telethon and
            GramJS string formats never do; tdata and Pyrogram formats do).
        server_address: dotted/expanded IP when stored (Telethon SQLite and
            GramJS store it; vanilla Pyrogram derives it from dc_id at
            connect time, so reads return ``None``).
        port: UDP/TCP port when stored (same rules as server_address).
        is_bot: bot flag when stored (Pyrogram formats only).
        test_mode: True when the session belongs to a test DC.  Stored
            explicitly by Pyrogram formats; derived from the server address
            by Telethon/GramJS readers.
        api_id: api_id when stored (Pyrogram string/SQLite formats only;
            required by the Pyrogram string writer).
    """

    dc_id: int
    auth_key: bytes
    user_id: typing.Optional[int] = None
    server_address: typing.Optional[str] = None
    port: typing.Optional[int] = None
    is_bot: typing.Optional[bool] = None
    test_mode: bool = False
    api_id: typing.Optional[int] = None

    def validated(self) -> SessionData:
        """Validate invariants and return ``self`` (chainable)."""
        validate(self.dc_id, self.auth_key, self.user_id)
        return self


def validate(dc_id: int, auth_key: bytes, user_id: typing.Optional[int] = None) -> None:
    """Raise :class:`CodecError` unless the core authorization fields are sane.

    Ported from TGConvertor's ``sessions/_utils.validate_fields``.
    """
    if type(dc_id) is not int or not 1 <= dc_id <= 255:
        raise CodecError("dc_id must be an integer between 1 and 255")
    if not isinstance(auth_key, bytes) or len(auth_key) != 256 or not any(auth_key):
        raise CodecError("auth_key must be 256 bytes and must not be all zero")
    if user_id is not None and (type(user_id) is not int or not 0 < user_id < 2**63):
        raise CodecError("user_id must be a positive signed 64-bit integer")


def decode_b64(value: str, *, max_len: int = 512) -> bytes:
    """Decode a session-string body (urlsafe or standard base64, padded or not).

    Telethon writes padded urlsafe base64; Pyrogram-family strings are
    unpadded urlsafe; GramJS writes padded standard base64.  Accepting all
    of the above keeps readers forgiving while writers stay byte-exact for
    their framework.  Ported from TGConvertor's ``decode_string``.
    """
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise CodecError("Invalid session string")
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error):
        raise CodecError("Invalid session string encoding") from None


def read_sqlite_row(path: typing.Union[str, Path], required: set[str]) -> dict[str, typing.Any]:
    """Read exactly one authorization row from a ``sessions`` table, read-only.

    The source file is never modified (opened through a ``mode=ro`` URI) and
    additive schema changes (extra columns/tables from newer client
    versions) are tolerated as long as every required column exists.
    Ported from TGConvertor's ``read_session``.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Session file does not exist: {path}")
    try:
        with closing(
            sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        ) as db:
            db.row_factory = sqlite3.Row
            columns = {row["name"] for row in db.execute("PRAGMA table_info(sessions)")}
            if not required.issubset(columns):
                raise CodecError("Session database has an unsupported schema")
            rows = db.execute("SELECT * FROM sessions LIMIT 2").fetchall()
            if len(rows) != 1:
                raise CodecError("Session database must contain exactly one authorization")
            return dict(rows[0])
    except sqlite3.Error:
        raise CodecError(
            "Cannot read session database; close its client and check the format"
        ) from None


#: ``link(2)`` errors that mean "this filesystem has no hard links" rather
#: than "you may not publish here": FAT/exFAT and SMB mounts answer EXDEV,
#: some overlays/sandboxes answer EOPNOTSUPP/ENOTSUP, a few answer EPERM or
#: ENOSYS.  Only these fall back to the copy publish; a real EACCES/EIO
#: still surfaces.
_NO_HARDLINK = frozenset(
    (
        errno.EXDEV,
        errno.EOPNOTSUPP,
        getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
        errno.EPERM,
        errno.ENOSYS,
    )
)


def _publish_private(temporary: Path, path: Path) -> None:
    """Publish `temporary` as `path` and never replace an existing `path`.

    A hard link is the preferred publish: exclusive-by-construction, so a
    concurrent writer loses loudly instead of clobbering a session, and no
    partial output can ever be visible.  Filesystems without hard links
    (FAT/exFAT/SMB/overlay mounts) reject ``link(2)``; there we fall back to
    an ``O_EXCL`` create plus a byte copy, which keeps the never-overwrite
    guarantee (the half-written file is unlinked if the copy fails) and
    keeps the 0600 mode set by the caller.
    """
    try:
        os.link(temporary, path)
        return
    except OSError as exc:
        if exc.errno not in _NO_HARDLINK:
            raise
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as destination, open(temporary, "rb") as source:
            shutil.copyfileobj(source, destination)
            destination.flush()
            os.fsync(destination.fileno())
        os.chmod(path, 0o600)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def write_text_file(
    path: typing.Union[str, Path],
    text: str,
) -> None:
    """Publish a session-string file privately.

    Same discipline as :func:`write_sqlite_file` (it shares the publish
    helper): the text is written to a temporary file next to the destination
    and hard-linked into place, so an existing file is never replaced and a
    failed write leaves no partial output.  On filesystems without hard
    links the publish degrades to an ``O_EXCL`` copy (see
    :func:`_publish_private`).  Output is chmod 0600 — a session string is a
    credential.
    """
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"Output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".tgmint-codec-", suffix=".string", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fp:
            fp.write(text)
            fp.flush()
            os.fsync(fp.fileno())
        os.chmod(temporary, 0o600)
        _publish_private(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_sqlite_file(
    path: typing.Union[str, Path],
    populate: typing.Callable[[sqlite3.Connection], None],
) -> None:
    """Build a session database privately, then publish it exclusively.

    The database is created under a temporary name next to the destination
    and published exclusively (hard link where the filesystem has them, else
    an ``O_EXCL`` copy — see :func:`_publish_private`), so an existing file
    is never replaced (a concurrent writer loses loudly instead of clobbering
    a session) and a failed write leaves no partial output.  Output is chmod
    0600 — session files are credentials.  Ported from TGConvertor's
    ``write_database``.
    """
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"Output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".tgmint-codec-", suffix=".session", dir=path.parent)
    os.close(fd)
    temporary = Path(name)
    try:
        with closing(sqlite3.connect(temporary)) as db:
            populate(db)
            db.commit()
        os.chmod(temporary, 0o600)
        _publish_private(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
