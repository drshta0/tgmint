"""tgmint.profile — the portable identity envelope (``.tgmint``).

Today one identity is three unrelated files:
the session, the fingerprint sidecar, and the passkey that can recover it.
This module bundles all three into one portable artifact, plaintext or
sealed with a passphrase, and teaches :mod:`tgmint.codec` to read it — so
``tgmint convert --from profile`` and ``tgmint heal`` compose with it.

Plaintext form (JSON, UTF-8, written atomically, mode 0600)::

    {"format": "tgmint-profile/1",
     "session": {"format": "telethon-string", "encoding": "utf8",
                 "data": "1..."},
     "fingerprint": {... Fingerprint.to_dict() ...} | null,
     "passkey": {... passkey store JSON ...} | null,
     "meta": {"created": "<iso8601>", "tgmint": "<version>", "note": "..."}}

Sealed form (the same file, encrypted)::

    {"format": "tgmint-profile/1",
     "sealed": {"kdf": "pbkdf2-sha256", "iterations": 600000,
                "salt": "<b64>", "nonce": "<b64>", "ciphertext": "<b64>"}}

The ``ciphertext`` is AES-256-GCM over the *plaintext container bytes* —
the exact UTF-8 JSON this module writes when unsealed — keyed by
PBKDF2-HMAC-SHA256(passphrase, salt, 600000 iterations, 32 bytes).  The
format id ``tgmint-profile/1`` is the GCM associated data, so a sealed
block cannot be replayed into a differently-versioned container.  Wrong
passphrase and tampered ciphertext are indistinguishable by construction
and both raise one error: :class:`ProfileError`.

``cryptography`` is imported lazily: an unsealed profile never needs it,
and the CLI/`convert` paths keep working on a build without the
``[passkeys]`` extra.

What the ``session`` block stores
---------------------------------

The payload is a session *string* of the format's own family, because a
string is the one representation every codec can read without a
filesystem: ``telethon-*`` store the Telethon StringSession,
``pyrogram-*`` the Pyrogram 2.x string, ``gramjs-string`` the GramJS
string.  The ``format`` label records provenance, so a session that came
from a ``.session`` SQLite file still says ``telethon-session`` even
though its payload is that file's string form (an authorization *is*
``dc_id`` + ``auth_key``; the file and its string carry the same pair).
``tdata`` has no string form of its own, so its payload is the Telethon
string of the folder's authorization — the ``user_id`` a tdata folder
knows is not carried by that form, and the destination client learns it
from the server on first connect again.

``encoding`` says how ``data`` is written down: ``"utf8"`` for the
session string itself, ``"base64"`` when the caller handed us raw
(payload) bytes instead of a :class:`~tgmint.codec.data.SessionData`.

Verification status
-------------------

* **Fully verified offline** — plaintext and sealed round trips, the
  file discipline (0600, atomic, never overwrite), wrong passphrase and
  tampered ciphertext (both are real AES-GCM authentication failures),
  cross-validation of session ↔ fingerprint ↔ passkey, and the codec
  integration: ``tests/test_profile.py``.
* **NOT verified** — nothing here touches the network, so there is no
  live-account claim to make.  The sealed form has no external oracle: it
  is our own container, and its security rests on AES-256-GCM and
  PBKDF2-SHA256 exactly as ``cryptography`` implements them.  A profile
  is only as strong as the passphrase the user picks; 600000 PBKDF2
  iterations is a floor for interactive use, not a substitute for one.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple, Union

from . import __version__ as _tgmint_version
from .codec import gramjs as _gramjs
from .codec import pyrogram as _pyrogram
from .codec import telethon as _telethon
from .codec.data import CodecError, SessionData
from .fingerprint import Fingerprint

__all__ = [
    "FORMAT",
    "KDF",
    "ITERATIONS",
    "ProfileError",
    "OpenedProfile",
    "SESSION_FORMATS",
    "seal",
    "open_profile",
    "write_profile",
    "read_profile",
    "inspect_profile",
    "guess_format",
]

#: the container's self-identifying format id; also the GCM associated data
FORMAT = "tgmint-profile/1"
FORMAT_BYTES = FORMAT.encode("utf-8")

KDF = "pbkdf2-sha256"
#: interactive-use floor; stored in the file so a future bump stays readable
ITERATIONS = 600_000
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32

#: guard rails when reading a file we did not write (a 2**40-iteration
#: sealed block would hang the reader forever)
_MAX_ITERATIONS = 10_000_000


class ProfileError(CodecError):
    """A profile is malformed, sealed with another passphrase, or tampered with.

    One type for every failure on the read side on purpose: AES-GCM cannot
    tell a wrong passphrase from a modified file, so neither can we — and
    a caller that wants to distinguish "ask again" from "corrupt" has no
    reliable signal to do it with.

    Subclasses :class:`tgmint.codec.data.CodecError` (itself a
    ``ValueError``), so ``except ValueError`` and ``except CodecError``
    both keep working.
    """


# ---------------------------------------------------------------------------
# session payload: label -> (writer, reader)
# ---------------------------------------------------------------------------

#: session-format label -> (writer, reader).  ``*-session`` labels ride the
#: family's string form (see the module docstring); ``tdata`` rides the
#: Telethon string because tdesktop's own storage has no string form.
_SESSION_CODECS: Dict[str, Tuple[Callable[[SessionData], str], Callable[[str], SessionData]]] = {
    "telethon-session": (_telethon.write_string, _telethon.read_string),
    "telethon-string": (_telethon.write_string, _telethon.read_string),
    "pyrogram-session": (_pyrogram.write_string, _pyrogram.read_string),
    "pyrogram-string": (_pyrogram.write_string, _pyrogram.read_string),
    "gramjs-string": (_gramjs.write_string, _gramjs.read_string),
    "tdata": (_telethon.write_string, _telethon.read_string),
}

#: every session format a profile may record, sorted for messages/help
SESSION_FORMATS = tuple(sorted(_SESSION_CODECS))

_PROFILE_SUFFIX = ".tgmint"


def guess_format(path: Union[str, Path]) -> str:
    """Best-guess codec format for ``path``: ``.tgmint`` -> ``profile``.

    Everything else defaults to ``telethon-session`` (the format this
    repository is centred on) — callers that know better must say so.
    """
    if str(path).endswith(_PROFILE_SUFFIX):
        return "profile"
    return "telethon-session"


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: Any, what: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ProfileError(f"profile: sealed block has no usable {what}")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, binascii.Error, UnicodeEncodeError):
        raise ProfileError(f"profile: sealed block has a malformed {what}") from None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _crypto(name: str):
    """Import one ``cryptography`` primitive, or explain what to install.

    Lazily, because an unsealed profile (and every other codec path) must
    keep working on a build without the ``[passkeys]`` extra.
    """
    try:
        if name == "AESGCM":
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            return AESGCM
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        return PBKDF2HMAC, hashes.SHA256
    except ImportError as exc:  # pragma: no cover - exercised by tests via mock
        raise ProfileError(
            "sealing a profile needs the 'passkeys' extra (cryptography is "
            f"not importable: {exc}); install it with "
            "'pip install tgmint[passkeys]' — an unsealed profile needs no "
            "crypto at all"
        ) from None


def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    PBKDF2HMAC, sha256 = _crypto("PBKDF2HMAC")
    return PBKDF2HMAC(
        algorithm=sha256(),
        length=KEY_BYTES,
        salt=salt,
        iterations=iterations,
    ).derive(passphrase.encode("utf-8"))


def _fingerprint_dict(fingerprint: Any) -> Optional[Dict[str, Any]]:
    """Normalize a Fingerprint | dict | None into a plain dict."""
    if fingerprint is None:
        return None
    if isinstance(fingerprint, Fingerprint):
        return fingerprint.to_dict()
    if isinstance(fingerprint, dict):
        return dict(fingerprint)
    raise ProfileError(
        "fingerprint must be a Fingerprint, a dict, or None, got "
        f"{type(fingerprint).__name__}"
    )


def _passkey_dict(passkey: Any) -> Optional[Dict[str, Any]]:
    """Normalize a passkey store payload (the JSON of ``PasskeyStore``)."""
    if passkey is None:
        return None
    if not isinstance(passkey, dict):
        raise ProfileError(
            "passkey must be the passkey store's JSON object (a dict) or "
            f"None, got {type(passkey).__name__}"
        )
    for key in ("user_handle", "private_key"):
        if not isinstance(passkey.get(key), str) or not passkey[key]:
            raise ProfileError(
                "passkey is not a tgmint passkey store (no "
                f"{key!r}); pass the JSON content of a file written by "
                "tgmint.passkeys.register_passkey"
            )
    return dict(passkey)


# ---------------------------------------------------------------------------
# sealing / opening the seal
# ---------------------------------------------------------------------------


def _seal_container(container: Dict[str, Any], passphrase: str) -> Dict[str, Any]:
    """Encrypt a plaintext container into the sealed JSON tree."""
    if not isinstance(passphrase, str) or not passphrase:
        raise ProfileError("a passphrase must be a non-empty string")
    AESGCM = _crypto("AESGCM")
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = _derive_key(passphrase, salt, ITERATIONS)
    plaintext = json.dumps(container, indent=2).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, FORMAT_BYTES)
    return {
        "format": FORMAT,
        "sealed": {
            "kdf": KDF,
            "iterations": ITERATIONS,
            "salt": _b64e(salt),
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ciphertext),
        },
    }


def _open_sealed(raw: Dict[str, Any], passphrase: Optional[str], where: str) -> Dict[str, Any]:
    """Decrypt the sealed block of ``raw`` into a plaintext container."""
    sealed = raw.get("sealed")
    if not isinstance(sealed, dict):
        raise ProfileError(f"{where}: 'sealed' is not an object")
    if sealed.get("kdf") != KDF:
        raise ProfileError(
            f"{where}: unsupported seal KDF {sealed.get('kdf')!r} "
            f"(this build understands {KDF!r})"
        )
    if passphrase is None or not passphrase:
        raise ProfileError(
            f"{where}: this profile is sealed; a passphrase is required "
            "(use --passphrase-env VAR or --passphrase-stdin)"
        )
    try:
        iterations = int(sealed["iterations"])
    except (KeyError, TypeError, ValueError):
        raise ProfileError(f"{where}: sealed block has no usable iterations") from None
    if not 1 <= iterations <= _MAX_ITERATIONS:
        raise ProfileError(
            f"{where}: sealed block asks for {iterations} PBKDF2 iterations, "
            f"outside the sane range 1..{_MAX_ITERATIONS}"
        )
    salt = _b64d(sealed.get("salt"), "salt")
    nonce = _b64d(sealed.get("nonce"), "nonce")
    ciphertext = _b64d(sealed.get("ciphertext"), "ciphertext")
    if len(nonce) != NONCE_BYTES or len(salt) < 8:
        raise ProfileError(f"{where}: sealed block has an implausible salt/nonce size")

    AESGCM = _crypto("AESGCM")
    key = _derive_key(passphrase, salt, iterations)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, FORMAT_BYTES)
    except ProfileError:
        raise
    except Exception:
        # InvalidTag — wrong passphrase, tampered ciphertext, or a
        # different associated data.  Deliberately one message.
        raise ProfileError(
            f"{where}: wrong passphrase, or the profile was tampered with "
            "(AES-256-GCM authentication failed)"
        ) from None
    try:
        container = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ProfileError(f"{where}: decrypted payload is not a JSON container") from None
    if not isinstance(container, dict) or container.get("format") != FORMAT:
        raise ProfileError(f"{where}: decrypted payload is not a {FORMAT} container")
    return container


# ---------------------------------------------------------------------------
# containers
# ---------------------------------------------------------------------------


def seal(
    session: Union[SessionData, bytes],
    session_format: str,
    *,
    fingerprint: Any = None,
    passkey: Any = None,
    passphrase: Optional[str] = None,
    note: str = "",
) -> Dict[str, Any]:
    """Build the profile container for one authorization.

    Args:
        session: a :class:`~tgmint.codec.data.SessionData`, or the
            already-serialized session-string *bytes* for
            ``session_format`` (stored base64-encoded).
        session_format: the codec format name the identity came from
            (one of :data:`SESSION_FORMATS`); recorded as provenance.
        fingerprint: a :class:`~tgmint.fingerprint.Fingerprint`, its dict
            form, or ``None``.  A dict may additionally carry ``user_id``
            / ``dc_id``; those are cross-checked when the profile is
            opened.
        passkey: the passkey store's JSON object (``PasskeyStore.to_dict()``)
            or ``None``.
        passphrase: when given, the container is sealed with it; ``None``
            (or ``""``) leaves it plaintext.
        note: free text stored in ``meta.note``.

    Returns:
        the container dict — plaintext or ``{"format", "sealed"}``.  Pass
        it to :func:`write_profile`.

    Raises:
        ProfileError: unknown session format, an unrepresentable session,
            a malformed passkey payload, or missing crypto when sealing.
    """
    if not isinstance(session_format, str) or session_format not in _SESSION_CODECS:
        raise ProfileError(
            f"unknown session format {session_format!r}; expected one of "
            f"{list(SESSION_FORMATS)}"
        )
    writer, _reader = _SESSION_CODECS[session_format]

    if isinstance(session, SessionData):
        try:
            payload = writer(session.validated())
        except CodecError as exc:
            raise ProfileError(
                f"cannot store this session as {session_format}: {exc}"
            ) from None
        encoding = "utf8"
    elif isinstance(session, (bytes, bytearray)):
        raw = bytes(session)
        if not raw:
            raise ProfileError("session bytes payload is empty")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ProfileError(
                "a bytes session payload must be the UTF-8 session string "
                f"of a {session_format} session"
            ) from None
        try:  # fail fast: seal only what can be opened again
            _SESSION_CODECS[session_format][1](text)
        except CodecError as exc:
            raise ProfileError(
                f"the bytes payload is not a readable {session_format} "
                f"session string: {exc}"
            ) from None
        payload = text
        # bytes in = payload verbatim (base64-encoded), text in = text out
        encoding = "base64"
    else:
        raise ProfileError(
            "session must be a SessionData or the session-string bytes for "
            f"{session_format}, got {type(session).__name__}"
        )

    container: Dict[str, Any] = {
        "format": FORMAT,
        "session": {
            "format": session_format,
            "encoding": encoding,
            "data": _b64e(payload.encode("utf-8")) if encoding == "base64" else payload,
        },
        "fingerprint": _fingerprint_dict(fingerprint),
        "passkey": _passkey_dict(passkey),
        "meta": {
            "created": _now_iso(),
            "tgmint": _tgmint_version,
            "note": note or "",
        },
    }
    if passphrase:
        return _seal_container(container, passphrase)
    return container


@dataclass
class OpenedProfile:
    """One opened profile: session + recorded identity + recovery material.

    Attributes:
        session: the authorization the envelope carries.
        fingerprint: the identity the session was born with, when recorded.
        passkey: the passkey store JSON, when recorded.
        meta: the container's ``meta`` object (created / tgmint / note).
        session_format: the recorded codec format label (provenance).
        sealed: True when the file on disk was sealed.
        path: where it was read from, when it came from a file.
    """

    session: SessionData
    fingerprint: Optional[Fingerprint] = None
    passkey: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any] = field(default_factory=dict)
    session_format: str = ""
    sealed: bool = False
    path: Optional[str] = None


def _decode_container(
    container: Any, *, sealed: bool, where: str
) -> OpenedProfile:
    """Turn a plaintext container dict into an :class:`OpenedProfile`."""
    if not isinstance(container, dict):
        raise ProfileError(f"{where}: a profile container must be a JSON object")
    if container.get("format") != FORMAT:
        raise ProfileError(
            f"{where}: unsupported profile format {container.get('format')!r} "
            f"(expected {FORMAT!r})"
        )

    session_block = container.get("session")
    if not isinstance(session_block, dict):
        raise ProfileError(f"{where}: profile has no 'session' object")
    session_format = session_block.get("format")
    if session_format not in _SESSION_CODECS:
        raise ProfileError(
            f"{where}: unknown session format {session_format!r}; expected "
            f"one of {list(SESSION_FORMATS)}"
        )
    encoding = session_block.get("encoding")
    data = session_block.get("data")
    if not isinstance(data, str) or not data:
        raise ProfileError(f"{where}: profile has no session data")
    if encoding == "base64":
        raw = _b64d(data, "session data")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ProfileError(
                f"{where}: the stored {session_format} payload is not UTF-8"
            ) from None
    elif encoding == "utf8":
        text = data
    else:
        raise ProfileError(
            f"{where}: unknown session encoding {encoding!r} "
            "(expected 'utf8' or 'base64')"
        )
    _writer, reader = _SESSION_CODECS[session_format]
    try:
        session = reader(text)
    except CodecError as exc:
        raise ProfileError(
            f"{where}: the stored {session_format} session does not parse ({exc})"
        ) from None

    fingerprint_data = container.get("fingerprint")
    fingerprint: Optional[Fingerprint] = None
    recorded_user_id = None
    recorded_dc_id = None
    if fingerprint_data is not None:
        if not isinstance(fingerprint_data, dict):
            raise ProfileError(f"{where}: 'fingerprint' is not an object")
        recorded_user_id = fingerprint_data.get("user_id")
        recorded_dc_id = fingerprint_data.get("dc_id")
        try:
            fingerprint = Fingerprint.from_dict(fingerprint_data)
        except (ValueError, TypeError) as exc:
            raise ProfileError(f"{where}: unusable fingerprint ({exc})") from None

    passkey = container.get("passkey")
    if passkey is not None and not isinstance(passkey, dict):
        raise ProfileError(f"{where}: 'passkey' is not an object")

    meta = container.get("meta")
    if meta is not None and not isinstance(meta, dict):
        raise ProfileError(f"{where}: 'meta' is not an object")

    _cross_validate(
        where,
        session,
        recorded_user_id=recorded_user_id,
        recorded_dc_id=recorded_dc_id,
        passkey=passkey,
    )

    return OpenedProfile(
        session=session,
        fingerprint=fingerprint,
        passkey=dict(passkey) if passkey is not None else None,
        meta=dict(meta) if meta else {},
        session_format=session_format,
        sealed=sealed,
        path=None if where.startswith("<") else where,
    )


def _passkey_user_id(passkey: Dict[str, Any]) -> Optional[int]:
    """The user id encoded in a passkey store's ``"dc:user"`` handle."""
    handle = passkey.get("user_handle")
    if not isinstance(handle, str) or ":" not in handle:
        return None
    try:
        return int(handle.split(":", 1)[1])
    except ValueError:
        return None


def _cross_validate(
    where: str,
    session: SessionData,
    *,
    recorded_user_id: Any,
    recorded_dc_id: Any,
    passkey: Optional[Dict[str, Any]],
) -> None:
    """Refuse a container whose parts describe different accounts.

    The envelope's whole point is that its pieces belong together, so two
    known-and-different identities are an error, not a warning: healing or
    converting from such a profile would move one account's session under
    another account's identity.
    """
    if (
        recorded_user_id is not None
        and session.user_id is not None
        and int(recorded_user_id) != int(session.user_id)
    ):
        raise ProfileError(
            f"{where}: fingerprint says user_id {int(recorded_user_id)} but "
            f"the session belongs to user_id {int(session.user_id)}"
        )
    if recorded_dc_id is not None and int(recorded_dc_id) != int(session.dc_id):
        raise ProfileError(
            f"{where}: fingerprint says dc_id {int(recorded_dc_id)} but the "
            f"session lives on dc_id {int(session.dc_id)}"
        )
    if passkey is not None:
        passkey_user = _passkey_user_id(passkey)
        if (
            passkey_user is not None
            and session.user_id is not None
            and passkey_user != int(session.user_id)
        ):
            raise ProfileError(
                f"{where}: the passkey belongs to user_id {passkey_user} but "
                f"the session belongs to user_id {int(session.user_id)}"
            )


def _read_container(
    path: Union[str, Path], passphrase: Optional[str]
) -> Tuple[Dict[str, Any], bool]:
    """Read + (when sealed) decrypt a profile file -> (container, sealed)."""
    profile_path = Path(path)
    if not profile_path.is_file():
        raise FileNotFoundError(f"Profile file does not exist: {profile_path}")
    try:
        with open(profile_path, "r", encoding="utf-8") as fp:
            raw = json.load(fp)
    except (OSError, ValueError) as exc:
        raise ProfileError(f"{profile_path}: not a tgmint profile ({exc})") from None
    if not isinstance(raw, dict):
        raise ProfileError(f"{profile_path}: a profile must be a JSON object")
    if raw.get("format") != FORMAT:
        raise ProfileError(
            f"{profile_path}: unsupported profile format {raw.get('format')!r} "
            f"(expected {FORMAT!r})"
        )
    if "sealed" in raw:
        return _open_sealed(raw, passphrase, str(profile_path)), True
    return raw, False


def read_profile(path: Union[str, Path], *, passphrase: Optional[str] = None) -> Dict[str, Any]:
    """Read a profile file and return its **plaintext** container dict.

    Detects the sealed form by the presence of the top-level ``"sealed"``
    object and decrypts it with ``passphrase``.

    Raises:
        FileNotFoundError: ``path`` does not exist.
        ProfileError: not a profile, unknown/unsupported format, missing or
            wrong passphrase, or a tampered sealed block.
    """
    container, _sealed = _read_container(path, passphrase)
    return container


def open_profile(
    path_or_dict: Union[str, Path, Dict[str, Any]],
    *,
    passphrase: Optional[str] = None,
) -> OpenedProfile:
    """Open a profile (path or container dict) into an :class:`OpenedProfile`.

    Raises:
        ProfileError: anything :func:`read_profile` rejects, plus a session
            payload that does not parse and cross-validation failures
            (session vs fingerprint vs passkey).
    """
    if isinstance(path_or_dict, dict):
        raw = path_or_dict
        if not isinstance(raw, dict):
            raise ProfileError("a profile container must be a JSON object")
        if raw.get("format") != FORMAT:
            raise ProfileError(
                f"<profile>: unsupported profile format {raw.get('format')!r} "
                f"(expected {FORMAT!r})"
            )
        if "sealed" in raw:
            container = _open_sealed(raw, passphrase, "<profile>")
            return _decode_container(container, sealed=True, where="<profile>")
        return _decode_container(raw, sealed=False, where="<profile>")

    container, sealed = _read_container(path_or_dict, passphrase)
    return _decode_container(container, sealed=sealed, where=str(path_or_dict))


def write_profile(container: Dict[str, Any], path: Union[str, Path]) -> None:
    """Write a container as a private profile file; never overwrites.

    Same publish discipline as the codec's writers: the JSON is written to
    a temporary file in the destination's directory (mode 0600 from its
    first byte), fsync'd, then hard-linked into place — an existing file is
    refused with :class:`FileExistsError` and a failed write leaves no
    partial output behind.

    Raises:
        FileExistsError: ``path`` already exists.
        ProfileError: ``container`` is not a profile container.
    """
    if not isinstance(container, dict):
        raise ProfileError(
            f"container must be a dict, got {type(container).__name__}"
        )
    if container.get("format") != FORMAT:
        raise ProfileError(
            f"container format must be {FORMAT!r}, got {container.get('format')!r}"
        )
    if "sealed" in container:
        if not isinstance(container["sealed"], dict):
            raise ProfileError("container 'sealed' must be an object")
    elif not isinstance(container.get("session"), dict):
        raise ProfileError("container has no 'session' object")

    destination = Path(path)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"Output already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    text = json.dumps(container, indent=2, ensure_ascii=False) + "\n"
    fd, name = tempfile.mkstemp(
        prefix=".tgmint-profile-", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            fp.write(text)
            fp.flush()
            os.fsync(fp.fileno())
        os.chmod(temporary, 0o600)
        os.link(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# inspection (what `tgmint profile inspect` prints)
# ---------------------------------------------------------------------------


def inspect_profile(
    path: Union[str, Path], *, passphrase: Optional[str] = None
) -> Dict[str, Any]:
    """Summarize a profile without exposing any secret.

    Reports the container format, whether it is sealed (and with which KDF
    / iteration count), the recorded session format, the authorization's
    ``dc_id``/``user_id``, whether a fingerprint and a passkey are bundled,
    and the ``meta`` block.  A sealed profile without a passphrase is
    reported as locked instead of failing: ``inspect`` must stay a
    read-only, offline, no-passphrase command.

    Raises:
        FileNotFoundError: ``path`` does not exist.
        ProfileError: not a profile, or an unusable container/passphrase.
    """
    profile_path = Path(path)
    if not profile_path.is_file():
        raise FileNotFoundError(f"Profile file does not exist: {profile_path}")
    try:
        with open(profile_path, "r", encoding="utf-8") as fp:
            raw = json.load(fp)
    except (OSError, ValueError) as exc:
        raise ProfileError(f"{profile_path}: not a tgmint profile ({exc})") from None
    if not isinstance(raw, dict):
        raise ProfileError(f"{profile_path}: a profile must be a JSON object")
    if raw.get("format") != FORMAT:
        raise ProfileError(
            f"{profile_path}: unsupported profile format {raw.get('format')!r} "
            f"(expected {FORMAT!r})"
        )

    sealed_block = raw.get("sealed")
    sealed = isinstance(sealed_block, dict)
    summary: Dict[str, Any] = {
        "path": str(profile_path),
        "format": FORMAT,
        "sealed": sealed,
        "locked": bool(sealed and not passphrase),
        "session_format": None,
        "dc_id": None,
        "user_id": None,
        "has_fingerprint": False,
        "has_passkey": False,
        "fingerprint": None,
        "passkey": None,
        "meta": {},
    }
    if sealed:
        summary["kdf"] = sealed_block.get("kdf")
        summary["iterations"] = sealed_block.get("iterations")
        if not passphrase:
            return summary

    opened = _decode_container(
        _open_sealed(raw, passphrase, str(profile_path)) if sealed else raw,
        sealed=sealed,
        where=str(profile_path),
    )
    summary.update(
        {
            "session_format": opened.session_format,
            "dc_id": opened.session.dc_id,
            "user_id": opened.session.user_id,
            "has_fingerprint": opened.fingerprint is not None,
            "has_passkey": opened.passkey is not None,
            "fingerprint": (
                opened.fingerprint.to_dict() if opened.fingerprint else None
            ),
            "passkey": (
                {
                    "name": opened.passkey.get("name"),
                    "origin": opened.passkey.get("origin"),
                    "rp_id": opened.passkey.get("rp_id"),
                    "alg": opened.passkey.get("alg"),
                    "user_handle": opened.passkey.get("user_handle"),
                    "sign_count": opened.passkey.get("sign_count"),
                    "created_at": opened.passkey.get("created_at"),
                }
                if opened.passkey
                else None
            ),
            "meta": dict(opened.meta),
        }
    )
    return summary
