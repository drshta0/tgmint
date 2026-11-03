"""tgmint.heal — session repair with the passkey.

A session that the server has logged out is normally dead: the auth key is
gone, and nothing local can bring it back.  The one exception is a session
whose account has a **tgmint software passkey** (:mod:`tgmint.passkeys`):
the passkey can sign in again with no phone number and no OTP, and the
result is a *new* auth key for the same account.  This module does exactly
that and nothing else:

1. read the session (any codec source format, including a `.tgmint`
   envelope),
2. probe liveness cheaply (one ``get_me`` on the stored auth key),
3. if the server still accepts the auth key: report and **touch nothing**,
4. if it does not: sign in with the passkey on a client minted from the
   *recorded* fingerprint (the session's sidecar, or the envelope's
   fingerprint; a fresh minted identity when neither exists),
5. rewrite the session **atomically** with the fresh auth key — in
   place when the format stays the same, into ``out`` when it does not
   (converting in place would destroy the original format while the file
   name kept claiming it),
6. report old -> new ``user_id`` and ``dc_id``, the placeholders the
   destination format had to fill (777000 / 2040) and any notes.

Guardrails (deliberate, not configurable)
-----------------------------------------

* **one account, one session per invocation** — there is no batch mode,
  no ``--all``, no glob and no daemon loop.  "Heal every session in this
  folder" is exactly the dangerous feature this design refuses.
* **no in-place format change** — ``to_format`` different from the
  source format requires ``out``: the original session must survive a
  conversion, and its extension must keep telling the truth.
* **no overwriting a session that moved under us** — the file is
  snapshotted before the read and re-checked before the write; anything
  else writing that session in the read->login->write window makes the
  heal refuse instead of silently discarding that change.
* **no blind re-login** — without ``live=True`` the probe never runs, and
  the caller must say ``force=True`` explicitly to re-login anyway.  A
  probe that fails for a *network* reason (not an auth rejection) also
  refuses unless ``force=True``: "the wifi is down" is not "the session is
  dead".
* **the same account** — the passkey store encodes ``dc:user`` in its
  ``user_handle``; when the session's ``user_id`` is known and differs,
  this refuses rather than swapping one account's session for another's.
* **no crypto duplicated here** — the ceremony is
  :func:`tgmint.passkeys.login_with_passkey`, the read/write is
  :mod:`tgmint.codec` (plus :mod:`tgmint.profile` for envelopes).

Verification status
-------------------

* **Verified offline** (``tests/test_heal.py``): every decision this
  module makes is exercised against a fake client and a fake login —
  alive -> no-op with the session file byte-identical, dead auth key ->
  rewrite with the fresh key in place (same path, same format, 0600,
  old key gone), probe failure and the missing ``--live``/``--force``
  pair -> refusals, passkey/session user mismatch -> refusal, `.tgmint`
  envelope repair keeping the fingerprint and passkey.  The Telethon
  client, the passkey ceremony and the network are injected or mocked in
  all of them; none of these tests opens a socket.
* **NOT verified offline**: the live probe against real Telegram, the
  real passkey login, and therefore the end-to-end "this dead session
  really came back to life".  That needs a live account with a registered
  tgmint passkey, and is documented as manually testable only.  The
  probe's error classification is also a best-effort name/class match
  (Telegram can add auth error constructors); a novel error is treated as
  "unknown", which refuses to heal unless forced.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import os
import shutil
import stat
import tempfile
import typing
from pathlib import Path

from . import codec
from .codec.data import CodecError, SessionData
from .fingerprint import Fingerprint

__all__ = [
    "DEFAULT_PRESETS",
    "HealError",
    "HealRefusal",
    "probe_session",
    "make_client",
    "heal_session",
    "write_session_atomically",
]

#: which ``--api-preset`` name maps to which official family.  Mirrors the
#: CLI's table; only used when no fingerprint was recorded for the session.
DEFAULT_PRESETS: typing.Dict[str, str] = {
    "desktop": "TelegramDesktop",
    "android": "TelegramAndroid",
    "android-x": "TelegramAndroidX",
    "ios": "TelegramIOS",
    "macos": "TelegramMacOS",
}

#: formats ``heal_session`` can rewrite in place (single-file formats; a
#: tdata folder is a directory tree and has no atomic swap here)
_HEAL_TARGETS = (
    "telethon-session",
    "telethon-string",
    "pyrogram-session",
    "pyrogram-string",
    "gramjs-string",
)

#: Telethon error classes that mean "the server no longer accepts this
#: auth key".  Matched by class *and* by class name, so a fake client in a
#: test (or a future telethon that renames one) is still classified right.
_DEAD_AUTH_NAMES = frozenset(
    {
        "AuthKeyUnregisteredError",
        "AuthKeyInvalidError",
        "AuthKeyPermEmptyError",
        "AuthKeyDuplicatedError",
        "SessionRevokedError",
        "SessionExpiredError",
        "UserDeactivatedError",
        "UserDeactivatedBanError",
    }
)


class HealError(ValueError):
    """A heal request that this module refuses or cannot complete.

    Subclasses :class:`ValueError`.  :class:`HealRefusal` is the subset the
    caller can fix by changing the invocation (missing ``--live``/
    ``--force``, another account's passkey, an impossible target format);
    the CLI maps a refusal to exit 2 and a plain *HealError* to exit 1.
    """


class HealRefusal(HealError):
    """A usage-shaped refusal: the request, not the account, is the problem."""


# ---------------------------------------------------------------------------
# seams (patched by the offline tests, mocked by nobody else)
# ---------------------------------------------------------------------------


def _dead_auth_errors() -> typing.Tuple[type, ...]:
    """Telethon's "auth key is gone" error classes, when telethon is here."""
    try:
        from telethon import errors
    except ImportError:  # pragma: no cover - telethon is a hard dependency
        return ()
    found = []
    for name in _DEAD_AUTH_NAMES:
        klass = getattr(errors, name, None)
        if isinstance(klass, type):
            found.append(klass)
    return tuple(found)


def is_dead_auth_error(exc: BaseException) -> bool:
    """True when ``exc`` means the server rejected the stored auth key."""
    classes = _dead_auth_errors()
    if classes and isinstance(exc, classes):
        return True
    for klass in type(exc).__mro__:
        if klass.__name__ in _DEAD_AUTH_NAMES:
            return True
    return False


async def probe_session(client) -> typing.Dict[str, typing.Any]:
    """Cheap liveness probe for one stored authorization.

    Connects the client (telethon's ``connect`` is idempotent) and asks for
    the logged-in user — the smallest round trip that proves the auth key
    is still accepted.  Never raises for a *classified* outcome; the
    result is a plain dict so the caller (and the tests) can read it::

        {"performed": True, "alive": True | False | None,
         "dead": bool, "reason": str, "user_id": int | None}

    ``alive=None`` means "the probe could not tell" (a network or protocol
    error, not an auth rejection) — the caller must not heal on that
    without an explicit force.
    """
    try:
        connect = getattr(client, "connect", None)
        if connect is not None:
            outcome = connect()
            if inspect.isawaitable(outcome):
                await outcome
        me = await client.get_me()
    except Exception as exc:
        if is_dead_auth_error(exc):
            return {
                "performed": True,
                "alive": False,
                "dead": True,
                "reason": (
                    "the server rejected the stored auth key "
                    f"({type(exc).__name__}: {exc})"
                ),
                "user_id": None,
            }
        return {
            "performed": True,
            "alive": None,
            "dead": False,
            "reason": f"the liveness probe failed for a non-auth reason ({type(exc).__name__}: {exc})",
            "user_id": None,
        }
    return {
        "performed": True,
        "alive": True,
        "dead": False,
        "reason": "the server accepted the stored auth key",
        "user_id": getattr(me, "id", None),
    }


def make_client(*, kind: str, api, data: typing.Optional[SessionData] = None):
    """Build the Telethon client a heal step needs.

    Seam, not API: the tests replace it with a fake, which is the only way
    to exercise the flow without a live account.

    Args:
        kind: ``"probe"`` builds a client on the *stored* auth key (a
            throwaway ``StringSession``, so the user's file is never
            opened by the probe); ``"login"`` builds a fresh client in a
            private temp directory for the passkey sign-in.
        api: the minted/recorded ``APIData`` (or a Fingerprint-backed
            equivalent) the client presents.
        data: the stored authorization, for ``kind="probe"``.
    """
    from telethon.sessions import StringSession

    from . import tl as tgmint_tl

    if kind == "probe":
        if data is None:
            raise HealError("a probe client needs the stored session data")
        return tgmint_tl.TelegramClient(
            StringSession(codec.telethon.write_string(data)), api=api
        )
    if kind == "login":
        tmpdir = tempfile.mkdtemp(prefix="tgmint-heal-")
        client = tgmint_tl.TelegramClient(
            os.path.join(tmpdir, "heal.session"), api=api
        )
        # remembered so the caller can remove the private temp session
        client._tgmint_tmpdir = tmpdir
        return client
    raise HealError(f"unknown client kind {kind!r}; expected 'probe' or 'login'")


async def _default_login(client, *, passkey_path: str, password: typing.Optional[str]):
    """The real passkey sign-in (reused, never reimplemented)."""
    from .passkeys import login_with_passkey

    return await login_with_passkey(client, path=passkey_path, password=password)


def _mint_api(preset: str):
    """Mint an ``APIData`` for ``preset`` (used when nothing was recorded)."""
    from .api import API

    name = DEFAULT_PRESETS.get(preset)
    if name is None:
        raise HealRefusal(
            f"unknown api preset {preset!r}; expected one of "
            f"{sorted(DEFAULT_PRESETS)}"
        )
    return getattr(API, name).Generate()


def _api_from_fingerprint(fingerprint: Fingerprint):
    """An ``APIData`` carrying the recorded identity (so the new session
    is born with the same device/app identity the old one used)."""
    from .api import APIData

    api = APIData(
        fingerprint.api_id,
        fingerprint.api_hash,
        device_model=fingerprint.device_model,
        system_version=fingerprint.system_version,
        app_version=fingerprint.app_version,
        lang_code=fingerprint.lang_code,
        system_lang_code=fingerprint.system_lang_code,
        lang_pack=fingerprint.lang_pack,
    )
    api.tz_zone = fingerprint.tz_zone
    return api


# ---------------------------------------------------------------------------
# reading and writing
# ---------------------------------------------------------------------------


def _load_source(
    session_path: str,
    session_format: str,
    passphrase: typing.Optional[str],
) -> typing.Tuple[SessionData, typing.Optional[typing.Any], typing.Dict[str, typing.Any]]:
    """Read the session under repair -> (session, opened-profile, notes)."""
    notes: typing.List[str] = []
    if session_format == "profile":
        from .profile import open_profile

        opened = open_profile(session_path, passphrase=passphrase)
        return opened.session, opened, notes
    if session_format == "tdata":
        notes.append(
            "tdata folders are read for the probe but healed by --to-format "
            "to a single-file format"
        )
    return (
        codec.read_session(session_path, session_format, passphrase=passphrase),
        None,
        notes,
    )


def _recorded_fingerprint(
    session_path: str,
    session_format: str,
    opened_profile: typing.Optional[typing.Any],
) -> typing.Tuple[typing.Optional[Fingerprint], typing.Optional[str]]:
    """The identity to present again: envelope > sidecar > nothing.

    Returns ``(fingerprint, where_it_came_from)``.
    """
    if opened_profile is not None and opened_profile.fingerprint is not None:
        return opened_profile.fingerprint, str(session_path)
    try:
        from .sidecar import sidecar_path_for
    except ImportError:  # pragma: no cover - sidecar is part of the package
        return None, None
    sidecar = sidecar_path_for(session_path)
    try:
        if os.path.isfile(str(sidecar)):
            return Fingerprint.load(str(sidecar)), str(sidecar)
    except (ValueError, OSError):
        return None, None
    return None, None


def _passkey_store_user(passkey_path: str) -> typing.Optional[int]:
    """The account a passkey file belongs to, from its ``dc:user`` handle."""
    try:
        from .passkeys_core import PasskeyError, PasskeyStore
    except ImportError as exc:  # pragma: no cover - defensive
        raise HealError(f"the passkey layer is unavailable ({exc})") from None
    try:
        store = PasskeyStore.load(passkey_path)
    except (PasskeyError, ValueError, KeyError, TypeError, OSError) as exc:
        raise HealError(f"--passkey {passkey_path}: not a usable passkey store ({exc})") from None
    return store.user_id


def _refuse_symlink(path: typing.Union[str, "os.PathLike[str]"], what: str) -> None:
    """Refuse a symlinked session path, like ``profile.write_profile`` does.

    ``os.replace`` onto a symlink replaces the *link*, leaving the file it
    points at untouched — a heal through one would report success while
    the real session kept its dead auth key.  Refusing (rather than
    silently resolving) is the safer half of the choice: the operator
    named a path, and a link is not the file.
    """
    target = Path(path)
    if target.is_symlink():
        raise HealRefusal(
            f"{what} {target} is a symlink — rewriting it would replace the "
            "link, not the session it points at, so nothing would really be "
            "healed; point at the real file (or move the link away) and re-run"
        )


def _file_snapshot(path: str) -> typing.Optional[typing.Tuple[int, int, str]]:
    """``(size, mtime_ns, sha256)`` of a regular file, else ``None``."""
    try:
        info = os.stat(path)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    try:
        with open(path, "rb") as fp:
            digest = hashlib.sha256(fp.read()).hexdigest()
    except OSError:
        return None
    return (info.st_size, info.st_mtime_ns, digest)


def _require_unchanged(
    path: str, snapshot: typing.Optional[typing.Tuple[int, int, str]]
) -> None:
    """Refuse to overwrite a session that changed during the read→write window.

    Between reading the session, probing it and signing in again, seconds
    (or minutes) pass.  If something rewrote the file meanwhile — a live
    client saving it, the operator, another tool — overwriting it would
    throw that change away, so the heal refuses instead.
    """
    if snapshot is None:
        return
    current = _file_snapshot(path)
    if current is None:
        raise HealRefusal(
            f"{path}: the session changed while heal was working (it is no "
            "longer a readable regular file with the bytes that were read); "
            "refusing to overwrite it — re-run"
        )
    if current != snapshot:
        raise HealRefusal(
            f"{path}: the session changed while heal was working "
            f"(read {snapshot[0]} bytes with sha256 {snapshot[2][:12]}…, it "
            f"now has {current[0]} bytes with sha256 {current[2][:12]}…); "
            "refusing to overwrite a file that was touched in the meantime — "
            "re-run when nothing else is writing that session"
        )


def write_session_atomically(
    data: SessionData, path: str, destination_format: str
) -> str:
    """Write ``data`` over ``path`` atomically, keeping mode 0600.

    Returns the path written.  The full write result (what the codec
    reported, including the ``filled`` placeholders and their ``notes``)
    comes from :func:`_write_session_atomically`; this public wrapper
    keeps the path-only return the tests and earlier callers used.
    """
    return _write_session_atomically(data, path, destination_format)["output"]


def _write_session_atomically(
    data: SessionData, path: str, destination_format: str
) -> typing.Dict[str, typing.Any]:
    """Like :func:`write_session_atomically`, returning the write result.

    The codec writers never overwrite (that is right for ``convert``), so
    this writes a private temp file *next to the target* and then
    ``os.replace``s it into place — the target is therefore either the old
    session or the new one, never a half-written file.  The temp file is
    removed on failure.  A symlinked target is refused outright.

    The result is the codec's own dict with ``output`` pointing at the
    real target: it carries ``filled`` / ``notes`` when the destination
    format needed a placeholder (777000/2040), so callers can report the
    placeholder honestly instead of guessing.
    """
    if destination_format == "tdata":
        raise HealRefusal(
            "heal rewrites single-file sessions only: a tdata folder has no "
            "atomic swap here — pass --to-format telethon-string (or another "
            "file format) and convert to tdata afterwards with `tgmint convert`"
        )
    if destination_format not in _HEAL_TARGETS:
        raise HealRefusal(
            f"cannot heal into {destination_format!r}; expected one of "
            f"{list(_HEAL_TARGETS)}"
        )
    _refuse_symlink(path, "the session path")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(
        prefix=".tgmint-heal-", suffix=".tmp", dir=target.parent
    )
    os.close(fd)
    temporary = Path(name)
    temporary.unlink()  # reserve the name, let the codec writer create it
    try:
        result = codec.write_session(
            data,
            str(temporary),
            destination_format,
            user_id=data.user_id,
            api_id=data.api_id,
        )
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    result["output"] = str(target)
    return result


def _write_profile_atomically(
    session: SessionData,
    path: str,
    opened_profile: typing.Any,
    passphrase: typing.Optional[str],
    note: str,
) -> typing.Tuple[str, typing.Optional[str]]:
    """Rewrite a ``.tgmint`` envelope in place with the fresh session.

    Returns ``(path, downgraded_from)`` — ``downgraded_from`` is set when
    the recorded session format could not represent the fresh
    authorization (a Pyrogram string needs a ``user_id`` the login could
    not report) and the payload was written as its Telethon string
    instead.  A symlinked target is refused, exactly like
    :func:`write_session_atomically` and ``profile.write_profile``.
    """
    from .profile import ProfileError, seal, write_profile

    _refuse_symlink(path, "the profile path")
    recorded = opened_profile.session_format or "telethon-string"
    downgraded: typing.Optional[str] = None
    try:
        container = seal(
            session,
            recorded,
            fingerprint=opened_profile.fingerprint,
            passkey=opened_profile.passkey,
            passphrase=passphrase if opened_profile.sealed else None,
            note=note,
        )
    except ProfileError:
        downgraded = recorded
        container = seal(
            session,
            "telethon-string",
            fingerprint=opened_profile.fingerprint,
            passkey=opened_profile.passkey,
            passphrase=passphrase if opened_profile.sealed else None,
            note=note,
        )
    target = Path(path)
    fd, name = tempfile.mkstemp(
        prefix=".tgmint-heal-", suffix=".tmp", dir=target.parent
    )
    os.close(fd)
    Path(name).unlink(missing_ok=True)  # write_profile publishes exclusively
    try:
        write_profile(container, name)
        os.chmod(name, 0o600)
        os.replace(name, target)
    finally:
        Path(name).unlink(missing_ok=True)
    return str(target), downgraded


def _session_from_client(client, user_id: typing.Optional[int]) -> SessionData:
    """The authorization a freshly logged-in client holds."""
    session = client.session
    auth_key = getattr(session, "auth_key", None)
    key = getattr(auth_key, "key", auth_key)
    if not isinstance(key, bytes) or len(key) != 256:
        raise HealError(
            "the passkey login produced no usable auth key (the client "
            "session was not authorized?)"
        )
    dc_id = getattr(session, "dc_id", None)
    if not isinstance(dc_id, int):
        raise HealError("the passkey login produced no dc_id")
    return SessionData(
        dc_id=dc_id,
        auth_key=key,
        user_id=user_id,
    )


# ---------------------------------------------------------------------------
# the flow
# ---------------------------------------------------------------------------


async def _close(client) -> None:
    """Disconnect, and drop the private temp session a login client used."""
    disconnect = getattr(client, "disconnect", None)
    if disconnect is not None:
        try:
            outcome = disconnect()
            if inspect.isawaitable(outcome):
                await outcome
        except Exception:
            pass
    tmpdir = getattr(client, "_tgmint_tmpdir", None)
    if tmpdir:
        shutil.rmtree(tmpdir, ignore_errors=True)


async def heal_session(
    session_path: str,
    *,
    passkey_path: str,
    session_format: typing.Optional[str] = None,
    to_format: typing.Optional[str] = None,
    out: typing.Optional[str] = None,
    api_preset: str = "desktop",
    passphrase: typing.Optional[str] = None,
    password: typing.Optional[str] = None,
    live: bool = False,
    force: bool = False,
    probe=None,
    client_factory=None,
    login=None,
) -> typing.Dict[str, typing.Any]:
    """Repair one session with the passkey that can sign back into it.

    Library entrypoint behind ``tgmint heal``.

    Args:
        session_path: the session file (or ``.tgmint`` envelope) to repair.
        passkey_path: the passkey store that signs back in.
        session_format: codec source format; ``None`` infers it from the
            path (``.tgmint`` -> ``profile``, else ``telethon-session``).
        to_format: format to rewrite in; defaults to ``session_format``
            (a ``profile`` source is rewritten as a profile, so the
            envelope keeps its fingerprint and passkey).
        out: where to write the healed session.  ``None`` means "in place,
            same format" — the only in-place rewrite this module does.
            Required as soon as ``to_format`` differs from the source
            format: converting in place would destroy the original while
            the file name kept claiming the old format.
        api_preset: identity to mint when neither an envelope nor a
            sidecar recorded one.
        passphrase: passphrase of a sealed envelope (read and rewrite).
        password: the account's 2FA cloud password, when it has one.
        live: run the liveness probe.  Without it nothing is probed and
            healing needs ``force=True``.
        force: re-login even when the probe is unavailable or inconclusive
            (never overrides "the session is alive" — that always no-ops).
        probe / client_factory / login: injection seams for the offline
            tests; production callers leave them ``None``.

    Returns:
        a JSON-friendly report: ``action`` (``"noop"`` or ``"healed"``),
        ``probe``, ``old`` / ``new`` (``user_id`` + ``dc_id``),
        ``auth_key_changed``, the format pair, ``output`` / ``in_place``,
        the identity source, ``filled`` (placeholders the destination
        format needed) and any ``notes``.

    Raises:
        FileNotFoundError: the session or the passkey file does not exist.
        CodecError: the session cannot be read (including profile
            cross-validation failures).
        HealError: a refusal (no live probe and no force, another account's
            passkey, an unclassifiable probe result without force, a
            symlinked session, a format change without ``out``, a session
            that changed under us) or a runtime failure (login failed,
            unwritable target).
    """
    path = str(session_path)
    fmt = session_format or codec.infer_source_format(path)
    if fmt in codec.PROFILE_FORMATS:
        fmt = "profile"
    target_format = to_format or fmt
    probe_fn = probe or probe_session
    client_factory = client_factory or make_client
    login_fn = login or _default_login
    notes: typing.List[str] = []

    if not os.path.exists(path):
        raise FileNotFoundError(f"Session does not exist: {path}")
    if not os.path.exists(passkey_path):
        raise FileNotFoundError(f"--passkey {passkey_path}: no such file")

    # --- where the result lands (and the refusals about it)
    _refuse_symlink(path, "the session")
    target_path = str(out) if out else path
    in_place = os.path.abspath(target_path) == os.path.abspath(path)
    if in_place:
        if target_format != fmt:
            raise HealRefusal(
                f"--to-format {target_format} differs from the source format "
                f"{fmt}: rewriting it in place would destroy the original "
                f"{fmt} session while the file kept its name; pass --out PATH "
                "so the converted session lands in a new file (in-place heal "
                "is same-format only)"
            )
    else:
        _refuse_symlink(target_path, "--out")
        if os.path.exists(target_path) or os.path.islink(target_path):
            raise HealRefusal(
                f"--out {target_path}: already exists — refusing to overwrite "
                "it; pick a new path or move the old one away"
            )

    # the read→login→write window is long: remember what the file looked
    # like so the final write can refuse if someone changed it meanwhile
    baseline = _file_snapshot(path) if in_place else None

    session, opened_profile, load_notes = _load_source(path, fmt, passphrase)
    notes.extend(load_notes)

    # --- guardrail: the passkey must belong to the session's account
    passkey_user = _passkey_store_user(passkey_path)
    if session.user_id is not None and passkey_user is not None:
        if int(session.user_id) != int(passkey_user):
            raise HealRefusal(
                f"the session belongs to user_id {int(session.user_id)} but "
                f"the passkey belongs to user_id {int(passkey_user)} — this "
                "command heals one account with its own passkey, it does not "
                "swap accounts"
            )

    fingerprint, identity_source = _recorded_fingerprint(path, fmt, opened_profile)

    # --- decision: probe, or refuse, or (force) go straight to the login
    if not live and not force:
        raise HealRefusal(
            "refusing to re-login without checking anything: pass --live to "
            "probe the session first, or --force to heal it anyway"
        )

    probe_report: typing.Dict[str, typing.Any] = {
        "performed": False,
        "alive": None,
        "dead": False,
        "reason": "not probed (--force without --live)",
        "user_id": None,
    }
    old = {"user_id": session.user_id, "dc_id": session.dc_id}

    if live:
        probe_client = client_factory(
            kind="probe", api=_identity_api(fingerprint, api_preset), data=session
        )
        try:
            probe_report = await probe_fn(probe_client)
        finally:
            await _close(probe_client)
        if probe_report.get("alive") is True:
            return {
                "ok": True,
                "action": "noop",
                "reason": (
                    "the session is alive; nothing was changed "
                    f"({probe_report.get('reason')})"
                ),
                "session": path,
                "session_format": fmt,
                "to_format": target_format,
                "output": None,
                "in_place": in_place,
                "filled": [],
                "probe": probe_report,
                "passkey": str(passkey_path),
                "identity": {
                    "source": "recorded" if fingerprint else "minted",
                    "path": identity_source,
                },
                "old": old,
                "new": dict(old),
                "auth_key_changed": False,
                "notes": notes,
            }
        if probe_report.get("alive") is None and not force:
            raise HealRefusal(
                "the liveness probe could not decide whether the session is "
                f"alive ({probe_report.get('reason')}); refusing to re-login "
                "blindly — fix the connection and re-run, or pass --force"
            )

    # --- heal: sign in with the passkey on a fresh client
    api = _identity_api(fingerprint, api_preset)
    login_client = client_factory(kind="login", api=api, data=None)
    try:
        connect = getattr(login_client, "connect", None)
        if connect is not None:
            outcome = connect()
            if inspect.isawaitable(outcome):
                await outcome
        me = await login_fn(
            login_client, passkey_path=str(passkey_path), password=password
        )
        new_user_id = getattr(me, "id", None)
        if new_user_id is None:
            new_user_id = passkey_user
        if (
            passkey_user is not None
            and new_user_id is not None
            and int(passkey_user) != int(new_user_id)
        ):
            raise HealError(
                f"the passkey logged in as user_id {int(new_user_id)}, but "
                f"the store says it belongs to user_id {int(passkey_user)}; "
                "refusing to write a session for the wrong account"
            )
        # the fresh authorization, read while the client still holds it
        fresh = _session_from_client(login_client, new_user_id)
    except HealError:
        raise
    except Exception as exc:
        raise HealError(f"the passkey login failed: {exc}") from None
    finally:
        await _close(login_client)

    fresh = fresh._replace(api_id=getattr(api, "api_id", None))
    auth_key_changed = fresh.auth_key != session.auth_key

    # --- the write: refuse if the file moved under us, then rewrite it
    if in_place:
        _require_unchanged(path, baseline)

    note = f"healed {old['user_id']} on {old['dc_id']} at {_now_iso()}"
    filled: typing.List[str] = []
    if target_format == "profile":
        if opened_profile is None:
            raise HealRefusal(
                f"--to-format profile rebuilds an envelope, but {path} is not "
                "one; run `tgmint profile seal` to create the envelope"
            )
        written, downgraded = _write_profile_atomically(
            fresh, target_path, opened_profile, passphrase, note
        )
        written_user_id = fresh.user_id
        if downgraded:
            notes.append(
                f"the recorded {downgraded} session format could not carry "
                "the fresh authorization; the envelope now stores its "
                "telethon string"
            )
    else:
        written_result = _write_session_atomically(fresh, target_path, target_format)
        written = written_result["output"]
        # the codec's own placeholders (777000 / 2040) are reported here
        # instead of being silently dropped: the file holds what it says
        filled = list(written_result.get("filled") or ())
        notes.extend(written_result.get("notes") or ())
        written_user_id = written_result.get("user_id")
        if written_user_id is None:
            written_user_id = fresh.user_id

    new = {"user_id": written_user_id, "dc_id": fresh.dc_id}
    if "user_id" in filled:
        new["user_id_is_placeholder"] = True

    return {
        "ok": True,
        "action": "healed",
        "reason": "the passkey signed in and the session was rewritten",
        "session": path,
        "session_format": fmt,
        "to_format": target_format,
        "output": written,
        "in_place": in_place,
        "filled": filled,
        "probe": probe_report,
        "passkey": str(passkey_path),
        "identity": {
            "source": "recorded" if fingerprint else "minted",
            "path": identity_source,
        },
        "old": old,
        "new": new,
        "auth_key_changed": auth_key_changed,
        "notes": notes,
    }


def _identity_api(fingerprint: typing.Optional[Fingerprint], api_preset: str):
    """The APIData both clients present: recorded identity, else minted."""
    if fingerprint is not None:
        return _api_from_fingerprint(fingerprint)
    return _mint_api(api_preset)


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def heal_session_sync(*args, **kwargs) -> typing.Dict[str, typing.Any]:
    """Run :func:`heal_session` from synchronous code (the CLI).

    A separate name on purpose: importing ``tgmint.heal`` must not create
    an event loop, and an embedding application that already runs one
    should call the coroutine itself.
    """
    return asyncio.run(heal_session(*args, **kwargs))
