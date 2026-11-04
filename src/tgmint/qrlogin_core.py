"""Framework-neutral QR login: the Telegram ceremony as a state machine.

This module is the QR-login sibling of :mod:`tgmint.passkeys_core`: the TL
wire spec as data, a neutral writer/reader, and the ceremony as a state
machine whose every network byte goes through a tiny duck-typed *invoker* —
so the thin per-framework drivers (:mod:`tgmint.qrlogin` for Telethon,
:mod:`tgmint.qrlogin_pyrogram` for the Pyrogram family) cannot get the
ordering rules wrong.

The wire format (verified against the generated TL layers of Telethon 1.45.0
and kurigram 2.2.26, both layer 229 — see ``tests/test_wire_golden.py``; the
schemas at https://core.telegram.org/schema and
https://corefork.telegram.org/schema agree)::

    auth.exportLoginToken#b7e085fe api_id:int api_hash:string
        except_ids:Vector<long> = auth.LoginToken;
    auth.importLoginToken#95ac5ce4 token:bytes = auth.LoginToken;
    auth.loginToken#629f1980 expires_in:int token:bytes = auth.LoginToken;
    auth.loginTokenMigrateTo#68e9916 dc_id:int token:bytes = auth.LoginToken;
    auth.loginTokenSuccess#390d5c5e authorization:auth.Authorization
        = auth.LoginToken;
    updateLoginToken#564fe691 = Update;

``auth.exportLoginToken`` answers ``auth.loginToken`` (a fresh token to
render as ``tg://login?token=<base64url>``), ``auth.loginTokenMigrateTo``
(the QR was confirmed by an account living on another DC: switch there,
then ``auth.importLoginToken``), or ``auth.loginTokenSuccess`` (confirmed,
same DC).  ``SESSION_PASSWORD_NEEDED`` from either request means the
account has a 2FA cloud password; the ceremony surfaces that as the typed
result :class:`QrPasswordNeeded` instead of prompting — prompting is the
driver's/CLI's job, exactly like the passkey ceremony's
:class:`tgmint.passkeys_core.TwoFactorRequired`.

QR login itself is not new (Telethon has ``client.qr_login``, kurigram has
``pyrogram.qrlogin``).  What tgmint adds is the shape: one framework-neutral
ceremony over an invoker, the same shared DC-switch/rollback
(:mod:`tgmint.dcswitch`) as the passkey login, and a minted official
fingerprint for the session this mints.

Nothing here imports ``telethon`` or a Pyrogram-family package — that is
the point.  ``cryptography`` is not needed either: the QR ceremony has no
local secret material.
"""
from __future__ import annotations

import base64
import dataclasses
import struct
import time
from typing import Any, Optional, Protocol
from collections.abc import Sequence

from .passkeys_core import (
    AuthorizationResult,
    PasskeyError,
    TLReader,
    TwoFactorRequired,
    _CTOR_AUTH_AUTHORIZATION,
    _CTOR_AUTH_SIGNUP_REQUIRED,
    _read_authorization,
    _require_int32,
    _serialize_tl_bytes,
    to_signed_int64,
)

__all__ = [
    "QRLOGIN_TL_SPEC",
    "QRLOGIN_MESSAGE_NAMES",
    "QrLoginError",
    "QrLoginToken",
    "QrMigrateTo",
    "QrSuccess",
    "QrPasswordNeeded",
    "QrLoginMachine",
    "QrInvoker",
    "run_ceremony",
    "encode_request",
    "parse_login_token",
    "login_url",
]


class QrLoginError(PasskeyError):
    """A QR-login ceremony failure (bad fields, unexpected wire answer).

    Deliberately a :class:`tgmint.passkeys_core.PasskeyError` subclass: that
    is the neutral driver-error type the passkey ceremonies already use, so
    a caller guarding against corrupted state with ``except PasskeyError``
    is not surprised by the QR twin — while QR code can still catch its own
    type.  The 2FA signal is NOT an error and never lands here (see
    :class:`QrPasswordNeeded`).
    """


# --- TL constructor ids -----------------------------------------------------
#
# Single source for the whole QR stack. tests/test_wire_golden.py pins each
# of these against BOTH installed frameworks' generated classes, the way the
# passkey constructors are pinned (tests/test_passkeys_core.py).

_ctor_export_login_token = 0xB7E085FE
_ctor_import_login_token = 0x95AC5CE4
_ctor_login_token = 0x629F1980
_ctor_login_token_migrate_to = 0x068E9916
_ctor_login_token_success = 0x390D5C5E

#: The QR-login wire spec, the same shape as
#: :data:`tgmint.passkeys_core.PASSKEY_TL_SPEC` so ports and tooling can
#: consume either.  Plain JSON-serializable data (asserted in the tests).
QRLOGIN_TL_SPEC: dict[str, Any] = {
    "about": (
        "Telegram QR-login TL wire spec (TL layer 229, verified against the "
        "generated layers of Telethon 1.45.0 and kurigram 2.2.26). Scalar "
        "field types follow the passkey spec's conventions: 'int' int32, "
        "'long' int64, 'bytes'/'string' TL byte strings, 'vector<T>' the TL "
        "Vector constructor, or the name of an object/union defined below."
    ),
    "layer": 229,
    "constructors": {
        "auth.exportLoginToken": _ctor_export_login_token,
        "auth.importLoginToken": _ctor_import_login_token,
        "auth.loginToken": _ctor_login_token,
        "auth.loginTokenMigrateTo": _ctor_login_token_migrate_to,
        "auth.loginTokenSuccess": _ctor_login_token_success,
        # shared response objects (also in PASSKEY_TL_SPEC)
        "auth.authorization": _CTOR_AUTH_AUTHORIZATION,
        "auth.authorizationSignUpRequired": _CTOR_AUTH_SIGNUP_REQUIRED,
    },
    "objects": {
        "loginToken": {
            "tl_name": "auth.loginToken",
            "class": None,  # parsed straight into QrLoginToken
            "constructor": _ctor_login_token,
            "fields": [
                {"name": "expires_in", "type": "int"},
                {"name": "token", "type": "bytes"},
            ],
        },
        "loginTokenMigrateTo": {
            "tl_name": "auth.loginTokenMigrateTo",
            "class": None,  # parsed straight into QrMigrateTo
            "constructor": _ctor_login_token_migrate_to,
            "fields": [
                {"name": "dc_id", "type": "int"},
                {"name": "token", "type": "bytes"},
            ],
        },
        "loginTokenSuccess": {
            "tl_name": "auth.loginTokenSuccess",
            "class": None,  # parsed straight into QrSuccess
            "constructor": _ctor_login_token_success,
            "fields": [
                {"name": "authorization", "type": "auth.Authorization"},
            ],
            # auth.Authorization parsing is reused from passkeys_core
            # (_read_authorization), which both ceremonies need byte-identical
        },
    },
    "messages": {
        "exportLoginToken": {
            "tl_name": "auth.exportLoginToken",
            "constructor": _ctor_export_login_token,
            "fields": [
                {"name": "api_id", "type": "int"},
                {"name": "api_hash", "type": "string"},
                {"name": "except_ids", "type": "vector<long>"},
            ],
            "result": {"kind": "login_token", "type": "auth.LoginToken"},
        },
        "importLoginToken": {
            "tl_name": "auth.importLoginToken",
            "constructor": _ctor_import_login_token,
            "fields": [{"name": "token", "type": "bytes"}],
            "result": {"kind": "login_token", "type": "auth.LoginToken"},
            "note": (
                "in practice the answer is auth.loginTokenSuccess (the "
                "authorization lives on the account's home DC, which is why "
                "the driver must complete auth.loginTokenMigrateTo first)"
            ),
        },
    },
}

QRLOGIN_MESSAGE_NAMES: tuple[str, ...] = tuple(QRLOGIN_TL_SPEC["messages"])

_MESSAGES = QRLOGIN_TL_SPEC["messages"]


def _resolve_message(name: str) -> tuple[str, dict[str, Any]]:
    """Message key by friendly or TL name (spec-validated)."""
    key = name if name in _MESSAGES else _normalize_key(name)
    if key is None:
        raise QrLoginError(
            f"unknown QR-login message {name!r}; expected one of "
            f"{list(_MESSAGES)}"
        )
    return key, _MESSAGES[key]


def _normalize_key(name: str) -> Optional[str]:
    """`auth.exportLoginToken` -> `exportLoginToken`."""
    short = name.rsplit(".", 1)[-1]
    for key in _MESSAGES:
        if key.lower() == short.lower() or _MESSAGES[key]["tl_name"] == name:
            return key
    return None


_VECTOR_LONG = 0x1CB5C415  # vector<T> constructor (ids as signed int64)


# ---------------------------------------------------------------------------
# Neutral writer: (message name, field dict) -> the exact wire bytes
# ---------------------------------------------------------------------------

def _require_int64(value: Any, *, what: str) -> int:
    """A TL ``long`` in its signed two's-complement spelling."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise QrLoginError(f"{what} must be an int, got {type(value)!r}")
    return to_signed_int64(value, what=what)


def encode_request(message_name: str, fields: Optional[dict[str, Any]] = None) -> bytes:
    """Serialize one QR-login request exactly as the wire wants it.

    ``exportLoginToken`` takes ``api_id`` (int32), ``api_hash`` (string) and
    ``except_ids`` (``vector<long>``, default empty — already-logged-in user
    ids the server should skip, which a single-account tool never sets).
    ``importLoginToken`` takes the raw ``token`` bytes.  Unknown or missing
    fields raise :class:`QrLoginError` naming them, so a driver cannot send
    a malformed ceremony step.  Byte-identical to the generated request
    classes of Telethon and the Pyrogram family (pinned in
    ``tests/test_wire_golden.py``).
    """
    key, spec = _resolve_message(message_name)
    payload = dict(fields or {})
    known = {f["name"] for f in spec["fields"]}
    unknown = sorted(set(payload) - known)
    if unknown:
        raise QrLoginError(f"{key}: unknown field(s) {unknown}")

    if key == "exportLoginToken":
        if "api_id" not in payload or "api_hash" not in payload:
            raise QrLoginError(
                "exportLoginToken needs api_id and api_hash (the fingerprint "
                "the new session is born with)"
            )
        api_id = _require_int32(payload["api_id"], what="api_id")
        api_hash = payload["api_hash"]
        if not isinstance(api_hash, str):
            raise QrLoginError(f"api_hash must be a str, got {type(api_hash)!r}")
        except_ids = payload.get("except_ids", [])
        if isinstance(except_ids, (str, bytes)) or not isinstance(
            except_ids, (list, tuple)
        ):
            raise QrLoginError(
                f"except_ids must be a sequence of ints, got {type(except_ids)!r}"
            )
        ids = [
            _require_int64(value, what=f"except_ids[{i}]")
            for i, value in enumerate(except_ids)
        ]
        return b"".join(
            (
                struct.pack("<I", _ctor_export_login_token),
                struct.pack("<i", api_id),
                _serialize_tl_bytes(api_hash),
                struct.pack("<I", _VECTOR_LONG),
                struct.pack("<i", len(ids)),
                b"".join(struct.pack("<q", value) for value in ids),
            )
        )

    # importLoginToken
    if "token" not in payload:
        raise QrLoginError("importLoginToken needs the token bytes")
    token = payload["token"]
    if isinstance(token, (bytearray, memoryview)):
        token = bytes(token)
    if not isinstance(token, bytes):
        raise QrLoginError(f"token must be bytes, got {type(token)!r}")
    return struct.pack("<I", _ctor_import_login_token) + _serialize_tl_bytes(token)


# ---------------------------------------------------------------------------
# Typed results (the state machine's states)
# ---------------------------------------------------------------------------

def login_url(token: bytes) -> str:
    """``tg://login?token=<base64url>`` — what the QR encodes.

    Standard urlsafe base64 without padding, byte-for-byte the URL Telethon's
    and kurigram's own QR helpers build (``telethon/tl/custom/qrlogin.py``,
    ``pyrogram/qrlogin.py``): opening it in an app where the account is
    logged in confirms this login.
    """
    if not isinstance(token, (bytes, bytearray)):
        raise QrLoginError(f"token must be bytes, got {type(token)!r}")
    encoded = base64.urlsafe_b64encode(bytes(token)).decode("ascii").rstrip("=")
    return f"tg://login?token={encoded}"


@dataclasses.dataclass(frozen=True)
class QrLoginToken:
    """``auth.loginToken`` — a fresh token: render it, then wait.

    ``expires_in`` is the server's seconds-from-now; the machine tracks the
    deadline itself (:meth:`QrLoginMachine.seconds_left`).
    """

    expires_in: int
    token: bytes

    @property
    def url(self) -> str:
        """The ``tg://login?token=...`` URL to encode into the QR."""
        return login_url(self.token)


@dataclasses.dataclass(frozen=True)
class QrMigrateTo:
    """``auth.loginTokenMigrateTo`` — confirmed, account lives on ``dc_id``.

    The driver must move the client to ``dc_id`` (with the shared snapshot/
    rollback from :mod:`tgmint.dcswitch`) and only then call
    :meth:`QrLoginMachine.import_token` with this object.
    """

    dc_id: int
    token: bytes


@dataclasses.dataclass(frozen=True)
class QrSuccess:
    """``auth.loginTokenSuccess`` — the login is authorized.

    ``authorization`` is the neutral
    :class:`tgmint.passkeys_core.AuthorizationResult` (user_id, sign_up_required,
    and the raw ``auth.Authorization`` bytes a framework's own TL layer can
    still read — the drivers need exactly that for their login bookkeeping).
    """

    authorization: AuthorizationResult


@dataclasses.dataclass(frozen=True)
class QrPasswordNeeded:
    """``SESSION_PASSWORD_NEEDED`` — the account has a 2FA cloud password.

    A typed result, not an exception and not a prompt: the ceremony stops
    here and the *driver* runs the framework's password step (Telethon
    ``client.sign_in(password=...)``, Pyrogram family
    ``client.check_password(...)``) — on the connection the ceremony ended
    on, which after a migrate is the account's home DC (a wrong password
    must stay retryable there, like in the passkey login).
    """

    stage: str
    """``"export"`` or ``"import"`` — which call was answered with the 2FA
    demand."""


# ---------------------------------------------------------------------------
# Neutral reader: response bytes -> the typed union member
# ---------------------------------------------------------------------------

def parse_login_token(payload: Any) -> Any:
    """Parse one ``auth.LoginToken`` answer into its typed union member.

    Returns :class:`QrLoginToken`, :class:`QrMigrateTo` or :class:`QrSuccess`;
    anything else on the wire raises :class:`QrLoginError` naming the
    constructor.  The embedded ``auth.Authorization`` is parsed by the same
    reader the passkey ceremony uses (``passkeys_core._read_authorization``),
    so the two ceremonies cannot disagree about that response.
    """
    reader = TLReader(payload)
    constructor = reader.read_uint()
    if constructor == _ctor_login_token:
        expires_in = reader.read_int()
        token = reader.read_bytes()
        if reader.remaining:
            raise QrLoginError(
                f"auth.loginToken: {reader.remaining} trailing byte(s) after "
                "the token"
            )
        return QrLoginToken(expires_in=expires_in, token=token)
    if constructor == _ctor_login_token_migrate_to:
        dc_id = reader.read_int()
        token = reader.read_bytes()
        if reader.remaining:
            raise QrLoginError(
                f"auth.loginTokenMigrateTo: {reader.remaining} trailing "
                "byte(s) after the token"
            )
        return QrMigrateTo(dc_id=dc_id, token=token)
    if constructor == _ctor_login_token_success:
        # the raw authorization bytes start right after the success header —
        # keep them whole so a driver can hand them to its own TL layer
        raw = reader.stream[reader.position:]
        return QrSuccess(authorization=_read_authorization(reader, raw))
    raise QrLoginError(
        f"unexpected constructor 0x{constructor:08x}, expected the "
        "auth.LoginToken union (auth.loginToken 0x629f1980, "
        "auth.loginTokenMigrateTo 0x068e9916, auth.loginTokenSuccess "
        "0x390d5c5e)"
    )


# ---------------------------------------------------------------------------
# The ceremony: a state machine over an invoker
# ---------------------------------------------------------------------------

class QrInvoker(Protocol):
    """The duck-typed driver contract (mirrors ``PasskeyInvoker``).

    Implement ONE of the two methods; the machine looks them up
    (``request_bytes`` first, then ``native``), never ``isinstance``-checks,
    so a driver imports nothing from this module.  Both methods send the
    message named by ``name`` with ``fields`` and must return the server's
    **response bytes** — a driver whose framework parses first re-serializes
    (``bytes(response)`` in Telethon, ``response.write()`` in the Pyrogram
    family); this module owns the parsing.
    """

    async def request_bytes(self, name: str, fields: dict[str, Any]) -> bytes:
        """Send ``name`` and return the server's raw response bytes."""
        ...

    async def native(self, name: str, fields: dict[str, Any]) -> Any:
        """Send ``name`` and return the response as bytes (see above)."""
        ...


def _resolve_invoker(invoker: Any) -> Any:
    """The invoker's callable, or a QrLoginError explaining the contract."""
    if invoker is None:
        raise QrLoginError(
            "a QR-login invoker is required: an object with an async "
            "request_bytes(name, fields) or native(name, fields) method "
            "returning the response bytes"
        )
    for method in ("request_bytes", "native"):
        call = getattr(invoker, method, None)
        if callable(call):
            return call
    raise QrLoginError(
        f"{type(invoker).__name__} is not a QR-login invoker: implement an "
        "async request_bytes(name, fields) -> bytes or native(name, fields) "
        "-> bytes"
    )


async def _invoke(invoker_call: Any, message_name: str, fields: dict[str, Any]) -> Any:
    """One ceremony step: validate the fields by encoding, invoke, parse.

    ``TwoFactorRequired`` (the neutral 2FA signal a driver raises when the
    framework reports ``SESSION_PASSWORD_NEEDED``) propagates unchanged —
    the public steps translate it into :class:`QrPasswordNeeded`.
    """
    key, _ = _resolve_message(message_name)
    encode_request(key, fields)  # validation: fails before any network byte
    value = await invoker_call(key, fields)
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise QrLoginError(
            f"{key}: the invoker must return the response bytes, got "
            f"{type(value).__name__} (a framework-parsed object is "
            "re-serialized by the driver: bytes(response) / response.write())"
        )
    return parse_login_token(bytes(value))


class QrLoginMachine:
    """The QR-login ceremony as a framework-neutral state machine.

    Drives ``auth.exportLoginToken`` / ``auth.importLoginToken`` through an
    invoker (:class:`QrInvoker`); the DC move a :class:`QrMigrateTo` demands
    is deliberately NOT here — it is framework I/O, so the driver does it
    with the shared :mod:`tgmint.dcswitch` helpers and then hands the
    migrate object back to :meth:`import_token`.

    Usage (what both drivers and the CLI do)::

        machine = QrLoginMachine(invoker, api_id=2040, api_hash="...")
        result = await machine.start()            # QrLoginToken -> render QR
        ...
        result = await machine.poll()             # after updateLoginToken
        result = await machine.refresh()          # after the token expired
        if isinstance(result, QrMigrateTo):
            ... switch DC (driver, snapshot first) ...
            result = await machine.import_token(result)

    Every step returns the typed union (:class:`QrLoginToken`,
    :class:`QrMigrateTo`, :class:`QrSuccess`) or :class:`QrPasswordNeeded`;
    nothing prompts and nothing switches DCs by itself.
    """

    def __init__(
        self,
        invoker: QrInvoker,
        *,
        api_id: int,
        api_hash: str,
        except_ids: Sequence[int] = (),
        clock: Any = time.monotonic,
    ):
        self.invoker = invoker
        """The driver object every step goes through (for driver bookkeeping)."""
        self._call = _resolve_invoker(invoker)
        self._export_fields: dict[str, Any] = {
            "api_id": _require_int32(api_id, what="api_id"),
            "api_hash": api_hash if isinstance(api_hash, str) else None,
            "except_ids": list(except_ids),
        }
        if not isinstance(self._export_fields["api_hash"], str):
            raise QrLoginError(f"api_hash must be a str, got {type(api_hash)!r}")
        # fail fast on bad ids / non-int entries, exactly like encode would
        encode_request("exportLoginToken", self._export_fields)
        self._clock = clock
        self.token: Optional[QrLoginToken] = None
        """The pending token (set by every export that answered with one)."""
        self.exports = 0
        """How many ``auth.exportLoginToken`` calls were made."""
        self.imports = 0
        """How many ``auth.importLoginToken`` calls were made."""
        self._expires_at: Optional[float] = None

    # -- the four steps ----------------------------------------------------

    async def start(self) -> Any:
        """Step 1: export the first token (the QR to render).

        Normally answers :class:`QrLoginToken`.  A connection that already
        carries a confirmed token can answer success/migrate immediately —
        every member of the union is returned as-is, so the caller's loop
        needs no special case.
        """
        return await self._step()

    async def refresh(self) -> Any:
        """Re-export after the token expired without a scan.

        The server mints a fresh token (the previous QR stops working).
        Same union return as :meth:`start`.
        """
        return await self._step()

    async def poll(self) -> Any:
        """Re-export after ``updateLoginToken`` arrived (QR confirmed).

        Answers :class:`QrMigrateTo` (switch DC, then
        :meth:`import_token`), :class:`QrSuccess`, or — when the
        confirmation was not visible yet — a fresh :class:`QrLoginToken` to
        re-render.
        """
        return await self._step()

    async def import_token(self, migrate: QrMigrateTo) -> Any:
        """``auth.importLoginToken`` — only after the driver moved the client.

        ``migrate`` is the :class:`QrMigrateTo` the export answered with; the
        caller must already be on ``migrate.dc_id`` (the driver's job, with
        :func:`tgmint.dcswitch.session_snapshot` taken first).  Answers
        :class:`QrSuccess` or :class:`QrPasswordNeeded`.
        """
        if not isinstance(migrate, QrMigrateTo):
            raise QrLoginError(
                f"import_token needs the QrMigrateTo the export answered "
                f"with, got {type(migrate).__name__}"
            )
        try:
            result = await _invoke(
                self._call, "importLoginToken", {"token": migrate.token}
            )
        except TwoFactorRequired:
            return QrPasswordNeeded(stage="import")
        if isinstance(result, QrLoginToken):
            raise QrLoginError(
                "auth.importLoginToken answered a fresh auth.loginToken — "
                "the migrate token was rejected; re-export and render a new "
                "QR"
            )
        if isinstance(result, QrMigrateTo):
            raise QrLoginError(
                "auth.importLoginToken answered another auth.loginTokenMigrateTo "
                f"(dc {result.dc_id}); the server disagrees about the home DC "
                "mid-ceremony — re-export and render a new QR"
            )
        self.imports += 1
        return result


    # -- expiry bookkeeping -------------------------------------------------

    def seconds_left(self, now: Optional[float] = None) -> Optional[float]:
        """Seconds until the pending token expires (``None`` without one).

        The clock is the constructor's ``clock`` (monotonic by default and
        injectable in tests); a token past its deadline reports ``<= 0``.
        """
        if self._expires_at is None:
            return None
        if now is None:
            now = self._clock()
        return self._expires_at - now

    @property
    def expired(self) -> bool:
        """Whether the pending token is past its server-side deadline."""
        left = self.seconds_left()
        return left is not None and left <= 0

    # -- internals ----------------------------------------------------------

    async def _step(self) -> Any:
        """One export step: invoke, track the token, translate 2FA."""
        try:
            result = await _invoke(
                self._call, "exportLoginToken", dict(self._export_fields)
            )
        except TwoFactorRequired:
            return QrPasswordNeeded(stage="export")
        if isinstance(result, QrLoginToken):
            self.token = result
            self._expires_at = self._clock() + result.expires_in
        self.exports += 1
        return result


async def run_ceremony(
    machine: QrLoginMachine,
    *,
    wait: Any,
    migrate: Any,
    finish_password: Any,
    complete: Any,
    password: Optional[str] = None,
    render: Any = None,
    timeout: Optional[float] = None,
    clock: Any = time.monotonic,
) -> Any:
    """Drive :class:`QrLoginMachine` through the full interactive ceremony.

    This is the loop both drivers' ``login_with_qr`` delegate to, so the
    policy lives once: render every fresh token, wait for the confirmation
    signal until the token's server-side deadline, refresh an expired
    unscanned token, hand :class:`QrMigrateTo` to the driver's DC move (the
    only framework I/O here), and finish the login.  Everything
    framework-bound arrives as a callable:

    * ``wait(timeout)`` — block until ``updateLoginToken`` (raises
      ``asyncio.TimeoutError``),
    * ``migrate(migrate_to)`` — switch DC with rollback, then
      :meth:`QrLoginMachine.import_token`; returns the next state,
    * ``finish_password(password)`` — the framework's 2FA completion
      (``sign_in(password=...)`` / ``check_password(...)``),
    * ``complete(success)`` — post-login bookkeeping; returns ``me``.

    ``render(token)`` displays a fresh token (sync or async; default prints
    the URL — the CLI passes the terminal QR renderer).  ``timeout`` is an
    overall budget in seconds; ``None`` keeps refreshing expired tokens
    until one is confirmed.  Returns whatever ``complete`` (or
    ``finish_password``) returns.

    A 2FA-protected account without a ``password`` raises
    :class:`tgmint.passkeys_core.TwoFactorRequired` (the same neutral signal
    the passkey ceremonies use, deliberately not a :class:`QrLoginError`)
    with the client left on the connection the ceremony ended on — after a
    migrate that is the account's home DC, where the password step belongs.
    """
    import asyncio

    async def _show(token: QrLoginToken) -> None:
        if render is None:
            print(token.url)
            return
        outcome = render(token)
        if asyncio.iscoroutine(outcome):
            await outcome

    started = clock()
    result = await machine.start()
    while True:
        if isinstance(result, QrLoginToken):
            await _show(result)
            left = machine.seconds_left()
            if timeout is not None:
                remaining = timeout - (clock() - started)
                if remaining <= 0:
                    raise asyncio.TimeoutError(
                        "timed out waiting for the QR to be scanned"
                    )
                left = remaining if left is None else min(left, remaining)
            try:
                await wait(left)
            except asyncio.TimeoutError:
                if machine.expired:
                    result = await machine.refresh()  # expired unscanned
                    continue
                raise
            result = await machine.poll()
            continue
        if isinstance(result, QrMigrateTo):
            result = await migrate(result)
            continue
        if isinstance(result, QrPasswordNeeded):
            if password is None:
                raise TwoFactorRequired(
                    "the account has a 2FA cloud password; complete the "
                    "login with the framework's password step on the "
                    "connection the ceremony ended on"
                )
            return await finish_password(password)
        if isinstance(result, QrSuccess):
            return await complete(result)
        raise QrLoginError(f"unexpected ceremony state {result!r}")
