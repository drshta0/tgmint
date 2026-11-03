"""
Software passkeys for Telegram accounts — the Telethon driver.

Register a passkey on an account for which you already hold an authorized
session, and later log back into that account with nothing but the passkey
(no phone number, no SMS/OTP). The passkey's private key is generated and
kept locally — Telegram only ever sees the public key and WebAuthn
signatures, exactly like a hardware key or password manager would produce.

Wire format implemented from the official Android client source
(DrKLO/Telegram 12.10.6, TL layer 230)::

    account.initPasskeyRegistration#429547e8 = account.PasskeyRegistrationOptions;
    account.registerPasskey#55b41fd6 credential:InputPasskeyCredential = Passkey;
    account.getPasskeys#ea1f0c52 = account.Passkeys;
    account.deletePasskey#f5b5563f id:string = Bool;
    auth.initPasskeyLogin#518ad0b7 api_id:int api_hash:string = auth.PasskeyLoginOptions;
    auth.finishPasskeyLogin#9857ad07
        flags:# credential:InputPasskeyCredential
        from_dc_id:flags.0?int from_auth_key_id:flags.0?long = auth.Authorization;

    inputPasskeyCredentialPublicKey#3c27b78f id:string raw_id:string
        response:InputPasskeyResponse = InputPasskeyCredential;
    inputPasskeyResponseRegister#3e63935c client_data:DataJSON attestation_data:bytes
        = InputPasskeyResponse;
    inputPasskeyResponseLogin#c31fc14a client_data:DataJSON authenticator_data:bytes
        signature:bytes user_handle:string = InputPasskeyResponse;
    account.passkey#98613ebf flags:# id:string name:string date:int
        software_emoji_id:flags.0?long last_usage_date:flags.1?int = Passkey;

What is in this module, and what is not
---------------------------------------

This module is a **thin Telethon driver** over the framework-neutral
:mod:`tgmint.passkeys_core`. The ceremony — which call comes first, when the
bumped signature counter must be persisted (before any network step after
it), when to switch DCs and with which ``from_dc_id``/``from_auth_key_id``,
what a ``SESSION_PASSWORD_NEEDED`` answer means — lives in the core, which is
shared with the Pyrogram-family driver (and with any other driver that
implements the same ``PasskeyInvoker`` contract). Reimplementing that state
machine per framework is exactly how the silent variants crept in.

So this file holds only what is genuinely Telethon-bound:

* the six hand-written request classes plus the three credential objects —
  Telethon 1.43.2's bundled TL layer predates these constructors, so they
  are declared here (their bytes are pinned against
  ``tgmint.passkeys_core.encode_request`` in ``tests/test_passkeys_core.py``);
* :class:`TelethonInvoker`, which builds those classes out of the field
  dicts the core's :data:`tgmint.passkeys_core.PASSKEY_TL_SPEC` describes,
  calls ``await client(request)`` and normalizes the answer back into the
  neutral shapes;
* the four public functions, which are one core call each.

The credential data layer (CBOR/COSE, :class:`SoftwareAuthenticator`,
:class:`PasskeyStore`, :class:`PasskeyInfo`, the error classes) is
*re-exported* from the core rather than copied, so both dialects share one
implementation — and one exception class, which matters for callers that
``except tgmint.passkeys.PasskeyError``: :class:`TelethonInvoker` translates
the server's ``PASSKEY_*``/``SESSION_*`` answers into that same
:class:`PasskeyError` (as the Pyrogram-family driver does), so one ``except``
clause covers both frameworks. The 2FA answer is the exception to that rule:
it becomes :class:`TwoFactorRequired` (also re-exported here), never a
:class:`PasskeyError`.

Typical use (while logged in)::

    from tgmint.passkeys import register_passkey
    info = await register_passkey(client, path="myaccount.passkey.json")

Later, with no phone/OTP access at all::

    client = TelegramClient("recovered.session", api=API.TelegramAndroid.Generate())
    await client.connect()
    me = await login_with_passkey(client, path="myaccount.passkey.json")

Requires ``cryptography`` (only when actually creating/signing credentials).

VERIFICATION LABELS
-------------------

* **TL request/response layer** — *verified offline*: every request class's
  bytes are compared byte for byte against the neutral writer, and every
  ``read_result`` has a neutral twin in ``passkeys_core.parse_result`` that
  is tested against the same payloads.
* **Credential + store layer** — the same code as before (now shared with the
  core): ``tests/test_passkeys.py`` parses our attestation object, rebuilds
  the COSE public key and verifies the ES256/Ed25519 assertion the way
  Telegram's server does, and checks the store file is 0600 and atomic.
* **Ceremony** — verified offline against a simulated server that checks the
  WebAuthn signature partner-side, including the counter-before-network
  ordering, the cross-DC handoff and the 2FA branch.
* **NOT verified here**: no live-account passkey round trip is performed by
  this repository; Telegram may change the layer or its origin/RP-ID policy
  at any time; the passkey flow needs an MTProto surface, so it can never
  work on the Bot API (TDLib has its own native passkey path).
"""
from __future__ import annotations

import re
import struct
from typing import Any, Dict, List, Optional, Tuple

from telethon import utils as tl_utils
from telethon.errors import RPCError, SessionPasswordNeededError
from telethon.extensions import BinaryReader
from telethon.tl.tlobject import TLObject, TLRequest

from . import passkeys_core as _core

__all__ = [
    "DEFAULT_ORIGIN",
    "ALG_ES256",
    "ALG_ED25519",
    "PasskeyInfo",
    "PasskeyStore",
    "PasskeyRejectedError",
    "TwoFactorRequired",
    "SoftwareAuthenticator",
    "CreatedCredential",
    "InitPasskeyRegistrationRequest",
    "RegisterPasskeyRequest",
    "GetPasskeysRequest",
    "DeletePasskeyRequest",
    "InitPasskeyLoginRequest",
    "FinishPasskeyLoginRequest",
    "InputPasskeyCredentialPublicKey",
    "InputPasskeyResponseRegister",
    "InputPasskeyResponseLogin",
    "TelethonInvoker",
    "register_passkey",
    "login_with_passkey",
    "list_passkeys",
    "delete_passkey",
]

# ---------------------------------------------------------------------------
# The data layer: one implementation, shared with the neutral core
# ---------------------------------------------------------------------------
#
# These names used to be defined here; they were copied into passkeys_core so
# a Telethon-free driver could use them. Keeping both copies meant two
# PasskeyError classes (so a caller catching one would not catch the other)
# and two PasskeyStore classes (so `isinstance` across the boundary was
# false). They are re-exported now: same public API, one implementation.

# The WebAuthn origin we claim in clientDataJSON. Telegram's server supplies
# the rpId in its options; the origin string must be one it accepts. The web
# client origin is the natural choice for a software authenticator. If the
# server ever rejects the challenge (origin not allowed), try
# "android:APK_CERT_HASH_BASE64URL:<b64url sha256 of official APK cert>".
DEFAULT_ORIGIN = _core.DEFAULT_ORIGIN

ALG_ES256 = _core.ALG_ES256   # ECDSA w/ SHA-256 on P-256, DER signature
ALG_ED25519 = _core.ALG_ED25519  # Ed25519, raw 64-byte signature

PasskeyError = _core.PasskeyError
PasskeyRejectedError = _core.PasskeyRejectedError
# the neutral 2FA signal login_with_passkey raises when no password was given
TwoFactorRequired = _core.TwoFactorRequired
PasskeyInfo = _core.PasskeyInfo
CreatedCredential = _core.CreatedCredential
SoftwareAuthenticator = _core.SoftwareAuthenticator
PasskeyStore = _core.PasskeyStore

# helper spellings this module used to define (tests and downstream code
# import some of them from here; they are the very same functions now)
_b64u_encode = _core._b64u_encode
_b64u_decode = _core._b64u_decode
_cbor_encode = _core._cbor_encode
_dump_json = _core._dump_json
_sha256 = _core._sha256
_SUPPORTED_ALGS = _core._SUPPORTED_ALGS
_USER_HANDLE_RE = _core._USER_HANDLE_RE


def _pack_uint32(value: int) -> bytes:
    return struct.pack("<I", value)


# ---------------------------------------------------------------------------
# Telegram TL layer (custom requests — not yet in Telethon's bundled layer)
# ---------------------------------------------------------------------------

_CTOR_DATAJSON = 0x7D748D04
_CTOR_PASSKEY = 0x98613EBF
_CTOR_ACCOUNT_PASSKEYS = 0xF8E0AA1C
_CTOR_ACCOUNT_PASSKEY_REGISTRATION_OPTIONS = 0xE16B5CE1
_CTOR_AUTH_PASSKEY_LOGIN_OPTIONS = 0xE2037789
_CTOR_INPUT_CRED_PUBLIC_KEY = 0x3C27B78F
_CTOR_INPUT_RESPONSE_REGISTER = 0x3E63935C
_CTOR_INPUT_RESPONSE_LOGIN = 0xC31FC14A
_CTOR_BOOL_TRUE = 0x997275B5
_CTOR_BOOL_FALSE = 0xBC799737
_CTOR_VECTOR = 0x1CB5C415


def _read_passkey(reader: BinaryReader) -> PasskeyInfo:
    if reader.read_int(signed=False) != _CTOR_PASSKEY:
        raise PasskeyError("unexpected constructor, expected account.passkey")
    flags = reader.read_int(signed=False)
    info = PasskeyInfo(
        id=reader.tgread_string(),
        name=reader.tgread_string(),
        date=reader.read_int(signed=True),
    )
    if flags & 1:
        info.software_emoji_id = reader.read_long(signed=False)
    if flags & 2:
        info.last_usage_date = reader.read_int(signed=True)
    return info


class _DataJSONObject(TLObject):
    CONSTRUCTOR_ID = _CTOR_DATAJSON

    def __init__(self, data: str):
        self.data = data

    def to_dict(self):
        return {"_": "DataJSON", "data": self.data}

    def _bytes(self):
        return _pack_uint32(_CTOR_DATAJSON) + TLObject.serialize_bytes(self.data)


class InputPasskeyResponseRegister(TLObject):
    """inputPasskeyResponseRegister#3e63935c"""

    CONSTRUCTOR_ID = _CTOR_INPUT_RESPONSE_REGISTER

    def __init__(self, client_data: "_DataJSONObject", attestation_data: bytes):
        self.client_data = client_data
        self.attestation_data = attestation_data

    def to_dict(self):
        return {
            "_": "inputPasskeyResponseRegister",
            "client_data": self.client_data.data,
            "attestation_data": self.attestation_data,
        }

    def _bytes(self):
        return (
            _pack_uint32(_CTOR_INPUT_RESPONSE_REGISTER)
            + self.client_data._bytes()
            + TLObject.serialize_bytes(self.attestation_data)
        )


class InputPasskeyResponseLogin(TLObject):
    """inputPasskeyResponseLogin#c31fc14a"""

    CONSTRUCTOR_ID = _CTOR_INPUT_RESPONSE_LOGIN

    def __init__(
        self,
        client_data: "_DataJSONObject",
        authenticator_data: bytes,
        signature: bytes,
        user_handle: str,
    ):
        self.client_data = client_data
        self.authenticator_data = authenticator_data
        self.signature = signature
        self.user_handle = user_handle

    def to_dict(self):
        return {
            "_": "inputPasskeyResponseLogin",
            "client_data": self.client_data.data,
            "authenticator_data": self.authenticator_data,
            "signature": self.signature,
            "user_handle": self.user_handle,
        }

    def _bytes(self):
        return (
            _pack_uint32(_CTOR_INPUT_RESPONSE_LOGIN)
            + self.client_data._bytes()
            + TLObject.serialize_bytes(self.authenticator_data)
            + TLObject.serialize_bytes(self.signature)
            + TLObject.serialize_bytes(self.user_handle)
        )


class InputPasskeyCredentialPublicKey(TLObject):
    """inputPasskeyCredentialPublicKey#3c27b78f"""

    CONSTRUCTOR_ID = _CTOR_INPUT_CRED_PUBLIC_KEY

    def __init__(self, id: str, raw_id: str, response: TLObject):
        # id/raw_id: base64url strings of the credential id (as JSON fields)
        self.id = id
        self.raw_id = raw_id
        self.response = response

    def to_dict(self):
        return {
            "_": "inputPasskeyCredentialPublicKey",
            "id": self.id,
            "raw_id": self.raw_id,
            "response": self.response.to_dict(),
        }

    def _bytes(self):
        return (
            _pack_uint32(_CTOR_INPUT_CRED_PUBLIC_KEY)
            + TLObject.serialize_bytes(self.id)
            + TLObject.serialize_bytes(self.raw_id)
            + self.response._bytes()
        )


class InitPasskeyRegistrationRequest(TLRequest):
    """account.initPasskeyRegistration#429547e8 → options JSON string"""

    CONSTRUCTOR_ID = 0x429547E8

    def to_dict(self):
        return {"_": "InitPasskeyRegistrationRequest"}

    def _bytes(self):
        return _pack_uint32(0x429547E8)

    @staticmethod
    def read_result(reader: BinaryReader) -> str:
        if reader.read_int(signed=False) != _CTOR_ACCOUNT_PASSKEY_REGISTRATION_OPTIONS:
            raise PasskeyError("unexpected constructor, expected account.passkeyRegistrationOptions")
        if reader.read_int(signed=False) != _CTOR_DATAJSON:
            raise PasskeyError("expected DataJSON inside passkeyRegistrationOptions")
        return reader.tgread_string()


class RegisterPasskeyRequest(TLRequest):
    """account.registerPasskey#55b41fd6 → Passkey"""

    CONSTRUCTOR_ID = 0x55B41FD6

    def __init__(self, credential: InputPasskeyCredentialPublicKey):
        self.credential = credential

    def to_dict(self):
        return {"_": "RegisterPasskeyRequest", "credential": self.credential.to_dict()}

    def _bytes(self):
        return _pack_uint32(0x55B41FD6) + self.credential._bytes()

    @staticmethod
    def read_result(reader: BinaryReader) -> PasskeyInfo:
        return _read_passkey(reader)


class GetPasskeysRequest(TLRequest):
    """account.getPasskeys#ea1f0c52 → list[PasskeyInfo]"""

    CONSTRUCTOR_ID = 0xEA1F0C52

    def to_dict(self):
        return {"_": "GetPasskeysRequest"}

    def _bytes(self):
        return _pack_uint32(0xEA1F0C52)

    @staticmethod
    def read_result(reader: BinaryReader) -> List[PasskeyInfo]:
        if reader.read_int(signed=False) != _CTOR_ACCOUNT_PASSKEYS:
            raise PasskeyError("unexpected constructor, expected account.passkeys")
        if reader.read_int(signed=False) != _CTOR_VECTOR:
            raise PasskeyError("expected Vector<Passkey>")
        count = reader.read_int(signed=True)
        return [_read_passkey(reader) for _ in range(count)]


class DeletePasskeyRequest(TLRequest):
    """account.deletePasskey#f5b5563f → Bool"""

    CONSTRUCTOR_ID = 0xF5B5563F

    def __init__(self, id: str):
        self.id = id

    def to_dict(self):
        return {"_": "DeletePasskeyRequest", "id": self.id}

    def _bytes(self):
        return _pack_uint32(0xF5B5563F) + TLObject.serialize_bytes(self.id)

    @staticmethod
    def read_result(reader: BinaryReader) -> bool:
        ctor = reader.read_int(signed=False)
        if ctor == _CTOR_BOOL_TRUE:
            return True
        if ctor == _CTOR_BOOL_FALSE:
            return False
        raise PasskeyError(f"unexpected constructor 0x{ctor:08x}, expected Bool")


class InitPasskeyLoginRequest(TLRequest):
    """auth.initPasskeyLogin#518ad0b7 → options JSON string

    Can be sent on an unauthorized connection (that is the whole point)."""

    CONSTRUCTOR_ID = 0x518AD0B7

    def __init__(self, api_id: int, api_hash: str):
        self.api_id = api_id
        self.api_hash = api_hash

    def to_dict(self):
        return {"_": "InitPasskeyLoginRequest", "api_id": self.api_id, "api_hash": self.api_hash}

    def _bytes(self):
        return (
            _pack_uint32(0x518AD0B7)
            + struct.pack("<i", self.api_id)
            + TLObject.serialize_bytes(self.api_hash)
        )

    @staticmethod
    def read_result(reader: BinaryReader) -> str:
        if reader.read_int(signed=False) != _CTOR_AUTH_PASSKEY_LOGIN_OPTIONS:
            raise PasskeyError("unexpected constructor, expected auth.passkeyLoginOptions")
        if reader.read_int(signed=False) != _CTOR_DATAJSON:
            raise PasskeyError("expected DataJSON inside passkeyLoginOptions")
        return reader.tgread_string()


class FinishPasskeyLoginRequest(TLRequest):
    """auth.finishPasskeyLogin#9857ad07 → auth.Authorization

    No ``read_result`` on purpose: the response is deserialized with
    Telethon's own layer (``auth.Authorization`` is ancient and always
    available), which is what ``client._on_login`` needs. The driver
    re-serializes that object with ``bytes(...)`` for the neutral parser."""

    CONSTRUCTOR_ID = 0x9857AD07

    def __init__(
        self,
        credential: InputPasskeyCredentialPublicKey,
        from_dc_id: Optional[int] = None,
        from_auth_key_id: Optional[int] = None,
    ):
        self.credential = credential
        self.from_dc_id = from_dc_id
        self.from_auth_key_id = from_auth_key_id

    @property
    def flags(self) -> int:
        return 1 if self.from_dc_id is not None else 0

    def to_dict(self):
        return {
            "_": "FinishPasskeyLoginRequest",
            "credential": self.credential.to_dict(),
            "from_dc_id": self.from_dc_id,
            "from_auth_key_id": self.from_auth_key_id,
        }

    def _bytes(self):
        out = _pack_uint32(0x9857AD07) + struct.pack("<i", self.flags) + self.credential._bytes()
        if self.from_dc_id is not None:
            out += struct.pack("<i", self.from_dc_id)
            out += struct.pack("<q", self.from_auth_key_id or 0)
        return out


# ---------------------------------------------------------------------------
# The Telethon invoker: field dicts (from PASSKEY_TL_SPEC) -> TL classes -> client
# ---------------------------------------------------------------------------

_SCALAR_TL_TYPES = frozenset({"int", "long", "flags", "bytes", "string", "Bool"})

_SPEC: Dict[str, Any] = _core.PASSKEY_TL_SPEC


def _normalize(name: str) -> str:
    return name.replace("_", "").replace("#", "").lower()


def _message_spec(name: str) -> Tuple[str, Dict[str, Any]]:
    """Resolve a message name (spec key, TL name or class name) to its spec."""
    messages = _SPEC["messages"]
    if name in messages:
        return name, messages[name]
    wanted = _normalize(name)
    for key, spec in messages.items():
        spellings = (key, spec["tl_name"], spec["class"])
        if wanted in {_normalize(item) for item in spellings if item}:
            return key, spec
    raise PasskeyError(f"unknown passkey message {name!r}; known: {sorted(messages)}")


def _class_by_name(name: str, what: str):
    cls = globals().get(name)
    if not (isinstance(cls, type) and issubclass(cls, TLObject)):
        raise PasskeyError(
            f"{what}: no TL class {name!r} in tgmint.passkeys — the spec "
            "message/object names must match the classes declared above"
        )
    return cls


def _build_value(type_name: str, value: Any, *, what: str) -> Any:
    """Build the TL value for one spec field (object, union or scalar)."""
    if type_name in _SCALAR_TL_TYPES:
        return _scalar_value(type_name, value, what=what)
    unions = _SPEC["unions"]
    if type_name in unions:
        candidates = list(unions[type_name]["constructors"])
        constructor = value.get("_") if isinstance(value, dict) else None
        if constructor is None:
            if len(candidates) != 1:
                raise PasskeyError(
                    f"{what}: {type_name} needs a '_' constructor name, "
                    f"one of {candidates}"
                )
            constructor = candidates[0]
        if constructor not in candidates:
            raise PasskeyError(
                f"{what}: {constructor!r} is not a constructor of {type_name}; "
                f"expected one of {candidates}"
            )
        return _construct_object(constructor, value, what=constructor)
    return _construct_object(type_name, value, what=what)


def _scalar_value(type_name: str, value: Any, *, what: str) -> Any:
    """Normalize one scalar spec field before it reaches a hand-written class.

    TL's ``long`` is **signed** while frameworks expose the auth key id as an
    unsigned 64-bit integer (``sha1(auth_key)[-8:]``). Half of all key ids are
    ``>= 2**63``, and ``struct.pack("<q", ...)`` in
    :meth:`FinishPasskeyLoginRequest._bytes` raises ``struct.error`` for those
    — while the neutral writer (:func:`tgmint.passkeys_core.encode_request`)
    and the pyrogram driver both accept them. Normalizing here keeps this
    driver's bytes identical to the core's for the same field dict.
    """
    if type_name == "long" and isinstance(value, int) and not isinstance(value, bool):
        return _core.to_signed_int64(value, what=what)
    return value


def _construct_object(object_key: str, values: Any, *, what: str):
    """Build the TL object/union named by ``object_key`` from its field dict."""
    spec = _SPEC["objects"].get(object_key)
    if spec is None:
        raise PasskeyError(
            f"{what}: no TL object {object_key!r} in PASSKEY_TL_SPEC "
            f"(scalar types: {sorted(_SCALAR_TL_TYPES)})"
        )
    class_name = spec.get("class")
    if not class_name:
        raise PasskeyError(
            f"{what}: {object_key!r} has no Telethon class (it is parsed "
            f"straight into {spec.get('result_class', 'a neutral value')})"
        )
    return _construct(class_name, spec, values, what=what)


def _construct(class_name: str, spec: Dict[str, Any], values: Any, *, what: str):
    """Instantiate one hand-written TL class from a spec field dict.

    ``flags`` fields are never passed (the classes derive them from the flag
    fields they carry, exactly like :func:`tgmint.passkeys_core.encode_request`
    computes them), a flag-gated field becomes a keyword argument when the
    dict carries it, and everything else is positional in spec order.
    """
    cls = _class_by_name(class_name, what)
    if isinstance(values, str):
        # convenience shared with the neutral writer: dataJSON accepts the
        # bare string as well as {"data": ...}
        string_fields = [
            field["name"] for field in spec["fields"]
            if field["type"] == "string" and "flag" not in field
        ]
        if len(spec["fields"]) == 1 and string_fields:
            values = {string_fields[0]: values}
    if not isinstance(values, dict):
        raise PasskeyError(
            f"{what}: a field dict expected, got {type(values).__name__}"
        )

    declared = [field["name"] for field in spec["fields"]]
    args: List[Any] = []
    kwargs: Dict[str, Any] = {}
    for field in spec["fields"]:
        if field["type"] == "flags":
            continue  # derived by the class (see FinishPasskeyLoginRequest.flags)
        name = field["name"]
        if field.get("flag") is not None:
            value = values.get(name)
            if value is not None:
                kwargs[name] = _build_value(field["type"], value, what=name)
            continue
        if name not in values:
            raise PasskeyError(f"{what}: missing field {name!r}; expected {declared}")
        args.append(_build_value(field["type"], values[name], what=name))
    return cls(*args, **kwargs)


def _build_request(message_key: str, spec: Dict[str, Any], fields: Optional[Dict[str, Any]]):
    """The Telethon request instance for one ceremony step."""
    if fields is None:
        fields = {}
    if not isinstance(fields, dict):
        raise PasskeyError(
            f"{message_key}: a field dict expected, got {type(fields).__name__}"
        )
    return _construct(spec["class"], spec, dict(fields), what=message_key)


def _response_bytes(response: Any, *, what: str) -> bytes:
    """The raw TL bytes of an already-parsed Telethon object.

    Telethon's generated classes expose ``__bytes__``/``_bytes()`` rather
    than a ``to_bytes()`` method, so ``bytes(obj)`` is the equivalent (and
    re-serializing is lossless enough for the fields the login state machine
    reads: constructor, flags, then the user's flags words and id).
    """
    try:
        return bytes(response)
    except TypeError as exc:  # pragma: no cover - defensive
        raise PasskeyError(
            f"{what}: cannot re-serialize {type(response).__name__} ({exc}); "
            "the neutral parser needs the response bytes"
        ) from None


# A server error that belongs to the passkey flow. Errors outside these
# prefixes keep Telethon's own semantics — including SESSION_PASSWORD_NEEDED,
# which is the 2FA signal and is mapped to TwoFactorRequired before this runs.
_SERVER_ERROR_RE = re.compile(r"\b((?:PASSKEY|SESSION)_[A-Z0-9_]+)\b")

_SERVER_ERROR_HINTS = {
    "PASSKEY_ORIGIN_MISMATCH": (
        " — Telegram rejected the WebAuthn origin in clientDataJSON; "
        f"tgmint defaults to {_core.DEFAULT_ORIGIN}, and re-registering with "
        "an origin the server accepts is the fix"
    ),
    "PASSKEY_CHALLENGE_EXPIRED": (
        " — the challenge is bound to the connection named in "
        "from_dc_id/from_auth_key_id; re-run the flow without pausing "
        "between challenge and finish"
    ),
    "PASSKEY_CREDENTIAL_NOT_FOUND": " — this credential id is not registered on the account",
    "PASSKEY_SIGNATURE_INVALID": (
        " — the stored credential did not verify; the passkey file may be corrupt"
    ),
}


def _server_error(key: str, exc: RPCError) -> Optional[PasskeyError]:
    """Translate a passkey-flow Telethon RPCError, or ``None`` to leave it alone.

    ``tgmint.passkeys_core.PasskeyError`` is the one error type both drivers
    promise (see the module docstring and
    :func:`tgmint.passkeys_pyrogram._server_error`), so a caller can write
    ``except tgmint.passkeys.PasskeyError`` and get the same behaviour on
    Telethon and on the Pyrogram family. Only PASSKEY_*/SESSION_* server
    answers are translated; a network failure, a flood wait or a phone-number
    error keeps its framework type, and the 2FA signal never reaches here
    (``SessionPasswordNeededError`` is caught first, and is also deliberately
    excluded by the marker check).
    """
    message = getattr(exc, "message", None)
    text = message if isinstance(message, str) else str(exc)
    match = _SERVER_ERROR_RE.search(text)
    if match is None:
        return None
    marker = match.group(1)
    if marker == "SESSION_PASSWORD_NEEDED":  # the 2FA signal, not an error
        return None
    hint = _SERVER_ERROR_HINTS.get(marker, "")
    return PasskeyError(f"{key}: Telegram rejected the request: {text}{hint}")


class TelethonInvoker:
    """Drive the neutral passkey ceremony through a Telethon client.

    Implements exactly one side of the
    :class:`tgmint.passkeys_core.PasskeyInvoker` contract — the structured
    ``native(name, fields)`` one — because Telethon hands us the response
    already parsed (``request.read_result`` for the six hand-written classes,
    its own TL layer for ``auth.Authorization``).

    For the four response kinds the core wants a value it can adopt (options
    JSON, a passkey, a list of passkeys, a bool) the parsed object is
    returned as is. ``finishPasskeyLogin`` is special: the core needs an
    :class:`tgmint.passkeys_core.AuthorizationResult`, so the framework object
    is re-serialized with ``bytes(...)`` and parsed by
    :func:`tgmint.passkeys_core.parse_result` — while the object itself is
    kept in :attr:`last_response`, because ``client._on_login`` needs the real
    ``User`` and the core cannot manufacture one.

    ``SESSION_PASSWORD_NEEDED`` on the finish call means "the account has a
    2FA cloud password" in neutral terms, so that exception is translated
    into :class:`tgmint.passkeys_core.TwoFactorRequired`; the password entry
    point stays in :func:`login_with_passkey`.
    """

    def __init__(self, client):
        self.client = client
        self.last_response: Any = None

    async def native(self, name: str, fields: Dict[str, Any]) -> Any:
        key, spec = _message_spec(name)
        request = _build_request(key, spec, fields)
        try:
            response = await self.client(request)
        except SessionPasswordNeededError as exc:
            # the 2FA signal: the *driver* decides which password call to
            # make, so this is deliberately not a PasskeyError
            if spec["result"]["kind"] == "authorization":
                raise _core.TwoFactorRequired() from exc
            raise
        except RPCError as exc:
            translated = _server_error(key, exc)
            if translated is None:
                raise
            raise translated from exc
        self.last_response = response
        if spec["result"]["kind"] == "authorization":
            return _core.parse_result(key, _response_bytes(response, what=key))
        return response


# ---------------------------------------------------------------------------
# Datacenter handoff rollback (Telethon's _switch_dc has no undo)
# ---------------------------------------------------------------------------

def _session_snapshot(client) -> Dict[str, Any]:
    """Everything ``client._switch_dc`` overwrites, captured before it runs.

    ``_switch_dc`` (telethon/client/telegrambaseclient.py:770-784) rewrites
    ``session.set_dc(...)``, sets ``session.auth_key`` **and** the sender's
    key to ``None``, saves the session, then reconnects — i.e. it permanently
    moves the caller's persistent session and erases its auth key. A failed
    ``finishPasskeyLogin`` after that point would leave the caller's session
    file pointing at another DC with no key at all, so the pre-switch state
    is captured here and put back by :func:`_restore_session`.
    """
    session = getattr(client, "session", None)
    return {
        "session": session,
        "dc_id": getattr(session, "dc_id", None),
        "server_address": getattr(session, "server_address", None),
        "port": getattr(session, "port", None),
        "auth_key": getattr(session, "auth_key", None),
    }


async def _restore_session(client, snapshot: Optional[Dict[str, Any]]) -> None:
    """Best-effort rollback of :meth:`TelethonClient._switch_dc`.

    Best effort by design: the login error is what the caller needs to see,
    so a rollback that also fails is swallowed (the client keeps the
    switched-to session — the same state a failed passkey login leaves in any
    client). The session file is written back and the connection re-opened on
    the restored DC, because ``_switch_dc`` reconnected to the new one.
    """
    if not snapshot:
        return
    session = snapshot["session"]
    try:
        if session is not None and snapshot["dc_id"] is not None:
            await tl_utils.maybe_async(
                session.set_dc(
                    snapshot["dc_id"], snapshot["server_address"], snapshot["port"]
                )
            )
            session.auth_key = snapshot["auth_key"]
            # the sender holds its own copy of the key; put it back before
            # reconnecting so connect() does not mint a brand new one
            sender_key = getattr(getattr(client, "_sender", None), "auth_key", None)
            old_key = snapshot["auth_key"]
            if sender_key is not None and old_key is not None:
                try:
                    sender_key.key = getattr(old_key, "key", old_key)
                except Exception:  # nocov - a sender that does not allow it
                    pass
            await tl_utils.maybe_async(session.save())
        disconnect = getattr(client, "_disconnect", None)
        connect = getattr(client, "connect", None)
        if callable(disconnect) and callable(connect):
            await disconnect()
            await connect()
    except Exception:  # nocov - a rollback that cannot complete
        pass


def _auth_user(invoker: TelethonInvoker, result: "_core.AuthorizationResult"):
    """The Telethon ``User`` behind a finished passkey login.

    The invoker keeps the framework object; if a caller replaced it (or only
    kept the bytes), the object is rebuilt from ``result.raw`` — the bytes
    the core already parsed — through Telethon's own TL layer.
    """
    response = getattr(invoker, "last_response", None)
    if response is None:
        from telethon.tl import types as tl_types

        constructors = _SPEC["messages"]["finishPasskeyLogin"]["result"]["constructors"]
        if result.constructor == constructors["authorization"]:
            cls = tl_types.auth.Authorization
        else:
            cls = tl_types.auth.AuthorizationSignUpRequired
        response = cls.from_reader(BinaryReader(result.raw))
    user = getattr(response, "user", None)
    if user is None:
        raise PasskeyError(
            "auth.finishPasskeyLogin answered auth.authorizationSignUpRequired: "
            "the account behind this passkey no longer exists, so there is no "
            "user to return"
        )
    return user


# ---------------------------------------------------------------------------
# High-level flows — one core call each
# ---------------------------------------------------------------------------

async def register_passkey(
    client,
    *,
    path: str,
    origin: str = DEFAULT_ORIGIN,
    name: str = "tgmint software passkey",
    alg: Optional[int] = None,
) -> Tuple[PasskeyInfo, PasskeyStore]:
    """Register a new passkey on the account this client is logged into.

    The credential is generated locally (ES256 or Ed25519, whatever the
    server prefers — ``alg`` overrides that preference, and is validated
    against the algorithms the server actually offered) and saved to ``path``
    — chmod 600. Keep that file: it is the only thing needed to log in later
    besides a possible 2FA cloud password.

    Returns ``(server_passkey_info, store)``.
    """
    return await _core.register_passkey_core(
        TelethonInvoker(client),
        store_path=path,
        origin=origin,
        name=name,
        alg=alg,
    )


async def login_with_passkey(
    client,
    *,
    path: str,
    origin: Optional[str] = None,
    password: Optional[str] = None,
):
    """Log an unauthorized, connected client into the passkey's account.

    Mirrors the official client: fetch the login challenge, sign it, and
    finish on the account's home datacenter (switching DCs if needed,
    passing from_dc_id/from_auth_key_id exactly like the Android app).

    If the account has a 2FA cloud password, pass it as ``password``. Without
    a password the neutral :class:`tgmint.passkeys_core.TwoFactorRequired`
    signal propagates (it is deliberately *not* a :class:`PasskeyError`), so a
    caller that guards against a corrupt store does not swallow a password
    prompt along with it; call again with ``password=`` to finish.

    A failed login after the DC switch restores the previous session state
    (DC, server address, port and auth key) best-effort — ``client._switch_dc``
    rewrites the caller's persistent session and erases its auth key, so
    without the rollback one expired challenge would permanently move the
    session file and lose the key.

    Returns the logged-in ``me`` user.
    """
    session = client.session
    store = PasskeyStore.load(path)
    invoker = TelethonInvoker(client)

    # 1. Fetch the challenge on the CURRENT connection first — the server
    #    binds it to this connection's auth key (PasskeysController.java
    #    sends initPasskeyLogin on whatever DC the connection is on).
    options_json = await _core.fetch_login_challenge(
        invoker, api_id=client.api_id, api_hash=client.api_hash
    )

    # 2. Sign it. The core persists the bumped signature counter BEFORE any
    #    further network step (a failed login must not leave a stale,
    #    reusable counter behind) and works out the cross-DC handoff: the
    #    auth key id of the connection that got the challenge, normalized to
    #    the signed int64 the TL field wants (half of all key ids are
    #    >= 2**63).
    auth_key = getattr(session, "auth_key", None)
    plan = await _core.login_passkey_assertion(
        store,
        options_json,
        origin=origin,
        connection_dc=getattr(session, "dc_id", None),
        connection_auth_key_id=getattr(auth_key, "key_id", None),
        home_dc=store.home_dc,
    )

    # 3. If the account's home DC differs, switch now and pass
    #    from_dc_id/from_auth_key_id of the connection that got the
    #    challenge — exactly like the official client does. The switch is
    #    destructive (new DC, auth key erased), so snapshot first and restore
    #    on every failure path below.
    snapshot = None
    if plan["switch_to_dc"] is not None:
        snapshot = _session_snapshot(client)
        try:
            await client._switch_dc(plan["switch_to_dc"])
        except BaseException:
            await _restore_session(client, snapshot)
            raise

    # 4. Finish on the home DC.
    try:
        result = await _core.finish_login(invoker, plan["finish_fields"])
    except _core.TwoFactorRequired:
        if password is None:
            # nothing can be finished without the password, so put the
            # caller's session back before asking for one (the retry starts
            # from the DC it originally connected to)
            await _restore_session(client, snapshot)
            raise
        # The password step completes the login on the home-DC session, so the
        # switch is intentionally kept: a wrong password stays retryable with
        # ``client.sign_in(password=...)`` on that DC.
        me = await client.sign_in(password=password)
        store.save()
        return me
    except BaseException:
        await _restore_session(client, snapshot)
        raise

    store.save()
    me = await client._on_login(_auth_user(invoker, result))
    await tl_utils.maybe_async(session.save())
    return me


async def list_passkeys(client) -> List[PasskeyInfo]:
    """Passkeys currently registered on the logged-in account."""
    return await _core.list_passkeys_core(TelethonInvoker(client))


async def delete_passkey(client, passkey_id: str) -> bool:
    """Remove a passkey from the account (does not delete your local file)."""
    return await _core.delete_passkey_core(TelethonInvoker(client), passkey_id)
