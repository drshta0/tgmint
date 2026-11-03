"""
Software passkeys for the Pyrogram family (kurigram, pyrofork, …).

:mod:`tgmint.passkeys` speaks passkeys to Telethon with ~250 lines of
hand-written TL classes, because Telethon's TL layer (224) predates the
passkey constructors.  The Pyrogram forks that ship a raw layer with
passkeys — **kurigram ≥ 2.2.26** (layer 229) and **pyrofork ≥ 2.3.69**
(layer 220) — generate all fourteen constructors, and those generated
classes serialize **byte-identically** to tgmint's hand-written ones
(verified for all six requests, including both flag spellings of
``finishPasskeyLogin``).  So this driver needs no TL work at all: it

* converts the framework-neutral field dicts of :mod:`tgmint.passkeys_core`
  into the distribution's generated ``raw`` classes,
* sends them with ``await client.invoke(...)``,
* normalizes the framework's response objects back into the neutral shapes
  (``str`` options, :class:`~tgmint.passkeys_core.PasskeyInfo`,
  ``list[PasskeyInfo]``, ``bool``, :class:`~tgmint.passkeys_core.AuthorizationResult`),

which is exactly the ``native(name, fields)`` half of the core's invoker
contract, so the whole ceremony (state machine, counter handling, cross-DC
plan) is the *same code* the Telethon driver runs.

The constructor lookup is done by **TL constructor id** against the
distribution's own object table (``pyrogram.raw.all.objects``), never by
module path guessing: a fork that renamed or moved a class still resolves,
and a fork that does not ship the constructor (hydrogram 0.2.0, layer 181)
gets a clear error instead of an ``AttributeError``.

Usage — registration (an authorized client)::

    from tgmint.adapters.pyrogram import client_kwargs
    from tgmint.api import API
    from tgmint.fingerprint import Fingerprint
    from tgmint.passkeys_pyrogram import register_passkey

    fp = Fingerprint.from_apidata(API.TelegramDesktop.Generate(system="windows"))
    client = Client("acct", **client_kwargs(fp), in_memory=True)
    await client.connect()                     # a connected, authorized session
    info, store = await register_passkey(client, path="acct.passkey.json")

Usage — login with nothing but the passkey file::

    client = Client("fresh", **client_kwargs(fp), in_memory=True)
    await client.connect()                     # connected, NOT started
    me = await login_with_passkey(client, path="acct.passkey.json")

**Device identity matters here.**  A Pyrogram client announces
``device_model``/``app_version``/``system_version``/``lang_code`` in
``InitConnection``, and Telegram's server does apply an
origin/attestation check to passkeys (``PASSKEY_ORIGIN_MISMATCH``).  Build
the client from a minted tgmint fingerprint — ``client_kwargs`` above —
rather than the framework defaults, so the device identity, the ``api_id``
and the claimed WebAuthn origin all come from one place.  Letting Pyrogram
present itself as ``"Pyrogram 2.x"`` is the one new failure mode this
driver has that the Telethon one does not (see
:data:`tgmint.passkeys_core.DEFAULT_ORIGIN`).

**Own account only.**  These functions manage *your own* account's
passkeys: registration needs a session you are already logged into, login
needs the passkey file you created there.  tgmint never registers a
passkey on somebody else's account, never exports a passkey, and never
enables passkey login for an account you cannot already access.  Treat the
passkey file like a password: whoever holds it (plus the 2FA password, if
set) can log in.

**pyrofork** ships the same fourteen constructors, so registration, listing,
deletion and a same-DC login work there too.  It has no
``Client.get_session``, though, and a cross-DC login needs one: on pyrofork
this driver raises a ``PasskeyError`` saying so instead of failing
obscurely.  (Doing it by hand means constructing
``Session(client, dc_id, auth_key, test_mode)`` with an
``await Auth(client, dc_id, test_mode).create()`` key — deliberately not
implemented, since kurigram does it in one call.)

**Diagnostics.**  kurigram maps ``PASSKEY_CREDENTIAL_NOT_FOUND`` and
``PASSKEY_ORIGIN_MISMATCH`` to named errors but everything else
(``PASSKEY_CHALLENGE_EXPIRED``, ``PASSKEY_SIGNATURE_INVALID``) degrades to
a generic ``BadRequest`` whose ``.value`` is ``"[400 PASSKEY_…]"``, and the
framework appends a line to ``./unknown_errors.txt`` in the process CWD for
each unmapped error.  This driver catches ``BadRequest``, translates it to
:class:`~tgmint.passkeys_core.PasskeyError` with the server text and a hint,
and leaves that litter file alone (set the CWD if it matters).

Requires a Pyrogram-family distribution with the passkey layer.  Importing
this module without one succeeds; the functions raise
:class:`~tgmint.passkeys_core.PasskeyError` explaining what to install.
"""
from __future__ import annotations

import hashlib
import importlib
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import passkeys_core as core

__all__ = [
    "PYROGRAM_AVAILABLE",
    "PyrogramInvoker",
    "build_request",
    "register_passkey",
    "login_with_passkey",
    "list_passkeys",
    "delete_passkey",
]

try:  # kurigram / pyrofork / any Pyrogram fork: same import name
    import pyrogram
    from pyrogram import errors as pyrogram_errors
    from pyrogram import types as pyrogram_types

    PYROGRAM_AVAILABLE = True
except ImportError:  # nocov - environment dependent
    pyrogram = None  # type: ignore[assignment]
    pyrogram_errors = None  # type: ignore[assignment]
    pyrogram_types = None  # type: ignore[assignment]
    PYROGRAM_AVAILABLE = False


# auth.authorizationSignUpRequired#44747e9a — the "no account on this
# number" answer; a passkey login can never create one.
_CTOR_AUTHORIZATION_SIGN_UP_REQUIRED = 0x44747E9A

# pyrogram.raw.core.BoolTrue / BoolFalse, for forks that hand back the
# primitive object instead of a Python bool.
_CTOR_BOOL_TRUE = 0x997275B5

_TWO_FACTOR_MESSAGE = (
    "the account has a 2FA cloud password; call again with password=..."
)


def _framework() -> Any:
    """The ``pyrogram`` module, or a PasskeyError saying what to install."""
    if not PYROGRAM_AVAILABLE:  # nocov - environment dependent
        raise core.PasskeyError(
            "native passkeys need a Pyrogram-family distribution that ships "
            "the passkey TL layer (kurigram >= 2.2.26, layer 229, or "
            "pyrofork >= 2.3.69); install one, e.g. pip install kurigram"
        )
    return pyrogram


def _distribution() -> str:
    """``"<fork name> <version>"`` of the distribution providing ``pyrogram``.

    Every Pyrogram fork installs the same top-level ``pyrogram`` package, so
    the error messages ask the package metadata which one is answering
    instead of guessing from the import path (``kurigram 2.2.26``).
    """
    try:
        from importlib import metadata
    except ImportError:  # nocov - Python < 3.8
        metadata = None
    if metadata is not None:
        for candidate in ("kurigram", "pyrofork", "hydrogram", "pyrogram"):
            try:
                dist = metadata.distribution(candidate)
            except metadata.PackageNotFoundError:
                continue
            except Exception:  # nocov - broken metadata
                break
            files = dist.files or []
            if any(
                str(item).replace("\\", "/").startswith("pyrogram/")
                for item in files
            ):
                name = dist.metadata["Name"] or candidate
                return f"{name} {dist.version}"
    return f"pyrogram {getattr(pyrogram, '__version__', '?')}"


# ---------------------------------------------------------------------------
# Constructor lookup: TL id -> the distribution's generated class
# ---------------------------------------------------------------------------

def _object_table() -> Dict[int, Any]:
    """``pyrogram.raw.all.objects``: constructor id -> class.

    The table is the distribution's own registry (``pyrogram/raw/all.py``,
    rewritten in place into ``{id: class}`` when ``pyrogram.raw`` imports),
    so looking a constructor up here is fork-agnostic: it does not care
    which module the class lives in, and it is the same table the
    framework's reader uses to parse responses.
    """
    module = importlib.import_module("pyrogram.raw.all")
    table = getattr(module, "objects", None)
    if not isinstance(table, dict):  # nocov - a fork without the registry
        raise core.PasskeyError(
            f"{_distribution()} does not expose pyrogram.raw.all.objects; "
            "cannot resolve passkey constructors"
        )
    return table


def _resolve_dotted(path: str) -> Any:
    module_path, _, attribute = path.rpartition(".")
    return getattr(importlib.import_module(module_path), attribute)


def _tl_class(constructor: int, *, what: str) -> Any:
    """The generated class for one TL constructor id (or a clear error)."""
    class_or_path = _object_table().get(constructor)
    if class_or_path is None:
        raise core.PasskeyError(
            f"{_distribution()} does not ship {what} (TL constructor "
            f"0x{constructor:08x}): its raw layer predates passkeys. Native "
            "passkeys need kurigram >= 2.2.26 or pyrofork >= 2.3.69"
        )
    if isinstance(class_or_path, str):  # pragma: no cover - pre-rewrite table
        class_or_path = _resolve_dotted(class_or_path)
    return class_or_path


# ---------------------------------------------------------------------------
# Field dict -> generated raw classes (the core's spec drives the mapping)
# ---------------------------------------------------------------------------

def _key_name(name: Any) -> str:
    return str(name).replace("_", "").replace("#", "").lower()


def _message_key(name: str) -> str:
    """Resolve a spec name, TL name or class name to the spec message key."""
    messages = core.PASSKEY_TL_SPEC["messages"]
    if name in messages:
        return name
    wanted = _key_name(name)
    for key, spec in messages.items():
        spellings = (key, spec.get("tl_name"), spec.get("class"))
        if wanted in {_key_name(item) for item in spellings if item}:
            return key
    raise core.PasskeyError(
        f"unknown passkey message {name!r}; known: {sorted(messages)}"
    )


def _type_entry(type_name: str) -> Tuple[Optional[str], Dict[str, Any]]:
    """``(object key, spec)`` for an object type; key is None for a union."""
    objects = core.PASSKEY_TL_SPEC["objects"]
    unions = core.PASSKEY_TL_SPEC["unions"]
    if type_name in objects:
        return type_name, objects[type_name]
    if type_name in unions:
        return None, unions[type_name]
    wanted = _key_name(type_name)
    for key, spec in objects.items():
        spellings = (key, spec.get("tl_name"), spec.get("class"))
        if wanted in {_key_name(item) for item in spellings if item}:
            return key, spec
    for key, spec in unions.items():
        if wanted in {_key_name(key), _key_name(spec["tl_name"])}:
            return None, spec
    raise core.PasskeyError(
        f"unknown passkey TL type {type_name!r}; known objects: "
        f"{sorted(objects)}, unions: {sorted(unions)}"
    )


def _match_union_constructor(
    name: str, candidates: Sequence[str], *, what: str
) -> str:
    objects = core.PASSKEY_TL_SPEC["objects"]
    wanted = _key_name(name)
    for key in candidates:
        spec = objects[key]
        spellings = (key, spec.get("tl_name"), spec.get("class"))
        if wanted in {_key_name(item) for item in spellings if item}:
            return key
    raise core.PasskeyError(
        f"{what}: {name!r} is not a constructor of this union; expected one "
        f"of {sorted(candidates)}"
    )


_VECTOR_RE = re.compile(r"^vector<(.+)>$")


def _vector_item(type_name: str) -> Optional[str]:
    match = _VECTOR_RE.match(type_name)
    return match.group(1) if match else None


def _checked_int32(value: Any, *, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise core.PasskeyError(f"{what}: int field expected, got {type(value)!r}")
    if not -(1 << 31) <= value < (1 << 31):
        raise core.PasskeyError(f"{what}: int out of range: {value}")
    return value


def _convert_value(type_name: str, value: Any, *, what: str) -> Any:
    """One spec-typed value -> the value the generated class expects."""
    if type_name == "int":
        return _checked_int32(value, what=what)
    if type_name == "long":
        # pyrogram writes `long` with int.to_bytes(..., signed=True), so the
        # unsigned spelling of a key id >= 2**63 is an OverflowError there;
        # the signed normalization is the same one the core applies.
        return core.to_signed_int64(value, what=what)
    if type_name == "string":
        if not isinstance(value, str):
            raise core.PasskeyError(f"{what}: str expected, got {type(value)!r}")
        return value
    if type_name == "bytes":
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise core.PasskeyError(f"{what}: bytes expected, got {type(value)!r}")
        return bytes(value)
    if type_name == "Bool":
        return bool(value)
    item_type = _vector_item(type_name)
    if item_type is not None:
        if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
            raise core.PasskeyError(f"{what}: a list of {item_type} expected")
        return [
            _convert_value(item_type, item, what=f"{what}[{index}]")
            for index, item in enumerate(value)
        ]
    return _build_object(type_name, value, what=what)


def _build_object(type_name: str, value: Any, *, what: str) -> Any:
    """Build a nested ``raw.types`` object from a field dict."""
    key, spec = _type_entry(type_name)
    if key is None:  # union: the dict names its constructor with "_"
        candidates = list(spec["constructors"])
        if not isinstance(value, dict):
            raise core.PasskeyError(
                f"{what}: a field dict expected for {spec['tl_name']}, got "
                f"{type(value).__name__}"
            )
        fields = dict(value)
        chosen = fields.pop("_", None)
        if chosen is None:
            if len(candidates) != 1:
                raise core.PasskeyError(
                    f"{what}: {spec['tl_name']} needs a '_' constructor name, "
                    f"one of {candidates}"
                )
            chosen = candidates[0]
        key = _match_union_constructor(chosen, candidates, what=what)
        spec = core.PASSKEY_TL_SPEC["objects"][key]
    else:
        if not isinstance(value, (dict, str)):
            raise core.PasskeyError(
                f"{what}: a field dict expected for {spec['tl_name']}, got "
                f"{type(value).__name__}"
            )
        fields = dict(value) if isinstance(value, dict) else value
        if isinstance(fields, dict):
            fields.pop("_", None)
        if isinstance(fields, str):
            # convenience shared with the core writer: a dataJSON field also
            # accepts the bare JSON string
            string_fields = [
                item["name"] for item in spec["fields"]
                if item["type"] == "string" and "flag" not in item
            ]
            if len(spec["fields"]) != 1 or not string_fields:
                raise core.PasskeyError(
                    f"{what}: a field dict expected for {spec['tl_name']}, "
                    f"got a bare string"
                )
            fields = {string_fields[0]: fields}
    cls = _tl_class(spec["constructor"], what=spec["tl_name"])
    return cls(**_kwargs_for(spec, fields, what=what))


def _flags_word(spec: Dict[str, Any], fields: Dict[str, Any]) -> int:
    """The ``flags`` word a construct would carry (core's rule, mirrored)."""
    flags = 0
    for bit, driver in (spec.get("flag_bits") or {}).items():
        if fields.get(driver) is not None:
            flags |= 1 << int(bit)
    return flags


def _kwargs_for(
    spec: Dict[str, Any], fields: Dict[str, Any], *, what: str
) -> Dict[str, Any]:
    """Convert a spec field dict into the generated class's keyword arguments.

    Both Pyrogram and Telethon derive the ``flags`` word from field presence,
    so ``flags`` itself is never passed.  A flagged field whose bit is clear
    becomes ``None``; a flagged field whose bit is set but which is absent
    from the dict falls back to its declared ``default`` — that is the only
    such field, ``from_auth_key_id``, and it reproduces the Telethon class's
    ``from_auth_key_id or 0`` rule (generated Pyrogram classes would
    ``OverflowError``/``TypeError`` on ``None`` there).
    """
    field_specs = spec["fields"]
    declared = [field["name"] for field in field_specs]
    unknown = sorted(set(fields) - set(declared))
    if unknown:
        raise core.PasskeyError(
            f"{what}: unknown field(s) {unknown}; expected {declared}"
        )
    flags = _flags_word(spec, fields)
    kwargs: Dict[str, Any] = {}
    for field in field_specs:
        name, type_name = field["name"], field["type"]
        if type_name == "flags":
            continue
        bit = field.get("flag")
        present = bit is None or (flags >> bit) & 1
        if not present:
            kwargs[name] = None
            continue
        if name not in fields:
            if "default" not in field:
                raise core.PasskeyError(
                    f"{what}: missing field {name!r}; expected {declared}"
                )
            kwargs[name] = field["default"]
            continue
        value = fields[name]
        if value is None:
            raise core.PasskeyError(f"{what}: field {name!r} is None")
        kwargs[name] = _convert_value(type_name, value, what=f"{what}.{name}")
    return kwargs


def build_request(name: str, fields: Optional[Dict[str, Any]] = None) -> Any:
    """The distribution's generated request object for a passkey message.

    This is the whole field-dict → ``raw`` class conversion, exposed because
    it is the piece worth testing on its own: the object it returns must
    serialize (``.write()``) to exactly the bytes
    :func:`tgmint.passkeys_core.encode_request` produces for the same dict.

    ``name`` is a spec message name (``"registerPasskey"``) or its TL/class
    spelling; ``fields`` is the field dict the core's builders return.  The
    dict is validated with :func:`~tgmint.passkeys_core.encode_request`
    first, so both paths accept and reject exactly the same input.
    """
    _framework()
    key = _message_key(name)
    payload = dict(fields or {})
    core.encode_request(key, payload)  # spec check, same errors as the core
    spec = core.PASSKEY_TL_SPEC["messages"][key]
    cls = _tl_class(spec["constructor"], what=spec["tl_name"])
    return cls(**_kwargs_for(spec, payload, what=key))


# ---------------------------------------------------------------------------
# Response normalization: generated objects -> the core's neutral shapes
# ---------------------------------------------------------------------------

def _unsigned_long(value: Any) -> Any:
    """pyrogram reads ``long`` signed; the core's spec says unsigned.

    Only differs for ids >= 2**63 (a huge custom-emoji id), where the
    framework hands back a negative int and the core hands back the unsigned
    one — normalize so both drivers agree.
    """
    if isinstance(value, int) and not isinstance(value, bool) and value < 0:
        return value + (1 << 64)
    return value


def _write_bytes(value: Any) -> bytes:
    """Re-serialize a response object with the framework's own writer."""
    writer = getattr(value, "write", None)
    if not callable(writer):
        return b""
    try:
        data = writer()
    except Exception:  # nocov - a fork whose writer needs arguments
        return b""
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    return b""


def _options_json(key: str, response: Any) -> str:
    options = getattr(response, "options", None)
    data = getattr(options, "data", None)
    if not isinstance(data, str):
        raise core.PasskeyError(
            f"{key}: expected account.passkeyRegistrationOptions / "
            f"auth.passkeyLoginOptions carrying a dataJSON (a JSON string), "
            f"got {type(response).__name__}"
        )
    return data


def _passkey_list(key: str, response: Any) -> List[Any]:
    if isinstance(response, (list, tuple)):
        return list(response)
    items = getattr(response, "passkeys", None)
    if items is None:
        raise core.PasskeyError(
            f"{key}: expected account.passkeys#f8e0aa1c with a .passkeys "
            f"vector, got {type(response).__name__}"
        )
    return list(items)


def _passkey_info(key: str, value: Any) -> core.PasskeyInfo:
    """account.passkey#98613ebf -> :class:`~tgmint.passkeys_core.PasskeyInfo`."""
    if isinstance(value, core.PasskeyInfo):
        return value
    if isinstance(value, dict):
        ident, name, date = value.get("id"), value.get("name"), value.get("date")
        emoji, last_usage = value.get("software_emoji_id"), value.get("last_usage_date")
    else:
        ident = getattr(value, "id", None)
        name = getattr(value, "name", None)
        date = getattr(value, "date", None)
        emoji = getattr(value, "software_emoji_id", None)
        last_usage = getattr(value, "last_usage_date", None)
    missing = [
        field for field, item in
        (("id", ident), ("name", name), ("date", date)) if item is None
    ]
    if missing:
        raise core.PasskeyError(
            f"{key}: cannot read an account.passkey out of "
            f"{type(value).__name__} (missing {missing})"
        )
    return core.PasskeyInfo(
        id=ident,
        name=name,
        date=date,
        software_emoji_id=_unsigned_long(emoji),
        last_usage_date=last_usage,
    )


def _bool_result(key: str, value: Any) -> bool:
    """account.deletePasskey = Bool -> a Python bool.

    The framework's parser already answers a real ``bool``; a value that was
    not parsed (e.g. replayed from bytes) is the four-byte Bool constructor.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)) and len(value) == 4:
        return int.from_bytes(bytes(value), "little") == _CTOR_BOOL_TRUE
    flag = getattr(value, "value", None)  # pyrogram.raw.core.BoolTrue.value
    if isinstance(flag, bool):
        return flag
    raise core.PasskeyError(
        f"{key}: expected a BoolTrue/BoolFalse answer, got {type(value).__name__}"
    )


def _authorization_from_fields(
    response: Any, raw_bytes: bytes
) -> core.AuthorizationResult:
    """Build the neutral result straight from the framework's parsed object.

    The fallback for a distribution whose response objects cannot be
    re-serialized: the driver knows its own framework's field names, so it
    reads them here instead of asking the core to parse bytes it cannot get.
    """
    user = getattr(response, "user", None)
    constructor = getattr(response, "ID", None)
    return core.AuthorizationResult(
        constructor=constructor if isinstance(constructor, int) else 0,
        sign_up_required=(
            constructor == _CTOR_AUTHORIZATION_SIGN_UP_REQUIRED
            or user is None
        ),
        tmp_sessions=getattr(response, "tmp_sessions", None),
        otherwise_relogin_days=getattr(response, "otherwise_relogin_days", None),
        future_auth_token=getattr(response, "future_auth_token", None),
        user_constructor=getattr(user, "ID", None) if user is not None else None,
        user_id=getattr(user, "id", None) if user is not None else None,
        raw=raw_bytes,
    )


def _authorization(response: Any) -> core.AuthorizationResult:
    """auth.Authorization -> :class:`AuthorizationResult`.

    Pyrogram's generated response objects carry a ``write()``, so the normal
    path is: re-serialize the object and let the core parse the bytes — the
    same parser the byte-path drivers use, which keeps the wire spec honest.

    The framework's own parse still wins for the ``user``: at layer 229 the
    user constructor is ``user#b1b8cc83``, which the core's flag-word table
    does not know (it knows ``user#31774388``), so ``parse_result`` leaves
    ``user_id`` unset for kurigram bytes.  The driver fills it from the
    object it was handed (as it does for any field the core could not read),
    and falls back to reading the fields directly when the object cannot be
    re-serialized at all.
    """
    raw_bytes = _write_bytes(response)
    result = None
    if raw_bytes:
        try:
            result = core.parse_result("finishPasskeyLogin", raw_bytes)
        except core.PasskeyError:  # nocov - a fork with a different layout
            result = None
    if result is None:
        return _authorization_from_fields(response, raw_bytes)

    user = getattr(response, "user", None)
    if user is not None:
        constructor = getattr(user, "ID", None)
        if isinstance(constructor, int):
            result.user_constructor = constructor
        if result.user_id is None:
            result.user_id = getattr(user, "id", None)
    if result.tmp_sessions is None:
        result.tmp_sessions = getattr(response, "tmp_sessions", None)
    if result.otherwise_relogin_days is None:
        result.otherwise_relogin_days = getattr(response, "otherwise_relogin_days", None)
    if result.future_auth_token is None:
        result.future_auth_token = getattr(response, "future_auth_token", None)
    return result


def _server_error(key: str, exc: Exception) -> core.PasskeyError:
    """Translate a framework RPC error into the core's error type."""
    code = getattr(exc, "ID", None)
    value = getattr(exc, "value", None)
    text = value if isinstance(value, str) else str(exc)
    haystack = f"{code or ''} {text}"
    hint = ""
    if "PASSKEY_ORIGIN_MISMATCH" in haystack:
        hint = (
            " — Telegram rejected the WebAuthn origin in clientDataJSON; "
            f"tgmint defaults to {core.DEFAULT_ORIGIN}, and re-registering with "
            "an origin the server accepts is the fix"
        )
    elif "PASSKEY_CHALLENGE_EXPIRED" in haystack:
        hint = (
            " — the challenge is bound to the connection named in "
            "from_dc_id/from_auth_key_id; re-run the flow without pausing "
            "between challenge and finish"
        )
    elif "PASSKEY_CREDENTIAL_NOT_FOUND" in haystack:
        hint = " — this credential id is not registered on the account"
    elif "PASSKEY_SIGNATURE_INVALID" in haystack:
        hint = " — the stored credential did not verify; the passkey file may be corrupt"
    return core.PasskeyError(
        f"{key}: Telegram rejected the request: {text}{hint}"
    )


# ---------------------------------------------------------------------------
# The invoker: the core's `native(name, fields)` contract
# ---------------------------------------------------------------------------

class PyrogramInvoker:
    """``native(name, fields)`` backed by a connected Pyrogram-family client.

    The core resolves the invoker by method lookup and calls it once per
    network round trip; the field dicts come from the core's builders, so
    this class never builds a ceremony step of its own.  It also remembers
    the last ``finishPasskeyLogin`` response object, because the driver
    needs the framework's own ``auth.Authorization.user`` for the login
    bookkeeping and the core's neutral result deliberately drops it.

    ``client`` must be an initialized, **connected** client (``await
    client.connect()``) — ``client.start()`` is interactive and prompts for
    a phone number, so it must not be used by a passkey driver.
    """

    def __init__(self, client: Any):
        _framework()
        if not callable(getattr(client, "invoke", None)):
            raise core.PasskeyError(
                "a Pyrogram-family Client (with an async .invoke) is required, "
                f"got {type(client).__name__}"
            )
        self.client = client
        self.sent: List[Any] = []
        """Every request object this invoker sent, in order (audit/debug)."""
        self.last_finish_response: Any = None
        """The framework's auth.Authorization answer to ``finishPasskeyLogin``."""

    async def native(self, name: str, fields: Optional[Dict[str, Any]] = None) -> Any:
        """Send one passkey message and return the normalized result."""
        key = _message_key(name)
        request = build_request(key, fields)
        self.sent.append(request)
        try:
            response = await self.client.invoke(request)
        except pyrogram_errors.SessionPasswordNeeded:
            # the account has a 2FA cloud password: the *driver* decides
            # which password call to make, the core only learns the signal
            raise core.TwoFactorRequired(_TWO_FACTOR_MESSAGE) from None
        except pyrogram_errors.BadRequest as exc:
            raise _server_error(key, exc) from exc
        return self._normalize(key, response)

    def _normalize(self, key: str, response: Any) -> Any:
        if key in ("initPasskeyRegistration", "initPasskeyLogin"):
            return _options_json(key, response)
        if key == "registerPasskey":
            return _passkey_info(key, response)
        if key == "getPasskeys":
            return [_passkey_info(key, item) for item in _passkey_list(key, response)]
        if key == "deletePasskey":
            return _bool_result(key, response)
        if key == "finishPasskeyLogin":
            self.last_finish_response = response
            return _authorization(response)
        raise core.PasskeyError(f"{key}: no response normalization implemented")


# ---------------------------------------------------------------------------
# Datacenter handoff (kurigram's own QR-login recipe)
# ---------------------------------------------------------------------------

def _auth_key_bytes(session: Any) -> Any:
    key = getattr(session, "auth_key", None)
    return getattr(key, "key", key)


def _auth_key_id(session: Any) -> Optional[int]:
    """The connection's auth key id as the signed int64 TL carries.

    Pyrogram exposes ``session.auth_key_id`` as the raw eight bytes
    ``sha1(auth_key)[-8:]`` (``session/session.py``), while
    ``finishPasskeyLogin.from_auth_key_id`` is a signed ``long``:
    ``int.from_bytes`` of those bytes, then the core's normalization.
    """
    key_id = getattr(session, "auth_key_id", None)
    unsigned = None
    if isinstance(key_id, (bytes, bytearray, memoryview)) and len(key_id) == 8:
        unsigned = int.from_bytes(bytes(key_id), "little", signed=False)
    else:
        key = _auth_key_bytes(session)
        if isinstance(key, (bytes, bytearray, memoryview)) and key:
            unsigned = int.from_bytes(
                hashlib.sha1(bytes(key)).digest()[-8:], "little", signed=False
            )
    return core.to_signed_int64(unsigned, what="connection_auth_key_id")


def _require_session(client: Any) -> Any:
    """The client's current session, or a PasskeyError about connect()."""
    session = getattr(client, "session", None)
    if session is None:
        raise core.PasskeyError(
            "the client has no session yet: await client.connect() first "
            "(client.start() is interactive and must not be used for a "
            "passkey login)"
        )
    return session


async def _dc_option(client: Any, dc_id: int) -> Any:
    getter = getattr(client, "get_dc_option", None)
    if not callable(getter):
        raise core.PasskeyError(
            f"{_distribution()} has no Client.get_session/get_dc_option, so a "
            "cross-DC passkey login cannot be completed with it (pyrofork "
            "builds sessions by hand); use kurigram >= 2.2.26, or connect a "
            "client that is already on the account's home DC"
        )
    ipv6 = bool(getattr(client, "ipv6", False))
    try:
        return await getter(dc_id, ipv6=ipv6)
    except TypeError:  # nocov - a fork whose get_dc_option takes no ipv6
        return await getter(dc_id)


async def _switch_dc(client: Any, dc_id: int) -> Dict[str, Any]:
    """Move the client to ``dc_id`` with a fresh, unauthorized auth key.

    This is kurigram's own QR-login migration (``pyrogram/qrlogin.py``):
    ``get_session(..., export_authorization=False, temporary=True)`` creates
    a *new* auth key on the target DC, then the session is swapped and the
    storage updated.  ``client.set_dc()`` is not usable here — it keeps the
    old auth key, and the passkey challenge is bound to the connection named
    in ``from_dc_id``/``from_auth_key_id``, not to the destination.

    Returns the snapshot :func:`_restore_dc` needs.
    """
    getter = getattr(client, "get_session", None)
    if not callable(getter):
        raise core.PasskeyError(
            f"{_distribution()} has no Client.get_session, so the client "
            "cannot move to the account's home DC; use kurigram >= 2.2.26 "
            "(pyrofork would need a hand-built Session + Auth.create)"
        )
    option = await _dc_option(client, dc_id)
    old_session = _require_session(client)
    snapshot = {
        "session": old_session,
        "dc_id": await client.storage.dc_id(),
        "server_address": await client.storage.server_address(),
        "port": await client.storage.port(),
        "auth_key": await client.storage.auth_key(),
    }
    new_session = await getter(
        dc_id=dc_id,
        server_address=option.ip_address,
        port=option.port,
        export_authorization=False,
        temporary=True,
    )
    client.session = new_session
    await client.storage.dc_id(dc_id)
    await client.storage.server_address(option.ip_address)
    await client.storage.port(option.port)
    await client.storage.auth_key(_auth_key_bytes(new_session))
    stop = getattr(old_session, "stop", None)
    if callable(stop):
        try:
            await stop()
        except Exception:  # nocov - a session that dislikes being closed
            pass
    return snapshot


async def _restore_dc(client: Any, snapshot: Dict[str, Any]) -> None:
    """Put the client back where it was after a failed login.

    Best effort by design: the login error is what the caller needs to see,
    so a restore that also fails is swallowed (the client is left on the
    home DC, unauthorized — the same state a failed passkey login leaves in
    any client).
    """
    current = getattr(client, "session", None)
    stop = getattr(current, "stop", None)
    if callable(stop):
        try:
            await stop()
        except Exception:  # nocov
            pass
    client.session = snapshot["session"]
    start = getattr(snapshot["session"], "start", None)
    if callable(start):
        try:
            await start()
        except Exception:  # nocov
            pass
    for name in ("dc_id", "server_address", "port", "auth_key"):
        accessor = getattr(client.storage, name, None)
        if callable(accessor):
            try:
                await accessor(snapshot[name])
            except Exception:  # nocov
                pass


# ---------------------------------------------------------------------------
# Public API (mirrors tgmint.passkeys)
# ---------------------------------------------------------------------------

def _invoker(client: Any) -> PyrogramInvoker:
    # a constructed-but-not-connected Pyrogram client answers None here
    # (`connection and connection.is_connected`), a connected one True; a
    # duck-typed client that does not expose the attribute is assumed live
    if not getattr(client, "is_connected", True):
        raise core.PasskeyError(
            "the client is not connected: await client.connect() first "
            "(client.start() is interactive and must not be used here)"
        )
    return PyrogramInvoker(client)


async def register_passkey(
    client: Any,
    *,
    path: str,
    origin: str = core.DEFAULT_ORIGIN,
    name: str = core.DEFAULT_PASSKEY_NAME,
    alg: Optional[int] = None,
) -> Tuple[core.PasskeyInfo, core.PasskeyStore]:
    """Register a new passkey on the account this client is logged into.

    Mirrors :func:`tgmint.passkeys.register_passkey`: fetch the registration
    options, mint the credential locally (ES256 or Ed25519, whatever the
    server prefers — ``alg`` overrides it), send ``account.registerPasskey``
    and save the credential to ``path`` (mode 0600, atomically).  Keep that
    file: it is the only thing needed to log in later besides a possible 2FA
    cloud password.

    The client must be an **authorized** kurigram/pyrofork client built from
    a minted fingerprint (see :func:`tgmint.adapters.pyrogram.client_kwargs`)
    and connected with ``client.connect()``.  Own account only.

    Returns ``(server_passkey_info, store)``.
    """
    return await core.register_passkey_core(
        _invoker(client),
        store_path=path,
        origin=origin,
        name=name,
        alg=alg,
    )


async def login_with_passkey(
    client: Any,
    *,
    path: str,
    origin: Optional[str] = None,
    password: Optional[str] = None,
):
    """Log a connected, unauthorized client into the passkey's account.

    The order is the official client's, and it is what the core's ceremony
    enforces:

    1. ``auth.initPasskeyLogin(api_id, api_hash)`` on the **current**
       connection (the server binds the challenge to that connection's auth
       key),
    2. sign the challenge and persist the bumped signature counter *before*
       any further network step,
    3. if the account's home DC (decoded from the passkey's user handle)
       differs from the connection's DC: move the client there with a fresh
       auth key and carry ``from_dc_id``/``from_auth_key_id`` of the
       connection that got the challenge — ``finishPasskeyLogin`` then runs
       on the home DC,
    4. ``auth.finishPasskeyLogin`` → ``auth.Authorization``,
    5. record ``user_id``/``is_bot`` in the framework storage and return the
       framework's ``types.User``.

    If the account has a 2FA cloud password the finish call answers
    ``SESSION_PASSWORD_NEEDED``; pass the password as ``password`` and
    ``client.check_password`` completes the login on the home DC. Without a
    password the neutral :class:`tgmint.passkeys_core.TwoFactorRequired`
    signal propagates unchanged (it is deliberately not a
    :class:`tgmint.passkeys_core.PasskeyError`), and the previous session is
    restored first, so calling again with ``password=`` starts from the DC the
    client originally connected to.

    A failed finish after the DC switch restores the previous session and
    storage best-effort, so a retry starts from where it left off.

    The session is not persisted here — the framework owns its storage, so
    call ``await client.storage.save()`` (or keep the client open) when you
    want the logged-in session to survive the process.

    Own account only: this logs into the account whose passkey file you
    hold.  Returns the logged-in ``me`` user.
    """
    invoker = _invoker(client)
    store = core.PasskeyStore.load(path)
    origin = origin or store.origin

    options_json = await core.fetch_login_challenge(
        invoker, api_id=client.api_id, api_hash=client.api_hash
    )
    session = _require_session(client)
    plan = await core.login_passkey_assertion(
        store,
        options_json,
        origin=origin,
        connection_dc=getattr(session, "dc_id", None),
        connection_auth_key_id=_auth_key_id(session),
        home_dc=store.home_dc,
    )

    snapshot = None
    if plan["switch_to_dc"] is not None:
        snapshot = await _switch_dc(client, plan["switch_to_dc"])

    try:
        result = await core.finish_login(invoker, plan["finish_fields"])
    except core.TwoFactorRequired:
        if password is None:
            # nothing can be finished without the password: restore the
            # session/storage first, then let the neutral 2FA signal
            # propagate unchanged (it is deliberately NOT a PasskeyError, so
            # a caller guarding against a corrupt store cannot swallow the
            # password prompt)
            if snapshot is not None:
                await _restore_dc(client, snapshot)
            raise
        # check_password finishes the login and does the same storage
        # bookkeeping, then parses the user — on the home-DC session, so the
        # switch is intentionally kept for the password step
        return await client.check_password(password)
    except BaseException:
        if snapshot is not None:
            await _restore_dc(client, snapshot)
        raise

    return await _complete_login(client, invoker, result)


async def _complete_login(
    client: Any, invoker: PyrogramInvoker, result: core.AuthorizationResult
):
    """Post-login bookkeeping (the three lines kurigram's sign_in.py uses)."""
    if result.sign_up_required:
        raise core.PasskeyError(
            "the server answered auth.authorizationSignUpRequired: no account "
            "is attached to this passkey, and passkey login cannot create one"
        )
    response = invoker.last_finish_response
    user = getattr(response, "user", None) if response is not None else None
    if user is None:
        raise core.PasskeyError(
            "finishPasskeyLogin returned an authorization without a user "
            "object; cannot finish the login bookkeeping"
        )
    user_id = getattr(user, "id", None)
    if not isinstance(user_id, int) or isinstance(user_id, bool):
        raise core.PasskeyError(
            f"the authorization user has no usable id ({user_id!r})"
        )
    await client.storage.user_id(user_id)
    await client.storage.is_bot(False)
    me = await pyrogram_types.User._parse(client, user)
    if me is None:  # nocov - a fork returning a non-User object
        raise core.PasskeyError(
            f"{_distribution()} could not parse its own user object "
            f"({type(user).__name__})"
        )
    return me


async def list_passkeys(client: Any) -> List[core.PasskeyInfo]:
    """Passkeys currently registered on the logged-in account.

    Own account only: the server answers for the account the client is
    authorized as, so this never lists anybody else's passkeys.
    """
    return await core.list_passkeys_core(_invoker(client))


async def delete_passkey(client: Any, passkey_id: str) -> bool:
    """Remove a passkey from the account (does not delete your local file).

    Own account only: it deletes a passkey *you* registered, on the account
    the client is authorized as.  The local store file is untouched — delete
    it yourself if you never want to log in with it again.
    """
    return await core.delete_passkey_core(_invoker(client), passkey_id)
