"""
Software passkeys for Telegram accounts.

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

Typical use (while logged in)::

    from tgmint.passkeys import register_passkey
    info = await register_passkey(client, path="myaccount.passkey.json")

Later, with no phone/OTP access at all::

    client = TelegramClient("recovered.session", api=API.TelegramAndroid.Generate())
    await client.connect()
    me = await login_with_passkey(client, path="myaccount.passkey.json")

Requires ``cryptography`` (only when actually creating/signing credentials).
"""
from __future__ import annotations

import base64
import dataclasses
import datetime
import hashlib
import json
import os
import re
import struct
from typing import Any, Dict, List, Optional, Tuple

from telethon.errors import SessionPasswordNeededError
from telethon.extensions import BinaryReader
from telethon.tl.tlobject import TLObject, TLRequest

__all__ = [
    "DEFAULT_ORIGIN",
    "ALG_ES256",
    "ALG_ED25519",
    "PasskeyInfo",
    "PasskeyStore",
    "PasskeyRejectedError",
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
    "register_passkey",
    "login_with_passkey",
    "list_passkeys",
    "delete_passkey",
]

# The WebAuthn origin we claim in clientDataJSON. Telegram's server supplies
# the rpId in its options; the origin string must be one it accepts. The web
# client origin is the natural choice for a software authenticator. If the
# server ever rejects the challenge (origin not allowed), try
# "android:APK_CERT_HASH_BASE64URL:<b64url sha256 of official APK cert>".
DEFAULT_ORIGIN = "https://web.telegram.org"

ALG_ES256 = -7   # ECDSA w/ SHA-256 on P-256, DER signature
ALG_ED25519 = -8 # Ed25519, raw 64-byte signature

_SUPPORTED_ALGS = (ALG_ES256, ALG_ED25519)

# Telegram encodes the account as "dcId:userId" in the WebAuthn user handle
# (e.g. "2:123456789"); everything downstream (home_dc, user_id, the login
# request) depends on that shape.
_USER_HANDLE_RE = re.compile(r"^\d+:\d+$")


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _pack_uint32(value: int) -> bytes:
    return struct.pack("<I", value)


def _dump_json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=False)


class PasskeyError(Exception):
    pass


class PasskeyRejectedError(PasskeyError):
    """The server's allow-list does not include our credential id."""


# ---------------------------------------------------------------------------
# Minimal CTAP2-canonical CBOR encoder (RFC 7049 deterministic form as used
# by WebAuthn: map keys sorted by length first, then bytewise).
# ---------------------------------------------------------------------------

def _cbor_head(major: int, length: int) -> bytes:
    if length < 24:
        return bytes([(major << 5) | length])
    if length < 0x100:
        return bytes([(major << 5) | 24, length])
    if length < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack(">H", length)
    return bytes([(major << 5) | 26]) + struct.pack(">I", length)


def _cbor_encode(item: Any) -> bytes:
    if item is True:
        return b"\xf5"
    if item is False:
        return b"\xf4"
    if item is None:
        return b"\xf6"
    if isinstance(item, int):
        if item >= 0:
            return _cbor_head(0, item)
        return _cbor_head(1, -item - 1)
    if isinstance(item, bytes):
        return _cbor_head(2, len(item)) + item
    if isinstance(item, str):
        raw = item.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(item, (list, tuple)):
        return _cbor_head(4, len(item)) + b"".join(_cbor_encode(x) for x in item)
    if isinstance(item, dict):
        entries = sorted(
            ((_cbor_encode(k), _cbor_encode(v)) for k, v in item.items()),
            key=lambda kv: (len(kv[0]), kv[0]),
        )
        return _cbor_head(5, len(entries)) + b"".join(k + v for k, v in entries)
    raise TypeError(f"cannot CBOR-encode {type(item)!r}")


# ---------------------------------------------------------------------------
# WebAuthn software authenticator
# ---------------------------------------------------------------------------

_FLAG_UP = 0x01  # user present
_FLAG_UV = 0x04  # user verified
_FLAG_AT = 0x40  # attested credential data present


def _new_keypair(alg: int) -> Tuple[Any, bytes]:
    """Returns (private_key, cose_public_key_bytes)."""
    if alg == ALG_ES256:
        from cryptography.hazmat.primitives.asymmetric import ec

        priv = ec.generate_private_key(ec.SECP256R1())
        numbers = priv.public_key().public_numbers()
        cose = _cbor_encode({
            1: 2, 3: ALG_ES256, -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        })
        return priv, cose
    if alg == ALG_ED25519:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        priv = ed25519.Ed25519PrivateKey.generate()
        raw = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        cose = _cbor_encode({1: 1, 3: ALG_ED25519, -1: raw})
        return priv, cose
    raise PasskeyError(f"unsupported algorithm {alg}; supported: {_SUPPORTED_ALGS}")


def _sign(priv: Any, alg: int, data: bytes) -> bytes:
    if alg == ALG_ES256:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        return priv.sign(data, ec.ECDSA(hashes.SHA256()))
    return priv.sign(data)


def _key_to_pem(priv: Any) -> str:
    from cryptography.hazmat.primitives import serialization

    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _key_from_pem(pem: str) -> Any:
    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_private_key(pem.encode("ascii"), password=None)


def _authenticator_data(
    rp_id: str,
    flags: int,
    sign_count: int,
    attested: Optional[Tuple[bytes, bytes]] = None,
) -> bytes:
    data = _sha256(rp_id.encode("ascii")) + bytes([flags]) + struct.pack(">I", sign_count)
    if attested is not None:
        credential_id, cose_public = attested
        # aaguid all-zero (unspecified) + credIdLen + credId + COSE key
        data += b"\x00" * 16 + struct.pack(">H", len(credential_id)) + credential_id + cose_public
    return data


@dataclasses.dataclass
class CreatedCredential:
    """A freshly minted WebAuthn credential (registration output)."""

    credential_id: bytes
    rp_id: str
    origin: str
    alg: int
    user_handle: str      # decoded "dcId:userId" string from options.user.id
    client_data_json: str
    attestation_object: bytes
    private_key_pem: str
    sign_count: int = 0


class SoftwareAuthenticator:
    """A minimal WebAuthn authenticator whose keys live in your filesystem.

    It speaks the exact subset of WebAuthn Telegram's server needs:
    ES256/Ed25519 credentials with ``fmt: "none"`` attestation, UP|UV flags
    and a monotonically increasing signature counter.
    """

    @staticmethod
    def pick_algorithm(options: Dict[str, Any]) -> int:
        offered = [p.get("alg") for p in options.get("pubKeyCredParams") or []]
        for alg in offered:
            if alg in _SUPPORTED_ALGS:
                return alg
        raise PasskeyError(
            "server offers no supported algorithm "
            f"(offered: {offered}, supported: {list(_SUPPORTED_ALGS)})"
        )

    @classmethod
    def create_credential(
        cls,
        options: Any,
        *,
        origin: str = DEFAULT_ORIGIN,
        alg: Optional[int] = None,
    ) -> CreatedCredential:
        if isinstance(options, str):
            options = json.loads(options)
        if "publicKey" in options and "rp" not in options:
            # the server wraps the WebAuthn options in a publicKey envelope,
            # same unwrap as PasskeysController.java:78-80
            options = options["publicKey"]
        rp_id = options["rp"]["id"]
        challenge = options["challenge"]
        user = options["user"]
        # options.user.id is base64url bytes of "dcId:userId"; the official
        # client decodes it before putting it on the wire, and so do we
        # (PasskeysController.java:227-230).
        raw_user_handle = user["id"]
        try:
            user_handle = _b64u_decode(raw_user_handle).decode()
        except Exception:
            user_handle = raw_user_handle
        if alg is None:
            alg = cls.pick_algorithm(options)

        priv, cose_public = _new_keypair(alg)
        credential_id = os.urandom(32)

        client_data_json = _dump_json({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": origin,
        })
        auth_data = _authenticator_data(
            rp_id, _FLAG_UP | _FLAG_UV | _FLAG_AT, 0, (credential_id, cose_public)
        )
        attestation_object = _cbor_encode({
            "fmt": "none",
            "attStmt": {},
            "authData": auth_data,
        })
        return CreatedCredential(
            credential_id=credential_id,
            rp_id=rp_id,
            origin=origin,
            alg=alg,
            user_handle=user_handle,
            client_data_json=client_data_json,
            attestation_object=attestation_object,
            private_key_pem=_key_to_pem(priv),
        )

    @staticmethod
    def produce_assertion(
        store: "PasskeyStore",
        options: Any,
        *,
        origin: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Sign a login challenge with a stored credential.

        Returns the fields needed for ``inputPasskeyResponseLogin`` and
        bumps the stored signature counter (call ``store.save()`` after).
        """
        if isinstance(options, str):
            options = json.loads(options)
        if "publicKey" in options and "rpId" not in options and "rp" not in options:
            options = options["publicKey"]
        origin = origin or store.origin
        rp_id = options.get("rpId") or store.rp_id
        if rp_id != store.rp_id:
            raise PasskeyError(
                f"rpId mismatch: stored {store.rp_id!r}, server wants {rp_id!r}"
            )
        allow = options.get("allowCredentials") or []
        if allow:
            ids = {c.get("id") for c in allow}
            if _b64u_encode(store.credential_id) not in ids:
                raise PasskeyRejectedError(
                    "this passkey is not in the server's allow-list "
                    "(deleted from the account, or a different account)"
                )

        sign_count = max(store.sign_count, 0) + 1
        client_data_json = _dump_json({
            "type": "webauthn.get",
            "challenge": options["challenge"],
            "origin": origin,
        })
        auth_data = _authenticator_data(rp_id, _FLAG_UP | _FLAG_UV, sign_count)
        # WebAuthn signs authenticatorData || sha256(clientDataJSON) — in THAT order
        signature = _sign(store.private_key, store.alg, auth_data + _sha256(client_data_json.encode()))
        store.sign_count = sign_count
        return {
            "id": _b64u_encode(store.credential_id),
            "client_data_json": client_data_json,
            "authenticator_data": auth_data,
            "signature": signature,
            # TL wants the *decoded* "dcId:userId" string (see PasskeysController.java:227)
            "user_handle": store.user_handle,
        }


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


@dataclasses.dataclass
class PasskeyInfo:
    """account.passkey#98613ebf as returned by the server."""

    id: str
    name: str
    date: int
    software_emoji_id: Optional[int] = None
    last_usage_date: Optional[int] = None

    @property
    def created_on(self) -> Optional[datetime.datetime]:
        return datetime.datetime.fromtimestamp(self.date, tz=datetime.timezone.utc) if self.date else None


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

    Response is deserialized with Telethon's own layer (auth.Authorization
    is ancient and always available)."""

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
# Passkey store (your credential — back this file up, it IS the login)
# ---------------------------------------------------------------------------

class PasskeyStore:
    """A saved software passkey: private key + credential id + user handle.

    Treat the file like a password. Losing it means logging in the old way;
    leaking it means somebody else can log in (subject to your 2FA password).
    """

    VERSION = 1

    def __init__(
        self,
        *,
        credential_id: bytes,
        rp_id: str,
        origin: str,
        alg: int,
        user_handle: str,
        private_key_pem: str,
        sign_count: int = 0,
        created_at: Optional[str] = None,
        telegram_passkey_id: Optional[str] = None,
        name: str = "tgmint software passkey",
        path: Optional[str] = None,
    ):
        self.credential_id = credential_id
        self.rp_id = rp_id
        self.origin = origin
        self.alg = alg
        self.user_handle = user_handle

        # fail fast with a clear error instead of a cryptic ValueError from
        # home_dc/user_id later — a store without a "dc:user" handle is not
        # a tgmint passkey file (or the server changed its user-handle
        # encoding, which we would need to mirror).
        if not _USER_HANDLE_RE.match(user_handle or ""):
            raise PasskeyError(
                f"passkey store has an invalid user_handle {user_handle!r} "
                "— this file does not look like a tgmint passkey store"
            )

        self.private_key_pem = private_key_pem
        self.sign_count = sign_count
        self.created_at = created_at or datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.telegram_passkey_id = telegram_passkey_id
        self.name = name
        self.path = path
        self._priv = None

    @property
    def private_key(self):
        if self._priv is None:
            self._priv = _key_from_pem(self.private_key_pem)
        return self._priv

    @property
    def home_dc(self) -> int:
        """The account's home datacenter, decoded from user_handle 'dc:userId'."""
        return int(self.user_handle.split(":")[0])

    @property
    def user_id(self) -> int:
        return int(self.user_handle.split(":")[1])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.VERSION,
            "credential_id": _b64u_encode(self.credential_id),
            "rp_id": self.rp_id,
            "origin": self.origin,
            "alg": self.alg,
            "user_handle": self.user_handle,
            "private_key": self.private_key_pem,
            "sign_count": self.sign_count,
            "created_at": self.created_at,
            "telegram_passkey_id": self.telegram_passkey_id,
            "name": self.name,
        }

    def save(self, path: Optional[str] = None) -> str:
        path = path or self.path
        if not path:
            raise PasskeyError("no path set for passkey store")
        self.path = path

        # fork note: written atomically and private from the very first
        # byte. The old plain open() created the file with the umask
        # default (often 0644) and only chmod'ed it after the write, and a
        # crash mid-write left a truncated JSON behind. We now write to a
        # temp file in the SAME directory (so os.replace never crosses a
        # filesystem), fsync it, then atomically swap it into place.
        # os.replace is atomic on POSIX and works on Windows too.
        directory = os.path.dirname(os.path.abspath(path))
        tmp = os.path.join(
            directory, f".{os.path.basename(path)}.tmp.{os.getpid()}"
        )
        payload = json.dumps(self.to_dict(), indent=2) + "\n"

        fd = os.open(
            tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
        )
        replaced = False
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                fp.write(payload)
                fp.flush()
                os.fsync(fp.fileno())
            os.replace(tmp, path)
            replaced = True
        finally:
            if not replaced:
                # the atomic swap never happened — don't leave the
                # half-written temp file (and its 0600 key) behind
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            # covers pre-existing files that may have looser permissions
            os.chmod(path, 0o600)
        return path

    @classmethod
    def load(cls, path: str) -> "PasskeyStore":
        with open(path, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        if data.get("version") != cls.VERSION:
            raise PasskeyError(f"unsupported passkey store version {data.get('version')!r}")
        return cls(
            credential_id=_b64u_decode(data["credential_id"]),
            rp_id=data["rp_id"],
            origin=data["origin"],
            alg=data["alg"],
            user_handle=data["user_handle"],
            private_key_pem=data["private_key"],
            sign_count=data.get("sign_count", 0),
            created_at=data.get("created_at"),
            telegram_passkey_id=data.get("telegram_passkey_id"),
            name=data.get("name", "tgmint software passkey"),
            path=path,
        )

    @classmethod
    def from_credential(cls, cred: CreatedCredential, path: Optional[str] = None) -> "PasskeyStore":
        return cls(
            credential_id=cred.credential_id,
            rp_id=cred.rp_id,
            origin=cred.origin,
            alg=cred.alg,
            user_handle=cred.user_handle,
            private_key_pem=cred.private_key_pem,
            sign_count=cred.sign_count,
            path=path,
        )

    def produce_assertion(self, options: Any, *, origin: Optional[str] = None) -> Dict[str, Any]:
        return SoftwareAuthenticator.produce_assertion(self, options, origin=origin)


# ---------------------------------------------------------------------------
# High-level flows
# ---------------------------------------------------------------------------

async def register_passkey(
    client,
    *,
    path: str,
    origin: str = DEFAULT_ORIGIN,
    name: str = "tgmint software passkey",
) -> Tuple[PasskeyInfo, PasskeyStore]:
    """Register a new passkey on the account this client is logged into.

    The credential is generated locally (ES256 or Ed25519, whatever the
    server prefers) and saved to ``path`` — chmod 600. Keep that file: it
    is the only thing needed to log in later besides a possible 2FA
    cloud password.

    Returns ``(server_passkey_info, store)``.
    """
    options_json = await client(InitPasskeyRegistrationRequest())
    cred = SoftwareAuthenticator.create_credential(options_json, origin=origin)
    tl_credential = InputPasskeyCredentialPublicKey(
        id=_b64u_encode(cred.credential_id),
        raw_id=_b64u_encode(cred.credential_id),
        response=InputPasskeyResponseRegister(
            client_data=_DataJSONObject(cred.client_data_json),
            attestation_data=cred.attestation_object,
        ),
    )
    info = await client(RegisterPasskeyRequest(tl_credential))
    store = PasskeyStore.from_credential(cred, path=path)
    store.name = name
    store.telegram_passkey_id = info.id
    store.save()
    return info, store


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
    If the account has a 2FA cloud password, pass it as ``password``
    (or handle ``SessionPasswordNeededError`` yourself and call
    ``client.sign_in(password=...)``).

    Returns the logged-in ``me`` user.
    """
    from telethon import utils as tl_utils

    store = PasskeyStore.load(path)
    origin = origin or store.origin

    # 1. Fetch the challenge on the CURRENT connection first — the server
    #    binds it to this connection's auth key (PasskeysController.java
    #    sends initPasskeyLogin on whatever DC the connection is on).
    options_json = await client(InitPasskeyLoginRequest(client.api_id, client.api_hash))
    assertion = store.produce_assertion(options_json, origin=origin)

    # persist the bumped signature counter BEFORE any network attempt, so
    # a failed login doesn't leave the store with a stale (reusable)
    # counter behind
    store.save()

    # 2. If the account's home DC differs, switch now and pass
    #    from_dc_id/from_auth_key_id of the connection that got the
    #    challenge — exactly like the official client does.
    home_dc = store.home_dc
    from_dc_id = None
    from_auth_key_id = None
    if getattr(client.session, "dc_id", None) not in (None, home_dc):
        from_dc_id = client.session.dc_id
        auth_key = client.session.auth_key
        from_auth_key_id = auth_key.key_id if auth_key else None
        # Telethon reads key_id UNSIGNED; the TL field is a signed long.
        # Half of all keys are >= 2**63 and failed to serialize.
        if from_auth_key_id is not None and from_auth_key_id >= 1 << 63:
            from_auth_key_id -= 1 << 64
        await client._switch_dc(home_dc)

    request = FinishPasskeyLoginRequest(
        credential=InputPasskeyCredentialPublicKey(
            id=assertion["id"],
            raw_id=assertion["id"],
            response=InputPasskeyResponseLogin(
                client_data=_DataJSONObject(assertion["client_data_json"]),
                authenticator_data=assertion["authenticator_data"],
                signature=assertion["signature"],
                user_handle=assertion["user_handle"],
            ),
        ),
        from_dc_id=from_dc_id,
        from_auth_key_id=from_auth_key_id,
    )

    try:
        result = await client(request)
    except SessionPasswordNeededError:
        if password is None:
            raise PasskeyError(
                "the account has a 2FA cloud password; call again with password=..."
            ) from None
        me = await client.sign_in(password=password)
        store.save()
        return me

    store.save()
    me = await client._on_login(result.user)
    await tl_utils.maybe_async(client.session.save())
    return me


async def list_passkeys(client) -> List[PasskeyInfo]:
    """Passkeys currently registered on the logged-in account."""
    return await client(GetPasskeysRequest())


async def delete_passkey(client, passkey_id: str) -> bool:
    """Remove a passkey from the account (does not delete your local file)."""
    return await client(DeletePasskeyRequest(passkey_id))
