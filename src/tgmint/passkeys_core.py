"""Framework-neutral data layer for Telegram software passkeys.

This module is the Telethon-free half of :mod:`tgmint.passkeys`: the
credential primitives (CTAP2-canonical CBOR, COSE keys, WebAuthn
registration/assertion signing), the local ``PasskeyStore`` file format,
and a machine-readable TL wire spec with a neutral writer/reader for the
six passkey requests and for the response shapes Telegram sends back.

Nothing here imports ``telethon`` or :mod:`tgmint.tl` — that is the point.
A Pyrogram/gramjs/TDLib driver, or a non-Python port fed by the TL spec
below, can reach the same passkey protocol without Telethon. The
framework-bound drivers live in :mod:`tgmint.passkeys` (its hand-written
TL classes plus the Telethon ceremony functions this module is the
framework-neutral half of).

Two layers live here, both Telethon-free:

* the **data layer** (already described above) — credential primitives,
  the store file, the TL spec and the neutral writer/reader; and
* the **ceremony layer** (see "Ceremony layer" near the end of the file) —
  the register/login/list/delete state machines, with every byte of
  framework I/O pushed outside through a tiny duck-typed *invoker*. The
  ordering rules that matter (persisting the bumped signature counter
  before any network step, the signed-int64 auth-key-id normalization,
  when to switch DCs and with which ``from_dc_id``/``from_auth_key_id``)
  are encoded there, so a Telethon driver and a Pyrogram-family driver are
  both thin and cannot get those rules subtly wrong.

The wire format is implemented from the official Android client source
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

VERIFICATION LABELS:

* **Credential + store layer** — copied from :mod:`tgmint.passkeys`
  without behavioural change (same helpers, same 0600/atomic file
  discipline); ``tests/test_passkeys.py`` exercises the identical code
  there, and ``tests/test_passkeys_core.py`` re-verifies the WebAuthn
  signature partner-side against the COSE public key here.
* **TL wire writer** — *fully verified offline*: byte-identical to the
  ``to_bytes()`` output of the hand-written Telethon classes for every
  message and for the nested credential/response objects, including the
  signed ``long`` ``from_auth_key_id`` edge (a value >= 2**63 is accepted
  in its unsigned form and encodes to the same two's-complement bytes).
* **TL wire reader** — *verified against the same classes' read logic*:
  the ``read_result`` implementations of :mod:`tgmint.passkeys` are copied
  onto the neutral primitives here, and the ``auth.Authorization`` result
  of ``finishPasskeyLogin`` is pinned against Telethon 1.43.2's own object
  reader. Unknown constructors raise :class:`PasskeyError` instead of
  guessing.

The spec is plain ``dict``/``list``/``int``/``str`` data so ports (and
JSON export in a later stage) can consume it directly; ``PASSKEY_TL_SPEC``
is asserted JSON-serializable in the tests.

Credits: wire format from DrKLO/Telegram (reference client) and the
public Telegram TL schemas (layer 230 constructor signatures only — no
code vendored); the credential layer is tgmint's own, adapted from the
WebAuthn (CTAP2) specifications. ``cryptography`` is imported lazily
inside the signing helpers exactly like :mod:`tgmint.passkeys`, so
importing this module needs nothing beyond the standard library.
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
from typing import Any, Dict, List, Optional, Protocol, Tuple

__all__ = [
    # credential layer (copied from tgmint.passkeys)
    "DEFAULT_ORIGIN",
    "ALG_ES256",
    "ALG_ED25519",
    "PasskeyInfo",
    "PasskeyStore",
    "PasskeyRejectedError",
    "PasskeyError",
    "SoftwareAuthenticator",
    "CreatedCredential",
    # TL wire spec + neutral (de)serializer
    "PASSKEY_TL_SPEC",
    "PASSKEY_MESSAGE_NAMES",
    "TLReader",
    "AuthorizationResult",
    "encode_request",
    "parse_result",
    # ceremony layer (state machines, all framework I/O via an invoker)
    "DEFAULT_PASSKEY_NAME",
    "TwoFactorRequired",
    "PasskeyInvoker",
    "to_signed_int64",
    "registration_fields",
    "finish_login_fields",
    "get_passkeys_fields",
    "delete_passkey_fields",
    "fetch_registration_options",
    "fetch_login_challenge",
    "register_passkey_core",
    "login_passkey_assertion",
    "finish_login",
    "list_passkeys_core",
    "delete_passkey_core",
    # private helpers, exported for parity tests and port-side auditing
    "_b64u_encode",
    "_b64u_decode",
    "_sha256",
    "_pack_uint32",
    "_dump_json",
    "_cbor_head",
    "_cbor_encode",
    "_new_keypair",
    "_sign",
    "_key_to_pem",
    "_key_from_pem",
    "_authenticator_data",
    "_serialize_tl_bytes",
    "_encode_value",
    "_decode_value",
]

# The wire constants below are mirrored in PASSKEY_TL_SPEC (further down);
# that spec is the machine-readable ground truth and the tests pin both to
# the Telethon classes, so a layer bump has exactly one place to edit.

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


# ---------------------------------------------------------------------------
# Encoding helpers (stdlib only)
# ---------------------------------------------------------------------------

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
# Passkey store (your credential — back this file up, it IS the login)
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class PasskeyInfo:
    """account.passkey#98613ebf as returned by the server.

    Telethon callers see the same class through ``tgmint.passkeys``
    (which re-exports it), so the two modules share one identity.
    """

    id: str
    name: str
    date: int
    software_emoji_id: Optional[int] = None
    last_usage_date: Optional[int] = None

    @property
    def created_on(self) -> Optional[datetime.datetime]:
        return datetime.datetime.fromtimestamp(self.date, tz=datetime.timezone.utc) if self.date else None


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
# TL wire spec (machine-readable ground truth for the neutral (de)serializer)
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

# auth.Authorization constructors as carried by Telethon 1.43.2 (layer 224).
_CTOR_AUTH_AUTHORIZATION = 0x2EA2C0D4
_CTOR_AUTH_SIGNUP_REQUIRED = 0x44747E9A

# Which user constructors we can count flag words for. ``id:long`` follows
# the last flags word, so a two-flags-word user (the current schema) needs
# a lookup instead of an assumption. Unknown constructors leave user_id
# unset rather than guessing a layout.
_USER_FLAG_WORDS = {0x31774388: 2, 0xB1B8CC83: 2}  # user#31774388 (L224), user#B1B8CC83 (L229)

PASSKEY_TL_SPEC: Dict[str, Any] = {
    "about": (
        "Telegram passkey TL wire spec as implemented by the hand-written "
        "classes in tgmint.passkeys (DrKLO/Telegram 12.10.6, TL layer 230). "
        "Scalar field types: 'int' int32, 'long' int64, 'flags' uint32 "
        "bitfield, 'bytes'/'string' TL byte strings, 'Bool' "
        "boolTrue|boolFalse, 'vector<T>' the TL Vector constructor, or the "
        "name of an object/union defined below. A field carrying 'flag' is "
        "present only when that bit of its flags field is set; 'flag_bits' "
        "names the field whose presence sets each bit."
    ),
    "layer": 230,
    "constructors": {
        "account.initPasskeyRegistration": 0x429547E8,
        "account.registerPasskey": 0x55B41FD6,
        "account.getPasskeys": 0xEA1F0C52,
        "account.deletePasskey": 0xF5B5563F,
        "auth.initPasskeyLogin": 0x518AD0B7,
        "auth.finishPasskeyLogin": 0x9857AD07,
        "inputPasskeyCredentialPublicKey": _CTOR_INPUT_CRED_PUBLIC_KEY,
        "inputPasskeyResponseRegister": _CTOR_INPUT_RESPONSE_REGISTER,
        "inputPasskeyResponseLogin": _CTOR_INPUT_RESPONSE_LOGIN,
        "dataJSON": _CTOR_DATAJSON,
        "account.passkey": _CTOR_PASSKEY,
        "account.passkeys": _CTOR_ACCOUNT_PASSKEYS,
        "account.passkeyRegistrationOptions": _CTOR_ACCOUNT_PASSKEY_REGISTRATION_OPTIONS,
        "auth.passkeyLoginOptions": _CTOR_AUTH_PASSKEY_LOGIN_OPTIONS,
    },
    "objects": {
        "dataJSON": {
            "tl_name": "dataJSON",
            "class": "_DataJSONObject",
            "constructor": _CTOR_DATAJSON,
            "fields": [{"name": "data", "type": "string"}],
        },
        "inputPasskeyCredentialPublicKey": {
            "tl_name": "inputPasskeyCredentialPublicKey",
            "class": "InputPasskeyCredentialPublicKey",
            "constructor": _CTOR_INPUT_CRED_PUBLIC_KEY,
            "fields": [
                {"name": "id", "type": "string"},
                {"name": "raw_id", "type": "string"},
                {"name": "response", "type": "InputPasskeyResponse"},
            ],
        },
        "inputPasskeyResponseRegister": {
            "tl_name": "inputPasskeyResponseRegister",
            "class": "InputPasskeyResponseRegister",
            "constructor": _CTOR_INPUT_RESPONSE_REGISTER,
            "fields": [
                {"name": "client_data", "type": "dataJSON"},
                {"name": "attestation_data", "type": "bytes"},
            ],
        },
        "inputPasskeyResponseLogin": {
            "tl_name": "inputPasskeyResponseLogin",
            "class": "InputPasskeyResponseLogin",
            "constructor": _CTOR_INPUT_RESPONSE_LOGIN,
            "fields": [
                {"name": "client_data", "type": "dataJSON"},
                {"name": "authenticator_data", "type": "bytes"},
                {"name": "signature", "type": "bytes"},
                {"name": "user_handle", "type": "string"},
            ],
        },
        "passkey": {
            "tl_name": "account.passkey",
            "class": None,  # parsed straight into PasskeyInfo (no TL class)
            "constructor": _CTOR_PASSKEY,
            "result_class": "PasskeyInfo",
            "fields": [
                {"name": "flags", "type": "flags"},
                {"name": "id", "type": "string"},
                {"name": "name", "type": "string"},
                {"name": "date", "type": "int"},
                # read_long(signed=False) in tgmint.passkeys._read_passkey —
                # the unsigned form only differs for ids >= 2**63
                {"name": "software_emoji_id", "type": "long", "flag": 0, "signed": False},
                {"name": "last_usage_date", "type": "int", "flag": 1},
            ],
            "flag_bits": {"0": "software_emoji_id", "1": "last_usage_date"},
        },
    },
    "unions": {
        "InputPasskeyCredential": {
            "tl_name": "InputPasskeyCredential",
            "constructors": ["inputPasskeyCredentialPublicKey"],
        },
        "InputPasskeyResponse": {
            "tl_name": "InputPasskeyResponse",
            "constructors": [
                "inputPasskeyResponseRegister",
                "inputPasskeyResponseLogin",
            ],
        },
    },
    "messages": {
        "initPasskeyRegistration": {
            "tl_name": "account.initPasskeyRegistration",
            "class": "InitPasskeyRegistrationRequest",
            "constructor": 0x429547E8,
            "fields": [],
            "result": {
                "kind": "options",
                "wrapper": ["account.passkeyRegistrationOptions",
                            _CTOR_ACCOUNT_PASSKEY_REGISTRATION_OPTIONS],
                "payload": ["dataJSON", _CTOR_DATAJSON],
                "type": "string",
            },
        },
        "registerPasskey": {
            "tl_name": "account.registerPasskey",
            "class": "RegisterPasskeyRequest",
            "constructor": 0x55B41FD6,
            "fields": [{"name": "credential", "type": "InputPasskeyCredential"}],
            "result": {"kind": "object", "type": "passkey", "type_name": "PasskeyInfo"},
        },
        "getPasskeys": {
            "tl_name": "account.getPasskeys",
            "class": "GetPasskeysRequest",
            "constructor": 0xEA1F0C52,
            "fields": [],
            "result": {
                "kind": "vector",
                "type": "passkey",
                "type_name": "list[PasskeyInfo]",
                "wrapper": ["account.passkeys", _CTOR_ACCOUNT_PASSKEYS],
            },
        },
        "deletePasskey": {
            "tl_name": "account.deletePasskey",
            "class": "DeletePasskeyRequest",
            "constructor": 0xF5B5563F,
            "fields": [{"name": "id", "type": "string"}],
            "result": {"kind": "bool", "type": "Bool"},
        },
        "initPasskeyLogin": {
            "tl_name": "auth.initPasskeyLogin",
            "class": "InitPasskeyLoginRequest",
            "constructor": 0x518AD0B7,
            "fields": [
                {"name": "api_id", "type": "int"},
                {"name": "api_hash", "type": "string"},
            ],
            "result": {
                "kind": "options",
                "wrapper": ["auth.passkeyLoginOptions", _CTOR_AUTH_PASSKEY_LOGIN_OPTIONS],
                "payload": ["dataJSON", _CTOR_DATAJSON],
                "type": "string",
            },
        },
        "finishPasskeyLogin": {
            "tl_name": "auth.finishPasskeyLogin",
            "class": "FinishPasskeyLoginRequest",
            "constructor": 0x9857AD07,
            "fields": [
                {"name": "flags", "type": "flags"},
                {"name": "credential", "type": "InputPasskeyCredential"},
                {"name": "from_dc_id", "type": "int", "flag": 0},
                # signed long on the wire (two's complement); Telethon's login
                # path normalizes key ids >= 2**63 to a negative Python int.
                # The writer accepts either form and emits identical bytes.
                {"name": "from_auth_key_id", "type": "long", "flag": 0, "default": 0},
            ],
            "flag_bits": {"0": "from_dc_id"},
            "note": (
                "FinishPasskeyLoginRequest.flags is derived from from_dc_id "
                "alone; from_dc_id is written for bit 0 and from_auth_key_id "
                "follows with `or 0` (see tgmint.passkeys)."
            ),
            "result": {
                "kind": "authorization",
                "type": "Authorization",
                "constructors": {
                    "authorization": _CTOR_AUTH_AUTHORIZATION,
                    "authorizationSignUpRequired": _CTOR_AUTH_SIGNUP_REQUIRED,
                },
                "note": (
                    "auth.Authorization is parsed by the caller's TL layer in "
                    "tgmint.passkeys; the neutral parser extracts the fields "
                    "the login state machine needs (user_id, tmp_sessions) and "
                    "keeps the raw bytes for the framework's own reader. "
                    "Constructor ids as carried by Telethon 1.43.2 (TL layer 224)."
                ),
            },
        },
    },
}

PASSKEY_MESSAGE_NAMES: Tuple[str, ...] = tuple(PASSKEY_TL_SPEC["messages"])


# ---------------------------------------------------------------------------
# Neutral writer: (message name, field dict) -> the exact wire bytes
# ---------------------------------------------------------------------------

def _serialize_tl_bytes(data: Any) -> bytes:
    """TL byte string (``bytes``/``string`` share this encoding).

    Byte-for-byte the same rule as ``telethon.tl.tlobject.TLObject.
    serialize_bytes`` (also used by the hand-written classes): one length
    byte for < 254 bytes (the count includes a NUL terminator that is part
    of the padding), otherwise 0xfe + a 3-byte little-endian length; the
    payload is then zero-padded to a 4-byte boundary.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    elif isinstance(data, (bytearray, memoryview)):
        data = bytes(data)
    elif not isinstance(data, bytes):
        raise PasskeyError(f"TL bytes/string expected, got {type(data)!r}")
    if len(data) < 254:
        out = bytes([len(data)]) + data
        padding = (len(data) + 1) % 4
        return out + b"\x00" * ((4 - padding) if padding else 0)
    if len(data) >= 0x1000000:
        raise PasskeyError(f"TL byte string too long: {len(data)} bytes")
    padding = len(data) % 4
    head = bytes([0xFE, len(data) % 256, (len(data) >> 8) % 256, (len(data) >> 16) % 256])
    return head + data + b"\x00" * ((4 - padding) if padding else 0)


_VECTOR_RE = re.compile(r"^vector<(.+)>$")


def _vector_item(type_name: str) -> Optional[str]:
    match = _VECTOR_RE.match(type_name)
    return match.group(1) if match else None


def _pack_int32(value: Any) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PasskeyError(f"int field expected, got {type(value)!r}")
    if not -(1 << 31) <= value < (1 << 31):
        raise PasskeyError(f"int out of range: {value}")
    return struct.pack("<i", value)


def _pack_long(value: Any) -> bytes:
    """64-bit two's complement, accepting signed or unsigned spelling.

    TL has no unsigned ``long``: a key id >= 2**63 is written as the same
    bytes whether the caller spells it positive or negative, so both are
    accepted here (a port should mask, not reject).
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise PasskeyError(f"long field expected, got {type(value)!r}")
    if not -(1 << 63) <= value < (1 << 64):
        raise PasskeyError(f"long out of range: {value}")
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def _normalize_name(name: str) -> str:
    return name.replace("_", "").replace("#", "").lower()


def _resolve_message(name: str) -> Tuple[str, Dict[str, Any]]:
    messages = PASSKEY_TL_SPEC["messages"]
    if name in messages:
        return name, messages[name]
    wanted = _normalize_name(name)
    for key, spec in messages.items():
        candidates = (spec["tl_name"], spec.get("class") or "")
        if wanted in {_normalize_name(c) for c in candidates if c}:
            return key, spec
    raise PasskeyError(
        f"unknown passkey message {name!r}; known: {sorted(messages)}"
    )


def _resolve_object(name: str) -> Tuple[Optional[str], Dict[str, Any]]:
    """Returns ``(object key, spec)``; key is None for a union."""
    objects = PASSKEY_TL_SPEC["objects"]
    if name in objects:
        return name, objects[name]
    unions = PASSKEY_TL_SPEC["unions"]
    if name in unions:
        return None, unions[name]
    wanted = _normalize_name(name)
    for key, spec in objects.items():
        candidates = (spec.get("tl_name") or "", spec.get("class") or "")
        if wanted in {_normalize_name(c) for c in candidates if c}:
            return key, spec
    for key, spec in unions.items():
        if wanted == _normalize_name(spec["tl_name"]):
            return None, spec
    raise PasskeyError(
        f"unknown passkey TL type {name!r}; known objects: {sorted(objects)}, "
        f"unions: {sorted(unions)}"
    )


def _match_constructor(name: str, candidates: List[str], what: str) -> str:
    objects = PASSKEY_TL_SPEC["objects"]
    wanted = _normalize_name(name)
    for key in candidates:
        spec = objects[key]
        spellings = (key, spec.get("tl_name") or "", spec.get("class") or "")
        if wanted in {_normalize_name(c) for c in spellings if c}:
            return key
    raise PasskeyError(
        f"{what}: {name!r} is not a constructor of this union; "
        f"expected one of {sorted(candidates)}"
    )


def _encode_value(type_name: str, value: Any) -> bytes:
    """Encode one value of a scalar/vector/object TL type."""
    if type_name == "int":
        return _pack_int32(value)
    if type_name == "long":
        return _pack_long(value)
    if type_name == "flags":
        return _pack_uint32(value)
    if type_name in ("bytes", "string"):
        return _serialize_tl_bytes(value)
    if type_name == "Bool":
        return _pack_uint32(_CTOR_BOOL_TRUE if value else _CTOR_BOOL_FALSE)
    inner = _vector_item(type_name)
    if inner is not None:
        if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
            raise PasskeyError(f"{type_name}: a list of {inner} expected")
        return (
            _pack_uint32(_CTOR_VECTOR)
            + struct.pack("<i", len(value))
            + b"".join(_encode_value(inner, item) for item in value)
        )
    return _encode_object(type_name, value)


def _encode_object(type_name: str, value: Any) -> bytes:
    key, spec = _resolve_object(type_name)
    if key is None:  # union: pick the constructor from "_" (or the only one)
        candidates = list(spec["constructors"])
        if isinstance(value, dict) and "_" in value:
            fields = dict(value)
            name = fields.pop("_")
            key = _match_constructor(name, candidates, type_name)
        elif len(candidates) == 1 and isinstance(value, dict):
            key = candidates[0]
            fields = dict(value)
        else:
            raise PasskeyError(
                f"{type_name}: give a '_' constructor name, one of {candidates}"
            )
        spec = PASSKEY_TL_SPEC["objects"][key]
    else:
        fields = dict(value) if isinstance(value, dict) else value
        if isinstance(fields, dict):
            fields.pop("_", None)

    string_fields = [f["name"] for f in spec["fields"]
                     if f["type"] == "string" and "flag" not in f]
    if isinstance(fields, str) and len(spec["fields"]) == 1 and string_fields:
        # convenience: dataJSON accepts the bare string, {"data": ...} too
        fields = {string_fields[0]: fields}
    if not isinstance(fields, dict):
        raise PasskeyError(f"{key}: a field dict expected, got {type(fields)!r}")

    return _encode_construct(spec, fields, what=key)


def _encode_construct(spec: Dict[str, Any], fields: Dict[str, Any], what: str) -> bytes:
    declared = [f["name"] for f in spec["fields"]]
    unknown = sorted(set(fields) - set(declared))
    if unknown:
        raise PasskeyError(
            f"{what}: unknown field(s) {unknown}; expected {declared}"
        )

    flags = 0
    for bit, driver in (spec.get("flag_bits") or {}).items():
        if fields.get(driver) is not None:
            flags |= 1 << int(bit)

    out = bytearray(_pack_uint32(spec["constructor"]))
    for field in spec["fields"]:
        name = field["name"]
        if field["type"] == "flags":
            out += _pack_uint32(flags)
            continue
        bit = field.get("flag")
        if bit is not None and not (flags >> bit) & 1:
            continue
        if name in fields:
            value = fields[name]
        elif "default" in field:
            # mirrors FinishPasskeyLoginRequest's `from_auth_key_id or 0`
            value = field["default"]
        else:
            raise PasskeyError(f"{what}: missing field {name!r}; expected {declared}")
        if value is None:
            raise PasskeyError(f"{what}: field {name!r} is None")
        out += _encode_value(field["type"], value)
    return bytes(out)


def encode_request(message_name: str, fields: Optional[Dict[str, Any]] = None) -> bytes:
    """Serialize a passkey request exactly as the Telethon classes do.

    ``message_name`` is the spec name (``"registerPasskey"``) or its TL or
    class spelling; ``fields`` is a field dict whose nested values are
    field dicts too, e.g.::

        encode_request("registerPasskey", {
            "credential": {
                "id": _b64u_encode(cred.credential_id),
                "raw_id": _b64u_encode(cred.credential_id),
                "response": {
                    "_": "inputPasskeyResponseRegister",
                    "client_data": {"data": cred.client_data_json},
                    "attestation_data": cred.attestation_object,
                },
            },
        })

    A union-typed field needs ``"_"`` only when the union has more than one
    implemented constructor, and a ``dataJSON`` field also accepts the bare
    string. Unknown or missing field names raise :class:`PasskeyError`
    rather than silently producing a different layout.
    """
    key, spec = _resolve_message(message_name)
    return _encode_construct(spec, dict(fields or {}), what=key)


# ---------------------------------------------------------------------------
# Neutral reader: own TL primitives + the response shapes the server sends
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class AuthorizationResult:
    """The fields of ``auth.Authorization`` the login flow actually needs.

    ``tgmint.passkeys`` hands the finish-login response to Telethon's own
    TL layer; a neutral caller has no such layer, so this parser reads the
    constructor + flags and the few fields the state machine uses
    (``user_id`` for the store cross-check, ``tmp_sessions``), and keeps
    ``raw`` intact for the framework driver to deserialize its own way.
    """

    constructor: int
    sign_up_required: bool = False
    tmp_sessions: Optional[int] = None
    otherwise_relogin_days: Optional[int] = None
    future_auth_token: Optional[bytes] = None
    user_constructor: Optional[int] = None
    user_id: Optional[int] = None
    raw: bytes = b""


class TLReader:
    """Little-endian TL primitives over one buffer.

    Deliberately self-contained (no Telethon ``BinaryReader``): uint/int32,
    int64, TL byte strings, Bool constructors and Vector<T>. Every failure
    raises :class:`PasskeyError` naming the offset, so a caller parsing a
    hostile or truncated response gets a diagnostic instead of a
    ``struct.error``.
    """

    __slots__ = ("stream", "position")

    def __init__(self, data: Any) -> None:
        if isinstance(data, (bytearray, memoryview)):
            data = bytes(data)
        if not isinstance(data, bytes):
            raise PasskeyError(f"bytes expected for a TL buffer, got {type(data)!r}")
        self.stream = data
        self.position = 0

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"TLReader({len(self.stream)} bytes, at {self.position})"

    @property
    def remaining(self) -> int:
        return len(self.stream) - self.position

    def _take(self, size: int) -> bytes:
        end = self.position + size
        if end > len(self.stream):
            raise PasskeyError(
                f"truncated TL payload: need {size} byte(s) at offset "
                f"{self.position}, have {self.remaining}"
            )
        chunk = self.stream[self.position:end]
        self.position = end
        return chunk

    def read_byte(self) -> int:
        return self._take(1)[0]

    def read_uint(self) -> int:
        return struct.unpack("<I", self._take(4))[0]

    def read_int(self) -> int:
        return struct.unpack("<i", self._take(4))[0]

    def read_long(self, signed: bool = True) -> int:
        return struct.unpack("<q" if signed else "<Q", self._take(8))[0]

    def read_bool(self) -> bool:
        constructor = self.read_uint()
        if constructor == _CTOR_BOOL_TRUE:
            return True
        if constructor == _CTOR_BOOL_FALSE:
            return False
        raise PasskeyError(
            f"unexpected constructor 0x{constructor:08x} at offset "
            f"{self.position - 4}, expected Bool"
        )

    def read_bytes(self) -> bytes:
        """TL byte string — same rule as ``tgread_bytes``."""
        first = self.read_byte()
        if first == 254:
            length = self.read_byte() | (self.read_byte() << 8) | (self.read_byte() << 16)
            padding = length % 4
        else:
            length = first
            padding = (length + 1) % 4
        data = self._take(length)
        if padding:
            self._take(4 - padding)
        return data

    def read_string(self) -> str:
        return self.read_bytes().decode("utf-8", errors="replace")

    def read_object(self, type_name: str) -> Any:
        """Read an object/union by spec name (returns its field dict)."""
        return _read_object(self, type_name)


def _decode_value(reader: TLReader, field: Dict[str, Any]) -> Any:
    """Read one value described by a spec field dict (``{"type": ...}``).

    The inverse of :func:`_encode_value`; a field dict is used rather than a
    bare type name so the ``signed`` hint of ``account.passkey``'s
    ``software_emoji_id`` travels with the read.
    """
    type_name = field["type"]
    if type_name == "int":
        return reader.read_int()
    if type_name == "long":
        return reader.read_long(signed=field.get("signed", True))
    if type_name == "flags":
        return reader.read_uint()
    if type_name == "bytes":
        return reader.read_bytes()
    if type_name == "string":
        return reader.read_string()
    if type_name == "Bool":
        return reader.read_bool()
    inner = _vector_item(type_name)
    if inner is not None:
        count = _read_vector_head(reader)
        return [_read_item(reader, inner) for _ in range(count)]
    return _read_object(reader, type_name)


def _read_item(reader: TLReader, type_name: str) -> Any:
    inner = _vector_item(type_name)
    if inner is not None:
        count = _read_vector_head(reader)
        return [_read_item(reader, inner) for _ in range(count)]
    if _looks_like_type(type_name):
        return _read_object(reader, type_name)
    # scalar item type (e.g. vector<bytes>)
    return _decode_value(reader, {"name": "item", "type": type_name})


def _looks_like_type(name: str) -> bool:
    try:
        _resolve_object(name)
    except PasskeyError:
        return False
    return True


def _read_vector_head(reader: TLReader) -> int:
    constructor = reader.read_uint()
    if constructor != _CTOR_VECTOR:
        raise PasskeyError(
            f"unexpected constructor 0x{constructor:08x}, expected Vector"
        )
    return reader.read_int()


def _read_fields(reader: TLReader, spec: Dict[str, Any], what: str) -> Dict[str, Any]:
    values: Dict[str, Any] = {}
    flags: Optional[int] = None
    for field in spec["fields"]:
        if field["type"] == "flags":
            flags = reader.read_uint()
            values[field["name"]] = flags
            continue
        bit = field.get("flag")
        if bit is not None:
            if flags is None:
                raise PasskeyError(f"{what}: flag bit {bit} before a flags field")
            if not (flags >> bit) & 1:
                continue
        try:
            values[field["name"]] = _decode_value(reader, field)
        except PasskeyError as exc:
            raise PasskeyError(f"{what}.{field['name']}: {exc}") from None
    return values


def _read_object(reader: TLReader, type_name: str) -> Dict[str, Any]:
    key, spec = _resolve_object(type_name)
    constructor = reader.read_uint()
    if key is None:  # union: dispatch on the constructor id
        candidates = list(spec["constructors"])
        for candidate in candidates:
            if PASSKEY_TL_SPEC["objects"][candidate]["constructor"] == constructor:
                key = candidate
                spec = PASSKEY_TL_SPEC["objects"][candidate]
                break
        else:
            raise PasskeyError(
                f"{type_name}: unexpected constructor 0x{constructor:08x}; "
                f"expected one of {candidates}"
            )
    elif constructor != spec["constructor"]:
        raise PasskeyError(
            f"{type_name}: unexpected constructor 0x{constructor:08x}, "
            f"expected 0x{spec['constructor']:08x}"
        )
    values = _read_fields(reader, spec, what=key)
    values["_"] = key
    return values


def _passkey_info(values: Dict[str, Any]) -> PasskeyInfo:
    return PasskeyInfo(
        id=values["id"],
        name=values["name"],
        date=values["date"],
        software_emoji_id=values.get("software_emoji_id"),
        last_usage_date=values.get("last_usage_date"),
    )


def _read_options(reader: TLReader, result: Dict[str, Any]) -> str:
    wrapper_name, wrapper_constructor = result["wrapper"]
    constructor = reader.read_uint()
    if constructor != wrapper_constructor:
        raise PasskeyError(
            f"unexpected constructor 0x{constructor:08x}, expected "
            f"{wrapper_name} (0x{wrapper_constructor:08x})"
        )
    payload_name, payload_constructor = result["payload"]
    constructor = reader.read_uint()
    if constructor != payload_constructor:
        raise PasskeyError(
            f"expected {payload_name} (0x{payload_constructor:08x}) inside "
            f"{wrapper_name}, got 0x{constructor:08x}"
        )
    return reader.read_string()


def _read_authorization(reader: TLReader, raw: bytes) -> AuthorizationResult:
    constructor = reader.read_uint()
    if constructor == _CTOR_AUTH_SIGNUP_REQUIRED:
        # auth.authorizationSignUpRequired#44747e9a
        #     flags:# terms_of_service:flags.0?help.TermsOfService
        # (the terms-of-service object is left to the framework's TL layer,
        # exactly like everything else that is not login state)
        reader.read_uint()
        return AuthorizationResult(
            constructor=constructor,
            sign_up_required=True,
            raw=raw,
        )
    if constructor != _CTOR_AUTH_AUTHORIZATION:
        raise PasskeyError(
            f"unexpected constructor 0x{constructor:08x}, expected "
            f"auth.authorization (0x{_CTOR_AUTH_AUTHORIZATION:08x}) or "
            f"auth.authorizationSignUpRequired (0x{_CTOR_AUTH_SIGNUP_REQUIRED:08x})"
        )
    # auth.authorization#2ea2c0d4 flags:# setup_password_required:flags.1?true
    #     otherwise_relogin_days:flags.1?int tmp_sessions:flags.0?int
    #     future_auth_token:flags.2?bytes user:User
    flags = reader.read_uint()
    result = AuthorizationResult(constructor=constructor, raw=raw)
    if flags & 2:
        result.otherwise_relogin_days = reader.read_int()
    if flags & 1:
        result.tmp_sessions = reader.read_int()
    if flags & 4:
        result.future_auth_token = reader.read_bytes()
    result.user_constructor = reader.read_uint()
    flag_words = _USER_FLAG_WORDS.get(result.user_constructor, 0)
    if flag_words == 0:
        # unknown user constructor: do not guess where id:long sits
        return result
    for _ in range(flag_words):
        reader.read_uint()
    result.user_id = reader.read_long(signed=True)
    return result


def parse_result(message_name: str, payload: Any) -> Any:
    """Parse one server response for ``message_name`` (see the ``result``
    entries in :data:`PASSKEY_TL_SPEC`).

    The expectations are the ones :mod:`tgmint.passkeys` encodes in each
    class's ``read_result``: the two init calls return the raw WebAuthn
    options JSON, ``registerPasskey`` returns a :class:`PasskeyInfo`,
    ``getPasskeys`` a list of them, ``deletePasskey`` a ``bool``, and
    ``finishPasskeyLogin`` an :class:`AuthorizationResult`.
    """
    if isinstance(payload, TLReader):
        raise PasskeyError("parse_result expects bytes, not a TLReader")
    key, spec = _resolve_message(message_name)
    result = spec["result"]
    reader = TLReader(payload)
    kind = result["kind"]
    if kind == "options":
        return _read_options(reader, result)
    if kind == "bool":
        return reader.read_bool()
    if kind == "object":
        if result["type"] != "passkey":
            raise PasskeyError(f"{key}: unhandled object result {result['type']!r}")
        return _passkey_info(_read_object(reader, "passkey"))
    if kind == "vector":
        wrapper_name, wrapper_constructor = result["wrapper"]
        constructor = reader.read_uint()
        if constructor != wrapper_constructor:
            raise PasskeyError(
                f"unexpected constructor 0x{constructor:08x}, expected "
                f"{wrapper_name} (0x{wrapper_constructor:08x})"
            )
        count = _read_vector_head(reader)
        items = [_read_object(reader, result["type"]) for _ in range(count)]
        return [_passkey_info(item) for item in items]
    if kind == "authorization":
        return _read_authorization(reader, reader.stream)
    raise PasskeyError(f"{key}: unhandled result kind {kind!r}")


# ---------------------------------------------------------------------------
# Ceremony layer: the passkey state machines, with all framework I/O outside
# ---------------------------------------------------------------------------
#
# Everything above is data and wire format. What follows is the *ceremony*:
# the two multi-step flows a driver used to have to re-derive (and could get
# wrong), expressed so that registration and login are a sequence of pure
# steps plus one invoke per network round trip.
#
# The ground truth is :mod:`tgmint.passkeys`, whose ``register_passkey`` and
# ``login_with_passkey`` were verified against the official Android client.
# The rules this layer pins, in the order they matter:
#
#   REGISTRATION
#     1. initPasskeyRegistration            -> options JSON (WebAuthn create)
#     2. SoftwareAuthenticator.create_credential(options, origin)
#     3. registration_fields(cred)          -> the registerPasskey field dict
#                                              (spec-validated by encode_request
#                                              BEFORE the driver sees it)
#     4. registerPasskey                    -> account.passkey -> PasskeyInfo
#     5. PasskeyStore.from_credential(cred) -> name + telegram_passkey_id,
#                                              saved atomically with mode 0600
#
#   LOGIN
#     1. initPasskeyLogin(api_id, api_hash) -> options JSON (WebAuthn get)
#     2. store.produce_assertion(options)   -> bumps the stored counter
#     3. store.save()                       -> **BEFORE any network-bound step
#                                              after the bump** (passkeys.py:
#                                              a failed login must not leave a
#                                              stale, reusable counter behind)
#     4. from_dc_id/from_auth_key_id when the connection DC is not the
#        account's home DC (auth key id taken from the CONNECTION that got
#        the challenge, normalized to the signed int64 TL carries)
#     5. driver switches DC if switch_to_dc says so
#     6. finishPasskeyLogin                 -> auth.Authorization
#
# ---------------------------------------------------------------------------
# The invoker contract
# ---------------------------------------------------------------------------
#
# A driver is any object with ONE of these two async methods:
#
#   await invoker.request_bytes(name, fields) -> bytes
#       The generic path. ``name`` is a :data:`PASSKEY_TL_SPEC` message name
#       ("registerPasskey", ...), ``fields`` is the exact field dict
#       :func:`encode_request` accepts. The driver serializes the request with
#       its framework, sends it, and returns the server's **raw response
#       bytes** — this module parses them with :func:`parse_result`.
#
#   await invoker.native(name, fields) -> Any
#       The structured path. Same arguments, but the driver returns its
#       framework's already-parsed object (or the neutral shape directly).
#       Accepted per message:
#         initPasskeyRegistration / initPasskeyLogin -> the options JSON ``str``
#         registerPasskey  -> a PasskeyInfo, or any object/dict carrying
#                             ``id``, ``name``, ``date`` and optionally
#                             ``software_emoji_id``/``last_usage_date``
#         getPasskeys      -> a list/tuple of those, or an object whose
#                             ``passkeys`` attribute holds the list
#                             (``account.passkeys`` in every framework)
#         deletePasskey    -> a ``bool``
#         finishPasskeyLogin -> the raw bytes OR an
#                             :class:`AuthorizationResult`; a framework's own
#                             auth.Authorization object must be normalized by
#                             the driver (only the driver knows how its
#                             framework names the fields).
#       Anything else, and anything that does not fit the message, raises
#       :class:`PasskeyError` — no silent guessing.
#
# If an object has both methods, ``request_bytes`` wins: it is the path whose
# output this module can always interpret. Drivers should implement exactly
# one.
#
# The invoker must not raise framework exceptions for the 2FA case: when the
# framework reports SESSION_PASSWORD_NEEDED, the driver raises
# :class:`TwoFactorRequired` and the *driver* decides which
# password-check call to make afterwards. This module never learns what a
# "sign_in"/"check_password" is, and never calls one.
#
# A Telethon driver gets raw bytes by overriding ``read_result`` on a copy of
# the hand-written request class (the sender calls
# ``request.read_result(reader)``), so ``request_bytes`` and ``native`` are
# both implementable without touching this module. A kurigram/pyrofork
# driver has the generated classes and returns them from ``native``
# (attribute adoption above), or returns raw bytes if it can capture them.
#
# Nothing in this section imports a framework, opens a socket, or writes
# anything except the passkey store file.
# ---------------------------------------------------------------------------


DEFAULT_PASSKEY_NAME = "tgmint software passkey"
"""Store name used when the caller does not pick one."""


class TwoFactorRequired(Exception):
    """Neutral signal: the account is protected by a 2FA cloud password.

    A driver raises this from its ``request_bytes``/``native`` method when
    the framework reports that ``finishPasskeyLogin`` answered
    SESSION_PASSWORD_NEEDED; the *driver* then decides which password-check
    call to make (Telethon: ``client.sign_in(password=...)``; pyrogram:
    ``check_password``) and whether to re-run the ceremony.

    Deliberately **not** a :class:`PasskeyError`: a caller that guards
    against corrupted data or a dead credential must not swallow a 2FA
    prompt along with it.
    """

    def __init__(self, message: str = "the account has a 2FA cloud password"):
        super().__init__(message)


class PasskeyInvoker(Protocol):
    """The duck-typed driver contract: implement ONE of the two methods.

    This class is documentation that a type checker can read — the ceremony
    functions never call ``isinstance`` against it, they look the methods up
    (``request_bytes`` first, then ``native``), so a driver does not have to
    import or subclass anything. See the section comment above for what each
    message must return on each path.
    """

    async def request_bytes(self, name: str, fields: Dict[str, Any]) -> bytes:
        """Send ``name`` and return the server's raw response bytes."""
        ...

    async def native(self, name: str, fields: Dict[str, Any]) -> Any:
        """Send ``name`` and return the framework's parsed result."""
        ...


def to_signed_int64(value: Optional[int], *, what: str = "auth_key_id") -> Optional[int]:
    """Normalize an auth key id to the signed 64-bit form TL's ``long`` wants.

    Frameworks expose the auth key id as an **unsigned** 64-bit integer
    (``sha1(auth_key)[-8:]``), but ``finishPasskeyLogin.from_auth_key_id`` is
    a signed ``long``: half of all key ids are >= 2**63 and used to fail to
    serialize. :mod:`tgmint.passkeys` fixes this by subtracting 2**64
    (passkeys.py:928-933); this is that exact normalization, framework
    neutral, and idempotent for values that are already negative.

    ``None`` passes through (a connection without an auth key yet), non-int
    values and values outside ``[-2**63, 2**64)`` raise :class:`PasskeyError`.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise PasskeyError(f"{what} must be an int or None, got {type(value)!r}")
    if value >= 1 << 63:
        if value >= 1 << 64:
            raise PasskeyError(f"{what} does not fit a 64-bit key id: {value}")
        return value - (1 << 64)
    if value < -(1 << 63):
        raise PasskeyError(f"{what} does not fit a 64-bit key id: {value}")
    return value


def _resolve_invoker(invoker: Any) -> Tuple[Any, bool]:
    """Returns ``(callable, is_native_path)`` for a driver object."""
    if invoker is None:
        raise PasskeyError(
            "a passkey invoker is required: an object with an async "
            "request_bytes(name, fields) or native(name, fields) method"
        )
    request_bytes = getattr(invoker, "request_bytes", None)
    if callable(request_bytes):
        return request_bytes, False
    native = getattr(invoker, "native", None)
    if callable(native):
        return native, True
    raise PasskeyError(
        f"{type(invoker).__name__} is not a passkey invoker: implement an async "
        "request_bytes(name, fields) -> bytes or native(name, fields) -> object"
    )


_PASSKEY_INFO_FIELDS = (
    "id", "name", "date", "software_emoji_id", "last_usage_date",
)


def _adopt_passkey_info(value: Any, *, what: str) -> PasskeyInfo:
    """Accept a PasskeyInfo, a foreign object with the same attributes, or a dict."""
    if isinstance(value, PasskeyInfo):
        return value
    if isinstance(value, dict):
        values = {name: value.get(name) for name in _PASSKEY_INFO_FIELDS}
    else:
        values = {name: getattr(value, name, None) for name in _PASSKEY_INFO_FIELDS}
    missing = [name for name in ("id", "name", "date") if values[name] is None]
    if missing:
        raise PasskeyError(
            f"{what}: cannot read an account.passkey out of "
            f"{type(value).__name__} (missing {missing}); return the response "
            "bytes instead and let tgmint parse them"
        )
    return PasskeyInfo(**values)


def _adopt_result(message_name: str, value: Any) -> Any:
    """Normalize one ``native`` result to the neutral shape for a message."""
    key, spec = _resolve_message(message_name)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return parse_result(key, bytes(value))
    kind = spec["result"]["kind"]
    if kind == "options":
        if isinstance(value, str):
            return value
        raise PasskeyError(
            f"{key}: a native invoker must return the options JSON as str, "
            f"got {type(value).__name__}"
        )
    if kind == "bool":
        if isinstance(value, bool):
            return value
        raise PasskeyError(
            f"{key}: a native invoker must return a bool, got {type(value).__name__}"
        )
    if kind == "object":
        return _adopt_passkey_info(value, what=key)
    if kind == "vector":
        if isinstance(value, (list, tuple)):
            items = list(value)
        else:
            # account.passkeys#f8e0aa1c passkeys:Vector<Passkey> — every
            # framework names the attribute after the TL field
            items = getattr(value, "passkeys", None)
            if items is None:
                raise PasskeyError(
                    f"{key}: a native invoker must return a list of passkeys "
                    f"(or an object with a .passkeys list), got "
                    f"{type(value).__name__}"
                )
            items = list(items)
        return [_adopt_passkey_info(item, what=key) for item in items]
    if kind == "authorization":
        if isinstance(value, AuthorizationResult):
            return value
        raise PasskeyError(
            f"{key}: a native invoker must return the response bytes or an "
            f"AuthorizationResult, got {type(value).__name__} — normalize your "
            "framework's auth.Authorization in the driver"
        )
    raise PasskeyError(f"{key}: unhandled result kind {kind!r}")


async def _invoke(invoker: Any, message_name: str, fields: Optional[Dict[str, Any]]) -> Any:
    """One ceremony step: validate the field dict, invoke, normalize the result.

    The field dict is serialized with :func:`encode_request` *first*, so a
    driver never has to defend against a malformed ceremony: an unknown or
    missing field fails here with a :class:`PasskeyError` naming it.
    """
    key, _ = _resolve_message(message_name)
    payload = dict(fields or {})
    encode_request(key, payload)
    call, is_native = _resolve_invoker(invoker)
    value = await call(key, payload)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return parse_result(key, bytes(value))
    if not is_native:
        raise PasskeyError(
            f"{key}: request_bytes must return the raw response bytes, got "
            f"{type(value).__name__} — use the native(name, fields) path for "
            "already-parsed results"
        )
    return _adopt_result(key, value)


# --- field-dict builders (pure, spec-validated, no I/O) --------------------

def registration_fields(cred: CreatedCredential) -> Dict[str, Any]:
    """The ``registerPasskey`` field dict for a freshly created credential.

    ``id`` and ``raw_id`` are both the base64url credential id (the official
    client sends the same value twice), and the nested response is
    ``inputPasskeyResponseRegister{client_data:dataJSON, attestation_data}``
    exactly as :func:`encode_request` / :data:`PASSKEY_TL_SPEC` describe it.
    """
    if not isinstance(cred, CreatedCredential):
        raise PasskeyError(
            f"registration_fields expects a CreatedCredential, got {type(cred).__name__}"
        )
    encoded_id = _b64u_encode(cred.credential_id)
    return {
        "credential": {
            "id": encoded_id,
            "raw_id": encoded_id,
            "response": {
                "_": "inputPasskeyResponseRegister",
                "client_data": {"data": cred.client_data_json},
                "attestation_data": cred.attestation_object,
            },
        },
    }


def finish_login_fields(
    assertion: Dict[str, Any],
    *,
    from_dc_id: Optional[int] = None,
    from_auth_key_id: Optional[int] = None,
) -> Dict[str, Any]:
    """The ``finishPasskeyLogin`` field dict for a produced assertion.

    ``assertion`` is what :meth:`SoftwareAuthenticator.produce_assertion`
    returns. ``from_auth_key_id`` is only sent when ``from_dc_id`` is set
    (``FinishPasskeyLoginRequest.flags`` derives from ``from_dc_id`` alone,
    so a bare key id is dropped on the wire) and is normalized to the signed
    int64 spelling here, so a driver cannot reintroduce the >= 2**63 bug.
    """
    if not isinstance(assertion, dict):
        raise PasskeyError(f"assertion must be a dict, got {type(assertion).__name__}")
    missing = [
        name for name in
        ("id", "client_data_json", "authenticator_data", "signature", "user_handle")
        if name not in assertion
    ]
    if missing:
        raise PasskeyError(
            f"assertion is missing {missing}; pass the dict returned by "
            "SoftwareAuthenticator.produce_assertion / PasskeyStore.produce_assertion"
        )
    fields: Dict[str, Any] = {
        "credential": {
            "id": assertion["id"],
            "raw_id": assertion["id"],
            "response": {
                "_": "inputPasskeyResponseLogin",
                "client_data": {"data": assertion["client_data_json"]},
                "authenticator_data": assertion["authenticator_data"],
                "signature": assertion["signature"],
                "user_handle": assertion["user_handle"],
            },
        },
    }
    if from_dc_id is not None:
        fields["from_dc_id"] = _require_int32(from_dc_id, what="from_dc_id")
        key_id = to_signed_int64(from_auth_key_id, what="from_auth_key_id")
        if key_id is not None:
            fields["from_auth_key_id"] = key_id
    return fields


def get_passkeys_fields() -> Dict[str, Any]:
    """``account.getPasskeys`` takes no arguments."""
    return {}


def delete_passkey_fields(passkey_id: str) -> Dict[str, Any]:
    """``account.deletePasskey id:string``."""
    if not isinstance(passkey_id, str):
        raise PasskeyError(f"passkey_id must be a str, got {type(passkey_id)!r}")
    return {"id": passkey_id}


def _require_int32(value: Any, *, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PasskeyError(f"{what} must be an int, got {type(value)!r}")
    if not -(1 << 31) <= value < (1 << 31):
        raise PasskeyError(f"{what} out of range: {value}")
    return value


# --- ceremony steps --------------------------------------------------------

async def fetch_registration_options(invoker: PasskeyInvoker) -> str:
    """Step 1 of registration: ``initPasskeyRegistration`` -> options JSON."""
    return await _invoke(invoker, "initPasskeyRegistration", {})


async def fetch_login_challenge(invoker: PasskeyInvoker, *, api_id: int, api_hash: str) -> str:
    """Step 1 of login: ``initPasskeyLogin`` -> options JSON.

    Sent on the **current** connection: the server binds the challenge to
    that connection's auth key, which is why the driver has to hand the
    connection's DC id and auth key id to :func:`login_passkey_assertion`
    later if it switches DCs. Works on an unauthorized connection — that is
    the whole point of passkey login.
    """
    return await _invoke(
        invoker, "initPasskeyLogin", {"api_id": api_id, "api_hash": api_hash}
    )


async def register_passkey_core(
    invoker: PasskeyInvoker,
    *,
    store_path: str,
    origin: str = DEFAULT_ORIGIN,
    name: str = DEFAULT_PASSKEY_NAME,
    alg: Optional[int] = None,
) -> Tuple[PasskeyInfo, PasskeyStore]:
    """Register a passkey on the account the driver is authorized as.

    Mirrors :func:`tgmint.passkeys.register_passkey` step for step: fetch the
    options, mint the credential locally (``alg`` overrides the server's
    preference; both are validated), send ``registerPasskey``, then write the
    store to ``store_path`` with the server's passkey id and ``name``.

    The store is written **after** the server accepted the credential, so a
    failed registration leaves no file behind, and it uses the same
    atomic-and-0600 writer as everywhere else in this module. The file is
    interchangeable with :class:`tgmint.passkeys.PasskeyStore`.

    Returns ``(server_passkey_info, store)``.
    """
    if not isinstance(store_path, str) or not store_path:
        raise PasskeyError("store_path is required (where the passkey file is written)")
    options_json = await fetch_registration_options(invoker)
    cred = SoftwareAuthenticator.create_credential(options_json, origin=origin, alg=alg)
    info = await _invoke(invoker, "registerPasskey", registration_fields(cred))
    if not isinstance(info, PasskeyInfo):  # defensive: _adopt_result guarantees it
        raise PasskeyError(f"registerPasskey returned {type(info).__name__}, not PasskeyInfo")
    store = PasskeyStore.from_credential(cred, path=store_path)
    store.name = name
    store.telegram_passkey_id = info.id
    store.save()
    return info, store


async def login_passkey_assertion(
    store: PasskeyStore,
    options_json: str,
    *,
    origin: Optional[str] = None,
    connection_dc: Optional[int] = None,
    connection_auth_key_id: Optional[int] = None,
    home_dc: Optional[int] = None,
    persist: bool = True,
) -> Dict[str, Any]:
    """Sign the login challenge and plan the ``finishPasskeyLogin`` call.

    This is the pure part of login: no invoker, no network. It signs
    ``options_json`` with the stored credential, **persists the bumped
    signature counter before returning** (passkeys.py: never let a failed
    login leave a stale, reusable counter behind), and works out the
    cross-DC handoff.

    ``connection_dc``/``connection_auth_key_id`` describe the connection that
    received the challenge. When that DC is not the account's ``home_dc``
    (default: the DC decoded from the store's user handle), the official
    client switches DC and passes the old connection's
    ``from_dc_id``/``from_auth_key_id``; the auth key id is normalized with
    :func:`to_signed_int64` because TL's ``long`` is signed and half of all
    key ids are >= 2**63.

    Returns::

        {
          "finish_fields": {...},   # the finished finishPasskeyLogin field dict
          "switch_to_dc": int|None, # DC the driver must switch to first, or None
          "assertion": {...},       # raw produce_assertion output (audit/debug)
          "home_dc": int,
          "from_dc_id": int|None,
          "from_auth_key_id": int|None,
        }

    ``persist=False`` skips the store write and is only for callers that keep
    the counter elsewhere; a store without a ``path`` raises
    :class:`PasskeyError` instead of silently skipping the save.
    """
    origin = origin or store.origin
    assertion = store.produce_assertion(options_json, origin=origin)
    if persist:
        if not getattr(store, "path", None):
            raise PasskeyError(
                "cannot persist the bumped signature counter: the passkey store "
                "has no path (load it with PasskeyStore.load(path)); passing "
                "persist=False leaves the stored counter stale and reusable"
            )
        store.save()

    home = store.home_dc if home_dc is None else _require_int32(home_dc, what="home_dc")
    from_dc_id = None
    from_auth_key_id = None
    switch_to_dc = None
    if connection_dc is not None:
        connection_dc = _require_int32(connection_dc, what="connection_dc")
        if connection_dc != home:
            from_dc_id = connection_dc
            from_auth_key_id = to_signed_int64(
                connection_auth_key_id, what="connection_auth_key_id"
            )
            switch_to_dc = home

    return {
        "finish_fields": finish_login_fields(
            assertion, from_dc_id=from_dc_id, from_auth_key_id=from_auth_key_id
        ),
        "switch_to_dc": switch_to_dc,
        "assertion": assertion,
        "home_dc": home,
        "from_dc_id": from_dc_id,
        "from_auth_key_id": from_auth_key_id,
    }


async def finish_login(invoker: PasskeyInvoker, fields: Dict[str, Any]) -> AuthorizationResult:
    """Last step of login: ``finishPasskeyLogin`` -> the login state.

    ``fields`` is ``plan["finish_fields"]`` from
    :func:`login_passkey_assertion`; the driver must already have switched to
    ``plan["switch_to_dc"]`` when that is not ``None``.

    If the account has a 2FA cloud password the invoker raises
    :class:`TwoFactorRequired` and that propagates unchanged — this module
    has no password entry point by design.

    The result's ``raw`` field keeps the response bytes, so a driver can still
    feed its own TL layer (Telethon needs the real ``auth.Authorization``
    object for ``client._on_login``) without asking for the bytes twice.
    """
    if not isinstance(fields, dict):
        raise PasskeyError(f"fields must be a dict, got {type(fields).__name__}")
    result = await _invoke(invoker, "finishPasskeyLogin", fields)
    if not isinstance(result, AuthorizationResult):  # defensive: _adopt_result
        raise PasskeyError(
            f"finishPasskeyLogin returned {type(result).__name__}, not AuthorizationResult"
        )
    return result


async def list_passkeys_core(invoker: PasskeyInvoker) -> List[PasskeyInfo]:
    """``account.getPasskeys`` for the authorized account."""
    result = await _invoke(invoker, "getPasskeys", get_passkeys_fields())
    return list(result)


async def delete_passkey_core(invoker: PasskeyInvoker, passkey_id: str) -> bool:
    """``account.deletePasskey`` — removes the server copy, never the local file."""
    return await _invoke(invoker, "deletePasskey", delete_passkey_fields(passkey_id))
