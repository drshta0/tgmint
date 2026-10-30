"""Offline tests for tgmint.passkeys_core — the framework-neutral layer.

Three invariants are pinned here, none of which needs the network or an
account:

* **Telethon-free** — the module must import and sign with ``telethon``
  (and ``tgmint.tl`` / ``tgmint.passkeys``) poisoned, and its own import
  list must contain nothing but the standard library.  That is what makes
  the passkey protocol reachable from Pyrogram-family drivers and from the
  non-Python ports the repo's TL spec pack is meant to feed.
* **Byte identity** — the neutral writer must produce exactly the bytes
  the hand-written Telethon classes in :mod:`tgmint.passkeys` produce.
  Telethon is the oracle and is imported in THIS TEST ONLY; every message
  (including both spellings of the signed ``long`` ``from_auth_key_id``
  edge) is compared against a real class instance, never against a
  literal array that could drift with the module.
* **Parser parity** — the neutral reader must return the same values those
  classes' ``read_result`` implementations return (and Telethon's own
  object reader for ``auth.Authorization``), and an assertion produced by
  the neutral authenticator must still verify against the COSE public key
  recomputed from the attestation object, exactly as Telegram's server
  would check it.

The CBOR/COSE helpers below are the test-only mirror of the decoder in
``tests/test_passkeys.py`` (kept local so neither test module imports the
other).
"""

import ast
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import types
import unittest

import tgmint.passkeys_core as core
from tgmint.passkeys_core import (
    ALG_ED25519,
    ALG_ES256,
    AuthorizationResult,
    PasskeyError,
    PasskeyInfo,
    PasskeyStore,
    SoftwareAuthenticator,
    TLReader,
    encode_request,
    parse_result,
)

# The oracle: the hand-written Telethon classes. Imported in the TEST only.
from telethon.extensions import BinaryReader
from telethon.tl.tlobject import TLObject
from tgmint.passkeys import (
    DeletePasskeyRequest,
    FinishPasskeyLoginRequest,
    GetPasskeysRequest,
    InitPasskeyLoginRequest,
    InitPasskeyRegistrationRequest,
    InputPasskeyCredentialPublicKey,
    InputPasskeyResponseLogin,
    InputPasskeyResponseRegister,
    RegisterPasskeyRequest,
    _DataJSONObject,
)
from tgmint.passkeys import PasskeyInfo as TelethonPasskeyInfo

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")


# ---------------------------------------------------------------------------
# Test-only CBOR / COSE helpers (mirror of tests/test_passkeys.py)
# ---------------------------------------------------------------------------

def cbor_decode(data):
    item, offset = _cbor_item(data, 0)
    assert offset == len(data), "trailing bytes after CBOR item"
    return item


def _cbor_item(data, pos):
    ib = data[pos]
    pos += 1
    major, info = ib >> 5, ib & 0x1F
    if major == 0:
        value, pos = _cbor_uint(data, pos, info)
        return value, pos
    if major == 1:
        value, pos = _cbor_uint(data, pos, info)
        return -1 - value, pos
    if major in (2, 3):
        length, pos = _cbor_uint(data, pos, info)
        raw = data[pos:pos + length]
        assert len(raw) == length
        return (raw if major == 2 else raw.decode()), pos + length
    if major == 4:
        length, pos = _cbor_uint(data, pos, info)
        items = []
        for _ in range(length):
            item, pos = _cbor_item(data, pos)
            items.append(item)
        return items, pos
    if major == 5:
        length, pos = _cbor_uint(data, pos, info)
        result = {}
        for _ in range(length):
            key, pos = _cbor_item(data, pos)
            value, pos = _cbor_item(data, pos)
            result[key] = value
        return result, pos
    if major == 7:
        if info == 20:
            return False, pos
        if info == 21:
            return True, pos
        if info == 22:
            return None, pos
    raise ValueError(f"unsupported CBOR major {major} info {info}")


def _cbor_uint(data, pos, info):
    if info < 24:
        return info, pos
    if info == 24:
        return data[pos], pos + 1
    if info == 25:
        return struct.unpack_from(">H", data, pos)[0], pos + 2
    if info == 26:
        return struct.unpack_from(">I", data, pos)[0], pos + 4
    raise ValueError("additional info too large for tests")


def parse_auth_data(auth_data):
    """(rp_id_hash, flags, sign_count, credential_id, cose) per WebAuthn."""
    assert len(auth_data) >= 37
    rp_id_hash = auth_data[:32]
    flags = auth_data[32]
    sign_count = struct.unpack_from(">I", auth_data, 33)[0]
    rest = auth_data[37:]
    credential_id = cose = None
    if flags & 0x40:
        (cred_len,) = struct.unpack_from(">H", rest, 16)
        credential_id = rest[18:18 + cred_len]
        cose, _ = _cbor_item(rest, 18 + cred_len)
    return rp_id_hash, flags, sign_count, credential_id, cose


def cose_to_public_key(cose):
    alg = cose[3]
    if alg == ALG_ES256:
        from cryptography.hazmat.primitives.asymmetric import ec

        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(cose[-2], "big"),
            int.from_bytes(cose[-3], "big"),
            ec.SECP256R1(),
        ).public_key()
    if alg == ALG_ED25519:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        return ed25519.Ed25519PublicKey.from_public_bytes(cose[-1])
    raise ValueError(alg)


def verify_assertion(public_key, alg, client_data_json, auth_data, signature):
    """The check Telegram's server performs on an assertion."""
    signed = auth_data + hashlib.sha256(client_data_json.encode()).digest()
    if alg == ALG_ES256:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    else:
        public_key.verify(signature, signed)


# ---------------------------------------------------------------------------
# Fixed fixtures
# ---------------------------------------------------------------------------

CREDENTIAL_ID = bytes(range(32))
CREDENTIAL_B64 = core._b64u_encode(CREDENTIAL_ID)
CLIENT_DATA = '{"type":"webauthn.create","challenge":"abc","origin":"https://web.telegram.org"}'
LOGIN_CLIENT_DATA = '{"type":"webauthn.get"}'
AUTH_DATA = b"\x00" * 37
SIGNATURE = b"\x09" * 64
API_HASH = "b18441a1ff607e10a989891a5462e627"
USER_HANDLE = "2:123456789"

REGISTRATION_OPTIONS = json.dumps({
    "rp": {"id": "web.telegram.org", "name": "Telegram"},
    "user": {"id": core._b64u_encode(b"2:123456789"), "name": "user", "displayName": "User"},
    "challenge": core._b64u_encode(b"\x01" * 32),
    "pubKeyCredParams": [
        {"type": "public-key", "alg": -7},
        {"type": "public-key", "alg": -8},
    ],
    "timeout": 60000,
    "attestation": "none",
})


def login_options(challenge: bytes, credential_id_b64: str, rp_id="web.telegram.org") -> str:
    return json.dumps({
        "challenge": core._b64u_encode(challenge),
        "rpId": rp_id,
        "allowCredentials": [{"type": "public-key", "id": credential_id_b64}],
        "timeout": 60000,
        "userVerification": "required",
    })


def _register_fields(client_data=CLIENT_DATA, attestation=b"\x01\x02", b64=CREDENTIAL_B64):
    return {
        "credential": {
            "id": b64,
            "raw_id": b64,
            "response": {
                "_": "inputPasskeyResponseRegister",
                "client_data": client_data,
                "attestation_data": attestation,
            },
        },
    }


def _register_request(client_data=CLIENT_DATA, attestation=b"\x01\x02", b64=CREDENTIAL_B64):
    return RegisterPasskeyRequest(InputPasskeyCredentialPublicKey(
        b64, b64,
        InputPasskeyResponseRegister(_DataJSONObject(client_data), attestation),
    ))


def _login_fields(user_handle=USER_HANDLE, **extra):
    fields = {
        "credential": {
            "id": "BBB",
            "raw_id": "BBB",
            "response": {
                "_": "inputPasskeyResponseLogin",
                "client_data": LOGIN_CLIENT_DATA,
                "authenticator_data": AUTH_DATA,
                "signature": SIGNATURE,
                "user_handle": user_handle,
            },
        },
    }
    fields.update(extra)
    return fields


def _login_request(user_handle=USER_HANDLE, **extra):
    return FinishPasskeyLoginRequest(
        InputPasskeyCredentialPublicKey(
            "BBB", "BBB",
            InputPasskeyResponseLogin(
                _DataJSONObject(LOGIN_CLIENT_DATA), AUTH_DATA, SIGNATURE, user_handle,
            ),
        ),
        **extra,
    )


def _passkey_payload(passkey_id="cred-id", name="My Passkey", date=1730000000,
                     emoji=None, last_usage=None):
    """One account.passkey#98613ebf body, written with the test's own packers."""
    flags = (1 if emoji is not None else 0) | (2 if last_usage is not None else 0)
    body = (
        struct.pack("<I", 0x98613EBF)
        + struct.pack("<I", flags)
        + TLObject.serialize_bytes(passkey_id)
        + TLObject.serialize_bytes(name)
        + struct.pack("<i", date)
    )
    if emoji is not None:
        body += struct.pack("<Q", emoji & 0xFFFFFFFFFFFFFFFF)
    if last_usage is not None:
        body += struct.pack("<i", last_usage)
    return body


# ---------------------------------------------------------------------------
# 1. the module must be importable (and usable) without Telethon
# ---------------------------------------------------------------------------

class TelethonFreeImportTest(unittest.TestCase):
    """The whole point of this module: no Telethon, no tgmint.tl."""

    ALLOWED_IMPORT_ROOTS = {
        "__future__", "base64", "dataclasses", "datetime", "hashlib", "json",
        "os", "re", "struct", "typing", "cryptography",
    }

    def _imported_roots(self):
        with open(core.__file__, "r", encoding="utf-8") as fp:
            tree = ast.parse(fp.read(), filename=core.__file__)
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:  # a relative import would be package-internal
                    roots.add("." * node.level + (node.module or ""))
                elif node.module:
                    roots.add(node.module.split(".")[0])
        return roots

    def test_source_imports_only_stdlib(self):
        roots = self._imported_roots()
        # every import in passkeys_core.py, as written — this is the AST
        # assertion that keeps the module framework-neutral
        self.assertEqual(roots - self.ALLOWED_IMPORT_ROOTS, set())
        self.assertNotIn("telethon", roots)
        self.assertNotIn("tgmint", roots)

    def test_spec_names_match_the_tl_binaries(self):
        # No Telethon on the import side — but the SPEC must still name the
        # constructors the Telethon classes use (drift guard, oracle side).
        import tgmint.passkeys as passkeys

        for name, spec in core.PASSKEY_TL_SPEC["messages"].items():
            self.assertIn(spec["class"], passkeys.__all__, name)
            self.assertEqual(getattr(passkeys, spec["class"]).CONSTRUCTOR_ID,
                             spec["constructor"], name)
            self.assertEqual(core.PASSKEY_TL_SPEC["constructors"][spec["tl_name"]],
                             spec["constructor"], name)
        for name, spec in core.PASSKEY_TL_SPEC["objects"].items():
            cls_name = spec.get("class")
            if not cls_name:
                continue
            cls = getattr(passkeys, cls_name)
            self.assertEqual(cls.CONSTRUCTOR_ID, spec["constructor"], name)
            self.assertEqual(core.PASSKEY_TL_SPEC["constructors"][spec["tl_name"]],
                             spec["constructor"], name)

    def test_all_exported_names_exist(self):
        for name in core.__all__:
            self.assertTrue(hasattr(core, name), name)

    def test_package_exports_it_lazily(self):
        # PEP 562 lazy export: `from tgmint import passkeys_core` must work
        # without that path importing anything Telethon-bound
        from tgmint import passkeys_core as exported

        self.assertIs(exported, core)

    def test_works_with_telethon_poisoned(self):
        """Import + register + sign in a subprocess where Telethon is a trap."""
        script = r'''
import json, sys

BLOCKED = ("telethon", "tgmint.tl", "tgmint.passkeys")
for _name in BLOCKED:
    sys.modules[_name] = None

class _Blocker:
    def find_spec(self, name, path=None, target=None):
        for blocked in BLOCKED:
            if name == blocked or name.startswith(blocked + "."):
                raise ImportError("blocked in test: " + name)
        return None

sys.meta_path.insert(0, _Blocker())

import tgmint.passkeys_core as core
from tgmint import passkeys_core as _lazy_core  # PEP 562 lazy export
assert _lazy_core is core

options = json.dumps({
    "rp": {"id": "web.telegram.org", "name": "Telegram"},
    "user": {"id": core._b64u_encode(b"2:123456789"), "name": "u", "displayName": "U"},
    "challenge": core._b64u_encode(b"\x02" * 32),
    "pubKeyCredParams": [{"type": "public-key", "alg": -7},
                         {"type": "public-key", "alg": -8}],
})
cred = core.SoftwareAuthenticator.create_credential(options)
store = core.PasskeyStore.from_credential(cred)
assertion = core.SoftwareAuthenticator.produce_assertion(
    store,
    json.dumps({"challenge": core._b64u_encode(b"\x03" * 32),
                "rpId": "web.telegram.org"}),
)
wire = core.encode_request("finishPasskeyLogin", {
    "credential": {
        "id": assertion["id"], "raw_id": assertion["id"],
        "response": {
            "_": "inputPasskeyResponseLogin",
            "client_data": assertion["client_data_json"],
            "authenticator_data": assertion["authenticator_data"],
            "signature": assertion["signature"],
            "user_handle": assertion["user_handle"],
        },
    },
})
assert wire[:4] == b"\x07\xadW\x98", wire[:4]
assert store.user_id == 123456789 and store.home_dc == 2

# ... and the whole ceremony layer, through the documented invoker contract
import asyncio, struct

class Driver:
    def __init__(self):
        self.calls = []

    async def request_bytes(self, name, fields):
        self.calls.append(name)
        if name == "initPasskeyLogin":
            options = json.dumps({
                "challenge": core._b64u_encode(b"\x05" * 32),
                "rpId": "web.telegram.org",
            })
            return (struct.pack("<I", 0xE2037789) + struct.pack("<I", 0x7D748D04)
                    + core._serialize_tl_bytes(options))
        # auth.authorization#2ea2c0d4 flags=0 user:user#31774388
        return (struct.pack("<I", 0x2EA2C0D4) + struct.pack("<I", 0)
                + struct.pack("<I", 0x31774388) + struct.pack("<I", 0)
                + struct.pack("<I", 0) + struct.pack("<q", 123456789))

async def ceremony():
    driver = Driver()
    options = await core.fetch_login_challenge(driver, api_id=2040, api_hash="h")
    plan = await core.login_passkey_assertion(store, options, persist=False)
    assert plan["switch_to_dc"] is None, plan["switch_to_dc"]
    result = await core.finish_login(driver, plan["finish_fields"])
    assert isinstance(result, core.AuthorizationResult), result
    assert result.user_id == 123456789, result
    assert driver.calls == ["initPasskeyLogin", "finishPasskeyLogin"], driver.calls
    return plan

asyncio.run(ceremony())
print("POISONED-OK", wire[:4].hex())
'''
        env = dict(os.environ, PYTHONPATH=_SRC)
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("POISONED-OK", proc.stdout)
        # the poison trap must never have been tripped by the module itself
        self.assertNotIn("blocked in test", proc.stderr)


# ---------------------------------------------------------------------------
# 2. the machine-readable spec
# ---------------------------------------------------------------------------

class SpecTest(unittest.TestCase):
    def test_spec_is_json_serializable(self):
        # ports (and a later stage's JSON export) consume this verbatim
        self.assertEqual(json.loads(json.dumps(core.PASSKEY_TL_SPEC)),
                         core.PASSKEY_TL_SPEC)

    def test_all_six_messages_are_described(self):
        self.assertEqual(
            list(core.PASSKEY_TL_SPEC["messages"]),
            ["initPasskeyRegistration", "registerPasskey", "getPasskeys",
             "deletePasskey", "initPasskeyLogin", "finishPasskeyLogin"],
        )
        self.assertEqual(len(core.PASSKEY_MESSAGE_NAMES), 6)

    def test_flag_bits_reference_declared_fields(self):
        for section in ("messages", "objects"):
            for name, spec in core.PASSKEY_TL_SPEC[section].items():
                fields = {f["name"] for f in spec["fields"]}
                for bit, driver in (spec.get("flag_bits") or {}).items():
                    self.assertIn(driver, fields, (name, bit))
                for field in spec["fields"]:
                    if "flag" in field:
                        self.assertIn(int(field["flag"]),
                                      {int(b) for b in (spec.get("flag_bits") or {})},
                                      (name, field["name"]))

    def test_field_types_are_known(self):
        known = {"int", "long", "flags", "bytes", "string", "Bool"}
        known |= set(core.PASSKEY_TL_SPEC["objects"])
        known |= set(core.PASSKEY_TL_SPEC["unions"])
        for section in ("messages", "objects"):
            for name, spec in core.PASSKEY_TL_SPEC[section].items():
                for field in spec["fields"]:
                    type_name = field["type"]
                    inner = core._vector_item(type_name)
                    if inner is not None:
                        self.assertIn(inner, known, (name, field["name"]))
                    else:
                        self.assertIn(type_name, known, (name, field["name"]))

    def test_spec_matches_the_telethon_docstring_in_passkeys(self):
        """The six constructors are the ones passkeys.py documents."""
        doc = __import__("tgmint.passkeys", fromlist=["passkeys"]).__doc__
        for name, spec in core.PASSKEY_TL_SPEC["messages"].items():
            self.assertIn(f"{spec['tl_name']}#{spec['constructor']:08x}", doc, name)


# ---------------------------------------------------------------------------
# 3. byte identity with the Telethon classes (the writer's ground truth)
# ---------------------------------------------------------------------------

class TlByteIdentityTest(unittest.TestCase):
    """encode_request(...) == bytes(real Telethon class instance)."""

    def test_init_registration(self):
        self.assertEqual(encode_request("initPasskeyRegistration"),
                         bytes(InitPasskeyRegistrationRequest()))

    def test_get_passkeys(self):
        self.assertEqual(encode_request("getPasskeys"), bytes(GetPasskeysRequest()))

    def test_delete_passkey(self):
        for passkey_id in ("x", "cred-id", "A" * 200, "pässkey" * 40):
            with self.subTest(passkey_id=len(passkey_id)):
                self.assertEqual(
                    encode_request("deletePasskey", {"id": passkey_id}),
                    bytes(DeletePasskeyRequest(passkey_id)),
                )

    def test_init_passkey_login(self):
        for api_id, api_hash in ((2040, API_HASH), (1, ""), (2**31 - 1, "h")): 
            with self.subTest(api_id=api_id):
                self.assertEqual(
                    encode_request("initPasskeyLogin",
                                   {"api_id": api_id, "api_hash": api_hash}),
                    bytes(InitPasskeyLoginRequest(api_id, api_hash)),
                )

    def test_register_passkey(self):
        self.assertEqual(encode_request("registerPasskey", _register_fields()),
                         bytes(_register_request()))

    def test_register_passkey_crosses_the_long_string_boundary(self):
        # >= 254 bytes switches TLObject.serialize_bytes to 0xfe + 3-byte length
        for length in (253, 254, 255, 1023):
            client_data = '{"type":"webauthn.create","pad":"' + "A" * length + '"}'
            with self.subTest(length=length):
                self.assertEqual(
                    encode_request("registerPasskey",
                                   _register_fields(client_data=client_data)),
                    bytes(_register_request(client_data=client_data)),
                )

    def test_finish_passkey_login_plain(self):
        self.assertEqual(encode_request("finishPasskeyLogin", _login_fields()),
                         bytes(_login_request()))
        # flags 0 — no from_dc_id, nothing trailing
        self.assertEqual(encode_request("finishPasskeyLogin", _login_fields())[4:8],
                         b"\x00\x00\x00\x00")

    def test_finish_passkey_login_dc_migration(self):
        auth_key_id = 0x1122334455667788  # < 2**63: the signed long is positive
        self.assertEqual(
            encode_request("finishPasskeyLogin",
                           _login_fields(from_dc_id=2, from_auth_key_id=auth_key_id)),
            bytes(_login_request(from_dc_id=2, from_auth_key_id=auth_key_id)),
        )

    def test_finish_passkey_login_signed_long_high_bit(self):
        """key_id >= 2**63: Telethon normalizes to a negative int, the wire is
        two's complement — the neutral writer accepts the unsigned spelling
        and must emit identical bytes."""
        for value in ((1 << 63) + 0x1234567, (1 << 64) - 1):
            signed = value - (1 << 64)
            with self.subTest(value=hex(value)):
                neutral = encode_request(
                    "finishPasskeyLogin",
                    _login_fields(from_dc_id=2, from_auth_key_id=value),
                )
                telethon = bytes(_login_request(from_dc_id=2,
                                                from_auth_key_id=signed))
                self.assertEqual(neutral, telethon)
                self.assertEqual(neutral[-8:], struct.pack("<Q", value))

    def test_finish_passkey_login_drops_auth_key_id_without_dc(self):
        # FinishPasskeyLoginRequest.flags comes from from_dc_id alone, so a
        # bare from_auth_key_id is dropped; the neutral writer mirrors it.
        self.assertEqual(
            encode_request("finishPasskeyLogin",
                           _login_fields(from_auth_key_id=0x1122334455667788)),
            bytes(_login_request(from_auth_key_id=0x1122334455667788)),
        )

    def test_every_message_in_the_spec_encodes(self):
        fields = {
            "initPasskeyRegistration": None,
            "registerPasskey": _register_fields(),
            "getPasskeys": None,
            "deletePasskey": {"id": "x"},
            "initPasskeyLogin": {"api_id": 2040, "api_hash": API_HASH},
            "finishPasskeyLogin": _login_fields(),
        }
        for name in core.PASSKEY_MESSAGE_NAMES:
            with self.subTest(message=name):
                wire = encode_request(name, fields[name])
                self.assertEqual(wire[0:4], struct.pack("<I",
                                 core.PASSKEY_TL_SPEC["messages"][name]["constructor"]))

    def test_writer_accepts_tl_and_class_spellings(self):
        expected = encode_request("registerPasskey", _register_fields())
        for spelling in ("account.registerPasskey", "RegisterPasskeyRequest",
                         "registerPasskey"):
            with self.subTest(spelling=spelling):
                self.assertEqual(
                    encode_request(spelling, _register_fields()), expected)

    def test_writer_accepts_bare_string_client_data(self):
        fields = _register_fields()
        fields["credential"]["response"]["client_data"] = {"data": CLIENT_DATA}
        self.assertEqual(encode_request("registerPasskey", fields),
                         bytes(_register_request()))
        fields["credential"]["response"]["client_data"] = CLIENT_DATA
        self.assertEqual(encode_request("registerPasskey", fields),
                         bytes(_register_request()))

    def test_writer_rejects_unknown_and_missing_fields(self):
        with self.assertRaises(PasskeyError):
            encode_request("deletePasskey", {"idd": "x"})
        with self.assertRaises(PasskeyError):
            encode_request("deletePasskey", {})
        with self.assertRaises(PasskeyError):
            encode_request("finishPasskeyLogin", {"credential": {"id": "a"}})

    def test_writer_rejects_out_of_range_ints(self):
        with self.assertRaises(PasskeyError):
            encode_request("initPasskeyLogin", {"api_id": 1 << 31, "api_hash": "h"})
        with self.assertRaises(PasskeyError):
            encode_request("finishPasskeyLogin",
                           _login_fields(from_dc_id=2, from_auth_key_id=1 << 64))

    def test_byte_identity_example(self):
        """One named vector, so a port can diff against this test."""
        wire = encode_request(
            "finishPasskeyLogin", _login_fields(from_dc_id=2,
                                                from_auth_key_id=0x1122334455667788))
        self.assertEqual(wire, bytes(_login_request(
            from_dc_id=2, from_auth_key_id=0x1122334455667788)))
        self.assertEqual(wire[:16].hex(), "07ad5798" + "01000000" + "8fb7273c" + "03424242")
        self.assertEqual(wire[-12:].hex(), "02000000" + "8877665544332211")


# ---------------------------------------------------------------------------
# 4. parser parity with the Telethon read_result implementations
# ---------------------------------------------------------------------------

class TlParseTest(unittest.TestCase):
    def test_registration_options(self):
        options = '{"publicKey": {"challenge": "abc"}}'
        payload = (
            struct.pack("<I", 0xE16B5CE1)
            + struct.pack("<I", 0x7D748D04)
            + TLObject.serialize_bytes(options)
        )
        self.assertEqual(parse_result("initPasskeyRegistration", payload),
                         InitPasskeyRegistrationRequest.read_result(BinaryReader(payload)))
        self.assertEqual(parse_result("initPasskeyRegistration", payload), options)

    def test_login_options(self):
        options = '{"challenge": "xyz", "rpId": "web.telegram.org"}'
        payload = (
            struct.pack("<I", 0xE2037789)
            + struct.pack("<I", 0x7D748D04)
            + TLObject.serialize_bytes(options)
        )
        self.assertEqual(parse_result("initPasskeyLogin", payload),
                         InitPasskeyLoginRequest.read_result(BinaryReader(payload)))

    def test_register_passkey_result(self):
        cases = [
            _passkey_payload(),
            _passkey_payload("cred-2", "Two", 1730001000, emoji=12345678901234567,
                             last_usage=1730002000),
            # software_emoji_id is read UNSIGNED: values >= 2**63 must survive
            _passkey_payload("cred-3", "Three", 1730003000, emoji=(1 << 63) + 5),
        ]
        for payload in cases:
            with self.subTest(payload=payload[:20].hex()):
                oracle = RegisterPasskeyRequest.read_result(BinaryReader(payload))
                mine = parse_result("registerPasskey", payload)
                self.assertIsInstance(mine, PasskeyInfo)
                self.assertEqual(
                    (mine.id, mine.name, mine.date, mine.software_emoji_id,
                     mine.last_usage_date),
                    (oracle.id, oracle.name, oracle.date, oracle.software_emoji_id,
                     oracle.last_usage_date),
                )

    def test_get_passkeys_result(self):
        for count in (0, 1, 3):
            bodies = [_passkey_payload(f"cred-{i}", f"P{i}", 1730000000 + i) for i in range(count)]
            payload = (
                struct.pack("<I", 0xF8E0AA1C)
                + struct.pack("<I", 0x1CB5C415)
                + struct.pack("<i", count)
                + b"".join(bodies)
            )
            with self.subTest(count=count):
                oracle = GetPasskeysRequest.read_result(BinaryReader(payload))
                mine = parse_result("getPasskeys", payload)
                self.assertEqual([p.id for p in mine], [p.id for p in oracle])
                self.assertEqual(len(mine), count)
                self.assertTrue(all(isinstance(p, PasskeyInfo) for p in mine))

    def test_delete_passkey_result(self):
        for constructor, expected in ((0x997275B5, True), (0xBC799737, False)):
            payload = struct.pack("<I", constructor)
            with self.subTest(constructor=hex(constructor)):
                self.assertIs(parse_result("deletePasskey", payload),
                              DeletePasskeyRequest.read_result(BinaryReader(payload)))
                self.assertIs(parse_result("deletePasskey", payload), expected)

    def test_finish_login_authorization(self):
        from telethon.tl.types import User, auth

        for tmp_sessions in (None, 2, 30):
            payload = bytes(auth.Authorization(
                user=User(id=777000, first_name="A"), tmp_sessions=tmp_sessions))
            oracle = BinaryReader(payload).tgread_object()
            with self.subTest(tmp_sessions=tmp_sessions):
                mine = parse_result("finishPasskeyLogin", payload)
                self.assertIsInstance(mine, AuthorizationResult)
                self.assertEqual(mine.constructor, oracle.CONSTRUCTOR_ID)
                self.assertEqual(mine.user_id, oracle.user.id)
                self.assertEqual(mine.tmp_sessions, oracle.tmp_sessions)
                self.assertFalse(mine.sign_up_required)
                self.assertEqual(mine.raw, payload)

    def test_finish_login_sign_up_required(self):
        payload = struct.pack("<I", 0x44747E9A) + struct.pack("<I", 0)
        mine = parse_result("finishPasskeyLogin", payload)
        self.assertTrue(mine.sign_up_required)
        self.assertIsNone(mine.user_id)

    def test_parser_rejects_bad_constructors(self):
        with self.assertRaises(PasskeyError):
            parse_result("deletePasskey", struct.pack("<I", 0x12345678))
        with self.assertRaises(PasskeyError):
            parse_result("registerPasskey", struct.pack("<I", 0x12345678))
        with self.assertRaises(PasskeyError):
            parse_result("initPasskeyRegistration", struct.pack("<I", 0x12345678))
        with self.assertRaises(PasskeyError):
            parse_result("finishPasskeyLogin", struct.pack("<I", 0x12345678))

    def test_parser_rejects_truncated_payloads(self):
        full = _passkey_payload("cred-id", "n", 1730000000, emoji=7)
        for cut in (1, 3, 4, 8, 12, len(full) - 2):
            with self.subTest(cut=cut):
                with self.assertRaises(PasskeyError):
                    parse_result("registerPasskey", full[:cut])
        with self.assertRaises(PasskeyError):
            parse_result("getPasskeys", b"")

    def test_vector_and_bytes_primitives(self):
        items = [b"a", b"xy", b"", b"Z" * 300]
        wire = core._encode_value("vector<bytes>", items)
        self.assertEqual(wire[:8], struct.pack("<II", 0x1CB5C415, len(items)))
        reader = TLReader(wire)
        self.assertEqual(
            core._decode_value(reader, {"name": "items", "type": "vector<bytes>"}),
            items,
        )
        self.assertEqual(reader.remaining, 0)


# ---------------------------------------------------------------------------
# 5. crypto parity: the assertion verifies like the server would check it
# ---------------------------------------------------------------------------

class CryptoParityTest(unittest.TestCase):
    def _register(self, alg, challenge=b"\x01" * 32):
        return SoftwareAuthenticator.create_credential(
            REGISTRATION_OPTIONS, origin=core.DEFAULT_ORIGIN, alg=alg)

    def test_registration_attestation_shape(self):
        for alg in (ALG_ES256, ALG_ED25519):
            with self.subTest(alg=alg):
                cred = self._register(alg)
                att = cbor_decode(cred.attestation_object)
                self.assertEqual(att["fmt"], "none")
                self.assertEqual(att["attStmt"], {})
                rp_id_hash, flags, sign_count, credential_id, cose = parse_auth_data(
                    att["authData"])
                self.assertEqual(rp_id_hash, hashlib.sha256(b"web.telegram.org").digest())
                self.assertEqual(flags, 0x01 | 0x04 | 0x40)
                self.assertEqual(sign_count, 0)
                self.assertEqual(credential_id, cred.credential_id)
                self.assertEqual(cose[3], alg)
                self.assertEqual(cred.user_handle, USER_HANDLE)

    def _assert_assertion_verifies(self, alg):
        cred = self._register(alg)
        _, _, _, _, cose = parse_auth_data(
            cbor_decode(cred.attestation_object)["authData"])
        public_key = cose_to_public_key(cose)   # rebuilt from the COSE blob only
        store = PasskeyStore.from_credential(cred)

        challenge = b"\x07" * 32
        assertion = store.produce_assertion(
            login_options(challenge, core._b64u_encode(cred.credential_id)))
        self.assertEqual(store.sign_count, 1)

        rp_id_hash, flags, sign_count, credential_id, cose2 = parse_auth_data(
            assertion["authenticator_data"])
        self.assertEqual(rp_id_hash, hashlib.sha256(b"web.telegram.org").digest())
        self.assertEqual(flags, 0x01 | 0x04)   # no AT in an assertion
        self.assertEqual(sign_count, 1)
        self.assertIsNone(credential_id)
        self.assertIsNone(cose2)
        self.assertEqual(json.loads(assertion["client_data_json"]),
                         {"type": "webauthn.get",
                          "challenge": core._b64u_encode(challenge),
                          "origin": core.DEFAULT_ORIGIN})
        self.assertEqual(assertion["user_handle"], USER_HANDLE)
        # the signature covers authenticatorData || sha256(clientDataJSON)
        verify_assertion(public_key, alg, assertion["client_data_json"],
                         assertion["authenticator_data"], assertion["signature"])
        return store, public_key, assertion

    def test_es256_assertion_verifies_against_cose_key(self):
        self._assert_assertion_verifies(ALG_ES256)

    def test_ed25519_assertion_verifies_against_cose_key(self):
        self._assert_assertion_verifies(ALG_ED25519)

    def test_signature_counter_increments(self):
        store, public_key, first = self._assert_assertion_verifies(ALG_ES256)
        second = store.produce_assertion(
            login_options(b"\x08" * 32, core._b64u_encode(store.credential_id)))
        self.assertEqual(store.sign_count, 2)
        _, _, sign_count, _, _ = parse_auth_data(second["authenticator_data"])
        self.assertEqual(sign_count, 2)
        verify_assertion(public_key, ALG_ES256, second["client_data_json"],
                         second["authenticator_data"], second["signature"])
        self.assertNotEqual(first["signature"], second["signature"])

    def test_tampered_signature_fails(self):
        store, public_key, assertion = self._assert_assertion_verifies(ALG_ES256)
        tampered = bytearray(assertion["signature"])
        tampered[0] ^= 0x01
        with self.assertRaises(Exception):
            verify_assertion(public_key, ALG_ES256, assertion["client_data_json"],
                             assertion["authenticator_data"], bytes(tampered))
        # a tampered clientDataJSON (challenge swap) breaks it too
        other = login_options(b"\x09" * 32, core._b64u_encode(store.credential_id))
        swapped = json.loads(other)["challenge"]
        cdj = json.loads(assertion["client_data_json"])
        cdj["challenge"] = swapped
        with self.assertRaises(Exception):
            verify_assertion(public_key, ALG_ES256, core._dump_json(cdj),
                             assertion["authenticator_data"], assertion["signature"])

    def test_allowlist_rejection(self):
        cred = self._register(ALG_ES256)
        store = PasskeyStore.from_credential(cred)
        with self.assertRaises(core.PasskeyRejectedError):
            store.produce_assertion(
                login_options(b"\x0a" * 32, core._b64u_encode(b"not-our-key")))

    def test_rp_id_mismatch_rejected(self):
        cred = self._register(ALG_ES256)
        store = PasskeyStore.from_credential(cred)
        with self.assertRaises(PasskeyError):
            store.produce_assertion(login_options(
                b"\x0b" * 32, core._b64u_encode(cred.credential_id),
                rp_id="evil.example.org"))

    def test_algorithm_selection(self):
        self.assertEqual(
            SoftwareAuthenticator.pick_algorithm(json.loads(REGISTRATION_OPTIONS)),
            ALG_ES256,
        )
        with self.assertRaises(PasskeyError):
            SoftwareAuthenticator.pick_algorithm(
                {"pubKeyCredParams": [{"alg": -257}]})


# ---------------------------------------------------------------------------
# 6. store persistence (0600 + atomic), and the assertion -> wire handoff
# ---------------------------------------------------------------------------

class StoreTest(unittest.TestCase):
    def _store(self):
        cred = SoftwareAuthenticator.create_credential(
            REGISTRATION_OPTIONS, alg=ALG_ES256)
        return PasskeyStore.from_credential(cred)

    def test_save_is_private_and_leaves_no_temp_file(self):
        store = self._store()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k.json")
            store.save(path)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(sorted(os.listdir(tmp)), ["k.json"])
            with open(path, encoding="utf-8") as fp:
                data = json.load(fp)
            self.assertEqual(data["version"], 1)
            self.assertIn("BEGIN PRIVATE KEY", data["private_key"])

    def test_load_roundtrip(self):
        store = self._store()
        store.telegram_passkey_id = "server-id"
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k.json")
            store.save(path)
            loaded = PasskeyStore.load(path)
        self.assertEqual(loaded.credential_id, store.credential_id)
        self.assertEqual(loaded.user_handle, USER_HANDLE)
        self.assertEqual(loaded.home_dc, 2)
        self.assertEqual(loaded.user_id, 123456789)
        self.assertEqual(loaded.telegram_passkey_id, "server-id")
        self.assertEqual(loaded.private_key_pem, store.private_key_pem)

    def test_malformed_user_handle_rejected(self):
        for handle in ("garbage", "2:", "2:1:2", ""):
            with self.subTest(handle=handle):
                with self.assertRaises(PasskeyError):
                    PasskeyStore(
                        credential_id=CREDENTIAL_ID,
                        rp_id="web.telegram.org",
                        origin=core.DEFAULT_ORIGIN,
                        alg=ALG_ES256,
                        user_handle=handle,
                        private_key_pem="-----BEGIN PRIVATE KEY-----\n",
                    )

    def test_store_files_are_interchangeable_with_tgmint_passkeys(self):
        """A file written by one module's PasskeyStore loads in the other's.

        Stage 2 writes with whichever module its driver imports; the on-disk
        format has to stay identical (the private key is the login).
        """
        from tgmint import passkeys as bound

        with tempfile.TemporaryDirectory() as tmp:
            bound_path = os.path.join(tmp, "bound.json")
            neutral_path = os.path.join(tmp, "neutral.json")

            bound_store = bound.PasskeyStore.from_credential(
                bound.SoftwareAuthenticator.create_credential(
                    REGISTRATION_OPTIONS, alg=ALG_ES256),
                path=bound_path,
            )
            bound_store.save()
            loaded = PasskeyStore.load(bound_path)
            self.assertEqual(loaded.credential_id, bound_store.credential_id)
            self.assertEqual(loaded.private_key_pem, bound_store.private_key_pem)

            neutral_store = PasskeyStore.from_credential(
                SoftwareAuthenticator.create_credential(
                    REGISTRATION_OPTIONS, alg=ALG_ED25519),
                path=neutral_path,
            )
            neutral_store.save()
            reread = bound.PasskeyStore.load(neutral_path)
            self.assertEqual(reread.credential_id, neutral_store.credential_id)
            self.assertEqual(reread.alg, ALG_ED25519)

    def test_assertion_feeds_the_wire_writer(self):
        """The neutral authenticator's output goes straight onto the wire,
        and the neutral writer matches the Telethon class for those values."""
        store = self._store()
        assertion = store.produce_assertion(
            login_options(b"\x0c" * 32, core._b64u_encode(store.credential_id)))
        fields = _login_fields(user_handle=assertion["user_handle"])
        fields["credential"]["id"] = assertion["id"]
        fields["credential"]["raw_id"] = assertion["id"]
        fields["credential"]["response"].update({
            "client_data": assertion["client_data_json"],
            "authenticator_data": assertion["authenticator_data"],
            "signature": assertion["signature"],
        })
        fields.update({"from_dc_id": 2, "from_auth_key_id": 0x7F00000000000001})
        wire = encode_request("finishPasskeyLogin", fields)

        oracle = FinishPasskeyLoginRequest(
            InputPasskeyCredentialPublicKey(
                assertion["id"], assertion["id"],
                InputPasskeyResponseLogin(
                    _DataJSONObject(assertion["client_data_json"]),
                    assertion["authenticator_data"],
                    assertion["signature"],
                    assertion["user_handle"],
                ),
            ),
            from_dc_id=2,
            from_auth_key_id=0x7F00000000000001,
        )
        self.assertEqual(wire, bytes(oracle))

        # and the credential our authenticator minted survives the round trip
        reader = TLReader(wire)
        reader.read_uint()          # auth.finishPasskeyLogin
        reader.read_uint()          # flags
        credential = reader.read_object("InputPasskeyCredential")
        self.assertEqual(core._b64u_decode(credential["id"]), store.credential_id)
        self.assertEqual(credential["response"]["user_handle"], USER_HANDLE)


class PasskeyInfoNeutralTest(unittest.TestCase):
    def test_created_on(self):
        info = PasskeyInfo(id="a", name="b", date=1730000000)
        self.assertEqual(info.created_on.tzinfo is not None, True)
        self.assertIsNone(PasskeyInfo(id="a", name="b", date=0).created_on)

    def test_structurally_equal_to_the_telethon_dataclass(self):
        mine = PasskeyInfo(id="a", name="b", date=5, software_emoji_id=7)
        theirs = TelethonPasskeyInfo(id="a", name="b", date=5, software_emoji_id=7)
        self.assertEqual(dataclass_fields(mine), dataclass_fields(theirs))


def dataclass_fields(instance):
    return {field: getattr(instance, field) for field in
            ("id", "name", "date", "software_emoji_id", "last_usage_date")}


# ---------------------------------------------------------------------------
# 7. ceremony layer: the invoker contract and the register/login state machines
# ---------------------------------------------------------------------------
#
# These tests drive the ceremony functions the way a real framework driver
# would: the fake driver below puts bytes on the wire (never a field dict)
# and the fake server only ever sees those bytes and answers with raw TL
# bytes it packs itself. Server-side WebAuthn verification is the same one
# tests/test_passkeys.py performs against what Telegram does — the COSE key
# is rebuilt from the registration attestation, and the login assertion has
# to verify under it.

API_ID = 2040


def _foreign(info):
    """A framework-shaped passkey object (what ``native`` may return)."""
    return types.SimpleNamespace(**{
        name: getattr(info, name)
        for name in ("id", "name", "date", "software_emoji_id", "last_usage_date")
    })


class FakeTelegramServer:
    """Telegram's passkey endpoints, simulated from RAW TL BYTES only.

    Every request arrives as the exact byte string a framework would send
    (the driver serializes with :func:`encode_request`), and every response
    is packed here with ``struct``/``TLObject.serialize_bytes`` — never with
    ``encode_request`` — so both directions are independent of the code
    under test.
    """

    def __init__(self, *, home_dc=2, user_id=123456789, rp_id="web.telegram.org"):
        self.home_dc = home_dc
        self.user_id = user_id
        self.rp_id = rp_id
        self.passkeys = {}          # credential id (b64url) -> {public_key, alg, sign_count}
        self.registration_challenge = None
        self.login_challenge = None
        self.handled = []           # message names, in arrival order
        self.finish = None          # decoded finishPasskeyLogin facts
        self.sign_up_required = False
        self.corrupt = {}           # message name -> bytes to answer instead
        self.origins = []           # every clientDataJSON origin we saw
        self.passkey_counter = 0

    # -- helpers ------------------------------------------------------------
    def handle(self, name, wire):
        self.handled.append(name)
        if name in self.corrupt:
            return self.corrupt[name]
        return getattr(self, "_handle_" + name)(wire)

    @staticmethod
    def _reader(wire):
        reader = core.TLReader(wire)
        return reader

    def _must(self, condition, message):
        if not condition:
            raise ValueError(f"server rejected the request: {message}")

    # -- registration -------------------------------------------------------
    def _handle_initPasskeyRegistration(self, wire):
        self._must(wire == struct.pack("<I", 0x429547E8), "initPasskeyRegistration bytes")
        self.registration_challenge = core._b64u_encode(os.urandom(32))
        options = json.dumps({
            "rp": {"id": self.rp_id, "name": "Telegram"},
            "user": {
                "id": core._b64u_encode(f"{self.home_dc}:{self.user_id}".encode()),
                "name": "user",
                "displayName": "User",
            },
            "challenge": self.registration_challenge,
            "pubKeyCredParams": [{"type": "public-key", "alg": -7},
                                 {"type": "public-key", "alg": -8}],
            "timeout": 60000,
            "attestation": "none",
        })
        return (struct.pack("<I", 0xE16B5CE1) + struct.pack("<I", 0x7D748D04)
                + TLObject.serialize_bytes(options))

    def _handle_registerPasskey(self, wire):
        reader = self._reader(wire)
        self._must(reader.read_uint() == 0x55B41FD6, "registerPasskey constructor")
        credential = reader.read_object("InputPasskeyCredential")
        self._must(reader.remaining == 0, "trailing bytes after registerPasskey")

        response = credential["response"]
        cdj_text = response["client_data"]["data"]
        cdj = json.loads(cdj_text)
        self.origins.append(cdj["origin"])
        self._must(cdj["type"] == "webauthn.create", "clientDataJSON type")
        self._must(cdj["challenge"] == self.registration_challenge, "registration challenge")
        self._must(credential["id"] == credential["raw_id"], "id == raw_id")

        attestation = cbor_decode(response["attestation_data"])
        self._must(attestation["fmt"] == "none", "attestation fmt")
        self._must(attestation["attStmt"] == {}, "attestation attStmt")
        rp_id_hash, flags, sign_count, credential_id, cose = parse_auth_data(
            attestation["authData"])
        self._must(rp_id_hash == hashlib.sha256(self.rp_id.encode()).digest(), "rpId hash")
        self._must(flags == 0x01 | 0x04 | 0x40, f"registration flags {flags:#x}")
        self._must(sign_count == 0, "registration sign_count")
        self._must(credential_id is not None, "attested credential id")
        self._must(core._b64u_encode(credential_id) == credential["id"],
                   "credential id matches the attested one")
        self.passkeys[credential["id"]] = {
            "public_key": cose_to_public_key(cose),   # rebuilt from the COSE blob
            "alg": cose[3],
            "sign_count": sign_count,
        }
        self.passkey_counter += 1
        # account.passkey.id IS the credential id, like Telegram's server
        return _passkey_payload(credential["id"], "My Passkey",
                                1730000000 + self.passkey_counter)

    # -- login --------------------------------------------------------------
    def _handle_initPasskeyLogin(self, wire):
        reader = self._reader(wire)
        self._must(reader.read_uint() == 0x518AD0B7, "initPasskeyLogin constructor")
        self._must(reader.read_int() == API_ID, "api_id")
        self._must(reader.read_string() == API_HASH, "api_hash")
        self._must(reader.remaining == 0, "trailing bytes after initPasskeyLogin")
        self.login_challenge = core._b64u_encode(os.urandom(32))
        options = json.dumps({
            "challenge": self.login_challenge,
            "rpId": self.rp_id,
            "allowCredentials": [{"type": "public-key", "id": cid}
                                 for cid in self.passkeys],
            "timeout": 60000,
            "userVerification": "required",
        })
        return (struct.pack("<I", 0xE2037789) + struct.pack("<I", 0x7D748D04)
                + TLObject.serialize_bytes(options))

    def _handle_finishPasskeyLogin(self, wire):
        reader = self._reader(wire)
        self._must(reader.read_uint() == 0x9857AD07, "finishPasskeyLogin constructor")
        flags = reader.read_uint()
        credential = reader.read_object("InputPasskeyCredential")
        from_dc_id = from_auth_key_id = None
        if flags & 1:
            from_dc_id = reader.read_int()
            from_auth_key_id = reader.read_long(signed=True)
        self._must(reader.remaining == 0, "trailing bytes after finishPasskeyLogin")

        record = self.passkeys.get(credential["id"])
        self._must(record is not None, "unknown credential id")
        response = credential["response"]
        cdj_text = response["client_data"]["data"]
        cdj = json.loads(cdj_text)
        self.origins.append(cdj["origin"])
        self._must(cdj["type"] == "webauthn.get", "clientDataJSON type")
        self._must(cdj["challenge"] == self.login_challenge, "login challenge")
        self._must(response["user_handle"] == f"{self.home_dc}:{self.user_id}",
                   f"user handle {response['user_handle']!r}")
        rp_id_hash, auth_flags, sign_count, cred_id, cose = parse_auth_data(
            response["authenticator_data"])
        self._must(rp_id_hash == hashlib.sha256(self.rp_id.encode()).digest(), "rpId hash")
        self._must(auth_flags == 0x01 | 0x04, f"assertion flags {auth_flags:#x}")
        self._must(sign_count == record["sign_count"] + 1, "bumped signature counter")
        verify_assertion(record["public_key"], record["alg"], cdj_text,
                         response["authenticator_data"], response["signature"])
        record["sign_count"] = sign_count

        self.finish = {
            "flags": flags,
            "from_dc_id": from_dc_id,
            "from_auth_key_id": from_auth_key_id,
            "sign_count": sign_count,
            "credential_id": credential["id"],
        }
        if self.sign_up_required:
            return struct.pack("<I", 0x44747E9A) + struct.pack("<I", 0)
        # auth.authorization#2ea2c0d4 flags:# ... user:User (flags = 0)
        return (struct.pack("<I", 0x2EA2C0D4) + struct.pack("<I", 0)
                + struct.pack("<I", 0x31774388)      # user#31774388
                + struct.pack("<I", 0) + struct.pack("<I", 0)   # two flags words
                + struct.pack("<q", self.user_id))

    # -- list / delete ------------------------------------------------------
    def _handle_getPasskeys(self, wire):
        self._must(wire == struct.pack("<I", 0xEA1F0C52), "getPasskeys bytes")
        ids = list(self.passkeys)
        return (struct.pack("<I", 0xF8E0AA1C) + struct.pack("<I", 0x1CB5C415)
                + struct.pack("<i", len(ids))
                + b"".join(_passkey_payload(cid, f"P{i}", 1730000100 + i)
                           for i, cid in enumerate(ids)))

    def _handle_deletePasskey(self, wire):
        reader = self._reader(wire)
        self._must(reader.read_uint() == 0xF5B5563F, "deletePasskey constructor")
        passkey_id = reader.read_string()
        self._must(reader.remaining == 0, "trailing bytes after deletePasskey")
        removed = self.passkeys.pop(passkey_id, None) is not None
        return struct.pack("<I", 0x997275B5 if removed else 0xBC799737)


class BytesDriver:
    """The documented generic path, with no framework at all.

    ``request_bytes`` serializes the field dict with the neutral writer (so
    the ceremony's field dicts are exercised exactly as a driver would ship
    them) and returns the server's raw bytes. It also snapshots the passkey
    file as every call starts, which is the evidence for the persist-before-
    network ordering.
    """

    def __init__(self, server, *, store_path=None):
        self.server = server
        self.store_path = store_path
        self.calls = []        # (message name, wire length)
        self.wires = {}        # message name -> bytes put on the wire
        self.snapshots = []    # (message name, on-disk sign_count at call time)
        self.switched_to = "never-asked"

    async def request_bytes(self, name, fields):
        wire = encode_request(name, fields)
        self.calls.append(name)
        self.wires[name] = wire
        if self.store_path and os.path.exists(self.store_path):
            with open(self.store_path, encoding="utf-8") as fp:
                self.snapshots.append((name, json.load(fp)["sign_count"]))
        else:
            self.snapshots.append((name, None))
        return self.server.handle(name, wire)


class NativeDriver:
    """The documented structured path: the driver returns parsed objects.

    A real framework parses responses itself; this fake reuses the neutral
    parser to *get* the values and then hands them back the way a framework
    would — a ``str`` for options, generated-class-shaped objects for the
    passkey results, and raw bytes for ``finishPasskeyLogin`` (a framework's
    auth.Authorization is normalized in the driver).
    """

    def __init__(self, server, *, store_path=None):
        self.bytes_path = BytesDriver(server, store_path=store_path)
        self.calls = self.bytes_path.calls
        self.snapshots = self.bytes_path.snapshots

    async def native(self, name, fields):
        raw = await self.bytes_path.request_bytes(name, fields)
        if name in ("initPasskeyRegistration", "initPasskeyLogin"):
            return core.parse_result(name, raw)
        if name == "registerPasskey":
            return _foreign(core.parse_result(name, raw))
        if name == "getPasskeys":
            return types.SimpleNamespace(
                passkeys=[_foreign(info) for info in core.parse_result(name, raw)])
        if name == "deletePasskey":
            return core.parse_result(name, raw)
        return raw   # finishPasskeyLogin: bytes


def _documented_register(driver, tmpdir, **kwargs):
    """register_passkey_core through the documented contract."""
    return core.register_passkey_core(
        driver, store_path=os.path.join(tmpdir, "k.json"), **kwargs)


class CeremonyContractTest(unittest.IsolatedAsyncioTestCase):
    """The invoker contract itself: lookup, adoption, and its failure modes."""

    async def test_rejects_non_invokers(self):
        for bogus in (None, object(), types.SimpleNamespace(request_bytes=1)):
            with self.subTest(bogus=type(bogus).__name__):
                with self.assertRaises(core.PasskeyError) as ctx:
                    await core.fetch_registration_options(bogus)
                self.assertIn("invoker", str(ctx.exception))

    async def test_request_bytes_path_must_return_bytes(self):
        server = FakeTelegramServer()

        class Wrong(BytesDriver):
            async def request_bytes(self, name, fields):
                self.calls.append(name)
                return {"parsed": True}

        with self.assertRaises(core.PasskeyError) as ctx:
            await core.fetch_registration_options(Wrong(server))
        self.assertIn("request_bytes", str(ctx.exception))
        self.assertIn("native", str(ctx.exception))

    async def test_spec_check_runs_before_the_driver_is_called(self):
        server = FakeTelegramServer()
        driver = BytesDriver(server)
        # api_id far outside int32: the field dict is rejected locally
        with self.assertRaises(core.PasskeyError):
            await core.fetch_login_challenge(driver, api_id=1 << 40, api_hash="h")
        with self.assertRaises(core.PasskeyError):
            await core.finish_login(driver, {"credential": {"id": "only-an-id"}})
        self.assertEqual(driver.calls, [])
        self.assertEqual(server.handled, [])

    async def test_native_adoption_of_framework_objects(self):
        server = FakeTelegramServer()
        driver = NativeDriver(server)
        with tempfile.TemporaryDirectory() as tmp:
            info, store = await _documented_register(driver, tmp)
            passkey_id = core._b64u_encode(store.credential_id)
            self.assertEqual(info.id, passkey_id)
            self.assertEqual(store.telegram_passkey_id, passkey_id)
            listed = await core.list_passkeys_core(driver)
            self.assertEqual([item.id for item in listed], [passkey_id])
            self.assertTrue(await core.delete_passkey_core(driver, passkey_id))
            self.assertFalse(await core.delete_passkey_core(driver, passkey_id))

    async def test_native_adoption_accepts_dicts_and_core_objects(self):
        info = core.PasskeyInfo(id="a", name="b", date=7)

        class Dicts:
            """A native-only driver (no request_bytes), so nothing shadows it."""

            def __init__(self, server):
                self.server = server
                self.calls = []

            async def native(self, name, fields):
                raw = self.server.handle(name, encode_request(name, fields))
                self.calls.append(name)
                if name == "registerPasskey":
                    return {"id": "a", "name": "b", "date": 7}
                if name == "getPasskeys":
                    return [{"id": "a", "name": "b", "date": 7}, info]
                return core.parse_result(name, raw)

        server = FakeTelegramServer()
        with tempfile.TemporaryDirectory() as tmp:
            driver = Dicts(server)
            registered, store = await _documented_register(driver, tmp)
            self.assertEqual((registered.id, store.name), ("a", core.DEFAULT_PASSKEY_NAME))
            self.assertEqual([item.id for item in await core.list_passkeys_core(driver)],
                             ["a", "a"])

    async def test_native_rejects_shapes_it_cannot_read(self):
        class Bad:
            """A native-only driver returning something unreadable."""

            def __init__(self, value):
                self.value = value
                self.calls = []

            async def native(self, name, fields):
                self.calls.append(name)
                return self.value

        cases = [
            (object(), "initPasskeyRegistration", {}),
            (types.SimpleNamespace(no_id=True), "registerPasskey", _register_fields()),
            (types.SimpleNamespace(nothing=[1]), "getPasskeys", {}),
            (types.SimpleNamespace(user=None), "finishPasskeyLogin", _login_fields()),
        ]
        for value, name, fields in cases:
            with self.subTest(message=name):
                driver = Bad(value)
                with self.assertRaises(core.PasskeyError):
                    await core._invoke(driver, name, fields)
                self.assertEqual(driver.calls, [name])

    async def test_native_cannot_skip_normalizing_authorization(self):
        """Documented rule: a framework's auth.Authorization is the driver's
        job — core accepts bytes or its own AuthorizationResult only."""

        class NativeAuth:
            def __init__(self):
                self.calls = []

            async def native(self, name, fields):
                self.calls.append(name)
                return types.SimpleNamespace(CONSTRUCTOR_ID=0x2EA2C0D4,
                                             user=types.SimpleNamespace(id=1))

        with self.assertRaises(core.PasskeyError) as ctx:
            await core.finish_login(NativeAuth(), _login_fields())
        self.assertIn("AuthorizationResult", str(ctx.exception))

    async def test_two_factor_signal_is_not_a_passkey_error(self):
        # deliberately outside PasskeyError: a corrupt-data guard must not
        # swallow a 2FA prompt
        self.assertNotIsInstance(core.TwoFactorRequired(), core.PasskeyError)
        self.assertIsInstance(core.TwoFactorRequired(), Exception)


class RegistrationCeremonyTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.server = FakeTelegramServer()

    async def test_register_end_to_end(self):
        driver = BytesDriver(self.server)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k.json")
            driver.store_path = path
            info, store = await core.register_passkey_core(
                driver, store_path=path, origin=core.DEFAULT_ORIGIN)

            # the server verified the attestation itself (rpId hash, flags,
            # attested credential id) before answering
            self.assertEqual(self.server.handled,
                             ["initPasskeyRegistration", "registerPasskey"])
            passkey_id = core._b64u_encode(store.credential_id)
            self.assertEqual(info.id, passkey_id)
            self.assertEqual(store.telegram_passkey_id, passkey_id)
            self.assertEqual(store.name, core.DEFAULT_PASSKEY_NAME)
            self.assertEqual(store.user_handle, "2:123456789")
            self.assertEqual((store.home_dc, store.user_id), (2, 123456789))
            self.assertEqual(store.sign_count, 0)
            self.assertEqual(store.path, path)
            self.assertEqual(self.server.origins, [core.DEFAULT_ORIGIN])

            # the file is private, atomic, and readable by either module
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(sorted(os.listdir(tmp)), ["k.json"])
            with open(path, encoding="utf-8") as fp:
                data = json.load(fp)
            self.assertEqual(data["version"], 1)
            self.assertEqual(data["telegram_passkey_id"],
                             core._b64u_encode(store.credential_id))
            self.assertEqual(data["name"], core.DEFAULT_PASSKEY_NAME)
            self.assertIn("BEGIN PRIVATE KEY", data["private_key"])

            from tgmint import passkeys as bound
            reloaded = bound.PasskeyStore.load(path)
            self.assertEqual(reloaded.credential_id, store.credential_id)
            self.assertEqual(reloaded.private_key_pem, store.private_key_pem)

    async def test_registration_fields_are_byte_identical_to_the_classes(self):
        """The field dict the ceremony hands a driver is the one the hand-
        written Telethon request serializes; the driver's wire is that too."""
        driver = BytesDriver(self.server)
        with tempfile.TemporaryDirectory() as tmp:
            await _documented_register(driver, tmp)
        wire = driver.wires["registerPasskey"]

        # rebuild the real classes from the values the server received
        reader = core.TLReader(wire)
        reader.read_uint()
        credential = reader.read_object("InputPasskeyCredential")
        cdj = credential["response"]["client_data"]["data"]
        attestation = credential["response"]["attestation_data"]
        oracle = bytes(RegisterPasskeyRequest(InputPasskeyCredentialPublicKey(
            credential["id"], credential["id"],
            InputPasskeyResponseRegister(_DataJSONObject(cdj), attestation),
        )))
        self.assertEqual(wire, oracle)

        # and registration_fields() on a fresh credential is the same shape
        cred = SoftwareAuthenticator.create_credential(REGISTRATION_OPTIONS)
        fields = core.registration_fields(cred)
        self.assertEqual(fields["credential"]["response"]["_"],
                         "inputPasskeyResponseRegister")
        self.assertEqual(fields["credential"]["id"],
                         core._b64u_encode(cred.credential_id))
        self.assertEqual(
            encode_request("registerPasskey", fields),
            bytes(RegisterPasskeyRequest(InputPasskeyCredentialPublicKey(
                fields["credential"]["id"], fields["credential"]["id"],
                InputPasskeyResponseRegister(
                    _DataJSONObject(cred.client_data_json), cred.attestation_object),
            ))),
        )
        with self.assertRaises(core.PasskeyError):
            core.registration_fields("not-a-credential")

    async def test_register_name_and_origin_are_passed_through(self):
        origin = "android:APK_CERT_HASH_BASE64URL:abc"
        driver = BytesDriver(self.server)
        with tempfile.TemporaryDirectory() as tmp:
            info, store = await core.register_passkey_core(
                driver, store_path=os.path.join(tmp, "k.json"),
                origin=origin, name="Phone")
            self.assertEqual(store.name, "Phone")
            with open(store.path, encoding="utf-8") as fp:
                self.assertEqual(json.load(fp)["name"], "Phone")
            self.assertEqual(self.server.origins, [origin])
            self.assertEqual(store.origin, origin)

    async def test_register_alg_override_uses_ed25519(self):
        driver = BytesDriver(self.server)
        with tempfile.TemporaryDirectory() as tmp:
            _, store = await core.register_passkey_core(
                driver, store_path=os.path.join(tmp, "k.json"), alg=ALG_ED25519)
            self.assertEqual(store.alg, ALG_ED25519)
            record = self.server.passkeys[core._b64u_encode(store.credential_id)]
            self.assertEqual(record["alg"], ALG_ED25519)

    async def test_failed_registration_writes_no_file(self):
        self.server.corrupt["registerPasskey"] = struct.pack("<I", 0x12345678)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k.json")
            with self.assertRaises(core.PasskeyError):
                await core.register_passkey_core(BytesDriver(self.server), store_path=path)
            self.assertFalse(os.path.exists(path))
            self.assertEqual(sorted(os.listdir(tmp)), [])

    async def test_register_requires_a_store_path(self):
        with self.assertRaises(core.PasskeyError):
            await core.register_passkey_core(BytesDriver(self.server), store_path="")


class LoginCeremonyTest(unittest.IsolatedAsyncioTestCase):
    """Login: the persist-before-network ordering, the signed int64 handoff,
    the DC switch plan, and the 2FA signal."""

    def setUp(self):
        self.server = FakeTelegramServer()

    async def _registered_store(self, tmp):
        driver = BytesDriver(self.server)
        _, store = await core.register_passkey_core(
            driver, store_path=os.path.join(tmp, "k.json"))
        return store

    def _sign_count_on_disk(self, path):
        with open(path, encoding="utf-8") as fp:
            return json.load(fp)["sign_count"]

    async def test_full_login_and_call_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = await self._registered_store(tmp)
            driver = BytesDriver(self.server, store_path=store.path)

            options_json = await core.fetch_login_challenge(
                driver, api_id=API_ID, api_hash=API_HASH)
            plan = await core.login_passkey_assertion(store, options_json)
            if plan["switch_to_dc"] is not None:
                driver.switched_to = plan["switch_to_dc"]
            result = await core.finish_login(driver, plan["finish_fields"])

            # --- call order: init, finish; nothing else ---
            self.assertEqual(driver.calls, ["initPasskeyLogin", "finishPasskeyLogin"])
            # --- and the counter was already on disk when finish started ---
            self.assertEqual(driver.snapshots,
                             [("initPasskeyLogin", 0), ("finishPasskeyLogin", 1)])
            self.assertEqual(self._sign_count_on_disk(store.path), 1)

            self.assertIsInstance(result, AuthorizationResult)
            self.assertEqual(result.user_id, 123456789)
            self.assertEqual(result.constructor, 0x2EA2C0D4)
            self.assertFalse(result.sign_up_required)

            # home DC == connection DC, so no from_* flags and no switch
            self.assertIsNone(plan["switch_to_dc"])
            self.assertNotIn("from_dc_id", plan["finish_fields"])
            self.assertEqual(plan["home_dc"], 2)
            self.assertEqual(self.server.finish["flags"], 0)
            self.assertEqual(self.server.finish["sign_count"], 1)
            self.assertEqual(driver.switched_to, "never-asked")

            # second login bumps again, still before the network call
            options2 = await core.fetch_login_challenge(
                driver, api_id=API_ID, api_hash=API_HASH)
            plan2 = await core.login_passkey_assertion(store, options2)
            result2 = await core.finish_login(driver, plan2["finish_fields"])
            self.assertEqual(result2.user_id, 123456789)
            self.assertEqual(self._sign_count_on_disk(store.path), 2)
            self.assertEqual(driver.snapshots[-1], ("finishPasskeyLogin", 2))

            # the store on disk is the one the other module reads too
            from tgmint import passkeys as bound
            self.assertEqual(bound.PasskeyStore.load(store.path).sign_count, 2)

    async def test_counter_is_persisted_even_when_finish_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = await self._registered_store(tmp)
            driver = BytesDriver(self.server, store_path=store.path)
            options_json = await core.fetch_login_challenge(
                driver, api_id=API_ID, api_hash=API_HASH)
            plan = await core.login_passkey_assertion(store, options_json)

            class Boom(BytesDriver):
                async def request_bytes(self, name, fields):
                    self.calls.append(name)
                    raise RuntimeError("network died")

            boom = Boom(self.server)
            with self.assertRaises(RuntimeError):
                await core.finish_login(boom, plan["finish_fields"])
            self.assertEqual(self._sign_count_on_disk(store.path), 1)

    async def test_signed_int64_auth_key_id_on_the_wire(self):
        """Both halves of the key-id space, exactly like passkeys.py:928-933."""
        low = 0x1122334455667788          # < 2**63: stays positive
        high = [(1 << 63) + 0x1234567, (1 << 64) - 1]   # >= 2**63: wraps negative
        for value in [low] + high:
            with self.subTest(value=hex(value)), tempfile.TemporaryDirectory() as tmp:
                self.server = FakeTelegramServer()
                store = await self._registered_store(tmp)
                driver = BytesDriver(self.server, store_path=store.path)
                options_json = await core.fetch_login_challenge(
                    driver, api_id=API_ID, api_hash=API_HASH)
                plan = await core.login_passkey_assertion(
                    store, options_json,
                    connection_dc=4, connection_auth_key_id=value)

                expected_signed = value - (1 << 64) if value >= 1 << 63 else value
                self.assertEqual(plan["from_dc_id"], 4)
                self.assertEqual(plan["from_auth_key_id"], expected_signed)
                self.assertEqual(plan["finish_fields"]["from_dc_id"], 4)
                self.assertEqual(plan["finish_fields"]["from_auth_key_id"],
                                 expected_signed)
                self.assertEqual(plan["switch_to_dc"], 2)

                # switch first, then finish — like the official client
                driver.switched_to = plan["switch_to_dc"]
                result = await core.finish_login(driver, plan["finish_fields"])
                self.assertEqual(result.user_id, 123456789)
                self.assertEqual(driver.switched_to, 2)
                self.assertEqual(self.server.finish["from_dc_id"], 4)
                self.assertEqual(self.server.finish["from_auth_key_id"],
                                 expected_signed)
                self.assertEqual(self.server.finish["flags"], 1)

                wire = driver.wires["finishPasskeyLogin"]
                self.assertEqual(wire[4:8], struct.pack("<i", 1))       # flags
                self.assertEqual(wire[-12:-8], struct.pack("<i", 4))    # from_dc_id
                self.assertEqual(wire[-8:], struct.pack("<Q", value))   # two's complement

                assertion = plan["assertion"]
                oracle = bytes(FinishPasskeyLoginRequest(
                    InputPasskeyCredentialPublicKey(
                        assertion["id"], assertion["id"],
                        InputPasskeyResponseLogin(
                            _DataJSONObject(assertion["client_data_json"]),
                            assertion["authenticator_data"],
                            assertion["signature"],
                            assertion["user_handle"],
                        ),
                    ),
                    from_dc_id=4,
                    from_auth_key_id=expected_signed,
                ))
                self.assertEqual(wire, oracle)

    async def test_auth_key_id_dropped_when_no_connection_dc(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = await self._registered_store(tmp)
            driver = BytesDriver(self.server, store_path=store.path)
            options_json = await core.fetch_login_challenge(
                driver, api_id=API_ID, api_hash=API_HASH)
            plan = await core.login_passkey_assertion(
                store, options_json, connection_auth_key_id=0x1122334455667788)
            self.assertNotIn("from_dc_id", plan["finish_fields"])
            self.assertNotIn("from_auth_key_id", plan["finish_fields"])
            await core.finish_login(driver, plan["finish_fields"])
            self.assertEqual(self.server.finish["flags"], 0)

    async def test_auth_key_id_with_no_key_still_sends_dc(self):
        """A connection without an auth key (None) still reports from_dc_id;
        the writer supplies the 0 default, like `from_auth_key_id or 0`."""
        with tempfile.TemporaryDirectory() as tmp:
            store = await self._registered_store(tmp)
            driver = BytesDriver(self.server, store_path=store.path)
            options_json = await core.fetch_login_challenge(
                driver, api_id=API_ID, api_hash=API_HASH)
            plan = await core.login_passkey_assertion(
                store, options_json, connection_dc=4, connection_auth_key_id=None)
            self.assertEqual(plan["from_dc_id"], 4)
            self.assertIsNone(plan["from_auth_key_id"])
            self.assertNotIn("from_auth_key_id", plan["finish_fields"])
            await core.finish_login(driver, plan["finish_fields"])
            self.assertEqual(self.server.finish["flags"], 1)
            self.assertEqual(self.server.finish["from_auth_key_id"], 0)

    async def test_no_switch_plan_when_the_dc_already_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = await self._registered_store(tmp)
            driver = BytesDriver(self.server, store_path=store.path)
            options_json = await core.fetch_login_challenge(
                driver, api_id=API_ID, api_hash=API_HASH)
            plan = await core.login_passkey_assertion(
                store, options_json, connection_dc=2, connection_auth_key_id=42)
            self.assertIsNone(plan["switch_to_dc"])
            self.assertIsNone(plan["from_dc_id"])
            self.assertIsNone(plan["from_auth_key_id"])
            await core.finish_login(driver, plan["finish_fields"])
            self.assertEqual(self.server.finish["flags"], 0)

    async def test_home_dc_override_and_plan_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = await self._registered_store(tmp)
            driver = BytesDriver(self.server, store_path=store.path)
            options_json = await core.fetch_login_challenge(
                driver, api_id=API_ID, api_hash=API_HASH)
            plan = await core.login_passkey_assertion(
                store, options_json, connection_dc=2, home_dc=5)
            self.assertEqual(plan["home_dc"], 5)
            self.assertEqual(plan["switch_to_dc"], 5)
            self.assertEqual(plan["from_dc_id"], 2)
            self.assertEqual(
                set(plan),
                {"finish_fields", "switch_to_dc", "assertion", "home_dc",
                 "from_dc_id", "from_auth_key_id"},
            )
            self.assertEqual(plan["assertion"]["user_handle"], "2:123456789")

    async def test_two_factor_signal_propagates_and_counter_is_burned(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = await self._registered_store(tmp)
            driver = BytesDriver(self.server, store_path=store.path)
            options_json = await core.fetch_login_challenge(
                driver, api_id=API_ID, api_hash=API_HASH)
            plan = await core.login_passkey_assertion(store, options_json)

            class TwoFactor(BytesDriver):
                async def request_bytes(self, name, fields):
                    self.calls.append(name)
                    if name == "finishPasskeyLogin":
                        raise core.TwoFactorRequired()
                    return await super().request_bytes(name, fields)

            tfa = TwoFactor(self.server)
            with self.assertRaises(core.TwoFactorRequired):
                await core.finish_login(tfa, plan["finish_fields"])
            self.assertEqual(tfa.calls, ["finishPasskeyLogin"])
            self.assertEqual(self._sign_count_on_disk(store.path), 1)

    async def test_sign_up_required_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = await self._registered_store(tmp)
            self.server.sign_up_required = True
            driver = BytesDriver(self.server, store_path=store.path)
            options_json = await core.fetch_login_challenge(
                driver, api_id=API_ID, api_hash=API_HASH)
            plan = await core.login_passkey_assertion(store, options_json)
            result = await core.finish_login(driver, plan["finish_fields"])
            self.assertTrue(result.sign_up_required)
            self.assertIsNone(result.user_id)

    async def test_persist_requires_a_path_and_persist_false_skips_it(self):
        cred = SoftwareAuthenticator.create_credential(REGISTRATION_OPTIONS)
        options = json.loads(login_options(b"\x11" * 32,
                                           core._b64u_encode(cred.credential_id)))
        in_memory = PasskeyStore.from_credential(cred)   # no path
        with self.assertRaises(core.PasskeyError) as ctx:
            await core.login_passkey_assertion(in_memory, options)
        self.assertIn("path", str(ctx.exception))
        self.assertEqual(in_memory.sign_count, 1)   # bumped in memory, never saved

        plan = await core.login_passkey_assertion(in_memory, options, persist=False)
        self.assertEqual(plan["switch_to_dc"], None)
        self.assertIn("credential", plan["finish_fields"])


class ListDeleteCeremonyTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.server = FakeTelegramServer()

    async def test_list_and_delete_through_the_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            driver = BytesDriver(self.server)
            _, store = await core.register_passkey_core(
                driver, store_path=os.path.join(tmp, "k.json"))
            self.server.passkeys["other"] = {"public_key": None, "alg": ALG_ES256,
                                             "sign_count": 0}
            listed = await core.list_passkeys_core(driver)
            self.assertEqual([item.id for item in listed],
                             [core._b64u_encode(store.credential_id), "other"])
            self.assertTrue(all(isinstance(item, PasskeyInfo) for item in listed))
            self.assertIs(await core.delete_passkey_core(driver, "other"), True)
            self.assertIs(await core.delete_passkey_core(driver, "other"), False)
            self.assertEqual([item.id for item in await core.list_passkeys_core(driver)],
                             [core._b64u_encode(store.credential_id)])
            self.assertEqual(driver.calls,
                             ["initPasskeyRegistration", "registerPasskey",
                              "getPasskeys", "deletePasskey", "deletePasskey",
                              "getPasskeys"])

    async def test_field_builders_are_spec_checked(self):
        self.assertEqual(core.get_passkeys_fields(), {})
        self.assertEqual(
            encode_request("getPasskeys", core.get_passkeys_fields()),
            bytes(GetPasskeysRequest()))
        for passkey_id in ("x", "", "pässkey" * 40):
            with self.subTest(passkey_id=len(passkey_id)):
                self.assertEqual(
                    encode_request("deletePasskey",
                                   core.delete_passkey_fields(passkey_id)),
                    bytes(DeletePasskeyRequest(passkey_id)))
        with self.assertRaises(core.PasskeyError):
            core.delete_passkey_fields(123)
        with self.assertRaises(core.PasskeyError):
            core.finish_login_fields({"id": "x"})          # incomplete assertion
        with self.assertRaises(core.PasskeyError):
            core.finish_login_fields("nope")


class SignedInt64Test(unittest.TestCase):
    def test_normalization(self):
        self.assertIsNone(core.to_signed_int64(None))
        self.assertEqual(core.to_signed_int64(0), 0)
        self.assertEqual(core.to_signed_int64(0x1122334455667788), 0x1122334455667788)
        self.assertEqual(core.to_signed_int64(-1), -1)          # idempotent
        self.assertEqual(core.to_signed_int64(1 << 63), -(1 << 63))
        self.assertEqual(core.to_signed_int64((1 << 64) - 1), -1)
        for bad in (1 << 64, -(1 << 63) - 1, True, "x", 1.5):
            with self.subTest(bad=bad):
                with self.assertRaises(core.PasskeyError):
                    core.to_signed_int64(bad)


class FullFlowFakeDriverTest(unittest.IsolatedAsyncioTestCase):
    """The acceptance test for the contract: a driver that knows nothing but
    encode_request + raw response bytes (or nothing but parsed objects) can
    run registration AND login with the ceremony layer doing the rest."""

    async def _flow(self, driver_factory, connection_dc, key_id):
        server = FakeTelegramServer()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k.json")
            register_driver = driver_factory(server, store_path=path)
            info, store = await core.register_passkey_core(
                register_driver, store_path=path)

            # a fresh connection (the driver object is per-connection fresh)
            login_driver = driver_factory(server, store_path=path)
            options_json = await core.fetch_login_challenge(
                login_driver, api_id=API_ID, api_hash=API_HASH)
            plan = await core.login_passkey_assertion(
                store, options_json,
                connection_dc=connection_dc, connection_auth_key_id=key_id)
            if plan["switch_to_dc"] is not None:
                login_driver.switched_to = plan["switch_to_dc"]
            result = await core.finish_login(login_driver, plan["finish_fields"])
            listed = await core.list_passkeys_core(login_driver)
            return info, store, result, plan, login_driver, server, listed

    async def test_bytes_driver_full_flow(self):
        info, store, result, plan, driver, server, listed = await self._flow(
            BytesDriver, 4, 0x7F00000000000001)
        self.assertEqual(info.id, core._b64u_encode(store.credential_id))
        self.assertEqual(result.user_id, 123456789)
        self.assertEqual(plan["switch_to_dc"], 2)
        self.assertEqual(driver.switched_to, 2)
        self.assertEqual(driver.calls,
                         ["initPasskeyLogin", "finishPasskeyLogin", "getPasskeys"])
        self.assertEqual(server.finish["from_dc_id"], 4)
        self.assertEqual(server.finish["from_auth_key_id"], 0x7F00000000000001)
        self.assertEqual([item.id for item in listed],
                         [core._b64u_encode(store.credential_id)])
        self.assertEqual(store.user_id, result.user_id)

    async def test_native_driver_full_flow(self):
        info, store, result, plan, driver, server, listed = await self._flow(
            NativeDriver, 5, (1 << 63) + 0x0BADF00D)
        self.assertEqual(info.id, core._b64u_encode(store.credential_id))
        self.assertEqual(result.user_id, 123456789)
        self.assertEqual(plan["switch_to_dc"], 2)
        self.assertEqual(driver.switched_to, 2)
        self.assertEqual(server.finish["from_dc_id"], 5)
        self.assertEqual(server.finish["from_auth_key_id"],
                         ((1 << 63) + 0x0BADF00D) - (1 << 64))
        self.assertEqual([item.id for item in listed],
                         [core._b64u_encode(store.credential_id)])

    async def test_driver_stays_thin(self):
        """What a driver actually implements: one method, two lines."""
        calls = []

        class ThinDriver:
            async def request_bytes(self, name, fields):
                calls.append(name)
                return SERVER.handle(name, encode_request(name, fields))

        SERVER = FakeTelegramServer()
        with tempfile.TemporaryDirectory() as tmp:
            await core.register_passkey_core(
                ThinDriver(), store_path=os.path.join(tmp, "k.json"))
            store = PasskeyStore.load(os.path.join(tmp, "k.json"))
            options_json = await core.fetch_login_challenge(
                ThinDriver(), api_id=API_ID, api_hash=API_HASH)
            plan = await core.login_passkey_assertion(store, options_json)
            result = await core.finish_login(ThinDriver(), plan["finish_fields"])
        self.assertEqual(result.user_id, 123456789)
        self.assertEqual(calls, ["initPasskeyRegistration", "registerPasskey",
                                 "initPasskeyLogin", "finishPasskeyLogin"])


if __name__ == "__main__":
    unittest.main()
