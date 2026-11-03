"""Offline tests for tgmint.passkeys — no network, no account needed.

Besides unit checks, these simulate what Telegram's server does when it
receives a registration and a login assertion: parse the attestation
object, rebuild the public key from the COSE blob, and verify the
Ed25519/ES256 signature over clientDataJSON hash || authenticatorData.
"""
import asyncio
import hashlib
import json
import os
import struct
import tempfile
import unittest

from tgmint.passkeys import (
    ALG_ED25519,
    ALG_ES256,
    CreatedCredential,
    DeletePasskeyRequest,
    FinishPasskeyLoginRequest,
    GetPasskeysRequest,
    InitPasskeyLoginRequest,
    InitPasskeyRegistrationRequest,
    InputPasskeyCredentialPublicKey,
    InputPasskeyResponseLogin,
    InputPasskeyResponseRegister,
    PasskeyError,
    PasskeyStore,
    RegisterPasskeyRequest,
    SoftwareAuthenticator,
    _DataJSONObject,
    _b64u_decode,
    _b64u_encode,
    _cbor_encode,
    login_with_passkey,
)
from telethon.extensions import BinaryReader
from telethon.tl.tlobject import TLObject


# ---------------------------------------------------------------------------
# Tiny definite-length CBOR decoder (test-only, enough for our structures)
# ---------------------------------------------------------------------------

def cbor_decode(data: bytes):
    item, offset = _cbor_item(data, 0)
    assert offset == len(data), "trailing bytes after CBOR item"
    return item


def _cbor_item(data: bytes, pos: int):
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


def _cbor_uint(data: bytes, pos: int, info: int):
    if info < 24:
        return info, pos
    if info == 24:
        return data[pos], pos + 1
    if info == 25:
        return struct.unpack_from(">H", data, pos)[0], pos + 2
    if info == 26:
        return struct.unpack_from(">I", data, pos)[0], pos + 4
    raise ValueError("additional info too large for tests")


def parse_auth_data(auth_data: bytes):
    assert len(auth_data) >= 37
    rp_id_hash = auth_data[:32]
    flags = auth_data[32]
    sign_count = struct.unpack_from(">I", auth_data, 33)[0]
    rest = auth_data[37:]
    credential_id = cose = None
    if flags & 0x40:
        aaguid = rest[:16]
        (cred_len,) = struct.unpack_from(">H", rest, 16)
        credential_id = rest[18:18 + cred_len]
        cose, _ = _cbor_item(rest, 18 + cred_len)
    return rp_id_hash, flags, sign_count, credential_id, cose


def cose_to_public_key(cose: dict):
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


def verify_assertion(public_key, alg, client_data_json: str, auth_data: bytes, signature: bytes):
    signed = auth_data + hashlib.sha256(client_data_json.encode()).digest()
    if alg == ALG_ES256:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    else:
        public_key.verify(signature, signed)


REG_OPTIONS = json.dumps({
    "rp": {"id": "web.telegram.org", "name": "Telegram"},
    "user": {"id": _b64u_encode(b"2:123456789"), "name": "user", "displayName": "User"},
    "challenge": _b64u_encode(os.urandom(32)),
    "pubKeyCredParams": [
        {"type": "public-key", "alg": -7},
        {"type": "public-key", "alg": -8},
    ],
    "timeout": 60000,
    "attestation": "none",
})


def login_options(challenge: bytes, credential_id_b64: str) -> str:
    return json.dumps({
        "challenge": _b64u_encode(challenge),
        "rpId": "web.telegram.org",
        "allowCredentials": [{"type": "public-key", "id": credential_id_b64}],
        "timeout": 60000,
        "userVerification": "required",
    })


class TestCbor(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(_cbor_encode(0), b"\x00")
        self.assertEqual(_cbor_encode(23), b"\x17")
        self.assertEqual(_cbor_encode(24), b"\x18\x18")
        self.assertEqual(_cbor_encode(500), b"\x19\x01\xf4")
        self.assertEqual(_cbor_encode(-7), b"\x26")
        self.assertEqual(_cbor_encode(-8), b"\x27")
        self.assertEqual(_cbor_encode(b"ab"), b"\x42ab")
        self.assertEqual(_cbor_encode("none"), b"\x64none")
        self.assertEqual(_cbor_encode(True), b"\xf5")
        self.assertEqual(_cbor_encode(None), b"\xf6")

    def test_canonical_map_key_order(self):
        # keys must be sorted by encoded length first, then bytewise:
        # "fmt"(3) < "attStmt"(7) < "authData"(8)
        out = _cbor_encode({"fmt": "none", "attStmt": {}, "authData": b"\x01\x02"})
        expected = (
            b"\xa3"
            b"\x63fmt" b"\x64none"
            b"\x67attStmt" b"\xa0"
            b"\x68authData" b"\x42\x01\x02"
        )
        self.assertEqual(out, expected)

    def test_cose_map_order(self):
        out = _cbor_encode({1: 2, 3: -7, -1: 1})
        # 0x01 0x02 | 0x03 0x26 | 0x20 0x01
        self.assertEqual(out, b"\xa3\x01\x02\x03\x26\x20\x01")

    def test_roundtrip(self):
        obj = {"a": [1, -2, b"x", "y", True, None], "b": {2: 3}}
        self.assertEqual(cbor_decode(_cbor_encode(obj)), obj)


class TestSoftwareAuthenticator(unittest.TestCase):
    def _register_and_verify_like_server(self, alg):
        origin = "https://web.telegram.org"
        cred = SoftwareAuthenticator.create_credential(
            REG_OPTIONS, origin=origin, alg=alg
        )
        self.assertEqual(cred.rp_id, "web.telegram.org")
        self.assertEqual(cred.user_handle, "2:123456789")

        # --- server side: parse attestation, rebuild pubkey ---
        att = cbor_decode(cred.attestation_object)
        self.assertEqual(att["fmt"], "none")
        self.assertEqual(att["attStmt"], {})
        rp_id_hash, flags, sign_count, credential_id, cose = parse_auth_data(att["authData"])
        self.assertEqual(rp_id_hash, hashlib.sha256(b"web.telegram.org").digest())
        self.assertEqual(flags, 0x01 | 0x04 | 0x40)
        self.assertEqual(sign_count, 0)
        self.assertEqual(credential_id, cred.credential_id)
        public_key = cose_to_public_key(cose)
        self.assertEqual(cose[3], alg)

        # clientDataJSON exactly as WebAuthn defines it
        cdj = json.loads(cred.client_data_json)
        self.assertEqual(cdj["type"], "webauthn.create")
        self.assertEqual(cdj["origin"], origin)
        self.assertEqual(cdj["challenge"], json.loads(REG_OPTIONS)["challenge"])
        return cred, public_key

    def test_register_es256_server_verification(self):
        self._register_and_verify_like_server(ALG_ES256)

    def test_register_ed25519_server_verification(self):
        self._register_and_verify_like_server(ALG_ED25519)

    def test_alg_selection_follows_server_preference(self):
        self.assertEqual(SoftwareAuthenticator.pick_algorithm(json.loads(REG_OPTIONS)), ALG_ES256)

    def test_alg_rejection(self):
        with self.assertRaises(Exception):
            SoftwareAuthenticator.pick_algorithm({"pubKeyCredParams": [{"alg": -257}]})

    def _login_and_verify_like_server(self, alg):
        cred, public_key = self._register_and_verify_like_server(alg)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k.json")
            store = PasskeyStore.from_credential(cred, path=path)
            store.save()
            store = PasskeyStore.load(path)
            self.assertEqual(store.home_dc, 2)
            self.assertEqual(store.user_id, 123456789)

            options = login_options(os.urandom(32), _b64u_encode(store.credential_id))
            assertion = store.produce_assertion(options)
            self.assertEqual(store.sign_count, 1)
            store.save()
            store = PasskeyStore.load(path)

            # --- server side: verify the assertion ---
            cdj = json.loads(assertion["client_data_json"])
            self.assertEqual(cdj["type"], "webauthn.get")
            self.assertEqual(cdj["origin"], store.origin)
            self.assertEqual(cdj["challenge"], json.loads(options)["challenge"])
            rp_id_hash, flags, sign_count, credential_id, cose = parse_auth_data(
                assertion["authenticator_data"]
            )
            self.assertEqual(rp_id_hash, hashlib.sha256(b"web.telegram.org").digest())
            self.assertEqual(flags, 0x01 | 0x04)
            self.assertEqual(sign_count, 1)
            self.assertIsNone(cose)
            self.assertEqual(assertion["user_handle"], "2:123456789")
            verify_assertion(
                public_key, alg, assertion["client_data_json"],
                assertion["authenticator_data"], assertion["signature"],
            )

            # second login bumps the counter and still verifies
            options2 = login_options(os.urandom(32), _b64u_encode(store.credential_id))
            assertion2 = store.produce_assertion(options2)
            _, _, sign_count2, _, _ = parse_auth_data(assertion2["authenticator_data"])
            self.assertEqual(sign_count2, 2)
            verify_assertion(
                public_key, alg, assertion2["client_data_json"],
                assertion2["authenticator_data"], assertion2["signature"],
            )

    def test_login_es256(self):
        self._login_and_verify_like_server(ALG_ES256)

    def test_login_ed25519(self):
        self._login_and_verify_like_server(ALG_ED25519)

    def test_store_file_permissions(self):
        cred, _ = self._register_and_verify_like_server(ALG_ES256)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k.json")
            store = PasskeyStore.from_credential(cred, path=path)
            store.save()
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with open(path) as fp:
                data = json.load(fp)
            self.assertEqual(data["version"], 1)
            self.assertIn("BEGIN PRIVATE KEY", data["private_key"])

    def test_allowlist_rejects_unknown_credential(self):
        cred, _ = self._register_and_verify_like_server(ALG_ES256)
        store = PasskeyStore.from_credential(cred)
        options = login_options(os.urandom(32), _b64u_encode(b"not-our-key"))
        with self.assertRaises(Exception):
            store.produce_assertion(options)


class TestStoreValidation(unittest.TestCase):
    """user_handle must be the 'dcId:userId' string Telegram sends.

    A store file without that shape used to blow up later with a cryptic
    ValueError from home_dc/user_id; PasskeyStore now rejects it loudly.
    """

    def _make_store(self, user_handle):
        cred, _ = TestSoftwareAuthenticator()._register_and_verify_like_server(
            ALG_ES256
        )
        return PasskeyStore(
            credential_id=cred.credential_id,
            rp_id=cred.rp_id,
            origin=cred.origin,
            alg=cred.alg,
            user_handle=user_handle,
            private_key_pem=cred.private_key_pem,
        )

    def test_construct_rejects_malformed_user_handle(self):
        for bad in ("garbage", "2:123456789:extra", "abc:123", "2:", ":123",
                    "2 123", "", "123456789"):
            with self.assertRaises(PasskeyError, msg=repr(bad)):
                self._make_store(bad)

    def test_construct_error_message_is_helpful(self):
        with self.assertRaises(PasskeyError) as ctx:
            self._make_store("definitely not a handle")
        self.assertIn("invalid user_handle", str(ctx.exception))
        self.assertIn("passkey store", str(ctx.exception))

    def test_construct_accepts_valid_handles(self):
        store = self._make_store("2:123456789")
        self.assertEqual(store.home_dc, 2)
        self.assertEqual(store.user_id, 123456789)

    def test_load_rejects_malformed_user_handle(self):
        cred, _ = TestSoftwareAuthenticator()._register_and_verify_like_server(
            ALG_ES256
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k.json")
            data = {
                "version": 1,
                "credential_id": _b64u_encode(cred.credential_id),
                "rp_id": cred.rp_id,
                "origin": cred.origin,
                "alg": cred.alg,
                "user_handle": "not-a-handle",
                "private_key": cred.private_key_pem,
                "sign_count": 0,
            }
            with open(path, "w", encoding="utf-8") as fp:
                json.dump(data, fp)
            with self.assertRaises(PasskeyError):
                PasskeyStore.load(path)


class TestTlWire(unittest.TestCase):
    def test_init_registration_bytes(self):
        self.assertEqual(
            bytes(InitPasskeyRegistrationRequest()._bytes()),
            b"\xe8G\x95B",  # 0x429547e8 little-endian
        )

    def test_init_login_bytes(self):
        req = InitPasskeyLoginRequest(2040, "b18441a1ff607e10a989891a5462e627")
        self.assertEqual(bytes(req)[:4], b"\xb7\xd0\x8aQ")  # 0x518ad0b7
        self.assertEqual(bytes(req)[4:8], struct.pack("<i", 2040))
        reader = BinaryReader(bytes(req)[8:])
        self.assertEqual(reader.tgread_string(), "b18441a1ff607e10a989891a5462e627")

    def test_registration_options_response_parse(self):
        options = '{"publicKey": {"challenge": "abc"}}'
        payload = (
            struct.pack("<I", 0xE16B5CE1)
            + struct.pack("<I", 0x7D748D04)
            + TLObject.serialize_bytes(options)
        )
        self.assertEqual(InitPasskeyRegistrationRequest.read_result(BinaryReader(payload)), options)

    def test_login_options_response_parse(self):
        options = '{"challenge": "xyz", "rpId": "web.telegram.org"}'
        payload = (
            struct.pack("<I", 0xE2037789)
            + struct.pack("<I", 0x7D748D04)
            + TLObject.serialize_bytes(options)
        )
        self.assertEqual(InitPasskeyLoginRequest.read_result(BinaryReader(payload)), options)

    def test_passkey_response_parse(self):
        flags = 0
        body = (
            struct.pack("<I", 0x98613EBF)
            + struct.pack("<I", flags)
            + TLObject.serialize_bytes("cred-id")
            + TLObject.serialize_bytes("My Passkey")
            + struct.pack("<i", 1730000000)
        )
        info = RegisterPasskeyRequest.read_result(BinaryReader(body))
        self.assertEqual(info.id, "cred-id")
        self.assertEqual(info.name, "My Passkey")
        self.assertEqual(info.date, 1730000000)
        self.assertIsNone(info.last_usage_date)

        # with optional fields
        body2 = (
            struct.pack("<I", 0x98613EBF)
            + struct.pack("<I", 0b11)
            + TLObject.serialize_bytes("cred-id")
            + TLObject.serialize_bytes("My Passkey")
            + struct.pack("<i", 1730000000)
            + struct.pack("<q", 12345678901234567)
            + struct.pack("<i", 1730001000)
        )
        info2 = RegisterPasskeyRequest.read_result(BinaryReader(body2))
        self.assertEqual(info2.software_emoji_id, 12345678901234567)
        self.assertEqual(info2.last_usage_date, 1730001000)

    def test_get_passkeys_response_parse(self):
        one = (
            struct.pack("<I", 0x98613EBF)
            + struct.pack("<I", 0)
            + TLObject.serialize_bytes("cred-1")
            + TLObject.serialize_bytes("A")
            + struct.pack("<i", 5)
        )
        payload = (
            struct.pack("<I", 0xF8E0AA1C)
            + struct.pack("<I", 0x1CB5C415)
            + struct.pack("<i", 1)
            + one
        )
        result = GetPasskeysRequest.read_result(BinaryReader(payload))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].id, "cred-1")

    def test_delete_response_parse(self):
        self.assertIs(DeletePasskeyRequest.read_result(BinaryReader(struct.pack("<I", 0x997275B5))), True)
        self.assertIs(DeletePasskeyRequest.read_result(BinaryReader(struct.pack("<I", 0xBC799737))), False)

    def test_credential_serialization_roundtrip_layout(self):
        cdj = '{"type":"webauthn.create","challenge":"abc","origin":"https://web.telegram.org"}'
        cred = InputPasskeyCredentialPublicKey(
            id="AAA",
            raw_id="AAA",
            response=InputPasskeyResponseRegister(
                client_data=_DataJSONObject(cdj),
                attestation_data=b"\x01\x02",
            ),
        )
        req = RegisterPasskeyRequest(cred)
        self.assertEqual(bytes(req)[:4], b"\xd6\x1f\xb4U")  # 0x55b41fd6
        reader = BinaryReader(bytes(req)[4:])
        self.assertEqual(reader.read_int(signed=False), 0x3C27B78F)
        self.assertEqual(reader.tgread_string(), "AAA")
        self.assertEqual(reader.tgread_string(), "AAA")
        self.assertEqual(reader.read_int(signed=False), 0x3E63935C)
        self.assertEqual(reader.read_int(signed=False), 0x7D748D04)
        self.assertEqual(reader.tgread_string(), cdj)
        self.assertEqual(reader.tgread_bytes(), b"\x01\x02")

    def test_login_credential_serialization(self):
        cdj = '{"type":"webauthn.get"}'
        cred = InputPasskeyCredentialPublicKey(
            id="BBB",
            raw_id="BBB",
            response=InputPasskeyResponseLogin(
                client_data=_DataJSONObject(cdj),
                authenticator_data=b"\x00" * 37,
                signature=b"\x09" * 64,
                user_handle="2:123456789",
            ),
        )
        req = FinishPasskeyLoginRequest(cred)
        self.assertEqual(bytes(req)[:4], b"\x07\xadW\x98")  # 0x9857ad07
        self.assertEqual(bytes(req)[4:8], b"\x00\x00\x00\x00")  # flags = 0
        reader = BinaryReader(bytes(req)[8:])
        self.assertEqual(reader.read_int(signed=False), 0x3C27B78F)
        self.assertEqual(reader.tgread_string(), "BBB")
        reader.tgread_string()  # rawId
        self.assertEqual(reader.read_int(signed=False), 0xC31FC14A)
        self.assertEqual(reader.read_int(signed=False), 0x7D748D04)
        self.assertEqual(reader.tgread_string(), cdj)
        self.assertEqual(reader.tgread_bytes(), b"\x00" * 37)
        self.assertEqual(reader.tgread_bytes(), b"\x09" * 64)
        self.assertEqual(reader.tgread_string(), "2:123456789")

    def test_login_with_migration_fields(self):
        cred = InputPasskeyCredentialPublicKey(
            id="BBB",
            raw_id="BBB",
            response=InputPasskeyResponseLogin(
                client_data=_DataJSONObject("{}"),
                authenticator_data=b"",
                signature=b"",
                user_handle="5:42",
            ),
        )
        req = FinishPasskeyLoginRequest(cred, from_dc_id=2, from_auth_key_id=0x1122334455667788)
        self.assertEqual(bytes(req)[4:8], b"\x01\x00\x00\x00")  # flags = 1
        self.assertEqual(bytes(req)[-12:-8], struct.pack("<i", 2))
        self.assertEqual(bytes(req)[-8:], struct.pack("<q", 0x1122334455667788))

    def test_requests_are_valid_telethon_requests(self):
        from telethon.tl.tlobject import TLRequest as _TLR

        for req in (
            InitPasskeyRegistrationRequest(),
            RegisterPasskeyRequest(
                InputPasskeyCredentialPublicKey("a", "a", InputPasskeyResponseRegister(_DataJSONObject("{}"), b""))
            ),
            GetPasskeysRequest(),
            DeletePasskeyRequest("x"),
            InitPasskeyLoginRequest(1, "h"),
            FinishPasskeyLoginRequest(
                InputPasskeyCredentialPublicKey("a", "a", InputPasskeyResponseLogin(_DataJSONObject("{}"), b"", b"", "1:1"))
            ),
        ):
            self.assertIsInstance(req, _TLR)
            self.assertIsInstance(bytes(req), bytes)
            self.assertIsInstance(req.to_dict(), dict)
            str(req)  # must not raise


# ---------------------------------------------------------------------------
# 2026-11 code review regressions (Telethon driver only)
# ---------------------------------------------------------------------------

def _raw_finish_fields(**extra):
    """A finishPasskeyLogin field dict, written by hand (no core builder)."""
    fields = {
        "credential": {
            "id": "BBB",
            "raw_id": "BBB",
            "response": {
                "_": "inputPasskeyResponseLogin",
                "client_data": '{"type":"webauthn.get"}',
                "authenticator_data": b"\x00" * 37,
                "signature": b"\x09" * 64,
                "user_handle": "2:123456789",
            },
        },
    }
    fields.update(extra)
    return fields


class TestUnsignedLongFields(unittest.TestCase):
    """The driver accepts the *unsigned* auth key ids every framework hands out.

    ``_construct`` used to feed the value straight into
    ``FinishPasskeyLoginRequest``, whose ``struct.pack("<q", ...)`` raises
    ``struct.error`` for ids >= 2**63 — half of them — although the neutral
    writer and the pyrogram driver both accept them.
    """

    def _build(self, fields):
        from tgmint import passkeys as drv

        key, spec = drv._message_spec("finishPasskeyLogin")
        return drv._build_request(key, spec, fields)

    def test_unsigned_id_is_normalized_like_the_core(self):
        from tgmint import passkeys_core as core

        for key_id in ((1 << 63) + 0x0BADF00D, (1 << 64) - 1, 0, 0x1122334455667788):
            with self.subTest(key_id=key_id):
                fields = _raw_finish_fields(from_dc_id=2, from_auth_key_id=key_id)
                request = self._build(fields)
                self.assertEqual(
                    bytes(request), core.encode_request("finishPasskeyLogin", fields))
                self.assertLess(request.from_auth_key_id, 1 << 63)

    def test_negative_ids_stay_negative(self):
        request = self._build(_raw_finish_fields(from_dc_id=2, from_auth_key_id=-5))
        self.assertEqual(request.from_auth_key_id, -5)

    def test_out_of_range_ids_are_still_rejected(self):
        for bad in (1 << 64, -(1 << 63) - 1):
            with self.subTest(bad=bad):
                with self.assertRaises(PasskeyError):
                    self._build(_raw_finish_fields(from_dc_id=2, from_auth_key_id=bad))


class _RaisingClient:
    """A Telethon-shaped client whose every request raises ``exc``."""

    api_id = 2040
    api_hash = "b18441a1ff607e10a989891a5462e627"

    def __init__(self, exc):
        self.exc = exc
        self.requests = []

    async def __call__(self, request):
        self.requests.append(request)
        raise self.exc


class TestServerErrorTranslation(unittest.TestCase):
    """A passkey server error is a PasskeyError on both drivers."""

    def _invoker(self, exc):
        from tgmint.passkeys import TelethonInvoker

        return TelethonInvoker(_RaisingClient(exc))

    def test_passkey_server_errors_become_passkey_errors(self):
        from telethon.errors import BadRequestError

        for message, hint in (
            ("PASSKEY_ORIGIN_MISMATCH", "origin"),
            ("PASSKEY_CHALLENGE_EXPIRED", "challenge"),
            ("PASSKEY_CREDENTIAL_NOT_FOUND", "credential"),
            ("PASSKEY_SIGNATURE_INVALID", "corrupt"),
        ):
            with self.subTest(message=message):
                invoker = self._invoker(BadRequestError(object(), message, 400))
                with self.assertRaises(PasskeyError) as ctx:
                    asyncio.run(invoker.native("initPasskeyRegistration", {}))
                self.assertIn(message, str(ctx.exception))
                self.assertIn(hint, str(ctx.exception))

    def test_the_2fa_signal_is_not_a_passkey_error(self):
        from telethon.errors import SessionPasswordNeededError
        from tgmint import passkeys_core as core

        invoker = self._invoker(SessionPasswordNeededError(object()))
        with tempfile.TemporaryDirectory() as tmp:
            fields = _finish_fields_for(tmp)
            with self.assertRaises(core.TwoFactorRequired) as ctx:
                asyncio.run(invoker.native("finishPasskeyLogin", fields))
        self.assertNotIsInstance(ctx.exception, PasskeyError)

    def test_other_rpc_errors_keep_their_own_type(self):
        from telethon.errors import BadRequestError

        exc = BadRequestError(object(), "PHONE_NUMBER_INVALID", 400)
        invoker = self._invoker(exc)
        with self.assertRaises(BadRequestError):
            asyncio.run(invoker.native(
                "initPasskeyLogin", {"api_id": 2040, "api_hash": "hash"}))


def _finish_fields_for(tmpdir, home_dc=2):
    """The core's finishPasskeyLogin field dict for a fresh credential."""
    from tgmint import passkeys_core as core

    options = json.loads(REG_OPTIONS)
    options["user"]["id"] = _b64u_encode(f"{home_dc}:123456789".encode())
    cred = SoftwareAuthenticator.create_credential(json.dumps(options), alg=ALG_ES256)
    store = PasskeyStore.from_credential(cred, path=os.path.join(tmpdir, "k.json"))
    assertion = store.produce_assertion(
        login_options(os.urandom(32), _b64u_encode(cred.credential_id)))
    return core.finish_login_fields(assertion)


class _FakeAuthKey:
    def __init__(self, key, key_id):
        self.key = key
        self.key_id = key_id


class _FakeSession:
    """The slice of a Telethon ``Session`` that ``_switch_dc`` rewrites."""

    def __init__(self, dc_id, server_address, port, auth_key):
        self.dc_id = dc_id
        self.server_address = server_address
        self.port = port
        self.auth_key = auth_key
        self.saves = 0

    def set_dc(self, dc_id, server_address, port):
        self.dc_id = dc_id
        self.server_address = server_address
        self.port = port

    def save(self):
        self.saves += 1


class _SwitchableClient:
    """Just enough of a Telethon client for :func:`login_with_passkey`."""

    api_id = 2040
    api_hash = "b18441a1ff607e10a989891a5462e627"

    def __init__(self, session, login_options_json, finish_error):
        self.session = session
        self.login_options_json = login_options_json
        self.finish_error = finish_error
        self.switched_to = []
        self.connects = 0
        self.disconnects = 0
        self.signed_in = []

    async def __call__(self, request):
        from tgmint.passkeys import FinishPasskeyLoginRequest, InitPasskeyLoginRequest

        if isinstance(request, InitPasskeyLoginRequest):
            return (
                struct.pack("<I", 0xE2037789)
                + struct.pack("<I", 0x7D748D04)
                + TLObject.serialize_bytes(self.login_options_json)
            )
        assert isinstance(request, FinishPasskeyLoginRequest), request
        raise self.finish_error

    async def _switch_dc(self, dc_id):
        # what Telethon's _switch_dc does to the caller's session
        self.switched_to.append(dc_id)
        self.session.set_dc(dc_id, "91.108.4.1", 443)
        self.session.auth_key = None
        self.session.save()

    async def _disconnect(self):
        self.disconnects += 1

    async def connect(self):
        self.connects += 1

    async def sign_in(self, password=None):
        self.signed_in.append(password)
        return "me"

    async def _on_login(self, user):
        return user


class TestDatacenterRollback(unittest.TestCase):
    """A failed finish must not leave the caller's session on another DC.

    ``client._switch_dc`` rewrites the persistent session (new DC, auth key
    erased); without the rollback one expired challenge permanently moved the
    session file and lost its key.
    """

    def _store(self, tmpdir, home_dc=4):
        options = json.loads(REG_OPTIONS)
        options["user"]["id"] = _b64u_encode(f"{home_dc}:123456789".encode())
        cred = SoftwareAuthenticator.create_credential(json.dumps(options), alg=ALG_ES256)
        store = PasskeyStore.from_credential(cred, path=os.path.join(tmpdir, "k.json"))
        store.save()
        return store

    def _client(self, store, finish_error):
        session = _FakeSession(2, "149.154.167.51", 443, _FakeAuthKey(b"\x7f" * 256, 0x0123456789))
        return _SwitchableClient(
            session,
            login_options(os.urandom(32), _b64u_encode(store.credential_id)),
            finish_error,
        )

    def test_a_failed_finish_restores_the_session(self):
        from telethon.errors import BadRequestError

        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp)
            client = self._client(
                store, BadRequestError(object(), "PASSKEY_CHALLENGE_EXPIRED", 400))
            original_key = client.session.auth_key
            with self.assertRaises(PasskeyError) as ctx:
                asyncio.run(login_with_passkey(client, path=store.path))
            self.assertIn("PASSKEY_CHALLENGE_EXPIRED", str(ctx.exception))
            self.assertEqual(client.switched_to, [4])
            self.assertEqual(client.session.dc_id, 2)
            self.assertEqual(client.session.server_address, "149.154.167.51")
            self.assertEqual(client.session.port, 443)
            self.assertIs(client.session.auth_key, original_key)
            self.assertEqual(client.session.auth_key.key, b"\x7f" * 256)
            # ... and the connection was re-opened on the restored DC
            self.assertEqual((client.disconnects, client.connects), (1, 1))

    def test_two_factor_without_a_password_propagates_and_restores(self):
        from telethon.errors import SessionPasswordNeededError
        from tgmint import passkeys_core as core

        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp)
            client = self._client(store, SessionPasswordNeededError(object()))
            with self.assertRaises(core.TwoFactorRequired) as ctx:
                asyncio.run(login_with_passkey(client, path=store.path))
            self.assertNotIsInstance(ctx.exception, PasskeyError)
            self.assertEqual(client.signed_in, [])
            self.assertEqual(client.session.dc_id, 2)
            self.assertIsInstance(client.session.auth_key, _FakeAuthKey)

    def test_a_same_dc_login_needs_no_rollback(self):
        from telethon.errors import BadRequestError

        with tempfile.TemporaryDirectory() as tmp:
            store = self._store(tmp, home_dc=2)
            client = self._client(
                store, BadRequestError(object(), "PASSKEY_SIGNATURE_INVALID", 400))
            with self.assertRaises(PasskeyError):
                asyncio.run(login_with_passkey(client, path=store.path))
            # nothing was switched, so nothing is torn down either
            self.assertEqual(client.switched_to, [])
            self.assertEqual((client.disconnects, client.connects), (0, 0))
            self.assertEqual(client.session.dc_id, 2)


class TestRegisterPasskeyApiDrift(unittest.TestCase):
    """register_passkey mirrors the pyrogram driver's signature (alg=)."""

    def test_two_factor_required_is_reexported(self):
        from tgmint import passkeys as telethon_driver
        from tgmint import passkeys_core as core

        self.assertIs(telethon_driver.TwoFactorRequired, core.TwoFactorRequired)
        self.assertIn("TwoFactorRequired", telethon_driver.__all__)

    def test_the_alg_parameter_exists_on_both_drivers(self):
        import inspect

        from tgmint import passkeys as telethon_driver
        from tgmint import passkeys_pyrogram as pyrogram_driver

        for module in (telethon_driver, pyrogram_driver):
            with self.subTest(module=module.__name__):
                parameters = inspect.signature(module.register_passkey).parameters
                self.assertIn("alg", parameters)
                self.assertIsNone(parameters["alg"].default)


if __name__ == "__main__":
    unittest.main()
