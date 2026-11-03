"""Offline tests for :mod:`tgmint.passkeys_pyrogram` — the Pyrogram driver.

The driver is the thin half of the passkey work: the ceremony, the crypto and
the TL spec all live in :mod:`tgmint.passkeys_core`, and this module only

* converts the core's field dicts into a distribution's generated ``raw``
  classes (``build_request``),
* invokes them on a client, and
* normalizes the framework's response objects back to the neutral shapes.

So the obligations pinned here are exactly those three, plus the login
choreography the driver has to own (challenge on the current connection,
counter persisted before the finish, the DC hop, 2FA, and restore-on-failure):

* **Byte identity** — for every passkey message, the object ``build_request``
  returns must serialize with the framework's own ``write()`` to the exact
  bytes :func:`tgmint.passkeys_core.encode_request` produces.  The core is
  itself pinned against the hand-written Telethon classes in
  ``test_passkeys_core.py``, so this compares against the same oracle.
* **Conversion shape** — nested objects, unions, ``dataJSON`` wrappers, the
  derived ``flags`` word, and the signed ``from_auth_key_id`` edge.
* **Normalization** — responses are crafted as raw TL bytes here (with the
  test's own packers) and parsed by the framework's own reader, so the
  normalization is exercised on genuine framework objects, never on mocks of
  them.
* **Choreography** — through a duck-typed fake client (no socket, no
  session file): invocation order, counter-before-finish, the cross-DC plan,
  2FA, and the restore path.

Everything skips when no Pyrogram-family distribution is importable (CI
without kurigram) or when the installed one predates the passkey constructors
(hydrogram), keeping the suite green.
"""

import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import types as pytypes
import unittest

import tgmint.passkeys_core as core
from tgmint import passkeys_pyrogram as drv

HAS_PYROGRAM = False
try:  # kurigram, pyrofork, or any other distribution providing `pyrogram`
    import pyrogram
    from pyrogram import errors as pyrogram_errors
    from pyrogram import raw
    from pyrogram import types as pyrogram_types
    from pyrogram.raw.core.tl_object import TLObject
    from pyrogram import Client

    HAS_PYROGRAM = True
except Exception:  # nocov - environment dependent
    pyrogram = None
    raw = None

# The passkey layer only exists from kurigram 2.2.26 (layer 229) /
# pyrofork 2.3.69 (layer 220) on; hydrogram 0.2.0 (layer 181) lacks it.
HAS_PASSKEY_LAYER = False
if HAS_PYROGRAM:  # nocov - environment dependent
    try:
        HAS_PASSKEY_LAYER = all(
            hasattr(raw.functions.account, name)
            for name in (
                "InitPasskeyRegistration",
                "RegisterPasskey",
                "GetPasskeys",
                "DeletePasskey",
            )
        ) and all(
            hasattr(raw.functions.auth, name)
            for name in ("InitPasskeyLogin", "FinishPasskeyLogin")
        )
    except AttributeError:
        HAS_PASSKEY_LAYER = False

SKIP_REASON = None
if not HAS_PYROGRAM:
    SKIP_REASON = (
        "no pyrogram-family distribution installed "
        "(pip install kurigram; tgmint's Pyrogram passkey driver needs one)"
    )
elif not HAS_PASSKEY_LAYER:
    SKIP_REASON = (
        f"the installed pyrogram distribution ({drv._distribution()}) has no "
        "passkey raw layer (need kurigram >= 2.2.26 or pyrofork >= 2.3.69)"
    )

_SRC = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"
)

# --- fixed values used across the module -----------------------------------
API_ID = 2040
API_HASH = "0123456789abcdef0123456789abcdef"
USER_ID = 777000
CREDENTIAL_B64 = core._b64u_encode(b"\x11" * 32)
CLIENT_DATA = json.dumps({
    "type": "webauthn.create",
    "challenge": core._b64u_encode(b"\x02" * 32),
    "origin": core.DEFAULT_ORIGIN,
    "crossOrigin": False,
})
LOGIN_CLIENT_DATA = json.dumps({
    "type": "webauthn.get",
    "challenge": core._b64u_encode(b"\x03" * 32),
    "origin": core.DEFAULT_ORIGIN,
    "crossOrigin": False,
})

# constructor ids (independent literals: the test must not borrow the code's)
CTOR_OPTIONS_REGISTER = 0xE16B5CE1
CTOR_OPTIONS_LOGIN = 0xE2037789
CTOR_DATAJSON = 0x7D748D04
CTOR_PASSKEY = 0x98613EBF
CTOR_PASSKEYS = 0xF8E0AA1C
CTOR_VECTOR = 0x1CB5C415
CTOR_AUTHORIZATION = 0x2EA2C0D4
CTOR_SIGN_UP_REQUIRED = 0x44747E9A
CTOR_BOOL_TRUE = 0x997275B5
CTOR_BOOL_FALSE = 0xBC799737
CTOR_USER_LAYER229 = 0xB1B8CC83  # the user kurigram's layer 229 parses


# ---------------------------------------------------------------------------
# Independent TL packers (the test never borrows the driver's writer)
# ---------------------------------------------------------------------------

def tl_bytes(data):
    """TL ``bytes``/``string`` encoding, written here from the spec."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if len(data) < 254:
        head, padding = bytes([len(data)]), (len(data) + 1) % 4
    else:
        head = bytes([0xFE, len(data) % 256, (len(data) >> 8) % 256,
                      (len(data) >> 16) % 256])
        padding = len(data) % 4
    return head + data + b"\x00" * ((4 - padding) if padding else 0)


def options_payload(wrapper_ctor, options_json):
    """account.passkeyRegistrationOptions / auth.passkeyLoginOptions."""
    return (struct.pack("<I", wrapper_ctor) + struct.pack("<I", CTOR_DATAJSON)
            + tl_bytes(options_json))


def passkey_payload(passkey_id="cred-id", name="My Passkey", date=1730000000,
                    emoji=None, last_usage=None, constructor=CTOR_PASSKEY):
    flags = (1 if emoji is not None else 0) | (2 if last_usage is not None else 0)
    body = (struct.pack("<I", constructor) + struct.pack("<I", flags)
            + tl_bytes(passkey_id) + tl_bytes(name) + struct.pack("<i", date))
    if emoji is not None:
        body += struct.pack("<Q", emoji & 0xFFFFFFFFFFFFFFFF)
    if last_usage is not None:
        body += struct.pack("<i", last_usage)
    return body


def passkeys_payload(items):
    return (struct.pack("<I", CTOR_PASSKEYS) + struct.pack("<I", CTOR_VECTOR)
            + struct.pack("<i", len(items)) + b"".join(items))


def user_payload(user_id, constructor=CTOR_USER_LAYER229):
    """user#b1b8cc83 flags:# flags2:# id:long (what layer 229 parses)."""
    return (struct.pack("<I", constructor) + struct.pack("<I", 0)
            + struct.pack("<I", 0) + struct.pack("<q", user_id))


def authorization_payload(user_id=USER_ID, *, constructor=CTOR_AUTHORIZATION,
                          user_constructor=CTOR_USER_LAYER229, tmp_sessions=None,
                          otherwise_relogin_days=None, future_auth_token=None):
    flags = 0
    tail = b""
    if otherwise_relogin_days is not None:
        flags |= 2
    if tmp_sessions is not None:
        flags |= 1
    if future_auth_token is not None:
        flags |= 4
    head = struct.pack("<I", constructor) + struct.pack("<I", flags)
    if otherwise_relogin_days is not None:
        head += struct.pack("<i", otherwise_relogin_days)
    if tmp_sessions is not None:
        head += struct.pack("<i", tmp_sessions)
    if future_auth_token is not None:
        head += tl_bytes(future_auth_token)
    if constructor == CTOR_SIGN_UP_REQUIRED:
        return head
    return head + user_payload(user_id, user_constructor)


def parse_payload(payload):
    """Parse a response payload with the distribution's own reader."""
    return TLObject.read(io.BytesIO(payload))


# ---------------------------------------------------------------------------
# Field dicts (the shapes the core's builders emit)
# ---------------------------------------------------------------------------

def register_fields(client_data=CLIENT_DATA, attestation=b"\x01\x02\x03",
                    b64=CREDENTIAL_B64):
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


def login_fields(user_handle=f"2:{USER_ID}", **extra):
    fields = {
        "credential": {
            "id": CREDENTIAL_B64,
            "raw_id": CREDENTIAL_B64,
            "response": {
                "_": "inputPasskeyResponseLogin",
                "client_data": LOGIN_CLIENT_DATA,
                "authenticator_data": b"\x20" * 37,
                "signature": b"\x30" * 70,
                "user_handle": user_handle,
            },
        },
    }
    fields.update(extra)
    return fields


def registration_options(home_dc=2, user_id=USER_ID):
    return json.dumps({
        "rp": {"id": "web.telegram.org", "name": "Telegram"},
        "user": {
            "id": core._b64u_encode(f"{home_dc}:{user_id}".encode()),
            "name": "user",
            "displayName": "User",
        },
        "challenge": core._b64u_encode(b"\x02" * 32),
        "pubKeyCredParams": [{"type": "public-key", "alg": -7},
                             {"type": "public-key", "alg": -8}],
        "timeout": 60000,
        "attestation": "none",
    })


def login_options(credential_b64=CREDENTIAL_B64):
    return json.dumps({
        "challenge": core._b64u_encode(b"\x03" * 32),
        "rpId": "web.telegram.org",
        "allowCredentials": [{"type": "public-key", "id": credential_b64}],
        "userVerification": "required",
    })


# ---------------------------------------------------------------------------
# (a) Byte identity: build_request == core.encode_request
# ---------------------------------------------------------------------------

@unittest.skipIf(SKIP_REASON is not None, SKIP_REASON or "")
class TlByteIdentityTest(unittest.TestCase):
    """The generated class must write exactly the core's bytes, per message."""

    def assert_identical(self, name, fields):
        built = drv.build_request(name, fields)
        self.assertEqual(
            built.write(),
            core.encode_request(name, fields),
            f"{name}: framework bytes differ from the neutral writer",
        )
        return built

    def test_every_message_from_the_spec(self):
        cases = {
            "initPasskeyRegistration": {},
            "registerPasskey": register_fields(),
            "getPasskeys": {},
            "deletePasskey": {"id": "cred-id"},
            "initPasskeyLogin": {"api_id": API_ID, "api_hash": API_HASH},
            "finishPasskeyLogin": login_fields(),
        }
        self.assertEqual(sorted(cases), sorted(core.PASSKEY_TL_SPEC["messages"]))
        for name, fields in cases.items():
            with self.subTest(message=name):
                self.assert_identical(name, fields)

    def test_finish_with_dc_handoff_both_flag_spellings(self):
        for key_id in (6563825541305743292, -1, 0, -(2 ** 63)):
            with self.subTest(auth_key_id=key_id):
                fields = login_fields(from_dc_id=4, from_auth_key_id=key_id)
                built = self.assert_identical("finishPasskeyLogin", fields)
                self.assertEqual(built.from_dc_id, 4)
                self.assertEqual(built.from_auth_key_id, key_id)
                # flags word: bit 0 set, and only bit 0
                self.assertEqual(built.write()[4:8], struct.pack("<I", 1))

    def test_finish_without_dc_handoff_writes_flags_zero(self):
        built = self.assert_identical("finishPasskeyLogin", login_fields())
        self.assertIsNone(built.from_dc_id)
        self.assertIsNone(built.from_auth_key_id)
        self.assertEqual(built.write()[4:8], b"\x00\x00\x00\x00")
        # and the whole request is the credential with no extra fields
        self.assertEqual(len(built.write()), 8 + len(built.credential.write()))

    def test_finish_auth_key_id_unsigned_spelling(self):
        # a key id >= 2**63 spelled unsigned: pyrogram's Long is signed, so the
        # driver must normalize it — and the bytes must still match the core
        unsigned = 2 ** 63 + 12345
        fields = login_fields(from_dc_id=4, from_auth_key_id=unsigned)
        built = self.assert_identical("finishPasskeyLogin", fields)
        self.assertEqual(built.from_auth_key_id, unsigned - (1 << 64))

    def test_finish_auth_key_id_defaults_when_only_dc_is_sent(self):
        fields = login_fields(from_dc_id=2)
        built = self.assert_identical("finishPasskeyLogin", fields)
        # the Telethon class writes `from_auth_key_id or 0`
        self.assertEqual(built.from_auth_key_id, 0)

    def test_long_attestation_crosses_the_254_byte_boundary(self):
        fields = register_fields(attestation=b"\xA5" * 300)
        built = self.assert_identical("registerPasskey", fields)
        self.assertEqual(built.credential.response.attestation_data, b"\xA5" * 300)

    def test_spec_name_spellings_resolve_to_the_same_object(self):
        reference = drv.build_request("deletePasskey", {"id": "x"}).write()
        for spelling in ("deletePasskey", "account.deletePasskey",
                         "DeletePasskeyRequest"):
            with self.subTest(spelling=spelling):
                self.assertEqual(
                    drv.build_request(spelling, {"id": "x"}).write(), reference
                )

    def test_built_objects_are_the_distributions_own_classes(self):
        request = drv.build_request("registerPasskey", register_fields())
        self.assertEqual(type(request).ID, 0x55B41FD6)
        self.assertIn("RegisterPasskey", type(request).__name__)
        self.assertIn("pyrogram", type(request).__module__)


# ---------------------------------------------------------------------------
# (b) Field dict -> class conversion
# ---------------------------------------------------------------------------

@unittest.skipIf(SKIP_REASON is not None, SKIP_REASON or "")
class FieldConversionTest(unittest.TestCase):
    """Nested objects, unions, DataJSON wrappers, flags and defaults."""

    def test_nested_registration_objects(self):
        built = drv.build_request("registerPasskey", register_fields())
        credential = built.credential
        self.assertEqual(credential.id, CREDENTIAL_B64)
        self.assertEqual(credential.raw_id, CREDENTIAL_B64)
        self.assertEqual(type(credential.response).__name__,
                         "InputPasskeyResponseRegister")
        self.assertEqual(type(credential.response.client_data).__name__, "DataJSON")
        self.assertEqual(credential.response.client_data.data, CLIENT_DATA)
        self.assertEqual(credential.response.attestation_data, b"\x01\x02\x03")

    def test_nested_login_objects(self):
        built = drv.build_request("finishPasskeyLogin", login_fields())
        response = built.credential.response
        self.assertEqual(type(response).__name__, "InputPasskeyResponseLogin")
        self.assertEqual(response.client_data.data, LOGIN_CLIENT_DATA)
        self.assertEqual(response.authenticator_data, b"\x20" * 37)
        self.assertEqual(response.signature, b"\x30" * 70)
        self.assertEqual(response.user_handle, f"2:{USER_ID}")

    def test_datajson_accepts_the_bare_string(self):
        fields = register_fields(client_data=CLIENT_DATA)
        self.assertIsInstance(fields["credential"]["response"]["client_data"], str)
        bare = drv.build_request("registerPasskey", fields)
        wrapped = drv.build_request(
            "registerPasskey",
            register_fields(client_data={"data": CLIENT_DATA}),
        )
        self.assertEqual(bare.write(), wrapped.write())
        self.assertEqual(bare.credential.response.client_data.data, CLIENT_DATA)

    def test_union_constructor_name_spellings(self):
        reference = drv.build_request("registerPasskey", register_fields()).write()
        for spelling in ("inputPasskeyResponseRegister",
                         "InputPasskeyResponseRegister",
                         "input_passkey_response_register"):
            with self.subTest(spelling=spelling):
                fields = register_fields()
                fields["credential"]["response"]["_"] = spelling
                self.assertEqual(
                    drv.build_request("registerPasskey", fields).write(), reference
                )

    def test_union_needs_an_explicit_constructor_when_ambiguous(self):
        fields = login_fields()
        del fields["credential"]["response"]["_"]
        with self.assertRaises(core.PasskeyError) as ctx:
            drv.build_request("finishPasskeyLogin", fields)
        self.assertIn("constructor", str(ctx.exception))

    def test_nested_values_must_be_field_dicts(self):
        # the core's contract is field dicts; a pre-built raw object is not
        # silently accepted (no guessing about which field it stands for)
        fields = register_fields(client_data=raw.types.DataJSON(data=CLIENT_DATA))
        with self.assertRaises(core.PasskeyError) as ctx:
            drv.build_request("registerPasskey", fields)
        self.assertIn("field dict expected", str(ctx.exception))

    def test_from_auth_key_id_negative_and_unsigned_forms_agree(self):
        low = drv.build_request(
            "finishPasskeyLogin",
            login_fields(from_dc_id=2, from_auth_key_id=42),
        )
        high = drv.build_request(
            "finishPasskeyLogin",
            login_fields(from_dc_id=2, from_auth_key_id=2 ** 63 + 42),
        )
        self.assertEqual(high.from_auth_key_id, 2 ** 63 + 42 - (1 << 64))
        self.assertNotEqual(low.write(), high.write())
        self.assertEqual(
            high.write(),
            core.encode_request(
                "finishPasskeyLogin",
                login_fields(from_dc_id=2, from_auth_key_id=2 ** 63 + 42),
            ),
        )

    def test_rejects_what_the_core_rejects(self):
        cases = [
            ("nope", {}, "unknown passkey message"),
            ("deletePasskey", {"id": "x", "extra": 1}, "unknown field"),
            ("initPasskeyLogin", {"api_id": API_ID}, "missing field"),
            ("initPasskeyLogin", {"api_id": 1 << 40, "api_hash": "h"}, "out of range"),
            ("initPasskeyLogin", {"api_id": "2040", "api_hash": "h"}, "int field"),
            ("deletePasskey", {"id": b"bytes"}, "str expected"),
            ("finishPasskeyLogin", {"credential": None}, "None"),
        ]
        for name, fields, message in cases:
            with self.subTest(name=name, fields=fields):
                with self.assertRaises(core.PasskeyError) as ctx:
                    drv.build_request(name, fields)
                self.assertIn(message, str(ctx.exception))

    def test_matches_the_cores_own_field_builders(self):
        # the dicts that actually travel through the ceremony, not just
        # hand-written ones: registration_fields() and finish_login_fields()
        credential = core.SoftwareAuthenticator.create_credential(
            registration_options())
        fields = core.registration_fields(credential)
        self.assertEqual(
            drv.build_request("registerPasskey", fields).write(),
            core.encode_request("registerPasskey", fields),
        )

        assertion = {
            "id": CREDENTIAL_B64,
            "client_data_json": LOGIN_CLIENT_DATA,
            "authenticator_data": b"\x01" * 37,
            "signature": b"\x02" * 70,
            "user_handle": f"2:{USER_ID}",
        }
        fields = core.finish_login_fields(
            assertion, from_dc_id=2, from_auth_key_id=2 ** 63 + 9
        )
        built = drv.build_request("finishPasskeyLogin", fields)
        self.assertEqual(
            built.write(), core.encode_request("finishPasskeyLogin", fields)
        )
        # finish_login_fields already normalized it to the signed form
        self.assertEqual(built.from_auth_key_id, 2 ** 63 + 9 - (1 << 64))

    def test_accepts_what_the_core_accepts(self):
        for name, fields in (
            ("initPasskeyRegistration", None),
            ("getPasskeys", None),
            ("deletePasskey", {"id": ""}),
            ("initPasskeyLogin", {"api_id": -(1 << 31), "api_hash": ""}),
        ):
            with self.subTest(name=name):
                self.assertEqual(
                    drv.build_request(name, fields).write(),
                    core.encode_request(name, fields),
                )


# ---------------------------------------------------------------------------
# Fake clients: one for normalization, one for the ceremony
# ---------------------------------------------------------------------------

class RawStubClient:
    """Answers each invoke with a canned object; records what it was sent."""

    def __init__(self, responses, *, is_connected=True):
        self.responses = dict(responses)
        self.requests = []
        self.is_connected = is_connected
        self.api_id, self.api_hash = API_ID, API_HASH

    @property
    def sent(self):
        return [type(request).__name__ for request in self.requests]

    async def invoke(self, request):
        name = type(request).__name__
        self.requests.append(request)
        return self._answer(name, request)

    def _answer(self, name, request):
        answer = self.responses[name]
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, pytypes.FunctionType):  # a responder, not an object
            return answer(request)
        return answer


UNSET = object()


class FakeStorage:
    def __init__(self, **values):
        self.values = dict(values)

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)

        async def accessor(value=UNSET):
            if value is UNSET:
                return self.values.get(name)
            self.values[name] = value

        return accessor


class FakeSession:
    def __init__(self, dc_id, auth_key):
        self.dc_id = dc_id
        self.auth_key = auth_key
        self.auth_key_id = hashlib.sha1(auth_key).digest()[-8:]
        self.stop_calls = 0
        self.start_calls = 0

    async def stop(self):
        self.stop_calls += 1

    async def start(self):
        self.start_calls += 1


class FakeSessionWithoutKeyId:
    """A session that only carries the key (the sha1 fallback path)."""

    def __init__(self, dc_id, auth_key):
        self.dc_id = dc_id
        self.auth_key = auth_key


class FakeClient:
    """Duck-typed Pyrogram client: no socket, no session file, no framework."""

    def __init__(self, *, dc_id=2, responses=None):
        self.api_id, self.api_hash = API_ID, API_HASH
        self.is_connected = True
        self.ipv6 = False
        key = b"\x7f" * 256
        self.session = FakeSession(dc_id, key)
        self.storage = FakeStorage(
            dc_id=dc_id,
            server_address="149.154.167.51",
            port=443,
            auth_key=key,
            user_id=None,
            is_bot=None,
        )
        self.responses = dict(responses or {})
        self.dc_options = {4: pytypes.SimpleNamespace(
            ip_address="91.108.4.1", port=443)}
        self.calls = []
        self.requests = []
        self.session_kwargs = []
        self.password_calls = []

    @property
    def sent(self):
        return [type(request).__name__ for request in self.requests]

    async def invoke(self, request):
        name = type(request).__name__
        self.requests.append(request)
        self.calls.append(("invoke", name, getattr(self.session, "dc_id", None)))
        if name not in self.responses:
            raise AssertionError(f"unexpected invoke {name}")
        return self._answer(name, request)

    def _answer(self, name, request):
        answer = self.responses[name]
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, pytypes.FunctionType):  # a responder, not an object
            return answer(request)
        return answer

    async def get_dc_option(self, dc_id, ipv6=False):
        self.calls.append(("get_dc_option", dc_id))
        return self.dc_options[dc_id]

    async def get_session(self, **kwargs):
        self.calls.append(("get_session", kwargs.get("dc_id")))
        self.session_kwargs.append(kwargs)
        return FakeSession(kwargs["dc_id"], b"\x5a" * 256)

    async def check_password(self, password):
        self.calls.append(("check_password", getattr(self.session, "dc_id", None)))
        self.password_calls.append(password)
        await self.storage.user_id(USER_ID)
        await self.storage.is_bot(False)
        return pytypes.SimpleNamespace(id=USER_ID, via_check_password=True)


def make_store(tmpdir, *, home_dc=2, name="k.passkey.json", credential=None):
    """A real passkey store (real ES256/Ed25519 credential) for the ceremony."""
    credential = credential or core.SoftwareAuthenticator.create_credential(
        registration_options(home_dc=home_dc)
    )
    store = core.PasskeyStore.from_credential(
        credential, path=os.path.join(tmpdir, name)
    )
    store.telegram_passkey_id = core._b64u_encode(credential.credential_id)
    store.save()
    return store


def login_responses(store, *, finish=None, tmp_sessions=None):
    """The canned answers a login ceremony needs, parsed from raw bytes."""
    options = json.dumps({
        "challenge": core._b64u_encode(b"\x09" * 32),
        "rpId": store.rp_id,
        "allowCredentials": [
            {"type": "public-key", "id": core._b64u_encode(store.credential_id)}
        ],
        "userVerification": "required",
    })
    return {
        "InitPasskeyLogin": parse_payload(
            options_payload(CTOR_OPTIONS_LOGIN, options)
        ),
        "FinishPasskeyLogin": finish
        if finish is not None
        else parse_payload(authorization_payload(
            USER_ID, tmp_sessions=tmp_sessions)),
    }


# ---------------------------------------------------------------------------
# (c) Native normalization of framework response objects
# ---------------------------------------------------------------------------

@unittest.skipIf(SKIP_REASON is not None, SKIP_REASON or "")
class OptionsNormalizationTest(unittest.IsolatedAsyncioTestCase):
    async def test_registration_options_are_the_json_string(self):
        response = parse_payload(
            options_payload(CTOR_OPTIONS_REGISTER, registration_options())
        )
        client = RawStubClient({"InitPasskeyRegistration": response})
        invoker = drv.PyrogramInvoker(client)
        self.assertEqual(
            await invoker.native("initPasskeyRegistration"),
            registration_options(),
        )
        self.assertEqual(client.sent, ["InitPasskeyRegistration"])
        # ... and through the core's ceremony step
        self.assertEqual(
            await core.fetch_registration_options(invoker), registration_options()
        )

    async def test_login_options_are_the_json_string(self):
        response = parse_payload(options_payload(CTOR_OPTIONS_LOGIN, login_options()))
        client = RawStubClient({"InitPasskeyLogin": response})
        invoker = drv.PyrogramInvoker(client)
        self.assertEqual(
            await core.fetch_login_challenge(
                invoker, api_id=API_ID, api_hash=API_HASH
            ),
            login_options(),
        )
        sent = client.requests[0]
        self.assertEqual(sent.api_id, API_ID)
        self.assertEqual(sent.api_hash, API_HASH)

    async def test_the_invoker_records_what_it_sent(self):
        client = RawStubClient({
            "InitPasskeyRegistration": parse_payload(
                options_payload(CTOR_OPTIONS_REGISTER, registration_options())),
            "GetPasskeys": parse_payload(passkeys_payload([])),
        })
        invoker = drv.PyrogramInvoker(client)
        await invoker.native("initPasskeyRegistration")
        await invoker.native("getPasskeys")
        self.assertEqual(
            [type(request).__name__ for request in invoker.sent],
            ["InitPasskeyRegistration", "GetPasskeys"],
        )

    async def test_wrong_response_shape_is_reported(self):
        client = RawStubClient({
            "InitPasskeyRegistration": parse_payload(
                passkeys_payload([passkey_payload()])
            )
        })
        with self.assertRaises(core.PasskeyError) as ctx:
            await drv.PyrogramInvoker(client).native("initPasskeyRegistration")
        self.assertIn("dataJSON", str(ctx.exception))


@unittest.skipIf(SKIP_REASON is not None, SKIP_REASON or "")
class PasskeyNormalizationTest(unittest.IsolatedAsyncioTestCase):
    async def test_register_passkey_becomes_passkey_info(self):
        payload = passkey_payload("cred-1", "My Passkey", 1730000000,
                                  emoji=5361605941848833135,
                                  last_usage=1730000100)
        client = RawStubClient({"RegisterPasskey": parse_payload(payload)})
        invoker = drv.PyrogramInvoker(client)
        info = await invoker.native("registerPasskey", register_fields())
        self.assertIsInstance(info, core.PasskeyInfo)
        self.assertEqual(
            (info.id, info.name, info.date, info.software_emoji_id,
             info.last_usage_date),
            ("cred-1", "My Passkey", 1730000000, 5361605941848833135, 1730000100),
        )
        # identical to what the neutral parser reads from the same bytes
        self.assertEqual(info, core.parse_result("registerPasskey", payload))

    async def test_flag_bits_absent_mean_none(self):
        client = RawStubClient({"RegisterPasskey": parse_payload(passkey_payload())})
        info = await drv.PyrogramInvoker(client).native(
            "registerPasskey", register_fields())
        self.assertIsNone(info.software_emoji_id)
        self.assertIsNone(info.last_usage_date)

    async def test_huge_emoji_id_is_normalized_unsigned(self):
        # pyrogram reads `long` signed; the core's spec says unsigned
        payload = passkey_payload(emoji=2 ** 63 + 7)
        client = RawStubClient({"RegisterPasskey": parse_payload(payload)})
        info = await drv.PyrogramInvoker(client).native(
            "registerPasskey", register_fields())
        self.assertEqual(info.software_emoji_id, 2 ** 63 + 7)
        self.assertEqual(info, core.parse_result("registerPasskey", payload))

    async def test_get_passkeys_becomes_a_list(self):
        payload = passkeys_payload([
            passkey_payload("a", "First", 1730000001),
            passkey_payload("b", "Second", 1730000002, emoji=5, last_usage=17),
        ])
        client = RawStubClient({"GetPasskeys": parse_payload(payload)})
        listed = await core.list_passkeys_core(drv.PyrogramInvoker(client))
        self.assertEqual([item.id for item in listed], ["a", "b"])
        self.assertEqual(listed, core.parse_result("getPasskeys", payload))
        self.assertEqual(listed[1].software_emoji_id, 5)
        self.assertEqual(listed[1].last_usage_date, 17)

    async def test_get_passkeys_empty(self):
        client = RawStubClient({"GetPasskeys": parse_payload(passkeys_payload([]))})
        self.assertEqual(await core.list_passkeys_core(drv.PyrogramInvoker(client)), [])

    async def test_delete_passkey_becomes_bool(self):
        for payload, expected in (
            (struct.pack("<I", CTOR_BOOL_TRUE), True),
            (struct.pack("<I", CTOR_BOOL_FALSE), False),
        ):
            with self.subTest(expected=expected):
                client = RawStubClient({"DeletePasskey": parse_payload(payload)})
                invoker = drv.PyrogramInvoker(client)
                self.assertIs(await core.delete_passkey_core(invoker, "cred-1"),
                              expected)
                self.assertEqual(client.requests[0].id, "cred-1")


@unittest.skipIf(SKIP_REASON is not None, SKIP_REASON or "")
class AuthorizationNormalizationTest(unittest.IsolatedAsyncioTestCase):
    """finishPasskeyLogin: the bytes-vs-fields decision, on real objects."""

    async def test_reads_bytes_back_through_the_core_parser(self):
        payload = authorization_payload(USER_ID)
        client = RawStubClient({"FinishPasskeyLogin": parse_payload(payload)})
        invoker = drv.PyrogramInvoker(client)
        result = await core.finish_login(invoker, login_fields())
        self.assertIsInstance(result, core.AuthorizationResult)
        self.assertFalse(result.sign_up_required)
        self.assertEqual(result.constructor, CTOR_AUTHORIZATION)
        # pyrogram's writer reproduces the server's bytes exactly, so the core
        # parsed the *same* response the framework did; the user-flag table
        # knows layer 229's user#b1b8cc83, so the parse matches the driver's
        self.assertEqual(result.raw, payload)
        # layer 229's user constructor is not in the core's flag-word table,
        # so the driver had to take user_id from the framework's own parse
        self.assertEqual(result.user_constructor, CTOR_USER_LAYER229)
        self.assertEqual(result.user_id, USER_ID)
        self.assertIsNotNone(invoker.last_finish_response)

    async def test_tmp_sessions_is_carried(self):
        payload = authorization_payload(USER_ID, tmp_sessions=3,
                                        otherwise_relogin_days=30)
        client = RawStubClient({"FinishPasskeyLogin": parse_payload(payload)})
        result = await core.finish_login(drv.PyrogramInvoker(client), login_fields())
        self.assertEqual(result.tmp_sessions, 3)
        self.assertEqual(result.otherwise_relogin_days, 30)
        neutral = core.parse_result("finishPasskeyLogin", payload)
        for name in ("constructor", "sign_up_required", "tmp_sessions",
                     "otherwise_relogin_days", "future_auth_token",
                     "user_constructor", "raw"):
            with self.subTest(field=name):
                self.assertEqual(getattr(result, name), getattr(neutral, name))
        # the core's user-flag table knows both known user constructors
        # (L224 user#31774388 and L229 user#b1b8cc83), so the neutral parse
        # already yields the user id; the driver's fill is a no-op here
        self.assertEqual(neutral.user_id, USER_ID)
        self.assertEqual(result.user_id, USER_ID)

    async def test_sign_up_required_has_no_user(self):
        payload = authorization_payload(constructor=CTOR_SIGN_UP_REQUIRED)
        client = RawStubClient({"FinishPasskeyLogin": parse_payload(payload)})
        invoker = drv.PyrogramInvoker(client)
        result = await core.finish_login(invoker, login_fields())
        self.assertTrue(result.sign_up_required)
        self.assertIsNone(result.user_id)
        self.assertIsNone(getattr(invoker.last_finish_response, "user", None))

    async def test_field_path_when_the_object_cannot_be_reserialized(self):
        class Unserializable:
            """An auth.Authorization-shaped object with no write()."""

            ID = CTOR_AUTHORIZATION

            def __init__(self):
                self.user = pytypes.SimpleNamespace(ID=CTOR_USER_LAYER229, id=USER_ID)
                self.tmp_sessions = 2
                self.otherwise_relogin_days = None
                self.future_auth_token = None

        client = RawStubClient({"FinishPasskeyLogin": Unserializable()})
        result = await core.finish_login(drv.PyrogramInvoker(client), login_fields())
        self.assertEqual(result.constructor, CTOR_AUTHORIZATION)
        self.assertEqual(result.user_id, USER_ID)
        self.assertEqual(result.user_constructor, CTOR_USER_LAYER229)
        self.assertEqual(result.tmp_sessions, 2)
        self.assertEqual(result.raw, b"")

    async def test_unparseable_bytes_fall_back_to_the_fields(self):
        class Lying:
            """write() returns something the core cannot parse."""

            ID = CTOR_AUTHORIZATION

            def __init__(self):
                self.user = pytypes.SimpleNamespace(ID=CTOR_USER_LAYER229, id=USER_ID)
                self.tmp_sessions = None
                self.otherwise_relogin_days = None
                self.future_auth_token = None

            def write(self):
                return b"\x01\x02"

        client = RawStubClient({"FinishPasskeyLogin": Lying()})
        result = await core.finish_login(drv.PyrogramInvoker(client), login_fields())
        self.assertEqual(result.user_id, USER_ID)
        self.assertEqual(result.raw, b"\x01\x02")


@unittest.skipIf(SKIP_REASON is not None, SKIP_REASON or "")
class InvokerErrorTest(unittest.IsolatedAsyncioTestCase):
    """Framework signals are translated into the core's error contract."""

    def _bad_request(self, value):
        # is_unknown=False: the framework's own mapping for unmapped errors
        # also appends to ./unknown_errors.txt, which a test must not do
        return pyrogram_errors.BadRequest(value=value)

    async def test_two_factor_becomes_the_neutral_signal(self):
        client = RawStubClient({
            "FinishPasskeyLogin": pyrogram_errors.SessionPasswordNeeded()
        })
        with self.assertRaises(core.TwoFactorRequired):
            await core.finish_login(drv.PyrogramInvoker(client), login_fields())

    async def test_two_factor_is_not_a_passkey_error(self):
        # data-guard code catches PasskeyError; a 2FA prompt must survive it
        self.assertFalse(issubclass(core.TwoFactorRequired, core.PasskeyError))

    async def test_bad_request_becomes_passkey_error_with_the_server_text(self):
        client = RawStubClient({
            "FinishPasskeyLogin": self._bad_request("[400 PASSKEY_CHALLENGE_EXPIRED]")
        })
        with self.assertRaises(core.PasskeyError) as ctx:
            await core.finish_login(drv.PyrogramInvoker(client), login_fields())
        message = str(ctx.exception)
        self.assertIn("PASSKEY_CHALLENGE_EXPIRED", message)
        self.assertIn("from_dc_id", message)  # the hint

    async def test_named_passkey_errors_are_handled_too(self):
        # kurigram maps exactly two passkey errors to named classes; the rest
        # arrive as a generic BadRequest with the code in .value
        cases = (
            (pyrogram_errors.PasskeyCredentialNotFound, "not registered"),
            (pyrogram_errors.PasskeyOriginMismatch, "origin"),
            (lambda: self._bad_request("[400 PASSKEY_SIGNATURE_INVALID]"),
             "corrupt"),
        )
        for make, hint in cases:
            with self.subTest(hint=hint):
                client = RawStubClient({"FinishPasskeyLogin": make()})
                with self.assertRaises(core.PasskeyError) as ctx:
                    await core.finish_login(drv.PyrogramInvoker(client), login_fields())
                message = str(ctx.exception)
                self.assertIn("PASSKEY_", message)
                self.assertIn(hint, message)

    async def test_non_passkey_rpc_errors_are_left_to_the_framework(self):
        flood = pyrogram_errors.FloodWait(value=17)
        client = RawStubClient({"InitPasskeyLogin": flood})
        with self.assertRaises(pyrogram_errors.FloodWait):
            await core.fetch_login_challenge(
                drv.PyrogramInvoker(client), api_id=API_ID, api_hash=API_HASH
            )


# ---------------------------------------------------------------------------
# (d) Driver-level choreography against a fake client
# ---------------------------------------------------------------------------

@unittest.skipIf(SKIP_REASON is not None, SKIP_REASON or "")
class AuthKeyIdTest(unittest.TestCase):
    """The signed-int64 trap: pyrogram exposes the key id as raw bytes."""

    def test_bytes_attribute_is_little_endian(self):
        session = FakeSession(2, b"\x01" * 256)
        expected = int.from_bytes(hashlib.sha1(b"\x01" * 256).digest()[-8:], "little")
        self.assertEqual(drv._auth_key_id(session), core.to_signed_int64(expected))

    def test_sha1_fallback_without_the_attribute(self):
        session = FakeSessionWithoutKeyId(2, b"\x02" * 256)
        expected = int.from_bytes(hashlib.sha1(b"\x02" * 256).digest()[-8:], "little")
        self.assertEqual(drv._auth_key_id(session), core.to_signed_int64(expected))

    def test_high_bit_becomes_negative(self):
        session = pytypes.SimpleNamespace(auth_key_id=b"\xff" * 8)
        self.assertEqual(drv._auth_key_id(session), -1)

    def test_no_key_yet_is_none(self):
        self.assertIsNone(drv._auth_key_id(
            pytypes.SimpleNamespace(auth_key_id=None, auth_key=None)))


@unittest.skipIf(SKIP_REASON is not None, SKIP_REASON or "")
class LoginChoreographyTest(unittest.IsolatedAsyncioTestCase):
    """The login flow: order, counter, DC hop, bookkeeping — all offline."""

    async def test_same_dc_login(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = make_store(tmpdir, home_dc=2)
            client = FakeClient(dc_id=2, responses=login_responses(store))
            me = await drv.login_with_passkey(client, path=store.path)
        self.assertEqual(client.sent, ["InitPasskeyLogin", "FinishPasskeyLogin"])
        finish = client.requests[1]
        self.assertIsNone(finish.from_dc_id)
        self.assertIsNone(finish.from_auth_key_id)
        self.assertEqual(finish.credential.id,
                         core._b64u_encode(store.credential_id))
        self.assertEqual((me.id, type(me).__module__.split(".")[0]),
                         (USER_ID, "pyrogram"))
        self.assertEqual(client.storage.values["user_id"], USER_ID)
        self.assertIs(client.storage.values["is_bot"], False)

    async def test_counter_is_persisted_before_the_finish_call(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = make_store(tmpdir, home_dc=2)
            self.assertEqual(core.PasskeyStore.load(store.path).sign_count, 0)
            observed = []

            def respond(request):
                with open(store.path, encoding="utf-8") as handle:
                    observed.append(json.load(handle)["sign_count"])
                return parse_payload(authorization_payload(USER_ID))

            responses = login_responses(store)
            responses["FinishPasskeyLogin"] = respond
            client = FakeClient(dc_id=2, responses=responses)
            await drv.login_with_passkey(client, path=store.path)
            # the bump made by produce_assertion was already on disk when the
            # finish request went out (a failed login must not leave a stale,
            # reusable counter behind)
            self.assertEqual(observed, [1])
            self.assertEqual(core.PasskeyStore.load(store.path).sign_count, 1)

    async def test_cross_dc_login_switches_then_finishes_on_the_home_dc(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = make_store(tmpdir, home_dc=4)
            old_key = client_key = b"\x7f" * 256  # FakeClient's key
            responses = login_responses(store)
            client = FakeClient(dc_id=2, responses=responses)
            me = await drv.login_with_passkey(client, path=store.path)

            self.assertEqual(
                client.sent, ["InitPasskeyLogin", "FinishPasskeyLogin"]
            )
            self.assertEqual(client.calls[0][2], 2)       # challenge on dc 2
            self.assertEqual(client.calls[-1][2], 4)      # finish on dc 4
            self.assertIn(("get_dc_option", 4), client.calls)
            self.assertEqual(len(client.session_kwargs), 1)
            kwargs = client.session_kwargs[0]
            self.assertEqual(kwargs["dc_id"], 4)
            self.assertEqual(kwargs["server_address"], "91.108.4.1")
            self.assertEqual(kwargs["port"], 443)
            self.assertIs(kwargs["export_authorization"], False)
            self.assertIs(kwargs["temporary"], True)

            # the client really moved: session, and storage
            self.assertEqual(client.session.dc_id, 4)
            self.assertEqual(client.storage.values["dc_id"], 4)
            self.assertEqual(client.storage.values["server_address"], "91.108.4.1")
            self.assertEqual(client.storage.values["auth_key"], client.session.auth_key)
            self.assertEqual(client.storage.values["user_id"], USER_ID)

            finish = client.requests[-1]
            self.assertEqual(finish.from_dc_id, 2)
            self.assertEqual(
                finish.from_auth_key_id,
                core.to_signed_int64(int.from_bytes(
                    hashlib.sha1(old_key).digest()[-8:], "little")),
            )
        self.assertEqual(me.id, USER_ID)

    async def test_cross_dc_login_stops_the_old_session(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = make_store(tmpdir, home_dc=4)
            client = FakeClient(dc_id=2, responses=login_responses(store))
            old_session = client.session
            await drv.login_with_passkey(client, path=store.path)
            self.assertEqual(old_session.stop_calls, 1)
            self.assertEqual(client.session.dc_id, 4)

    async def test_two_factor_without_a_password_asks_for_one(self):
        """No password: the neutral signal propagates and the DC is restored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = make_store(tmpdir, home_dc=4)
            responses = login_responses(
                store, finish=pyrogram_errors.SessionPasswordNeeded()
            )
            client = FakeClient(dc_id=2, responses=responses)
            old_session = client.session
            with self.assertRaises(core.TwoFactorRequired) as ctx:
                await drv.login_with_passkey(client, path=store.path)
            # deliberately NOT a PasskeyError: a caller guarding against a
            # corrupt store must not swallow the password prompt
            self.assertNotIsInstance(ctx.exception, core.PasskeyError)
            self.assertIn("2FA", str(ctx.exception))
            self.assertIn("password", str(ctx.exception))
            self.assertEqual(client.password_calls, [])
            # a retry has to start from the DC it originally connected to
            self.assertIs(client.session, old_session)
            self.assertEqual(old_session.start_calls, 1)
            self.assertEqual(client.session.dc_id, 2)
            self.assertEqual(client.storage.values["dc_id"], 2)
            self.assertEqual(client.storage.values["auth_key"], b"\x7f" * 256)

    async def test_two_factor_with_a_password_completes_the_login(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = make_store(tmpdir, home_dc=4)
            responses = login_responses(
                store, finish=pyrogram_errors.SessionPasswordNeeded()
            )
            client = FakeClient(dc_id=2, responses=responses)
            me = await drv.login_with_passkey(
                client, path=store.path, password="hunter2"
            )
        self.assertEqual(client.password_calls, ["hunter2"])
        self.assertEqual(("check_password", 4), client.calls[-1])
        self.assertTrue(me.via_check_password)
        self.assertEqual(client.storage.values["user_id"], USER_ID)
        self.assertEqual(client.storage.values["dc_id"], 4)

    async def test_failure_after_the_switch_restores_the_client(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = make_store(tmpdir, home_dc=4)
            responses = login_responses(
                store,
                finish=pyrogram_errors.BadRequest(
                    value="[400 PASSKEY_SIGNATURE_INVALID]"
                ),
            )
            client = FakeClient(dc_id=2, responses=responses)
            old_session = client.session
            with self.assertRaises(core.PasskeyError) as ctx:
                await drv.login_with_passkey(client, path=store.path)
            self.assertIn("PASSKEY_SIGNATURE_INVALID", str(ctx.exception))
            # ... and the client is back on the DC it started from
            self.assertIs(client.session, old_session)
            self.assertEqual(old_session.start_calls, 1)
            self.assertEqual(client.storage.values["dc_id"], 2)
            self.assertEqual(client.storage.values["server_address"],
                             "149.154.167.51")
            self.assertEqual(client.storage.values["auth_key"], b"\x7f" * 256)

    async def test_cross_dc_without_get_session_says_so(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = make_store(tmpdir, home_dc=4)
            client = FakeClient(dc_id=2, responses=login_responses(store))
            client.get_session = None  # pyrofork shape: no Client.get_session
            with self.assertRaises(core.PasskeyError) as ctx:
                await drv.login_with_passkey(client, path=store.path)
            self.assertIn("get_session", str(ctx.exception))
            self.assertIn("kurigram", str(ctx.exception))

    async def test_disconnected_client_is_refused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = make_store(tmpdir, home_dc=2)
            client = FakeClient(dc_id=2, responses={})
            client.is_connected = False
            with self.assertRaises(core.PasskeyError) as ctx:
                await drv.login_with_passkey(client, path=store.path)
            self.assertIn("connect", str(ctx.exception))
            self.assertEqual(client.requests, [])

    async def test_sign_up_required_is_refused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = make_store(tmpdir, home_dc=2)
            responses = login_responses(store)
            responses["FinishPasskeyLogin"] = parse_payload(
                authorization_payload(constructor=CTOR_SIGN_UP_REQUIRED)
            )
            client = FakeClient(dc_id=2, responses=responses)
            with self.assertRaises(core.PasskeyError) as ctx:
                await drv.login_with_passkey(client, path=store.path)
            self.assertIn("SignUpRequired", str(ctx.exception))
            self.assertIsNone(client.storage.values["user_id"])


@unittest.skipIf(SKIP_REASON is not None, SKIP_REASON or "")
class RegisterChoreographyTest(unittest.IsolatedAsyncioTestCase):
    """Registration and the two list/delete wrappers, offline."""

    async def test_register_writes_the_store_after_the_server_accepts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "new.passkey.json")
            options = registration_options(home_dc=2)
            responses = {
                "InitPasskeyRegistration": parse_payload(
                    options_payload(CTOR_OPTIONS_REGISTER, options)),
                "RegisterPasskey": parse_payload(
                    passkey_payload("server-id", "server name", 1730000000)),
            }
            client = FakeClient(dc_id=2, responses=responses)
            info, store = await drv.register_passkey(
                client, path=path, name="my passkey")
            self.assertEqual(
                client.sent, ["InitPasskeyRegistration", "RegisterPasskey"])
            sent = client.requests[1]
            self.assertEqual(sent.credential.id,
                             core._b64u_encode(store.credential_id))
            client_data = json.loads(
                sent.credential.response.client_data.data)
            self.assertEqual(client_data["type"], "webauthn.create")
            self.assertEqual(client_data["challenge"],
                             json.loads(options)["challenge"])
            self.assertEqual(client_data["origin"], core.DEFAULT_ORIGIN)
            self.assertIsInstance(info, core.PasskeyInfo)
            self.assertEqual(info.id, "server-id")
            self.assertEqual(store.name, "my passkey")
            self.assertEqual(store.telegram_passkey_id, "server-id")
            # the file is a private, loadable tgmint store
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            reloaded = core.PasskeyStore.load(path)
            self.assertEqual(reloaded.credential_id, store.credential_id)
            self.assertEqual(reloaded.user_handle, f"2:{USER_ID}")

    async def test_register_failure_leaves_no_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "never.passkey.json")
            responses = {
                "InitPasskeyRegistration": parse_payload(
                    options_payload(CTOR_OPTIONS_REGISTER,
                                    registration_options(home_dc=2))),
                "RegisterPasskey": pyrogram_errors.BadRequest(
                    value="[400 PASSKEY_ORIGIN_MISMATCH]"),
            }
            client = FakeClient(dc_id=2, responses=responses)
            with self.assertRaises(core.PasskeyError):
                await drv.register_passkey(client, path=path)
            self.assertFalse(os.path.exists(path))

    async def test_list_and_delete_wrappers(self):
        payload = passkeys_payload([
            passkey_payload("one", "First", 1),
            passkey_payload("two", "Second", 2),
        ])
        responses = {
            "GetPasskeys": parse_payload(payload),
            "DeletePasskey": parse_payload(struct.pack("<I", CTOR_BOOL_TRUE)),
        }
        client = FakeClient(dc_id=2, responses=responses)
        listed = await drv.list_passkeys(client)
        self.assertEqual([item.id for item in listed], ["one", "two"])
        self.assertIs(await drv.delete_passkey(client, "one"), True)
        self.assertEqual(client.requests[-1].id, "one")


@unittest.skipIf(SKIP_REASON is not None, SKIP_REASON or "")
class RealClientSmokeTest(unittest.TestCase):
    """A REAL kurigram Client, constructed offline from a minted fingerprint.

    Construction (``in_memory=True``) opens no socket and writes no session
    file, and nothing here starts the client, so this is still an offline
    test — it only pins that the driver accepts the framework's own Client
    type and refuses one that was never connected (kurigram answers ``None``
    from ``is_connected`` in that state, not ``False``).
    """

    def _client(self):
        from tgmint.adapters.pyrogram import client_kwargs, installed_layer
        from tgmint.api import API
        from tgmint.fingerprint import Fingerprint

        layer = installed_layer()
        if layer is None:  # nocov - only if pyrogram broke mid-session
            self.skipTest("installed layer unreadable")
        fingerprint = Fingerprint.from_apidata(
            API.TelegramDesktop.Generate(
                system="windows", unique_id="passkey-driver", layer=layer
            )
        )
        return Client(":memory:", **client_kwargs(fingerprint), in_memory=True)

    def test_unconnected_real_client_is_refused(self):
        client = self._client()
        self.assertFalse(client.is_connected)
        with self.assertRaises(core.PasskeyError) as ctx:
            drv._invoker(client)
        self.assertIn("connect", str(ctx.exception))
        self.assertFalse(client.is_connected)  # nothing was started

    def test_invoker_accepts_a_real_client(self):
        invoker = drv.PyrogramInvoker(self._client())
        self.assertIsNone(invoker.last_finish_response)
        self.assertEqual(invoker.sent, [])

    def test_live_test_recipe_is_constructible(self):
        # the documented recipe: minted fingerprint -> client_kwargs -> Client
        client = self._client()
        for name in ("device_model", "system_version", "app_version",
                     "lang_code", "api_id", "api_hash"):
            self.assertTrue(getattr(client, name), name)


# ---------------------------------------------------------------------------
# Framework-optional behaviour
# ---------------------------------------------------------------------------

class SoftImportTest(unittest.TestCase):
    """The module must be importable, and explain itself, without pyrogram."""

    def test_imports_with_pyrogram_poisoned(self):
        script = r'''
import sys

BLOCKED = ("pyrogram",)
for _name in BLOCKED:
    sys.modules[_name] = None

class _Blocker:
    def find_spec(self, name, path=None, target=None):
        for blocked in BLOCKED:
            if name == blocked or name.startswith(blocked + "."):
                raise ImportError("blocked in test: " + name)
        return None

sys.meta_path.insert(0, _Blocker())

from tgmint import passkeys_pyrogram as drv

import tgmint.passkeys_core as core

assert drv.PYROGRAM_AVAILABLE is False, drv.PYROGRAM_AVAILABLE
assert drv.build_request is not None and drv.PyrogramInvoker is not None

from tgmint import passkeys_pyrogram as _lazy  # PEP 562 lazy export
assert _lazy is drv

for call in (
    lambda: drv.build_request("getPasskeys"),
    lambda: drv.PyrogramInvoker(object()),
):
    try:
        call()
    except core.PasskeyError as exc:
        assert "kurigram" in str(exc), exc
    else:
        raise AssertionError("expected a PasskeyError")
print("SOFT-IMPORT-OK")
'''
        env = dict(os.environ, PYTHONPATH=_SRC)
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("SOFT-IMPORT-OK", proc.stdout)

    def test_exports_are_importable(self):
        for name in drv.__all__:
            self.assertTrue(hasattr(drv, name), name)

    def test_package_exports_it_lazily(self):
        from tgmint import passkeys_pyrogram as exported

        self.assertIs(exported, drv)


if __name__ == "__main__":
    unittest.main()
