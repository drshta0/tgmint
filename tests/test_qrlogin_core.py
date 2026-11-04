"""Offline tests for the framework-neutral QR login (tgmint.qrlogin_core).

The ceremony is driven by a scripted fake invoker — no socket, no
framework, deterministic bytes. Telethon's generated classes appear only
as *oracles* (to build response bytes the way the server would send
them), the same arrangement as ``tests/test_passkeys_core.py``.

Cases the task list names, all covered here:

* plain success (export -> update -> poll -> loginTokenSuccess),
* expiry -> refresh (a fresh token replaces the expired one),
* migrate DC (export -> loginTokenMigrateTo -> import on the target DC),
* 2FA (SESSION_PASSWORD_NEEDED from the export poll AND from the import),
* migrate-DC failure -> rollback (driver-level, with a fake Telethon
  client whose ``_switch_dc`` destroys the session like the real one).
"""
from __future__ import annotations

import asyncio
import struct
import unittest

import pytest
from telethon import types as tl_types
from telethon.tl.functions.auth import (
    ExportLoginTokenRequest,
    ImportLoginTokenRequest,
)

from tgmint import qrlogin_core as core
from tgmint.passkeys_core import TwoFactorRequired

USER_ID = 123456789
TOKEN = bytes(range(20))  # a login token the way the server mints it
EXPIRES = 900


# --- response builders (server-side bytes) ----------------------------------


def _tl_bytes(data: bytes) -> bytes:
    from tgmint.passkeys_core import _serialize_tl_bytes

    return _serialize_tl_bytes(data)


def login_token_bytes(expires_in: int = EXPIRES, token: bytes = TOKEN) -> bytes:
    return (
        struct.pack("<I", 0x629F1980) + struct.pack("<i", expires_in) + _tl_bytes(token)
    )


def migrate_bytes(dc_id: int = 4, token: bytes = TOKEN) -> bytes:
    return struct.pack("<I", 0x068E9916) + struct.pack("<i", dc_id) + _tl_bytes(token)


def success_bytes(user_id: int = USER_ID) -> bytes:
    """auth.loginTokenSuccess carrying a telethon-built authorization."""
    user = tl_types.User(id=user_id, first_name="QR", is_self=True)
    authorization = tl_types.auth.Authorization(user=user)
    return struct.pack("<I", 0x390D5C5E) + bytes(authorization)


class _Script:
    """A scripted invoker: answers popped from a list, every call recorded.

    Each entry is either ``bytes`` (the response) or an exception
    instance/class (raised, e.g. ``TwoFactorRequired`` for the 2FA case).
    """

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls: list = []

    async def request_bytes(self, name, fields):
        self.calls.append((name, dict(fields)))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, type) and issubclass(answer, BaseException):
            raise answer()
        return answer


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def _machine(script, clock=None):
    return core.QrLoginMachine(
        script,
        api_id=2040,
        api_hash="b18441a1ff607e10a989891a5462e627",
        except_ids=(1,),
        clock=clock if clock is not None else _Clock(),
    )


# --- the neutral wire layer ---------------------------------------------------


class TestEncodeRequest(unittest.TestCase):
    EXPORT_FIELDS = {
        "api_id": 2040,
        "api_hash": "b18441a1ff607e10a989891a5462e627",
        "except_ids": [777000, 2 ** 63 + 5],  # includes an unsigned spelling
    }

    def test_export_matches_telethon_bytes(self):
        mine = core.encode_request("exportLoginToken", self.EXPORT_FIELDS)
        reference = bytes(
            ExportLoginTokenRequest(
                api_id=2040,
                api_hash="b18441a1ff607e10a989891a5462e627",
                except_ids=[777000, 2 ** 63 + 5 - (1 << 64)],
            )
        )
        self.assertEqual(mine, reference)
        # the last long is the two's-complement form of 2**63 + 5
        self.assertEqual(mine[-8:], struct.pack("<q", -(2 ** 63) + 5))

    def test_import_matches_telethon_bytes(self):
        mine = core.encode_request("importLoginToken", {"token": TOKEN})
        self.assertEqual(
            mine, bytes(ImportLoginTokenRequest(token=TOKEN))
        )

    def test_export_defaults_to_empty_except_ids(self):
        fields = dict(self.EXPORT_FIELDS)
        del fields["except_ids"]
        mine = core.encode_request("exportLoginToken", fields)
        reference = bytes(
            ExportLoginTokenRequest(
                api_id=2040,
                api_hash="b18441a1ff607e10a989891a5462e627",
                except_ids=[],
            )
        )
        self.assertEqual(mine, reference)

    def test_unknown_and_missing_fields_are_rejected(self):
        with pytest.raises(core.QrLoginError):
            core.encode_request("exportLoginToken", {"api_id": 1})
        with pytest.raises(core.QrLoginError):
            core.encode_request(
                "exportLoginToken",
                dict(self.EXPORT_FIELDS, nonsense=1),
            )
        with pytest.raises(core.QrLoginError):
            core.encode_request("importLoginToken", {})
        with pytest.raises(core.QrLoginError):
            core.encode_request("noSuchMessage", {})

    def test_bad_field_types_are_rejected(self):
        from tgmint.passkeys_core import PasskeyError

        # int32 range checks come from the shared neutral helper, so the
        # api_id failure surfaces as the family root type
        bad = dict(self.EXPORT_FIELDS, api_id="2040")
        with pytest.raises(PasskeyError):
            core.encode_request("exportLoginToken", bad)
        bad = dict(self.EXPORT_FIELDS, except_ids="777000")
        with pytest.raises(core.QrLoginError):
            core.encode_request("exportLoginToken", bad)
        with pytest.raises(core.QrLoginError):
            core.encode_request("importLoginToken", {"token": "not-bytes"})

    def test_qr_error_is_a_passkey_error_subclass(self):
        # one neutral driver-error family: a caller guarding with
        # except PasskeyError is not surprised by the QR twin
        self.assertTrue(issubclass(core.QrLoginError, Exception))
        from tgmint.passkeys_core import PasskeyError

        self.assertTrue(issubclass(core.QrLoginError, PasskeyError))


class TestParseLoginToken(unittest.TestCase):
    def test_login_token(self):
        result = core.parse_login_token(login_token_bytes(expires_in=42, token=b"ab"))
        self.assertIsInstance(result, core.QrLoginToken)
        self.assertEqual(result.expires_in, 42)
        self.assertEqual(result.token, b"ab")
        self.assertEqual(result.url, "tg://login?token=YWI")

    def test_migrate_to(self):
        result = core.parse_login_token(migrate_bytes(dc_id=4, token=b"xy"))
        self.assertIsInstance(result, core.QrMigrateTo)
        self.assertEqual((result.dc_id, result.token), (4, b"xy"))

    def test_success_authorization(self):
        result = core.parse_login_token(success_bytes())
        self.assertIsInstance(result, core.QrSuccess)
        self.assertEqual(result.authorization.user_id, USER_ID)
        self.assertFalse(result.authorization.sign_up_required)
        # the raw authorization bytes survive for a framework's own TL layer
        self.assertTrue(result.authorization.raw.startswith(b"\xd4\xc0\xa2\x2e"))

    def test_unknown_constructor_rejected(self):
        with pytest.raises(core.QrLoginError) as ctx:
            core.parse_login_token(struct.pack("<I", 0xDEADBEEF) + b"\x00" * 8)
        self.assertIn("0xdeadbeef", str(ctx.value))

    def test_trailing_bytes_rejected(self):
        payload = login_token_bytes() + b"junk"
        with pytest.raises(core.QrLoginError):
            core.parse_login_token(payload)

    def test_login_url_is_urlsafe_b64_without_padding(self):
        self.assertEqual(
            core.login_url(b"\xff\xff\xff"),
            "tg://login?token=" + core.base64.urlsafe_b64encode(b"\xff\xff\xff")
            .decode()
            .rstrip("="),
        )


# --- the state machine ---------------------------------------------------------

class TestMachineSuccess(unittest.TestCase):
    def test_plain_success_same_dc(self):
        script = _Script(
            login_token_bytes(),
            success_bytes(),
        )
        machine = _machine(script)
        first = asyncio.run(machine.start())
        self.assertIsInstance(first, core.QrLoginToken)
        self.assertEqual(machine.exports, 1)
        # the phone confirmed: the re-export answers success directly
        result = asyncio.run(machine.poll())
        self.assertIsInstance(result, core.QrSuccess)
        self.assertEqual(result.authorization.user_id, USER_ID)
        self.assertEqual(script.calls[0][0], "exportLoginToken")
        self.assertEqual(script.calls[1][0], "exportLoginToken")

    def test_export_fields_reach_the_invoker(self):
        script = _Script(login_token_bytes())
        machine = _machine(script)
        asyncio.run(machine.start())
        name, fields = script.calls[0]
        self.assertEqual(name, "exportLoginToken")
        self.assertEqual(fields["api_id"], 2040)
        self.assertEqual(fields["except_ids"], [1])


class TestMachineExpiryRefresh(unittest.TestCase):
    def test_expired_token_reports_negative_seconds_left(self):
        clock = _Clock()
        script = _Script(
            login_token_bytes(expires_in=30, token=b"first-token"),
            login_token_bytes(expires_in=60, token=b"second-token"),
        )
        machine = _machine(script, clock)
        first = asyncio.run(machine.start())
        self.assertEqual(machine.seconds_left(), 30)
        self.assertFalse(machine.expired)
        clock.advance(31)
        self.assertTrue(machine.expired)

        # the caller refreshes an expired unscanned token: fresh QR
        second = asyncio.run(machine.refresh())
        self.assertIsInstance(second, core.QrLoginToken)
        self.assertNotEqual(second.token, first.token)
        self.assertEqual(machine.exports, 2)
        self.assertEqual(machine.seconds_left(), 60)

    def test_seconds_left_is_none_before_the_first_export(self):
        machine = _machine(_Script())
        self.assertIsNone(machine.seconds_left())
        self.assertFalse(machine.expired)


class TestMachineMigrate(unittest.TestCase):
    def test_migrate_then_import(self):
        script = _Script(
            login_token_bytes(),
            migrate_bytes(dc_id=4, token=TOKEN),
            success_bytes(user_id=777),
        )
        machine = _machine(script)
        asyncio.run(machine.start())
        step = asyncio.run(machine.poll())
        self.assertIsInstance(step, core.QrMigrateTo)
        # the DRIVER switches DC here (not the core); then:
        result = asyncio.run(machine.import_token(step))
        self.assertIsInstance(result, core.QrSuccess)
        self.assertEqual(result.authorization.user_id, 777)
        self.assertEqual(machine.imports, 1)
        self.assertEqual(
            script.calls[2], ("importLoginToken", {"token": TOKEN})
        )

    def test_import_token_requires_a_migrate(self):
        machine = _machine(_Script())
        with pytest.raises(core.QrLoginError):
            asyncio.run(machine.import_token(object()))

    def test_import_answering_a_fresh_token_is_an_error(self):
        script = _Script(login_token_bytes(expires_in=900, token=b"new"))
        machine = _machine(script)
        migrate = core.QrMigrateTo(dc_id=4, token=TOKEN)
        with pytest.raises(core.QrLoginError) as ctx:
            asyncio.run(machine.import_token(migrate))
        self.assertIn("rejected", str(ctx.value))

    def test_import_answering_another_migrate_is_an_error(self):
        script = _Script(migrate_bytes(dc_id=5, token=b"zz"))
        machine = _machine(script)
        with pytest.raises(core.QrLoginError) as ctx:
            asyncio.run(machine.import_token(core.QrMigrateTo(dc_id=4, token=TOKEN)))
        self.assertIn("home DC", str(ctx.value))


class TestMachineTwoFactor(unittest.TestCase):
    def test_2fa_from_the_export_poll_is_a_typed_result(self):
        script = _Script(login_token_bytes(), TwoFactorRequired())
        machine = _machine(script)
        asyncio.run(machine.start())
        result = asyncio.run(machine.poll())
        self.assertIsInstance(result, core.QrPasswordNeeded)
        self.assertEqual(result.stage, "export")

    def test_2fa_from_the_import_is_a_typed_result(self):
        machine = _machine(_Script())
        migrate = core.QrMigrateTo(dc_id=4, token=TOKEN)
        script = _Script(TwoFactorRequired())
        machine = _machine(script)
        result = asyncio.run(machine.import_token(migrate))
        self.assertIsInstance(result, core.QrPasswordNeeded)
        self.assertEqual(result.stage, "import")

    def test_2fa_is_not_an_error_type(self):
        # the typed result must not be swallowable as a PasskeyError
        script = _Script(login_token_bytes(), TwoFactorRequired())
        machine = _machine(script)
        asyncio.run(machine.start())
        result = asyncio.run(machine.poll())
        self.assertNotIsInstance(result, Exception)


class TestInvokerContract(unittest.TestCase):
    def test_an_invoker_without_methods_is_rejected(self):
        with pytest.raises(core.QrLoginError):
            core.QrLoginMachine(object(), api_id=1, api_hash="h")

    def test_none_invoker_is_rejected(self):
        with pytest.raises(core.QrLoginError):
            core.QrLoginMachine(None, api_id=1, api_hash="h")

    def test_non_bytes_answers_are_rejected(self):
        class _Obj:
            async def request_bytes(self, name, fields):
                return "not bytes"

        machine = core.QrLoginMachine(_Obj(), api_id=1, api_hash="h")
        with pytest.raises(core.QrLoginError) as ctx:
            asyncio.run(machine.start())
        self.assertIn("response bytes", str(ctx.value))

    def test_native_path_answers_must_also_be_bytes(self):
        class _Native:
            async def native(self, name, fields):
                return login_token_bytes()

        machine = core.QrLoginMachine(_Native(), api_id=1, api_hash="h")
        first = asyncio.run(machine.start())
        self.assertIsInstance(first, core.QrLoginToken)

    def test_bad_constructor_args_fail_before_any_call(self):
        from tgmint.passkeys_core import PasskeyError

        script = _Script()
        with pytest.raises(PasskeyError):  # shared int32 range helper
            core.QrLoginMachine(script, api_id="2040", api_hash="h")
        with pytest.raises(core.QrLoginError):
            core.QrLoginMachine(script, api_id=2040, api_hash=2040)
        self.assertEqual(script.calls, [])


# --- the full ceremony loop -----------------------------------------------------


class TestRunCeremony(unittest.TestCase):
    def _run(self, script, clock=None, **kwargs):
        machine = _machine(script, clock)
        waits = []

        async def wait(seconds):
            waits.append(seconds)
            # the fake phone confirms instantly

        async def migrate(step):
            # the fake driver "switches" and imports
            return await machine.import_token(step)

        async def finish_password(password):
            return ("finished-with", password)

        async def complete(success):
            return ("me", success.authorization.user_id)

        outcome = asyncio.run(
            core.run_ceremony(
                machine,
                wait=wait,
                migrate=migrate,
                finish_password=finish_password,
                complete=complete,
                clock=clock if clock is not None else _Clock(),
                **kwargs,
            )
        )
        return machine, waits, outcome

    def test_success_loop(self):
        script = _Script(login_token_bytes(), success_bytes())
        machine, waits, outcome = self._run(script)
        self.assertEqual(outcome, ("me", USER_ID))
        self.assertEqual(machine.exports, 2)

    def test_migrate_loop(self):
        script = _Script(
            login_token_bytes(), migrate_bytes(dc_id=4), success_bytes(user_id=42)
        )
        machine, waits, outcome = self._run(script)
        self.assertEqual(outcome, ("me", 42))
        self.assertEqual(machine.imports, 1)

    def test_password_completes_when_given(self):
        script = _Script(login_token_bytes(), TwoFactorRequired())
        machine, waits, outcome = self._run(script, password="hunter2")
        self.assertEqual(outcome, ("finished-with", "hunter2"))

    def test_password_missing_raises_the_neutral_signal(self):
        script = _Script(login_token_bytes(), TwoFactorRequired())
        with pytest.raises(TwoFactorRequired):
            self._run(script)

    def test_zero_budget_times_out_after_the_first_token(self):
        # timeout=0: the first token is rendered, then the (empty) budget
        # raises before any wait — deterministic, no clock games needed
        script = _Script(login_token_bytes(expires_in=900))
        machine, waits, _ = self._run_for_timeout(script, timeout=0)
        self.assertEqual(waits, [])
        self.assertEqual(machine.exports, 1)

    def _run_for_timeout(self, script, timeout):
        machine = _machine(script)

        async def wait(seconds):
            waits.append(seconds)

        async def noop(*args, **kwargs):
            raise AssertionError("must not be reached")

        async def complete(success):
            return success

        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(
                core.run_ceremony(
                    machine,
                    wait=wait,
                    migrate=noop,
                    finish_password=noop,
                    complete=complete,
                    timeout=timeout,
                )
            )
        waits = getattr(self, "_waits", [])
        return machine, waits, None

    def test_render_receives_every_fresh_token(self):
        shown = []
        script = _Script(login_token_bytes(expires_in=900))
        machine = _machine(script)

        async def wait(seconds):
            raise asyncio.TimeoutError()  # never confirmed, never expires

        async def noop(*args, **kwargs):
            raise AssertionError("must not be reached")

        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(
                core.run_ceremony(
                    machine,
                    wait=wait,
                    migrate=noop,
                    finish_password=noop,
                    complete=noop,
                    render=shown.append,
                    timeout=None,
                )
            )
        self.assertEqual(len(shown), 1)
        self.assertEqual(shown[0].url, core.login_url(TOKEN))


# --- the Telethon driver: rollback on a failed migrate import ------------------


class _FakeAuthKey:
    def __init__(self, key):
        self.key = key


class _FakeSession:
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
        return True


class _FakeQrClient:
    """Just enough Telethon for the QR driver, switch-destroying included."""

    api_id = 2040
    api_hash = "b18441a1ff607e10a989891a5462e627"

    def __init__(self, answers):
        self.session = _FakeSession(
            2, "149.154.167.51", 443, _FakeAuthKey(b"\x7f" * 256)
        )
        self.answers = list(answers)
        self.switched_to = []
        self.connects = 0
        self.disconnects = 0
        self.signed_in = []
        self.on_login = []
        self.handlers = []

    async def __call__(self, request):
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return answer()
        return answer

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
        return types_user()

    async def _on_login(self, user):
        self.on_login.append(user)
        return user

    def add_event_handler(self, handler, event=None):
        self.handlers.append((handler, event))

    def remove_event_handler(self, handler, event=None):
        self.handlers = [
            pair for pair in self.handlers if pair != (handler, event)
        ]


def types_user():
    from telethon import types

    return types.User(id=USER_ID, first_name="QR", is_self=True)


def _confirming_wait(seconds=None):
    async def wait(timeout):
        return None  # the phone confirmed instantly

    return wait


class TestTelethonDriverRollback(unittest.TestCase):
    """The migrate-DC failure must not leave the caller's session destroyed."""

    def _client_with_migrate_then_failure(self, error):

        client = _FakeQrClient(
            [
                tl_types.auth.LoginToken(
                    expires=None, token=TOKEN
                ),  # export #1 (expires is datetime in telethon; unused here)
                tl_types.auth.LoginTokenMigrateTo(dc_id=4, token=TOKEN),
                error,
            ]
        )
        return client

    def test_failed_import_rolls_the_session_back(self):
        from telethon.errors import BadRequestError

        client = self._client_with_migrate_then_failure(
            BadRequestError(object(), "AUTH_KEY_UNREG", 401)
        )
        original_key = client.session.auth_key
        from tgmint import qrlogin

        with pytest.raises(Exception) as ctx:
            asyncio.run(
                qrlogin.login_with_qr(
                    client, render=lambda token: None, timeout=60
                )
            )
        self.assertIn("AUTH_KEY_UNREG", str(ctx.value))
        # the switch happened, and the rollback restored everything
        self.assertEqual(client.switched_to, [4])
        self.assertEqual(client.session.dc_id, 2)
        self.assertEqual(client.session.server_address, "149.154.167.51")
        self.assertEqual(client.session.port, 443)
        self.assertIs(client.session.auth_key, original_key)
        self.assertEqual(client.session.auth_key.key, b"\x7f" * 256)
        # ... and the connection was re-opened on the restored DC
        self.assertEqual((client.disconnects, client.connects), (1, 1))

    def test_2fa_without_password_keeps_the_migrated_session(self):
        from telethon.errors import SessionPasswordNeededError

        client = self._client_with_migrate_then_failure(
            SessionPasswordNeededError(object())
        )
        from tgmint import qrlogin

        with pytest.raises(TwoFactorRequired):
            asyncio.run(
                qrlogin.login_with_qr(
                    client, render=lambda token: None, timeout=60
                )
            )
        # the password step must run on the migrated (home) DC: the session
        # is intentionally NOT rolled back — a wrong password stays
        # retryable there, like in the passkey login
        self.assertEqual(client.switched_to, [4])
        self.assertEqual(client.session.dc_id, 4)
        self.assertEqual(client.signed_in, [])

    def test_2fa_with_password_completes_on_the_migrated_dc(self):
        from telethon.errors import SessionPasswordNeededError

        client = self._client_with_migrate_then_failure(
            SessionPasswordNeededError(object())
        )
        from tgmint import qrlogin

        me = asyncio.run(
            qrlogin.login_with_qr(
                client, render=lambda token: None, timeout=60, password="s3cret"
            )
        )
        self.assertEqual(client.signed_in, ["s3cret"])
        self.assertEqual(getattr(me, "id", None), USER_ID)

    def test_success_path_authorizes_and_saves(self):
        client = _FakeQrClient(
            [
                tl_types.auth.LoginToken(expires=None, token=TOKEN),
                lambda: _success_object(),
            ]
        )
        from tgmint import qrlogin

        me = asyncio.run(
            qrlogin.login_with_qr(client, render=lambda token: None, timeout=60)
        )
        self.assertEqual(getattr(me, "id", None), USER_ID)
        self.assertEqual(len(client.on_login), 1)
        self.assertGreaterEqual(client.session.saves, 1)


def _success_object():
    return tl_types.auth.LoginTokenSuccess(
        authorization=tl_types.auth.Authorization(user=types_user())
    )


class TestSpecData(unittest.TestCase):
    def test_spec_is_json_serializable(self):
        import json

        json.dumps(core.QRLOGIN_TL_SPEC)

    def test_spec_lists_the_five_qr_constructors(self):
        constructors = core.QRLOGIN_TL_SPEC["constructors"]
        self.assertEqual(constructors["auth.exportLoginToken"], 0xB7E085FE)
        self.assertEqual(constructors["auth.importLoginToken"], 0x95AC5CE4)
        self.assertEqual(constructors["auth.loginToken"], 0x629F1980)
        self.assertEqual(constructors["auth.loginTokenMigrateTo"], 0x068E9916)
        self.assertEqual(constructors["auth.loginTokenSuccess"], 0x390D5C5E)

    def test_layer_matches_both_installed_frameworks(self):
        # the spec pins layer 229; telethon 1.45.0 and kurigram 2.2.26 are
        # both layer 229 (checked in test_wire_golden against the packages)
        self.assertEqual(core.QRLOGIN_TL_SPEC["layer"], 229)


if __name__ == "__main__":
    unittest.main()
