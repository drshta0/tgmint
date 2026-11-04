"""Golden wire tests — what actually goes on the wire.

These construct tgmint's TelegramClient exactly like production code
does (without connecting) and assert that the InitConnectionRequest
telethon stored (``client._init_request``) carries the full official
fingerprint: the eight identity fields INCLUDING ``lang_pack`` (which
stock telethon hardcodes to ``""``) and, when the fingerprint has a
timezone, the ``params`` JSON blob with ``tz_offset`` the way official
clients send it.

The envelope test serializes the real InvokeWithLayer(...) request to
bytes, so any regression that degrades the fingerprint on the wire
fails here instead of silently in production.
"""

import unittest

from telethon import functions
from telethon.sessions import MemorySession
from telethon.tl.alltlobjects import LAYER

from tgmint.api import API
from tgmint.tl import TelegramClient


class WireGoldenTest(unittest.TestCase):
    def _make(self, api):
        return TelegramClient(MemorySession(), api=api)

    def test_scoped_init_request_fields(self):
        """The stored InitConnectionRequest matches the fingerprint."""
        api = API.TelegramDesktop.Generate(system="windows", unique_id="gold-w")
        client = self._make(api)
        request = client._init_request

        self.assertEqual(request.api_id, api.api_id)
        self.assertEqual(request.device_model, api.device_model)
        self.assertEqual(request.system_version, api.system_version)
        self.assertEqual(request.app_version, api.app_version)
        self.assertEqual(request.lang_code, api.lang_code)
        self.assertEqual(request.system_lang_code, api.system_lang_code)
        # the whole point of the patch: lang_pack must be "tdesktop", not ""
        self.assertEqual(request.lang_pack, "tdesktop")
        # legacy mint (locale=None) -> no timezone -> no params blob;
        # the tz path is covered in test_tz_offset_params_blob below
        legacy = API.TelegramDesktop.Generate(
            system="windows", unique_id="gold-w", locale=None
        )
        self.assertIsNone(self._make(legacy)._init_request.params)

    def test_lang_pack_reaches_wire_bytes(self):
        """lang_pack + fingerprint fields serialize into the real envelope."""
        api = API.TelegramAndroid.Generate(unique_id="gold-a")
        client = self._make(api)
        request = client._init_request
        request.query = functions.help.GetConfigRequest()

        blob = bytes(functions.InvokeWithLayerRequest(LAYER, request))

        # lang_pack on the wire (stock telethon sends "")
        self.assertIn(b"android", blob)
        # the fingerprint fields themselves
        self.assertIn(api.app_version.encode(), blob)
        self.assertIn(api.device_model.encode(), blob)
        self.assertIn(api.system_version.encode(), blob)

    def test_pid_not_smuggled_as_device_model(self):
        """The old PID-through-device_model path must not leak the registry id."""
        api = API.TelegramIOS.Generate(unique_id="gold-i")
        client = self._make(api)
        self.assertNotEqual(client._init_request.device_model, api.pid)
        client._init_request.query = functions.help.GetConfigRequest()
        self.assertNotIn(str(api.pid).encode(), bytes(client._init_request))

    def test_default_api_is_telegram_desktop(self):
        """No api= -> official Telegram Desktop identity, lang_pack included."""
        client = TelegramClient(MemorySession())
        request = client._init_request
        self.assertEqual(request.api_id, 2040)
        self.assertEqual(request.lang_pack, "tdesktop")
        self.assertEqual(request.device_model, API.TelegramDesktop.device_model)

    def test_tz_offset_params_blob(self):
        """A fingerprint with tz_zone puts tz_offset into params on the wire."""
        api = API.TelegramDesktop.Generate(system="windows", unique_id="gold-tz")
        api.tz_zone = "Europe/Berlin"  # attribute wired in by the minting layer
        client = self._make(api)
        request = client._init_request

        self.assertIsNotNone(request.params)
        request.query = functions.help.GetConfigRequest()
        blob = bytes(functions.InvokeWithLayerRequest(LAYER, request))
        self.assertIn(b"tz_offset", blob)
        # JsonNumber is a double; +3600/+7200 both encode with the same
        # mantissa digits -- assert the value round-trips instead of a byte
        # constant, so DST is covered by computing what _now_ would be.
        value = request.params.value[0].value.value
        self.assertIn(value, (3600.0, 7200.0))

    def test_unknown_zone_leaves_params_unset(self):
        api = API.TelegramDesktop.Generate(system="linux", unique_id="gold-bad")
        api.tz_zone = "Not/AZone"
        client = self._make(api)
        self.assertIsNone(client._init_request.params)

    def test_params_skipped_on_request_without_the_field(self):
        """Older telethon (< ~1.36, layer < 196) has no `params` field on
        InitConnectionRequest — the tz blob must be skipped, not assigned
        to a field the serializer does not know (and never a crash)."""
        from types import SimpleNamespace

        api = API.TelegramDesktop.Generate(system="windows", unique_id="gold-old")
        api.tz_zone = "Europe/Berlin"
        client = self._make(api)

        # a stand-in for the old-telethon request object: every identity
        # field present, `params` absent
        stub = SimpleNamespace(
            api_id=0,
            device_model="x",
            system_version="x",
            app_version="x",
            lang_code="x",
            system_lang_code="x",
            lang_pack="x",
        )
        client._init_request = stub
        try:
            client._applyApiToInitRequest(api)
        except Exception as exc:  # pragma: no cover - the bug would crash
            self.fail(f"_applyApiToInitRequest crashed on params-less request: {exc}")
        self.assertFalse(hasattr(stub, "params"))


# ---------------------------------------------------------------------------
# QR login (tgmint.qrlogin_core): the five constructors both frameworks ship
# ---------------------------------------------------------------------------

try:  # the Pyrogram family is optional in the test environment
    from pyrogram.raw.functions.auth import ExportLoginToken as _KExport
    from pyrogram.raw.functions.auth import ImportLoginToken as _KImport
    from pyrogram.raw.types.auth import LoginToken as _KLoginToken
    from pyrogram.raw.types.auth import LoginTokenMigrateTo as _KMigrateTo
    from pyrogram.raw.types.auth import LoginTokenSuccess as _KSuccess

    # pyrogram.raw.all.layer is the plain int (229 in kurigram 2.2.26)
    PYROGRAM_LAYER = __import__("pyrogram.raw.all", fromlist=["layer"]).layer
    KURIGRAM_AVAILABLE = True
except Exception:  # pragma: no cover - environment dependent
    KURIGRAM_AVAILABLE = False


class QrLoginWireGoldenTest(unittest.TestCase):
    """The QR-login wire: one spec, two generated layers, identical bytes.

    The constructor ids in ``tgmint.qrlogin_core.QRLOGIN_TL_SPEC`` are
    asserted against BOTH installed frameworks' generated classes —
    Telethon always, the Pyrogram family when a distribution is present —
    the same drift-guard arrangement the passkey constructors use
    (tests/test_passkeys_core.py). The request byte equality makes the
    neutral writer's output literally the frameworks' own serialization.
    """

    EXPORT_FIELDS = {
        "api_id": 2040,
        "api_hash": "b18441a1ff607e10a989891a5462e627",
        "except_ids": [777000, 4242],
    }

    def test_spec_constructors_match_telethon(self):
        from telethon.tl import functions
        from telethon.tl import types

        from tgmint.qrlogin_core import QRLOGIN_TL_SPEC

        pairs = (
            ("auth.exportLoginToken", functions.auth.ExportLoginTokenRequest),
            ("auth.importLoginToken", functions.auth.ImportLoginTokenRequest),
            ("auth.loginToken", types.auth.LoginToken),
            ("auth.loginTokenMigrateTo", types.auth.LoginTokenMigrateTo),
            ("auth.loginTokenSuccess", types.auth.LoginTokenSuccess),
        )
        for name, cls in pairs:
            with self.subTest(name=name):
                self.assertEqual(
                    QRLOGIN_TL_SPEC["constructors"][name],
                    cls.CONSTRUCTOR_ID,
                )
        self.assertEqual(QRLOGIN_TL_SPEC["layer"], LAYER)

    @unittest.skipUnless(KURIGRAM_AVAILABLE, "no pyrogram-family package")
    def test_spec_constructors_match_the_pyrogram_family(self):
        from tgmint.qrlogin_core import QRLOGIN_TL_SPEC

        pairs = (
            ("auth.exportLoginToken", _KExport),
            ("auth.importLoginToken", _KImport),
            ("auth.loginToken", _KLoginToken),
            ("auth.loginTokenMigrateTo", _KMigrateTo),
            ("auth.loginTokenSuccess", _KSuccess),
        )
        for name, cls in pairs:
            with self.subTest(name=name):
                self.assertEqual(
                    QRLOGIN_TL_SPEC["constructors"][name], cls.ID
                )
        # The constructor ids above are the real drift guard. The spec's
        # layer is pinned to Telethon's (checked in the Telethon test).
        # The installed Pyrogram-family layer depends on which version pip
        # resolves (Python 3.9 gets kurigram 2.2.25 = layer 228, newer
        # Pythons get 2.2.26 = 229), so only require it to be a real layer.
        self.assertIsInstance(PYROGRAM_LAYER, int)
        self.assertGreater(PYROGRAM_LAYER, 0)

    def test_export_request_bytes_match_telethon(self):
        from tgmint.qrlogin_core import encode_request
        from telethon.tl.functions.auth import ExportLoginTokenRequest

        mine = encode_request("exportLoginToken", self.EXPORT_FIELDS)
        reference = bytes(ExportLoginTokenRequest(**{
            "api_id": 2040,
            "api_hash": "b18441a1ff607e10a989891a5462e627",
            "except_ids": [777000, 4242],
        }))
        self.assertEqual(mine, reference)

    def test_import_request_bytes_match_telethon(self):
        from tgmint.qrlogin_core import encode_request
        from telethon.tl.functions.auth import ImportLoginTokenRequest

        token = bytes(range(20))
        self.assertEqual(
            encode_request("importLoginToken", {"token": token}),
            bytes(ImportLoginTokenRequest(token=token)),
        )

    @unittest.skipUnless(KURIGRAM_AVAILABLE, "no pyrogram-family package")
    def test_request_bytes_match_the_pyrogram_family(self):
        from tgmint.qrlogin_core import encode_request

        export = _KExport(
            api_id=2040,
            api_hash="b18441a1ff607e10a989891a5462e627",
            except_ids=[777000, 4242],
        )
        self.assertEqual(
            encode_request("exportLoginToken", self.EXPORT_FIELDS), export.write()
        )
        token = bytes(range(20))
        import_ = _KImport(token=token)
        self.assertEqual(
            encode_request("importLoginToken", {"token": token}),
            import_.write(),
        )

    def test_responses_round_trip_through_the_neutral_parser(self):
        from tgmint.qrlogin_core import (
            QrLoginToken,
            QrMigrateTo,
            QrSuccess,
            parse_login_token,
        )
        from telethon.tl import types

        token_bytes = bytes(range(20))
        user = types.User(id=424242, first_name="QR", is_self=True)
        authorization = types.auth.Authorization(user=user)

        # telethon converts expires_in <-> datetime; expires=None serializes
        # the wire form of expires_in=0
        fresh = parse_login_token(
            bytes(types.auth.LoginToken(expires=None, token=token_bytes))
        )
        self.assertIsInstance(fresh, QrLoginToken)
        self.assertEqual(fresh.token, token_bytes)
        self.assertEqual(fresh.expires_in, 0)

        migrate = parse_login_token(
            bytes(types.auth.LoginTokenMigrateTo(dc_id=4, token=token_bytes))
        )
        self.assertIsInstance(migrate, QrMigrateTo)
        self.assertEqual((migrate.dc_id, migrate.token), (4, token_bytes))

        success = parse_login_token(
            bytes(types.auth.LoginTokenSuccess(authorization=authorization))
        )
        self.assertIsInstance(success, QrSuccess)
        self.assertEqual(success.authorization.user_id, 424242)

    def test_spec_is_plain_json_data(self):
        import json

        from tgmint.qrlogin_core import QRLOGIN_TL_SPEC

        json.dumps(QRLOGIN_TL_SPEC)


if __name__ == "__main__":
    unittest.main()
