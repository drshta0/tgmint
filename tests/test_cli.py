"""Tests for the tgmint CLI — tgmint.cli.main and `python -m tgmint`.

All offline: minting is seeded with --unique-id, sidecars live in
tempfile dirs, and `freshness` is asserted to never touch the network.
`convert` is exercised end-to-end through the real handler with a fixed
auth_key, unconditionally — the v1.16.0 predecessor of this test class
skipped itself whenever `tgmint.codec` was importable, which is exactly
how a dead command stayed green (see the v1.16.1 changelog).
"""

import contextlib
import dataclasses
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tgmint import cli, codec
from tgmint.codec import SessionData, gramjs, pyrogram, telethon
from tgmint.codec.dcs import PROD_DC
from tgmint.fingerprint import SCHEMA_VERSION
from tgmint.versions import PINNED

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")

try:  # tdata destinations route through tgmint.td (needs tgcrypto)
    import tgmint.td  # noqa: F401

    HAVE_TD = True
except Exception:  # pragma: no cover - optional dependency absent
    HAVE_TD = False


KEY = bytes(range(256))
NEW_KEY = bytes(reversed(range(256)))
USER_ID = 777000
DC_ID = 2
NEW_DC = 4


def _session(key=None, **overrides):
    """A fixed authorization (never a random one: reports must be comparable)."""
    fields = dict(dc_id=DC_ID, auth_key=key or KEY, user_id=USER_ID, api_id=2040)
    fields.update(overrides)
    return SessionData(**fields)


def stat_mode(path):
    return os.stat(path).st_mode & 0o777


def run_cli(argv):
    """Run cli.main with captured streams -> (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def _find_key(payload, key):
    """Recursively find `key` in nested dicts (parity output may nest)."""
    if isinstance(payload, dict):
        if key in payload:
            return payload[key]
        for value in payload.values():
            found = _find_key(value, key)
            if found is not None:
                return found
    return None


class MintInspectAuditRoundTrip(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            sidecar = os.path.join(tmp, "acct.fingerprint.json")

            # mint (JSON) — every --json output must parse with json.loads
            code, out, err = run_cli(
                [
                    "mint", "--preset", "desktop", "--system", "linux",
                    "--unique-id", "cli-rt", "--save", sidecar, "--json",
                ]
            )
            self.assertEqual(code, 0, err)
            minted = json.loads(out)
            self.assertEqual(minted["origin"], "tdesktop")
            self.assertEqual(minted["lang_pack"], "tdesktop")
            self.assertIn("tz_zone", minted)
            self.assertEqual(minted["saved_to"], sidecar)
            self.assertTrue(os.path.isfile(sidecar))
            self.assertEqual(minted["schema_version"], SCHEMA_VERSION)

            # inspect — same fields back
            code, out, err = run_cli(["inspect", sidecar, "--json"])
            self.assertEqual(code, 0, err)
            inspected = json.loads(out)
            for field in (
                "api_id", "api_hash", "device_model", "system_version",
                "app_version", "lang_code", "system_lang_code", "lang_pack",
                "tz_zone", "origin",
            ):
                self.assertEqual(inspected[field], minted[field], field)
            self.assertIn("tz_offset", inspected)

            # audit — freshly minted identity is healthy, exit 0
            code, out, err = run_cli(["audit", sidecar, "--json"])
            self.assertEqual(code, 0, err)
            report = json.loads(out)
            self.assertEqual(report["problems"], [])
            self.assertTrue(report["ok"])

            # human mode round-trip too (no --json): same exit codes
            code, out, err = run_cli(["inspect", sidecar])
            self.assertEqual(code, 0)
            self.assertIn("lang_pack: tdesktop", out)
            code, out, err = run_cli(["audit", sidecar])
            self.assertEqual(code, 0)
            self.assertIn("coherence: ok", out)

    def test_mint_deterministic_per_unique_id(self):
        args = ["mint", "--preset", "ios", "--unique-id", "stable-id", "--json"]
        code_a, out_a, _ = run_cli(args)
        code_b, out_b, _ = run_cli(args)
        self.assertEqual(code_a, 0)
        self.assertEqual(code_b, 0)
        a, b = json.loads(out_a), json.loads(out_b)
        self.assertEqual(a["device_model"], b["device_model"])
        self.assertEqual(a["app_version"], b["app_version"])

    def test_mint_locale_none_has_no_timezone(self):
        code, out, err = run_cli(
            ["mint", "--preset", "desktop", "--system", "linux",
             "--unique-id", "cli-legacy", "--locale", "none", "--json"]
        )
        self.assertEqual(code, 0, err)
        data = json.loads(out)
        self.assertEqual(data["lang_code"], "en")
        self.assertEqual(data["system_lang_code"], "en-US")
        self.assertIsNone(data["tz_zone"])
        self.assertIsNone(data["tz_offset"])

    def test_mint_bad_locale_exits_2(self):
        code, out, err = run_cli(
            ["mint", "--preset", "desktop", "--locale", "xx", "--json"]
        )
        self.assertEqual(code, 2)
        self.assertIn("locale", err)

    def test_mint_bad_system_exits_2(self):
        code, out, err = run_cli(
            ["mint", "--preset", "desktop", "--system", "templeos", "--json"]
        )
        self.assertEqual(code, 2)
        self.assertIn("mint failed", err)

    def test_inspect_missing_file_exits_2(self):
        code, out, err = run_cli(["inspect", "/nonexistent/fp.json"])
        self.assertEqual(code, 2)
        self.assertIn("no such sidecar", err)


class AuditCliTest(unittest.TestCase):
    def _mint_and_save(self, tmp, **overrides):
        from tgmint.api import API
        from tgmint.fingerprint import Fingerprint

        api = API.TelegramDesktop.Generate(
            system="linux", unique_id="cli-audit", locale=None
        )
        fp = Fingerprint.from_apidata(api)
        if overrides:
            fp = dataclasses.replace(fp, **overrides)
        path = os.path.join(tmp, "bad.fingerprint.json")
        fp.save(path)
        return path

    def test_incoherent_fingerprint_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._mint_and_save(tmp, api_hash="DEADBEEF")
            code, out, err = run_cli(["audit", path, "--json"])
            self.assertEqual(code, 1)
            report = json.loads(out)
            self.assertFalse(report["ok"])
            self.assertTrue(
                any("api_hash" in p for p in report["problems"]),
                report["problems"],
            )

            code, out, err = run_cli(["audit", path])  # human mode
            self.assertEqual(code, 1)
            self.assertIn("problem:", out)
            self.assertIn("api_hash", out)

    def test_corrupt_sidecar_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "broken.json")
            with open(path, "w", encoding="utf-8") as fp:
                fp.write("{not json")
            code, out, err = run_cli(["audit", path])
            self.assertEqual(code, 2)
            self.assertIn("tgmint:", err)


class FreshnessCliTest(unittest.TestCase):
    def test_json_shape(self):
        code, out, err = run_cli(["freshness", "--json"])
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertTrue(payload["offline"])
        self.assertEqual(payload["pinned"], PINNED)
        self.assertIn("cache_ttl_seconds", payload)
        cache = payload["cache"]
        self.assertIn("path", cache)
        self.assertIn("exists", cache)
        self.assertIn("entries", cache)

    def test_never_touches_the_network(self):
        # any fetch attempt would blow up — freshness must only read the
        # compiled-in pins and the local cache file
        with mock.patch(
            "tgmint.versions._http_get",
            side_effect=AssertionError("network touched"),
        ):
            code, out, err = run_cli(["freshness", "--json"])
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["pinned"]["tdesktop"], PINNED["tdesktop"])

    def test_human_output(self):
        code, out, err = run_cli(["freshness"])
        self.assertEqual(code, 0)
        self.assertIn("tdesktop", out)
        self.assertIn(PINNED["tdesktop"], out)
        self.assertIn("cache:", out)


class ParityCliTest(unittest.TestCase):
    def test_envelope_fields(self):
        code, out, err = run_cli(
            ["parity", "--preset", "android", "--unique-id", "cli-par", "--json"]
        )
        self.assertEqual(code, 0, err)
        envelope = json.loads(out)
        # lang_pack must be the official one — the whole point (stock
        # telethon hardcodes "")
        self.assertEqual(_find_key(envelope, "lang_pack"), "android")
        self.assertNotEqual(_find_key(envelope, "lang_pack"), "")
        self.assertEqual(_find_key(envelope, "api_id"), 4)
        for field in (
            "device_model", "system_version", "app_version",
            "system_lang_code", "lang_code",
        ):
            self.assertTrue(_find_key(envelope, field), field)

    def test_layer_coherent_desktop_envelope(self):
        code, out, err = run_cli(
            [
                "parity", "--preset", "desktop", "--system", "linux",
                "--layer", "224", "--unique-id", "cli-par224", "--json",
            ]
        )
        self.assertEqual(code, 0, err)
        envelope = json.loads(out)
        self.assertEqual(_find_key(envelope, "layer"), 224)
        # layer 224 -> the newest tdesktop that genuinely spoke it
        self.assertEqual(_find_key(envelope, "app_version"), "6.7.8")
        self.assertEqual(_find_key(envelope, "lang_pack"), "tdesktop")
        # default locale=auto mints a zone -> a computed tz offset
        self.assertIsInstance(_find_key(envelope, "tz_offset"), int)

    def test_no_layer_is_fabricated_from_telethon(self):
        # parity used to report telethon's own
        # layer (224) even for an iOS identity whose mint refuses < 232,
        # which defeats describe_envelope's reverse lookup
        from tgmint.layers import telethon_layer

        try:
            telethon_own = telethon_layer()
        except Exception:  # pragma: no cover - layers module unavailable
            telethon_own = None
        for preset in ("ios", "android", "desktop"):
            with self.subTest(preset=preset):
                code, out, err = run_cli(
                    ["parity", "--preset", preset, "--unique-id", f"cli-layer-{preset}", "--json"]
                )
                self.assertEqual(code, 0, err)
                layer = _find_key(json.loads(out), "layer")
                self.assertNotEqual(layer, telethon_own)
                # and an explicit --layer is still honoured verbatim
                if preset == "desktop":
                    code, out, err = run_cli(
                        [
                            "parity", "--preset", preset, "--layer", "150",
                            "--unique-id", "cli-layer-explicit", "--json",
                        ]
                    )
                    self.assertEqual(code, 0, err)
                    self.assertEqual(_find_key(json.loads(out), "layer"), 150)

    def test_human_mode_does_not_crash(self):
        code, out, err = run_cli(
            ["parity", "--preset", "ios", "--unique-id", "cli-parh"]
        )
        self.assertEqual(code, 0, err)
        self.assertIn("initConnection envelope", out)


class ConvertCliTest(unittest.TestCase):
    """Every cell runs through the REAL CLI handler (`cli.main`) with a
    fixed 256-byte auth_key; outputs are parsed back and must round-trip
    to the same key. None of these tests may skip when the codec exists
    — that is the regression this class pins.
    """

    KEY = bytes(range(256))  # fixed seed; the only secret that moves
    DC = 2
    USER = 777000
    API = 2040

    def _telethon_string(self):
        return telethon.write_string(
            SessionData(
                dc_id=self.DC,
                auth_key=self.KEY,
                server_address=PROD_DC[self.DC],
                port=443,
            )
        )

    def _pyrogram_string(self):
        return pyrogram.write_string(
            SessionData(
                dc_id=self.DC, auth_key=self.KEY,
                user_id=self.USER, api_id=self.API,
            )
        )

    def test_telethon_string_to_pyrogram_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.pyrogram.string")
            code, out_txt, err = run_cli(
                [
                    "convert",
                    "--from", self._telethon_string(),
                    "--from-format", "telethon-string",
                    "--to", out,
                    "--to-format", "pyrogram-string",
                    "--json",
                ]
            )
            self.assertEqual(code, 0, err)
            payload = json.loads(out_txt)
            result = payload["result"]
            self.assertEqual(result["dc_id"], self.DC)
            # the source format stores no identity: the CLI reports the
            # placeholder fills instead of hiding them
            self.assertEqual(sorted(result["filled"]), ["api_id", "user_id"])
            self.assertTrue(result["notes"])
            with open(out, encoding="ascii") as fp:
                string = fp.read().strip()
            data = pyrogram.read_string(string)
            self.assertEqual(data.auth_key, self.KEY)
            self.assertEqual(data.dc_id, self.DC)

    def test_telethon_string_from_file(self):
        # --from may point at a file that holds the session string
        # (what anyone who saved their StringSession to disk does)
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "saved.string")
            with open(src, "w", encoding="ascii") as fp:
                fp.write(self._telethon_string() + "\n")
            out = os.path.join(tmp, "out.pyrogram.string")
            code, _out_txt, err = run_cli(
                [
                    "convert",
                    "--from", src,
                    "--from-format", "telethon-string",
                    "--to", out,
                    "--to-format", "pyrogram-string",
                    "--json",
                ]
            )
            self.assertEqual(code, 0, err)
            with open(out, encoding="ascii") as fp:
                string = fp.read().strip()
            data = pyrogram.read_string(string)
            self.assertEqual(data.auth_key, self.KEY)
            self.assertEqual(data.dc_id, self.DC)

    def test_pyrogram_string_to_gramjs_string(self):
        # gramjs-string must be accepted as a --to format end to end
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.gramjs.string")
            code, out_txt, err = run_cli(
                [
                    "convert",
                    "--from", self._pyrogram_string(),
                    "--from-format", "pyrogram-string",
                    "--to", out,
                    "--to-format", "gramjs-string",
                    "--json",
                ]
            )
            self.assertEqual(code, 0, err)
            payload = json.loads(out_txt)
            self.assertEqual(payload["to_format"], "gramjs-string")
            with open(out, encoding="ascii") as fp:
                string = fp.read().strip()
            data = gramjs.read_string(string)
            self.assertEqual(data.auth_key, self.KEY)
            self.assertEqual(data.dc_id, self.DC)
            # endpoint not representable in the source string; the writer
            # resolved it from the DC table
            self.assertEqual(data.server_address, PROD_DC[self.DC])

    def test_telethon_string_to_telethon_session_sqlite(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.session")
            code, out_txt, err = run_cli(
                [
                    "convert",
                    "--from", self._telethon_string(),
                    "--from-format", "telethon-string",
                    "--to", out,
                    "--to-format", "telethon-session",
                ]
            )
            self.assertEqual(code, 0, err)
            self.assertIn("converted", out_txt)  # human mode
            self.assertIn(f"dc_id: {self.DC}", out_txt)
            self.assertEqual(telethon.read_sqlite(out).auth_key, self.KEY)
            # sqlite output is created private, never world-readable
            self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)

    def test_pyrogram_session_sqlite_to_telethon_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src.session")
            pyrogram.write_sqlite(
                SessionData(
                    dc_id=self.DC, auth_key=self.KEY,
                    user_id=self.USER, api_id=self.API,
                ),
                src,
                variant="pyrogram",
            )
            out = os.path.join(tmp, "out.telethon.string")
            code, out_txt, err = run_cli(
                [
                    "convert",
                    "--from", src,
                    "--from-format", "pyrogram-session",
                    "--to", out,
                    "--to-format", "telethon-string",
                    "--json",
                ]
            )
            self.assertEqual(code, 0, err)
            with open(out, encoding="ascii") as fp:
                string = fp.read().strip()
            data = telethon.read_string(string)
            self.assertEqual(data.auth_key, self.KEY)
            # vanilla pyrogram sqlite stores no endpoint; the telethon
            # writer filled it from the DC table
            self.assertEqual(data.server_address, PROD_DC[self.DC])
            self.assertEqual(data.port, 443)

    @unittest.skipUnless(HAVE_TD, "tgmint.td (tgcrypto) not installed — tdata destination skipped")
    def test_telethon_string_to_tdata_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = os.path.join(tmp, "tdata")
            code, out_txt, err = run_cli(
                [
                    "convert",
                    "--from", self._telethon_string(),
                    "--from-format", "telethon-string",
                    "--to", folder,
                    "--to-format", "tdata",
                    "--json",
                ]
            )
            self.assertEqual(code, 0, err)
            result = json.loads(out_txt)["result"]
            self.assertEqual(result["output_kind"], "tdata-directory")
            from tgmint.codec import tdata

            data = tdata.read(folder)
            self.assertEqual(data.auth_key, self.KEY)
            self.assertEqual(data.dc_id, self.DC)

    def test_existing_output_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "precious.string")
            with open(out, "w", encoding="utf-8") as fp:
                fp.write("keep me")
            code, out_txt, err = run_cli(
                [
                    "convert",
                    "--from", self._telethon_string(),
                    "--from-format", "telethon-string",
                    "--to", out,
                    "--to-format", "pyrogram-string",
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("convert failed", err)
            with open(out, encoding="utf-8") as fp:
                self.assertEqual(fp.read(), "keep me")

    def test_an_unset_passphrase_env_is_a_usage_error(self):
        # convert ignored --passphrase-env for a
        # non-profile source, so a typo'd variable name stayed invisible
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.pyrogram.string")
            code, out_txt, err = run_cli(
                [
                    "convert",
                    "--from", self._telethon_string(),
                    "--from-format", "telethon-string",
                    "--to", out,
                    "--to-format", "pyrogram-string",
                    "--passphrase-env", "TGMINT_SURELY_NOT_SET",
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("TGMINT_SURELY_NOT_SET", err)
            self.assertFalse(os.path.exists(out))

    def test_a_json_failure_is_machine_readable(self):
        # convert's --json failures printed
        # nothing on stdout
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "taken.string")
            with open(out, "w", encoding="utf-8") as fp:
                fp.write("keep me")
            code, out_txt, err = run_cli(
                [
                    "convert",
                    "--from", self._telethon_string(),
                    "--from-format", "telethon-string",
                    "--to", out,
                    "--to-format", "pyrogram-string",
                    "--json",
                ]
            )
            self.assertEqual(code, 2)
            payload = json.loads(out_txt)
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["command"], "convert")
            self.assertIn("convert failed", payload["error"])

    def test_an_unset_passcode_env_is_a_usage_error(self):
        # a tdata passcode is a secret, so it comes from the environment;
        # a typo'd variable name must not read as "no passcode"
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.pyrogram.string")
            code, out_txt, err = run_cli(
                [
                    "convert",
                    "--from", self._telethon_string(),
                    "--from-format", "telethon-string",
                    "--to", out,
                    "--to-format", "pyrogram-string",
                    "--passcode-env", "TGMINT_SURELY_NOT_SET",
                    "--json",
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("TGMINT_SURELY_NOT_SET", err)
            self.assertIn("not set", json.loads(out_txt)["error"])
            self.assertFalse(os.path.exists(out))

    def test_the_variant_reaches_convert_session(self):
        captured = {}

        def fake_convert(source, source_format, destination, destination_format, **kwargs):
            captured.update(kwargs)
            return {"dc_id": self.DC, "output": destination, "notes": []}

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(codec, "convert_session", fake_convert):
                code, out_txt, err = run_cli(
                    [
                        "convert",
                        "--from", self._telethon_string(),
                        "--from-format", "telethon-string",
                        "--to", os.path.join(tmp, "out.session"),
                        "--to-format", "pyrogram-session",
                        "--variant", "kurigram",
                        "--json",
                    ]
                )
            self.assertEqual(code, 0, err)
        self.assertEqual(captured["variant"], "kurigram")

    def test_the_account_index_reaches_convert_session(self):
        captured = {}

        def fake_convert(source, source_format, destination, destination_format, **kwargs):
            captured.update(kwargs)
            return {"dc_id": self.DC, "output": destination, "notes": []}

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(codec, "convert_session", fake_convert):
                code, out_txt, err = run_cli(
                    [
                        "convert",
                        "--from", os.path.join(tmp, "tdata"),
                        "--from-format", "tdata",
                        "--to", os.path.join(tmp, "out.string"),
                        "--to-format", "telethon-string",
                        "--account-index", "1",
                        "--json",
                    ]
                )
            self.assertEqual(code, 0, err)
        self.assertEqual(captured["account_index"], 1)

    def test_unknown_format_rejected_by_argparse(self):
        with self.assertRaises(SystemExit) as ctx:
            run_cli(
                [
                    "convert",
                    "--from", "x", "--from-format", "telethon-string",
                    "--to", "y", "--to-format", "hydrogram-string",
                ]
            )
        self.assertEqual(ctx.exception.code, 2)

    def test_exit_2_when_codec_missing(self):
        # a build without the codec must still fail cleanly, never crash:
        # a None entry in sys.modules makes `import tgmint.codec` raise
        with mock.patch.dict(sys.modules, {"tgmint.codec": None}):
            code, out_txt, err = run_cli(
                [
                    "convert",
                    "--from", "in.session",
                    "--from-format", "telethon-session",
                    "--to", "out.tdata",
                    "--to-format", "tdata",
                ]
            )
        self.assertEqual(code, 2)
        self.assertIn("codec module not available", err)

    def test_convert_via_python_dash_m(self):
        # the console path too: `python -m tgmint convert` in a subprocess
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.pyrogram.string")
            env = dict(os.environ, PYTHONPATH=_SRC)
            proc = subprocess.run(
                [
                    sys.executable, "-m", "tgmint", "convert",
                    "--from", self._telethon_string(),
                    "--from-format", "telethon-string",
                    "--to", out,
                    "--to-format", "pyrogram-string",
                ],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("converted", proc.stdout)
            with open(out, encoding="ascii") as fp:
                string = fp.read().strip()
            self.assertEqual(pyrogram.read_string(string).auth_key, self.KEY)


class LoginPasskeyCliTest(unittest.TestCase):
    """`login-passkey` — validation and refusal paths only.

    The command's real path (passkey ceremony -> login -> convert) needs a
    live account with a registered passkey, so it stays manually testable.
    What is pinned here is everything that must happen *before* a socket
    is opened: argparse requiredness, preset/format choice validation, the
    missing/corrupt passkey refusal, the existing-output refusal, and the
    --json error shape. None of these tests may touch the network.
    """

    PRESETS = ("desktop", "android", "android-x", "ios", "macos")
    FORMATS = (
        "telethon-session",
        "telethon-string",
        "pyrogram-session",
        "pyrogram-string",
        "gramjs-string",
        "tdata",
    )

    def _argv(self, tmp, passkey=None, preset=None, fmt="telethon-session"):
        argv = [
            "login-passkey",
            "--passkey", passkey or os.path.join(tmp, "missing.passkey.json"),
        ]
        if preset is not None:
            argv += ["--preset", preset]
        argv += [
            "--to", os.path.join(tmp, "out.session"),
            "--to-format", fmt,
        ]
        return argv

    def _stub_passkey(self, tmp):
        """A file that exists but is not a passkey store: enough to get
        past the existence check and reach the later refusals offline."""
        path = os.path.join(tmp, "stub.passkey.json")
        with open(path, "w", encoding="utf-8") as fp:
            fp.write("{}")
        return path

    def test_missing_passkey_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit) as ctx:
                run_cli(
                    [
                        "login-passkey",
                        "--to", os.path.join(tmp, "out.session"),
                        "--to-format", "telethon-session",
                    ]
                )
        self.assertEqual(ctx.exception.code, 2)

    def test_missing_to_path_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as ctx:
            run_cli(
                [
                    "login-passkey", "--passkey", "acct.passkey.json",
                    "--to-format", "telethon-session",
                ]
            )
        self.assertEqual(ctx.exception.code, 2)

    def test_missing_to_format_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as ctx:
            run_cli(
                [
                    "login-passkey", "--passkey", "acct.passkey.json",
                    "--to", "out.session",
                ]
            )
        self.assertEqual(ctx.exception.code, 2)

    def test_unknown_preset_rejected_by_argparse(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit) as ctx:
                run_cli(self._argv(tmp, preset="web"))
        self.assertEqual(ctx.exception.code, 2)

    def test_unknown_to_format_rejected_by_argparse(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit) as ctx:
                run_cli(self._argv(tmp, fmt="hydrogram-string"))
        self.assertEqual(ctx.exception.code, 2)

    def test_every_preset_and_format_is_accepted(self):
        # argparse-level acceptance only: each value gets past the parser
        # and then fails on the missing passkey (exit 2, not SystemExit) —
        # so no value is silently rejected as a choice
        for preset in self.PRESETS:
            for fmt in self.FORMATS:
                with tempfile.TemporaryDirectory() as tmp:
                    code, out, err = run_cli(
                        self._argv(tmp, preset=preset, fmt=fmt)
                    )
                self.assertEqual(code, 2, (preset, fmt, err))
                self.assertIn("no such file", err, (preset, fmt))

    def test_bad_passkey_path_exits_2_with_clear_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "gone.passkey.json")
            code, out, err = run_cli(self._argv(tmp, passkey=missing))
            self.assertEqual(code, 2)
            self.assertIn(f"--passkey {missing}: no such file", err)
            self.assertIn("tgmint:", err)
            # nothing is created when the command refuses up front
            self.assertFalse(os.path.exists(os.path.join(tmp, "out.session")))

    def test_corrupt_passkey_store_is_a_refusal(self):
        # a session we cannot even read is a usage refusal (2), never a
        # failed login (1) — and it is caught before any connection
        with tempfile.TemporaryDirectory() as tmp:
            passkey = os.path.join(tmp, "corrupt.passkey.json")
            with open(passkey, "w", encoding="utf-8") as fp:
                fp.write("{not json")
            code, out, err = run_cli(self._argv(tmp, passkey=passkey))
            self.assertEqual(code, 2)
            self.assertIn("not a usable passkey store", err)

    def test_macos_layer_refused(self):
        # macos stays pin-only (no verified layer table): the mint helper's
        # refusal surfaces as exit 2, before any login is attempted
        with tempfile.TemporaryDirectory() as tmp:
            passkey = self._stub_passkey(tmp)
            code, out, err = run_cli(
                self._argv(tmp, passkey=passkey, preset="macos")
                + ["--layer", "200"]
            )
            self.assertEqual(code, 2)
            self.assertIn("--layer is not supported for the macos preset", err)

    def test_existing_output_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            passkey = self._stub_passkey(tmp)
            to = os.path.join(tmp, "precious.session")
            with open(to, "w", encoding="utf-8") as fp:
                fp.write("keep me")
            code, out, err = run_cli(
                [
                    "login-passkey", "--passkey", passkey,
                    "--to", to, "--to-format", "telethon-session",
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("output already exists", err)
            with open(to, encoding="utf-8") as fp:
                self.assertEqual(fp.read(), "keep me")

    def test_json_error_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "gone.passkey.json")
            code, out, err = run_cli(
                self._argv(tmp, passkey=missing) + ["--json"]
            )
            self.assertEqual(code, 2)
            payload = json.loads(out)  # machine-readable, must parse
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["command"], "login-passkey")
            self.assertIn("no such file", payload["error"])
            self.assertIn("tgmint:", err)  # the human line stays on stderr

    def test_json_error_shape_for_refused_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            passkey = self._stub_passkey(tmp)
            to = os.path.join(tmp, "taken.session")
            with open(to, "w", encoding="utf-8") as fp:
                fp.write("x")
            code, out, err = run_cli(
                [
                    "login-passkey", "--passkey", passkey,
                    "--to", to, "--to-format", "telethon-session",
                    "--json",
                ]
            )
            self.assertEqual(code, 2)
            payload = json.loads(out)
            self.assertFalse(payload["ok"])
            self.assertIn("output already exists", payload["error"])

    def test_exit_2_when_tgmint_tl_missing(self):
        # a build without telethon must fail cleanly with a "needs the
        # telethon extra" message, never a traceback
        with tempfile.TemporaryDirectory() as tmp:
            passkey = self._stub_passkey(tmp)
            with mock.patch.dict(sys.modules, {"tgmint.tl": None}):
                code, out, err = run_cli(self._argv(tmp, passkey=passkey))
        self.assertEqual(code, 2)
        self.assertIn("telethon extra", err)

    def test_help_keeps_the_own_account_language(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as ctx:
                cli.main(["login-passkey", "--help"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("a session you own", out.getvalue())


class ProfileCliTest(unittest.TestCase):
    """`profile seal` / `profile open` / `profile inspect`, end to end.

    Everything here is offline and lives in a temp directory. The sealed
    cases use a real passphrase through an environment variable, which is
    also the point: a passphrase must never have to appear in argv.
    """

    def _session_file(self, tmp, key=None):
        path = os.path.join(tmp, "acct.string")
        with open(path, "w", encoding="ascii") as fp:
            fp.write(telethon.write_string(_session(key=key)))
        return path

    def _profile(self, tmp, *extra):
        session = self._session_file(tmp)
        out = os.path.join(tmp, "acct.tgmint")
        code, stdout, err = run_cli(
            [
                "profile", "seal",
                "--session", session,
                "--from-format", "telethon-string",
                "--out", out,
                *extra,
            ]
        )
        return code, stdout, err, out

    def test_seal_then_inspect_then_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out_json, err, profile = self._profile(tmp, "--json")
            self.assertEqual(code, 0, err)
            payload = json.loads(out_json)
            self.assertTrue(payload["ok"])
            self.assertFalse(payload["sealed"])
            self.assertEqual(payload["session_format"], "telethon-string")
            self.assertEqual(payload["dc_id"], DC_ID)
            self.assertEqual(payload["out"], profile)
            self.assertTrue(os.path.isfile(profile))
            self.assertEqual(stat_mode(profile), 0o600)

            code, out_json, err = run_cli(["profile", "inspect", profile, "--json"])
            self.assertEqual(code, 0, err)
            summary = json.loads(out_json)
            self.assertFalse(summary["sealed"])
            self.assertFalse(summary["locked"])
            self.assertEqual(summary["session_format"], "telethon-string")
            self.assertEqual(summary["dc_id"], DC_ID)
            self.assertFalse(summary["has_fingerprint"])
            self.assertFalse(summary["has_passkey"])

            # the human form must not leak the auth key either
            code, out_text, err = run_cli(["profile", "inspect", profile])
            self.assertEqual(code, 0, err)
            self.assertIn("session_format: telethon-string", out_text)
            self.assertNotIn(KEY.hex(), out_text)

            target = os.path.join(tmp, "out.gramjs")
            code, out_json, err = run_cli(
                [
                    "profile", "open", profile,
                    "--to", target, "--to-format", "gramjs-string", "--json",
                ]
            )
            self.assertEqual(code, 0, err)
            opened = json.loads(out_json)
            self.assertTrue(opened["ok"])
            self.assertEqual(opened["conversion"]["dc_id"], DC_ID)
            with open(target, encoding="ascii") as fp:
                self.assertEqual(gramjs.read_string(fp.read()).auth_key, KEY)

    def test_sealed_profile_via_env_var(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"TGMINT_TEST_PASS": "hunter2"}):
                code, out_json, err, profile = self._profile(
                    tmp, "--passphrase-env", "TGMINT_TEST_PASS", "--json"
                )
                self.assertEqual(code, 0, err)
                self.assertTrue(json.loads(out_json)["sealed"])

                # locked without the passphrase, detailed with it
                code, out_json, err = run_cli(
                    ["profile", "inspect", profile, "--json"]
                )
                self.assertEqual(code, 0, err)
                locked = json.loads(out_json)
                self.assertTrue(locked["sealed"])
                self.assertTrue(locked["locked"])
                self.assertIsNone(locked["dc_id"])

                code, out_json, err = run_cli(
                    [
                        "profile", "inspect", profile,
                        "--passphrase-env", "TGMINT_TEST_PASS", "--json",
                    ]
                )
                self.assertEqual(code, 0, err)
                opened = json.loads(out_json)
                self.assertFalse(opened["locked"])
                self.assertEqual(opened["dc_id"], DC_ID)

                # opening it needs the passphrase too
                target = os.path.join(tmp, "out.string")
                code, _, err = run_cli(
                    ["profile", "open", profile, "--to", target,
                     "--to-format", "telethon-string"]
                )
                self.assertEqual(code, 2)
                self.assertIn("sealed", err)
                self.assertFalse(os.path.exists(target))

                code, _, err = run_cli(
                    [
                        "profile", "open", profile,
                        "--passphrase-env", "TGMINT_TEST_PASS",
                        "--to", target, "--to-format", "telethon-string",
                    ]
                )
                self.assertEqual(code, 0, err)
                with open(target, encoding="ascii") as fp:
                    self.assertEqual(telethon.read_string(fp.read()).auth_key, KEY)

    def test_seal_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            _code, _out, _err, profile = self._profile(tmp)
            with open(profile, "rb") as fp:
                before = fp.read()
            session = self._session_file(tmp)
            code, out_json, err = run_cli(
                [
                    "profile", "seal",
                    "--session", session,
                    "--from-format", "telethon-string",
                    "--out", profile, "--json",
                ]
            )
            self.assertEqual(code, 2)
            payload = json.loads(out_json)
            self.assertFalse(payload["ok"])
            self.assertIn("already exists", payload["error"])
            with open(profile, "rb") as fp:
                self.assertEqual(fp.read(), before)

    def test_missing_passphrase_env_var_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = self._session_file(tmp)
            code, out_json, err = run_cli(
                [
                    "profile", "seal",
                    "--session", session,
                    "--from-format", "telethon-string",
                    "--out", os.path.join(tmp, "x.tgmint"),
                    "--passphrase-env", "TGMINT_SURELY_NOT_SET",
                    "--json",
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("TGMINT_SURELY_NOT_SET", err)
            self.assertIn("not set", json.loads(out_json)["error"])
            self.assertFalse(os.path.exists(os.path.join(tmp, "x.tgmint")))

    def test_seal_human_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err, profile = self._profile(tmp, "--note", "primary")
            self.assertEqual(code, 0, err)
            self.assertIn("wrote " + profile, out)
            self.assertIn("plaintext", out)
            self.assertIn("session_format: telethon-string", out)

    def test_seal_picks_up_the_sessions_own_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = self._session_file(tmp)
            sidecar = session + ".fingerprint.json"
            code, _out, err = run_cli(
                [
                    "mint", "--preset", "desktop", "--unique-id", "cli-profile",
                    "--save", sidecar,
                ]
            )
            self.assertEqual(code, 0, err)
            code, out_json, err, profile = self._profile(tmp, "--json")
            self.assertEqual(code, 0, err)
            payload = json.loads(out_json)
            self.assertEqual(payload["fingerprint"], sidecar)
            code, out_json, err = run_cli(["profile", "inspect", profile, "--json"])
            self.assertTrue(json.loads(out_json)["has_fingerprint"])

    def test_seal_with_a_broken_session_is_a_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            broken = os.path.join(tmp, "broken.string")
            with open(broken, "w", encoding="ascii") as fp:
                fp.write("not-a-session")
            code, out_json, err = run_cli(
                [
                    "profile", "seal",
                    "--session", broken,
                    "--from-format", "telethon-string",
                    "--out", os.path.join(tmp, "x.tgmint"), "--json",
                ]
            )
            self.assertEqual(code, 2)
            self.assertFalse(json.loads(out_json)["ok"])
            self.assertIn("broken.string", err)

    def test_open_refuses_an_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            _code, _out, _err, profile = self._profile(tmp)
            target = os.path.join(tmp, "taken.string")
            with open(target, "w", encoding="ascii") as fp:
                fp.write("keep me")
            code, out_json, err = run_cli(
                [
                    "profile", "open", profile,
                    "--to", target, "--to-format", "telethon-string", "--json",
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("already exists", json.loads(out_json)["error"])
            with open(target, encoding="ascii") as fp:
                self.assertEqual(fp.read(), "keep me")

    def test_inspect_missing_file(self):
        code, out_json, err = run_cli(
            ["profile", "inspect", "/nonexistent/x.tgmint", "--json"]
        )
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out_json)["command"], "profile inspect")

    def test_no_subcommand_exits_2(self):
        code, out, err = run_cli(["profile"])
        self.assertEqual(code, 2)
        self.assertIn("seal, open, or inspect", err)

    def test_convert_from_a_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            _code, _out, _err, profile = self._profile(tmp)
            target = os.path.join(tmp, "converted.pyro")
            code, out_json, err = run_cli(
                [
                    "convert",
                    "--from", profile, "--from-format", "profile",
                    "--to", target, "--to-format", "pyrogram-string",
                    "--json",
                ]
            )
            self.assertEqual(code, 0, err)
            payload = json.loads(out_json)
            self.assertEqual(payload["result"]["source_format"], "profile")
            with open(target, encoding="ascii") as fp:
                self.assertEqual(pyrogram.read_string(fp.read()).auth_key, KEY)

    def test_resealing_a_sealed_envelope_reads_it_with_the_passphrase(self):
        # seal never passed passphrase= to
        # read_session, so `--from-format profile` on a sealed envelope
        # failed with "a passphrase is required" even though one was given
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"TGMINT_TEST_PASS": "hunter2"}):
                code, _out, err, profile = self._profile(
                    tmp, "--passphrase-env", "TGMINT_TEST_PASS", "--json"
                )
                self.assertEqual(code, 0, err)
                again = os.path.join(tmp, "again.tgmint")
                code, out_json, err = run_cli(
                    [
                        "profile", "seal",
                        "--session", profile,
                        "--from-format", "profile",
                        "--out", again,
                        "--passphrase-env", "TGMINT_TEST_PASS",
                        "--json",
                    ]
                )
                self.assertEqual(code, 0, err)
                payload = json.loads(out_json)
                self.assertTrue(payload["sealed"])
                # the new envelope records the *inner* format, not "profile"
                self.assertEqual(payload["source_format"], "profile")
                self.assertEqual(payload["session_format"], "telethon-string")
                # the second envelope opens with the same passphrase
                code, out_json, err = run_cli(
                    [
                        "profile", "inspect", again,
                        "--passphrase-env", "TGMINT_TEST_PASS", "--json",
                    ]
                )
                self.assertEqual(code, 0, err)
                self.assertEqual(json.loads(out_json)["dc_id"], DC_ID)

    def test_seal_reports_an_oserror_as_a_refusal(self):
        # only FileExistsError/ValueError were
        # caught, so an OSError escaped as a traceback and exit 1
        with tempfile.TemporaryDirectory() as tmp:
            session = self._session_file(tmp)
            code, out_json, err = run_cli(
                [
                    "profile", "seal",
                    "--session", session,
                    "--from-format", "telethon-string",
                    "--out", os.path.join(tmp, "x.tgmint"),
                    "--json",
                ]
            )
            self.assertEqual(code, 0, err)  # sanity: the plain path works
            with mock.patch(
                "tgmint.profile.write_profile", side_effect=OSError("disk full")
            ):
                code, out_json, err = run_cli(
                    [
                        "profile", "seal",
                        "--session", session,
                        "--from-format", "telethon-string",
                        "--out", os.path.join(tmp, "y.tgmint"),
                        "--json",
                    ]
                )
            self.assertEqual(code, 2)
            self.assertIn("disk full", err)
            payload = json.loads(out_json)
            self.assertFalse(payload["ok"])
            self.assertIn("disk full", payload["error"])

    def test_help_mentions_the_envelope(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as ctx:
                cli.main(["profile", "seal", "--help"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("--passphrase-env", out.getvalue())


class _FakeSession:
    def __init__(self, key):
        self.dc_id = NEW_DC
        self.auth_key = dataclasses.make_dataclass("K", ["key"])(key)


class _FakeClient:
    """Just enough of a Telethon client for the heal handler's seams."""

    def __init__(self, key=None, me=None, error=None):
        self.session = _FakeSession(key or NEW_KEY)
        self.me = me if me is not None else type("Me", (), {"id": USER_ID})()
        self.error = error
        self.disconnects = 0

    async def connect(self):
        return None

    async def disconnect(self):
        self.disconnects += 1

    async def get_me(self):
        if self.error is not None:
            raise self.error
        return self.me


class HealCliTest(unittest.TestCase):
    """`tgmint heal` with the library's network seams mocked out.

    No socket is opened: the client factory, the liveness probe and the
    passkey login are all replaced, so what is pinned is the command's
    control flow, its exit codes and its reporting.
    """

    def _fixture(self, tmp, fmt="telethon-session", key=None):
        path = os.path.join(tmp, "acct.session" if fmt.startswith("telethon-session") else "acct.string")
        codec.write_session(_session(key=key), path, fmt)
        passkey = os.path.join(tmp, "acct.passkey.json")
        with open(passkey, "w", encoding="utf-8") as fp:
            json.dump(
                {
                    "version": 1,
                    "credential_id": "Y3JlZC0x",
                    "rp_id": "telegram.org",
                    "origin": "https://telegram.org",
                    "alg": -7,
                    "user_handle": f"2:{USER_ID}",
                    "private_key": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
                    "sign_count": 0,
                    "name": "tgmint software passkey",
                },
                fp,
            )
        return path, passkey

    def _patch(self, *, probe, login, clients=None):
        from tgmint import heal as heal_module

        clients = clients or {}

        def factory(*, kind, api, data=None):
            return clients[kind]

        patches = [
            mock.patch.object(heal_module, "make_client", factory),
        ]
        if probe is not None:
            patches.append(mock.patch.object(heal_module, "probe_session", probe))
        if login is not None:
            patches.append(mock.patch.object(heal_module, "_default_login", login))
        return patches

    def test_alive_session_is_reported_and_left_alone(self):
        async def probe(_client):
            return {
                "performed": True,
                "alive": True,
                "dead": False,
                "reason": "the server accepted the stored auth key",
                "user_id": USER_ID,
            }

        async def login(_client, *, passkey_path, password=None):  # pragma: no cover
            raise AssertionError("the login must not run for an alive session")

        with tempfile.TemporaryDirectory() as tmp:
            path, passkey = self._fixture(tmp)
            with open(path, "rb") as fp:
                before = fp.read()
            patches = self._patch(
                probe=probe, login=login, clients={"probe": _FakeClient()}
            )
            for patch in patches:
                patch.start()
                self.addCleanup(patch.stop)
            code, out, err = run_cli(
                ["heal", path, "--passkey", passkey, "--live", "--json"]
            )
            for patch in patches:
                patch.stop()
            self.assertEqual(code, 0, err)
            report = json.loads(out)
            self.assertEqual(report["action"], "noop")
            self.assertFalse(report["auth_key_changed"])
            with open(path, "rb") as fp:
                self.assertEqual(fp.read(), before)

    def test_dead_session_is_healed(self):
        async def probe(_client):
            return {
                "performed": True,
                "alive": False,
                "dead": True,
                "reason": "the server rejected the stored auth key",
                "user_id": None,
            }

        async def login(_client, *, passkey_path, password=None):
            return type("Me", (), {"id": USER_ID})()

        with tempfile.TemporaryDirectory() as tmp:
            path, passkey = self._fixture(tmp)
            patches = self._patch(
                probe=probe,
                login=login,
                clients={"probe": _FakeClient(error=RuntimeError("dead")), "login": _FakeClient()},
            )
            for patch in patches:
                patch.start()
                self.addCleanup(patch.stop)
            code, out, err = run_cli(
                ["heal", path, "--passkey", passkey, "--live", "--json"]
            )
            for patch in patches:
                patch.stop()
            self.assertEqual(code, 0, err)
            report = json.loads(out)
            self.assertEqual(report["action"], "healed")
            self.assertTrue(report["auth_key_changed"])
            self.assertEqual(report["new"]["dc_id"], NEW_DC)
            fresh = codec.read_session(path, "telethon-session")
            self.assertEqual(fresh.auth_key, NEW_KEY)
            self.assertNotEqual(fresh.auth_key, KEY)

    def test_without_live_or_force_is_a_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, passkey = self._fixture(tmp)
            code, out, err = run_cli(
                ["heal", path, "--passkey", passkey, "--json"]
            )
            self.assertEqual(code, 2)
            payload = json.loads(out)
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["command"], "heal")
            self.assertIn("--live", payload["error"])
            self.assertIn("--force", payload["error"])

    def test_missing_passkey_is_a_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _passkey = self._fixture(tmp)
            code, out, err = run_cli(
                [
                    "heal", path,
                    "--passkey", os.path.join(tmp, "gone.passkey.json"),
                    "--live", "--json",
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("no such file", json.loads(out)["error"])

    def test_login_failure_exits_2(self):
        # a failed login is a runtime error (2); exit 1 belongs to audit
        async def probe(_client):
            return {
                "performed": True,
                "alive": False,
                "dead": True,
                "reason": "dead",
                "user_id": None,
            }

        async def login(_client, *, passkey_path, password=None):
            raise RuntimeError("server said no")

        with tempfile.TemporaryDirectory() as tmp:
            path, passkey = self._fixture(tmp)
            patches = self._patch(
                probe=probe, login=login, clients={"probe": _FakeClient(), "login": _FakeClient()}
            )
            for patch in patches:
                patch.start()
                self.addCleanup(patch.stop)
            code, out, err = run_cli(
                ["heal", path, "--passkey", passkey, "--live", "--json"]
            )
            for patch in patches:
                patch.stop()
            self.assertEqual(code, 2)
            payload = json.loads(out)
            self.assertFalse(payload["ok"])
            self.assertIn("server said no", payload["error"])

    def test_a_plain_session_is_not_asked_for_a_profile_passphrase(self):
        # heal resolved the passphrase
        # unconditionally, prompting for a "profile passphrase" even when
        # the source is a plain session (bootstrap gates the same way)
        async def probe(_client):
            return {
                "performed": True,
                "alive": True,
                "dead": False,
                "reason": "alive",
                "user_id": USER_ID,
            }

        async def login(_client, *, passkey_path, password=None):  # pragma: no cover
            raise AssertionError("the login must not run for an alive session")

        with tempfile.TemporaryDirectory() as tmp:
            path, passkey = self._fixture(tmp)
            patches = self._patch(
                probe=probe, login=login, clients={"probe": _FakeClient()}
            )
            resolver = mock.patch.object(
                cli, "_resolve_passphrase", side_effect=AssertionError("prompted")
            )
            for patch in patches:
                patch.start()
                self.addCleanup(patch.stop)
            resolver.start()
            self.addCleanup(resolver.stop)
            try:
                code, out, err = run_cli(
                    ["heal", path, "--passkey", passkey, "--live", "--json"]
                )
            finally:
                resolver.stop()
                for patch in patches:
                    patch.stop()
            self.assertEqual(code, 0, err)

    def test_a_passphrase_flag_is_still_validated(self):
        # the flags are honoured (and validated) whenever they are given
        with tempfile.TemporaryDirectory() as tmp:
            path, passkey = self._fixture(tmp)
            code, out, err = run_cli(
                [
                    "heal", path, "--passkey", passkey, "--live",
                    "--passphrase-env", "TGMINT_SURELY_NOT_SET", "--json",
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("TGMINT_SURELY_NOT_SET", json.loads(out)["error"])

    def test_a_format_change_needs_out(self):
        # heal converted in place, destroying
        # the original format while the file name kept claiming it
        with tempfile.TemporaryDirectory() as tmp:
            path, passkey = self._fixture(tmp)
            with open(path, "rb") as fp:
                before = fp.read()
            code, out, err = run_cli(
                [
                    "heal", path, "--passkey", passkey, "--live",
                    "--to-format", "gramjs-string", "--json",
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("--out", json.loads(out)["error"])
            with open(path, "rb") as fp:
                self.assertEqual(fp.read(), before)

    def test_out_writes_the_healed_session_elsewhere(self):
        async def probe(_client):
            return {
                "performed": True,
                "alive": False,
                "dead": True,
                "reason": "dead",
                "user_id": None,
            }

        async def login(_client, *, passkey_path, password=None):
            return type("Me", (), {"id": USER_ID})()

        with tempfile.TemporaryDirectory() as tmp:
            path, passkey = self._fixture(tmp)
            out_path = os.path.join(tmp, "healed.gramjs")
            with open(path, "rb") as fp:
                before = fp.read()
            patches = self._patch(
                probe=probe,
                login=login,
                clients={"probe": _FakeClient(), "login": _FakeClient()},
            )
            for patch in patches:
                patch.start()
                self.addCleanup(patch.stop)
            try:
                code, out, err = run_cli(
                    [
                        "heal", path, "--passkey", passkey, "--live",
                        "--to-format", "gramjs-string", "--out", out_path, "--json",
                    ]
                )
            finally:
                for patch in patches:
                    patch.stop()
            self.assertEqual(code, 0, err)
            payload = json.loads(out)
            self.assertEqual(payload["output"], out_path)
            self.assertFalse(payload["in_place"])
            self.assertEqual(
                gramjs.read_string(open(out_path, encoding="ascii").read()).auth_key,
                NEW_KEY,
            )
            with open(path, "rb") as fp:  # the source is untouched
                self.assertEqual(fp.read(), before)

    def test_help_states_the_single_account_guardrail(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as ctx:
                cli.main(["heal", "--help"])
        self.assertEqual(ctx.exception.code, 0)
        text = out.getvalue()
        self.assertIn("batch mode", text)
        self.assertIn("--live", text)


class LoginPasskeyIdentityTest(unittest.TestCase):
    """`login-passkey` must convert with the identity it learned at login.

    the command held ``user_id`` and ``api_id``
    and passed neither to ``convert_session``, so every pyrogram/gramjs
    destination was written with the placeholder ``user_id`` 777000 /
    ``api_id`` 2040 instead of the account's real numbers.
    """

    def _run_flow(self, tmp):
        import asyncio
        from types import SimpleNamespace

        class FakeSessionObject:
            dc_id = 4

            def save(self):
                return None

        class FakeClient:
            def __init__(self, path, api=None):
                self.session = FakeSessionObject()
                self.api = api

            async def connect(self):
                return None

            async def disconnect(self):
                return None

        async def fake_login(client, *, path, password=None, origin=None):
            return SimpleNamespace(id=USER_ID)

        captured = {}

        def fake_convert(source, source_format, destination, destination_format, **kwargs):
            captured.update(kwargs)
            return {"dc_id": 4, "output": destination, "notes": []}

        api = SimpleNamespace(api_id=2040)
        args = SimpleNamespace(
            to_path=os.path.join(tmp, "out.pyro"),
            to_format="pyrogram-string",
            password=None,
            origin=None,
        )
        import tgmint.codec
        import tgmint.passkeys

        try:
            import tgmint.tl
        except Exception as exc:  # pragma: no cover - telethon absent
            self.skipTest(f"tgmint.tl is not importable ({exc})")

        with mock.patch.object(
            tgmint.tl, "TelegramClient", FakeClient
        ), mock.patch.object(
            tgmint.passkeys, "login_with_passkey", fake_login
        ), mock.patch.object(
            tgmint.codec, "convert_session", fake_convert
        ):
            result = asyncio.run(cli._login_passkey_flow(api, args, "/x/acct.passkey.json"))
        return captured, result

    def test_the_conversion_gets_the_real_user_id_and_api_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            captured, result = self._run_flow(tmp)
        self.assertEqual(captured["user_id"], USER_ID)
        self.assertEqual(captured["api_id"], 2040)
        self.assertEqual(result["user_id"], USER_ID)


class BootstrapCliTest(unittest.TestCase):
    """`tgmint bootstrap` at the CLI boundary (the module itself is covered
    in tests/test_bootstrap.py; these pin the command's contract)."""

    def test_dry_run_json_needs_no_session(self):
        code, out, err = run_cli(
            ["bootstrap", "--preset", "android", "--dry-run", "--json"]
        )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["command"], "bootstrap")
        self.assertEqual(payload["platform"], "android")
        self.assertEqual(payload["sent"], 0)
        self.assertEqual(payload["errors"], [])
        self.assertEqual([e["status"] for e in payload["steps"]][0], "planned")
        # android's first network request is help.getConfig
        self.assertEqual(payload["steps"][0]["method"], "help.getConfig")

    def test_live_mode_refuses_without_a_session(self):
        code, out, err = run_cli(["bootstrap", "--preset", "desktop", "--json"])
        self.assertEqual(code, 2, err)
        payload = json.loads(out)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["command"], "bootstrap")
        self.assertIn("--session", payload["error"])
        self.assertIn("--dry-run", payload["error"])

    def test_dry_run_human_lists_the_plan(self):
        code, out, err = run_cli(["bootstrap", "--preset", "desktop", "--dry-run"])
        self.assertEqual(code, 0, err)
        self.assertIn("help.getConfig", out)
        self.assertIn("13 steps", out)


class MacosPresetCliTest(unittest.TestCase):
    def test_mint_macos_json(self):
        code, out, err = run_cli(
            ["mint", "--preset", "macos", "--unique-id", "cli-mac", "--json"]
        )
        self.assertEqual(code, 0, err)
        data = json.loads(out)
        self.assertEqual(data["preset"], "macos")
        self.assertEqual(data["lang_pack"], "macos")
        self.assertEqual(data["origin"], "macos")
        self.assertEqual(data["api_id"], 2834)
        self.assertTrue(data["device_model"])
        self.assertTrue(data["system_version"].startswith("macOS"))
        # default locale=auto mints a coherent triple
        self.assertIn("tz_zone", data)
        self.assertIsInstance(data["tz_offset"], int)

    def test_mint_macos_deterministic(self):
        args = ["mint", "--preset", "macos", "--unique-id", "stable-mac", "--json"]
        code_a, out_a, _ = run_cli(args)
        code_b, out_b, _ = run_cli(args)
        self.assertEqual(code_a, 0)
        self.assertEqual(code_b, 0)
        a, b = json.loads(out_a), json.loads(out_b)
        self.assertEqual(a["device_model"], b["device_model"])
        self.assertEqual(a["app_version"], b["app_version"])

    def test_mint_macos_layer_refused(self):
        # no verified macOS layer table exists, so --layer must surface a
        # clear refusal (exit 2), not a guess and not a crash
        code, out, err = run_cli(
            ["mint", "--preset", "macos", "--layer", "200", "--json"]
        )
        self.assertEqual(code, 2)
        self.assertIn("mint failed", err)
        self.assertIn("--layer is not supported for the macos preset", err)


class DoctorCliTest(unittest.TestCase):
    def test_doctor_smoke_json(self):
        code, out, err = run_cli(["doctor", "--json"])
        self.assertEqual(code, 0, err)
        report = json.loads(out)
        self.assertIn("version", report["python"])
        self.assertIn("wire_layer", report["telethon"])
        self.assertIn("tzdata", report)
        self.assertIn("extras", report)
        for extra in ("PyQt5", "cryptography", "pyrogram"):
            self.assertIn(extra, report["extras"])
        self.assertEqual(report["pinned"], PINNED)

    def test_doctor_human_smoke(self):
        code, out, err = run_cli(["doctor"])
        self.assertEqual(code, 0)
        self.assertIn("python", out)
        self.assertIn("telethon", out)
        self.assertIn("pinned versions", out)


class MainModuleTest(unittest.TestCase):
    def test_python_dash_m_runs(self):
        env = dict(os.environ, PYTHONPATH=_SRC)
        proc = subprocess.run(
            [sys.executable, "-m", "tgmint", "doctor", "--json"],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("python", json.loads(proc.stdout))

    def test_python_dash_m_help_exits_0(self):
        env = dict(os.environ, PYTHONPATH=_SRC)
        proc = subprocess.run(
            [sys.executable, "-m", "tgmint", "--help"],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("exit codes", proc.stdout)  # documented in --help

    def test_no_command_exits_2(self):
        code, out, err = run_cli([])
        self.assertEqual(code, 2)

    def test_unknown_command_argparse_exits_2(self):
        with self.assertRaises(SystemExit) as ctx:
            run_cli(["frobnicate"])
        self.assertEqual(ctx.exception.code, 2)

    def test_every_json_output_parses(self):
        # a final sweep: one --json call per command, each must parse
        with tempfile.TemporaryDirectory() as tmp:
            sidecar = os.path.join(tmp, "sweep.json")
            code, _, _ = run_cli(
                ["mint", "--preset", "android", "--unique-id", "sweep",
                 "--save", sidecar, "--json"]
            )
            self.assertEqual(code, 0)
            checks = [
                ["inspect", sidecar, "--json"],
                ["audit", sidecar, "--json"],
                ["freshness", "--json"],
                ["parity", "--preset", "android", "--json"],
                ["bootstrap", "--preset", "android", "--dry-run", "--json"],
                ["doctor", "--json"],
            ]
            for argv in checks:
                code, out, err = run_cli(argv)
                self.assertEqual(code, 0, f"{argv}: {err}")
                json.loads(out)  # must not raise


if __name__ == "__main__":
    unittest.main()
