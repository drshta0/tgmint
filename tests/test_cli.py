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

from tgmint import cli
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
        self.assertEqual(_find_key(envelope, "api_id"), 6)
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
                ["doctor", "--json"],
            ]
            for argv in checks:
                code, out, err = run_cli(argv)
                self.assertEqual(code, 0, f"{argv}: {err}")
                json.loads(out)  # must not raise


if __name__ == "__main__":
    unittest.main()
