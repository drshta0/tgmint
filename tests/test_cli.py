"""Tests for the tgmint CLI — tgmint.cli.main and `python -m tgmint`.

All offline: minting is seeded with --unique-id, sidecars live in
tempfile dirs, and `freshness` is asserted to never touch the network.
The `convert` test EXPECTS the codec module to be absent (it is, in
this tree) and skips itself in builds where a codec landed.
"""

import contextlib
import dataclasses
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tgmint import cli
from tgmint.fingerprint import SCHEMA_VERSION
from tgmint.versions import PINNED

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")


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
    def _codec_present(self):
        return importlib.util.find_spec("tgmint.codec") is not None

    def test_exit_2_when_codec_missing(self):
        if self._codec_present():
            self.skipTest("tgmint.codec exists in this build")
        code, out, err = run_cli(
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
