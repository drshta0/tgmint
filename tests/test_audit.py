"""Tests for tgmint.audit — the pure library layer under `tgmint audit`.

Everything here is offline: fingerprints are minted deterministically
(via --unique-id seeds) or built by hand, and the pin tables are either
the compiled-in PINNED or explicit dicts passed by the test.
"""

import dataclasses
import unittest
from datetime import datetime, timezone

from tgmint.api import API
from tgmint.audit import (
    app_family,
    audit_fingerprint,
    base_version,
    staleness_report,
    tz_report,
)
from tgmint.fingerprint import Fingerprint
from tgmint.versions import PINNED


def _desktop_fp(**overrides):
    # locale=None -> legacy en/en-US, no timezone (the CLI's --locale none)
    api = API.TelegramDesktop.Generate(
        system="linux", unique_id="audit-test", locale=None
    )
    fp = Fingerprint.from_apidata(api)
    return dataclasses.replace(fp, **overrides) if overrides else fp


class BaseVersionTest(unittest.TestCase):
    def test_strips_platform_suffixes(self):
        self.assertEqual(base_version("7.3.3 x64"), "7.3.3")
        self.assertEqual(base_version("7.3.3 arm64"), "7.3.3")
        self.assertEqual(base_version("13.1.0 (72291)"), "13.1.0")
        self.assertEqual(base_version("0.29.1 (1817)"), "0.29.1")
        self.assertEqual(base_version("1.0.1 K"), "1.0.1")
        self.assertEqual(base_version("7.3.3"), "7.3.3")

    def test_non_versions_are_empty(self):
        self.assertEqual(base_version("MyClient"), "")
        self.assertEqual(base_version(""), "")
        self.assertEqual(base_version(None), "")
        self.assertEqual(base_version(42), "")


class AppFamilyTest(unittest.TestCase):
    def test_official_api_ids_resolve(self):
        cases = [
            (2040, "tdesktop"),
            (6, "android"),
            (21724, "android_x"),  # android X shares lang_pack "android"
            (10840, "ios"),
            (2834, "macos"),
            (2496, "web_z"),
        ]
        for api_id, expected in cases:
            fp = _desktop_fp(api_id=api_id, origin="android")
            self.assertEqual(app_family(fp), expected, f"api_id={api_id}")

    def test_origin_fallback_and_unknown(self):
        self.assertEqual(app_family(_desktop_fp(origin="tdesktop")), "tdesktop")
        self.assertIsNone(app_family(_desktop_fp(api_id=999999, origin="")))
        self.assertIsNone(app_family(_desktop_fp(api_id=999999, origin="weird")))


class StalenessReportTest(unittest.TestCase):
    def test_minted_desktop_is_current(self):
        report = staleness_report(_desktop_fp())
        self.assertEqual(report["app"], "tdesktop")
        self.assertEqual(report["status"], "current")
        self.assertEqual(report["base_version"], base_version(PINNED["tdesktop"]))
        self.assertTrue(report["known_release"])

    def test_older_release_is_outdated_but_known(self):
        fp = _desktop_fp(app_version="6.7.8")  # layer-224 coherent release
        report = staleness_report(fp)
        self.assertEqual(report["status"], "outdated")
        self.assertTrue(report["known_release"])

    def test_newer_than_pin_is_ahead(self):
        report = staleness_report(_desktop_fp(app_version="99.0.0 x64"))
        self.assertEqual(report["status"], "ahead")

    def test_unrecognizable_version_is_unknown(self):
        report = staleness_report(_desktop_fp(app_version="MyFork build 42"))
        self.assertEqual(report["status"], "unknown")
        self.assertFalse(report["known_release"])
        self.assertIn("does not look like", report["detail"])

    def test_unknown_family_is_unknown(self):
        fp = _desktop_fp(api_id=123456, origin="")
        report = staleness_report(fp)
        self.assertIsNone(report["app"])
        self.assertEqual(report["status"], "unknown")

    def test_android_x_family_resolves_and_compares(self):
        api = API.TelegramAndroidX.Generate(unique_id="audit-x")
        report = staleness_report(Fingerprint.from_apidata(api))
        self.assertEqual(report["app"], "android_x")
        self.assertEqual(report["status"], "current")

    def test_explicit_pin_table_is_used(self):
        # pure function: the caller controls the pin table
        report = staleness_report(
            _desktop_fp(), pinned={"tdesktop": "6.7.8"}
        )
        self.assertEqual(report["pinned"], "6.7.8")
        self.assertEqual(report["status"], "ahead")

    def test_offline_pure_no_network(self):
        # staleness must resolve from compiled-in data alone: block the
        # versions fetcher path by feeding an empty pin table — no
        # lookup, no KeyError, just an honest unknown
        report = staleness_report(_desktop_fp(), pinned={})
        self.assertEqual(report["status"], "unknown")
        self.assertIn("no pinned version", report["detail"])


class TzReportTest(unittest.TestCase):
    def test_unset_zone(self):
        report = tz_report(_desktop_fp(tz_zone=None))
        self.assertEqual(report["status"], "unset")
        self.assertIsNone(report["zone"])
        self.assertIsNone(report["tz_offset"])

    def test_valid_zone_computes_offset(self):
        at = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
        report = tz_report(_desktop_fp(tz_zone="Europe/Berlin"), at=at)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["tz_offset"], 3600)  # CET, winter

    def test_valid_zone_dst(self):
        at = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)
        report = tz_report(_desktop_fp(tz_zone="Europe/Berlin"), at=at)
        self.assertEqual(report["tz_offset"], 7200)  # CEST, summer

    def test_unresolvable_zone(self):
        report = tz_report(_desktop_fp(tz_zone="Not/AZone"))
        self.assertEqual(report["status"], "unresolvable")
        self.assertIsNone(report["tz_offset"])
        self.assertIn("could not be computed", report["detail"])


class AuditFingerprintTest(unittest.TestCase):
    def test_healthy_fingerprint_has_no_problems(self):
        report = audit_fingerprint(_desktop_fp())
        self.assertTrue(report["ok"])
        self.assertEqual(report["problems"], [])
        self.assertEqual(
            report["checks"],
            {"coherence": "ok", "tz": "unset", "staleness": "current"},
        )

    def test_incoherent_api_hash_is_a_problem(self):
        report = audit_fingerprint(_desktop_fp(api_hash="not-a-hash"))
        self.assertFalse(report["ok"])
        self.assertTrue(
            any("api_hash" in p for p in report["problems"]),
            report["problems"],
        )
        self.assertEqual(report["checks"]["coherence"], "problems")

    def test_bad_zone_flags_both_coherence_and_tz(self):
        report = audit_fingerprint(_desktop_fp(tz_zone="Mars/Olympus"))
        self.assertFalse(report["ok"])
        joined = "\n".join(report["problems"])
        self.assertIn("Mars/Olympus", joined)
        self.assertIn("coherence:", joined)
        self.assertIn("tz:", joined)
        self.assertEqual(report["checks"]["tz"], "unresolvable")

    def test_unknown_release_is_a_problem_outdated_is_not(self):
        unknown = audit_fingerprint(_desktop_fp(app_version="custom-build"))
        self.assertFalse(unknown["ok"])
        self.assertTrue(any("staleness:" in p for p in unknown["problems"]))

        # an older-but-real release is only a WARNING: layer-coherent
        # minting (tgmint.layers) intentionally claims those
        outdated = audit_fingerprint(_desktop_fp(app_version="6.7.8"))
        self.assertTrue(outdated["ok"], outdated["problems"])
        self.assertEqual(outdated["checks"]["staleness"], "outdated")
        self.assertEqual(len(outdated["warnings"]), 1)
        self.assertIn("staleness:", outdated["warnings"][0])

    def test_locale_coherence_flows_through(self):
        fp = _desktop_fp(lang_code="zz", system_lang_code="zz-ZZ")
        report = audit_fingerprint(fp)
        self.assertFalse(report["ok"])
        self.assertTrue(
            any("locale pair" in p for p in report["problems"]),
            report["problems"],
        )


if __name__ == "__main__":
    unittest.main()
