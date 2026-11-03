"""Offline tests for tgmint.versions and tgmint.sidecar — no real network.

The version resolver is exercised with the _fetch_* helpers and
urllib.request.urlopen patched, so every code path (cache hit, TTL
expiry, force refresh, offline, corrupt cache, fetcher failure) runs
without leaving the machine. One opt-in test at the bottom documents
live behavior; set TGMINT_NET_TESTS=1 to enable it.

The urlopen patches double as request-building proof: they assert the
exact URL opened, the non-default User-Agent and the forwarded timeout.
"""
from __future__ import annotations

import json
import os
import pathlib
import tempfile
import time
import unittest
import urllib.error
from unittest import mock

from tgmint import sidecar, versions


ALL_APPS = ("tdesktop", "android", "android_x", "ios", "macos")


def fake_urlopen(body: bytes):
    """A urllib.request.urlopen mock whose response reads back ``body``.

    urlopen is used as a context manager, so the body must come off the
    __enter__ result, not the call return value itself.
    """
    response = mock.MagicMock(name="http_response")
    response.read.return_value = body
    urlopen = mock.MagicMock(name="urlopen")
    urlopen.return_value.__enter__.return_value = response
    return urlopen


def http_error(status: int = 404) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://example/", status, "Nope", {}, None)


# ---------------------------------------------------------------------------
# versions
# ---------------------------------------------------------------------------

class VersionCacheTestCase(unittest.TestCase):
    """Every version test gets an empty cache in a temp dir — no test
    ever reads or writes the real user cache."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cache = pathlib.Path(tmp.name) / "versions.json"
        patcher = mock.patch.object(
            versions, "_cache_path", return_value=self.cache
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_cache(self, fetched_at=None, version_map=None):
        self.cache.write_text(
            json.dumps({"fetched_at": fetched_at or {}, "versions": version_map or {}}),
            encoding="utf-8",
        )


class TestPins(VersionCacheTestCase):
    def test_unknown_app_raises_key_error(self):
        with self.assertRaises(KeyError) as ctx:
            versions.current_version("nokia-3310", offline=True)
        self.assertIn("nokia-3310", str(ctx.exception))

    def test_pinned_covers_all_six_apps(self):
        self.assertEqual(set(versions.PINNED), set(ALL_APPS))
        for app, version in versions.PINNED.items():
            self.assertIsInstance(version, str, app)
            self.assertTrue(version, app)

    def test_sources_cover_every_app(self):
        # docs/audit surface: one URL per app
        self.assertEqual(set(versions.SOURCES), set(versions.PINNED))
        for app, url in versions.SOURCES.items():
            self.assertTrue(url.startswith("https://"), app)

    def test_ttl_is_one_day(self):
        self.assertEqual(versions.CACHE_TTL_SECONDS, 86400)


class TestCurrentVersion(VersionCacheTestCase):
    def test_fetch_result_returned_and_cached(self):
        with mock.patch.object(versions, "_fetch_td_desktop", return_value="9.9.9"):
            self.assertEqual(versions.current_version("tdesktop"), "9.9.9")
        # the lookup landed in the cache file, stamped with ~now
        data = json.loads(self.cache.read_text(encoding="utf-8"))
        self.assertEqual(data["versions"]["tdesktop"], "9.9.9")
        self.assertAlmostEqual(data["fetched_at"]["tdesktop"], time.time(), delta=60)

    def test_fresh_cache_short_circuits(self):
        self.write_cache(
            fetched_at={"tdesktop": time.time()},
            version_map={"tdesktop": "8.8.8"},
        )
        fetcher = mock.MagicMock(return_value="9.9.9")
        with mock.patch.object(versions, "_fetch_td_desktop", fetcher), \
                mock.patch("urllib.request.urlopen") as urlopen:
            self.assertEqual(versions.current_version("tdesktop"), "8.8.8")
        fetcher.assert_not_called()
        urlopen.assert_not_called()

    def test_failed_refetch_returns_stale_cache(self):
        # older than the TTL, so the fetcher IS consulted; it fails and
        # the stale cached value survives without ever touching the wire
        self.write_cache(
            fetched_at={"tdesktop": time.time() - 10 * versions.CACHE_TTL_SECONDS},
            version_map={"tdesktop": "8.8.8"},
        )
        fetcher = mock.MagicMock(return_value=None)
        with mock.patch.object(versions, "_fetch_td_desktop", fetcher), \
                mock.patch("urllib.request.urlopen") as urlopen:
            self.assertEqual(versions.current_version("tdesktop"), "8.8.8")
        fetcher.assert_called_once()
        urlopen.assert_not_called()

    def test_stale_cache_refetches(self):
        self.write_cache(
            fetched_at={"tdesktop": time.time() - versions.CACHE_TTL_SECONDS - 5},
            version_map={"tdesktop": "8.8.8"},
        )
        with mock.patch.object(versions, "_fetch_td_desktop", return_value="9.9.9"):
            self.assertEqual(versions.current_version("tdesktop"), "9.9.9")
        data = json.loads(self.cache.read_text(encoding="utf-8"))
        self.assertEqual(data["versions"]["tdesktop"], "9.9.9")

    def test_future_stamp_is_not_fresh_forever(self):
        # a garbage / future-dated fetched_at (corrupted file, poisoned
        # cache, huge clock skew) must NOT pin the entry as "fresh": the
        # resolver re-checks the network instead of trusting it blindly
        self.write_cache(
            fetched_at={"tdesktop": 1e18},
            version_map={"tdesktop": "0.0.1-POISON"},
        )
        fetcher = mock.MagicMock(return_value="9.9.9")
        with mock.patch.object(versions, "_fetch_td_desktop", fetcher):
            self.assertEqual(versions.current_version("tdesktop"), "9.9.9")
        fetcher.assert_called_once()

        # same for a negative stamp (fetched "before the epoch")
        self.write_cache(
            fetched_at={"tdesktop": -12345.0},
            version_map={"tdesktop": "0.0.1-POISON"},
        )
        with mock.patch.object(versions, "_fetch_td_desktop", return_value="9.9.9"):
            self.assertEqual(versions.current_version("tdesktop"), "9.9.9")

    def test_ttl_uses_fetched_at_not_mtime(self):
        # fresh fetched_at but ancient mtime -> cache hit, no refetch
        self.write_cache(
            fetched_at={"tdesktop": time.time()},
            version_map={"tdesktop": "8.8.8"},
        )
        old = time.time() - 10 * versions.CACHE_TTL_SECONDS
        os.utime(self.cache, (old, old))
        with mock.patch.object(versions, "_fetch_td_desktop", return_value="9.9.9"):
            self.assertEqual(versions.current_version("tdesktop"), "8.8.8")

        # ...and the converse: ancient fetched_at, future-bleeding mtime
        # (a hand-made file) -> still refetched
        self.write_cache(
            fetched_at={"tdesktop": time.time() - 10 * versions.CACHE_TTL_SECONDS},
            version_map={"tdesktop": "8.8.8"},
        )
        future = time.time() + 10 * versions.CACHE_TTL_SECONDS
        os.utime(self.cache, (future, future))
        with mock.patch.object(versions, "_fetch_td_desktop", return_value="9.9.9"):
            self.assertEqual(versions.current_version("tdesktop"), "9.9.9")

    def test_force_refresh_bypasses_fresh_cache(self):
        self.write_cache(
            fetched_at={"tdesktop": time.time()},
            version_map={"tdesktop": "8.8.8"},
        )
        fetcher = mock.MagicMock(return_value="9.9.9")
        with mock.patch.object(versions, "_fetch_td_desktop", fetcher):
            self.assertEqual(
                versions.current_version("tdesktop", force_refresh=True), "9.9.9"
            )
        fetcher.assert_called_once()

    def test_offline_never_opens_urlopen(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            # empty cache -> the pin
            self.assertEqual(
                versions.current_version("tdesktop", offline=True),
                versions.PINNED["tdesktop"],
            )
            # stale cache -> the stale value, still with zero network
            self.write_cache(
                fetched_at={"tdesktop": time.time() - 10 * versions.CACHE_TTL_SECONDS},
                version_map={"tdesktop": "1.2.3"},
            )
            self.assertEqual(versions.current_version("tdesktop", offline=True), "1.2.3")
        urlopen.assert_not_called()

    def test_corrupt_cache_returns_pin_then_recovers(self):
        self.cache.write_text("{definitely not json", encoding="utf-8")
        with mock.patch.object(versions, "_fetch_td_desktop", return_value=None):
            self.assertEqual(
                versions.current_version("tdesktop"), versions.PINNED["tdesktop"]
            )
        # a later successful lookup overwrites the corrupt file wholesale
        with mock.patch.object(versions, "_fetch_td_desktop", return_value="9.9.9"):
            self.assertEqual(versions.current_version("tdesktop"), "9.9.9")
        data = json.loads(self.cache.read_text(encoding="utf-8"))
        self.assertEqual(data["versions"]["tdesktop"], "9.9.9")

    def test_every_fetcher_failure_ends_in_pinned(self):
        # both "returned None" and "blew up" — the resolver must not care
        for behavior in (lambda timeout: None, lambda timeout: (_ for _ in ()).throw(RuntimeError("boom"))):
            for app in ALL_APPS:
                name = versions.FETCHERS.get(app)
                patcher = (
                    mock.patch.object(versions, name, behavior)
                    if name else nullcontext()
                )
                with patcher:
                    self.assertEqual(
                        versions.current_version(app),
                        versions.PINNED[app],
                        f"{app} should fall back to its pin",
                    )

    def test_macos_without_a_working_fetcher_is_pin_only(self):
        # the documented reality: the pbxproj URL 404s today, so the
        # fetcher returns None and the pin answers
        with mock.patch.object(versions, "_fetch_macos", return_value=None):
            self.assertEqual(versions.current_version("macos"), versions.PINNED["macos"])


class nullcontext:
    # contextlib.nullcontext is 3.7+; kept local to stay explicit about
    # the "app has no fetcher" branch
    def __enter__(self):
        return None

    def __exit__(self, *exc):
        return False


class TestFetchersOffline(unittest.TestCase):
    """Request building + payload parsing, proven against a patched
    urllib.request.urlopen — no real network anywhere."""

    def test_td_desktop_builds_github_request_and_parses_tag(self):
        urlopen = fake_urlopen(b'{"tag_name": "v11.3.1", "name": "11.3.1"}')
        with mock.patch("urllib.request.urlopen", urlopen):
            self.assertEqual(versions._fetch_td_desktop(1.5), "11.3.1")
        urlopen.assert_called_once()
        (request,), kwargs = urlopen.call_args
        self.assertEqual(request.full_url, versions.SOURCES["tdesktop"])
        # a real User-Agent: GitHub (and APKPure) 403 the python default
        agent = request.get_header("User-agent")
        self.assertIn("Mozilla", agent)
        self.assertNotIn("Python-urllib", agent)
        self.assertEqual(kwargs["timeout"], 1.5)

    def test_td_desktop_bad_payloads(self):
        for body in (b'{"message": "Not Found"}', b"[]", b"", b"<html>"):
            with mock.patch("urllib.request.urlopen", fake_urlopen(body)):
                self.assertIsNone(versions._fetch_td_desktop(0.1), body)

    def test_ios_lookup_parses_first_result(self):
        payload = json.dumps(
            {"resultCount": 1, "results": [{"version": "13.1.1", "trackId": 686449807}]}
        ).encode()
        urlopen = fake_urlopen(payload)
        with mock.patch("urllib.request.urlopen", urlopen):
            self.assertEqual(versions._fetch_ios(2.0), "13.1.1")
        self.assertEqual(urlopen.call_args[0][0].full_url, versions.SOURCES["ios"])

    def test_ios_empty_results(self):
        with mock.patch("urllib.request.urlopen", fake_urlopen(b'{"resultCount": 0, "results": []}')):
            self.assertIsNone(versions._fetch_ios(0.1))

    def test_macos_parses_marketing_version(self):
        pbxproj = b"""
			buildSettings = {
				INFOPLIST_KEY_UILaunchScreen_Generation = YES;
				MARKETING_VERSION = 11.14.1;
				PRODUCT_BUNDLE_IDENTIFIER = org.telegram.desktop;
			};
"""
        with mock.patch("urllib.request.urlopen", fake_urlopen(pbxproj)):
            self.assertEqual(versions._fetch_macos(2.0), "11.14.1")

    def test_macos_404_or_no_match_is_none(self):
        for body in (b"404: Not Found", b"PRODUCT_BUNDLE_IDENTIFIER = nope;"):
            with mock.patch("urllib.request.urlopen", fake_urlopen(body)):
                self.assertIsNone(versions._fetch_macos(0.1), body)
        with mock.patch("urllib.request.urlopen", side_effect=http_error(404)):
            self.assertIsNone(versions._fetch_macos(0.1))

    def test_android_parses_apkpure_blob(self):
        blob = (
            b'{"loadingThreshold":0,"useBtnLoading":false,'
            b'"packageName":"org.telegram.messenger","crawlerLanguage":"en-US",'
            b'"isCrawler":false,"hasTrendingTopic":false,'
            b'"versionName":"13.1.0","versionCode":72291,'
            b'"category":"COMMUNICATION","appType":1}'
        )
        urlopen = fake_urlopen(b"<html>" + blob + b"</html>")
        with mock.patch("urllib.request.urlopen", urlopen):
            # APKPure serves the ABI-split versionCode (72291); DrKLO's own
            # app_version prints 7229 — the pinned/verified wire string.
            self.assertEqual(versions._fetch_android(2.0), "13.1.0 (7229)")
        self.assertEqual(urlopen.call_args[0][0].full_url, versions.SOURCES["android"])

    def test_android_x_strips_abi_split(self):
        # Telegram X ships ABI-qualified names: version 0.29.1, base code
        # 1817 riding in the 4th component, split code 1817302
        blob = (
            b'{"packageName":"org.thunderdog.challegram","crawlerLanguage":"en-US",'
            b'"versionName":"0.29.1.1817-arm64-v8a","versionCode":1817302,'
            b'"category":"SOCIAL","appType":1}'
        )
        urlopen = fake_urlopen(blob)
        with mock.patch("urllib.request.urlopen", urlopen):
            self.assertEqual(versions._fetch_android_x(2.0), "0.29.1 (1817)")
        self.assertEqual(urlopen.call_args[0][0].full_url, versions.SOURCES["android_x"])

    def test_android_any_failure_is_none(self):
        # fragile by design: anti-bot pages, layout changes, junk values
        cases = (
            b"<html>please verify you are human</html>",
            b'{"packageName":"org.telegram.messenger","versionName":"Varies with device","versionCode":1}',
            b"",
        )
        for body in cases:
            with mock.patch("urllib.request.urlopen", fake_urlopen(body)):
                self.assertIsNone(versions._fetch_android(0.1), body)
        with mock.patch("urllib.request.urlopen", side_effect=http_error(403)):
            self.assertIsNone(versions._fetch_android(0.1))
        with mock.patch("urllib.request.urlopen", side_effect=OSError("no route")):
            self.assertIsNone(versions._fetch_android_x(0.1))

    def test_cache_path_honors_xdg(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": tmp}):
                self.assertEqual(
                    versions._cache_path(),
                    pathlib.Path(tmp) / "tgmint" / "versions.json",
                )

    def test_cache_path_falls_back_to_tempdir_when_unwritable(self):
        if os.geteuid() == 0:  # permission bits don't bind root
            self.skipTest("running as root — permission bits not enforced")
        with tempfile.TemporaryDirectory() as tmp:
            locked = pathlib.Path(tmp) / "locked"
            locked.mkdir()
            locked.chmod(0o500)
            try:
                with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": str(locked)}):
                    self.assertEqual(
                        versions._cache_path(),
                        pathlib.Path(tempfile.gettempdir()) / "tgmint-versions.json",
                    )
            finally:
                locked.chmod(0o700)

    def test_load_cache_tolerates_garbage(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "versions.json"
            self.assertEqual(versions._load_cache(path), {})  # missing
            path.write_text("{corrupt", encoding="utf-8")
            self.assertEqual(versions._load_cache(path), {})  # corrupt
            path.write_text('["a list"]', encoding="utf-8")
            self.assertEqual(versions._load_cache(path), {})  # wrong shape

    def test_save_cache_failure_is_silent(self):
        # a read-only cache location must not raise out of the resolver
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "sub" / "versions.json"
            target.parent.mkdir()
            target.parent.chmod(0o500)
            try:
                versions._save_cache({"versions": {"ios": "1.0"}}, target)  # no raise
            finally:
                target.parent.chmod(0o700)


# ---------------------------------------------------------------------------
# APKPure normalization (ABI-split versionCode -> the printed app_version code)
# ---------------------------------------------------------------------------

class TestAndroidVersionNormalization(unittest.TestCase):
    def test_split_code_is_truncated_to_the_printed_code(self):
        # 72291 is the ABI-split APK versionCode; the app prints 7229
        # (DrKLO TLRPC.java at the 13.1.0 commit) — this is the exact value
        # layers.ANDROID_LAYERS[232] and versions.PINNED["android"] carry.
        self.assertEqual(
            versions._android_version_from("13.1.0", 72291), "13.1.0 (7229)"
        )
        self.assertEqual(
            versions._android_version_from("12.3.0", 63771), "12.3.0 (6377)"
        )

    def test_plain_code_is_kept(self):
        self.assertEqual(
            versions._android_version_from("13.1.0", 7229), "13.1.0 (7229)"
        )

    def test_zero_code_is_not_treated_as_absent(self):
        # 0 is a real reported value: it must not be mistaken for "the page
        # exposed no versionCode at all" (that case is None)
        self.assertEqual(versions._android_version_from("13.1.0", 0), "13.1.0 (0)")
        self.assertEqual(versions._android_version_from("13.1.0", None), "13.1.0")

    def test_fourth_component_wins_over_code_field(self):
        self.assertEqual(
            versions._android_version_from("0.29.1.1817-arm64-v8a", 1817302),
            "0.29.1 (1817)",
        )

    def test_junk_names_still_none(self):
        self.assertIsNone(versions._android_version_from("Varies with device", 1))
        self.assertIsNone(versions._android_version_from("", 1))


# ---------------------------------------------------------------------------
# sidecar
# ---------------------------------------------------------------------------

class TestSidecar(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = pathlib.Path(tmp.name)

    def test_save_load_roundtrip(self):
        data = {
            "api_id": 2040,
            "api_hash": "b18441a1ff607e10a989891a5462e627",
            "device_model": "Desktop",
            "app_version": "7.2.8",
        }
        path = sidecar.save_sidecar(self.dir / "acc.fingerprint.json", data)
        self.assertEqual(path, self.dir / "acc.fingerprint.json")
        self.assertIsInstance(path, pathlib.Path)
        loaded = sidecar.load_sidecar(path)
        self.assertEqual(loaded, dict(data, schema_version=sidecar.SCHEMA_VERSION))
        # the caller's dict is stamped on a copy, never mutated
        self.assertNotIn("schema_version", data)

    def test_schema_version_is_always_overwritten(self):
        path = sidecar.save_sidecar(
            self.dir / "s.json", {"schema_version": 99, "api_id": 6}
        )
        loaded = sidecar.load_sidecar(path)
        self.assertEqual(loaded["schema_version"], sidecar.SCHEMA_VERSION)
        self.assertEqual(loaded["api_id"], 6)

    def test_save_creates_parent_dirs(self):
        path = self.dir / "accounts" / "2026" / "acc.fingerprint.json"
        sidecar.save_sidecar(path, {"api_id": 6})
        self.assertTrue(path.is_file())

    def test_save_is_mode_0600_even_overwriting_0644(self):
        path = self.dir / "acc.fingerprint.json"
        path.write_text('{"schema_version": 1, "old": true}', encoding="utf-8")
        path.chmod(0o644)
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)  # precondition
        sidecar.save_sidecar(path, {"api_id": 6})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(sidecar.load_sidecar(path)["api_id"], 6)  # content swapped

    def test_repeated_saves_stay_0600(self):
        path = self.dir / "acc.fingerprint.json"
        for version in ("7.2.8", "7.3.3", "7.4.0"):
            sidecar.save_sidecar(path, {"app_version": version})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(sidecar.load_sidecar(path)["app_version"], "7.4.0")

    def test_load_missing_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            sidecar.load_sidecar(self.dir / "nope.fingerprint.json")

    def test_load_wrong_schema_version_raises_value_error(self):
        path = self.dir / "s.json"
        path.write_text(json.dumps({"schema_version": 99}), encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            sidecar.load_sidecar(path)
        message = str(ctx.exception)
        self.assertIn(str(path), message)
        self.assertIn("99", message)
        self.assertIn(str(sidecar.SCHEMA_VERSION), message)

    def test_load_missing_schema_version_raises_value_error(self):
        path = self.dir / "s.json"
        path.write_text(json.dumps({"api_id": 6}), encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            sidecar.load_sidecar(path)
        self.assertIn(str(path), str(ctx.exception))

    def test_load_corrupt_json_raises_value_error(self):
        path = self.dir / "s.json"
        path.write_text("{corrupt", encoding="utf-8")
        with self.assertRaises(ValueError):
            sidecar.load_sidecar(path)

    def test_sidecar_path_for(self):
        cases = (
            ("acc.session", "acc.fingerprint.json"),
            ("x/y.session.sqlite", "x/y.fingerprint.json"),
            ("/p/dir/tdata", "/p/dir/tdata.fingerprint.json"),  # tdata DIR: sibling
            ("convert/me.tdata", "convert/me.fingerprint.json"),
            ("noext", "noext.fingerprint.json"),
        )
        for session, expected in cases:
            self.assertEqual(
                sidecar.sidecar_path_for(session), pathlib.Path(expected), session
            )

    def test_sidecar_path_for_accepts_pathlib(self):
        self.assertEqual(
            sidecar.sidecar_path_for(pathlib.Path("/a/b.session")),
            pathlib.Path("/a/b.fingerprint.json"),
        )

    def test_sidecar_path_roundtrips_with_save(self):
        session = self.dir / "acc.session"
        sidecar.save_sidecar(sidecar.sidecar_path_for(session), {"api_id": 6})
        loaded = sidecar.load_sidecar(sidecar.sidecar_path_for(session))
        self.assertEqual(loaded["api_id"], 6)


# ---------------------------------------------------------------------------
# opt-in live network (documents real behavior; off in CI)
# ---------------------------------------------------------------------------

@unittest.skipUnless(
    os.environ.get("TGMINT_NET_TESTS"),
    "set TGMINT_NET_TESTS=1 to enable live-network checks",
)
class TestLiveNetwork(unittest.TestCase):
    def test_tdesktop_live_resolves_non_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = pathlib.Path(tmp) / "versions.json"
            with mock.patch.object(versions, "_cache_path", return_value=cache):
                version = versions.current_version("tdesktop", timeout=10.0)
        self.assertIsInstance(version, str)
        self.assertTrue(version)


if __name__ == "__main__":
    unittest.main()
