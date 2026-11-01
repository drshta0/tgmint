"""Offline tests for the keepalive cadence (`tgmint.cadence`).

What is pinned here, and why:

* **the numbers and where they come from** — 19 s / 35 s for Android and
  30 s / 60 s for Desktop are read out of the official trees, so the test
  asserts the values *and* the `file:line` that justifies each one.  The
  framework defaults are asserted against the installed packages whenever
  they are importable, so a framework bump that changes its own default fails
  here instead of quietly turning the table into a lie.
* **`apply` writes only what is safe** — against a real `TelegramClient`
  (instance shadowing: the class method stays at 60 s, `restore()` puts the
  client back) and against fake Pyrogram-family clients (`PING_INTERVAL`
  becomes an instance attribute, `Session.PING_INTERVAL` and `WAIT_TIMEOUT`
  are untouched).
* **the copied Telethon loop actually runs** — driven for a few ticks with a
  fake client and a 20 ms interval, asserting it pings, cleans exported
  senders and saves states, and that cancelling it stops it.
* **dry_run mutates nothing, and refusals are refusals** — unknown platform,
  a client family tgmint does not drive, a Telethon whose keepalive loop does
  not look like the one tgmint knows, and a Pyrogram client with no Session
  object yet all raise `CadenceError` (or report `unsupported`) instead of
  guessing.

No test in this file opens a socket: the "real" client is
`TelegramClient(MemorySession(), ...)`, which constructs offline, and the
Pyrogram-family clients are fakes carrying the attributes the module reads.
"""

import asyncio
import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError

import tgmint.cadence as cadence
from tgmint import cli
from tgmint.api import API
from tgmint.cadence import (
    FRAMEWORKS,
    PING_CADENCE,
    PLATFORMS,
    PYROGRAM_DISCONNECT_DELAY,
    PYROGRAM_PING_INTERVAL,
    PYROGRAM_REQUEST_TIMEOUT,
    TELETHON_PING_INTERVAL,
    CadenceError,
    PingCadence,
    apply,
    describe,
    restore,
    target,
)

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:  # the extra this whole package is tested against
    from telethon import TelegramClient
    from telethon.sessions import MemorySession

    HAVE_TELETHON = True
except Exception:  # pragma: no cover - telethon missing
    HAVE_TELETHON = False

try:  # kurigram, vendored in .pytestbox for the suite
    from pyrogram.session import Session as PyrogramSession

    HAVE_PYROGRAM = True
except Exception:  # pragma: no cover - familia absent
    HAVE_PYROGRAM = False


def run_cli(argv):
    """Run cli.main with captured streams -> (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def memory_client():
    """A real Telethon client that never connects (`in_memory` equivalent).

    Built with keywords on purpose: importing `tgmint.tl` swaps
    `telethon.TelegramClient.__init__` for tgmint's APIData-aware override
    (the "scoped client override" the package documents), which has a
    different positional order. Keyword arguments mean the same client
    whether or not another test module already imported it.
    """
    return TelegramClient(
        session=MemorySession(),
        api_id=12345,
        api_hash="0123456789abcdef0123456789abcdef",
    )


class FakeProtocol:
    async def _recv_from_socket(self, length):
        return b""


class FakeConnection:
    def __init__(self):
        self.protocol = FakeProtocol()

    async def connect(self):
        return None


class FakePyrogramSession:
    """The slice of ``pyrogram.session.Session`` the cadence code touches."""

    PING_INTERVAL = 5
    WAIT_TIMEOUT = 15

    def __init__(self):
        self.connection = FakeConnection()

    def ping_worker(self):  # presence is how the module recognises a Session
        raise AssertionError("ping_worker must never be called by the tests")

    async def send(self, data, *args, **kwargs):  # wrapped by apply()
        return data

    async def start(self):  # kept for API shape; not wrapped any more
        return None


class FakePyrogramClient:
    """A kurigram-shaped client: main-DC session plus a second DC."""

    def __init__(self, *, connected=True, extra_dc=True):
        self._session = FakePyrogramSession() if connected else None
        self.session = self._session
        self.sessions = {2: FakePyrogramSession()} if extra_dc else {}
        self.media_sessions = {}
        self.proxy = None
        self.connection_factory = FakeConnection


class FakeTelethonClient:
    """A Telethon-shaped client whose loop tgmint must *refuse* to replace."""

    def __init__(self):
        self._running = True

    def is_connected(self):
        return self._running

    async def _keepalive_loop(self):  # no marker strings: unrecognisable
        return None


# ---------------------------------------------------------------------------
# the data
# ---------------------------------------------------------------------------


class CadenceData(unittest.TestCase):
    def test_platforms_are_the_verified_ones(self):
        self.assertEqual(PLATFORMS, ("android", "desktop"))
        self.assertEqual(set(PING_CADENCE), set(PLATFORMS))

    def test_android_numbers_and_their_source(self):
        android = target("android")
        self.assertEqual(android.ping_interval, 19.0)
        self.assertEqual(android.disconnect_delay, 35)
        # the 19000 ms guard and the disconnect_delay assignment, same file
        self.assertIn("ConnectionsManager.cpp:295,1786", android.source)
        self.assertIn("12.10.6", android.source)

    def test_desktop_numbers_and_their_source(self):
        desktop = target("desktop")
        self.assertEqual(desktop.ping_interval, 30.0)
        self.assertEqual(desktop.disconnect_delay, 60)
        self.assertIn("session_private.cpp:40-42", desktop.source)
        self.assertIn("7.3.3", desktop.source)

    def test_client_versions_come_from_the_bootstrap_table(self):
        from tgmint.bootstrap import CLIENT_VERSIONS

        self.assertIs(cadence.CLIENT_VERSIONS, CLIENT_VERSIONS)
        self.assertEqual(describe("android")["client_version"], "12.10.6")
        self.assertEqual(describe("desktop")["client_version"], "7.3.3")

    def test_cadence_is_frozen(self):
        android = target("android")
        with self.assertRaises(FrozenInstanceError):
            android.ping_interval = 1.0
        self.assertEqual(android.ping_interval, 19.0)

    def test_aliases_resolve_to_the_same_object(self):
        for alias in ("android", "android_x", "androidx", " ANDROID "):
            self.assertIs(target(alias), target("android"))
        for alias in ("desktop", "tdesktop", "Desktop"):
            self.assertIs(target(alias), target("desktop"))
        self.assertIsInstance(target("android"), PingCadence)

    def test_aliases_agree_with_bootstrap_platform_for(self):
        from tgmint.bootstrap import platform_for

        for alias in ("android", "android_x", "tdesktop"):
            self.assertEqual(target(alias).ping_interval, target(platform_for(alias)).ping_interval)

    def test_unknown_platform_is_named(self):
        with self.assertRaises(CadenceError) as caught:
            target("symbian")
        self.assertIn("unknown platform", str(caught.exception))
        self.assertIn("android", str(caught.exception))

    def test_unverified_families_say_why(self):
        for platform in ("ios", "macos", "web"):
            with self.assertRaises(CadenceError) as caught:
                target(platform)
            self.assertIn("no verified cadence", str(caught.exception))
        with self.assertRaises(CadenceError):
            target(42)  # type: ignore[arg-type]

    def test_framework_defaults_match_the_installed_packages(self):
        """A framework bump that changes its own default fails here."""
        if not HAVE_PYROGRAM:  # pragma: no cover - env gate
            self.skipTest("pyrogram (kurigram) is not importable")
        self.assertEqual(PYROGRAM_PING_INTERVAL, PyrogramSession.PING_INTERVAL)
        self.assertEqual(PYROGRAM_REQUEST_TIMEOUT, PyrogramSession.WAIT_TIMEOUT)
        self.assertEqual(
            PYROGRAM_DISCONNECT_DELAY, PyrogramSession.WAIT_TIMEOUT + 10
        )

    def test_pyrogram_source_really_derives_the_delay(self):
        path = os.path.join(_ROOT, ".pytestbox", "pyrogram", "session", "session.py")
        if not os.path.exists(path):  # pragma: no cover - env gate
            self.skipTest("vendored kurigram checkout is absent")
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("PING_INTERVAL = 5", source)
        self.assertIn("WAIT_TIMEOUT = 15", source)
        self.assertIn("disconnect_delay=self.WAIT_TIMEOUT + 10", source)

    @unittest.skipUnless(HAVE_TELETHON, "telethon is not installed")
    def test_telethon_source_really_hardcodes_sixty(self):
        """The 60 s the module reports is the installed library's literal."""
        original = TelegramClient._keepalive_loop
        self.assertEqual(cadence._telethon_loop_interval(original), TELETHON_PING_INTERVAL)
        # and the delay is genuinely absent: telethon sends a plain PING
        import inspect

        source = inspect.getsource(original)
        self.assertNotIn("PingDelayDisconnect", source)


# ---------------------------------------------------------------------------
# describe
# ---------------------------------------------------------------------------


class DescribeTests(unittest.TestCase):
    def test_shape_and_official_block(self):
        report = describe("android")
        self.assertEqual(report["platform"], "android")
        self.assertEqual(
            report["official"],
            {
                "ping_interval": 19.0,
                "disconnect_delay": 35,
                "source": PING_CADENCE["android"].source,
            },
        )
        self.assertEqual(set(report["frameworks"]), set(FRAMEWORKS))
        for knobs in report["frameworks"].values():
            self.assertEqual(set(knobs), {"ping_interval", "disconnect_delay"})

    def test_what_is_settable_per_framework(self):
        frameworks = describe("desktop")["frameworks"]
        for name in FRAMEWORKS:
            self.assertTrue(frameworks[name]["ping_interval"]["settable"], name)
        self.assertFalse(
            frameworks["telethon"]["disconnect_delay"]["settable"],
            "Telethon never sends ping_delay_disconnect",
        )
        self.assertTrue(
            frameworks["pyrogram"]["disconnect_delay"]["settable"],
            "the delay is set by rewriting the outgoing PingDelayDisconnect",
        )
        self.assertEqual(
            frameworks["telethon"]["ping_interval"]["framework_default"], 60.0
        )
        self.assertIsNone(
            frameworks["telethon"]["disconnect_delay"]["framework_default"]
        )
        self.assertEqual(
            frameworks["pyrogram"]["ping_interval"]["framework_default"], 5.0
        )
        self.assertEqual(
            frameworks["pyrogram"]["disconnect_delay"]["framework_default"], 25.0
        )
        # the "why" is not empty for either refused knob
        self.assertIn(
            "PING", frameworks["telethon"]["disconnect_delay"]["reason"]
        )
        self.assertIn(
            "WAIT_TIMEOUT", frameworks["pyrogram"]["disconnect_delay"]["reason"]
        )

    def test_pyrogram_plan_includes_the_socket_read_timeout(self):
        # root cause (2026-11-01): the framework's own 10 s transport read
        # timeout, not the server, used to close the connection before the
        # official 19 s ping; the plan carries the patient replacement
        frameworks = describe("android")["frameworks"]
        pyrogram = frameworks["pyrogram"]["ping_interval"]
        self.assertEqual(pyrogram["applied_value"], 19.0)
        self.assertEqual(pyrogram["socket_read_timeout"], 45.0)
        self.assertEqual(
            frameworks["pyrogram"]["disconnect_delay"]["applied_value"], 35.0
        )
        telethon = frameworks["telethon"]["ping_interval"]
        self.assertNotIn("socket_read_timeout", telethon)

    def test_describe_is_json_serialisable_and_alias_insensitive(self):
        self.assertEqual(json.loads(json.dumps(describe("android_x"))), describe("android"))

    def test_describe_touches_no_client_and_no_framework(self):
        script = r'''
import json, sys
BLOCKED = ("telethon", "pyrogram")
class _Blocker:
    def find_spec(self, name, path=None, target=None):
        for blocked in BLOCKED:
            if name == blocked or name.startswith(blocked + "."):
                raise ImportError("blocked in test: " + name)
        return None
sys.meta_path.insert(0, _Blocker())
import tgmint.cadence as c
report = c.describe("android")
assert report["official"]["ping_interval"] == 19.0
assert c.target("tdesktop").disconnect_delay == 60
print(json.dumps({"ok": True, "modules": sorted(m for m in sys.modules
      if m.split(".")[0] in BLOCKED)}))
'''
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            env=dict(os.environ, PYTHONPATH=_SRC),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["modules"], [])

    def test_no_top_level_framework_import(self):
        import ast

        path = os.path.join(_SRC, "tgmint", "cadence.py")
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        for node in tree.body:  # module level only
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn(alias.name, ("telethon", "pyrogram"))
            elif isinstance(node, ast.ImportFrom):
                self.assertNotIn(node.module or "", ("telethon", "pyrogram"))


# ---------------------------------------------------------------------------
# telethon
# ---------------------------------------------------------------------------


@unittest.skipUnless(HAVE_TELETHON, "telethon is not installed")
class TelethonApply(unittest.TestCase):
    def test_ping_interval_is_set_on_the_instance_only(self):
        client = memory_client()
        report = apply(client, "android")

        self.assertEqual(report["framework"], "telethon")
        self.assertEqual(report["platform"], "android")
        self.assertFalse(report["dry_run"])
        applied = report["applied"]["ping_interval"]
        self.assertEqual(applied["value"], 19.0)
        self.assertEqual(applied["was"], 60.0)
        self.assertIn("next connect()", applied["takes_effect"])

        # the instance shadows the loop; the class keeps 60
        self.assertIn("_keepalive_loop", vars(client))
        self.assertEqual(
            cadence._telethon_loop_interval(TelegramClient._keepalive_loop), 60.0
        )
        # and the class still hands out the same function to a new client
        other = memory_client()
        self.assertNotIn("_keepalive_loop", vars(other))

    def test_restore_puts_the_framework_loop_back(self):
        client = memory_client()
        apply(client, "desktop")
        self.assertTrue(restore(client)["restored"])
        self.assertNotIn("_keepalive_loop", vars(client))
        self.assertNotIn(cadence._MARK, vars(client))
        self.assertFalse(restore(client)["restored"])  # idempotent, not an error

    def test_second_apply_does_not_launder_the_patch_as_the_callers_own(self):
        client = memory_client()
        apply(client, "android")
        apply(client, "desktop")
        self.assertEqual(vars(client)[cadence._MARK]["ping_interval"], 30.0)
        self.assertFalse(vars(client)[cadence._MARK]["had_own"])
        restore(client)
        self.assertNotIn("_keepalive_loop", vars(client))

    def test_dry_run_mutates_nothing(self):
        client = memory_client()
        before = dict(vars(client))
        report = apply(client, "android", dry_run=True)
        self.assertTrue(report["dry_run"])
        self.assertEqual(report["applied"]["ping_interval"]["value"], 19.0)
        self.assertEqual(report["applied"]["ping_interval"]["was"], 60.0)
        self.assertEqual(dict(vars(client)), before)
        self.assertNotIn("_keepalive_loop", vars(client))

    def test_disconnect_delay_is_reported_as_unsupported(self):
        report = apply(memory_client(), "android")
        refused = report["unsupported"]["disconnect_delay"]
        self.assertEqual(refused["official"], 35)
        self.assertIn("ping_delay_disconnect", refused["reason"])
        self.assertIn("mtprotosender.py", refused["source"])

    def test_an_unrecognised_keepalive_loop_is_refused(self):
        client = FakeTelethonClient()
        report = apply(client, "android")
        self.assertEqual(report["framework"], "telethon")
        self.assertEqual(report["applied"], {})
        self.assertIn("not the one tgmint knows", report["unsupported"]["ping_interval"]["reason"])
        self.assertNotIn("_keepalive_loop", vars(client))

    def test_a_live_connection_is_told_that_it_takes_a_reconnect(self):
        client = memory_client()
        client.is_connected = lambda: True  # type: ignore[assignment]
        report = apply(client, "android")
        self.assertIn("next connection", report["applied"]["ping_interval"]["takes_effect"])
        self.assertIn("reconnect", report["applied"]["ping_interval"]["takes_effect"])
        self.assertTrue(any("already running" in note for note in report["notes"]))


class TelethonLoopCopy(unittest.TestCase):
    """The replaced loop must keep doing what the original loop did."""

    class _Sender:
        def __init__(self):
            self.pings = 0

        def _transport_connected(self):
            return True

        def _keepalive_ping(self, rnd):  # noqa: D401 - telethon's name
            self.pings += 1

    class _Storage:
        def __init__(self):
            self.saves = 0

        def save(self):
            self.saves += 1

    class _Client:
        """Fake client shaped like Telethon's own keepalive contract."""

        def __init__(self, loop):
            self._sender = TelethonLoopCopy._Sender()
            self.session = TelethonLoopCopy._Storage()
            self.cleanups = 0
            self.handles = []
            self._running = True
            self._inner = loop.create_future()

        @property
        def disconnected(self):  # telethon: asyncio.shield(self._disconnected)
            return asyncio.shield(self._inner)

        def is_connected(self):
            return self._running

        async def _clean_exported_senders(self):
            self.cleanups += 1

        async def _save_states_and_entities(self):
            self.handles.append("saved")

        async def _keepalive_loop(self):  # the class method being replaced
            return None

    async def _drive(self, interval, seconds):
        loop = asyncio.get_running_loop()
        client = self._Client(loop)
        task = loop.create_task(cadence._make_telethon_loop(client, interval)())
        await asyncio.sleep(seconds)
        client._running = False
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        return client

    def test_the_loop_pings_and_flushes_on_every_tick(self):
        client = asyncio.run(self._drive(interval=0.01, seconds=0.06))
        self.assertGreaterEqual(client._sender.pings, 3)
        self.assertEqual(client._sender.pings, client.cleanups)
        self.assertEqual(len(client.handles), client._sender.pings)
        self.assertEqual(client.session.saves, client._sender.pings)
        # cancelling stopped it: nothing pings after the loop ends
        pings = client._sender.pings
        asyncio.run(asyncio.sleep(0.03))
        self.assertEqual(client._sender.pings, pings)

    def test_the_copied_loop_is_not_the_class_method(self):
        client = memory_client()
        apply(client, "android")
        self.assertIsNot(client._keepalive_loop, TelegramClient._keepalive_loop)
        self.assertTrue(asyncio.iscoroutinefunction(client._keepalive_loop))


# ---------------------------------------------------------------------------
# pyrogram family
# ---------------------------------------------------------------------------


class PyrogramApply(unittest.TestCase):
    def test_ping_interval_becomes_an_instance_attribute(self):
        client = FakePyrogramClient()
        main = client.session
        report = apply(client, "desktop")

        self.assertEqual(report["framework"], "pyrogram")
        applied = report["applied"]["ping_interval"]
        self.assertEqual(applied["value"], 30.0)
        self.assertEqual(applied["requested"], 30.0)
        self.assertNotIn("capped_to", applied)
        self.assertEqual(applied["was"], 5)
        self.assertIn("instance attribute", applied["scope"])
        self.assertIn("PING_INTERVAL", vars(client.session))
        self.assertEqual(main.PING_INTERVAL, 30.0)
        # the class default and the request-timeout knob are untouched
        self.assertEqual(FakePyrogramSession.PING_INTERVAL, 5)
        self.assertEqual(main.WAIT_TIMEOUT, 15)
        self.assertEqual(client.sessions[2].PING_INTERVAL, 30.0)
        # the patient read timeout and the official disconnect delay ride along
        self.assertEqual(report["applied"]["socket_read_timeout"]["value"], 67.0)
        self.assertEqual(report["applied"]["disconnect_delay"]["value"], 60.0)
        self.assertIn("send", vars(client.session))
        self.assertIsNot(client.connection_factory, FakeConnection)
        # a connection created later (a restart) is patched before its first read
        future = client.connection_factory()
        self.assertIn("connect", vars(future))
        import asyncio as _asyncio
        _asyncio.run(future.connect())
        self.assertIn("_recv_from_socket", vars(future.protocol))

    def test_disconnect_delay_is_rewritten_on_the_wire(self):
        # the worker hardcodes WAIT_TIMEOUT + 10 = 25; apply() must rewrite it
        # to the official 35 without touching WAIT_TIMEOUT itself
        report = apply(FakePyrogramClient(), "android")
        applied = report["applied"]["disconnect_delay"]
        self.assertEqual(applied["value"], 35.0)
        self.assertEqual(applied["was"], 25.0)
        self.assertIn("WAIT_TIMEOUT", applied["scope"] + applied["attribute"])
        self.assertNotIn("disconnect_delay", report["unsupported"])
        self.assertEqual(FakePyrogramClient().session.WAIT_TIMEOUT, 15)

    def test_notes_warn_about_later_sessions_and_the_class(self):
        report = apply(FakePyrogramClient(), "android")
        joined = " ".join(report["notes"])
        self.assertIn("patched 2 Session objects", joined)
        self.assertIn("created later", joined)
        self.assertIn("class was not touched", joined)
        self.assertNotIn("capped", joined)

    def test_restore_puts_the_framework_value_back(self):
        client = FakePyrogramClient()
        apply(client, "android")
        self.assertEqual(client.session.PING_INTERVAL, 19.0)
        self.assertTrue(restore(client)["restored"])
        self.assertEqual(client.session.PING_INTERVAL, 5)
        self.assertEqual(client.sessions[2].PING_INTERVAL, 5)
        self.assertIs(client.connection_factory, FakeConnection)
        self.assertNotIn("send", vars(client.session))
        self.assertNotIn(cadence._MARK, vars(client))

    def test_a_second_apply_keeps_the_framework_value_for_restore(self):
        client = FakePyrogramClient()
        apply(client, "android")
        report = apply(client, "desktop")
        self.assertEqual(report["applied"]["ping_interval"]["was"], 5)
        self.assertEqual(client.session.PING_INTERVAL, 30.0)
        restore(client)
        self.assertEqual(client.session.PING_INTERVAL, 5)

    def test_a_session_passed_directly_is_still_a_client(self):
        session = FakePyrogramSession()
        report = apply(session, "android")
        self.assertEqual(report["framework"], "pyrogram")
        self.assertEqual(session.PING_INTERVAL, 19.0)
        self.assertTrue(restore(session)["restored"])
        self.assertEqual(session.PING_INTERVAL, 5)

    def test_dry_run_reports_without_mutating(self):
        client = FakePyrogramClient()
        report = apply(client, "android", dry_run=True)
        self.assertEqual(report["applied"]["ping_interval"]["value"], 19.0)
        self.assertEqual(report["applied"]["ping_interval"]["was"], 5)
        self.assertEqual(client.session.PING_INTERVAL, 5)
        self.assertNotIn("PING_INTERVAL", vars(client.session))
        self.assertNotIn(cadence._MARK, vars(client))

    def test_a_session_without_a_ping_worker_is_not_a_session(self):
        class NotASession:
            PING_INTERVAL = 5

        client = FakePyrogramClient(connected=False, extra_dc=False)
        client.session = None
        client._session = NotASession()
        client.sessions = {}
        with self.assertRaises(CadenceError) as caught:
            apply(client, "android")
        self.assertIn("connect()", str(caught.exception))

    def test_not_connected_is_a_clear_error(self):
        client = FakePyrogramClient(connected=False, extra_dc=False)
        with self.assertRaises(CadenceError) as caught:
            apply(client, "android")
        message = str(caught.exception)
        self.assertIn("Session object", message)
        self.assertIn("connect()", message)

    @unittest.skipUnless(HAVE_PYROGRAM, "pyrogram (kurigram) is not importable")
    def test_the_real_session_class_keeps_its_defaults(self):
        self.assertEqual(PyrogramSession.PING_INTERVAL, PYROGRAM_PING_INTERVAL)
        self.assertEqual(PyrogramSession.WAIT_TIMEOUT, PYROGRAM_REQUEST_TIMEOUT)
        self.assertEqual(
            PyrogramSession.WAIT_TIMEOUT + 10, PYROGRAM_DISCONNECT_DELAY
        )


# ---------------------------------------------------------------------------
# platform resolution and refusals
# ---------------------------------------------------------------------------


class PlatformResolution(unittest.TestCase):
    def test_platform_is_derived_from_the_fingerprint(self):
        client = FakePyrogramClient()
        client.api = API.TelegramDesktop
        report = apply(client)
        self.assertEqual(report["platform"], "desktop")
        self.assertTrue(
            any("derived from the client's fingerprint" in note for note in report["notes"])
        )

    def test_explicit_platform_wins(self):
        client = FakePyrogramClient()
        client.api = API.TelegramDesktop
        self.assertEqual(apply(client, "android")["platform"], "android")

    def test_a_family_with_no_cadence_is_refused_through_the_fingerprint(self):
        client = FakePyrogramClient()
        client.api = API.TelegramIOS
        with self.assertRaises(CadenceError):
            apply(client)

    def test_no_fingerprint_asks_for_the_platform(self):
        with self.assertRaises(CadenceError) as caught:
            apply(FakePyrogramClient())
        self.assertIn("platform is required", str(caught.exception))

    def test_a_stranger_object_is_refused_by_name(self):
        with self.assertRaises(CadenceError) as caught:
            apply(object(), "android")
        self.assertIn("cannot detect the client family", str(caught.exception))

    def test_none_is_refused(self):
        with self.assertRaises(CadenceError):
            apply(None, "android")

    def test_bad_platform_is_refused_before_the_client_is_touched(self):
        client = FakePyrogramClient()
        with self.assertRaises(CadenceError):
            apply(client, "blackberry")
        self.assertNotIn(cadence._MARK, vars(client))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class CadenceCliTest(unittest.TestCase):
    def test_shows_both_presets_and_their_sources(self):
        code, out, err = run_cli(["cadence"])
        self.assertEqual(code, 0, err)
        self.assertIn("android", out)
        self.assertIn("desktop", out)
        self.assertIn("19s", out)
        self.assertIn("35s", out)
        self.assertIn("ConnectionsManager.cpp:295,1786", out)
        self.assertIn("session_private.cpp:40-42", out)
        self.assertIn("plan only", out)

    def test_one_preset_only(self):
        code, out, _ = run_cli(["cadence", "--preset", "desktop"])
        self.assertEqual(code, 0)
        self.assertIn("Telegram Desktop 7.3.3", out)
        self.assertNotIn("Telegram Android", out)

    def test_json_is_the_plan(self):
        code, out, _ = run_cli(["cadence", "--preset", "android", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["command"], "cadence")
        self.assertEqual(len(payload["presets"]), 1)
        preset = payload["presets"][0]
        self.assertEqual(preset["official"]["ping_interval"], 19.0)
        self.assertFalse(preset["frameworks"]["telethon"]["disconnect_delay"]["settable"])

    def test_the_cli_never_applies_anything(self):
        """No client, no session, no socket: the command is a pure plan."""
        code, out, _ = run_cli(["cadence", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(len(payload["presets"]), 2)
        self.assertNotIn("applied", payload)
        self.assertNotIn("_session", out)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
