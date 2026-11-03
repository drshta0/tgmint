"""Offline tests for the post-auth startup replay (`tgmint.bootstrap`).

What is pinned here, and why:

* **the order** — the shipped sequences are the source-read
  call sites turned into data.  The two order
  assertions that matter most are the ones the official source proves:
  Android's first *network* request is `help.getConfig` (the
  `setUserId` side effects that precede it are native, not requests), and
  Desktop's first two are `help.getConfig` then `updates.getState`
  (the `Main::Session` constructor fires getState before its own ctor
  body, which is why `invokeWithLayer(initConnection)` sits at spec row 2
  and is not replayed).
* **the allowlists** — a step may only send a vetted read-only method,
  cosmetic steps only ride along when asked for, and the forbidden names
  (`account.updateStatus`, `account.registerDevice`,
  `account.resetAuthorization`, `auth.*`) can never appear in a sequence.
  A sequence that escapes is refused at use time, not at review time.
* **the replay loop** — against a fake client: exact order, one failing
  request recorded while the replay continues, connection/auth failures
  re-raised, and a dry run that builds and calls nothing.
* **the module importability** — `import tgmint.bootstrap` must work with
  Telethon absent (same rule as `tgmint.codec`), so the request builder's
  Telethon import lives inside the function.

No test in this file opens a socket: the fake client's ``__call__``
records the request and returns ``None``, and the live path's client
factory (`bootstrap.make_client`) is never reached.
"""

import asyncio
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import tgmint.bootstrap as bootstrap
from tgmint import cli, codec
from tgmint.api import API
from tgmint.codec import SessionData
from tgmint.fingerprint import Fingerprint
from tgmint.sidecar import sidecar_path_for
from tgmint.bootstrap import (
    BOOTSTRAP_SEQUENCES,
    COSMETIC_METHODS,
    EXCLUDED_METHODS,
    FORBIDDEN_METHODS,
    PHASES,
    PLATFORMS,
    SAFE_METHODS,
    BootstrapError,
    Step,
    describe,
    is_forbidden,
    platform_for,
    replay_startup,
    sequence,
)

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")

#: methods the spec proves are state-mutating, auth-level or not startup
_MUST_NEVER_APPEAR = (
    "account.updateStatus",
    "account.registerDevice",
    "account.resetAuthorization",
    "auth.signIn",
    "updates.getDifference",
    "ping_delay_disconnect",
    "help.getNearestDc",
    "account.getAuthorizations",
)

_KEY = bytes(range(256))


def run_cli(argv):
    """Run cli.main with captured streams -> (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class FakeClient:
    """A Telethon-shaped client: records ``await client(request)``."""

    def __init__(self, fail_at=None, error=None, fatal_at=None, fatal=None):
        self.requests = []
        self.calls = 0
        self.fail_at = fail_at
        self.error = error
        self.fatal_at = fatal_at
        self.fatal = fatal
        self.connects = 0
        self.disconnects = 0

    async def __call__(self, request):
        self.calls += 1
        self.requests.append(request)
        if self.fatal_at is not None and self.calls == self.fatal_at:
            raise self.fatal
        if self.fail_at is not None and self.calls == self.fail_at:
            raise self.error
        return None

    async def connect(self):
        self.connects += 1

    async def disconnect(self):
        self.disconnects += 1


class FakeRPCError(Exception):
    """Duck-typed per-request error (Telegram answered with an error code).

    Deliberately NOT a ``ConnectionError``/``OSError`` and not a Telethon
    class: the replay has to classify it by behaviour, not by import.
    """

    code = 400
    message = "CHAT_WRITE_FORBIDDEN"

    def __init__(self, message="CHAT_WRITE_FORBIDDEN", code=400):
        super().__init__(message)
        self.message = message
        self.code = code


def _methods(steps):
    return [step.method for step in steps]


# ---------------------------------------------------------------------------
# the shipped data
# ---------------------------------------------------------------------------


class TestShippedSequences(unittest.TestCase):
    def test_platforms_are_android_and_desktop(self):
        self.assertEqual(tuple(PLATFORMS), ("android", "desktop"))
        self.assertEqual(set(BOOTSTRAP_SEQUENCES), {"android", "desktop"})

    def test_android_first_network_request_is_get_config(self):
        # The setUserId side effects (help.getConfig) are the first network
        # request: everything before it in onAuthSuccess is local state.
        plan = sequence("android")
        self.assertEqual(plan[0].method, "help.getConfig")
        self.assertEqual(plan[0].phase, "session")
        # and the second one is the config-driven app config, not a dialog read
        self.assertEqual(plan[1].method, "help.getAppConfig")

    def test_desktop_starts_config_then_state(self):
        plan = sequence("desktop")
        self.assertEqual(_methods(plan[:2]), ["help.getConfig", "updates.getState"])
        # invokeWithLayer(initConnection) is spec row 2 and must NOT be here:
        # it is fixed at connect time by the client
        self.assertNotIn("initConnection", " ".join(step.name for step in plan))

    def test_desktop_state_precedes_the_dialog_batch(self):
        plan = _methods(sequence("desktop"))
        state = plan.index("updates.getState")
        dialogs = plan.index("messages.getDialogs")
        pinned = plan.index("messages.getPinnedDialogs")
        contacts = plan.index("contacts.getContacts")
        self.assertLess(state, dialogs)
        self.assertLess(dialogs, pinned)
        self.assertLess(pinned, contacts)

    def test_android_config_precedes_autodownload_and_state(self):
        plan = _methods(sequence("android"))
        self.assertLess(
            plan.index("help.getConfig"), plan.index("account.getAutoDownloadSettings")
        )
        self.assertLess(plan.index("help.getConfig"), plan.index("updates.getState"))
        # the notify-settings trio is the dialogs phase, after the state read
        self.assertLess(plan.index("updates.getState"), plan.index("account.getNotifySettings"))

    def test_peer_color_pair_is_adjacent(self):
        plan = _methods(sequence("android"))
        colors = plan.index("help.getPeerColors")
        self.assertEqual(plan[colors + 1], "help.getPeerProfileColors")

    def test_every_shipped_step_is_allowlisted(self):
        for platform in PLATFORMS:
            for include in (False, True):
                for step in sequence(platform, include_cosmetic=include):
                    self.assertIsInstance(step, Step)
                    self.assertIn(step.phase, PHASES)
                    self.assertTrue(step.why, step.name)
                    self.assertTrue(step.source, step.name)
                    if step.phase == "cosmetic":
                        self.assertIn(step.method, COSMETIC_METHODS, step.name)
                    else:
                        self.assertIn(step.method, SAFE_METHODS, step.name)

    def test_cosmetic_methods_are_tagged_cosmetic(self):
        for platform in PLATFORMS:
            for step in BOOTSTRAP_SEQUENCES[platform]:
                if step.method in COSMETIC_METHODS:
                    self.assertEqual(step.phase, "cosmetic", step.name)

    def test_never_ships_forbidden_or_non_startup_methods(self):
        for platform in PLATFORMS:
            shipped = _methods(BOOTSTRAP_SEQUENCES[platform])
            for method in _MUST_NEVER_APPEAR:
                self.assertNotIn(method, shipped, f"{platform}: {method}")
            for step in BOOTSTRAP_SEQUENCES[platform]:
                self.assertFalse(is_forbidden(step.method), step.name)

    def test_step_names_are_unique(self):
        for platform in PLATFORMS:
            names = [step.name for step in BOOTSTRAP_SEQUENCES[platform]]
            self.assertEqual(len(names), len(set(names)), platform)

    def test_step_counts(self):
        # android: 19 safe steps + the 8 cosmetic ones; desktop has no
        # cosmetic row (its sticker panel loads lazily, per the spec)
        self.assertEqual(len(sequence("android")), 19)
        self.assertEqual(len(sequence("android", include_cosmetic=True)), 27)
        self.assertEqual(len(sequence("desktop")), 13)
        self.assertEqual(len(sequence("desktop", include_cosmetic=True)), 13)

    def test_every_safe_method_is_reachable_somewhere(self):
        # a method in the allowlist that no platform sends is dead weight the
        # next reader will wonder about (help.getNearestDc is the documented
        # exception: pre-auth only, kept in the allowlist as a rule)
        shipped = set()
        for platform in PLATFORMS:
            shipped.update(_methods(sequence(platform, include_cosmetic=True)))
        unused = set(SAFE_METHODS) - shipped - {"help.getNearestDc"}
        self.assertFalse(unused, f"allowlisted but never sent: {sorted(unused)}")

    def test_aliases_resolve_to_the_same_sequence(self):
        self.assertEqual(sequence("android_x"), sequence("android"))
        self.assertEqual(sequence("tdesktop"), sequence("desktop"))
        self.assertEqual(sequence("ANDROID"), sequence("android"))

    def test_unknown_platform_is_refused(self):
        with self.assertRaises(BootstrapError):
            sequence("ios")
        with self.assertRaises(BootstrapError):
            sequence("web")
        with self.assertRaises(BootstrapError):
            sequence(42)  # type: ignore[arg-type]

    def test_ios_and_macos_name_why_they_are_absent(self):
        for family in ("ios", "macos"):
            with self.assertRaises(BootstrapError) as ctx:
                sequence(family)
            self.assertIn("no verified sequence", str(ctx.exception))
            self.assertIn(family, str(ctx.exception))


class TestAllowlists(unittest.TestCase):
    def test_forbidden_set_is_exactly_the_brief(self):
        self.assertEqual(
            FORBIDDEN_METHODS,
            {
                "account.updateStatus",
                "account.registerDevice",
                "account.resetAuthorization",
                "auth.*",
            },
        )

    def test_safe_methods_contain_every_required_read(self):
        required = {
            "help.getConfig",
            "help.getAppConfig",
            "updates.getState",
            "help.getPeerColors",
            "help.getPeerProfileColors",
            "help.getPromoData",
            "contacts.getContacts",
            "users.getFullUser",
            "account.getNotifySettings",
            "messages.getDialogs",
            "messages.getPinnedDialogs",
            "messages.getQuickReplies",
            "help.getTermsOfServiceUpdate",
            "account.getAutoDownloadSettings",
            "account.getWebBrowserSettings",
            "langpack.getLanguages",
            "help.getInviteText",
            "help.getRecentMeUrls",
            "help.getNearestDc",
        }
        self.assertTrue(required <= SAFE_METHODS)
        # not a denylist in disguise: mutating/auth methods are not "safe"
        for method in FORBIDDEN_METHODS - {"auth.*"}:
            self.assertNotIn(method, SAFE_METHODS)
            self.assertNotIn(method, COSMETIC_METHODS)

    def test_is_forbidden_auth_prefix(self):
        self.assertTrue(is_forbidden("auth.signIn"))
        self.assertTrue(is_forbidden("auth.exportLoginToken"))
        self.assertTrue(is_forbidden("account.updateStatus"))
        self.assertFalse(is_forbidden("account.getNotifySettings"))
        self.assertFalse(is_forbidden("help.getConfig"))
        # not a prefix match on the whole string
        self.assertFalse(is_forbidden("auths.getConfig"))

    def test_excluded_methods_all_have_reasons(self):
        for method, reason in EXCLUDED_METHODS.items():
            self.assertTrue(reason, method)
            self.assertIsInstance(method, str)

    def test_forbidden_step_in_a_sequence_is_refused(self):
        bad = Step(
            name="account.updateStatus",
            method="account.updateStatus",
            phase="session",
            why="publishes presence",
            source="test",
        )
        with mock.patch.dict(
            bootstrap.BOOTSTRAP_SEQUENCES,
            {"android": tuple(BOOTSTRAP_SEQUENCES["android"]) + (bad,)},
        ):
            with self.assertRaises(BootstrapError) as ctx:
                sequence("android")
        self.assertIn("forbidden", str(ctx.exception))

    def test_forbidden_step_also_refused_by_replay_and_describe(self):
        bad = Step(
            name="account.registerDevice",
            method="account.registerDevice",
            phase="session",
            why="pushes into the void",
            source="test",
        )
        patched = {"android": tuple(BOOTSTRAP_SEQUENCES["android"]) + (bad,)}
        with mock.patch.dict(bootstrap.BOOTSTRAP_SEQUENCES, patched):
            with self.assertRaises(BootstrapError):
                describe("android")
            with self.assertRaises(BootstrapError):
                        asyncio.run(replay_startup(FakeClient(), platform="android"))

    def test_non_allowlisted_step_is_refused(self):
        sneaky = Step(
            name="messages.getAvailableEffects",
            method="messages.getAvailableEffects",
            phase="dialogs",
            why="not in the audited allowlist",
            source="test",
        )
        with mock.patch.dict(
            bootstrap.BOOTSTRAP_SEQUENCES,
            {"android": (sneaky,)},
        ):
            with self.assertRaises(BootstrapError) as ctx:
                sequence("android")
        self.assertIn("allowlist", str(ctx.exception))

    def test_step_rejects_an_unknown_phase(self):
        with self.assertRaises(BootstrapError):
            Step(name="x", method="help.getConfig", phase="login", why="", source="")


class TestCosmeticFiltering(unittest.TestCase):
    def test_cosmetic_steps_are_opted_out_by_default(self):
        plan = sequence("android")
        self.assertFalse([step for step in plan if step.phase == "cosmetic"])

    def test_include_cosmetic_adds_exactly_the_cosmetic_rows(self):
        plan = sequence("android", include_cosmetic=True)
        cosmetic = [step for step in plan if step.phase == "cosmetic"]
        self.assertEqual(len(cosmetic), 8)
        self.assertEqual(
            sorted(_methods(cosmetic)),
            sorted(
                [
                    "messages.getStickerSet",
                    "messages.getStickerSet",
                    "messages.getFavedStickers",
                    "messages.getRecentStickers",
                    "messages.getFeaturedStickers",
                    "messages.getArchivedStickers",
                    "messages.getAllStickers",
                    "messages.getAvailableReactions",
                ]
            ),
        )
        # the safe steps keep their order with cosmetics interleaved
        self.assertEqual(
            _methods(sequence("android")),
            [step.method for step in plan if step.phase != "cosmetic"],
        )

    def test_desktop_has_no_cosmetic_rows(self):
        self.assertEqual(describe("desktop")["cosmetic_steps"], 0)


class TestDescribe(unittest.TestCase):
    def test_shape_and_counts(self):
        info = describe("android")
        self.assertEqual(info["platform"], "android")
        self.assertEqual(info["client_version"], "12.10.6")
        self.assertFalse(info["include_cosmetic"])
        self.assertEqual(info["count"], 19)
        self.assertEqual(info["cosmetic_steps"], 8)
        self.assertEqual(len(info["steps"]), info["count"])
        self.assertEqual([entry["step"] for entry in info["steps"]], list(range(1, 20)))
        first = info["steps"][0]
        self.assertEqual(
            set(first), {"step", "name", "method", "phase", "source", "why"}
        )

    def test_desktop_version(self):
        self.assertEqual(describe("desktop")["client_version"], "7.3.3")

    def test_includes_cosmetic(self):
        info = describe("android", include_cosmetic=True)
        self.assertEqual(info["count"], 27)
        self.assertTrue(info["include_cosmetic"])
        self.assertEqual(info["cosmetic_steps"], 8)

    def test_json_serializable(self):
        json.dumps(describe("android"))
        json.dumps(describe("desktop", include_cosmetic=True))

    def test_excluded_documents_the_rules(self):
        excluded = describe("desktop")["excluded"]
        for method in ("account.updateStatus", "account.registerDevice", "auth.*"):
            self.assertIn(method, excluded)


class TestPlatformFor(unittest.TestCase):
    def test_lang_pack_strings(self):
        self.assertEqual(platform_for("android"), "android")
        self.assertEqual(platform_for("android_x"), "android")
        self.assertEqual(platform_for("tdesktop"), "desktop")
        self.assertEqual(platform_for("desktop"), "desktop")

    def test_apidata_classes_and_instances(self):
        self.assertEqual(platform_for(API.TelegramAndroid), "android")
        self.assertEqual(platform_for(API.TelegramAndroidX), "android")
        self.assertEqual(platform_for(API.TelegramDesktop), "desktop")
        minted = API.TelegramAndroid.Generate(unique_id="pf")
        self.assertEqual(platform_for(minted), "android")

    def test_fingerprint_origin(self):
        fingerprint = type(
            "Fp",
            (),
            {
                "lang_pack": "tdesktop",
                "origin": "tdesktop",
            },
        )()
        self.assertEqual(platform_for(fingerprint), "desktop")
        android_fp = type("Fp", (), {"lang_pack": "android", "origin": "android"})()
        self.assertEqual(platform_for(android_fp), "android")

    def test_unsupported_families_are_named(self):
        for family, preset in (("ios", API.TelegramIOS), ("macos", API.TelegramMacOS)):
            with self.assertRaises(BootstrapError) as ctx:
                platform_for(preset)
            message = str(ctx.exception)
            self.assertIn("no verified sequence", message)
            self.assertIn(family, message)

    def test_nothing_to_infer_from(self):
        with self.assertRaises(BootstrapError) as ctx:
            platform_for(object())
        self.assertIn("cannot infer", str(ctx.exception))

    def test_web_lang_pack_is_not_a_platform(self):
        with self.assertRaises(BootstrapError):
            platform_for(type("Fp", (), {"lang_pack": "", "origin": "web"})())


# ---------------------------------------------------------------------------
# the replay loop
# ---------------------------------------------------------------------------


class TestReplay(unittest.TestCase):
    def test_fake_client_records_the_exact_order(self):
        client = FakeClient()
        builder = lambda step: ("request", step.method)  # noqa: E731
        report = asyncio.run(
            replay_startup(client, platform="android", request=builder)
        )
        expected = _methods(sequence("android"))
        self.assertEqual([req[1] for req in client.requests], expected)
        self.assertEqual([entry["method"] for entry in report["steps"]], expected)
        self.assertEqual(report["sent"], len(expected))
        self.assertEqual(report["errors"], [])
        self.assertEqual({entry["status"] for entry in report["steps"]}, {"sent"})
        self.assertEqual(report["platform"], "android")

    def test_report_step_shape(self):
        report = asyncio.run(
            replay_startup(FakeClient(), platform="desktop", request=lambda s: s.name)
        )
        self.assertEqual(
            set(report), {"platform", "include_cosmetic", "dry_run", "steps", "sent", "errors"}
        )
        self.assertEqual(
            set(report["steps"][0]),
            {"step", "name", "method", "phase", "source", "status", "detail"},
        )

    def test_continues_after_a_failed_request(self):
        client = FakeClient(fail_at=3, error=FakeRPCError())
        report = asyncio.run(
            replay_startup(client, platform="android", request=lambda s: s.name)
        )
        statuses = [entry["status"] for entry in report["steps"]]
        self.assertEqual(statuses[2], "error")
        self.assertEqual(statuses[:2], ["sent", "sent"])
        self.assertEqual(statuses[3:], ["sent"] * (len(statuses) - 3))
        self.assertEqual(len(report["errors"]), 1)
        self.assertEqual(report["errors"][0]["step"], 3)
        self.assertIn("FakeRPCError", report["errors"][0]["type"])
        self.assertEqual(report["sent"], len(statuses) - 1)
        # the replay did not stop: every step was attempted
        self.assertEqual(client.calls, len(statuses))

    def test_connection_failure_stops_the_replay_with_a_partial_report(self):
        # a fatal stop raises BootstrapError (not the raw exception) and
        # carries what had already been sent, so a caller is never left
        # guessing which steps reached Telegram
        client = FakeClient(fatal_at=2, fatal=ConnectionResetError("wifi is down"))
        with self.assertRaises(BootstrapError) as ctx:
            asyncio.run(
                replay_startup(client, platform="android", request=lambda s: s.name)
            )
        error = ctx.exception
        self.assertIn("step 2", str(error))
        self.assertIsInstance(error.__cause__, ConnectionResetError)
        self.assertEqual(error.stopped_at, 2)
        self.assertEqual(error.sent, 1)
        self.assertEqual(error.report["sent"], 1)
        self.assertEqual(
            [entry["status"] for entry in error.report["steps"]], ["sent", "error"]
        )
        self.assertEqual(len(error.report["errors"]), 1)
        self.assertEqual(client.calls, 2)

    def test_auth_named_failure_stops_the_replay_with_a_partial_report(self):
        class AuthKeyUnregisteredError(Exception):
            pass

        client = FakeClient(fatal_at=1, fatal=AuthKeyUnregisteredError("dead key"))
        with self.assertRaises(BootstrapError) as ctx:
            asyncio.run(
                replay_startup(client, platform="android", request=lambda s: s.name)
            )
        self.assertEqual(ctx.exception.stopped_at, 1)
        self.assertIsInstance(ctx.exception.__cause__, AuthKeyUnregisteredError)
        self.assertEqual(ctx.exception.sent, 0)

    def test_a_hung_step_times_out_instead_of_stalling(self):
        class SleepingClient:
            def __init__(self):
                self.calls = 0

            async def __call__(self, request):
                self.calls += 1
                await asyncio.sleep(5)

        client = SleepingClient()
        with self.assertRaises(BootstrapError) as ctx:
            asyncio.run(
                replay_startup(
                    client,
                    platform="android",
                    request=lambda s: s.name,
                    step_timeout=0.01,
                )
            )
        self.assertIn("step 1", str(ctx.exception))
        self.assertEqual(ctx.exception.sent, 0)
        self.assertEqual(client.calls, 1)

    def test_dry_run_makes_zero_calls(self):
        client = FakeClient()
        report = asyncio.run(
            replay_startup(
                client, platform="android", include_cosmetic=True, dry_run=True
            )
        )
        self.assertEqual(client.calls, 0)
        self.assertEqual(client.requests, [])
        self.assertEqual(report["sent"], 0)
        self.assertEqual(report["errors"], [])
        self.assertEqual(len(report["steps"]), 27)
        self.assertEqual({entry["status"] for entry in report["steps"]}, {"planned"})

    def test_dry_run_needs_no_client(self):
        report = asyncio.run(
            replay_startup(None, platform="desktop", dry_run=True)
        )
        self.assertEqual(len(report["steps"]), 13)

    def test_live_mode_without_a_client_is_refused(self):
        with self.assertRaises(BootstrapError):
            asyncio.run(replay_startup(None, platform="desktop"))

    def test_unknown_platform_is_refused(self):
        with self.assertRaises(BootstrapError):
            asyncio.run(
                replay_startup(FakeClient(), platform="ios", request=lambda s: s.name)
            )

    def test_unbuildable_step_is_skipped_not_sent(self):
        plan = sequence("android", include_cosmetic=True)
        stub = next(step for step in plan if step.method == "messages.getStickerSet")

        def builder(step):
            return None if step is stub else ("request", step.method)

        client = FakeClient()
        report = asyncio.run(
            replay_startup(
                client, platform="android", include_cosmetic=True, request=builder
            )
        )
        statuses = {entry["name"]: entry["status"] for entry in report["steps"]}
        self.assertEqual(statuses[stub.name], "skipped")
        self.assertEqual(report["sent"], len(plan) - 1)
        self.assertEqual(report["errors"], [])
        self.assertEqual(len(client.requests), len(plan) - 1)


class TestBuilderFailures(unittest.TestCase):
    def test_a_broken_builder_is_one_failed_step(self):
        import asyncio

        def builder(step):
            if step.method == "contacts.getContacts":
                raise TypeError("unexpected keyword argument 'hash'")
            return ("request", step.method)

        client = FakeClient()
        report = asyncio.run(
            replay_startup(client, platform="android", request=builder)
        )
        statuses = [entry["status"] for entry in report["steps"]]
        self.assertIn("error", statuses)
        self.assertEqual(statuses.count("error"), 1)
        self.assertEqual(len(report["errors"]), 1)
        self.assertIn("could not build the request", report["steps"][7]["detail"])
        # nothing aborted: every other step still ran, in order
        self.assertEqual(client.calls, len(statuses) - 1)


class TestDefaultBuilder(unittest.TestCase):
    """The default builder builds real Telethon objects, offline."""

    def setUp(self):
        try:
            import telethon.tl.functions  # noqa: F401
        except Exception:  # pragma: no cover - optional dependency absent
            self.skipTest("telethon is not installed")

    def test_builds_a_request_for_the_vetted_methods(self):
        builder = bootstrap._make_builder("android")
        built = {}
        for step in sequence("android"):
            built[step.name] = builder(step)
        self.assertIsNotNone(built["help.getConfig"])
        self.assertIsNotNone(built["updates.getState"])
        self.assertIsNotNone(built["users.getFullUser"])
        self.assertIsNotNone(built["messages.getDialogs"])
        for name, request in built.items():
            if request is not None:
                self.assertTrue(
                    hasattr(request, "CONSTRUCTOR_ID"), f"{name} is not a TLObject"
                )

    def test_lang_pack_follows_the_platform(self):
        android = bootstrap._make_builder("android")(
            next(s for s in sequence("android") if s.method == "langpack.getLanguages")
        )
        desktop = bootstrap._make_builder("desktop")(
            next(s for s in sequence("desktop") if s.method == "help.getAppConfig")
        )
        if android is not None:
            self.assertEqual(android.lang_pack, "android")
        self.assertIsNotNone(desktop)

    def test_notify_settings_trio_uses_one_peer_class_each(self):
        builder = bootstrap._make_builder("desktop")
        peers = [
            builder(step)
            for step in sequence("desktop")
            if step.method == "account.getNotifySettings"
        ]
        names = {type(peer.peer).__name__ for peer in peers if peer is not None}
        if names:
            self.assertEqual(
                names, {"InputNotifyChats", "InputNotifyUsers", "InputNotifyBroadcasts"}
            )

    def test_default_builder_never_sends_a_sticker_set(self):
        # the set name is not part of the request the replay can honestly
        # invent, so both sticker-set rows are skipped without a caller seam
        builder = bootstrap._make_builder("android")
        for step in sequence("android", include_cosmetic=True):
            if step.method == "messages.getStickerSet":
                self.assertIsNone(builder(step))

    def test_replay_with_the_real_builder_never_touches_the_network(self):
        client = FakeClient()
        report = asyncio.run(
            replay_startup(client, platform="desktop", include_cosmetic=True)
        )
        self.assertGreater(report["sent"], 0)
        self.assertEqual(report["errors"], [])
        self.assertEqual(len(client.requests), report["sent"])


class TestLiveClientSeam(unittest.TestCase):
    def test_make_client_reuses_heals_probe_client(self):
        from tgmint import heal

        api = API.TelegramAndroid.Generate(unique_id="seam")
        data = mock.Mock()
        sentinel = object()
        with mock.patch.object(heal, "make_client", return_value=sentinel) as factory:
            from tgmint import bootstrap as module

            self.assertIs(module.make_client(api=api, data=data), sentinel)
        factory.assert_called_once_with(kind="probe", api=api, data=data)


# ---------------------------------------------------------------------------
# importability without Telethon
# ---------------------------------------------------------------------------


class TestImportableWithoutTelethon(unittest.TestCase):
    def test_module_imports_with_telethon_poisoned(self):
        """`import tgmint.bootstrap` must not need Telethon (or tgmint.tl)."""
        script = r'''
import json, sys

BLOCKED = ("telethon", "tgmint.tl", "tgmint.tg")
for _name in BLOCKED:
    sys.modules[_name] = None

class _Blocker:
    def find_spec(self, name, path=None, target=None):
        for blocked in BLOCKED:
            if name == blocked or name.startswith(blocked + "."):
                raise ImportError("blocked in test: " + name)
        return None

sys.meta_path.insert(0, _Blocker())

import tgmint.bootstrap as b

assert b.sequence("android")[0].method == "help.getConfig"
assert len(b.sequence("android")) == 19
assert len(b.sequence("android", include_cosmetic=True)) == 27
assert b.describe("desktop")["count"] == 13
assert b.platform_for("tdesktop") == "desktop"
# the default builder degrades to "nothing buildable", it does not raise
builder = b._make_builder("android")
assert builder(b.sequence("android")[0]) is None
print(json.dumps({"ok": True}))
'''
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            env=dict(os.environ, PYTHONPATH=_SRC),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"ok": true', result.stdout)

    def test_no_top_level_telethon_import(self):
        """Only the builder may import Telethon, and only inside a function."""
        import ast

        path = os.path.join(_SRC, "tgmint", "bootstrap.py")
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        for node in tree.body:  # module level only
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn("telethon", alias.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertNotIn("telethon", node.module or "")


# ---------------------------------------------------------------------------
# parity integration
# ---------------------------------------------------------------------------


class TestParityIntegration(unittest.TestCase):
    """`tgmint.parity.describe_envelope` reports what would be replayed."""

    def test_envelope_carries_a_bootstrap_summary(self):
        from tgmint.parity import describe_envelope

        self.assertEqual(
            describe_envelope(API.TelegramAndroid)["bootstrap"],
            {"platform": "android", "steps": 19, "cosmetic_steps": 8},
        )
        self.assertEqual(
            describe_envelope("android_x")["bootstrap"]["platform"], "android"
        )
        self.assertEqual(
            describe_envelope("tdesktop")["bootstrap"],
            {"platform": "desktop", "steps": 13, "cosmetic_steps": 0},
        )

    def test_families_without_a_sequence_report_zero(self):
        from tgmint.parity import describe_envelope

        for preset in ("ios", "macos"):
            self.assertEqual(
                describe_envelope(preset)["bootstrap"],
                {"platform": None, "steps": 0, "cosmetic_steps": 0},
            )

    def test_matches_describe(self):
        from tgmint.parity import describe_envelope

        info = describe("android")
        summary = describe_envelope(API.TelegramAndroid)["bootstrap"]
        self.assertEqual(summary["steps"], info["count"])
        self.assertEqual(summary["cosmetic_steps"], info["cosmetic_steps"])

    def test_cli_parity_shows_it(self):
        code, out, err = run_cli(
            ["parity", "--preset", "android", "--unique-id", "boot-par", "--json"]
        )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["bootstrap"]["platform"], "android")
        self.assertEqual(payload["bootstrap"]["steps"], 19)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class BootstrapCliTest(unittest.TestCase):
    """`tgmint bootstrap` through the real handler; no socket is opened."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.session = os.path.join(self._tmp.name, "acct.session")
        codec.write_session(
            SessionData(dc_id=2, auth_key=_KEY, user_id=777000, api_id=2040),
            self.session,
            "telethon-session",
        )

    def _sidecar(self, api) -> str:
        fingerprint = Fingerprint.from_apidata(api)
        path = str(sidecar_path_for(self.session))
        fingerprint.save(path)
        return path

    def test_dry_run_json(self):
        code, out, err = run_cli(
            ["bootstrap", "--preset", "android", "--dry-run", "--json"]
        )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["platform"], "android")
        self.assertEqual(payload["client_version"], "12.10.6")
        self.assertEqual(payload["sent"], 0)
        self.assertEqual(payload["errors"], [])
        self.assertEqual(len(payload["steps"]), 19)
        self.assertEqual(payload["steps"][0]["method"], "help.getConfig")
        self.assertEqual(payload["steps"][0]["status"], "planned")
        self.assertEqual(payload["cosmetic_steps"], 8)

    def test_dry_run_never_connects(self):
        with mock.patch.object(bootstrap, "make_client") as factory:
            code, _, err = run_cli(
                ["bootstrap", "--preset", "desktop", "--dry-run", "--json"]
            )
        self.assertEqual(code, 0, err)
        factory.assert_not_called()

    def test_dry_run_include_cosmetic(self):
        code, out, err = run_cli(
            [
                "bootstrap", "--preset", "android",
                "--include-cosmetic", "--dry-run", "--json",
            ]
        )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(len(payload["steps"]), 27)
        phases = {entry["phase"] for entry in payload["steps"]}
        self.assertIn("cosmetic", phases)

    def test_dry_run_human(self):
        code, out, err = run_cli(["bootstrap", "--preset", "desktop", "--dry-run"])
        self.assertEqual(code, 0, err)
        self.assertIn("desktop startup plan", out)
        self.assertIn("help.getConfig", out)
        self.assertIn("updates.getState", out)

    def test_auto_preset_reads_the_sidecar(self):
        self._sidecar(API.TelegramDesktop.Generate(unique_id="auto"))
        code, out, err = run_cli(
            ["bootstrap", "--session", self.session, "--dry-run", "--json"]
        )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["platform"], "desktop")
        self.assertEqual(payload["preset"], "auto")
        self.assertEqual(len(payload["steps"]), 13)

    def test_auto_preset_refuses_an_ios_sidecar(self):
        self._sidecar(API.TelegramIOS.Generate(unique_id="auto-ios", layer=232))
        code, out, err = run_cli(
            ["bootstrap", "--session", self.session, "--dry-run", "--json"]
        )
        self.assertEqual(code, 2, err)
        payload = json.loads(out)
        self.assertFalse(payload["ok"])
        self.assertIn("no verified sequence", payload["error"])

    def test_auto_preset_without_a_sidecar_exits_2(self):
        code, _, err = run_cli(["bootstrap", "--session", self.session, "--json"])
        self.assertEqual(code, 2)
        self.assertIn("no fingerprint sidecar", err)

    def test_explicit_preset_beats_the_sidecar(self):
        self._sidecar(API.TelegramDesktop.Generate(unique_id="auto2"))
        code, out, err = run_cli(
            [
                "bootstrap", "--preset", "android",
                "--session", self.session, "--dry-run", "--json",
            ]
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["platform"], "android")

    def test_live_without_session_exits_2(self):
        code, out, err = run_cli(["bootstrap", "--json"])
        self.assertEqual(code, 2, err)
        payload = json.loads(out)
        self.assertFalse(payload["ok"])
        self.assertIn("--session", payload["error"])

    def test_unknown_preset_is_rejected_by_argparse(self):
        with self.assertRaises(SystemExit) as ctx:
            run_cli(["bootstrap", "--preset", "ios", "--dry-run"])
        self.assertEqual(ctx.exception.code, 2)

    def test_unknown_api_preset_is_rejected_by_argparse(self):
        with self.assertRaises(SystemExit) as ctx:
            run_cli(
                ["bootstrap", "--preset", "android", "--dry-run",
                 "--api-preset", "web-z"]
            )
        self.assertEqual(ctx.exception.code, 2)

    def test_live_replay_with_a_fake_client(self):
        client = FakeClient()
        with mock.patch.object(bootstrap, "make_client", return_value=client):
            code, out, err = run_cli(
                [
                    "bootstrap", "--preset", "desktop",
                    "--session", self.session, "--json",
                ]
            )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["dry_run"])
        self.assertEqual(payload["platform"], "desktop")
        self.assertEqual(len(payload["steps"]), 13)
        self.assertGreater(payload["sent"], 0)
        self.assertEqual(payload["errors"], [])
        self.assertEqual(client.connects, 1)
        self.assertEqual(client.disconnects, 1)
        # nothing was recorded, so this replay minted its identity
        self.assertEqual(payload["identity"]["source"], "minted")
        self.assertIsNone(payload["identity"]["path"])

    def test_live_replay_presents_the_recorded_identity(self):
        # Telegram remembers the device a session signed in with, so a
        # replay must present the sidecar's identity, not a fresh one
        sidecar = self._sidecar(API.TelegramDesktop.Generate(unique_id="recorded"))
        recorded = Fingerprint.load(sidecar)
        client = FakeClient()
        with mock.patch.object(
            bootstrap, "make_client", return_value=client
        ) as factory:
            code, out, err = run_cli(
                [
                    "bootstrap", "--preset", "desktop",
                    "--session", self.session, "--json",
                ]
            )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["identity"]["source"], "recorded")
        self.assertEqual(payload["identity"]["path"], sidecar)
        presented = factory.call_args.kwargs["api"]
        self.assertEqual(presented.api_id, recorded.api_id)
        self.assertEqual(presented.device_model, recorded.device_model)
        self.assertEqual(presented.app_version, recorded.app_version)

    def test_api_preset_from_another_family_is_refused(self):
        client = FakeClient()
        with mock.patch.object(bootstrap, "make_client", return_value=client) as factory:
            code, out, err = run_cli(
                [
                    "bootstrap", "--preset", "android", "--api-preset", "desktop",
                    "--session", self.session, "--json",
                ]
            )
        self.assertEqual(code, 2, err)
        payload = json.loads(out)
        self.assertFalse(payload["ok"])
        self.assertIn("does not match the android replay", payload["error"])
        factory.assert_not_called()

    def test_a_recorded_identity_from_another_family_is_refused(self):
        # a desktop sidecar cannot be presented to an android replay
        self._sidecar(API.TelegramDesktop.Generate(unique_id="mismatch"))
        client = FakeClient()
        with mock.patch.object(bootstrap, "make_client", return_value=client) as factory:
            code, out, err = run_cli(
                [
                    "bootstrap", "--preset", "android",
                    "--session", self.session, "--json",
                ]
            )
        self.assertEqual(code, 2, err)
        payload = json.loads(out)
        self.assertFalse(payload["ok"])
        self.assertIn("desktop", payload["error"])
        self.assertIn("android", payload["error"])
        factory.assert_not_called()

    def test_live_replay_reports_a_dead_auth_key_as_exit_2(self):
        # exit 1 is reserved for "audit found problems"; a failed replay is
        # an error, like every other runtime failure in this CLI
        class AuthKeyUnregisteredError(Exception):
            pass

        client = FakeClient(
            fatal_at=1, fatal=AuthKeyUnregisteredError("the key is not registered")
        )
        with mock.patch.object(bootstrap, "make_client", return_value=client):
            code, out, err = run_cli(
                [
                    "bootstrap", "--preset", "android",
                    "--session", self.session, "--json",
                ]
            )
        self.assertEqual(code, 2, err)
        payload = json.loads(out)
        self.assertFalse(payload["ok"])
        self.assertIn("the key is not registered", payload["error"])
        # the partial report is attached, so a caller sees what was sent
        self.assertEqual(payload["stopped_at"], 1)
        self.assertEqual(payload["partial_report"]["sent"], 0)
        self.assertEqual(client.disconnects, 1)

    def test_live_replay_survives_a_per_request_error(self):
        client = FakeClient(fail_at=2, error=FakeRPCError())
        with mock.patch.object(bootstrap, "make_client", return_value=client):
            code, out, err = run_cli(
                [
                    "bootstrap", "--preset", "desktop",
                    "--session", self.session, "--json",
                ]
            )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(len(payload["errors"]), 1)
        self.assertEqual(
            [entry["status"] for entry in payload["steps"]].count("error"), 1
        )

    def test_help_mentions_the_guardrails(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit) as ctx:
                cli.main(["bootstrap", "--help"])
        self.assertEqual(ctx.exception.code, 0, err.getvalue())
        # argparse wraps the description, so a phrase can straddle a line
        # break: compare on normalized whitespace
        text = " ".join(out.getvalue().lower().split())
        for phrase in ("read-only", "initconnection", "refused", "no batch mode"):
            self.assertIn(phrase, text)
        self.assertIn("--dry-run", text)


if __name__ == "__main__":
    unittest.main()
