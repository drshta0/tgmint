"""Offline tests for tgmint.heal — session repair with the passkey.

The network path cannot be exercised here, so every test injects a fake
Telethon client, a fake liveness probe and a fake passkey login through the
seams ``heal_session`` exposes (``client_factory`` / ``probe`` / ``login``,
which default to the module's ``make_client`` / ``probe_session`` /
``_default_login``).  What is pinned is the *decisions*:

* an alive session is a no-op — the session file is byte-identical
  afterwards and no login is attempted;
* a dead auth key is rewritten in place, same path, same format, mode
  0600, with the fresh key and the old one gone;
* without ``--live`` nothing is probed and ``--force`` is mandatory;
* an inconclusive probe (a network failure, not an auth rejection) refuses
  unless forced;
* another account's passkey is refused before any client is built;
* a login that lands on a different account than the store claims is
  refused instead of written;
* a `.tgmint` envelope is rewritten as an envelope, keeping its
  fingerprint and passkey.

The live probe's error classification, the real passkey ceremony and the
end-to-end "the dead session really came back" are NOT covered here — that
needs a live account, and the module docstring says so.
"""

import asyncio
import base64
import json
import os
import stat
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

from tgmint import codec
from tgmint.codec import gramjs, pyrogram
from tgmint.codec.data import SessionData
from tgmint.heal import (
    HealError,
    HealRefusal,
    heal_session,
    is_dead_auth_error,
    probe_session,
    write_session_atomically,
)
from tgmint.profile import open_profile, seal, write_profile

OLD_KEY = bytes(range(256))
NEW_KEY = bytes(reversed(range(256)))
USER_ID = 777000
DC_ID = 2
NEW_DC = 4


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------


class FakeSession:
    """The slice of a Telethon session object the healer touches."""

    def __init__(self, dc_id=NEW_DC, key=NEW_KEY, without_key=False):
        self.dc_id = dc_id
        self.auth_key = None if without_key else SimpleNamespace(key=key)


class FakeClient:
    def __init__(self, session=None, *, me=None, error=None):
        self.session = session if session is not None else FakeSession()
        self.me = me if me is not None else SimpleNamespace(id=USER_ID)
        self.error = error
        self.connects = 0
        self.disconnects = 0

    async def connect(self):
        self.connects += 1

    async def disconnect(self):
        self.disconnects += 1

    async def get_me(self):
        if self.error is not None:
            raise self.error
        return self.me


class DeadAuthKey(Exception):
    """Same class name as Telethon's, so the probe classifies it the same."""


DeadAuthKey.__name__ = "AuthKeyUnregisteredError"


class FakeClients:
    """A ``make_client`` stand-in that records what it was asked for."""

    def __init__(self, *, probe=None, login=None):
        self.probe_client = probe
        self.login_client = login
        self.calls = []

    def __call__(self, *, kind, api, data=None):
        self.calls.append({"kind": kind, "api": api, "data": data})
        if kind == "probe":
            if self.probe_client is None:  # pragma: no cover - test bug
                raise AssertionError("no probe client configured")
            return self.probe_client
        if self.login_client is None:  # pragma: no cover - test bug
            raise AssertionError("no login client configured")
        return self.login_client

    @property
    def kinds(self):
        return [call["kind"] for call in self.calls]


class FakeLogin:
    def __init__(self, *, me=None, error=None):
        self.me = me if me is not None else SimpleNamespace(id=USER_ID)
        self.error = error
        self.calls = []

    async def __call__(self, client, *, passkey_path, password=None):
        self.calls.append({"client": client, "passkey": passkey_path, "password": password})
        if self.error is not None:
            raise self.error
        return self.me


async def dead_probe(client):
    """A probe that reports the dead auth key."""
    return {
        "performed": True,
        "alive": False,
        "dead": True,
        "reason": "the server rejected the stored auth key",
        "user_id": None,
    }


async def alive_probe(client):
    """A probe that reports an accepted auth key."""
    return {
        "performed": True,
        "alive": True,
        "dead": False,
        "reason": "the server accepted the stored auth key",
        "user_id": USER_ID,
    }


async def broken_probe(client):
    """A probe that could not decide (network, not auth)."""
    return {
        "performed": True,
        "alive": None,
        "dead": False,
        "reason": "the liveness probe failed for a non-auth reason (ConnectionError)",
        "user_id": None,
    }


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def session(**overrides):
    fields = dict(dc_id=DC_ID, auth_key=OLD_KEY, user_id=USER_ID, api_id=2040)
    fields.update(overrides)
    return SessionData(**fields)


def passkey_file(tmp, user_id=USER_ID, dc_id=DC_ID, name="acct.passkey.json"):
    path = os.path.join(tmp, name)
    payload = {
        "version": 1,
        "credential_id": base64.urlsafe_b64encode(b"cred-1").decode().rstrip("="),
        "rp_id": "telegram.org",
        "origin": "https://telegram.org",
        "alg": -7,
        "user_handle": f"{dc_id}:{user_id}",
        "private_key": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        "sign_count": 0,
        "name": "tgmint software passkey",
    }
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp)
    return path


_SUFFIXES = {
    "telethon-session": ".session",
    "telethon-string": ".string",
    "pyrogram-string": ".pyro",
    "gramjs-string": ".gramjs",
}


def session_file(tmp, fmt="pyrogram-string", data=None):
    path = os.path.join(tmp, "acct" + _SUFFIXES[fmt])
    data = data or session()
    codec.write_session(data, path, fmt)
    return path


def run(coro):
    return asyncio.run(coro)


class HealBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def read_back(self, path, fmt="pyrogram-string"):
        return codec.read_session(path, fmt)


# ---------------------------------------------------------------------------
# the decisions
# ---------------------------------------------------------------------------


class AliveSession(HealBase):
    def test_alive_is_a_noop_and_touches_nothing(self):
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        with open(path, "rb") as fp:
            before = fp.read()
        clients = FakeClients(probe=FakeClient(), login=FakeClient())
        login = FakeLogin()

        report = run(
            heal_session(
                path,
                passkey_path=passkey,
                session_format="pyrogram-string",
                live=True,
                probe=alive_probe,
                client_factory=clients,
                login=login,
            )
        )

        self.assertEqual(report["action"], "noop")
        self.assertTrue(report["ok"])
        self.assertFalse(report["auth_key_changed"])
        self.assertEqual(report["old"], report["new"])
        self.assertEqual(report["probe"]["alive"], True)
        self.assertEqual(clients.kinds, ["probe"])
        self.assertEqual(login.calls, [])  # never signed in
        with open(path, "rb") as fp:
            self.assertEqual(fp.read(), before)
        # one account, one session: nothing else appeared in the directory
        self.assertEqual(
            sorted(os.listdir(self.tmp)),
            sorted([os.path.basename(path), "acct.passkey.json"]),
        )


class DeadSession(HealBase):
    def _heal(self, fmt="pyrogram-string", **kwargs):
        path = session_file(self.tmp, fmt)
        passkey = passkey_file(self.tmp)
        clients = FakeClients(probe=FakeClient(error=DeadAuthKey()), login=FakeClient())
        login = FakeLogin()
        report = run(
            heal_session(
                path,
                passkey_path=passkey,
                session_format=fmt,
                live=True,
                probe=dead_probe,
                client_factory=clients,
                login=login,
                **kwargs,
            )
        )
        return path, report, clients, login

    def test_dead_session_is_rewritten_in_place(self):
        path, report, clients, login = self._heal()

        self.assertEqual(report["action"], "healed")
        self.assertTrue(report["auth_key_changed"])
        self.assertEqual(report["old"], {"user_id": USER_ID, "dc_id": DC_ID})
        self.assertEqual(report["new"], {"user_id": USER_ID, "dc_id": NEW_DC})
        self.assertEqual(report["output"], path)
        self.assertEqual(clients.kinds, ["probe", "login"])
        self.assertEqual(len(login.calls), 1)
        self.assertEqual(login.calls[0]["passkey"], os.path.join(self.tmp, "acct.passkey.json"))

        fresh = self.read_back(path)
        self.assertEqual(fresh.auth_key, NEW_KEY)
        self.assertEqual(fresh.dc_id, NEW_DC)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path, "rb") as fp:
            self.assertNotIn(OLD_KEY, fp.read())

    def test_rewrite_keeps_the_format(self):
        for fmt, reader in (
            ("gramjs-string", gramjs.read_string),
            ("pyrogram-string", pyrogram.read_string),
            ("telethon-session", None),
        ):
            with self.subTest(fmt=fmt):
                self._tmp.cleanup()
                self._tmp = tempfile.TemporaryDirectory()
                self.tmp = self._tmp.name
                self.addCleanup(self._tmp.cleanup)
                path, report, _clients, _login = self._heal(fmt)
                self.assertEqual(report["to_format"], fmt)
                if reader is None:
                    fresh = codec.read_session(path, "telethon-session")
                else:
                    with open(path, encoding="ascii") as fp:
                        fresh = reader(fp.read())
                self.assertEqual(fresh.auth_key, NEW_KEY)

    def test_probe_client_uses_the_stored_auth_key(self):
        _path, _report, clients, _login = self._heal()
        probe_call, login_call = clients.calls
        self.assertEqual(probe_call["data"].auth_key, OLD_KEY)
        self.assertIsNone(login_call["data"])  # the login client starts empty

    def test_2fa_password_is_forwarded(self):
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        login = FakeLogin()
        run(
            heal_session(
                path,
                passkey_path=passkey,
                session_format="pyrogram-string",
                live=True,
                password="cloud-password",
                probe=dead_probe,
                client_factory=FakeClients(
                    probe=FakeClient(), login=FakeClient()
                ),
                login=login,
            )
        )
        self.assertEqual(login.calls[0]["password"], "cloud-password")


class Refusals(HealBase):
    def test_without_live_and_without_force(self):
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        with open(path, "rb") as fp:
            before = fp.read()
        clients = FakeClients(probe=FakeClient(), login=FakeClient())
        with self.assertRaises(HealRefusal) as ctx:
            run(
                heal_session(
                    path,
                    session_format="pyrogram-string",
                    passkey_path=passkey,
                    client_factory=clients,
                    login=FakeLogin(),
                )
            )
        self.assertIn("--live", str(ctx.exception))
        self.assertIn("--force", str(ctx.exception))
        self.assertEqual(clients.calls, [])  # refused before any client
        with open(path, "rb") as fp:
            self.assertEqual(fp.read(), before)

    def test_force_without_live_heals_without_probing(self):
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        clients = FakeClients(probe=FakeClient(), login=FakeClient())
        login = FakeLogin()
        report = run(
            heal_session(
                path,
                passkey_path=passkey,
                session_format="pyrogram-string",
                force=True,
                probe=dead_probe,  # must not be called
                client_factory=clients,
                login=login,
            )
        )
        self.assertEqual(report["action"], "healed")
        self.assertFalse(report["probe"]["performed"])
        self.assertEqual(clients.kinds, ["login"])

    def test_inconclusive_probe_refuses_unless_forced(self):
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        with self.assertRaises(HealRefusal) as ctx:
            run(
                heal_session(
                    path,
                    session_format="pyrogram-string",
                    passkey_path=passkey,
                    live=True,
                    probe=broken_probe,
                    client_factory=FakeClients(probe=FakeClient(), login=FakeClient()),
                    login=FakeLogin(),
                )
            )
        self.assertIn("--force", str(ctx.exception))

        # ... and --force gets past it
        clients = FakeClients(probe=FakeClient(), login=FakeClient())
        report = run(
            heal_session(
                path,
                passkey_path=passkey,
                session_format="pyrogram-string",
                live=True,
                force=True,
                probe=broken_probe,
                client_factory=clients,
                login=FakeLogin(),
            )
        )
        self.assertEqual(report["action"], "healed")
        self.assertIsNone(report["probe"]["alive"])

    def test_another_accounts_passkey_is_refused(self):
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp, user_id=USER_ID + 1)
        clients = FakeClients(probe=FakeClient(), login=FakeClient())
        with self.assertRaises(HealRefusal) as ctx:
            run(
                heal_session(
                    path,
                    session_format="pyrogram-string",
                    passkey_path=passkey,
                    force=True,
                    client_factory=clients,
                    login=FakeLogin(),
                )
            )
        message = str(ctx.exception)
        self.assertIn(str(USER_ID), message)
        self.assertIn(str(USER_ID + 1), message)
        self.assertEqual(clients.calls, [])

    def test_login_landing_on_another_account_is_refused(self):
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        with self.assertRaises(HealError) as ctx:
            run(
                heal_session(
                    path,
                    session_format="pyrogram-string",
                    passkey_path=passkey,
                    force=True,
                    client_factory=FakeClients(login=FakeClient()),
                    login=FakeLogin(me=SimpleNamespace(id=USER_ID + 5)),
                )
            )
        self.assertIn("refusing to write", str(ctx.exception))
        # the refusal happens before the rewrite: the file is still the old one
        self.assertEqual(self.read_back(path).auth_key, OLD_KEY)

    def test_tdata_target_is_refused(self):
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        with self.assertRaises(HealRefusal):
            run(
                heal_session(
                    path,
                    session_format="pyrogram-string",
                    passkey_path=passkey,
                    force=True,
                    to_format="tdata",
                    client_factory=FakeClients(login=FakeClient()),
                    login=FakeLogin(),
                )
            )
        with self.assertRaises(HealRefusal):
            write_session_atomically(session(), path, "tdata")

    def test_profile_target_needs_a_profile_source(self):
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        out = os.path.join(self.tmp, "healed.tgmint")
        with self.assertRaises(HealRefusal) as ctx:
            run(
                heal_session(
                    path,
                    passkey_path=passkey,
                    session_format="pyrogram-string",
                    force=True,
                    to_format="profile",
                    out=out,  # a format change needs --out since v1.18
                    client_factory=FakeClients(login=FakeClient()),
                    login=FakeLogin(),
                )
            )
        self.assertIn("profile seal", str(ctx.exception))
        self.assertFalse(os.path.exists(out))

    def test_a_format_change_without_out_is_refused(self):
        # converting in place would destroy the original format while the
        # file name kept claiming it
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        with open(path, "rb") as fp:
            before = fp.read()
        clients = FakeClients(login=FakeClient())
        with self.assertRaises(HealRefusal) as ctx:
            run(
                heal_session(
                    path,
                    passkey_path=passkey,
                    session_format="pyrogram-string",
                    force=True,
                    to_format="gramjs-string",
                    client_factory=clients,
                    login=FakeLogin(),
                )
            )
        self.assertIn("--out", str(ctx.exception))
        self.assertEqual(clients.calls, [])  # refused before any client
        with open(path, "rb") as fp:
            self.assertEqual(fp.read(), before)

    def test_a_format_change_with_out_writes_the_new_file_only(self):
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        with open(path, "rb") as fp:
            before = fp.read()
        out = os.path.join(self.tmp, "healed.gramjs")
        report = run(
            heal_session(
                path,
                passkey_path=passkey,
                session_format="pyrogram-string",
                force=True,
                to_format="gramjs-string",
                out=out,
                client_factory=FakeClients(login=FakeClient()),
                login=FakeLogin(),
            )
        )
        self.assertEqual(report["action"], "healed")
        self.assertEqual(report["output"], out)
        self.assertFalse(report["in_place"])
        self.assertEqual(gramjs.read_string(open(out, encoding="ascii").read()).auth_key, NEW_KEY)
        # the original format is untouched
        with open(path, "rb") as fp:
            self.assertEqual(fp.read(), before)

    def test_an_existing_out_is_refused(self):
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        out = os.path.join(self.tmp, "taken.gramjs")
        with open(out, "w", encoding="ascii") as fp:
            fp.write("keep me")
        with self.assertRaises(HealRefusal) as ctx:
            run(
                heal_session(
                    path,
                    passkey_path=passkey,
                    session_format="pyrogram-string",
                    force=True,
                    to_format="gramjs-string",
                    out=out,
                    client_factory=FakeClients(login=FakeClient()),
                    login=FakeLogin(),
                )
            )
        self.assertIn("already exists", str(ctx.exception))
        with open(out, encoding="ascii") as fp:
            self.assertEqual(fp.read(), "keep me")

    def test_missing_inputs(self):
        passkey = passkey_file(self.tmp)
        with self.assertRaises(FileNotFoundError):
            run(
                heal_session(
                    os.path.join(self.tmp, "gone.session"),
                    passkey_path=passkey,
                    force=True,
                )
            )
        path = session_file(self.tmp)
        with self.assertRaises(FileNotFoundError):
            run(
                heal_session(
                    path,
                    session_format="pyrogram-string",
                    passkey_path=os.path.join(self.tmp, "gone.passkey.json"),
                    force=True,
                )
            )

    def test_unusable_passkey_store(self):
        path = session_file(self.tmp)
        broken = os.path.join(self.tmp, "broken.passkey.json")
        with open(broken, "w", encoding="utf-8") as fp:
            fp.write("{not json")
        with self.assertRaises(HealError) as ctx:
            run(
                heal_session(
                    path,
                    passkey_path=broken,
                    session_format="pyrogram-string",
                    force=True,
                )
            )
        self.assertIn("not a usable passkey store", str(ctx.exception))


class RuntimeFailures(HealBase):
    def test_login_failure_is_a_runtime_error_not_a_refusal(self):
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        with self.assertRaises(HealError) as ctx:
            run(
                heal_session(
                    path,
                    session_format="pyrogram-string",
                    passkey_path=passkey,
                    force=True,
                    client_factory=FakeClients(login=FakeClient()),
                    login=FakeLogin(error=RuntimeError("server said no")),
                )
            )
        self.assertNotIsInstance(ctx.exception, HealRefusal)
        self.assertIn("server said no", str(ctx.exception))
        self.assertEqual(self.read_back(path).auth_key, OLD_KEY)

    def test_login_client_without_an_auth_key(self):
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        with self.assertRaises(HealError) as ctx:
            run(
                heal_session(
                    path,
                    session_format="pyrogram-string",
                    passkey_path=passkey,
                    force=True,
                    client_factory=FakeClients(
                        login=FakeClient(session=FakeSession(without_key=True))
                    ),
                    login=FakeLogin(),
                )
            )
        self.assertIn("auth key", str(ctx.exception))


class Identity(HealBase):
    def test_recorded_fingerprint_is_reused(self):
        from tgmint.fingerprint import Fingerprint

        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        recorded = Fingerprint(
            api_id=2049,
            api_hash="0123456789abcdef0123456789abcdef",
            device_model="RecordedPC",
            system_version="Windows 10",
            app_version="5.4.1 x64",
            lang_code="en",
            system_lang_code="en-US",
            lang_pack="tdesktop",
            origin="tdesktop",
        )
        from tgmint.sidecar import sidecar_path_for

        sidecar = sidecar_path_for(path)
        recorded.save(str(sidecar))

        clients = FakeClients(login=FakeClient())
        report = run(
            heal_session(
                path,
                passkey_path=passkey,
                session_format="pyrogram-string",
                force=True,
                client_factory=clients,
                login=FakeLogin(),
            )
        )
        self.assertEqual(report["identity"]["source"], "recorded")
        self.assertEqual(report["identity"]["path"], str(sidecar))
        self.assertEqual(clients.calls[0]["api"].device_model, "RecordedPC")
        self.assertEqual(clients.calls[0]["api"].api_id, 2049)

    def test_minted_identity_when_nothing_is_recorded(self):
        from tgmint.api import API

        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        clients = FakeClients(login=FakeClient())
        report = run(
            heal_session(
                path,
                passkey_path=passkey,
                session_format="pyrogram-string",
                force=True,
                api_preset="android",
                client_factory=clients,
                login=FakeLogin(),
            )
        )
        self.assertEqual(report["identity"]["source"], "minted")
        self.assertIsNone(report["identity"]["path"])
        self.assertEqual(clients.calls[0]["api"].api_id, API.TelegramAndroid.api_id)

    def test_unknown_preset_is_refused(self):
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        with self.assertRaises(HealRefusal):
            run(
                heal_session(
                    path,
                    session_format="pyrogram-string",
                    passkey_path=passkey,
                    force=True,
                    api_preset="web",
                    client_factory=FakeClients(login=FakeClient()),
                    login=FakeLogin(),
                )
            )


class EnvelopeSource(HealBase):
    def _profile(self, passphrase="pw"):
        path = os.path.join(self.tmp, "acct.tgmint")
        from tests.test_profile import fingerprint, passkey_store

        write_profile(
            seal(
                session(dc_id=DC_ID),
                "pyrogram-string",
                fingerprint=fingerprint(),
                passkey=passkey_store(),
                passphrase=passphrase,
            ),
            path,
        )
        return path

    def test_envelope_is_rewritten_as_an_envelope(self):
        path = self._profile()
        passkey = passkey_file(self.tmp)
        report = run(
            heal_session(
                path,
                passkey_path=passkey,
                passphrase="pw",
                force=True,
                client_factory=FakeClients(login=FakeClient()),
                login=FakeLogin(),
            )
        )
        self.assertEqual(report["session_format"], "profile")
        self.assertEqual(report["to_format"], "profile")
        self.assertEqual(report["identity"]["source"], "recorded")

        opened = open_profile(path, passphrase="pw")
        self.assertEqual(opened.session.auth_key, NEW_KEY)
        self.assertIsNotNone(opened.fingerprint)  # identity survived
        self.assertIsNotNone(opened.passkey)  # recovery material survived
        self.assertTrue(opened.sealed)
        self.assertIn("healed", opened.meta["note"])

    def test_envelope_can_be_downgraded_to_a_plain_session(self):
        path = self._profile()
        passkey = passkey_file(self.tmp)
        out = os.path.join(self.tmp, "healed.string")
        run(
            heal_session(
                path,
                passkey_path=passkey,
                passphrase="pw",
                force=True,
                to_format="telethon-string",
                out=out,  # a format change never happens in place
                client_factory=FakeClients(login=FakeClient()),
                login=FakeLogin(),
            )
        )
        fresh = codec.read_session(out, "telethon-string")
        self.assertEqual(fresh.auth_key, NEW_KEY)
        # the envelope itself was not touched
        self.assertEqual(open_profile(path, passphrase="pw").session.auth_key, OLD_KEY)


class SymlinkedSession(HealBase):
    """os.replace on a link replaces the LINK.

    The heal must refuse a symlinked session instead of reporting
    "healed" while the real file keeps the dead auth key.
    """

    def _link(self):
        target = session_file(self.tmp, "telethon-string")
        link = os.path.join(self.tmp, "linked.string")
        os.symlink(target, link)
        return target, link

    def test_a_symlinked_session_is_refused_before_any_client(self):
        target, link = self._link()
        passkey = passkey_file(self.tmp)
        with open(target, "rb") as fp:
            before = fp.read()
        clients = FakeClients(probe=FakeClient(), login=FakeClient())
        with self.assertRaises(HealRefusal) as ctx:
            run(
                heal_session(
                    link,
                    passkey_path=passkey,
                    session_format="telethon-string",
                    live=True,
                    force=True,
                    probe=dead_probe,
                    client_factory=clients,
                    login=FakeLogin(),
                )
            )
        message = str(ctx.exception)
        self.assertIn("symlink", message)
        self.assertIn("linked.string", message)
        self.assertEqual(clients.calls, [])  # refused before the probe/login
        # the link is still a link and the target still holds the old key
        self.assertTrue(os.path.islink(link))
        with open(target, "rb") as fp:
            self.assertEqual(fp.read(), before)

    def test_write_session_atomically_refuses_a_symlink(self):
        _target, link = self._link()
        with self.assertRaises(HealRefusal) as ctx:
            write_session_atomically(session(), link, "telethon-string")
        self.assertIn("symlink", str(ctx.exception))

    def test_a_symlinked_out_is_refused(self):
        path = session_file(self.tmp)
        passkey = passkey_file(self.tmp)
        real_out = os.path.join(self.tmp, "real.string")
        with open(real_out, "w", encoding="ascii") as fp:
            fp.write("keep me")
        link_out = os.path.join(self.tmp, "out.link")
        os.symlink(real_out, link_out)
        with self.assertRaises(HealRefusal) as ctx:
            run(
                heal_session(
                    path,
                    passkey_path=passkey,
                    session_format="telethon-string",
                    force=True,
                    out=link_out,
                    client_factory=FakeClients(login=FakeClient()),
                    login=FakeLogin(),
                )
            )
        self.assertIn("symlink", str(ctx.exception))
        with open(real_out, encoding="ascii") as fp:
            self.assertEqual(fp.read(), "keep me")


class PlaceholderHonesty(HealBase):
    """the placeholder the file really holds.

    ``pyrogram-string`` needs a ``user_id`` and a session with none gets
    777000 written into it, with the codec saying so.  Heal used to throw
    that result away — file says 777000, report says ``user_id: None``,
    ``notes: []``.  Both halves are pinned here: the writer reports it,
    and the heal report carries it through.
    """

    def test_the_writer_reports_the_placeholder(self):
        from tgmint.heal import _write_session_atomically

        out = os.path.join(self.tmp, "written.pyro")
        result = _write_session_atomically(
            SessionData(dc_id=DC_ID, auth_key=NEW_KEY), out, "pyrogram-string"
        )
        # both placeholders the destination format needs are reported
        self.assertEqual(result["filled"], ["user_id", "api_id"])
        self.assertTrue(any("placeholder" in note for note in result["notes"]))
        self.assertTrue(any("api_id" in note for note in result["notes"]))
        self.assertEqual(result["output"], out)
        self.assertEqual(codec.read_session(out, "pyrogram-string").user_id, 777000)

    def test_the_heal_report_surfaces_the_codec_filled_and_notes(self):
        # a store the login can't improve on: heal never invents an id, so
        # the placeholder path is the codec's — the report must carry it
        path = session_file(self.tmp, "telethon-string")
        passkey = passkey_file(self.tmp)
        out = os.path.join(self.tmp, "healed.pyro")
        real = codec.write_session

        def fake_write(data, destination, destination_format, **kwargs):
            result = real(data, destination, destination_format, **kwargs)
            result["filled"] = ["user_id"]
            result["notes"] = [
                "user_id: an in-memory session stores none; wrote placeholder "
                "777000 — the destination client learns the real id from the "
                "server on first connect"
            ]
            result["user_id"] = 777000
            return result

        with mock.patch.object(codec, "write_session", side_effect=fake_write):
            report = run(
                heal_session(
                    path,
                    passkey_path=passkey,
                    session_format="telethon-string",
                    force=True,
                    to_format="pyrogram-string",
                    out=out,
                    client_factory=FakeClients(login=FakeClient()),
                    login=FakeLogin(),
                )
            )
        self.assertEqual(report["action"], "healed")
        self.assertEqual(report["filled"], ["user_id"])
        self.assertTrue(report["new"]["user_id_is_placeholder"])
        self.assertEqual(report["new"]["user_id"], 777000)
        self.assertTrue(
            any("placeholder" in note for note in report["notes"]), report["notes"]
        )

    def test_a_known_user_id_is_not_replaced_by_a_placeholder(self):
        path = session_file(self.tmp, "pyrogram-string")
        passkey = passkey_file(self.tmp)
        out = os.path.join(self.tmp, "healed.pyro")
        report = run(
            heal_session(
                path,
                passkey_path=passkey,
                session_format="pyrogram-string",
                force=True,
                to_format="pyrogram-string",
                out=out,
                client_factory=FakeClients(login=FakeClient()),
                login=FakeLogin(),
            )
        )
        self.assertEqual(report["filled"], [])
        self.assertEqual(report["new"]["user_id"], USER_ID)
        self.assertNotIn("user_id_is_placeholder", report["new"])


class StalenessGuard(HealBase):
    """the read→login→replace window."""

    def test_a_session_changed_mid_heal_is_not_overwritten(self):
        path = session_file(self.tmp, "telethon-string")
        passkey = passkey_file(self.tmp)

        class MutatingLogin(FakeLogin):
            """Rewrites the session file between the read and the write."""

            async def __call__(self, client, *, passkey_path, password=None):
                with open(path, "wb") as fp:
                    fp.write(b"someone else wrote here")
                return await super().__call__(
                    client, passkey_path=passkey_path, password=password
                )

        with self.assertRaises(HealRefusal) as ctx:
            run(
                heal_session(
                    path,
                    passkey_path=passkey,
                    session_format="telethon-string",
                    force=True,
                    client_factory=FakeClients(login=FakeClient()),
                    login=MutatingLogin(),
                )
            )
        self.assertIn("changed", str(ctx.exception))
        with open(path, "rb") as fp:
            self.assertEqual(fp.read(), b"someone else wrote here")


class ProbeClassification(unittest.TestCase):
    def test_dead_auth_errors_are_recognized_by_name(self):
        class AuthKeyUnregisteredError(Exception):
            pass

        class ConnectionReset(Exception):
            pass

        self.assertTrue(is_dead_auth_error(AuthKeyUnregisteredError("x")))
        self.assertFalse(is_dead_auth_error(ConnectionReset("x")))

    def test_probe_reports_alive(self):
        result = run(probe_session(FakeClient()))
        self.assertTrue(result["alive"])
        self.assertFalse(result["dead"])
        self.assertEqual(result["user_id"], USER_ID)

    def test_probe_reports_death(self):
        result = run(probe_session(FakeClient(error=DeadAuthKey("gone"))))
        self.assertFalse(result["alive"])
        self.assertTrue(result["dead"])
        self.assertIn("auth key", result["reason"])

    def test_probe_reports_an_inconclusive_failure(self):
        result = run(probe_session(FakeClient(error=ConnectionResetError("no wifi"))))
        self.assertIsNone(result["alive"])
        self.assertFalse(result["dead"])
        self.assertIn("non-auth", result["reason"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
