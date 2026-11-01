"""tgmint.cadence - the official keepalive cadence, and what a client can set.

Official clients ping on their own schedule, and the frameworks tgmint supports
hardcode a different one.  That mismatch is one of the loudest "not the real
app" tells left after the fingerprint, the layer and the startup batch are
right, so this module carries the official numbers as data plus the smallest
honest way to ask a client to use them.

The two shipped numbers are read out of first-party source, not guessed:

* **Android 12.10.6** - ``PingDelayDisconnect`` every 19 s (the 19000 ms guard
  in ``TMessagesProj/jni/tgnet/ConnectionsManager.cpp:295``) with
  ``disconnect_delay = 35`` (same file, ``:1786``).
* **Desktop 7.3.3** - every 30 s with a 60 s disconnect delay
  (``Telegram/SourceFiles/mtproto/session_private.cpp:40-42``:
  ``kPingDelayDisconnect = 60`` and ``kPingSendAfter = 30 * crl::time(1000)``;
  ``kPingSendAfterForce = 45`` s is the force flag, not the steady state).

What the frameworks do instead (read out of the installed code, see the
``source`` field of every knob in :data:`_KNOBS`):

======================================  ====================================
framework                               keepalive as shipped
======================================  ====================================
Telethon 1.43.2                         plain ``PING`` every 60 s
                                        (``client/updates.py:516-548``, the
                                        ``timeout=60`` at ``:522``)
kurigram / Pyrogram 2.2.26              ``PING_DELAY_DISCONNECT`` every 5 s
                                        with ``disconnect_delay`` 25 s
                                        (``pyrogram/session/session.py:466``
                                        and ``:476``, ``WAIT_TIMEOUT + 10``)
======================================  ====================================

Guardrails (hard, not configurable)
-----------------------------------

* **pure until asked.**  :func:`target` and :func:`describe` import no
  framework, open no socket and never touch a client, and nothing here runs on
  import.  :func:`apply` is the only function that writes.
* **``dry_run`` reports, never mutates.**  Every number :func:`apply` reports
  with ``dry_run=True`` is the number it would write.
* **instance scope only.**  Nothing patches a class or a module global that a
  second client in the same process would inherit: Telethon's keepalive loop
  is replaced *on the instance* (which shadows the class method for that
  client only) and Pyrogram's interval is an *instance* attribute on the
  ``Session`` object (which shadows ``Session.PING_INTERVAL``).  Restore is
  :func:`restore`.
* **verified or refused.**  Telethon's 60 s is a literal inside the loop body,
  so the only way to change it is to replace the loop; :func:`apply` first
  proves it is looking at the loop it knows (marker strings + the literal
  itself, via :func:`_telethon_loop_interval`) and reports
  ``unsupported`` instead of blindly patching a version it does not
  recognise.
* **never ``wait_timeout``.**  ``disconnect_delay`` on the Pyrogram side is
  derived inside ``ping_worker`` as ``WAIT_TIMEOUT + 10``, and
  ``WAIT_TIMEOUT`` is also the request-timeout knob (it gates ``invoke()``'s
  startup wait and is the documented default of ``send``/``invoke``), so tgmint
  will not touch it.  The derived 25 s stays and is reported as
  ``unsupported`` with the reason.
* **no claim of safety.**  Matching the ping cadence removes *one* signal out
  of many.  It is not ban evasion, it does not make an account invisible, and
  tgmint does not sell it as either; see ``docs/cadence.md``.

Verification status (honest)
----------------------------

* **Verified offline** (``tests/test_cadence.py``): the shipped numbers and
  their sources, the alias/platform errors, :func:`describe` purity and JSON
  shape, ``apply`` against a real ``TelegramClient`` (instance shadowing only,
  class untouched, :func:`restore` puts it back), a fake Pyrogram-family client
  with ``_session`` / ``session`` / ``sessions``, ``dry_run`` mutating nothing,
  and the refusal paths (unknown platform, undetectable family, an
  unrecognised Telethon loop, a Pyrogram client that is not connected yet).
* **Verified live** (2026-11-01, own test accounts): Telethon at 19 s keeps a connection
  open with pings at 19.0 / 38.0 s. The Pyrogram family at the official 19 s
  used to reconnect every ~10 s, but the closer was **the framework, not
  Telegram**: ``TCP._recv_from_socket`` waits ``TCP.TIMEOUT = 10`` s for the
  next *inbound* byte and ``recv_worker`` treats the resulting ``None`` as a
  server close. ``apply`` now rebinds that read with
  :func:`pyrogram_read_timeout` before the first read (through the client's
  ``connection_factory``, so reconnects get it too) and rewrites the outgoing
  ``PingDelayDisconnect`` to the official ``disconnect_delay`` (the server
  enforces it; the framework hardcodes ``WAIT_TIMEOUT + 10``). Verified live
  afterwards: one reconnect at apply time (the read already in flight keeps
  the old timeout), then pings at 19.0-19.1 s intervals for 100 s on Android
  and 30 s intervals on desktop, each with the official delay.
* **NOT verified**: that the server *notices* the cadence difference. Both
  official numbers are reconstructed from the client source; whether a 19 s
  phone looks more like a phone than a 60 s one is a hypothesis, and the only
  honest test is an owner's own account over time.

The module is stdlib-only (``typing`` / ``dataclasses`` / ``inspect`` /
``re`` / ``asyncio`` / ``random``), imports Telethon and Pyrogram nowhere, and
takes the pinned client
versions from :data:`tgmint.bootstrap.CLIENT_VERSIONS` so there is one version
table in the package rather than two.
"""

from __future__ import annotations

import asyncio
import inspect
import random
import re
import types
import typing
from dataclasses import dataclass

from .bootstrap import CLIENT_VERSIONS, BootstrapError, platform_for

__all__ = [
    "CLIENT_VERSIONS",
    "FRAMEWORKS",
    "PING_CADENCE",
    "PLATFORMS",
    "PYROGRAM_DISCONNECT_DELAY",
    "PYROGRAM_PING_INTERVAL",
    "PYROGRAM_REQUEST_TIMEOUT",
    "PYROGRAM_READ_TIMEOUT_MARGIN",
    "PYROGRAM_MIN_READ_TIMEOUT",
    "pyrogram_read_timeout",
    "PingCadence",
    "TELETHON_PING_INTERVAL",
    "CadenceError",
    "apply",
    "describe",
    "restore",
    "target",
]


class CadenceError(Exception):
    """The cadence cannot be reported or applied as asked."""


#: Platforms with a source-verified cadence.  iOS, macOS and the web clients
#: are named in :data:`_UNSUPPORTED` with the reason instead of being silently
#: treated as "like Android".
PLATFORMS: typing.Tuple[str, ...] = ("android", "desktop")

#: The client families :func:`apply` knows how to drive.
FRAMEWORKS: typing.Tuple[str, ...] = ("telethon", "pyrogram")


# ---------------------------------------------------------------------------
# the official data
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PingCadence:
    """One official client's keepalive, as the source states it.

    Attributes:
        ping_interval: seconds between keepalives.
        disconnect_delay: the ``disconnect_delay`` the client puts in its
            ``ping_delay_disconnect`` (seconds; the server drops the
            connection after that long without a ping).
        source: ``path:line`` in the official tree this was read from, with
            the version, so the number can be re-checked instead of trusted.
    """

    ping_interval: float
    disconnect_delay: int
    source: str

    def as_dict(self) -> typing.Dict[str, typing.Any]:
        """Plain-data form (JSON friendly, used by :func:`describe`)."""
        return {
            "ping_interval": self.ping_interval,
            "disconnect_delay": self.disconnect_delay,
            "source": self.source,
        }


PING_CADENCE: typing.Dict[str, PingCadence] = {
    "android": PingCadence(
        ping_interval=19.0,
        disconnect_delay=35,
        source=(
            "TMessagesProj/jni/tgnet/ConnectionsManager.cpp:295,1786 "
            "(DrKLO/Telegram 12.10.6)"
        ),
    ),
    "desktop": PingCadence(
        ping_interval=30.0,
        disconnect_delay=60,
        source=(
            "Telegram/SourceFiles/mtproto/session_private.cpp:40-42 "
            "(tdesktop 7.3.3)"
        ),
    ),
}

#: framework -> keepalive the framework ships with, for reporting only.  The
#: values are re-read from the installed packages by the tests when they are
#: importable, so a framework bump that changes its default fails loudly
#: instead of quietly making this table a lie.
TELETHON_PING_INTERVAL = 60.0
PYROGRAM_PING_INTERVAL = 5.0
PYROGRAM_REQUEST_TIMEOUT = 15.0
PYROGRAM_DISCONNECT_DELAY = PYROGRAM_REQUEST_TIMEOUT + 10  # WAIT_TIMEOUT + 10

#: Seconds added on top of ``2 x ping_interval`` for the Pyrogram-family
#: socket read timeout a patched connection gets, and its floor.
#:
#: The framework's transport hardcodes ``TCP.TIMEOUT = 10`` for every
#: ``reader.read()``; a session whose next inbound packet is more than 10 s
#: away closes *itself* (``recv_worker`` treats the timeout ``None`` as a
#: "null packet" and restarts).  That was the real cause of the "19 s breaks
#: kurigram" observation on 2026-11-01 — not a server policy.  :func:`apply`
#: rebinds the read method with this patient timeout so the official interval
#: (19 s / 30 s) fits, while a genuinely dead link is still noticed.
PYROGRAM_READ_TIMEOUT_MARGIN = 7
PYROGRAM_MIN_READ_TIMEOUT = 25.0


def pyrogram_read_timeout(ping_interval: float) -> float:
    """Socket read timeout for a Pyrogram connection that pings every `ping_interval`."""
    return max(PYROGRAM_MIN_READ_TIMEOUT, 2.0 * ping_interval + PYROGRAM_READ_TIMEOUT_MARGIN)


#: spelling -> platform key (the same aliases :mod:`tgmint.bootstrap` accepts)
_ALIASES: typing.Dict[str, str] = {
    "android": "android",
    "android_x": "android",
    "androidx": "android",
    "desktop": "desktop",
    "tdesktop": "desktop",
}

#: platform -> why there is no number (asked for by name, never invented)
_UNSUPPORTED: typing.Dict[str, str] = {
    "ios": (
        "no keepalive cadence has been read out of the iOS tree yet (the "
        "Android and Desktop numbers are file:line verified, the Apple ones "
        "are not)"
    ),
    "macos": (
        "no keepalive cadence has been read out of the macOS tree yet (see "
        "'ios' for the same reason)"
    ),
    "web": (
        "the web clients (webk/webz) are not covered: their cadence lives in "
        "a bundled transport, not in a source file this project can cite"
    ),
    "webk": (
        "the web clients (webk/webz) are not covered: their cadence lives in "
        "a bundled transport, not in a source file this project can cite"
    ),
    "webz": (
        "the web clients (webk/webz) are not covered: their cadence lives in "
        "a bundled transport, not in a source file this project can cite"
    ),
}


def _normalize_platform(platform: str) -> str:
    """Map an alias to a platform key, or raise :class:`CadenceError`."""
    if not isinstance(platform, str):
        raise CadenceError(f"platform must be a string, got {platform!r}")
    key = platform.strip().lower()
    if key in _ALIASES:
        return _ALIASES[key]
    if key in _UNSUPPORTED:
        raise CadenceError(f"no verified cadence for {key} yet: {_UNSUPPORTED[key]}")
    raise CadenceError(
        f"unknown platform {platform!r}; expected one of {list(PLATFORMS)}"
    )


def target(platform: str) -> PingCadence:
    """The official cadence for `platform` (pure: no client, no network).

    ``platform`` accepts the aliases the rest of the package uses
    (``"android_x"`` / ``"tdesktop"``, case and surrounding spaces ignored).

    Raises:
        CadenceError: unknown platform, or a family with no verified numbers
            (``ios``, ``macos``, the web clients) — the message says which.
    """
    return PING_CADENCE[_normalize_platform(platform)]


# ---------------------------------------------------------------------------
# what each framework can actually be told
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Knob:
    """One settable-or-not knob on one framework, with the evidence."""

    framework: str
    knob: str
    attribute: str
    scope: str
    framework_default: typing.Optional[float]
    settable: bool
    reason: str
    source: str

    def as_dict(self) -> typing.Dict[str, typing.Any]:
        """Plain-data form (JSON friendly, used by :func:`describe`)."""
        return {
            "settable": self.settable,
            "framework_default": self.framework_default,
            "attribute": self.attribute,
            "scope": self.scope,
            "reason": self.reason,
            "source": self.source,
        }


_TELETHON_PING = _Knob(
    framework="telethon",
    knob="ping_interval",
    attribute="client._keepalive_loop",
    scope="instance (shadows the class method for this client only)",
    framework_default=TELETHON_PING_INTERVAL,
    settable=True,
    reason=(
        "Telethon has no interval attribute: 60 is a literal in the keepalive "
        "loop body, so the loop itself is replaced on the instance, before "
        "connect() creates the task. A version whose loop does not match the "
        "one tgmint recognises is reported unsupported instead of patched."
    ),
    source=(
        "telethon/client/updates.py:516-548 (_keepalive_loop, timeout=60 at "
        ":522); the task is created at telethon/client/telegrambaseclient.py:619"
    ),
)

_TELETHON_DISCONNECT = _Knob(
    framework="telethon",
    knob="disconnect_delay",
    attribute="",
    scope="",
    framework_default=None,
    settable=False,
    reason=(
        "Telethon never sends ping_delay_disconnect: its keepalive is a plain "
        "PING (ping#7abe77ec), which has no disconnect_delay field at all. "
        "There is no value to set, not even a wrong one, and sending the "
        "official method would mean replacing every ping the library makes."
    ),
    source=(
        "telethon/network/mtprotosender.py:438-448 "
        "(_keepalive_ping -> PingRequest)"
    ),
)

_PYROGRAM_PING = _Knob(
    framework="pyrogram",
    knob="ping_interval",
    attribute="Session.PING_INTERVAL",
    scope="instance attribute on the Session object (shadows the class default)",
    framework_default=PYROGRAM_PING_INTERVAL,
    settable=True,
    reason=(
        "ping_worker re-reads self.PING_INTERVAL on every tick, so an instance "
        "attribute takes effect at the next ping — no reconnect and no "
        "monkey-patching. The class value is left alone."
    ),
    source=(
        ".pytestbox/pyrogram/session/session.py:93 (PING_INTERVAL = 5), read at "
        ":466 (ping_worker); same file in kurigram 2.2.26"
    ),
)

_PYROGRAM_DISCONNECT = _Knob(
    framework="pyrogram",
    knob="disconnect_delay",
    attribute="Session.send (PingDelayDisconnect rewrite)",
    scope="instance wrapper on the Session object (WAIT_TIMEOUT untouched)",
    framework_default=PYROGRAM_DISCONNECT_DELAY,
    settable=True,
    reason=(
        "ping_worker hardcodes disconnect_delay=self.WAIT_TIMEOUT + 10, and "
        "WAIT_TIMEOUT also gates request timeouts, so tgmint does not touch it: "
        "it wraps Session.send and rewrites the outgoing PingDelayDisconnect's "
        "disconnect_delay to the official value instead. The server enforces "
        "that delay (a FIN lands delay seconds after the last packet), so it "
        "must be >= the ping interval."
    ),
    source=(
        ".pytestbox/pyrogram/session/session.py:89 (WAIT_TIMEOUT = 15), :476 "
        "(the hardcoded +10)"
    ),
)

#: every knob the module knows about, in reporting order
_KNOBS: typing.Tuple[_Knob, ...] = (
    _TELETHON_PING,
    _TELETHON_DISCONNECT,
    _PYROGRAM_PING,
    _PYROGRAM_DISCONNECT,
)


def _knob(framework: str, knob: str) -> _Knob:
    """Look one knob up by (framework, name)."""
    for entry in _KNOBS:
        if entry.framework == framework and entry.knob == knob:
            return entry
    raise CadenceError(  # pragma: no cover - table bug
        f"no cadence knob {knob!r} for framework {framework!r}"
    )


def _refused(
    knob: _Knob,
    official: typing.Union[float, int],
    reason: typing.Optional[str] = None,
) -> typing.Dict[str, typing.Any]:
    """The ``unsupported`` entry for a knob: describe's fields plus the target.

    Same shape as a :func:`describe` knob entry (``settable`` / ``attribute`` /
    ``scope`` / ``reason`` / ``source``) with ``official`` added, so a report
    consumer parses one shape, not two.
    """
    entry = dict(knob.as_dict())
    entry["official"] = official
    if reason is not None:
        entry["reason"] = reason
    return entry


def describe(platform: str) -> typing.Dict[str, typing.Any]:
    """The official cadence next to what each framework can be told (pure).

    Returns a JSON-friendly dict: ``platform``, ``client_version``,
    ``official`` (the three :class:`PingCadence` fields) and ``frameworks``
    (framework -> knob -> ``settable`` / ``framework_default`` /
    ``attribute`` / ``scope`` / ``reason`` / ``source``).

    Imports no framework and never touches a client: this is what
    ``tgmint cadence`` prints, and it is the honest version of "what would
    :func:`apply` change".
    """
    key = _normalize_platform(platform)
    frameworks: typing.Dict[str, typing.Dict[str, typing.Any]] = {}
    for name in FRAMEWORKS:
        frameworks[name] = {
            entry.knob: entry.as_dict() for entry in _KNOBS if entry.framework == name
        }
    # the Pyrogram family cannot hold the official interval (live finding):
    # report the cap next to the interval it would otherwise have to reach
    plan = _pyrogram_plan(PING_CADENCE[key])
    frameworks["pyrogram"]["ping_interval"]["applied_value"] = plan["ping_interval"]
    frameworks["pyrogram"]["ping_interval"]["socket_read_timeout"] = plan[
        "socket_read_timeout"
    ]
    frameworks["pyrogram"]["disconnect_delay"]["applied_value"] = plan[
        "disconnect_delay"
    ]
    return {
        "platform": key,
        "client_version": CLIENT_VERSIONS[key],
        "official": PING_CADENCE[key].as_dict(),
        "frameworks": frameworks,
    }


# ---------------------------------------------------------------------------
# client detection
# ---------------------------------------------------------------------------

#: every marker :func:`_make_telethon_loop` relies on.  If telethon's loop no
#: longer contains them, the copy would be a different loop with the same name
#: — that is a refuse, not a guess.
_TELETHON_LOOP_MARKERS: typing.Tuple[str, ...] = (
    "asyncio.wait_for",
    "self.disconnected",
    "_clean_exported_senders",
    "_transport_connected",
    "_keepalive_ping",
    "_save_states_and_entities",
    "session.save",
)

#: the interval literal inside that loop
_INTERVAL_RE = re.compile(r"timeout=(\d+(?:\.\d+)?)")

#: instance attribute :func:`apply` uses to remember what it changed
_MARK = "_tgmint_cadence"

#: where a fingerprint might ride along on a client, in lookup order.  tgmint
#: does not attach one itself (``heal``/``bootstrap`` build clients from a
#: sidecar), so this is a convenience for callers that do — and a clear error
#: when nobody does.
_FINGERPRINT_ATTRS: typing.Tuple[str, ...] = (
    "_tgmint_fingerprint",
    "tgmint_fingerprint",
    "fingerprint",
    "api_data",
    "_api_data",
    "api",
)


def _is_pyrogram_session(obj: typing.Any) -> bool:
    """True for a Pyrogram-family ``Session`` (the thing with ``ping_worker``)."""
    if obj is None:
        return False
    try:
        if not hasattr(obj, "PING_INTERVAL"):
            return False
        return hasattr(obj, "ping_worker") or hasattr(type(obj), "ping_worker")
    except Exception:  # pragma: no cover - hostile object
        return False


def _pyrogram_sessions(client: typing.Any) -> typing.List[typing.Any]:
    """Every Pyrogram ``Session`` object reachable from `client`.

    Kurigram 2.2.26 keeps the main-DC session in ``client.session`` (and
    ``client._session`` in some forks/older builds), other DCs in
    ``client.sessions`` and media sessions in ``client.media_sessions``.  Each
    object owns its own ``ping_worker``, so each one is patched.
    """
    found: typing.List[typing.Any] = []
    seen: typing.Set[int] = set()

    def add(obj: typing.Any) -> None:
        if not _is_pyrogram_session(obj) or id(obj) in seen:
            return
        seen.add(id(obj))
        found.append(obj)

    add(getattr(client, "_session", None))
    add(getattr(client, "session", None))
    for name in ("sessions", "media_sessions"):
        mapping = getattr(client, name, None)
        if isinstance(mapping, dict):
            for value in list(mapping.values()):
                add(value)
    add(client)  # someone passed the Session itself: still a thing we can set
    return found


def _detect(client: typing.Any) -> typing.Tuple[str, typing.List[typing.Any]]:
    """``(family, pyrogram_sessions)`` for `client`, or raise :class:`CadenceError`."""
    if client is None:
        raise CadenceError(
            "apply() needs a client: pass a connected telegram client (Telethon "
            "or the Pyrogram family), not None"
        )

    try:
        has_loop = hasattr(client, "_keepalive_loop")
    except Exception:  # pragma: no cover - hostile object
        has_loop = False
    if has_loop and hasattr(client, "is_connected"):
        return "telethon", []

    sessions = _pyrogram_sessions(client)
    if sessions:
        return "pyrogram", sessions

    # nothing detectable: say which of the two usual reasons it is
    looks_pyrogram = any(
        hasattr(client, name) for name in ("session", "sessions", "media_sessions")
    )
    if looks_pyrogram:
        raise CadenceError(
            "this looks like a Pyrogram client with no Session object yet: the "
            "Session (and its ping worker) only exists once the client is "
            "connected, so call apply() after 'await client.connect()' (or "
            "start()), or pass a client that is already running"
        )
    raise CadenceError(
        "cannot detect the client family: no Telethon keepalive loop "
        "(_keepalive_loop) and no Pyrogram Session (PING_INTERVAL + ping_worker) "
        "found on this object; tgmint.cadence only drives those two families"
    )


def _platform_from_client(client: typing.Any) -> typing.Optional[str]:
    """The platform a client's fingerprint names, or None (pure)."""
    for name in _FINGERPRINT_ATTRS:
        value = getattr(client, name, None)
        if value is None:
            continue
        try:
            return platform_for(value)
        except BootstrapError:
            continue
        except Exception:  # pragma: no cover - hostile object
            continue
    return None


# ---------------------------------------------------------------------------
# telethon: replace the keepalive loop on the instance
# ---------------------------------------------------------------------------


def _telethon_loop_interval(original: typing.Any) -> typing.Optional[float]:
    """The interval hardcoded in Telethon's keepalive loop, or None.

    None means "this is not the loop tgmint knows" (or the source is not
    available) — :func:`apply` refuses rather than guess.
    """
    if not inspect.iscoroutinefunction(original):
        return None
    try:
        source = inspect.getsource(original)
    except (OSError, TypeError):  # pragma: no cover - no source on disk
        return None
    if any(marker not in source for marker in _TELETHON_LOOP_MARKERS):
        return None
    found = _INTERVAL_RE.search(source)
    return float(found.group(1)) if found else None


def _make_telethon_loop(
    client: typing.Any, interval: float
) -> typing.Callable[[], typing.Coroutine[typing.Any, typing.Any, None]]:
    """A copy of Telethon's ``_keepalive_loop`` whose tick is `interval`.

    The body mirrors ``telethon/client/updates.py:516-548`` step for step
    (exported-sender cleanup, transport check, keepalive ping, entity/state
    flush) — :func:`_telethon_loop_interval` has already proved that file
    is the one this copy was written against.  ``asyncio`` / ``random`` come from
    the original function's own globals, so the copy cannot drift onto a
    different module instance than the library uses.  The returned function
    takes no ``self``: it closes over `client` and is stored as an *instance*
    attribute, where Python does not bind it.
    """
    original = getattr(type(client), "_keepalive_loop", None)
    namespace = getattr(original, "__globals__", None) or {}
    asyncio_module = namespace.get("asyncio") or asyncio
    random_module = namespace.get("random") or random

    async def keepalive_loop() -> None:
        # "Pings' ID don't really need to be secure, just random" (telethon)
        def rnd() -> int:
            return random_module.randrange(-2 ** 63, 2 ** 63)

        while client.is_connected():
            try:
                await asyncio_module.wait_for(
                    client.disconnected, timeout=interval
                )
                continue  # we only want to act upon the timeout
            except asyncio_module.TimeoutError:
                pass
            except asyncio_module.CancelledError:
                return
            except Exception:
                continue  # any disconnected exception is ignored

            # periodic cleanup of borrowed (exported) senders
            await client._clean_exported_senders()

            # no pings until the low-level connection is ready, otherwise a
            # batch of them lands on the wire at reconnect
            if not client._sender._transport_connected():
                continue

            try:
                client._sender._keepalive_ping(rnd())
            except (ConnectionError, asyncio_module.CancelledError):
                return

            # entities and states are flushed on this tick, not on insert
            await client._save_states_and_entities()
            saved = client.session.save()
            if inspect.isawaitable(saved):
                await saved

    return keepalive_loop


def _apply_telethon(
    client: typing.Any, platform: str, cadence: PingCadence, dry_run: bool,
    notes: typing.List[str],
) -> typing.Dict[str, typing.Any]:
    """Set what Telethon allows, report what it does not."""
    applied: typing.Dict[str, typing.Any] = {}
    unsupported: typing.Dict[str, typing.Any] = {}

    original = getattr(type(client), "_keepalive_loop", None)
    was = _telethon_loop_interval(original)
    if was is None:
        knob = _knob("telethon", "ping_interval")
        unsupported["ping_interval"] = _refused(
            knob,
            cadence.ping_interval,
            reason=(
                "this Telethon's keepalive loop is not the one tgmint knows "
                "(its source does not contain the expected steps), so it was "
                "left untouched: replacing a loop tgmint cannot verify could "
                "break the client"
            ),
        )
        notes.append(
            "telethon: ping_interval left at its framework default; upgrade "
            "tgmint (or pin telethon 1.43.x) for a supported loop"
        )
    else:
        already = isinstance(getattr(client, _MARK, None), dict)
        live = bool(getattr(client, "is_connected", lambda: False)())
        if not dry_run:
            # a second apply() must not make the *first* patch look like the
            # caller's own attribute, so the original state is carried over
            previous = getattr(client, _MARK, None) if already else None
            dictionary = getattr(client, "__dict__", {})
            if isinstance(previous, dict):
                had_own = bool(previous.get("had_own"))
                previous_own = previous.get("previous_own")
            else:
                had_own = "_keepalive_loop" in dictionary
                previous_own = dictionary.get("_keepalive_loop")
            client._keepalive_loop = _make_telethon_loop(client, cadence.ping_interval)
            setattr(
                client,
                _MARK,
                {
                    "platform": platform,
                    "framework": "telethon",
                    "ping_interval": cadence.ping_interval,
                    "previous": was,
                    "had_own": had_own,
                    "previous_own": previous_own,
                    "already_patched": already,
                },
            )
        applied["ping_interval"] = {
            "value": cadence.ping_interval,
            "was": was,
            "attribute": "client._keepalive_loop",
            "scope": "instance (the class method is untouched)",
            "takes_effect": (
                "next connection: the task was created at connect(), so "
                "disconnect() and reconnect (or apply() before connect())"
                if live
                else "the next connect(), which creates the task from this attribute"
            ),
        }
        if live:
            notes.append(
                "telethon: the keepalive task is already running on this "
                "connection; the new interval applies from the next connect()"
            )
        if already and not dry_run:
            notes.append(
                "telethon: this client was already patched by tgmint.cadence; "
                "the loop was replaced again with the new interval"
            )

    unsupported["disconnect_delay"] = _refused(
        _knob("telethon", "disconnect_delay"), cadence.disconnect_delay
    )
    return {"applied": applied, "unsupported": unsupported}


# ---------------------------------------------------------------------------
# pyrogram family: set the instance attribute the worker re-reads
# ---------------------------------------------------------------------------


def _pyrogram_plan(
    cadence: PingCadence,
) -> typing.Dict[str, float]:
    """The three numbers :func:`_apply_pyrogram` writes, and the cap they imply."""
    read_timeout = pyrogram_read_timeout(cadence.ping_interval)
    pdd_delay = float(cadence.disconnect_delay)
    capped = min(cadence.ping_interval, read_timeout - 2.0, pdd_delay - 2.0)
    return {
        "ping_interval": capped,
        "requested": cadence.ping_interval,
        "socket_read_timeout": read_timeout,
        "disconnect_delay": pdd_delay,
    }


def _make_patient_recv(timeout: float) -> typing.Callable[..., typing.Coroutine]:
    """A copy of pyrogram's ``TCP._recv_from_socket`` with a configurable timeout.

    The framework's version uses ``timeout=TCP.TIMEOUT`` (10 s, hardcoded and
    resolved through the *class* name), and ``Session.recv_worker`` treats the
    resulting ``None`` as a server close and restarts.  Rebinding the method on
    the protocol *instance* is the only per-client fix (a subclass that only
    overrides ``TIMEOUT`` does nothing).
    """

    async def _recv_from_socket(self: typing.Any, length: int) -> typing.Optional[bytes]:
        if not self.reader:
            return None
        data = b""
        while len(data) < length:
            try:
                chunk = await asyncio.wait_for(
                    self.reader.read(length - len(data)), timeout=timeout
                )
            except asyncio.TimeoutError:
                return None
            except OSError:
                return None
            if not chunk:
                return None
            data += chunk
        return data

    return _recv_from_socket


def _proto_of(session: typing.Any) -> typing.Any:
    connection = getattr(session, "connection", None)
    return getattr(connection, "protocol", None) if connection is not None else None


def _bind_patient_recv(session: typing.Any, timeout: float) -> bool:
    proto = _proto_of(session)
    if proto is None or not hasattr(proto, "_recv_from_socket"):
        return False
    dictionary = getattr(proto, "__dict__", None)
    if dictionary is None:  # pragma: no cover - C object
        return False
    dictionary.setdefault("_tgmint_recv_original", dictionary.get("_recv_from_socket"))
    proto._recv_from_socket = types.MethodType(_make_patient_recv(timeout), proto)
    return True


def _unbind_patient_recv(session: typing.Any) -> None:
    proto = _proto_of(session)
    dictionary = getattr(proto, "__dict__", None) if proto is not None else None
    if dictionary is None:
        return
    dictionary.pop("_recv_from_socket", None)
    original = dictionary.pop("_tgmint_recv_original", None)
    if original is not None:
        proto._recv_from_socket = original


def _make_send_wrapper(session: typing.Any, original, pdd_delay: float):
    """Rewrite the outgoing ``PingDelayDisconnect``'s delay, touch nothing else.

    The raw module is imported *inside* the wrapper, so apply() never needs the
    framework importable and a client that never pings pays nothing.
    """

    async def send(data, *args, **kwargs):
        from pyrogram import raw

        if isinstance(data, raw.functions.PingDelayDisconnect):
            # the TL field is an int; a float breaks the serializer
            delay = int(pdd_delay)
            if getattr(data, "disconnect_delay", None) != delay:
                data = raw.functions.PingDelayDisconnect(
                    ping_id=data.ping_id, disconnect_delay=delay
                )
        return await original(data, *args, **kwargs)

    return send


def _wrap_connection(connection: typing.Any, timeout: float) -> None:
    """Bind the patient read timeout as soon as this connection is up.

    ``Session.start()`` creates the ``Connection``, calls its ``connect()``
    and only then spawns ``recv_worker`` - so patching here (inside the
    factory) lands before the first read. Patching *after* ``connect()``
    returns is too late: the first read is already in flight with the
    framework's 10 s timeout and will kill the session once.
    """
    original = connection.connect

    async def connect(*args, **kwargs):
        result = await original(*args, **kwargs)
        proto = getattr(connection, "protocol", None)
        if proto is not None and hasattr(proto, "_recv_from_socket"):
            dictionary = getattr(proto, "__dict__", None)
            if dictionary is not None:
                dictionary.setdefault(
                    "_tgmint_recv_original", dictionary.get("_recv_from_socket")
                )
            proto._recv_from_socket = types.MethodType(
                _make_patient_recv(timeout), proto
            )
        return result

    connection.connect = connect


def _session_client(session: typing.Any) -> typing.Any:
    return getattr(session, "client", session)


def _apply_pyrogram(
    client: typing.Any,
    sessions: typing.List[typing.Any],
    platform: str,
    cadence: PingCadence,
    dry_run: bool,
    notes: typing.List[str],
) -> typing.Dict[str, typing.Any]:
    """Apply the official cadence to a Pyrogram-family client.

    Three writes per Session, each instance-scoped:

    * ``PING_INTERVAL`` - the interval ``ping_worker`` re-reads every tick;
    * a patient ``_recv_from_socket`` rebind - the framework's 10 s socket
      read timeout is what used to close the connection before the official
      19 s / 30 s ping arrived (see :data:`PYROGRAM_READ_TIMEOUT_MARGIN`), and
      the wrapped ``start()`` re-applies it after later reconnects;
    * a ``Session.send`` wrapper that rewrites the outgoing
      ``PingDelayDisconnect``'s ``disconnect_delay`` to the official 35 s /
      60 s, because ``ping_worker`` hardcodes ``WAIT_TIMEOUT + 10`` and the
      server enforces it.
    """
    applied: typing.Dict[str, typing.Any] = {}
    unsupported: typing.Dict[str, typing.Any] = {}

    # a second apply() must restore the *framework* value, not the first patch
    previous_mark = getattr(client, _MARK, None)
    foreign = (
        isinstance(previous_mark, dict)
        and previous_mark.get("framework") == "pyrogram"
    )
    was = (
        previous_mark.get("previous")
        if foreign
        else getattr(sessions[0], "PING_INTERVAL", None)
    )
    plan = _pyrogram_plan(cadence)
    capped = plan["ping_interval"] < plan["requested"]

    if not dry_run:
        previous_factory = getattr(client, "connection_factory", None)
        original_factory = previous_factory
        if callable(original_factory):
            timeout = plan["socket_read_timeout"]

            def factory(*args, **kwargs):
                connection = original_factory(*args, **kwargs)
                _wrap_connection(connection, timeout)
                return connection

            client.connection_factory = factory
        for session in sessions:
            session.PING_INTERVAL = plan["ping_interval"]
            dictionary = getattr(session, "__dict__", None)
            if dictionary is not None:
                if hasattr(session, "send"):
                    dictionary["_tgmint_send_original"] = dictionary.get("send")
                    dictionary["send"] = _make_send_wrapper(
                        session, session.send, plan["disconnect_delay"]
                    )
            _bind_patient_recv(session, plan["socket_read_timeout"])
        setattr(
            client,
            _MARK,
            {
                "platform": platform,
                "framework": "pyrogram",
                "ping_interval": plan["ping_interval"],
                "requested": plan["requested"],
                "previous": was,
                "socket_read_timeout": plan["socket_read_timeout"],
                "disconnect_delay": plan["disconnect_delay"],
                "sessions": [id(session) for session in sessions],
                "connection_factory": previous_factory,
            },
        )

    applied["ping_interval"] = {
        "value": plan["ping_interval"],
        "requested": plan["requested"],
        "was": was,
        "attribute": "PING_INTERVAL",
        "scope": "instance attribute on the Session object (class default untouched)",
        "takes_effect": "the next ping tick (ping_worker re-reads it every loop)",
    }
    applied["socket_read_timeout"] = {
        "value": plan["socket_read_timeout"],
        "was": 10.0,
        "attribute": "_recv_from_socket (rebound on the protocol instance)",
        "scope": "this connection, and every reconnect through the wrapped start()",
        "takes_effect": (
            "immediately; without it the framework treats its own 10 s read "
            "timeout as a server close and restarts"
        ),
    }
    applied["disconnect_delay"] = {
        "value": plan["disconnect_delay"],
        "was": float(PYROGRAM_DISCONNECT_DELAY),
        "attribute": "Session.send (PingDelayDisconnect rewrite)",
        "scope": "instance wrapper; WAIT_TIMEOUT and request timeouts untouched",
        "takes_effect": "the next ping (the server enforces this delay)",
    }
    if capped:
        applied["ping_interval"]["capped_to"] = plan["ping_interval"]
        notes.append(
            f"pyrogram: the official {plan['requested']:g}s interval is capped "
            f"to {plan['ping_interval']:g}s so it stays below the socket read "
            "timeout minus two seconds and below the enforced disconnect_delay"
        )
    if len(sessions) > 1:
        notes.append(
            f"pyrogram: patched {len(sessions)} Session objects (main DC plus "
            "media / other-DC sessions), each has its own ping worker"
        )
    notes.append(
        "pyrogram: sessions created later (a new DC, a media download) start "
        "with the framework default; call apply() again to cover them"
    )
    notes.append(
        "pyrogram: Session.PING_INTERVAL on the class was not touched, so "
        "clients you did not pass to apply() keep the framework value"
    )
    if not any(hasattr(session, "send") for session in sessions):
        unsupported["disconnect_delay"] = {
            "official": plan["disconnect_delay"],
            "settable": False,
            "framework_default": float(PYROGRAM_DISCONNECT_DELAY),
            "reason": (
                "the object has no Session.send to wrap, so the hardcoded "
                "WAIT_TIMEOUT + 10 delay cannot be rewritten here; a real "
                "Pyrogram Session always has send()"
            ),
            "source": ".pytestbox/pyrogram/session/session.py:89, :476",
        }
    if any(getattr(_session_client(session), "proxy", None) for session in sessions):
        unsupported["socket_read_timeout"] = {
            "official": plan["socket_read_timeout"],
            "settable": False,
            "framework_default": 10.0,
            "reason": (
                "a proxy connection reads through the proxy record layer "
                "(Connection.recv -> _records.recv) and never calls "
                "_recv_from_socket, so the 10 s transport timeout does not "
                "apply to it and this patch does not reach it"
            ),
            "source": ".pytestbox/pyrogram/connection/connection.py:137-141",
        }
    return {"applied": applied, "unsupported": unsupported}


# ---------------------------------------------------------------------------
# the entry points
# ---------------------------------------------------------------------------


def apply(
    client: typing.Any,
    platform: typing.Optional[str] = None,
    *,
    dry_run: bool = False,
) -> typing.Dict[str, typing.Any]:
    """Point `client`'s keepalive at the official cadence for `platform`.

    The client family is detected from the object itself (Telethon by its
    ``_keepalive_loop``, the Pyrogram family by the ``Session`` objects that
    carry ``PING_INTERVAL`` + ``ping_worker``), and only the knobs that are
    safe on that family are written.  See the module docstring for what each
    family does and does not allow.

    Args:
        client: a Telethon client, or a Pyrogram/kurigram client whose
            ``Session`` object exists (i.e. connected at least once).
        platform: ``"android"`` / ``"desktop"`` (aliases accepted).  When
            omitted, the platform is taken from a fingerprint carried on the
            client (``_tgmint_fingerprint``, ``fingerprint``, ``api``...);
            with neither, :class:`CadenceError` says to pass it.
        dry_run: report every number without writing anything.

    Returns:
        ``{"framework", "platform", "applied", "unsupported", "notes",
        "dry_run"}`` — ``applied`` maps a knob to the value written and where,
        ``unsupported`` maps a knob to the official number plus why it cannot
        be set, ``notes`` are the caveats a caller needs to hear (reconnect,
        later sessions, untouched class attributes).

    Raises:
        CadenceError: unknown/unsupported platform, a client family this
            module does not drive, a Pyrogram client with no Session yet.
    """
    notes: typing.List[str] = []

    if platform is None:
        derived = _platform_from_client(client)
        if derived is None:
            raise CadenceError(
                "platform is required: no fingerprint was found on this client, "
                "so the target cadence is unknown; pass platform= with one of "
                f"{list(PLATFORMS)} (tgmint.sidecar can read the session's "
                "recorded identity if you only have the file)"
            )
        key = derived
        notes.append(f"platform derived from the client's fingerprint: {key}")
    else:
        key = _normalize_platform(platform)

    cadence = PING_CADENCE[key]
    family, sessions = _detect(client)

    if family == "telethon":
        result = _apply_telethon(client, key, cadence, dry_run, notes)
    else:
        result = _apply_pyrogram(client, sessions, key, cadence, dry_run, notes)

    report: typing.Dict[str, typing.Any] = {
        "framework": family,
        "platform": key,
        "applied": result["applied"],
        "unsupported": result["unsupported"],
        "notes": notes,
        "dry_run": bool(dry_run),
    }
    return report


def restore(client: typing.Any) -> typing.Dict[str, typing.Any]:
    """Undo :func:`apply` on `client` (put the framework's own cadence back).

    Returns ``{"restored": bool, "platform": ...}``; a client tgmint never
    patched is reported, not raised, so a "make sure it is clean" call is safe.
    Does not reconnect and does not cancel a running task: a Telethon loop
    already created at connect() keeps the patched interval until the client
    reconnects, exactly like :func:`apply` says it would.
    """
    mark = getattr(client, _MARK, None)
    if not isinstance(mark, dict):
        return {
            "restored": False,
            "reason": "tgmint.cadence.apply() did not patch this client",
        }

    framework = mark.get("framework")
    if framework == "telethon":
        dictionary = getattr(client, "__dict__", {})
        if dictionary.get("_keepalive_loop") is not None:
            del dictionary["_keepalive_loop"]
        if mark.get("had_own") and mark.get("previous_own") is not None:
            client._keepalive_loop = mark["previous_own"]
    elif framework == "pyrogram":
        sessions = _pyrogram_sessions(client)
        previous = mark.get("previous")
        for session in sessions:
            if previous is not None:
                session.PING_INTERVAL = previous
            else:  # pragma: no cover - only if the class attr was missing
                session.__dict__.pop("PING_INTERVAL", None)
            _unbind_patient_recv(session)
            dictionary = getattr(session, "__dict__", None)
            if dictionary is not None:
                for name, backup in (("send", "_tgmint_send_original"),
                                     ("start", "_tgmint_start_original")):
                    if name in dictionary:
                        original = dictionary.pop(backup, None)
                        if original is not None:
                            dictionary[name] = original
                        else:
                            del dictionary[name]
        previous_factory = mark.get("connection_factory")
        if previous_factory is not None:
            client.connection_factory = previous_factory

    try:
        delattr(client, _MARK)
    except AttributeError:  # pragma: no cover - defensive
        pass
    return {"restored": True, "platform": mark.get("platform")}
