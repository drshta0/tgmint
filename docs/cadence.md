# Keepalive cadence: what the real apps send, and what tgmint can set

Official clients ping on their own schedule. The frameworks tgmint supports hardcode a
different one, and after the fingerprint, the wire layer and the startup batch are right,
that mismatch is one of the loudest "not the real app" tells left:

| Client | Keepalive | `disconnect_delay` | Where the number comes from |
|---|---|---|---|
| Telegram Android 12.10.6 | every **19 s** | **35 s** | `TMessagesProj/jni/tgnet/ConnectionsManager.cpp:295` (the `>= 19000` guard) and `:1786` (`disconnect_delay = ... 35`) |
| Telegram Desktop 7.3.3 | every **30 s** | **60 s** | `Telegram/SourceFiles/mtproto/session_private.cpp:40-42` (`kPingDelayDisconnect = 60`, `kPingSendAfter = 30 * crl::time(1000)`) |
| Telethon 1.43.2 | every **60 s** | not sent | `telethon/client/updates.py:516-548`, the literal `timeout=60` at `:522` |
| kurigram / Pyrogram 2.2.26 | every **5 s** | **25 s** | `pyrogram/session/session.py:93` (`PING_INTERVAL = 5`) and `:476` (`self.WAIT_TIMEOUT + 10`) |

`python -m tgmint cadence` prints exactly that comparison. It is a **plan**: no session,
no socket, no client. The only thing that sets anything is `tgmint.cadence.apply()`, and
it does so in-process.

## Command

```bash
python -m tgmint cadence                       # both presets
python -m tgmint cadence --preset android      # one
python -m tgmint cadence --preset desktop --json
```

## Using it from Python

```python
from tgmint.cadence import apply, describe

apply(client, "android")                 # what the framework allows, nothing else
apply(client, "android", dry_run=True)   # report only, mutates nothing
report = apply(client, platform=None)    # platform from a fingerprint on the client
```

The report is plain data:

```python
{
  "framework": "telethon",          # or "pyrogram"
  "platform": "android",
  "applied": {"ping_interval": {"value": 19.0, "was": 60.0, "attribute": "...",
                                "scope": "...", "takes_effect": "..."}},
  "unsupported": {"disconnect_delay": {"official": 35, "settable": False,
                                       "reason": "...", "source": "..."}},
  "notes": ["..."],                 # reconnect, later sessions, untouched class attrs
  "dry_run": False,
}
```

`platform=None` reads the platform off a fingerprint carried on the client
(`_tgmint_fingerprint`, `fingerprint`, `api`, …). There is no fingerprint on a plain
client, so the call raises a `CadenceError` that says to pass `platform=`, instead of
guessing from the session string. `target(platform)` returns the frozen `PingCadence`
(`ping_interval`, `disconnect_delay`, `source`) and `describe(platform)` the comparison
above as a dict — both pure, both import no framework.

## What can and cannot be changed, per framework

**Telethon 1.43.2 — interval yes, delay no.**

* `ping_interval`: there is **no attribute** to set. `60` is a literal inside
  `_keepalive_loop`. tgmint therefore replaces that loop *on the instance* (which shadows
  the class method for this client only) with a copy whose tick is the interval you asked
  for. The copy keeps every step of the original — exported-sender cleanup, transport
  check, keepalive ping, entity/state flush — and `apply()` first verifies the installed
  loop really is the one the copy was written against (marker strings + the `timeout=`
  literal). Anything else is reported `unsupported` rather than patched.
  The task is created at `connect()` (`telegrambaseclient.py:619`), so apply before
  connecting, or reconnect afterwards; the report says which.
* `disconnect_delay`: **not settable**. Telethon never sends `ping_delay_disconnect`; its
  keepalive is a plain `ping` (`network/mtprotosender.py:438-448`), a method with no
  `disconnect_delay` field. There is no value to set, not even a wrong one.

**kurigram / Pyrogram 2.2.26 — interval yes, delay no.**

* `ping_interval`: `ping_worker` re-reads `self.PING_INTERVAL` every tick, so setting it
  as an **instance attribute** on the `Session` object works and takes effect on the next
  ping: no reconnect, no monkey-patching, class default untouched. Each `Session` (main
  DC, other DCs, media sessions) has its own worker and gets patched; sessions created
  later start with the framework default, and the report says so.
* `disconnect_delay`: **not settable by choice**. It is derived as
  `WAIT_TIMEOUT + 10` inside `ping_worker`, and `WAIT_TIMEOUT` is also the
  request/startup timeout knob (`invoke()` waits on it). Moving it would change request
  behaviour to fake a ping field, so tgmint leaves the derived 25 s and reports it.

Undo with `tgmint.cadence.restore(client)`: the instance attribute goes away (Telethon)
or the framework value is written back (Pyrogram family). Nothing here ever patches a
class, a module or a global, so a second client in the same process is unaffected.

## This is not ban evasion

Matching a cadence removes **one** signal among many — the device fingerprint, the wire
layer, the API id, the startup batch, the update behaviour and the account's own history
are all still on the wire, and none of them are ours to guarantee. Two pings now look
like a phone's; that is the entire claim. tgmint does not promise that a session with the
official cadence is safe, undetectable or un-bannable, and using this on an account you
do not own is outside what the project supports.

## Why the Pyrogram family used to break at 19 s (root cause: the client, not Telegram)

The first live run looked like an edge policy: at the official 19 s interval the kurigram
session reconnected every ~10.07 s, and small intervals (8/9/9.5 s) were stable. That was
wrong. Instrumenting the transport showed the close is **local**:

* `pyrogram/connection/transport/tcp/tcp.py:159` hardcodes `TCP.TIMEOUT = 10`, and
  `_recv_from_socket` waits that long for the next inbound byte and returns `None`;
* `Session.recv_worker` (`session.py:473-500`) reads `None` as *"Server sent a null packet"*
  and restarts the session — the socket is still open (`at_eof()` false).

A logging TCP proxy confirmed the server sends nothing and never FINs at the 10 s mark.
The framework kills its own connection whenever it goes 10 s without receiving anything,
which is exactly what a 19 s (or 30 s) ping interval guarantees. 9.5 s only "worked"
because each pong arrived inside the 10 s window. Telethon has no per-read timeout, which
is why it always survived.

The second ingredient: `ping_delay_disconnect`'s `disconnect_delay` is **enforced** by the
server (a FIN lands `disconnect_delay` seconds after the last packet), and the framework
hardcodes `disconnect_delay = WAIT_TIMEOUT + 10 = 25`. So after fixing the read timeout,
19 s works (19 < 25) but the official 30 s would not — unless the delay is raised too.

`apply()` therefore writes three things per Session, all instance-scoped:

| write | why |
|---|---|
| `PING_INTERVAL` | the interval `ping_worker` re-reads each tick |
| a patient `_recv_from_socket` (2 × interval + 7 s, min 25 s), installed through the client's `connection_factory` so it lands **before** the first read of every connection | removes the framework's own 10 s self-close |
| a `Session.send` wrapper that rewrites the outgoing `PingDelayDisconnect` to the official 35 s / 60 s | the server enforces it and the worker hardcodes 25 s |

One side effect: the read already in flight when `apply()` is called keeps the old 10 s
timeout, so the session reconnects **once** right after apply and is stable afterwards
(verified: 100 s with pings at 19.0-19.1 s on Android, 30 s on desktop, zero further
reconnects).

## Verification status

* Verified offline (`tests/test_cadence.py`): the numbers and the `file:line` behind
  each, the framework defaults against the *installed* packages (a bump that changes its
  own default fails the suite), `apply` against a real `TelegramClient` (instance
  shadowing only, class untouched, `restore` puts it back), fake Pyrogram-family clients
  (`_session` / `session` / `sessions`), the copied Telethon loop actually driven for
  several ticks, `dry_run` mutating nothing, the cap arithmetic, and every refusal path
  (unknown platform, undetectable family, an unrecognised Telethon loop, a Pyrogram
  client with no `Session` yet).
* Verified live: Telethon's 19 s survives on a real connection; the Pyrogram family's
  floor (8/9/9.5 s clean, 10 s and above reconnect) and the ~10.07 s idle close.
* Not verified: that the server *notices* the cadence difference, and why Telethon's
  identical key/DC survives the silence that kills a kurigram socket. Both official
  numbers are reconstructed from client source; whether a 19 s phone looks more like a
  phone than a 60 s one is a hypothesis — the honest test is an owner's own account,
  over time.
