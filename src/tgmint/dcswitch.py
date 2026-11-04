"""Shared datacenter-switch helpers for the cross-DC login ceremonies.

Both login ceremonies that mint a session on the account's *home* DC —
the passkey login (:mod:`tgmint.passkeys`, :mod:`tgmint.passkeys_pyrogram`)
and the QR login (:mod:`tgmint.qrlogin`, :mod:`tgmint.qrlogin_pyrogram`) —
need the same two framework-specific operations:

* **Telethon**: snapshot everything ``client._switch_dc`` overwrites, switch,
  and put it back best-effort when the step after the switch fails.
  ``_switch_dc`` (telethon/client/telegrambaseclient.py:770-784) rewrites the
  caller's persistent session and erases its auth key, so without the
  rollback one rejected request would permanently move the session file and
  lose the key.
* **Pyrogram family**: the kurigram QR-login migration recipe
  (``pyrogram/qrlogin.py:78-101``): ``get_session(..., temporary=True)`` to
  mint a fresh auth key on the target DC, swap the client's session, update
  the storage — and the snapshot to undo all of it.

These helpers used to live once per driver; they are one implementation per
framework now, shared by the passkey and QR drivers so the two ceremonies
cannot drift. Nothing here is imported at module scope from ``telethon`` or
a Pyrogram-family package: every client is duck-typed, and the only real
import (``telethon.utils.maybe_async``) happens inside
:func:`restore_session` so a Telethon-free environment can still use the
Pyrogram half.

The error type is :class:`tgmint.passkeys_core.PasskeyError` — the neutral
"driver-level failure" type both ceremonies already surface.
"""
from __future__ import annotations

from typing import Any, Optional

from .passkeys_core import PasskeyError

__all__ = [
    "session_snapshot",
    "restore_session",
    "switch_dc",
    "restore_dc",
]


# ---------------------------------------------------------------------------
# Pyrogram-family probes (which distribution is installed?)
# ---------------------------------------------------------------------------

def _distribution_name() -> str:
    """``"<fork> <version>"`` for the error messages below.

    The authoritative metadata-based probe lives in
    :mod:`tgmint.passkeys_pyrogram` (``_distribution``); it is reached
    lazily so importing this module never pulls a Pyrogram-family package
    or creates an import cycle. Any failure degrades to a generic label —
    this only ever decorates an error that is about to be raised.
    """
    try:
        from .passkeys_pyrogram import _distribution

        return _distribution()
    except Exception:  # nocov - broken metadata / no pyrogram at all
        return "this Pyrogram-family distribution"


# ---------------------------------------------------------------------------
# Telethon: snapshot / switch / restore around client._switch_dc
# ---------------------------------------------------------------------------

def session_snapshot(client: Any) -> dict[str, Any]:
    """Everything ``client._switch_dc`` overwrites, captured before it runs.

    ``_switch_dc`` (telethon/client/telegrambaseclient.py:770-784) rewrites
    ``session.set_dc(...)``, sets ``session.auth_key`` **and** the sender's
    key to ``None``, saves the session, then reconnects — i.e. it permanently
    moves the caller's persistent session and erases its auth key. A failed
    request after that point would leave the caller's session file pointing
    at another DC with no key at all, so the pre-switch state is captured
    here and put back by :func:`restore_session`.
    """
    session = getattr(client, "session", None)
    return {
        "session": session,
        "dc_id": getattr(session, "dc_id", None),
        "server_address": getattr(session, "server_address", None),
        "port": getattr(session, "port", None),
        "auth_key": getattr(session, "auth_key", None),
    }


async def restore_session(client: Any, snapshot: Optional[dict[str, Any]]) -> None:
    """Best-effort rollback of :meth:`TelethonClient._switch_dc`.

    Best effort by design: the login error is what the caller needs to see,
    so a rollback that also fails is swallowed (the client keeps the
    switched-to session — the same state a failed login leaves in any
    client). The session file is written back and the connection re-opened on
    the restored DC, because ``_switch_dc`` reconnected to the new one.
    """
    if not snapshot:
        return
    from telethon import utils as tl_utils  # lazy: Telethon-free callers

    session = snapshot["session"]
    try:
        if session is not None and snapshot["dc_id"] is not None:
            await tl_utils.maybe_async(
                session.set_dc(
                    snapshot["dc_id"], snapshot["server_address"], snapshot["port"]
                )
            )
            session.auth_key = snapshot["auth_key"]
            # the sender holds its own copy of the key; put it back before
            # reconnecting so connect() does not mint a brand new one
            sender_key = getattr(getattr(client, "_sender", None), "auth_key", None)
            old_key = snapshot["auth_key"]
            if sender_key is not None and old_key is not None:
                try:
                    sender_key.key = getattr(old_key, "key", old_key)
                except Exception:  # nocov - a sender that does not allow it
                    pass
            await tl_utils.maybe_async(session.save())
        disconnect = getattr(client, "_disconnect", None)
        connect = getattr(client, "connect", None)
        if callable(disconnect) and callable(connect):
            await disconnect()
            await connect()
    except Exception:  # nocov - a rollback that cannot complete
        pass


# ---------------------------------------------------------------------------
# Pyrogram family: switch / restore (kurigram's own QR-login recipe)
# ---------------------------------------------------------------------------

def _auth_key_bytes(session: Any) -> Any:
    key = getattr(session, "auth_key", None)
    return getattr(key, "key", key)


def _require_session(client: Any) -> Any:
    """The client's current session, or a PasskeyError about connect()."""
    session = getattr(client, "session", None)
    if session is None:
        raise PasskeyError(
            "the client has no session yet: await client.connect() first "
            "(client.start() is interactive and must not be used for a "
            "cross-DC login)"
        )
    return session


async def _dc_option(client: Any, dc_id: int) -> Any:
    getter = getattr(client, "get_dc_option", None)
    if not callable(getter):
        raise PasskeyError(
            f"{_distribution_name()} has no Client.get_session/get_dc_option, so a "
            "cross-DC login cannot be completed with it (pyrofork builds "
            "sessions by hand); use kurigram >= 2.2.26, or connect a client "
            "that is already on the account's home DC"
        )
    ipv6 = bool(getattr(client, "ipv6", False))
    try:
        return await getter(dc_id, ipv6=ipv6)
    except TypeError:  # nocov - a fork whose get_dc_option takes no ipv6
        return await getter(dc_id)


async def switch_dc(client: Any, dc_id: int) -> dict[str, Any]:
    """Move the client to ``dc_id`` with a fresh, unauthorized auth key.

    This is kurigram's own QR-login migration (``pyrogram/qrlogin.py``):
    ``get_session(..., export_authorization=False, temporary=True)`` creates
    a *new* auth key on the target DC, then the session is swapped and the
    storage updated. ``client.set_dc()`` is not usable here — it keeps the
    old auth key, and a challenge bound to the old connection must not be
    replayed with it.

    Returns the snapshot :func:`restore_dc` needs.
    """
    getter = getattr(client, "get_session", None)
    if not callable(getter):
        raise PasskeyError(
            f"{_distribution_name()} has no Client.get_session, so the client "
            "cannot move to the target DC; use kurigram >= 2.2.26 "
            "(pyrofork would need a hand-built Session + Auth.create)"
        )
    option = await _dc_option(client, dc_id)
    old_session = _require_session(client)
    snapshot = {
        "session": old_session,
        "dc_id": await client.storage.dc_id(),
        "server_address": await client.storage.server_address(),
        "port": await client.storage.port(),
        "auth_key": await client.storage.auth_key(),
    }
    new_session = await getter(
        dc_id=dc_id,
        server_address=option.ip_address,
        port=option.port,
        export_authorization=False,
        temporary=True,
    )
    client.session = new_session
    await client.storage.dc_id(dc_id)
    await client.storage.server_address(option.ip_address)
    await client.storage.port(option.port)
    await client.storage.auth_key(_auth_key_bytes(new_session))
    stop = getattr(old_session, "stop", None)
    if callable(stop):
        try:
            await stop()
        except Exception:  # nocov - a session that dislikes being closed
            pass
    return snapshot


async def restore_dc(client: Any, snapshot: dict[str, Any]) -> None:
    """Put the client back where it was after a failed login.

    Best effort by design: the login error is what the caller needs to see,
    so a restore that also fails is swallowed (the client is left on the
    target DC, unauthorized — the same state a failed login leaves in any
    client).
    """
    current = getattr(client, "session", None)
    stop = getattr(current, "stop", None)
    if callable(stop):
        try:
            await stop()
        except Exception:  # nocov
            pass
    client.session = snapshot["session"]
    start = getattr(snapshot["session"], "start", None)
    if callable(start):
        try:
            await start()
        except Exception:  # nocov
            pass
    for name in ("dc_id", "server_address", "port", "auth_key"):
        accessor = getattr(client.storage, name, None)
        if callable(accessor):
            try:
                await accessor(snapshot[name])
            except Exception:  # nocov
                pass
