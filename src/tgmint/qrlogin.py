"""QR login over Telethon — the thin driver around :mod:`tgmint.qrlogin_core`.

Everything framework-bound lives here and is deliberately small: an invoker
that sends the two requests through a connected (unauthorized) Telethon
client and re-serializes the parsed answer, the ``updateLoginToken`` wait
(mirroring ``telethon.tl.custom.qrlogin.QRLogin.wait``), the DC migration
with the shared snapshot/rollback from :mod:`tgmint.dcswitch` (Telethon's
``client._switch_dc`` is destructive: it rewrites the caller's persistent
session and erases its auth key), and the post-login bookkeeping
(``client._on_login`` + session save).

The ordering rules — export on the current connection, wait for
``updateLoginToken``, re-export, migrate-then-import, 2FA as a typed stop —
live in the framework-neutral core, so this driver and the Pyrogram-family
one (:mod:`tgmint.qrlogin_pyrogram`) cannot drift apart.

Own-account tooling only: this mints a session for the account that
confirms the QR from *your* logged-in device. There is no batch mode and
there will not be one.
"""
from __future__ import annotations

import asyncio
from typing import Any, Callable, Optional

from telethon import events, types
from telethon.errors import SessionPasswordNeededError
from telethon.extensions import BinaryReader
from telethon.tl import functions as tl_functions

from . import dcswitch
from . import qrlogin_core as core
from .passkeys_core import TwoFactorRequired

__all__ = [
    "TelethonQrInvoker",
    "qr_login",
    "wait_for_confirmation",
    "migrate_and_import",
    "finish_with_password",
    "authorize",
    "login_with_qr",
]

# the neutral re-exports a driver-level caller (the CLI) works with
QrLoginError = core.QrLoginError
QrLoginToken = core.QrLoginToken
QrMigrateTo = core.QrMigrateTo
QrSuccess = core.QrSuccess
QrPasswordNeeded = core.QrPasswordNeeded


def _build_request(name: str, fields: dict[str, Any]):
    """The framework's own request object for one ceremony step."""
    core.encode_request(name, fields)  # validation lives in the core
    if name == "exportLoginToken":
        return tl_functions.auth.ExportLoginTokenRequest(
            api_id=fields["api_id"],
            api_hash=fields["api_hash"],
            except_ids=list(fields.get("except_ids", ())),
        )
    if name == "importLoginToken":
        return tl_functions.auth.ImportLoginTokenRequest(token=fields["token"])
    raise QrLoginError(f"unknown QR-login message {name!r}")


class TelethonQrInvoker:
    """The core's ``request_bytes`` contract over a Telethon client.

    Sends the framework's own generated request classes (so the constructor
    ids on the wire are Telethon's, pinned in ``tests/test_wire_golden.py``)
    and answers with the response re-serialized to bytes — the core owns
    parsing.  Keeps the last parsed response in :attr:`last_response`
    because ``authorize`` needs the framework's real ``User`` object for
    ``client._on_login``; the neutral result carries only the raw bytes.

    ``SESSION_PASSWORD_NEEDED`` is translated into the neutral
    :class:`tgmint.passkeys_core.TwoFactorRequired` signal (the same 2FA
    concept the passkey ceremonies use); the core turns it into its typed
    :class:`tgmint.qrlogin_core.QrPasswordNeeded` result.
    """

    def __init__(self, client):
        self.client = client
        self.last_response: Any = None

    async def request_bytes(self, name: str, fields: dict[str, Any]) -> bytes:
        request = _build_request(name, fields)
        try:
            response = await self.client(request)
        except SessionPasswordNeededError as exc:
            raise TwoFactorRequired() from exc
        self.last_response = response
        return bytes(response)


def qr_login(client, *, except_ids=None) -> core.QrLoginMachine:
    """The framework-neutral machine bound to this client's identity.

    The client must be **connected and unauthorized** (``await
    client.connect()``; ``client.start()`` is interactive and would prompt).
    ``except_ids`` is Telegram's "do not confirm for these already-logged-in
    users" filter — a single-account tool leaves it empty.
    """
    return core.QrLoginMachine(
        TelethonQrInvoker(client),
        api_id=client.api_id,
        api_hash=client.api_hash,
        except_ids=except_ids or (),
    )


async def wait_for_confirmation(client, timeout: Optional[float] = None) -> None:
    """Block until the server says the QR was scanned+confirmed.

    The signal is the ``updateLoginToken`` raw update, exactly like
    ``telethon.tl.custom.qrlogin.QRLogin.wait`` — an unauthorized connection
    receives this one update.  Raises ``asyncio.TimeoutError`` after
    ``timeout`` seconds (``None``: until the pending token expires — pass
    the machine's ``seconds_left()``).
    """
    event = asyncio.Event()

    async def handler(_update):
        event.set()

    client.add_event_handler(handler, events.Raw(types.UpdateLoginToken))
    try:
        await asyncio.wait_for(event.wait(), timeout=timeout)
    finally:
        client.remove_event_handler(handler)


async def migrate_and_import(
    client, machine: core.QrLoginMachine, migrate: core.QrMigrateTo
):
    """Move to the migrate DC, import there, roll the client back on failure.

    ``client._switch_dc`` permanently rewrites the caller's session (new DC,
    auth key erased), so the pre-switch state is snapshotted first
    (:func:`tgmint.dcswitch.session_snapshot`) and restored when the switch
    or the import fails — a rejected token then leaves the caller where it
    started, ready to re-export a fresh QR.  A
    :class:`tgmint.qrlogin_core.QrPasswordNeeded` answer intentionally keeps
    the migrated session: the password step must run on the account's home
    DC (a wrong password stays retryable there, like in the passkey login).
    """
    snapshot = dcswitch.session_snapshot(client)
    try:
        await client._switch_dc(migrate.dc_id)
    except BaseException:
        await dcswitch.restore_session(client, snapshot)
        raise
    try:
        return await machine.import_token(migrate)
    except BaseException:
        await dcswitch.restore_session(client, snapshot)
        raise


async def finish_with_password(client, password: str):
    """Complete a 2FA-blocked login: ``client.sign_in(password=...)``.

    Runs on whatever connection the ceremony ended on (after a migrate that
    is the account's home DC — that is the point of keeping the switch).
    """
    return await client.sign_in(password=password)


async def authorize(client, invoker: TelethonQrInvoker, success: core.QrSuccess):
    """Post-login bookkeeping for a finished QR login.

    ``client._on_login`` needs Telethon's real ``User``: taken from the
    invoker's kept response, or rebuilt from the neutral result's raw
    ``auth.Authorization`` bytes through Telethon's own TL layer when a
    caller replaced the invoker's memory of it.
    """
    from .passkeys_core import _CTOR_AUTH_AUTHORIZATION

    user = getattr(getattr(invoker, "last_response", None), "authorization", None)
    user = getattr(user, "user", None)
    if user is None:
        from telethon.tl import types as tl_types

        if success.authorization.constructor == _CTOR_AUTH_AUTHORIZATION:
            cls = tl_types.auth.Authorization
        else:
            cls = tl_types.auth.AuthorizationSignUpRequired
        response = cls.from_reader(BinaryReader(success.authorization.raw))
        user = getattr(response, "user", None)
    if user is None:
        raise QrLoginError(
            "auth.loginTokenSuccess carried auth.authorizationSignUpRequired: "
            "there is no account behind this login to authorize"
        )
    me = await client._on_login(user)
    saved = client.session.save()
    if asyncio.iscoroutine(saved):  # a Session.save that wants awaiting
        await saved
    return me


async def login_with_qr(
    client,
    *,
    password: Optional[str] = None,
    render: Optional[Callable[[core.QrLoginToken], Any]] = None,
    timeout: Optional[float] = None,
    except_ids=None,
):
    """Run the whole QR ceremony on a connected, unauthorized client.

    Renders every fresh token with ``render`` (default: print the
    ``tg://login?token=...`` URL; the CLI passes the terminal QR renderer),
    waits for the scan, performs the migrate-DC handoff with rollback on
    failure, and completes the login.  ``timeout`` is an overall budget in
    seconds (``None``: keep refreshing expired tokens until one is
    confirmed — Ctrl-C to stop).  Returns the logged-in ``me`` user, with
    the session saved.

    If the account has a 2FA cloud password: with ``password`` given the
    login completes here; without it the neutral
    :class:`tgmint.passkeys_core.TwoFactorRequired` propagates and the
    client is left ready for ``await client.sign_in(password=...)`` (after
    a migrate, on the account's home DC).

    Own account only: the session is minted for whoever confirms the QR
    from the logged-in device — you.
    """
    machine = qr_login(client, except_ids=except_ids)
    invoker = machine.invoker

    async def _wait(seconds):
        await wait_for_confirmation(client, timeout=seconds)

    async def _migrate(step):
        return await migrate_and_import(client, machine, step)

    async def _complete(success):
        me = await authorize(client, invoker, success)
        saved = client.session.save()
        if asyncio.iscoroutine(saved):  # a Session.save that wants awaiting
            await saved
        return me

    return await core.run_ceremony(
        machine,
        wait=_wait,
        migrate=_migrate,
        finish_password=lambda password: finish_with_password(client, password),
        complete=_complete,
        password=password,
        render=render,
        timeout=timeout,
    )
