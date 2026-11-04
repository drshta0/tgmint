"""QR login over the Pyrogram family — the thin kurigram-style driver.

Mirrors :mod:`tgmint.qrlogin` (the Telethon twin) driver for driver: the
same neutral core (:mod:`tgmint.qrlogin_core`) supplies the ceremony, and
everything here is framework glue — an invoker that builds the
distribution's own generated request classes (looked up by TL constructor
id through the same ``pyrogram.raw.all.objects`` registry the passkey
driver uses, so it is fork-agnostic), the ``updateLoginToken`` wait
(``RawUpdateHandler``, like ``pyrogram.qrlogin.QRLogin.wait``), the DC
migration by kurigram's own recipe (:func:`tgmint.dcswitch.switch_dc`,
shared with the passkey driver), and the three lines of post-login
bookkeeping (``storage.user_id`` / ``storage.is_bot`` / ``User._parse``).

Works with any Pyrogram-family distribution that ships the QR constructors
in its raw layer (they predate layer 100, so effectively all of them:
kurigram 2.2.26 layer 229 verified — see ``tests/test_wire_golden.py``).
``client.start()`` is interactive and must not be used: connect with
``await client.connect()`` and hand the client here.

Own-account tooling only; no batch surface, same as everywhere in tgmint.
"""
from __future__ import annotations

import asyncio
from typing import Any, Callable, Optional

from . import dcswitch
from . import qrlogin_core as core
from .passkeys_core import TwoFactorRequired
from .passkeys_pyrogram import (
    PYROGRAM_AVAILABLE,
    _distribution,
    _framework,
    _tl_class,
    pyrogram,
    pyrogram_errors,
    pyrogram_types,
)

__all__ = [
    "PYROGRAM_AVAILABLE",
    "PyrogramQrInvoker",
    "build_request",
    "qr_login",
    "wait_for_confirmation",
    "migrate_and_import",
    "finish_with_password",
    "authorize",
    "login_with_qr",
]

QrLoginError = core.QrLoginError
QrLoginToken = core.QrLoginToken
QrMigrateTo = core.QrMigrateTo
QrSuccess = core.QrSuccess
QrPasswordNeeded = core.QrPasswordNeeded

_UPDATE_LOGIN_TOKEN = 0x564FE691  # updateLoginToken#564fe691 (layer 229)


def build_request(name: str, fields: dict[str, Any]) -> Any:
    """The distribution's own request object for one ceremony step.

    Constructor ids come from :data:`tgmint.qrlogin_core.QRLOGIN_TL_SPEC` and
    the class is resolved through the registry (not an import path), so the
    bytes on the wire are the distribution's own serialization — pinned
    against Telethon's in ``tests/test_wire_golden.py``.
    """
    _framework()
    core.encode_request(name, fields)  # validation lives in the core
    if name == "exportLoginToken":
        cls = _tl_class(
            core.QRLOGIN_TL_SPEC["constructors"]["auth.exportLoginToken"],
            what="auth.exportLoginToken",
        )
        return cls(
            api_id=fields["api_id"],
            api_hash=fields["api_hash"],
            except_ids=list(fields.get("except_ids", ())),
        )
    if name == "importLoginToken":
        cls = _tl_class(
            core.QRLOGIN_TL_SPEC["constructors"]["auth.importLoginToken"],
            what="auth.importLoginToken",
        )
        return cls(token=fields["token"])
    raise QrLoginError(f"unknown QR-login message {name!r}")


class PyrogramQrInvoker:
    """The core's ``request_bytes`` contract over a connected client.

    Answers with the framework object re-serialized via ``write()`` — the
    core owns parsing.  Keeps the last response in :attr:`last_response`
    because ``authorize`` needs the framework's real ``User`` for the
    storage bookkeeping.  ``SESSION_PASSWORD_NEEDED`` (kurigram's typed
    ``SessionPasswordNeeded``) becomes the neutral
    :class:`tgmint.passkeys_core.TwoFactorRequired` signal, exactly like in
    the passkey driver.
    """

    def __init__(self, client: Any):
        _framework()
        if not callable(getattr(client, "invoke", None)):
            raise QrLoginError(
                "a Pyrogram-family Client (with an async .invoke) is required, "
                f"got {type(client).__name__}"
            )
        if not getattr(client, "is_connected", True):
            raise QrLoginError(
                "the client is not connected: await client.connect() first "
                "(client.start() is interactive and must not be used here)"
            )
        self.client = client
        self.sent: list = []
        """Every request object this invoker sent, in order (audit/debug)."""
        self.last_response: Any = None

    async def request_bytes(self, name: str, fields: dict[str, Any]) -> bytes:
        request = build_request(name, fields)
        self.sent.append(request)
        try:
            response = await self.client.invoke(request)
        except pyrogram_errors.SessionPasswordNeeded:
            # the account has a 2FA cloud password: the *driver* decides the
            # password call, the core only learns the typed signal
            raise TwoFactorRequired(
                "the account has a 2FA cloud password; call again with "
                "password=..."
            ) from None
        self.last_response = response
        write = getattr(response, "write", None)
        if not callable(write):  # nocov - a fork without TLObject.write
            raise QrLoginError(
                f"{name}: {type(response).__name__} has no write(); cannot "
                "hand the response to the neutral parser"
            )
        return write()


def qr_login(client: Any, *, except_ids: Optional[list] = None) -> core.QrLoginMachine:
    """The framework-neutral machine bound to this client's identity.

    The client must be **connected and unauthorized** (``await
    client.connect()``; ``client.start()`` is interactive).
    """
    return core.QrLoginMachine(
        PyrogramQrInvoker(client),
        api_id=client.api_id,
        api_hash=client.api_hash,
        except_ids=except_ids or (),
    )


async def wait_for_confirmation(client: Any, timeout: Optional[float] = None) -> None:
    """Block until the server says the QR was scanned+confirmed.

    Mirrors ``pyrogram.qrlogin.QRLogin.wait``: a ``RawUpdateHandler`` that
    completes when ``updateLoginToken`` arrives — matched by constructor id
    (not an import), so a fork that moves the class cannot break the wait.
    """
    event = asyncio.Event()

    async def raw_handler(_client, update, _users, _chats):
        if getattr(update, "ID", None) == _UPDATE_LOGIN_TOKEN:
            event.set()

    handler = client.add_handler(
        pyrogram.handlers.RawUpdateHandler(raw_handler)
    )
    try:
        await asyncio.wait_for(event.wait(), timeout=timeout)
    finally:
        try:
            client.remove_handler(*handler)
        except TypeError:  # nocov - a fork returning a bare handler
            client.remove_handler(handler)


async def migrate_and_import(
    client: Any, machine: core.QrLoginMachine, migrate: core.QrMigrateTo
):
    """Move to the migrate DC, import there, roll the client back on failure.

    The switch is kurigram's own migration recipe
    (:func:`tgmint.dcswitch.switch_dc`, which also takes the restore
    snapshot); a failed import restores session and storage so a retry
    starts where it left off.  A
    :class:`tgmint.qrlogin_core.QrPasswordNeeded` answer intentionally keeps
    the migrated session — the password step must run on the account's home
    DC (a wrong password stays retryable there, like in the passkey login).
    """
    snapshot = await dcswitch.switch_dc(client, migrate.dc_id)
    try:
        return await machine.import_token(migrate)
    except BaseException:
        await dcswitch.restore_dc(client, snapshot)
        raise


async def finish_with_password(client: Any, password: str):
    """Complete a 2FA-blocked login: ``client.check_password(...)``."""
    return await client.check_password(password)


async def authorize(client: Any, invoker: PyrogramQrInvoker, success: core.QrSuccess):
    """Post-login bookkeeping (the three lines kurigram's sign_in uses)."""

    user = getattr(getattr(invoker, "last_response", None), "authorization", None)
    user = getattr(user, "user", None)
    if user is None:
        # rebuild from the neutral result's raw auth.Authorization bytes
        import io

        raw_cls = _tl_class(
            success.authorization.constructor,
            what="auth.authorization",
        )
        user = getattr(
            raw_cls.read(io.BytesIO(success.authorization.raw)), "user", None
        )
    if user is None:
        raise QrLoginError(
            "auth.loginTokenSuccess carried auth.authorizationSignUpRequired: "
            "there is no account behind this login to authorize"
        )
    user_id = getattr(user, "id", None)
    if not isinstance(user_id, int) or isinstance(user_id, bool):
        raise QrLoginError(f"the authorization user has no usable id ({user_id!r})")
    await client.storage.user_id(user_id)
    await client.storage.is_bot(False)
    me = await pyrogram_types.User._parse(client, user)
    if me is None:  # nocov - a fork returning a non-User object
        raise QrLoginError(
            f"{_distribution()} could not parse its own user object "
            f"({type(user).__name__})"
        )
    return me


async def login_with_qr(
    client: Any,
    *,
    password: Optional[str] = None,
    render: Optional[Callable[[core.QrLoginToken], Any]] = None,
    timeout: Optional[float] = None,
    except_ids: Optional[list] = None,
):
    """Run the whole QR ceremony on a connected, unauthorized client.

    The Pyrogram-family twin of :func:`tgmint.qrlogin.login_with_qr`: render
    each fresh token (default: print the ``tg://login?token=...`` URL), wait
    for the scan, migrate with rollback on failure, complete the login and
    do the storage bookkeeping.  The session is not persisted here — the
    framework owns its storage, so call ``await client.storage.save()`` when
    the logged-in session should survive the process.

    With a 2FA-protected account: ``password`` completes the login here;
    without it the neutral :class:`tgmint.passkeys_core.TwoFactorRequired`
    propagates and the client is left ready for
    ``await client.check_password(...)`` (after a migrate, on the home DC).

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
        await client.storage.save()  # the framework owns its storage
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
