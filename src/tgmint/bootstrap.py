"""tgmint.bootstrap - post-auth startup replay.

After a client is authorized and connected, the official apps do not wait
for a user to touch anything: they fire a fixed batch of configuration and
contact reads, in a fixed order, and only then draw a screen.  This module
carries that batch as data (``BOOTSTRAP_SEQUENCES``) and replays it through
any Telethon-style client, so a session that tgmint minted can behave like
the app whose identity it wears.

The data was read out of the official client sources (one row per call
site, every row with a source and a confidence) for Telegram
Android 12.10.6 and Telegram Desktop 7.3.3.  Only rows the source proves to
be *startup* and *read-only* are shipped; the rest are ruled out below on
purpose.

Guardrails (hard, not configurable)
-----------------------------------

* **opt in.**  Nothing here runs on import, nothing hooks a client, and no
  tgmint command replays a sequence unless the caller asks for it.  A
  session that already works must never be silently re-bootstrapped.
* **an allowlist, not a denylist.**  A step may only send a method from
  :data:`SAFE_METHODS` (read-only startup reads) or, when the caller opts
  into cosmetics, from :data:`COSMETIC_METHODS`.  :func:`sequence` and
  :func:`replay_startup` validate the shipped data against both allowlists
  and raise :class:`BootstrapError` if a step ever escapes them.
* **never these.**  :data:`FORBIDDEN_METHODS` (``account.updateStatus``,
  ``account.registerDevice``, ``account.resetAuthorization``, ``auth.*``)
  are refused outright.  ``updateStatus`` publishes an online/last-seen
  state the caller did not ask for; ``registerDevice`` registers a push
  endpoint that would never receive anything, which is actively harmful;
  ``resetAuthorization`` and the ``auth.*`` family are not startup reads at
  all.
* **never ``initConnection``.**  It is fixed at connect time by the client
  (``tgmint.tl`` puts the minted envelope on the wire once per session) and
  replaying it would be a second, competing envelope.  The desktop spec has
  it as step 2 for exactly that reason: the first request of a new MTProto
  session is wrapped by the transport, not by startup code.
* **one account, one session, no loop.**  Same posture as ``tgmint heal``:
  no batch mode, no daemon, no "replay every session in this folder".

What is deliberately NOT replayed (see ``EXCLUDED_METHODS`` for the machine
readable version, each with its reason): ``updates.getDifference`` (consumes
the update queue rather than reading startup config),
``account.getReactionsNotifySettings`` and ``langpack.getLangPack`` (read-only
but outside the audited allowlist), the keepalive ``ping_delay_disconnect``
(that is the ping layer, see :data:`tgmint.parity.PING_PRESETS`),
``help.getNearestDc`` (pre-auth only), ``account.getAuthorizations`` and the
``langpack.getLanguages`` desktop offer (UI-triggered), and desktop's update
check (an HTTPS feed, not MTProto).

Verification status (honest)
----------------------------

* **Verified offline** (``tests/test_bootstrap.py``): the shipped order,
  the allowlist/forbidden gates, cosmetic filtering, the replay loop
  against a fake client (exact order, one failing request recorded and the
  replay continuing, dry run making zero calls), the request builder
  producing real Telethon objects, and the CLI's dry run.
* **NOT verified against Telegram**: that a real account accepts this batch
  and that the resulting behaviour matches the official app.  That needs a
  live account; the sequence is a faithful *reconstruction from source*,
  not an observed packet capture, and two rows are marked ``inferred`` in
  the spec (desktop ``help.getPromoData`` and Android's
  ``messages.getPinnedDialogs``).

The module is stdlib-only and imports Telethon lazily inside the request
builder, so ``import tgmint.bootstrap`` works without Telethon installed
(same rule as :mod:`tgmint.codec`).
"""

from __future__ import annotations

import asyncio
import inspect
import typing
from dataclasses import dataclass

__all__ = [
    "BOOTSTRAP_SEQUENCES",
    "BootstrapError",
    "CLIENT_VERSIONS",
    "COSMETIC_METHODS",
    "EXCLUDED_METHODS",
    "FORBIDDEN_METHODS",
    "PHASES",
    "PLATFORMS",
    "SAFE_METHODS",
    "STEP_TIMEOUT_SECONDS",
    "Step",
    "describe",
    "is_forbidden",
    "platform_for",
    "replay_startup",
    "sequence",
]


class BootstrapError(Exception):
    """The replay cannot be built or run as asked.

    When the replay *starts* and then dies (a connection or auth failure,
    or a step that hit :data:`STEP_TIMEOUT_SECONDS`), the error carries
    the partial report the run had built so far, so the caller can still
    see what was sent: ``report`` (the usual ``{"platform", "steps",
    "sent", "errors", ...}`` dict, with every step up to the failure),
    ``stopped_at`` (the 1-based step that died) and ``sent`` (how many
    requests had gone out before it).  All three are ``None`` for the
    errors raised before a replay starts.
    """

    #: the partial replay report, when the error came out of a live run
    report: typing.Optional[typing.Dict[str, typing.Any]] = None
    #: the 1-based step the replay stopped at, when known
    stopped_at: typing.Optional[int] = None
    #: how many requests were sent before the failure, when known
    sent: typing.Optional[int] = None


#: Generous per-step ceiling for the live replay: a startup request that
#: has not answered in a minute is a dead session, not a slow one, and
#: without a bound one hung request stalls the whole replay forever.
STEP_TIMEOUT_SECONDS: float = 60.0


#: The four phases a step can belong to.  ``session`` is the transport and
#: update-state layer, ``account`` is per-account configuration, ``dialogs``
#: is the first screen, ``cosmetic`` is the sticker/reaction/premium
#: fan-out that only paints UI.
PHASES: typing.Tuple[str, ...] = ("session", "account", "dialogs", "cosmetic")

#: Platforms with a source-verified sequence (iOS is not covered: the
#: relevant files are large remote blobs, so there is no file:line claim).
PLATFORMS: typing.Tuple[str, ...] = ("android", "desktop")


@dataclass(frozen=True)
class Step:
    """One startup request.

    Attributes:
        name: unique, human readable step name (``"help.getConfig"``, or
            ``"account.getNotifySettings (chats)"`` when one source row is
            several requests).
        method: the TL method in Telegram's ``namespace.methodName``
            spelling, e.g. ``"help.getConfig"``.
        why: what the official client does and why this step is here.
        source: ``file:line`` in the official client tree the row was read
            from.
        phase: one of :data:`PHASES`.
    """

    name: str
    method: str
    why: str
    source: str
    phase: str

    def __post_init__(self) -> None:
        if self.phase not in PHASES:
            raise BootstrapError(
                f"step {self.name!r} has phase {self.phase!r}; expected one of "
                f"{list(PHASES)}"
            )

    def as_dict(self) -> typing.Dict[str, str]:
        """A JSON-friendly copy (no status; see :func:`describe`)."""
        return {
            "name": self.name,
            "method": self.method,
            "phase": self.phase,
            "source": self.source,
            "why": self.why,
        }


# ---------------------------------------------------------------------------
# the allowlists
# ---------------------------------------------------------------------------

#: Read-only startup reads.  A step whose method is not in this set (and is
#: not a cosmetic step) cannot be part of a sequence: adding one is a code
#: change that has to argue with this comment first.
SAFE_METHODS: typing.FrozenSet[str] = frozenset(
    {
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
)

#: State-mutating or authentication methods.  ``"auth.*"`` is matched as a
#: prefix (see :func:`is_forbidden`), so no ``auth.`` constructor can be
#: added by accident either.
FORBIDDEN_METHODS: typing.FrozenSet[str] = frozenset(
    {
        "account.updateStatus",
        "account.registerDevice",
        "account.resetAuthorization",
        "auth.*",
    }
)

#: The cosmetic fan-out: sticker packs, dice/animated emoji packs, the
#: reaction set and the premium promo.  Read-only, but they download a pile
#: of media a non-UI client has no use for, so they are opt-in
#: (``include_cosmetic=True``).
COSMETIC_METHODS: typing.FrozenSet[str] = frozenset(
    {
        "messages.getStickerSet",
        "messages.getFavedStickers",
        "messages.getRecentStickers",
        "messages.getFeaturedStickers",
        "messages.getArchivedStickers",
        "messages.getAllStickers",
        "messages.getAvailableReactions",
        "messages.getPremiumPromo",
    }
)


def is_forbidden(method: str) -> bool:
    """True when `method` may never be replayed (see FORBIDDEN_METHODS)."""
    if method in FORBIDDEN_METHODS:
        return True
    return method.split(".", 1)[0] == "auth"


# ---------------------------------------------------------------------------
# the sequences (spec.json, order as the source proves it)
# ---------------------------------------------------------------------------

_ANDROID: typing.Tuple[Step, ...] = (
    Step(
        name="help.getConfig",
        method="help.getConfig",
        phase="session",
        source="TMessagesProj/jni/tgnet/ConnectionsManager.cpp:3342",
        why=(
            "updateDcSettings() builds it as soon as setUserId() sees a new "
            "non-zero user id; the reply carries dc_options and the server "
            "limits that drive the rest of the startup, and it fans out into "
            "help.getAppConfig and help.getPeerColors."
        ),
    ),
    Step(
        name="help.getAppConfig",
        method="help.getAppConfig",
        phase="account",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java:425",
        why=(
            "loadAppConfig() is called from onAuthSuccess and again when "
            "getConfig completes; hash 0 asks for the whole config, which "
            "carries the feature flags and premium gating."
        ),
    ),
    Step(
        name="account.getWebBrowserSettings",
        method="account.getWebBrowserSettings",
        phase="account",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java:25364",
        why=(
            "loadWebBrowserConfig() from onAuthSuccess: the in-app browser "
            "policy, fired without any user action."
        ),
    ),
    Step(
        name="help.getPeerColors",
        method="help.getPeerColors",
        phase="account",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java:24151",
        why=(
            "checkPeerColors(false) from onAuthSuccess, guarded on a non-null "
            "current user, so it is effectively auth-only."
        ),
    ),
    Step(
        name="help.getPeerProfileColors",
        method="help.getPeerProfileColors",
        phase="account",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java:24168",
        why=(
            "the second block of the same checkPeerColors() call, sent "
            "immediately after help.getPeerColors: a provable pair ordering."
        ),
    ),
    Step(
        name="help.getPromoData",
        method="help.getPromoData",
        phase="account",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java:10885",
        why=(
            "checkPromoInfo(true) from onAuthSuccess bypasses the throttle; "
            "the reply's expires becomes the next check time."
        ),
    ),
    Step(
        name="help.getTermsOfServiceUpdate",
        method="help.getTermsOfServiceUpdate",
        phase="account",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java:10839",
        why=(
            "checkTosUpdate() at the end of the promo check, in the same task "
            "as help.getPromoData."
        ),
    ),
    Step(
        name="contacts.getContacts",
        method="contacts.getContacts",
        phase="dialogs",
        source="TMessagesProj/src/main/java/org/telegram/messenger/ContactsController.java:1522",
        why=(
            "checkAppAccount() from onAuthSuccess reads the contact list from "
            "cache and then requests it with the cached hash (0 on first "
            "run); the same list names the dialog rows."
        ),
    ),
    Step(
        name="messages.getStickerSet (placeholder pack)",
        method="messages.getStickerSet",
        phase="cosmetic",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MediaDataController.java:2834",
        why=(
            "loadStickersByEmojiOrName() for the placeholder pack at the end "
            "of onAuthSuccess: an empty-state sticker preload, cosmetics only."
        ),
    ),
    Step(
        name="langpack.getLanguages",
        method="langpack.getLanguages",
        phase="account",
        source="TMessagesProj/src/main/java/org/telegram/messenger/LocaleController.java:3135",
        why=(
            "loadRemoteLanguages() from onAuthSuccess fills the language "
            "picker; applying one is a separate, local-only step."
        ),
    ),
    Step(
        name="account.getAutoDownloadSettings",
        method="account.getAutoDownloadSettings",
        phase="account",
        source="TMessagesProj/src/main/java/org/telegram/messenger/DownloadController.java:356",
        why=(
            "fired from updateConfig() when the help.getConfig reply lands, "
            "so help.getConfig provably precedes it."
        ),
    ),
    Step(
        name="updates.getState",
        method="updates.getState",
        phase="session",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java:16235",
        why=(
            "the pts == 0 branch of getDifference() after the server's "
            "new_session_created: the native counterpart of desktop's Updates "
            "constructor getState."
        ),
    ),
    Step(
        name="account.getNotifySettings (chats)",
        method="account.getNotifySettings",
        phase="dialogs",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java:12595",
        why=(
            "loadGlobalNotificationsSettings() loops over the peer classes, "
            "one request each: inputNotifyChats first."
        ),
    ),
    Step(
        name="account.getNotifySettings (users)",
        method="account.getNotifySettings",
        phase="dialogs",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java:12595",
        why="the same loop, inputNotifyUsers.",
    ),
    Step(
        name="account.getNotifySettings (broadcasts)",
        method="account.getNotifySettings",
        phase="dialogs",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java:12595",
        why="the same loop, inputNotifyBroadcasts.",
    ),
    Step(
        name="messages.getDialogs",
        method="messages.getDialogs",
        phase="dialogs",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java:12481",
        why=(
            "loadDialogs() on the first screen after auth; the replay asks "
            "with limit 0, so it reads the same shape without mirroring the "
            "account's dialog list."
        ),
    ),
    Step(
        name="help.getRecentMeUrls",
        method="help.getRecentMeUrls",
        phase="dialogs",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java:12253",
        why=(
            "loadHintDialogs(): conditional on a Play Install Referrer string "
            "being present, included because it is in the startup batch."
        ),
    ),
    Step(
        name="users.getFullUser",
        method="users.getFullUser",
        phase="dialogs",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java:7794",
        why=(
            "loadUserInfo(currentUser) when the dialog screen opens: the own "
            "account's full user object."
        ),
    ),
    Step(
        name="help.getInviteText",
        method="help.getInviteText",
        phase="dialogs",
        source="TMessagesProj/src/main/java/org/telegram/messenger/ContactsController.java:357",
        why=(
            "checkInviteText() when the dialog list is created, skipped by "
            "the client when a cached invite link is under 24 h old."
        ),
    ),
    Step(
        name="messages.getFavedStickers",
        method="messages.getFavedStickers",
        phase="cosmetic",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MediaDataController.java:2024",
        why="checkAllMedia(false) -> loadRecents(): part of the cosmetic fan-out.",
    ),
    Step(
        name="messages.getRecentStickers",
        method="messages.getRecentStickers",
        phase="cosmetic",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MediaDataController.java:2038",
        why="the same fan-out: recently used stickers.",
    ),
    Step(
        name="messages.getFeaturedStickers",
        method="messages.getFeaturedStickers",
        phase="cosmetic",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MediaDataController.java:2324",
        why="the same fan-out: featured packs (also for emoji).",
    ),
    Step(
        name="messages.getArchivedStickers",
        method="messages.getArchivedStickers",
        phase="cosmetic",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MediaDataController.java:2603",
        why="the same fan-out: the archived pack count.",
    ),
    Step(
        name="messages.getAllStickers",
        method="messages.getAllStickers",
        phase="cosmetic",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MediaDataController.java:3042",
        why="the same fan-out: the installed sticker-set list.",
    ),
    Step(
        name="messages.getAvailableReactions",
        method="messages.getAvailableReactions",
        phase="cosmetic",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MediaDataController.java:779",
        why=(
            "the same fan-out: the reaction set. The source's own fan-out "
            "also contains help.getPremiumPromo and messages.getAvailableEffects."
        ),
    ),
    Step(
        name="messages.getStickerSet (dice emoji packs)",
        method="messages.getStickerSet",
        phase="cosmetic",
        source="TMessagesProj/src/main/java/org/telegram/ui/DialogsActivity.java:2997",
        why=(
            "a loop over MessagesController.diceEmojies, N parallel requests "
            "for the dice/animated emoji packs. Cosmetic only, and the set "
            "name is not part of the request the replay can guess."
        ),
    ),
    Step(
        name="messages.getPinnedDialogs",
        method="messages.getPinnedDialogs",
        phase="dialogs",
        source="TMessagesProj/src/main/java/org/telegram/messenger/MessagesController.java:17359",
        why=(
            "loadPinnedDialogs(folder 0) when the dialog list needs pinned "
            "ordering. Trigger is inferred in the spec, the call is not."
        ),
    ),
)

_DESKTOP: typing.Tuple[Step, ...] = (
    Step(
        name="help.getConfig",
        method="help.getConfig",
        phase="session",
        source="Telegram/SourceFiles/mtproto/config_loader.cpp:64",
        why=(
            "the first request of a new MTP instance carries the DC options, "
            "the langpack versions, the online/offline timers and the limits."
        ),
    ),
    Step(
        name="updates.getState",
        method="updates.getState",
        phase="session",
        source="Telegram/SourceFiles/api/api_updates.cpp:256",
        why=(
            "sent inside the Main::Session constructor, before the "
            "constructor body's own requests (C++ member-initialization "
            "order proves it); its completion handler issues "
            "messages.getDialogs and account.updateStatus."
        ),
    ),
    Step(
        name="help.getTermsOfServiceUpdate",
        method="help.getTermsOfServiceUpdate",
        phase="account",
        source="Telegram/SourceFiles/apiwrap.cpp:348",
        why="requestTermsUpdate() in the Main::Session constructor body, right after updates.getState.",
    ),
    Step(
        name="users.getFullUser",
        method="users.getFullUser",
        phase="account",
        source="Telegram/SourceFiles/apiwrap.cpp:1224",
        why="requestFullPeer(_user) in the same constructor body: the own account's full user.",
    ),
    Step(
        name="account.getNotifySettings (chats)",
        method="account.getNotifySettings",
        phase="account",
        source="Telegram/SourceFiles/main/main_session.cpp:270",
        why=(
            "requestNotifySettings() at the end of the constructor, one "
            "request per peer class (the same trio as Android's "
            "loadGlobalNotificationsSettings): inputNotifyChats first."
        ),
    ),
    Step(
        name="account.getNotifySettings (users)",
        method="account.getNotifySettings",
        phase="account",
        source="Telegram/SourceFiles/main/main_session.cpp:270",
        why="the same trio, inputNotifyUsers.",
    ),
    Step(
        name="account.getNotifySettings (broadcasts)",
        method="account.getNotifySettings",
        phase="account",
        source="Telegram/SourceFiles/main/main_session.cpp:270",
        why="the same trio, inputNotifyBroadcasts.",
    ),
    Step(
        name="help.getPromoData",
        method="help.getPromoData",
        phase="account",
        source="Telegram/SourceFiles/data/components/promo_suggestions.cpp:90",
        why=(
            "the same request as Android's checkPromoInfo; the desktop "
            "trigger is an rpl subscription, so whether it fires at startup "
            "depends on emission semantics (inferred in the spec)."
        ),
    ),
    Step(
        name="messages.getDialogs",
        method="messages.getDialogs",
        phase="dialogs",
        source="Telegram/SourceFiles/apiwrap.cpp:938",
        why=(
            "requestDialogs() from the updates.getState completion handler, "
            "also re-issued after every differenceDone; the replay asks with "
            "limit 0."
        ),
    ),
    Step(
        name="messages.getPinnedDialogs",
        method="messages.getPinnedDialogs",
        phase="dialogs",
        source="Telegram/SourceFiles/apiwrap.cpp:1132",
        why=(
            "issued immediately after messages.getDialogs by the same "
            "requestMoreDialogs path: a proven ordering pair, not a "
            "whenever-the-list-needs-it call."
        ),
    ),
    Step(
        name="contacts.getContacts",
        method="contacts.getContacts",
        phase="dialogs",
        source="Telegram/SourceFiles/apiwrap.cpp:892",
        why=(
            "in the getDialogs completion, hash-based, so "
            "contacts.contactsNotModified short-circuits it."
        ),
    ),
    Step(
        name="messages.getQuickReplies",
        method="messages.getQuickReplies",
        phase="dialogs",
        source="Telegram/SourceFiles/data/business/data_shortcut_messages.cpp:465",
        why=(
            "the same requestMoreDialogsIfNeeded path: business quick-reply "
            "shortcuts, hash-guarded and empty for personal accounts."
        ),
    ),
    Step(
        name="help.getAppConfig",
        method="help.getAppConfig",
        phase="account",
        source="Telegram/SourceFiles/main/main_app_config.cpp:342",
        why=(
            "Main::AppConfig subscribes to the session channel and fetches "
            "the config once auth is up, hash-based "
            "(help.appConfigNotModified on a match)."
        ),
    ),
)

#: platform -> ordered steps, cosmetic rows included in their source
#: position.  :func:`sequence` filters the cosmetic ones out by default.
BOOTSTRAP_SEQUENCES: typing.Dict[str, typing.Tuple[Step, ...]] = {
    "android": _ANDROID,
    "desktop": _DESKTOP,
}

#: The client versions the sequences were read from (spec.json).
CLIENT_VERSIONS: typing.Dict[str, str] = {"android": "12.10.6", "desktop": "7.3.3"}

#: Methods that are never replayed, with the reason.  Documentation for
#: humans and for ``--dry-run`` output; the allowlists above are the
#: enforcement.
EXCLUDED_METHODS: typing.Dict[str, str] = {
    "account.updateStatus": (
        "mutates server state: it publishes an online/last-seen time the "
        "caller did not ask for"
    ),
    "account.registerDevice": (
        "registers a push endpoint that would never receive anything; "
        "absent from desktop 7.3 entirely"
    ),
    "account.resetAuthorization": "destructive: it kills sessions",
    "auth.*": "authorization, not startup",
    "invokeWithLayer(initConnection(...))": (
        "fixed at connect time by the client; replaying it would put a "
        "second, competing envelope on the wire"
    ),
    "updates.getDifference": (
        "consumes the update queue instead of reading startup config, and "
        "is not in the audited allowlist"
    ),
    "ping_delay_disconnect": (
        "keepalive cadence, not startup (the ping layer is parity.PING_PRESETS)"
    ),
    "langpack.getLangPack": (
        "read-only but outside the audited allowlist: it applies a language "
        "the caller never asked for"
    ),
    "account.getReactionsNotifySettings": (
        "read-only but outside the audited allowlist (desktop 7.3 fetches it "
        "at session construction)"
    ),
    "messages.getDialogFilters": (
        "read-only but outside the audited allowlist (Android loads the "
        "remote folder list with the dialogs batch)"
    ),
    "messages.getAvailableEffects": (
        "read-only but outside the audited allowlist: it belongs to Android's "
        "reaction/effect cosmetic fan-out"
    ),
    "help.getNearestDc": "pre-auth only, sent before authorization",
    "account.getAuthorizations": "UI-triggered by the sessions screen, never automatic",
    "langpack.getLanguages (desktop)": (
        "a language-picker offer on desktop, not part of its bootstrap"
    ),
}

#: platform -> lang_pack for ``langpack.getLanguages``
_LANG_PACK: typing.Dict[str, str] = {"android": "android", "desktop": "tdesktop"}

#: platform aliases accepted by :func:`sequence` / :func:`platform_for`
_ALIASES: typing.Dict[str, str] = {
    "android": "android",
    "android_x": "android",
    "android-x": "android",
    "desktop": "desktop",
    "tdesktop": "desktop",
}

#: families with no source-verified sequence (yet)
_UNSUPPORTED: typing.Dict[str, str] = {
    "ios": "the iOS client ships as remote blobs, so the spec has no file:line rows for it",
    "macos": "the macOS client shares the desktop core but was not part of the F5 read",
}


# ---------------------------------------------------------------------------
# platform resolution
# ---------------------------------------------------------------------------


def _normalize_platform(platform: str) -> str:
    """Map an alias to a platform key, or raise :class:`BootstrapError`."""
    if not isinstance(platform, str):
        raise BootstrapError(f"platform must be a string, got {platform!r}")
    key = platform.strip().lower()
    if key in _ALIASES:
        return _ALIASES[key]
    if key in _UNSUPPORTED:
        raise BootstrapError(
            f"no verified sequence for {key} yet: {_UNSUPPORTED[key]}"
        )
    raise BootstrapError(
        f"unknown platform {platform!r}; expected one of {list(PLATFORMS)}"
    )


def platform_for(identity: typing.Any) -> str:
    """The platform key an identity belongs to (pure, no network).

    ``identity`` is a :class:`tgmint.fingerprint.Fingerprint`, an ``APIData``
    class or instance (anything with ``origin`` / ``lang_pack``), or a bare
    string naming an origin or a lang_pack (``"android"``, ``"android_x"``,
    ``"tdesktop"``, ``"ios"``...).

    Returns:
        ``"android"`` for the android / android_x families, ``"desktop"``
        for tdesktop.

    Raises:
        BootstrapError: the family has no verified sequence (``ios``,
            ``macos``, web), or nothing in the identity names a family.
    """
    if isinstance(identity, str):
        return _normalize_platform(identity)

    candidates = []
    for attribute in ("lang_pack", "origin"):
        value = getattr(identity, attribute, None)
        if isinstance(value, str) and value.strip():
            candidates.append(value.strip().lower())

    for value in candidates:
        if value in _ALIASES:
            return _ALIASES[value]
        if value in _UNSUPPORTED:
            raise BootstrapError(
                f"no verified sequence for {value} yet: {_UNSUPPORTED[value]}"
            )

    named = ", ".join(sorted({repr(value) for value in candidates})) or "nothing"
    raise BootstrapError(
        f"cannot infer a platform from {identity!r} ({named}); pass "
        f"--preset with one of {list(PLATFORMS)}"
    )


# ---------------------------------------------------------------------------
# the plan
# ---------------------------------------------------------------------------


def _validate(platform: str, steps: typing.Sequence[Step]) -> None:
    """Refuse a sequence that escapes the allowlists (called on every use)."""
    seen: typing.Set[str] = set()
    for step in steps:
        if not isinstance(step, Step):  # pragma: no cover - defensive
            raise BootstrapError(f"sequence contains {step!r}, expected a Step")
        if is_forbidden(step.method):
            raise BootstrapError(
                f"refusing to replay {step.name!r}: {step.method} is forbidden "
                f"({sorted(FORBIDDEN_METHODS)}), it is not a startup read"
            )
        allowed = COSMETIC_METHODS if step.phase == "cosmetic" else SAFE_METHODS
        if step.method not in allowed:
            raise BootstrapError(
                f"refusing to replay {step.name!r}: {step.method} is not in the "
                f"{'cosmetic' if step.phase == 'cosmetic' else 'safe'} "
                "allowlist, so it is not a vetted read-only startup request"
            )
        if step.method in COSMETIC_METHODS and step.phase != "cosmetic":
            raise BootstrapError(
                f"refusing to replay {step.name!r}: {step.method} is a cosmetic "
                f"request tagged phase={step.phase!r}, expected 'cosmetic'"
            )
        if step.name in seen:
            raise BootstrapError(f"duplicate step name {step.name!r}")
        seen.add(step.name)


def sequence(platform: str, *, include_cosmetic: bool = False) -> typing.Tuple[Step, ...]:
    """The ordered steps for `platform`.

    Args:
        platform: ``"android"`` or ``"desktop"`` (aliases: ``android_x``,
            ``tdesktop``).
        include_cosmetic: keep the ``phase="cosmetic"`` rows (sticker packs,
            dice emoji, reactions).  Off by default: a non-UI client gains
            nothing from them and they pull media.

    Returns:
        A tuple of :class:`Step`, in the order the official client sends
        them.

    Raises:
        BootstrapError: unknown or unsupported platform, or a sequence that
            fails the allowlist check.
    """
    key = _normalize_platform(platform)
    steps = BOOTSTRAP_SEQUENCES[key]
    if not include_cosmetic:
        steps = tuple(step for step in steps if step.phase != "cosmetic")
    _validate(key, steps)
    return steps


def describe(platform: str, *, include_cosmetic: bool = False) -> typing.Dict[str, typing.Any]:
    """The plan as plain data (pure: no client, no network, no Telethon).

    Returns a JSON-friendly dict: ``platform``, ``client_version``,
    ``include_cosmetic``, ``count`` (steps in the plan),
    ``cosmetic_steps`` (cosmetic rows in the full source sequence),
    ``excluded`` (method -> why it is never replayed) and ``steps`` (one
    dict per step, ``step`` being its 1-based position).

    Used by ``tgmint bootstrap --dry-run``, by ``tgmint.parity`` for its
    envelope summary and by the tests.
    """
    key = _normalize_platform(platform)
    plan = sequence(key, include_cosmetic=include_cosmetic)
    full = BOOTSTRAP_SEQUENCES[key]
    return {
        "platform": key,
        "client_version": CLIENT_VERSIONS[key],
        "include_cosmetic": bool(include_cosmetic),
        "count": len(plan),
        "cosmetic_steps": sum(1 for step in full if step.phase == "cosmetic"),
        "excluded": dict(EXCLUDED_METHODS),
        "steps": [
            dict({"step": index}, **step.as_dict())
            for index, step in enumerate(plan, 1)
        ],
    }


# ---------------------------------------------------------------------------
# the request builder (Telethon imported lazily, never at module scope)
# ---------------------------------------------------------------------------

#: step name suffix -> Telethon peer-class name for the notify-settings trio
_NOTIFY_PEERS: typing.Dict[str, str] = {
    "chats": "InputNotifyChats",
    "users": "InputNotifyUsers",
    "broadcasts": "InputNotifyBroadcasts",
}


def _notify_peer_class(step: Step) -> typing.Optional[str]:
    """Which ``InputNotify*`` the step name asks for (``"chats"`` etc.)."""
    if "(" not in step.name:
        return None
    suffix = step.name.rsplit("(", 1)[1].rstrip(")").strip().lower()
    return _NOTIFY_PEERS.get(suffix)


#: the neutral value the replay can honestly give an argument a newer
#: Telethon layer made mandatory (``hash=0`` is TL's "I have no cached
#: copy, send everything" idiom).  Anything else is not invented: the step
#: is skipped instead.
_NEUTRAL_ARGS: typing.Dict[str, typing.Any] = {"hash": 0}


def _complete_required_args(
    cls: typing.Any, provided: typing.Dict[str, typing.Any]
) -> typing.Optional[typing.Dict[str, typing.Any]]:
    """``provided`` plus the required constructor args the replay may fill.

    Returns ``None`` when a required argument is one this module has no
    honest value for — the caller then skips the step (which is how the
    replay reports "this layer wants an argument I cannot invent").
    """
    try:
        signature = inspect.signature(cls.__init__)
    except (TypeError, ValueError):  # pragma: no cover - C-level classes
        return None
    required: typing.List[str] = []
    for parameter in signature.parameters.values():
        if parameter.name in ("self",) or parameter.name in provided:
            continue
        if parameter.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        if parameter.default is inspect.Parameter.empty:
            required.append(parameter.name)
    unknown = [name for name in required if name not in _NEUTRAL_ARGS]
    if unknown:
        return None
    completion = dict(provided)
    for name in required:
        completion[name] = _NEUTRAL_ARGS[name]
    return completion


def _build_request(step: Step, platform: str) -> typing.Optional[typing.Any]:
    """The TLObject for `step`, or ``None`` when it cannot be built here.

    ``None`` means "skip this step": the installed Telethon has no such
    constructor (its wire layer predates the method), or the request needs
    an argument the replay cannot honestly invent (a sticker-set short
    name).  A caller that knows the argument passes its own ``request``
    builder to :func:`replay_startup`.
    """
    try:
        from telethon.tl import functions, types
    except Exception:  # telethon absent: nothing can be built, nothing crashes
        return None

    def request(module: str, name: str, **kwargs: typing.Any) -> typing.Optional[typing.Any]:
        namespace = getattr(functions, module, None)
        cls = getattr(namespace, name + "Request", None)
        if cls is None:
            return None
        try:
            return cls(**kwargs)
        except TypeError:
            # the installed Telethon layer changed the signature: 1.45
            # gave account.getWebBrowserSettings a required ``hash``, so a
            # call that was right for 1.43 raises here.  Fill the required
            # arguments this replay can answer honestly (``hash=0`` = "give
            # me the current state") and skip the step otherwise, instead
            # of failing the whole batch on a layer difference.
            completion = _complete_required_args(cls, kwargs)
            if completion is None:
                return None
            try:
                return cls(**completion)
            except TypeError:
                return None

    method = step.method
    if method == "help.getConfig":
        return request("help", "GetConfig")
    if method == "help.getAppConfig":
        return request("help", "GetAppConfig", hash=0)
    if method == "account.getWebBrowserSettings":
        return request("account", "GetWebBrowserSettings")
    if method == "help.getPeerColors":
        return request("help", "GetPeerColors", hash=0)
    if method == "help.getPeerProfileColors":
        return request("help", "GetPeerProfileColors", hash=0)
    if method == "help.getPromoData":
        return request("help", "GetPromoData")
    if method == "help.getTermsOfServiceUpdate":
        return request("help", "GetTermsOfServiceUpdate")
    if method == "contacts.getContacts":
        return request("contacts", "GetContacts", hash=0)
    if method == "langpack.getLanguages":
        return request("langpack", "GetLanguages", lang_pack=_LANG_PACK[platform])
    if method == "account.getAutoDownloadSettings":
        return request("account", "GetAutoDownloadSettings")
    if method == "updates.getState":
        return request("updates", "GetState")
    if method == "account.getNotifySettings":
        peer_name = _notify_peer_class(step)
        peer = getattr(types, peer_name, None) if peer_name else None
        if peer is None:
            return None
        return request("account", "GetNotifySettings", peer=peer())
    if method == "messages.getDialogs":
        return request(
            "messages",
            "GetDialogs",
            offset_date=None,
            offset_id=0,
            offset_peer=types.InputPeerEmpty(),
            limit=0,
            hash=0,
        )
    if method == "help.getRecentMeUrls":
        return request("help", "GetRecentMeUrls", referer="")
    if method == "users.getFullUser":
        return request("users", "GetFullUser", id=types.InputUserSelf())
    if method == "help.getInviteText":
        return request("help", "GetInviteText")
    if method == "messages.getPinnedDialogs":
        return request("messages", "GetPinnedDialogs", folder_id=0)
    if method == "messages.getQuickReplies":
        return request("messages", "GetQuickReplies", hash=0)
    if method == "messages.getFavedStickers":
        return request("messages", "GetFavedStickers", hash=0)
    if method == "messages.getRecentStickers":
        return request("messages", "GetRecentStickers", hash=0)
    if method == "messages.getFeaturedStickers":
        return request("messages", "GetFeaturedStickers", hash=0)
    if method == "messages.getArchivedStickers":
        return request("messages", "GetArchivedStickers", offset_id=0, limit=0)
    if method == "messages.getAllStickers":
        return request("messages", "GetAllStickers", hash=0)
    if method == "messages.getAvailableReactions":
        return request("messages", "GetAvailableReactions", hash=0)
    if method == "help.getNearestDc":
        return request("help", "GetNearestDc")
    # messages.getStickerSet (and anything else added without a default
    # argument) has no honest default: the caller supplies a builder.
    return None


def _make_builder(platform: str) -> typing.Callable[[Step], typing.Optional[typing.Any]]:
    """The default builder for `platform` (closes over the lang_pack)."""

    def build(step: Step) -> typing.Optional[typing.Any]:
        return _build_request(step, platform)

    return build


# ---------------------------------------------------------------------------
# the replay
# ---------------------------------------------------------------------------

#: exception classes that mean "the session or the transport is gone", so
#: the replay stops instead of recording twenty failures
_FATAL_TYPES: typing.Tuple[type, ...] = (ConnectionError, TimeoutError, OSError)

#: names of Telethon/OS errors that are fatal even without the class (a
#: fake client in a test, or a Telethon that renamed one)
_FATAL_NAMES: typing.FrozenSet[str] = frozenset(
    {
        "AuthKeyError",
        "AuthKeyUnregisteredError",
        "AuthKeyInvalidError",
        "AuthKeyPermEmptyError",
        "AuthKeyDuplicatedError",
        "SessionRevokedError",
        "SessionExpiredError",
        "UnauthorizedError",
        "UserDeactivatedError",
        "UserDeactivatedBanError",
        "RPCConnectionError",
        "ConnectionError",
        "TimeoutError",
        "OSError",
        "EOFError",
    }
)


def _telethon_fatal_types() -> typing.Tuple[type, ...]:
    """Telethon's own fatal bases, or an empty tuple without Telethon."""
    try:
        from telethon.errors import AuthKeyError, RPCConnectionError
    except Exception:  # pragma: no cover - telethon absent or renamed
        return ()
    fatal: typing.List[type] = []
    for cls in (AuthKeyError, RPCConnectionError):
        if isinstance(cls, type):
            fatal.append(cls)
    return tuple(fatal)


def _is_fatal(exc: BaseException) -> bool:
    """True when `exc` is a connection/auth failure, not a per-request one."""
    if isinstance(exc, _FATAL_TYPES):
        return True
    if type(exc).__name__ in _FATAL_NAMES:
        return True
    fatal_types = _telethon_fatal_types()
    if fatal_types and isinstance(exc, fatal_types):
        return True
    return False


def _fatal_error(
    report: typing.Dict[str, typing.Any],
    index: int,
    step: "Step",
    exc: BaseException,
) -> "BootstrapError":
    """The BootstrapError a fatal stop raises, with the partial report.

    The exception class is not enough on its own: when a replay dies at
    step 7, what the caller needs is which steps were actually sent, so
    the report built so far travels with the error.
    """
    error = BootstrapError(
        f"the replay stopped at step {index} ({step.method}): "
        f"{type(exc).__name__}: {exc} — {report['sent']} step(s) had been "
        f"sent; the partial report is attached"
    )
    error.report = report
    error.stopped_at = index
    error.sent = report["sent"]
    return error


async def replay_startup(
    client: typing.Any,
    *,
    platform: str = "android",
    include_cosmetic: bool = False,
    dry_run: bool = False,
    request: typing.Optional[typing.Callable[[Step], typing.Any]] = None,
    step_timeout: typing.Optional[float] = STEP_TIMEOUT_SECONDS,
) -> typing.Dict[str, typing.Any]:
    """Send the startup batch of `platform` through an authorized client.

    The client only needs to be callable: every step is
    ``await client(request_object)``, exactly like a Telethon client, so a
    fake with an ``async def __call__`` is enough for the tests.

    Args:
        client: an authorized, connected client.  ``None`` is allowed with
            ``dry_run=True`` (the plan is returned and nothing else runs).
        platform: ``"android"`` or ``"desktop"`` (see :func:`sequence`).
        include_cosmetic: also send the sticker/reaction fan-out.
        dry_run: return the plan with every step ``"planned"``; nothing is
            built and nothing is sent.
        request: a builder ``(Step) -> TLObject | None`` replacing the
            default one.  ``None`` returned by the builder means "skip this
            step", which is also how the default builder reports a method
            this Telethon layer cannot send and the sticker-set steps whose
            argument the replay cannot invent.
        step_timeout: per-step ceiling in seconds
            (:data:`STEP_TIMEOUT_SECONDS`, 60 s, by default); ``None`` waits
            forever.  A request that hangs must not stall the whole replay:
            the timeout stops it like any other fatal failure.

    Returns:
        ``{"platform", "include_cosmetic", "dry_run", "steps", "sent",
        "errors"}``, where each step is ``{"step", "name", "method",
        "phase", "source", "status", "detail"}`` and ``status`` is one of
        ``"sent"``, ``"skipped"``, ``"error"``, ``"planned"``.  ``errors``
        lists the failed steps (``step``, ``name``, ``method``, ``type``,
        ``error``).

    Raises:
        BootstrapError: the platform is unknown/unsupported, the sequence
            fails the allowlist check, ``dry_run`` was not requested and no
            client was given, or a *fatal* failure stopped the replay
            (:func:`_is_fatal`: a connection/auth error or a step that hit
            ``step_timeout``).  A fatal stop carries the partial report the
            run had built (``error.report``) plus ``error.stopped_at`` and
            ``error.sent``; the original exception is ``__cause__``.
            Every other exception is recorded against its step and the
            replay continues, because one failing optional request must not
            abort the session.
    """
    steps = sequence(platform, include_cosmetic=include_cosmetic)
    platform_key = _normalize_platform(platform)
    builder = request or _make_builder(platform_key)

    report: typing.Dict[str, typing.Any] = {
        "platform": platform_key,
        "include_cosmetic": bool(include_cosmetic),
        "dry_run": bool(dry_run),
        "steps": [],
        "sent": 0,
        "errors": [],
    }

    if dry_run:
        for index, step in enumerate(steps, 1):
            report["steps"].append(
                {
                    "step": index,
                    "name": step.name,
                    "method": step.method,
                    "phase": step.phase,
                    "source": step.source,
                    "status": "planned",
                    "detail": "dry run: planned, nothing was built or sent",
                }
            )
        return report

    if client is None:
        raise BootstrapError(
            "replay_startup needs a client; pass dry_run=True to only get the plan"
        )

    for index, step in enumerate(steps, 1):
        entry = {
            "step": index,
            "name": step.name,
            "method": step.method,
            "phase": step.phase,
            "source": step.source,
        }
        try:
            build = builder(step)
        except Exception as exc:  # noqa: BLE001 - a builder bug is one step
            entry["status"] = "error"
            entry["detail"] = f"could not build the request: {type(exc).__name__}: {exc}"
            report["errors"].append(
                {
                    "step": index,
                    "name": step.name,
                    "method": step.method,
                    "type": type(exc).__name__,
                    "error": str(exc),
                }
            )
            report["steps"].append(entry)
            continue
        if build is None:
            entry["status"] = "skipped"
            entry["detail"] = (
                "no request object for this step: this Telethon layer has no "
                f"{step.method} constructor, or the step needs an argument the "
                "replay cannot invent (pass request= to supply one)"
            )
            report["steps"].append(entry)
            continue
        try:
            if step_timeout is None:
                await client(build)
            else:
                await asyncio.wait_for(client(build), timeout=step_timeout)
        except Exception as exc:  # noqa: BLE001 - classified right below
            if _is_fatal(exc):
                entry["status"] = "error"
                entry["detail"] = f"{type(exc).__name__}: {exc}"
                report["errors"].append(
                    {
                        "step": index,
                        "name": step.name,
                        "method": step.method,
                        "type": type(exc).__name__,
                        "error": str(exc),
                    }
                )
                report["steps"].append(entry)
                report["stopped_at"] = index
                report["stopped_method"] = step.method
                raise _fatal_error(report, index, step, exc) from exc
            entry["status"] = "error"
            entry["detail"] = f"{type(exc).__name__}: {exc}"
            report["errors"].append(
                {
                    "step": index,
                    "name": step.name,
                    "method": step.method,
                    "type": type(exc).__name__,
                    "error": str(exc),
                }
            )
        else:
            entry["status"] = "sent"
            entry["detail"] = type(build).__name__
            report["sent"] += 1
        report["steps"].append(entry)

    return report


# ---------------------------------------------------------------------------
# the live client (Telethon, lazily)
# ---------------------------------------------------------------------------


def make_client(*, api: typing.Any, data: typing.Any) -> typing.Any:
    """Build the client a live replay runs on.

    Seam, not API: the tests replace it with a fake so the live flow can be
    exercised offline.  It reuses ``tgmint.heal``'s probe client: the
    stored auth key goes into a throwaway ``StringSession``, so the replay
    never opens (or rewrites) the caller's session file.
    """
    from .heal import make_client as heal_make_client

    return heal_make_client(kind="probe", api=api, data=data)
