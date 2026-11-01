# Post-auth startup: what tgmint replays, what it refuses

After you authorize, the official app does not wait for you to tap anything. It sends a
fixed batch of configuration and contact reads, in a fixed order, and only then draws a
screen. `python -m tgmint bootstrap` replays that batch for one platform preset, so a
session tgmint minted behaves like the app whose identity it wears instead of like a
client that skips half of its own startup.

This page says exactly what is sent, what is left out and why. The sequence itself is
data in `tgmint/bootstrap.py`; every step carries the `file:line` in the official
client source it was read from.

> Status note, 2026-10-31: this is a faithful *reconstruction from the official source*,
> not an observed packet capture. It has not been replayed against a live account in
> this repo yet, and two rows are marked `inferred` in the spec (desktop
> `help.getPromoData`, Android `messages.getPinnedDialogs`).

## Command

```bash
# print the plan, no session, no socket
python -m tgmint bootstrap --preset android --dry-run
python -m tgmint bootstrap --preset desktop --dry-run --json

# replay it into one session you own
python -m tgmint bootstrap --preset android --session me.session
python -m tgmint bootstrap --session me.session          # platform from the sidecar
python -m tgmint bootstrap --preset android --session me.session --include-cosmetic
```

`--preset auto` (the default) reads the platform off the fingerprint sidecar recorded
next to the session: `android` / `android_x` become `android`, `tdesktop` becomes
`desktop`, and `ios` / `macos` are refused by name because no sequence has been read
out of those trees. An explicit `--preset` always wins. Live mode needs `--session`;
`--dry-run` needs neither a session nor a network.

## What a replay sends (android, default: 19 requests)

Read out of DrKLO's Android 12.10.6 tree. `help.getConfig` is first because
`setUserId()` fires it the moment auth lands; everything before it in `onAuthSuccess`
is local state, not a request.

| # | Request | Phase | Why it is there |
|---|---|---|---|
| 1 | `help.getConfig` | session | DC options and the server limits every later step reads, and the fan-out into steps 2 and 4 |
| 2 | `help.getAppConfig` | account | feature flags and premium gating (hash 0 = full config) |
| 3 | `account.getWebBrowserSettings` | account | in-app browser policy, fired with no user action |
| 4 | `help.getPeerColors` | account | peer colour palette, auth-guarded |
| 5 | `help.getPeerProfileColors` | account | the second half of the same call: a provable pair |
| 6 | `help.getPromoData` | account | proxy/promo suggestion, throttle bypassed on auth |
| 7 | `help.getTermsOfServiceUpdate` | account | ToS prompt, same task as step 6 |
| 8 | `contacts.getContacts` | dialogs | the contact list (hash 0 on first run) |
| 9 | `langpack.getLanguages` | account | language picker list |
| 10 | `account.getAutoDownloadSettings` | account | auto-download presets, from the config reply |
| 11 | `updates.getState` | session | the `pts == 0` branch after `new_session_created` |
| 12-14 | `account.getNotifySettings` ×3 | dialogs | global mute state per peer class (chats, users, broadcasts) |
| 15 | `messages.getDialogs` | dialogs | the first screen (`limit 0`: shape, not a mirror) |
| 16 | `help.getRecentMeUrls` | dialogs | hint dialogs (conditional on an install referrer) |
| 17 | `users.getFullUser` | dialogs | the own account's full user object |
| 18 | `help.getInviteText` | dialogs | invite-a-friend default text |
| 19 | `messages.getPinnedDialogs` | dialogs | pinned order for folder 0 (trigger `inferred`) |

Desktop 7.3.3 (13 requests) starts with `help.getConfig` then `updates.getState`, because
`updates.getState` fires *inside* the `Main::Session` constructor before the constructor
body requests `help.getTermsOfServiceUpdate`, `users.getFullUser` and the same
`account.getNotifySettings` trio. Its dialogs batch is `messages.getDialogs` →
`messages.getPinnedDialogs` → `contacts.getContacts` → `messages.getQuickReplies`, and
`help.getAppConfig` follows once the session channel is up. Desktop has no cosmetic rows
in the sequence: its sticker panel loads lazily.

## Cosmetic fan-out (opt-in, `--include-cosmetic`)

Android fires a wide sticker/reaction preload when the dialog list is created: two
`messages.getStickerSet` calls (an empty-state placeholder pack and the dice/animated
emoji packs), `messages.getFavedStickers`, `messages.getRecentStickers`,
`messages.getFeaturedStickers`, `messages.getArchivedStickers`,
`messages.getAllStickers`, `messages.getAvailableReactions` (and, in the same code,
`help.getPremiumPromo` and `messages.getAvailableEffects`). They are tagged
`phase="cosmetic"` and left out by default, because a non-UI client gains nothing from
them and they pull media. Two of them (`messages.getStickerSet`) are skipped even when
you opt in: the replay cannot honestly invent a sticker-set name, so pass your own
builder if you need them.

## What is never replayed, and why

| Excluded | Reason |
|---|---|
| `account.updateStatus` | **mutates server state.** It publishes an online/last-seen time you did not ask for. `--include-cosmetic` does not reach it; it is on the forbidden list. |
| `account.registerDevice` | **actively harmful without a real push token.** It registers an endpoint that will never receive anything. Desktop 7.3 does not call it at all. |
| `account.resetAuthorization` | destructive: it kills sessions. |
| `auth.*` | authorization, not startup. Matched as a prefix, so no `auth.` constructor can slip in. |
| `invokeWithLayer(initConnection(...))` | **fixed at connect time.** The client sends the minted envelope once per session (`tgmint.tl`); replaying it would put a second, competing envelope on the wire. The desktop spec lists it at row 2 for exactly that reason. |
| `updates.getDifference` | consumes the update queue instead of reading startup config, and is not in the audited read-only allowlist. |
| `ping_delay_disconnect` | keepalive cadence, not startup. That is the ping layer: see [docs/cadence.md](./cadence.md) for the verified official numbers and what each framework can actually set. |
| `help.getNearestDc` | pre-auth only: it is sent *before* authorization. |
| `account.getAuthorizations` | UI-triggered by the sessions screen, never automatic. |
| `langpack.getLangPack`, `messages.getDialogFilters`, `account.getReactionsNotifySettings`, `messages.getAvailableEffects` | read-only, but outside the audited allowlist; adding one is a code change that has to argue with the allowlist first. |

The enforcement is an allowlist, not a denylist: a step may only send a method in
`SAFE_METHODS` (plus `COSMETIC_METHODS` when you opt in), and `sequence()` /
`replay_startup()` validate the shipped data on every use and raise `BootstrapError` if a
step escapes. `FORBIDDEN_METHODS` is refused separately, on top of that.

## Own account only

This is the same posture as `tgmint heal`: one account, one session, invoked by its
owner, no batch mode, no daemon, no "replay every session in this folder". Everything it
sends is a read against the account whose auth key you already hold; it grants no
access, mints no identity and logs in as nobody.

## Failure behaviour

A failed request is recorded against its step and the replay **continues** (one optional
request must not abort a session). Connection- and auth-level failures (`OSError`,
`TimeoutError`, Telethon's `AuthKeyError` family, `UnauthorizedError`) are re-raised
instead, because carrying on would just produce twenty identical errors. The CLI exits
`0` when the batch ran (per-request failures are in the report), `1` when the replay
itself failed, `2` for bad usage or an unresolvable platform.

## Verification status

* Verified offline (`tests/test_bootstrap.py`, 75 tests): the shipped order, the
  allowlist and forbidden gates, cosmetic filtering, the replay loop against a fake
  client (exact order, one failing request recorded while the rest continue, fatal
  errors re-raised, dry run building and sending nothing), the default request builder
  producing real Telethon objects, the CLI's dry run and its refusal without a session,
  and `import tgmint.bootstrap` with Telethon absent.
* Not verified: a live replay against a real account, and therefore that Telegram's
  answers match what the official apps get. That needs an account you own; the honest
  way to try it is `--dry-run` first, then a live run on a throwaway session.
