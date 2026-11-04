# How it works

## What Telegram sees when a client connects

Every MTProto connection opens with `initConnection`. It's a handful of
strings that tell the server which app is talking:

| Field | Example (`tgmint mint --preset desktop --system linux`) |
|---|---|
| `api_id` / `api_hash` | `2040` / `b18441a1…` (Telegram Desktop's official pair) |
| `device_model` | `MS-7640` |
| `system_version` | `Linux XFCE X11 glibc 2.39` |
| `app_version` | `7.3.3` |
| `system_lang_code`, `lang_pack`, `lang_code` | `it-IT`, `tdesktop`, `it` |
| params | timezone (`Europe/Rome`, +3600 s) |

Together, these strings are the client's **fingerprint**. They show up in
*Settings → Devices*, and the server can compare them against what that app
version really sends.

Libraries ship defaults that don't look like any official app (Telethon
reports your Python platform, for example). Older identity packs give away
age instead: a 2022 app version speaking a 2026 wire layer is a combination
no real install ever produced.

## The three properties tgmint enforces

**Current.** Device pools and app versions come from live sources, and
every value carries the URL it was verified against. `tgmint freshness`
shows the pins, and a weekly CI job fails if any of them drift from what the
official apps actually ship.

**Coherent.** Fields have to agree with each other:

- the claimed `app_version` actually spoke the TL **layer** your framework
  uses (`Generate(layer=N)`),
- the device model existed when that OS version did (no 2014 phone on
  Android 16),
- the language triple and timezone form a believable locale.

`tgmint audit` checks a fingerprint against all of these rules.

**Sticky.** A real device doesn't change model between logins. Mint once,
save the fingerprint as a **sidecar** next to the session, and reload it
from then on. `Generate(unique_id=...)` is deterministic, so the same seed
always produces the same identity.

## Sessions vs identities

A **session** is the secret: an `auth_key` plus the data center it belongs
to. A **fingerprint** is the public face that goes with it. tgmint keeps the
two together but separate:

- the codec moves the **session** between formats (`convert`),
- the sidecar carries the **fingerprint**,
- the `.tgmint` envelope bundles both, plus an optional **passkey**, into
  one file per account.

## Where tgmint stops

- **The Bot API** speaks HTTPS, not MTProto, so it has no fingerprint
  surface. tgmint doesn't pretend to change one, and passkeys can't work
  there either.
- **Server policy wins.** tgmint makes a client accurate. It doesn't
  promise anything about how Telegram treats an account, and it makes no
  anti-ban claims.
- **Own accounts only.** There are no batch modes or multi-account
  orchestration, and there never will be.
