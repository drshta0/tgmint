# Acknowledgments

tgmint stands on other people's work. Everything below was taken with
gratitude, under the terms of its license; where code or data was adopted
the file headers say so, and the strongest credit — the preserved upstream
git history — is one `git log` away.

- **[thedemons/opentele](https://github.com/thedemons/opentele)** (MIT) — the
  upstream this repository *is*: the 2022 tdata/Telethon conversion
  machinery, the official-API presets and device pools, and the
  `initConnection` fingerprint trick this whole library descends from. Its
  `LICENSE` and copyright notice are kept verbatim, and its commits remain
  in our history.
- **[stufently/opentele](https://github.com/stufently/opentele)** ("opentele-ng",
  MIT) — the sibling fork we read before writing our own: the reference for
  the pure-Python `QDataStream` port (our Qt-free tdata codec), for
  layer-alignment thinking, and for tolerating tdata `lskType` variants we
  would otherwise have rejected.
- **[nazar220160/TGConvertor](https://github.com/nazar220160/TGConvertor)**
  (MIT) — the session-conversion matrix done right, long before us: the
  reference design for our Telethon / Pyrogram-family / GramJS / tdata
  session codec.
- **[batreller/AndroidTelePorter](https://github.com/batreller/AndroidTelePorter)**
  (MIT, on PyPI) — the prior art for reading the official Android app's
  `tgnet.dat` + `userconfing.xml` as a session source, in Python,
  before us. Our `android-dir` codec was cross-checked against it and
  makes no "first" claim; where it parses the `user` blob through
  Telethon's TL machinery, ours stays stdlib-only.
- **[DrKLO/Telegram](https://github.com/DrKLO/Telegram)** (GPL-2.0-or-later;
  source consulted, no code taken) — the official Android client whose
  `TMessagesProj/jni/tgnet/` serialization defines the `tgnet.dat`
  format our `android-dir` reader implements; every field cites the
  file and the pinned commit it was verified against.
- **[LonamiWebs/Telethon](https://github.com/LonamiWebs/Telethon)** (MIT) —
  the MTProto client everything here runs on, and whose documented internals
  made the scoped `initConnection` override possible.
- **The [pyrogram](https://github.com/pyrogram/pyrogram) /
  [kurigram](https://github.com/KurimuzonAkuma/pyrogram) ecosystem** — for
  the `Client` parameter surface our kwargs adapter relies on, the session
  storage formats our codec reads, and the docs that documented both.
