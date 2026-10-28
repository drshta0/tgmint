"""Layer-to-version coherence for Telegram Desktop.

Telegram's MTProto schema has a layer number; every official app release
speaks exactly one layer. A library client that claims ``app_version``
7.2.8 while invoking a different layer is internally contradictory — no
real 7.2.8 ever did that — so this module maps wire layers to the newest
Telegram Desktop release that genuinely spoke each layer.

How this table was built (all first-hand, 2026-10-24):

1. Listed the commit history of
   ``Telegram/SourceFiles/mtproto/scheme/api.tl`` in telegramdesktop/tdesktop
   via the GitHub API and collected the "Update API scheme to layer N"
   bump commits (first commit date per layer).
2. Listed the GitHub releases with their publish dates.
3. For each layer L, the newest release published after L's bump and
   before the next layer's bump is the newest release speaking L.
4. Verified with the compare API that the bump commit is an ancestor of
   the chosen tag for 210 -> v5.16.6, 224 -> v6.7.8 and 232 -> v7.3.3
   (status "behind": the tag contains the bump, so it speaks the layer).

Gap layers (e.g. 212, 213, 215, 217, 219, 222, 223, 226, 230) had no
tdesktop release between their bump and the next bump — tdesktop never
shipped them. ``pick_app_version`` resolves those to the closest lower
layer's version, which keeps the claim conservative (a slightly older
real version) instead of internally impossible (a newer version on an
older wire layer).

Notable: Telethon 1.43.2 speaks layer 224, whose newest tdesktop is
**6.7.8** — minting the "current" 7.2.8 on a Telethon session is exactly
the mismatch this module exists to prevent.

Sources:
- commits: https://api.github.com/repos/telegramdesktop/tdesktop/commits?path=Telegram/SourceFiles/mtproto/scheme/api.tl
- releases: https://api.github.com/repos/telegramdesktop/tdesktop/releases
- compare (verification): https://api.github.com/repos/telegramdesktop/tdesktop/compare/{tag}...{sha}
"""

from __future__ import annotations

from typing import Dict, Optional

# layer -> (newest tdesktop release speaking it, bump commit sha).
# Every entry verified 2026-10-24 with the method in the module docstring.
_TD_LAYERS: Dict[int, tuple] = {
    210: ("5.16.6", "9b990728f64f142f7ca3ce8e45c147c1680f0733"),
    211: ("6.0.3", "043bc754ae72ba660936f6a0439df1a0e4d94710"),
    214: ("6.1.4", "d51944e6a5fa42cfaddbf948fe3777e1b226f6e5"),
    216: ("6.2.6", "6974c511ea612f2ec50cd63b4cbe0d20b06abb4c"),
    218: ("6.3.4", "424f416fdd8deaa816b2785a3de6f74a68ebb454"),
    220: ("6.3.10", "23880ac6c120713070ef01908bbca398aa3aab05"),
    221: ("6.4.4", "7f70af58ee43936a5791a776b82b832f1723b4a2"),
    224: ("6.7.8", "affbcea601e0ef1f43ac1064a70c1e21f1ecba64"),
    225: ("6.8.5", "9636dbe71a03c09e720d6f4fd428b0e0b4edcc17"),
    227: ("6.9.4", "b1e012c466c57b128f2fcd37f987b4ac3bfdce6d"),
    228: ("7.0.9", "da3cc6156a6662b82b933ba3875e5cff2b44b25a"),
    229: ("7.2.10", "7d92b89078a3628739e15e703d7e06ec8b4ad69d"),
    231: ("7.3.1", "15c5b16f6d5e5a534c7838c8f7672d3b73562d54"),
    232: ("7.3.3", "850fb90eb6db96c124b6da1349060f9ed00f4fe4"),
}

TD_LAYERS: Dict[int, str] = {layer: version for layer, (version, _) in _TD_LAYERS.items()}

# layer -> the bump commit that introduced it (for docs/audit).
LAYER_SOURCES: Dict[int, str] = {
    layer: (
        f"https://github.com/telegramdesktop/tdesktop/commit/{sha} "
        f"(layer {layer} bump; release mapping via GitHub releases, verified 2026-10-24)"
    )
    for layer, (_, sha) in _TD_LAYERS.items()
}


def tdesktop_version_for_layer(layer: int) -> Optional[str]:
    """The newest Telegram Desktop release that genuinely speaks `layer`.

    Returns `None` for layers no tdesktop release ever shipped (the gaps)
    or unknown layers.
    """
    return TD_LAYERS.get(layer)


def pick_app_version(origin: str, layer: int, fallback: str) -> str:
    """Layer-coherent app_version for an identity.

    For ``origin == "tdesktop"``: the newest tdesktop release speaking
    `layer`; gap layers resolve to the closest *lower* layer's version
    (conservative — a slightly older real version, never a version that
    postdates the wire layer). For every other origin the `fallback` is
    returned unchanged: this passthrough is pinned by public tests, and
    the mobile mappings live in ``pick_mobile_app_version`` (same
    closest-lower rule, refusal below the verified floor).
    """
    if origin != "tdesktop":
        return fallback

    exact = tdesktop_version_for_layer(layer)
    if exact is not None:
        return exact

    # gap layers BETWEEN two known layers resolve to the closest lower
    # layer's version; a layer outside the covered span (older than the
    # table, or newer than any shipped tdesktop — a future layer) falls
    # back to the caller's version: claiming a release that "speaks" a
    # layer newer than it actually does would be incoherent.
    known = sorted(TD_LAYERS)
    if known[0] < layer < known[-1]:
        lower = [k for k in known if k < layer]
        return TD_LAYERS[max(lower)]
    return fallback


# ---------------------------------------------------------------------------
# Mobile layer tables
#
# Method — 100% first-hand, mirroring the discipline of _TD_LAYERS above:
#
# 1. Listed the commit history of DrKLO/Telegram's
#    ``TMessagesProj/src/main/java/org/telegram/tgnet/TLRPC.java`` via the
#    GitHub API. Release commits literally say "update to 13.1.0 (7229)".
#    The ``LAYER`` constant lives ONLY in that file, so any release whose
#    window contains no TLRPC.java commit speaks the previous layer.
# 2. For each selected release commit below, fetched the raw TLRPC.java AT
#    THAT SHA and read ``public static final int LAYER = N;`` directly:
#
#      214 -> "update to 12.0.0 (6163)"  aa5fe2ee8c9711e0a615cc955fba0ca040896144  2025-09-01
#      216 -> "update to 12.1.1 (6211)"  9cbf03332a5a68fce3e616852d7dc929022c8441  2025-10-15
#      221 -> "update to 12.3.0 (6377)"  28e25a4ca767b1fadc3c5ad8ba09acbe37ba6af3  2026-01-15
#      227 -> "update to 12.8.0 (6913)"  68d51749c4fcbaffa584829f23936565df55e08b  2026-06-16
#      232 -> "update to 13.1.0 (7229)"  4de548e79fed27f1a66fbdff84223321838fe925  2026-10-25
#
# 3. The negative fact that makes the table safe between rows: between
#    2026-01-15 (12.3.0, layer 221) and 2026-06-16 (12.8.0, layer 227)
#    the file had NO commits at all — so Android releases 12.4.x through
#    12.7.x all spoke layer 221, and NO Android release ever spoke
#    222-226. In particular the answer to "which Android app_version is
#    coherent on Telethon 1.43.2's wire layer 224?" is **12.3.0 (6377)**
#    (via closest-lower), NOT the current 13.1.0 — a real 13.1.0 speaks
#    232 and the pair (13.1.0, 224) is impossible on any real device.
#
# Cross-check note: stufently/opentele (opentele-ng) was the suggested
# secondary source, but its repo tree 404'd within the research budget;
# every row above is first-hand from DrKLO source instead, which is the
# stronger claim anyway. Rows are NOT interpolated — gaps resolve via
# closest-lower in pick_mobile_app_version().
#
# Telegram X (API.TelegramAndroidX) is served by the same table: it is
# the same DrKLO lineage and tracks mainline's LAYER constant, but its
# own app_version scheme differs (0.x.y) — minting a mainline version
# string for an X api_id is a documented approximation.
#
# layer -> (app_version, provenance).
_ANDROID_LAYERS: Dict[int, tuple] = {
    214: ("12.0.0 (6163)", "aa5fe2ee8c9711e0a615cc955fba0ca040896144"),
    216: ("12.1.1 (6211)", "9cbf03332a5a68fce3e616852d7dc929022c8441"),
    221: ("12.3.0 (6377)", "28e25a4ca767b1fadc3c5ad8ba09acbe37ba6af3"),
    227: ("12.8.0 (6913)", "68d51749c4fcbaffa584829f23936565df55e08b"),
    232: ("13.1.0 (7229)", "4de548e79fed27f1a66fbdff84223321838fe925"),
}

ANDROID_LAYERS: Dict[int, str] = {
    layer: version for layer, (version, _) in _ANDROID_LAYERS.items()
}

ANDROID_LAYER_SOURCES: Dict[int, str] = {
    layer: (
        f"https://github.com/DrKLO/Telegram/commit/{sha} "
        f"(TLRPC.java at this sha: LAYER = {layer}; "
        f"commit message names the app_version; verified 2026-10-25)"
    )
    for layer, (_, sha) in _ANDROID_LAYERS.items()
}

# iOS: the layer constant is generated into submodules/TelegramApi
# (submodules/TelegramApi/swift_scheme.tl in 2026-era trees). Verified
# first-hand: TelegramMessenger/Telegram-iOS commit
# 0d88328885dc5a99abe6ea69348bf2bd37a93ab6 "TelegramApi, TelegramCore:
# API layer 232" (2026-10-13) states the schema IS the complete
# layer-232 schema and serialization reports layer 232. The repo's
# GitHub releases stopped in 2023 (10.0.3), so no release-by-release
# join is possible from public data; the one row below is joined to the
# current App Store pin 13.1.1 (tgmint.versions, verified via the
# iTunes lookup 2026-09/10 — master >= 2026-10-13 is what 13.1.1
# shipped from). Fewer rows with solid provenance beat guesses; layers
# below the floor are refused rather than estimated.
_IOS_LAYERS_TABLE: Dict[int, tuple] = {
    232: ("13.1.1", "0d88328885dc5a99abe6ea69348bf2bd37a93ab6"),
}

IOS_LAYERS: Dict[int, str] = {
    layer: version for layer, (version, _) in _IOS_LAYERS_TABLE.items()
}

IOS_LAYER_SOURCES: Dict[int, str] = {
    layer: (
        f"https://github.com/TelegramMessenger/Telegram-iOS/commit/{sha} "
        f"(\"API layer {layer}\" schema bump; version joined via the "
        f"13.1.1 App Store pin — GitHub releases stopped 2023-09; "
        f"verified 2026-10-25)"
    )
    for layer, (_, sha) in _IOS_LAYERS_TABLE.items()
}

# macOS stays pin-only: the TelegramSwift pbxproj raw URL
# 404s (documented in tgmint.versions), so no layer= support there yet.

_MOBILE_TABLES = {
    "android": ANDROID_LAYERS,
    "androidx": ANDROID_LAYERS,
    "ios": IOS_LAYERS,
}


def android_version_for_layer(layer: int) -> Optional[str]:
    """The newest Telegram for Android release that genuinely speaks `layer`.

    `None` for layers no verified Android release spoke (the gaps, e.g.
    222-226) or unknown layers.
    """
    return ANDROID_LAYERS.get(layer)


def ios_version_for_layer(layer: int) -> Optional[str]:
    """The Telegram for iOS release that genuinely speaks `layer` (sparse)."""
    return IOS_LAYERS.get(layer)


def pick_mobile_app_version(platform: str, layer: int, fallback: str) -> str:
    """Layer-coherent app_version for a mobile preset (closest-lower).

    ``platform`` is one of ``"android"``, ``"androidx"``, ``"ios"``.
    Android and AndroidX share the DrKLO table (see module docstring).

    Resolution, mirroring the tdesktop rule in `pick_app_version`:
      - exact table hit -> that release;
      - a gap between two rows -> the closest *lower* row's release
        (conservative: a slightly older real version, never a release
        that postdates the wire layer);
      - a layer NEWER than the table's newest row -> `fallback` (the
        pinned-current release still speaks an older layer, which stays
        coherent);
      - a layer OLDER than the table's oldest row -> `ValueError`. There
        is no verified release to claim and silently returning the
        current pin would mint exactly the impossible
        (new-version, old-layer) pair this module exists to prevent.

    (``pick_app_version`` itself keeps its documented non-tdesktop
    passthrough — its mobile-origin behaviour is pinned by public
    tests; mobile callers use this function instead.)
    """
    try:
        table = _MOBILE_TABLES[platform]
    except KeyError:
        raise ValueError(
            f"platform must be one of {sorted(_MOBILE_TABLES)}, got {platform!r}"
        ) from None

    exact = table.get(layer)
    if exact is not None:
        return exact

    known = sorted(table)
    if layer > known[-1]:
        # future layer: claiming the newest release stays coherent
        return fallback
    if layer < known[0]:
        raise ValueError(
            f"layer {layer} is older than the oldest verified "
            f"{platform} mapping (layer {known[0]}); refusing to mint "
            f"an unverified (app_version, layer) pair — pass "
            f"layer=None to keep the pinned-current behaviour"
        )
    lower = [k for k in known if k < layer]
    return table[max(lower)]


def telethon_layer() -> int:
    """The TL layer of the installed Telethon (its wire layer)."""
    try:
        from telethon.tl.alltlobjects import LAYER
    except ImportError as exc:
        raise RuntimeError(
            "telethon_layer() needs telethon installed — it is not"
        ) from exc
    return LAYER
