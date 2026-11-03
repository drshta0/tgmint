"""
Live version resolver for the official Telegram clients — offline-first.

Every static fork's preset data rots within months, so
the pins baked into ``api.py`` are only the fallback of *last* resort
here. ``current_version(app)`` resolves through this chain:

1. a cache entry younger than ``CACHE_TTL_SECONDS`` (24 h) — no network;
2. one HTTPS lookup (stdlib ``urllib`` only, 3 s budget) written back to
   the cache;
3. a stale cache entry (``offline=True`` stops here, network untouched);
4. the compiled-in ``PINNED`` value.

The design rule is absolute: a login must NEVER be delayed or blocked by
a version lookup. Every failure path — DNS, timeout, HTTP error, an HTML
layout change on the fragile endpoints, a corrupt or unwritable cache —
degrades silently to the pin instead of raising. The only exception is
an unknown app name, which is a programming error (``KeyError``).

Endpoint notes, all verified live while writing this module (2026-10):
GitHub's releases API and the iTunes lookup are stable JSON; the Web Z
``version.txt`` now 301-redirects to ``/a/version.txt`` (the same app,
renamed) which ``urlopen`` follows transparently; the macOS pbxproj URL
returns 404 on the ``main`` branch, so macOS is pin-only in practice
(that fetcher stays wired for the day the file moves back); APKPure is
an anti-bot-protected HTML page parsed best-effort — ANY mismatch there
means None, i.e. the pin.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import tempfile
import time
import urllib.request

__all__ = ["PINNED", "SOURCES", "CACHE_TTL_SECONDS", "current_version"]

# Compiled-in fallbacks — exactly the app_version pins of the API.*
# presets in api.py (data refreshed 2026-09/10). Each value cites the
# source URL from api.py's comments that it was verified against; the
# weekly freshness job keeps them current.
PINNED: dict[str, str] = {
    "tdesktop": "7.3.3",            # https://github.com/telegramdesktop/tdesktop/releases
    # DrKLO's own wire string: TLRPC.java at the 13.1.0 commit carries
    # APP_VERSION_CODE 7229 (the APK's ABI-split versionCode is 72291).
    # Must equal layers.ANDROID_LAYERS[232] or parity can never resolve the
    # layer of a pinned-current Android identity.
    "android": "13.1.0 (7229)",     # https://github.com/DrKLO/Telegram
    "android_x": "0.29.1 (1817)",  # https://github.com/DrKLO/Telegram
    "ios": "13.1.1",                # https://github.com/TelegramMessenger/Telegram-iOS
    "macos": "11.14.1",             # https://github.com/overtake/TelegramSwift
}

# Where each app's live version is read from — exported for docs and the
# audit command. These are the same URLs the _fetch_*
# helpers below hit; no telemetry, no query strings, one GET per app.
SOURCES: dict[str, str] = {
    "tdesktop": "https://api.github.com/repos/telegramdesktop/tdesktop/releases/latest",
    "android": "https://apkpure.com/telegram/org.telegram.messenger",
    "android_x": "https://apkpure.com/telegram-x/org.thunderdog.challegram",
    "ios": "https://itunes.apple.com/lookup?id=686449807",
    "macos": (
        "https://raw.githubusercontent.com/overtake/TelegramSwift/main/"
        "Telegram/Telegram%20iOS/Telegram.xcodeproj/project.pbxproj"
    ),
}

# A fresh-enough cache entry short-circuits the network entirely.
CACHE_TTL_SECONDS: int = 86400  # 24 h

# Some endpoints 403 the default "Python-urllib/3.x" agent (APKPure sits
# behind anti-bot protection), so send a plain desktop browser UA.
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

# app -> name of its _fetch_* helper. Values are NAMES, not function
# objects, and are resolved through this module's globals at call time —
# that indirection is what lets tests patch e.g. tgmint.versions.
# _fetch_td_desktop in place and have current_version see the mock.
FETCHERS: dict[str, str] = {
    "tdesktop": "_fetch_td_desktop",
    "android": "_fetch_android",
    "android_x": "_fetch_android_x",
    "ios": "_fetch_ios",
    "macos": "_fetch_macos",
}


# ---------------------------------------------------------------------------
# cache
# ---------------------------------------------------------------------------

def _cache_path() -> pathlib.Path:
    """Cache file location: $XDG_CACHE_HOME/tgmint/versions.json (or
    ~/.cache/...), falling back to tempfile.gettempdir()/tgmint-versions.json
    when the cache directory cannot be created or written — an unusable
    cache must never make current_version raise."""
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    candidate = pathlib.Path(base) / "tgmint" / "versions.json"
    try:
        candidate.parent.mkdir(parents=True, exist_ok=True)
        if os.access(candidate.parent, os.W_OK):
            return candidate
    except OSError:
        pass
    return pathlib.Path(tempfile.gettempdir()) / "tgmint-versions.json"


def _load_cache(path: pathlib.Path | None = None) -> dict:
    """Read the cache; a missing or corrupt file counts as empty (the
    next successful fetch overwrites it). Cache IO is always non-fatal."""
    try:
        data = json.loads((path or _cache_path()).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_cache(cache: dict, path: pathlib.Path | None = None) -> None:
    """Best-effort write (temp file + os.replace, so a crash mid-write
    can never leave a torn file behind). Failure to write is silently
    ignored — it only means one extra network lookup next time."""
    target = path or _cache_path()
    tmp = target.with_name(f".{target.name}.tmp.{os.getpid()}")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(cache, fp, indent=2, sort_keys=True)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp, target)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# network helpers
# ---------------------------------------------------------------------------

def _http_get(url: str, timeout: float) -> str | None:
    """GET ``url`` and return the decoded body, or None on ANY failure
    (offline-first: a network error just means "use the pin")."""
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception:
        return None


def _fetch_td_desktop(timeout: float) -> str | None:
    """Latest tdesktop release tag from the GitHub releases API
    (``tag_name`` is "v7.3.3"-shaped; the leading "v" is stripped)."""
    body = _http_get(SOURCES["tdesktop"], timeout)
    if body is None:
        return None
    try:
        return str(json.loads(body)["tag_name"]).lstrip("v")
    except Exception:
        return None


def _fetch_ios(timeout: float) -> str | None:
    """Telegram for iOS version from Apple's iTunes lookup API."""
    body = _http_get(SOURCES["ios"], timeout)
    if body is None:
        return None
    try:
        return str(json.loads(body)["results"][0]["version"])
    except Exception:
        return None


# e.g. `MARKETING_VERSION = 11.14.1;` in the Xcode project file
_MACOS_VERSION_RE = re.compile(r"MARKETING_VERSION\s*=\s*(\d+\.\d+\.\d+)")


def _fetch_macos(timeout: float) -> str | None:
    """Telegram-Swift (macOS) MARKETING_VERSION from the raw pbxproj.

    Pin-only in practice: the file 404s on the current ``main`` branch
    (verified 2026-10), and no other endpoint exposes the Swift app's
    version, so macOS normally resolves via PINNED. Kept wired for the
    day the file returns — a 404 or a missing match is just None.
    """
    body = _http_get(SOURCES["macos"], timeout)
    if body is None:
        return None
    try:
        match = _MACOS_VERSION_RE.search(body)
        return match.group(1) if match else None
    except Exception:
        return None


def _android_version_from(version_name: str, version_code: int | None) -> str | None:
    """Normalize APKPure's fields into the official ``"x.y.z (code)"``
    app_version shape used by the android/android_x pins.

    APKPure serves the **ABI-split** ``versionCode``, which carries one
    extra trailing digit on top of the code the app itself prints in
    ``app_version``: Telegram 13.1.0 is versionCode 72291 but reports
    ``"13.1.0 (7229)"`` on the wire (DrKLO's own TLRPC.java at the 13.1.0
    commit says 7229 — see ``tgmint.layers.ANDROID_LAYERS[232]``). So a
    code of 5+ digits is truncated by that one split digit; otherwise the
    fetched string would never match the verified table or the pin.

    Telegram X is worse: "0.29.1.1817-arm64-v8a" with split code 1817302,
    where the *fourth name component* is the base code — that wins over
    any truncation of the code field.

    ``version_code=None`` means the page did not expose the field at all
    (no code is emitted); ``0`` is a real reported value and is kept, not
    treated as absent.
    """
    try:
        name = version_name.split("-", 1)[0].strip()  # drop "-arm64-v8a" etc.
        parts = name.split(".")

        code: str | None = None
        if version_code is not None:
            code_num = int(version_code)
            if code_num >= 0:
                # ABI split: "<printed code><abi digits>", e.g. 7229 ->
                # 72291 and 1817 -> 1817302. Strip split digits until the
                # code is back in the 4-digit range the app prints.
                while code_num >= 10000:
                    code_num //= 10
                code = str(code_num)

        if len(parts) == 4 and parts[3].isdigit():
            code = parts[3]  # "0.29.1.1817" -> version 0.29.1, code 1817
            parts = parts[:3]
        version = ".".join(parts)
        if not version or not re.fullmatch(r"[\d]+(\.[\d]+)*", version):
            return None
        return f"{version} ({code})" if code is not None else version
    except Exception:
        return None


def _fetch_android_page(url: str, package: str, timeout: float) -> str | None:
    """Parse APKPure's app page — fragile by design.

    The page embeds a JSON blob anchored on the package name carrying
    ``versionName``/``versionCode``. APKPure is an anti-bot-protected
    HTML page that can change layout or 403 at any time: ANY failure
    (fetch, match, parse) returns None and the caller falls back to the
    pin. ``[^{}]*?`` keeps the match inside that one JSON object.
    """
    html = _http_get(url, timeout)
    if html is None:
        return None
    try:
        pattern = re.compile(
            r'"packageName"\s*:\s*"' + re.escape(package) + r'"'
            r'[^{}]*?"versionName"\s*:\s*"([^"]*)"'
            r'[^{}]*?"versionCode"\s*:\s*(\d+)'
        )
        match = pattern.search(html)
        if not match:
            return None
        return _android_version_from(match.group(1), int(match.group(2)))
    except Exception:
        return None


def _fetch_android(timeout: float) -> str | None:
    """Best-effort Telegram for Android version from APKPure."""
    return _fetch_android_page(SOURCES["android"], "org.telegram.messenger", timeout)


def _fetch_android_x(timeout: float) -> str | None:
    """Best-effort Telegram X for Android version from APKPure."""
    return _fetch_android_page(SOURCES["android_x"], "org.thunderdog.challegram", timeout)


def _resolve_fetcher(app: str):
    """The _fetch_* helper for ``app`` resolved through module globals at
    call time (see FETCHERS), or None for a pin-only app."""
    name = FETCHERS.get(app)
    return globals().get(name) if name else None


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def current_version(
    app: str,
    *,
    timeout: float = 3.0,
    force_refresh: bool = False,
    offline: bool = False,
) -> str:
    """Resolve the current version of an official app.

    Chain: (1) fresh cache entry -> return it. (2) network lookup (unless
    ``offline``) -> update cache -> return. (3) stale cache entry (when
    offline, with no network attempt at all). (4) the ``PINNED`` value.
    NEVER raises on lookup failures; any error degrades to PINNED[app].

    Arguments:
        app (`str`):
            One of the PINNED keys — ``tdesktop``, ``android``,
            ``android_x``, ``ios``, ``macos``.

        timeout (`float`, default=`3.0`):
            Per-request network budget. A login must never be delayed by
            this resolver, so keep it small.

        force_refresh (`bool`, default=`False`):
            Skip step (1) even if the cache is fresh. A failed refresh
            still falls back to stale cache, then pin.

        offline (`bool`, default=`False`):
            Never touch the network — fresh/stale cache, then pin.

    Raises:
        `KeyError`: unknown app name (a programming error).
    """
    if app not in PINNED:
        raise KeyError(
            f"unknown app {app!r}; known apps: {sorted(PINNED)}"
        )

    cache_path = _cache_path()
    cache = _load_cache(cache_path)
    versions = cache.get("versions") if isinstance(cache.get("versions"), dict) else {}
    fetched_at = cache.get("fetched_at") if isinstance(cache.get("fetched_at"), dict) else {}
    now = time.time()

    # 1. fresh cache — no network at all. The stamp must be sane: a
    # garbage or future-dated fetched_at (clock skew, corrupted file, a
    # poisoned cache) must NOT count as "fresh forever" — the lower bound
    # forces a re-check, which then falls back to the stale entry anyway.
    if not force_refresh and app in versions:
        stamp = fetched_at.get(app)
        if (
            isinstance(stamp, (int, float))
            and 0 <= (now - stamp) < CACHE_TTL_SECONDS
        ):
            return str(versions[app])

    # 2. one network lookup (unless offline), written back to the cache
    if not offline:
        fetcher = _resolve_fetcher(app)
        if fetcher is not None:
            try:
                version = fetcher(timeout)
            except Exception:
                # the _fetch_* helpers never raise by contract; if one
                # does anyway (a bug), degrade to pin, never blow up a
                # login over a version string
                version = None
            if version:
                versions[app] = version
                fetched_at[app] = now
                _save_cache({"fetched_at": fetched_at, "versions": versions}, cache_path)
                return version

    # 3. stale cache — even after a failed refresh this beats the pin
    if app in versions:
        return str(versions[app])

    # 4. the compiled-in pin
    return PINNED[app]
