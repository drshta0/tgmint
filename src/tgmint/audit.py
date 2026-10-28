"""Reusable fingerprint auditing — coherence, tz sanity, staleness.

Library layer under the ``tgmint audit`` CLI:
pure functions over :class:`~tgmint.fingerprint.Fingerprint` objects —
no file I/O, no network, no hidden state. The CLI adds sidecar loading
and printing on top; everything here must stay importable and testable
in isolation (and offline).

Three independent checks:

* **coherence** — :meth:`Fingerprint.validate`: credential shapes, the
  locale pair, origin-vs-OS agreement and the tz_zone name.
* **tz sanity** — a fingerprint that *has* a zone must actually yield a
  ``tz_offset``. If it cannot (unknown zone, missing tzdata) the client
  would silently omit ``initConnection.params`` and drift from what a
  real device in that zone sends.
* **staleness** — is ``app_version`` a recognizable release of the
  identity's app family, and how does it compare to the compiled-in
  :data:`~tgmint.versions.PINNED` table? An *older* release is NOT a
  problem — layer-coherent minting (``tgmint.layers``) deliberately
  claims e.g. ``6.7.8`` for wire layer 224 — but an *unrecognizable*
  version is flagged: no official client ever shipped it.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional

from .versions import PINNED

if TYPE_CHECKING:  # pragma: no cover - typing only, no runtime import
    from .fingerprint import Fingerprint

__all__ = [
    "app_family",
    "base_version",
    "staleness_report",
    "tz_report",
    "audit_fingerprint",
]

# api_id -> app family (the keys of versions.PINNED). The api_id is the
# authoritative signal; the origin fallback below only fires for custom
# credentials that kept an official lang_pack.
_FAMILY_BY_API_ID = {
    2040: "tdesktop",
    6: "android",
    21724: "android_x",
    10840: "ios",
    2834: "macos",
    2496: "web_z",
}

# origin (lang_pack-derived) -> app family. "android" is ambiguous
# (Telegram and Telegram X share the lang_pack), so api_id decides there.
_FAMILY_BY_ORIGIN = {
    "tdesktop": "tdesktop",
    "android": "android",
    "ios": "ios",
    "macos": "macos",
    "web": "web_z",
}

# leading dotted version: "7.3.3 x64" -> "7.3.3", "13.1.0 (72291)" ->
# "13.1.0", "1.0.1 K" -> "1.0.1". Anything else ("MyClient", "") -> "".
_BASE_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)+)")


def app_family(fp: "Fingerprint") -> Optional[str]:
    """The :data:`~tgmint.versions.PINNED` app family this identity
    belongs to, or ``None`` when it cannot be determined.

    The official ``api_id`` wins (it separates android from android_x,
    which share the ``android`` lang_pack); the origin fallback covers
    custom credentials minted against an official platform family.
    """
    family = _FAMILY_BY_API_ID.get(fp.api_id)
    if family is None:
        family = _FAMILY_BY_ORIGIN.get(fp.origin)
    return family


def base_version(app_version: Any) -> str:
    """Strip the platform suffix from an ``app_version``.

    Official versions carry build noise — tdesktop appends `` x64`` /
    `` arm64``, Android appends `` (72291)`` — so staleness compares the
    bare dotted version. Returns ``""`` when nothing version-shaped
    leads the string.
    """
    if not isinstance(app_version, str):
        return ""
    match = _BASE_VERSION_RE.match(app_version.strip())
    return match.group(1) if match else ""


def _version_key(version: str):
    """``"7.3.3"`` -> ``(7, 3, 3)`` for ordering; ``()`` if unparseable."""
    try:
        return tuple(int(part) for part in version.split("."))
    except (ValueError, AttributeError):
        return ()


def staleness_report(
    fp: "Fingerprint", pinned: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Compare ``fp.app_version`` against the pinned release of its family.

    Pure and offline: the default pin table is the compiled-in
    :data:`~tgmint.versions.PINNED` (module import touches no network);
    tests may pass their own table.

    Returns a dict with::

        app            the PINNED family key, or None if unrecognized
        app_version    the raw app_version string
        base_version   app_version with the platform suffix stripped
        pinned         the pinned release for the family (str or None)
        status         "current" | "outdated" | "ahead" | "unknown"
        known_release  True when the version is recognizable at all
        detail         a human-readable sentence

    Status semantics (see module docstring): only ``unknown`` is treated
    as a problem by :func:`audit_fingerprint`; ``outdated`` is often the
    *intended* result of layer-coherent minting, and ``ahead`` means the
    local pin table has rotted behind reality.
    """
    pinned_table = PINNED if pinned is None else dict(pinned)
    family = app_family(fp)
    base = base_version(fp.app_version)
    pin = pinned_table.get(family) if family else None
    pin_base = base_version(pin) if isinstance(pin, str) else ""

    key = _version_key(base)
    pin_key = _version_key(pin_base)

    if family is None:
        status = "unknown"
        detail = (
            f"app family unknown (api_id={fp.api_id}, origin={fp.origin!r}); "
            "cannot judge staleness"
        )
    elif not base or key == ():
        status = "unknown"
        detail = (
            f"app_version {fp.app_version!r} does not look like a "
            f"release of the {family} family"
        )
    elif pin and pin_key == ():
        # defensive: a malformed PINNED entry must not crash the audit
        status = "unknown"
        detail = f"pinned {family} version {pin!r} is malformed"
    elif not pin:
        status = "unknown"
        detail = f"no pinned version for the {family} family"
    elif key == pin_key:
        status = "current"
        detail = f"{base} is the pinned {family} release"
    elif key < pin_key:
        status = "outdated"
        detail = (
            f"{base} is older than the pinned {pin_base} for {family} "
            "(expected for layer-coherent minting)"
        )
    else:
        status = "ahead"
        detail = (
            f"{base} is newer than the pinned {pin_base} for {family}; "
            "the local pin table may be stale"
        )

    return {
        "app": family,
        "app_version": fp.app_version,
        "base_version": base,
        "pinned": pin,
        "status": status,
        "known_release": status in ("current", "outdated", "ahead"),
        "detail": detail,
    }


def tz_report(fp: "Fingerprint", at: Optional[datetime] = None) -> Dict[str, Any]:
    """Timezone sanity for one fingerprint.

    ``at`` (default: now, resolved inside :meth:`Fingerprint.tz_offset`)
    is exposed so callers and tests can pin the evaluation instant.

    Returns a dict with ``zone``, ``tz_offset`` (seconds east of UTC or
    ``None``), ``status`` (``ok`` | ``unset`` | ``unresolvable``) and a
    human ``detail``. ``unset`` is not a problem — legacy fingerprints
    legitimately send no ``params`` — but ``unresolvable`` is: the
    identity *claims* a zone the machine cannot honor.
    """
    if not fp.tz_zone:
        return {
            "zone": None,
            "tz_offset": None,
            "status": "unset",
            "detail": "no tz_zone set: the client sends no params (legacy behaviour)",
        }

    offset = fp.tz_offset(at)
    if offset is None:
        return {
            "zone": fp.tz_zone,
            "tz_offset": None,
            "status": "unresolvable",
            "detail": (
                f"tz_offset for {fp.tz_zone!r} could not be computed "
                "(unknown zone or missing tzdata); params would be omitted"
            ),
        }

    return {
        "zone": fp.tz_zone,
        "tz_offset": offset,
        "status": "ok",
        "detail": f"tz_offset {offset:+d}s for {fp.tz_zone}",
    }


def audit_fingerprint(
    fp: "Fingerprint",
    pinned: Optional[Dict[str, str]] = None,
    at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Full audit: coherence problems, tz sanity and staleness.

    Returns a dict with::

        ok          False iff `problems` is non-empty
        problems    list of strings — each one a reason the identity is
                    unhealthy (coherence failures, an unresolvable
                    timezone, an unrecognizable app_version)
        warnings    non-fatal observations (an intentionally outdated
                    version, a pin table older than the fingerprint)
        checks      one-line status per check: coherence / tz / staleness
        tz          the :func:`tz_report` dict
        staleness   the :func:`staleness_report` dict

    Pure: no I/O, no network, deterministic for a fixed `at`.
    """
    coherence_problems = list(fp.validate())
    problems = [f"coherence: {p}" for p in coherence_problems]

    tz = tz_report(fp, at=at)
    if tz["status"] == "unresolvable":
        problems.append(f"tz: {tz['detail']}")

    staleness = staleness_report(fp, pinned=pinned)
    warnings = []
    if staleness["status"] == "unknown":
        problems.append(f"staleness: {staleness['detail']}")
    elif staleness["status"] in ("outdated", "ahead"):
        warnings.append(f"staleness: {staleness['detail']}")

    return {
        "ok": not problems,
        "problems": problems,
        "warnings": warnings,
        "checks": {
            "coherence": "ok" if not coherence_problems else "problems",
            "tz": tz["status"],
            "staleness": staleness["status"],
        },
        "tz": tz,
        "staleness": staleness,
    }
