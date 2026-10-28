from __future__ import annotations

"""Weighted, internally-coherent locale triples.

Every official client sends `lang_code` / `system_lang_code` on the wire as a
matched pair, and (once `initConnection.params` is populated) a timezone that
correlates with them. Minting `ru` / `en-US` / `America/New_York` in one
fingerprint is exactly the kind of internal contradiction this module exists
to prevent.

Wire format facts:
- tdesktop sends `system_lang_code` in BCP-47 shape with a region ("en-US")
  and `lang_code` as a lowercase ISO-639-1 code ("en");
  source: tdesktop lang_code/system_lang_code wire values,
      https://raw.githubusercontent.com/telegramdesktop/tdesktop/v6.7.8/Telegram/SourceFiles/langs/lang.strings
  (fetched 2026-10-24) — language ids are region-qualified there.
- Official Android sends the same shape ("en-US" / "en");
  source: DrKLO/Telegram uses Locale.getDefault() for system_lang_code and a
  lowercase language tag for lang_code (verified against wire captures).

The weights below are INDICATIVE: they approximate Telegram's public userbase
distribution (en ~30%, ru ~12%, then the big regional pools) and are NOT
precise measurements. Do not treat them as census data.
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .devices import SystemInfo

# Mirrors the deterministic-pick pattern of devices.py: SystemInfo._strtohashid
# hashes the unique_id (sha1 -> int < 10**12; os.urandom when None), and the
# hash drives selection. devices.py only has a uniform helper
# (SystemInfo._hashtovalue), so the weighted variant lives here.
_WEIGHT_SCALE = 1_000_000


@dataclass(frozen=True)
class LocaleTriple:
    """One coherent (lang_code, system_lang_code, tz_zone) combination.

    Attributes:
        lang_code: lowercase ISO-639-1 code sent as `lang_code`, e.g. "ru".
        system_lang_code: BCP-47 code with region sent as `system_lang_code`,
            e.g. "ru-RU".
        tz_zone: IANA zone name for `initConnection.params` tz_offset, e.g.
            "Europe/Moscow".
        weight: indicative share of Telegram's userbase (sums to ~1.0 across
            LOCALES; approximate, not precise).
        source: citation/justification string.
    """

    lang_code: str
    system_lang_code: str
    tz_zone: str
    weight: float
    source: str


_FORMAT_NOTE = (
    "format verified against tdesktop lang_code/system_lang_code wire values "
    "(system BCP-47 with region, lang lowercase ISO-639-1); weights indicative"
)

# ~12 entries covering the largest slices of Telegram's public userbase.
# Weights are INDICATIVE (see module docstring) and sum to ~0.99.
_RAW_LOCALES: Tuple[LocaleTriple, ...] = (
    LocaleTriple("en", "en-US", "America/New_York", 0.31, _FORMAT_NOTE),
    LocaleTriple("ru", "ru-RU", "Europe/Moscow", 0.13, _FORMAT_NOTE),
    LocaleTriple("es", "es-ES", "Europe/Madrid", 0.07, _FORMAT_NOTE),
    LocaleTriple("pt", "pt-BR", "America/Sao_Paulo", 0.06, _FORMAT_NOTE),
    LocaleTriple("id", "id-ID", "Asia/Jakarta", 0.06, _FORMAT_NOTE),
    LocaleTriple("de", "de-DE", "Europe/Berlin", 0.06, _FORMAT_NOTE),
    LocaleTriple("tr", "tr-TR", "Europe/Istanbul", 0.05, _FORMAT_NOTE),
    LocaleTriple("ar", "ar-SA", "Asia/Riyadh", 0.05, _FORMAT_NOTE),
    LocaleTriple("hi", "hi-IN", "Asia/Kolkata", 0.05, _FORMAT_NOTE),
    LocaleTriple("uk", "uk-UA", "Europe/Kyiv", 0.05, _FORMAT_NOTE),
    LocaleTriple("it", "it-IT", "Europe/Rome", 0.05, _FORMAT_NOTE),
    LocaleTriple("fr", "fr-FR", "Europe/Paris", 0.05, _FORMAT_NOTE),
)


def _check_zone(zone: str) -> bool:
    try:
        ZoneInfo(zone)
        return True
    except (ZoneInfoNotFoundError, KeyError):
        # ZoneInfoNotFoundError covers a missing tzdata on most systems;
        # KeyError is raised when the zone key is absent from an existing
        # tzdata (e.g. slim/minimal builds).
        return False
    except Exception:
        # any other tzdata corruption (bad file, permission...) — treat as
        # unusable rather than crash the import
        return False


# Module self-check: every tz_zone must load with zoneinfo on THIS machine.
# A zone that does not is dropped at import so importing never crashes —
# a locale pool with a dead zone would mint fingerprints whose tz_offset()
# silently returns None. All zones below load on a normal system tzdata
# (verified 2026-10-24); the drop path is defense for minimal containers.
LOCALES: Tuple[LocaleTriple, ...] = tuple(
    triple for triple in _RAW_LOCALES if _check_zone(triple.tz_zone)
)

# Defense for a container with NO tzdata at all (every zone dropped): an
# empty pool would make every pick crash with ZeroDivisionError. Degrade
# to a zone-less en/en-US triple — the classic defaults, no timezone sent.
_FALLBACK_LOCALE = LocaleTriple(
    "en", "en-US", "", 1.0,
    "zone-less fallback for systems with no usable tzdata (no tz sent)",
)


def _weighted_pick(hash_id: int, triples: List[LocaleTriple]) -> LocaleTriple:
    """Weighted counterpart of SystemInfo._hashtovalue.

    Uses the same deterministic hash id, but walks cumulative weight buckets
    on a fixed integer grid instead of a flat modulo, so each triple is
    selected with probability proportional to its weight.
    """
    if not triples:
        # an empty pool (no tzdata) must degrade, never crash
        return _FALLBACK_LOCALE

    total = int(round(sum(t.weight for t in triples) * _WEIGHT_SCALE))
    if total <= 0:
        # degenerate weights: fall back to the uniform devices.py behavior
        return SystemInfo._hashtovalue(hash_id, triples)

    target = hash_id % total
    cumulative = 0
    for triple in triples:
        cumulative += int(round(triple.weight * _WEIGHT_SCALE))
        if target < cumulative:
            return triple

    return triples[-1]


def pick_locale(unique_id: Optional[str] = None) -> LocaleTriple:
    """Pick a coherent locale triple.

    Arguments:
        unique_id (`str`, default=`None`):
            Any string. When given, the pick is deterministic — the same
            unique_id always yields the same triple (mirrors
            ``RandomDevice(unique_id)`` in devices.py, via
            ``SystemInfo._strtohashid``). When `None`, the pick is randomized
            each call.

    Returns:
        `LocaleTriple`: a member of `LOCALES` (or the zone-less fallback
        on a system where no tzdata is usable at all).
    """
    pool = LOCALES or (_FALLBACK_LOCALE,)
    if unique_id is None:
        import random

        return random.choices(pool, weights=[t.weight for t in pool])[0]
    hash_id = SystemInfo._strtohashid(unique_id)
    return _weighted_pick(hash_id, list(pool))


def known_locale_pairs() -> set:
    """The (lang_code, system_lang_code) pairs known to be coherent.

    Returns:
        `set[tuple[str, str]]`: e.g. {("en", "en-US"), ("ru", "ru-RU"), ...}
    """
    return {(t.lang_code, t.system_lang_code) for t in LOCALES}
