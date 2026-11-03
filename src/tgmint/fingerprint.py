"""Fingerprint — the framework-neutral identity object.

A `Fingerprint` is the complete set of values a Telegram client presents
about itself on the wire (`initConnection`) plus the metadata needed to
keep them coherent: an optional IANA timezone for `params.tz_offset` and
the platform family the identity was minted for. It is deliberately a
plain frozen dataclass with `to_dict`/`from_dict` so every framework
adapter — Telethon today, the Pyrogram family next, non-Python tools via
JSON — can consume the same object without touching the legacy APIData
metaclass machinery.
"""

from __future__ import annotations

import re
from dataclasses import MISSING, dataclass, asdict, fields
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

SCHEMA_VERSION = 1

_API_HASH_RE = re.compile(r"^[0-9a-f]{32}$")

# lang_pack -> origin platform family
_LANG_PACK_ORIGINS = {
    "tdesktop": "tdesktop",
    "android": "android",
    "ios": "ios",
    "macos": "macos",
    # An empty lang_pack means "no official app claimed" — the legacy
    # upstream default. It used to map to "web", but the web presets were
    # removed outright, so nothing in this package can mint a
    # web identity any more and labelling one "web" was a lie. Stored
    # fingerprints that already carry origin="web" still load; validate()
    # stays lenient about both labels.
    "": "unofficial",
}


@dataclass(frozen=True)
class Fingerprint:
    """One complete client identity.

    Attributes:
        api_id / api_hash: the official app credentials this identity uses.
        device_model / system_version / app_version: hardware + OS + build.
        lang_code / system_lang_code / lang_pack: the language triple.
        tz_zone: optional IANA zone name; when set, clients send
            `params.tz_offset` in initConnection like official apps do.
        origin: platform family the identity belongs to
            ("tdesktop", "android", "ios", "macos", or "unofficial" when no
            official app claimed the lang_pack). Legacy sidecars may still
            carry the retired "web" label — it loads and validates fine.
        schema_version: sidecar/JSON schema version (forward compat).
    """

    api_id: int
    api_hash: str
    device_model: str
    system_version: str
    app_version: str
    lang_code: str
    system_lang_code: str
    lang_pack: str
    tz_zone: Optional[str] = None
    origin: str = ""
    schema_version: int = SCHEMA_VERSION

    # -- timezone -------------------------------------------------------

    def tz_offset(self, at: Optional[datetime] = None) -> Optional[int]:
        """Seconds east of UTC for `tz_zone` at `at` (default: now).

        A naive `at` is read as wall-clock time in the fingerprint's zone
        (what a device reporting "my offset right now" means); an AWARE
        `at` names an instant and is converted into the zone, so DST
        transitions resolve for the actual moment. Returns `None` when no
        zone is set or the zone is unknown / tzdata is unavailable —
        callers must treat that as "send no params".
        """
        if not self.tz_zone:
            return None
        try:
            from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
        except ImportError:
            return None

        try:
            zone = ZoneInfo(self.tz_zone)
        except (ZoneInfoNotFoundError, KeyError, ValueError):
            # unknown zone name, or no tzdata on this system
            return None

        if at is None:
            # "right now" is an INSTANT, not a wall-clock reading: labelling
            # the host's naive now() with the fingerprint's zone
            # (`now().replace(tzinfo=zone)`) reports the zone's offset at the
            # host's *clock digits*, which is one hour wrong for the length
            # of the host/zone DST mismatch window. Converting the same
            # instant is what a device reporting its own offset means.
            wall = datetime.now().astimezone(zone)
        elif isinstance(at, datetime):
            wall = (
                at.astimezone(zone)
                if at.tzinfo is not None
                else at.replace(tzinfo=zone)
            )
        else:
            # a bad `at` is a caller bug — say so instead of returning None
            raise TypeError(
                f"at must be a datetime or None, got {type(at).__name__}"
            )

        return int(wall.utcoffset().total_seconds())

    # -- locale ---------------------------------------------------------

    def locale_pair(self) -> Tuple[str, str]:
        return (self.lang_code, self.system_lang_code)

    # -- serialization ----------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Fingerprint":
        if not isinstance(data, dict):
            raise ValueError(f"fingerprint data must be a dict, got {type(data).__name__}")
        version = data.get("schema_version")
        if version != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported fingerprint schema_version {version!r} "
                f"(expected {SCHEMA_VERSION})"
            )
        names = {f.name for f in fields(cls)}
        # Only fields WITHOUT a dataclass default are required. tz_zone and
        # origin are defaulted, so hand-written or older sidecars that omit
        # them must load (they were previously rejected as "missing keys",
        # which made those defaults unreachable through the JSON path).
        required = {
            f.name
            for f in fields(cls)
            if f.default is MISSING and f.default_factory is MISSING
        }
        missing = required - set(data)
        if missing:
            raise ValueError(f"fingerprint data is missing keys: {sorted(missing)}")
        # unknown keys are ignored (forward compat), defaulted absent ones
        # fall back to their dataclass defaults
        return cls(**{name: data[name] for name in names if name in data})

    # -- sidecar persistence (sticky identity) -------------

    def save(self, path) -> str:
        """Persist this fingerprint as an atomic, 0600 sidecar file.

        Telegram remembers the device a session signed in with, so a
        minted identity must be minted once and reloaded ever after —
        never re-rolled. Sidecars make that a one-liner.
        """
        from .sidecar import save_sidecar

        return str(save_sidecar(path, self.to_dict()))

    @classmethod
    def load(cls, path) -> "Fingerprint":
        """Load a fingerprint from a sidecar file written by `save`."""
        from .sidecar import load_sidecar

        return cls.from_dict(load_sidecar(path))

    # -- coherence --------------------------------------------------------

    def validate(self) -> List[str]:
        """Coherence checks; returns a list of problems (empty = coherent)."""
        problems: List[str] = []

        if not isinstance(self.api_id, int) or self.api_id <= 0:
            problems.append(f"api_id should be a positive int, got {self.api_id!r}")
        if not isinstance(self.api_hash, str) or not _API_HASH_RE.match(self.api_hash):
            problems.append("api_hash must be 32 lowercase hex characters")

        for field in ("device_model", "system_version", "app_version"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"{field} must be a non-empty string")

        # locale coherence: the pair must be a known-good one, with the
        # classic en/en-US default always acceptable (legacy fingerprints).
        from .locales import known_locale_pairs

        pair = self.locale_pair()
        if pair not in known_locale_pairs() and pair != ("en", "en-US"):
            problems.append(
                f"locale pair {pair} is not a known coherent combination"
            )
        if self.tz_zone:
            try:
                from zoneinfo import ZoneInfo

                ZoneInfo(self.tz_zone)
            except Exception:
                problems.append(f"tz_zone {self.tz_zone!r} is not a known IANA zone")

        # platform soft checks — the OS string must match the origin family.
        # Deliberately LENIENT: origin labels written by older versions stay
        # on disk ("web" from the removed web presets, "unknown" from custom
        # lang_packs), so a legacy label is never itself a problem — only a
        # *plainly contradictory* (origin, system_version) pair is.
        if self.origin == "tdesktop" and self.system_version and not (
            self.system_version.startswith("Windows")
            or self.system_version.startswith("macOS")
            or self.system_version.startswith("Linux")
        ):
            problems.append(
                f"tdesktop origin but system_version {self.system_version!r} "
                "looks like a mobile OS string"
            )
        if self.origin in ("android", "ios") and self.system_version and (
            self.system_version.startswith("Windows")
            or self.system_version.startswith("macOS")
            or self.system_version.startswith("Linux")
        ):
            problems.append(
                f"{self.origin} origin but system_version {self.system_version!r} "
                "looks like a desktop OS string"
            )
        # Telegram-Swift (macOS) reports "macOS <version>" — tdesktop's lib_base
        # form. Anything else is a cross-platform mismatch: a desktop OS other
        # than macOS ("Windows 11 x64"), an Android SDK level ("SDK 35"), or a
        # bare Apple-looking version number with no prefix ("15.5", "18.5").
        if self.origin == "macos" and self.system_version and not (
            self.system_version.startswith("macOS")
        ):
            problems.append(
                f"macos origin but system_version {self.system_version!r} does "
                "not look like a macOS release (expected 'macOS <version>')"
            )

        return problems

    # -- legacy bridge ------------------------------------------------------

    @classmethod
    def from_apidata(cls, api: Union[Any, type]) -> "Fingerprint":
        """Build a Fingerprint from an `APIData` instance or class.

        Imports `tgmint.api` lazily so this module never creates an import
        cycle with the legacy machinery.
        """
        from .api import APIData

        if not isinstance(api, APIData) and not (
            isinstance(api, type) and issubclass(api, APIData)
        ):
            raise TypeError("from_apidata expects an APIData instance or class")

        return cls(
            api_id=api.api_id,
            api_hash=api.api_hash,
            device_model=api.device_model,
            system_version=api.system_version,
            app_version=api.app_version,
            lang_code=api.lang_code,
            system_lang_code=api.system_lang_code,
            lang_pack=api.lang_pack,
            tz_zone=getattr(api, "tz_zone", None),
            origin=_LANG_PACK_ORIGINS.get(api.lang_pack, "unknown"),
        )
