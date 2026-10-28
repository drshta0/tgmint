"""Parity reporting data & helpers for tgmint.

This module is INERT by design: it imports nothing at module scope that
touches the network, it changes no client behaviour, and applying its
data is always the caller's explicit choice. It exists so the CLI/audit
tooling has one canonical place to read "what would this preset's
envelope look like" and "what keepalive cadence does this preset
suggest".

Two exports:

- ``PING_PRESETS`` — pure DATA. Per-preset suggested keepalive kwargs
  for ``TelegramClient``. Telethon's own defaults are untouched and
  remain what any tgmint client actually uses until the caller passes
  these explicitly. The per-official-client cadences have NOT yet been
  verified from first-party source; every value below is
  the Telethon baseline (``ping_interval`` default 60.0 s), exposed so
  the audit can diff a session against it and so F6 verification has a
  landing spot. Do not treat these as measured official numbers.

- ``describe_envelope(target, layer=None)`` — the exact initConnection
  field dict a preset (or a minted ``APIData``) would send: the 8
  fields (api_id, device_model, system_version, app_version,
  system_lang_code, lang_pack, lang_code, params) plus ``api_hash``
  (identity, not wire-visible) and the ``layer`` the identity claims.
  ``params`` carries ``tz_offset`` (seconds) when a timezone zone was
  minted (Generate(locale=...)), and is empty otherwise. When
  ``layer`` is not given it is reverse-looked-up from the version
  tables in ``tgmint.layers`` — i.e. the layer that minted
  ``app_version`` genuinely speaks — and is ``None`` when the version
  is not in any table (e.g. the Android pin's build code differs from
  the table's commit-verified string).

Bootstrap-sequence parity (which requests fire right
after auth, in what order) is deliberately NOT included here: there is
no live oracle to verify such a sequence against offline, and shipping
an unverified sequence would be exactly the kind of confidently-wrong
data this fork exists to eliminate. It stays opt-in future work.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Type, Union

from .api import APIData, API
from .layers import ANDROID_LAYERS, IOS_LAYERS, TD_LAYERS

__all__ = ["PING_PRESETS", "describe_envelope"]

# Keys map to presets; values are SUGGESTED TelegramClient kwargs.
# Inert data — see module docstring. Values are Telethon's baseline,
# not measured official cadences (verification pending).
PING_PRESETS: Dict[str, Dict[str, float]] = {
    "tdesktop": {"ping_interval": 60.0},
    "android": {"ping_interval": 60.0},
    "android_x": {"ping_interval": 60.0},
    "ios": {"ping_interval": 60.0},
    "macos": {"ping_interval": 60.0},
}

_PRESETS = {
    "tdesktop": API.TelegramDesktop,
    "android": API.TelegramAndroid,
    "android_x": API.TelegramAndroidX,
    "ios": API.TelegramIOS,
    "macos": API.TelegramMacOS,
}

# version -> layer, for reverse lookup (first match wins; version
# strings are unique across the tables in practice)
_REVERSE = {}
for _table in (TD_LAYERS, ANDROID_LAYERS, IOS_LAYERS):
    for _layer, _version in _table.items():
        _REVERSE.setdefault(_version, _layer)


def _tz_offset_seconds(zone: str) -> int:
    """Current UTC offset of `zone` in seconds (initConnection params)."""
    from datetime import datetime
    from zoneinfo import ZoneInfo

    return int(datetime.now(ZoneInfo(zone)).utcoffset().total_seconds())


def describe_envelope(
    target: Union[str, Type[APIData], APIData], layer: Optional[int] = None
) -> Dict[str, Any]:
    """The exact initConnection envelope a preset or minted identity sends.

    ``target`` is either a preset key (``"tdesktop"``, ``"android"``,
    ``"android_x"``, ``"ios"``, ``"macos"``) or an ``APIData`` class /
    minted instance (anything ``Generate()`` returned). Returns a dict
    with the 8 initConnection fields + ``api_hash`` + ``layer``:

    ```
    {
        "api_id": ..., "api_hash": ...,
        "device_model": ..., "system_version": ..., "app_version": ...,
        "system_lang_code": ..., "lang_pack": ..., "lang_code": ...,
        "params": {"tz_offset": <seconds>} | {},
        "layer": <int or None>,
    }
    ```

    ``layer``: the explicit argument wins; otherwise the layer the
    minted ``app_version`` genuinely speaks, reverse-looked-up from
    ``tgmint.layers`` (``None`` when the version is not in a table —
    e.g. a pinned-current string whose build code differs from the
    commit-verified table row). See the module docstring for why
    bootstrap-sequence parity is deliberately absent.
    """
    if isinstance(target, str):
        try:
            target = _PRESETS[target]
        except KeyError:
            raise ValueError(
                f"unknown preset {target!r}; expected one of {sorted(_PRESETS)}"
            ) from None

    cls = target if isinstance(target, type) else type(target)

    if not (isinstance(cls, type) and issubclass(cls, APIData)):
        raise TypeError(f"expected a preset key, APIData class or instance, got {target!r}")

    if layer is not None:
        resolved_layer = int(layer)
    else:
        resolved_layer = _REVERSE.get(target.app_version)

    params: Dict[str, Any] = {}
    zone = getattr(target, "tz_zone", None)
    if zone:
        params["tz_offset"] = _tz_offset_seconds(zone)

    return {
        "api_id": target.api_id,
        "api_hash": target.api_hash,
        "device_model": target.device_model,
        "system_version": target.system_version,
        "app_version": target.app_version,
        "system_lang_code": target.system_lang_code,
        "lang_pack": target.lang_pack,
        "lang_code": target.lang_code,
        "params": params,
        "layer": resolved_layer,
    }
