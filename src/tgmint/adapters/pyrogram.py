"""Pyrogram-family kwargs adapter.

Converts a tgmint identity — a :class:`tgmint.fingerprint.Fingerprint`
(preferred) or a legacy ``APIData`` instance/class — into constructor
kwargs for the **Pyrogram family** of MTProto clients:

* `kurigram <https://github.com/KurimuzonAkuma/pyrogram>`_ (active successor)
* `pyrofork <https://github.com/pyrogram/pyrofork>`_
* vanilla `pyrogram <https://github.com/pyrogram/pyrogram>`_
* `hydrogram <https://github.com/hydrogram/hydrogram>`_

Three of them ship the identical import name ``pyrogram``; hydrogram ships
as ``hydrogram`` and mirrors the same constructor — and that is the whole
point: Pyrogram's ``Client`` accepts
``device_model``, ``system_version``, ``app_version``, ``lang_code`` and
``lang_pack`` as native constructor arguments and forwards them verbatim into
its ``initConnection``
(see the `Client docs <https://docs.pyrogram.org/api/client>`__ and
`initConnection <https://docs.pyrogram.org/telegram/functions/init-connection>`__).
**No monkey-patching is needed** — unlike Telethon, which hard-codes
``lang_pack=""`` and needs the scoped override in ``tgmint.tl``.

::

    from tgmint.adapters.pyrogram import client_kwargs
    from pyrogram import Client

    fp = ...  # mint once, keep forever (sidecar)
    client = Client("myaccount", **client_kwargs(fp), in_memory=True)

Layer coherence: mint the fingerprint with ``layer=`` set to the
layer the *target framework* actually speaks — Telethon's layer and
Pyrogram's layer are different numbers. :func:`installed_layer` reads
``pyrogram.raw.all.layer`` from whatever ``pyrogram`` distribution is
importable, without making it a dependency of this module.

.. note::
   **Bot API frameworks (python-telegram-bot, aiogram) have no
   ``initConnection`` surface at all** — they speak HTTPS to the Bot API
   server, which never transmits a client fingerprint. Fingerprinting does
   not apply there; those users get API presets for self-hosted Bot API
   servers and session codecs instead. TDLib users do have
   the surface: see :func:`tdlib_params`.

Bridge-surface concept ported from opentele-ng's ``pyrogram_bridge.py``
(MIT, https://github.com/stufently/opentele — ``_client_params`` /
``pyrogram_layer``); the tgmint adapter consumes the minted
:class:`~tgmint.fingerprint.Fingerprint` rather than ported fixtures.
This module is dependency-free: stdlib + ``tgmint.fingerprint`` only.
"""

from __future__ import annotations

from typing import Any, Dict, Union

from ..fingerprint import Fingerprint

__all__ = [
    "PYROGRAM_KWARGS_FIELDS",
    "TDLIB_PARAMS",
    "pyrogram_kwargs",
    "client_kwargs",
    "tdlib_params",
    "installed_layer",
]

#: The five ``initConnection`` presentation fields every Pyrogram-family
#: ``Client`` accepts natively. kurigram (verified 2.2.26) additionally
#: accepts ``system_lang_code`` and ``init_connection_params`` — opt in via
#: the corresponding flags on :func:`client_kwargs` / :func:`pyrogram_kwargs`
#: so the default dict stays valid for vanilla pyrogram too.
PYROGRAM_KWARGS_FIELDS = (
    "device_model",
    "system_version",
    "app_version",
    "lang_code",
    "lang_pack",
)

#: TDLib consumes only these three identity strings — via the
#: ``x_tdlib_parameters``/authorization bundle or the matching
#: ``setOption`` calls (``version``, ``android_device`` etc. depending on
#: binding; the keys here are the canonical td_api parameter names).
TDLIB_PARAMS = (
    "device_model",
    "system_version",
    "app_version",
)

_Identity = Union[Fingerprint, Any]  # Any = APIData instance or subclass


def _coerce(identity: _Identity) -> Fingerprint:
    """Normalize Fingerprint | APIData-instance | APIData-class -> Fingerprint.

    ``Fingerprint`` is the preferred input (zero legacy machinery); the
    legacy ``APIData`` paths keep ``API.<Preset>.Generate(...)`` results and
    even the preset *classes* working unchanged.
    """
    if isinstance(identity, Fingerprint):
        return identity

    from ..api import APIData

    if isinstance(identity, APIData) or (
        isinstance(identity, type) and issubclass(identity, APIData)
    ):
        return Fingerprint.from_apidata(identity)

    raise TypeError(
        "identity must be a tgmint.fingerprint.Fingerprint or an APIData "
        f"instance/class, got {type(identity).__name__}"
    )


def pyrogram_kwargs(
    identity: _Identity,
    *,
    system_lang_code: bool = False,
) -> Dict[str, str]:
    """The five presentation kwargs every Pyrogram-family ``Client`` takes.

    Returns ``device_model``, ``system_version``, ``app_version``,
    ``lang_code``, ``lang_pack`` — exactly the fingerprint's fields,
    verbatim; no defaults are invented here. Pass
    ``system_lang_code=True`` to also include the fingerprint's
    ``system_lang_code``: kurigram (2.2.26) and pyrofork accept it natively;
    vanilla pyrogram's ``Client`` does not, hence the opt-in.
    """
    fp = _coerce(identity)
    kwargs: Dict[str, str] = {name: getattr(fp, name) for name in PYROGRAM_KWARGS_FIELDS}
    if system_lang_code:
        kwargs["system_lang_code"] = fp.system_lang_code
    return kwargs


def client_kwargs(
    identity: _Identity,
    *,
    system_lang_code: bool = False,
    tz_params: bool = False,
    **overrides: Any,
) -> Dict[str, Any]:
    """Full constructor kwargs: :func:`pyrogram_kwargs` + ``api_id``/``api_hash``.

    Everything in the returned dict is accepted natively by every
    ``pyrogram``-named ``Client`` (credentials + the five presentation
    fields), so ``Client(name, **client_kwargs(fp), in_memory=True)`` needs
    no patching. Explicit keyword arguments override fingerprint values —
    useful for pinning ``app_version`` to a specific release.

    Two opt-in extras (kurigram ≥ 2.x; pyrofork-class builds):

    * ``system_lang_code=True`` — also pass the fingerprint's
      ``system_lang_code`` (vanilla pyrogram has no such argument).
    * ``tz_params=True`` — pass ``init_connection_params={"tz_offset": …}``
      from the fingerprint's timezone, matching what official
      clients send in ``initConnection.params``. Omitted entirely (not set
      to ``None``) when the fingerprint has no usable zone.
    * ``init_connection_params={...}`` — set that bundle explicitly. It is
      the very key ``tz_params=True`` injects, so it is an accepted override
      (an explicit value replaces the tz-derived dict rather than raising
      ``TypeError``).

    Fork quirk to know about: kurigram's ``Client.__init__`` lowercases
    every language field (verified 2.2.26), so a minted ``"ru-RU"``
    ``system_lang_code`` reaches the wire as ``"ru-ru"`` — that folding
    happens inside the framework, after the verbatim hand-off here.

    The Bot API note applies: if your framework is python-telegram-bot or
    aiogram, these parameters do not exist on its constructors — Bot API
    has no client-fingerprint surface.
    """
    fp = _coerce(identity)
    kwargs: Dict[str, Any] = {
        "api_id": fp.api_id,
        "api_hash": fp.api_hash,
        **pyrogram_kwargs(fp, system_lang_code=system_lang_code),
    }
    if tz_params:
        offset = fp.tz_offset()
        if offset is not None:
            kwargs["init_connection_params"] = {"tz_offset": offset}
    unknown = set(overrides) - {
        *PYROGRAM_KWARGS_FIELDS,
        "api_id",
        "api_hash",
        "system_lang_code",
        # the same key ``tz_params=True`` injects: passing it explicitly is a
        # legitimate override (pin/replace the tz dict), not a typo
        "init_connection_params",
    }
    if unknown:
        # a typo'd override (e.g. device_modle=) would travel into
        # Client(**kwargs) and blow up far from the bug — fail at the source.
        raise TypeError(
            f"client_kwargs overrides must be fingerprint field names, "
            f"got unknown: {sorted(unknown)}"
        )
    kwargs.update(overrides)
    return kwargs


def tdlib_params(identity: _Identity, **overrides: str) -> Dict[str, str]:
    """TDLib parameter bundle: device_model / system_version / app_version.

    For `TDLib <https://core.telegram.org/tdlib>`_ bindings
    (python-tdlib, aiotdlib): these three strings go into the
    ``TdlibParameters``/auth bundle (and are settable via ``setOption``
    before authorization). Keyed by the canonical td_api parameter names
    (:data:`TDLIB_PARAMS`) so the dict can be splatted straight into a
    ``td_api.tdlibParameters(...)``-style constructor.
    """
    fp = _coerce(identity)
    params: Dict[str, str] = {name: getattr(fp, name) for name in TDLIB_PARAMS}
    unknown = set(overrides) - set(TDLIB_PARAMS)
    if unknown:
        raise TypeError(
            f"tdlib_params overrides must be one of {list(TDLIB_PARAMS)}, "
            f"got unknown: {sorted(unknown)}"
        )
    params.update(overrides)
    return params


def installed_layer() -> "int | None":
    """MTProto layer of the importable ``pyrogram`` distribution, or ``None``.

    Mirrors opentele-ng's ``pyrogram_layer()``: Pyrogram ships its own
    generated schema, generally on a different layer than Telethon. Mint
    fingerprints with ``API.<Preset>.Generate(..., layer=installed_layer())``
    so ``app_version`` claims a release that genuinely spoke the wire layer
    the client will actually send. Import failure is not an
    error — the adapter stays usable without any pyrogram installed.
    """
    try:
        from pyrogram.raw.all import layer  # type: ignore
    except Exception:  # nocov - depends on the environment
        return None
    try:
        return int(layer)
    except (TypeError, ValueError):  # nocov - defensive
        return None
