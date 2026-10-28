"""tgmint.adapters — thin per-framework identity glue.

The core mints and stores identities; adapters translate a minted
:class:`tgmint.fingerprint.Fingerprint` (or legacy ``APIData``) into
whatever a target client framework consumes. No framework is a dependency
of an adapter — everything here is dependency-free stdlib code, with the
optional real-client checks living in tests only.

Available adapters:

* :mod:`tgmint.adapters.pyrogram` — kurigram / pyrofork / vanilla pyrogram
  / hydrogram: constructor kwargs (no monkey-patching needed), plus a TDLib
  parameter exporter and a Bot API boundary note.

Fingerprints are minted once and reloaded ever after (Telegram remembers
the device a session signed in with) — adapters only *present* them.
"""

from .pyrogram import (
    PYROGRAM_KWARGS_FIELDS,
    TDLIB_PARAMS,
    client_kwargs,
    installed_layer,
    pyrogram_kwargs,
    tdlib_params,
)

__all__ = [
    "PYROGRAM_KWARGS_FIELDS",
    "TDLIB_PARAMS",
    "client_kwargs",
    "installed_layer",
    "pyrogram_kwargs",
    "tdlib_params",
]
