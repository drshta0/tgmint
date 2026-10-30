"""tgmint — opentele lineage: tdata/telethon conversion, official-API
fingerprints, software passkeys.

Submodules load lazily (PEP 562). `tgmint.tl` extends Telethon's
TelegramClient at import, and so does the older `opentele` build of this
same code; two such extensions in one process raise. A caller that only
needs `tgmint.passkeys` (which talks plain Telethon) must therefore be able
to import it without pulling `tgmint.tl` in — `from tgmint import passkeys`
now does exactly that. `tgmint.tl` / `tgmint.td` / `tgmint.api` still work
as attributes and as submodule imports.

`tgmint.passkeys_core` is the framework-neutral half of the passkey
feature (no Telethon import at all), so it loads lazily like the rest and
is reachable as both `tgmint.passkeys_core` and `from tgmint import
passkeys_core`. `tgmint.passkeys_pyrogram` is the Pyrogram-family driver
(kurigram/pyrofork); it imports no framework until it is actually used.
"""

from __future__ import annotations

import importlib

__all__ = [
    "api",
    "td",
    "tl",
    "passkeys",
    "passkeys_core",
    "passkeys_pyrogram",
    "adapters",
    "codec",
]

try:
    # distribution metadata when installed; falls back to the literal when
    # running straight from a checkout (PYTHONPATH=src) without installing
    from importlib.metadata import version as _dist_version

    __version__ = _dist_version("tgmint")
except Exception:
    __version__ = "1.17.0"


def __getattr__(name: str):
    if name in __all__:
        return importlib.import_module("." + name, __package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(globals()) | set(__all__))
