from __future__ import annotations

# fork note: upstream did `from .shared import *` here, which eagerly pulled
# the whole tdata stack (account/tdesktop/storage/mtp -> PyQt5). Since
# `tgmint.tl` imports this package, that made PyQt5 a hard requirement for
# even plain TelegramClient work. This package is now lazy (PEP 562): the
# tdata machinery loads only when a tdata API (TDesktop, Account, ...) is
# actually touched. `import tgmint.td.shared` still imports eagerly, as
# before.
#
# Second fork note: the tdata stack no longer needs PyQt5 at all — the Qt
# 5.1 binary format is parsed by the stdlib-only `tgmint.td.qdatastream`.
# PyQt5 remains an opt-in fallback backend there (TGMINT_TDATA_QT=1, the
# `[qt]` extra). The tdata stack still hard-requires telethon and
# tgcrypto, so an ImportError from those is a real environment problem
# and surfaces as-is.

_LAZY_ATTRS = [
    "Account",
    "StorageAccount",
    "MapData",
    "AuthKey",
    "AuthKeyType",
    "MTP",
    "Storage",
    "Serialize",
    "TDesktop",
]


def __getattr__(name: str):
    if name not in _LAZY_ATTRS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    # import through .shared, not the defining module: the tdata modules
    # are interdependent (tdesktop <-> shared) and only resolve in the
    # order upstream's eager `from .shared import *` established
    import importlib

    return getattr(importlib.import_module(".shared", __package__), name)


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + list(_LAZY_ATTRS))
