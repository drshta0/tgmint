from __future__ import annotations

# fork note: upstream did `from .shared import *` here, which eagerly pulled
# the whole tdata stack (account/tdesktop/storage/mtp -> PyQt5). Since
# `opentele.tl` imports this package, that made PyQt5 a hard requirement for
# even plain TelegramClient work. This package is now lazy (PEP 562): the Qt
# machinery loads only when a tdata API (TDesktop, Account, ...) is actually
# touched. `import opentele.td.shared` still imports eagerly, as before.

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
    try:
        # import through .shared, not the defining module: the tdata modules
        # are interdependent (tdesktop <-> shared) and only resolve in the
        # order upstream's eager `from .shared import *` established
        import importlib

        return getattr(importlib.import_module(".shared", __package__), name)
    except ImportError as e:
        raise ImportError(
            f"opentele.tdata APIs ({name}) require PyQt5 — install the fork's "
            f"'qt' extra (pip install opentele[qt]) or PyQt5 directly. "
            "Plain TelegramClient / API.Generate work without it."
        ) from e


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + list(_LAZY_ATTRS))
