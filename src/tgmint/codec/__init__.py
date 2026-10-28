"""tgmint.codec — the offline session-format conversion matrix.

Readers (→ :class:`SessionData`):

============================  ==============================================
format                        function
============================  ==============================================
Telethon SQLite ``.session``  :func:`tgmint.codec.telethon.read_sqlite`
Telethon StringSession (v1)   :func:`tgmint.codec.telethon.read_string`
Pyrogram SQLite (vanilla)     :func:`tgmint.codec.pyrogram.read_sqlite`
kurigram SQLite (v7 schema)   :func:`tgmint.codec.pyrogram.read_sqlite`
Pyrogram-family string        :func:`tgmint.codec.pyrogram.read_string`
GramJS StringSession          :func:`tgmint.codec.gramjs.read_string`
tdata folder                  :func:`tgmint.codec.tdata.read`
============================  ==============================================

Writers (← :class:`SessionData`): Telethon SQLite + string, Pyrogram
SQLite (``variant="pyrogram" | "kurigram"``) + string, GramJS string.
tdata *writing* stays with :mod:`tgmint.td` (``SaveTData``).

Honest verification status (details in each module docstring, pinned by
``tests/test_codec_matrix.py``):

* **Telethon** — fully verified offline against real Telethon 1.43.2
  (writer output byte-identical to ``StringSession.save()``; written
  ``.session`` files open with ``SQLiteSession``; telethon-written files
  read back).
* **GramJS** — cross-checked against TGConvertor's own semantics; no
  GramJS oracle in this tree.
* **Pyrogram / kurigram** — self-consistent only (we read back what we
  write); no external oracle today.

The whole package is stdlib-only (sqlite3/base64/struct/ipaddress);
PyQt5 is needed solely by the tdata reader and is imported lazily there.

Credit: the codecs are ported from TGConvertor by Nazar Ihnatiuk (MIT,
https://github.com/nazar220160/TGConvertor) — see each module's
docstring for the exact upstream file and the adaptations made.
"""

from __future__ import annotations

from .data import CodecError, SessionData
from . import data, dcs, gramjs, pyrogram, telethon

try:  # tdata.py itself is importable without Qt (the guard is lazy)
    from . import tdata
except ImportError:  # pragma: no cover - defensive; tdata has no top-level Qt import
    tdata = None  # type: ignore[assignment]

__all__ = [
    "SessionData",
    "CodecError",
    "data",
    "dcs",
    "telethon",
    "pyrogram",
    "gramjs",
    "tdata",
]
