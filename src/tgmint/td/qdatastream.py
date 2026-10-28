"""Pure-Python, stdlib-only replacements for the PyQt5.QtCore classes the
tdata stack uses (``tgmint.td`` reads and writes Telegram Desktop ``tdata``
folders in Qt's Qt_5_1 binary serialization format).

Killing the PyQt5 dependency: tdata read/write now works with nothing but
the standard library. PyQt5 remains available as an opt-in fallback backend
(set ``TGMINT_TDATA_QT=1`` before import, with the ``[qt]`` extra
installed) — handy for cross-checking against the real Qt implementation.

Ported from opentele-ng's phase-5 deliverable, adapted for this fork
(namespace, Python 3.9, PyQt5-oriented oracle notes). Byte-for-byte
equivalence with ``PyQt5.QtCore.QDataStream(Qt_5_1)`` is enforced by the
oracle tests in ``tests/test_qdatastream.py``, which serialize the same
structures through both implementations and compare the bytes.

Wire format (Qt_5_1, big-endian throughout):

* ``quint8/16/32/64`` and ``qint8/16/32/64`` are fixed-size big-endian
  integers, two's complement for the signed variants.
* ``QString``: ``uint32 byte-length + UTF-16-BE payload``;
  ``0xFFFFFFFF`` is the null marker and decodes to ``""`` (PyQt5 collapses
  Qt's null/empty QString distinction in Python, and so do we).
* ``QByteArray``: ``uint32 size + raw payload``; ``0xFFFFFFFF`` is the null
  marker. tdesktop's map header legitimately writes null QArrays
  (``map.writeData(QByteArray())``), so the null/empty distinction is
  real wire data, not cosmetic: a default-constructed (null) array
  serializes as ``0xFFFFFFFF`` while an explicit empty one serializes as
  ``0x00000000``. Reading either produces an empty, *non-null* array,
  matching PyQt5.

Probed constants (PyQt5 5.15, identical in PyQt6 6.6 per upstream):

* ``QDataStream.Version.Qt_5_1`` == ``14`` (Qt's internal datastream
  format version, not the 7 the C++ enum index suggests).
* ``QDataStream.Status``: ``Ok=0, ReadPastEnd=1, ReadCorruptData=2,
  WriteFailed=3``.
* ``QIODevice.OpenModeFlag``: ``ReadOnly=1, WriteOnly=2, ReadWrite=3``.

Provenance:
- port source (MIT): https://github.com/stufently/opentele/blob/main/src/td/qdatastream.py
- Qt serialization reference: https://doc.qt.io/qt-5/qdatastream.html
- tdesktop consumer of the format:
  https://github.com/telegramdesktop/tdesktop/blob/dev/Telegram/SourceFiles/storage/details/storage_file_utilities.cpp
"""

from __future__ import annotations

import os
import pathlib
import platform
import struct
from enum import IntEnum
from typing import Optional, Union

__all__ = [
    "QByteArray",
    "QDataStream",
    "QIODevice",
    "QBuffer",
    "QFile",
    "QDir",
    "QSysInfo",
]


# ---------------------------------------------------------------------------
# QIODevice (used only as an enum carrier in the tdata code)
# ---------------------------------------------------------------------------


class _OpenModeFlag(IntEnum):
    NotOpen = 0
    ReadOnly = 1
    WriteOnly = 2
    ReadWrite = 3
    Append = 4
    Truncate = 8
    Text = 16
    Unbuffered = 32


class QIODevice:
    """Minimal carrier for the ``OpenModeFlag`` enum values.

    The tdata code never instantiates ``QIODevice`` directly — it only
    references ``QIODevice.OpenModeFlag.ReadOnly`` / ``.WriteOnly`` as flags
    passed to :class:`QFile` / :class:`QBuffer`.
    """

    OpenModeFlag = _OpenModeFlag


# ---------------------------------------------------------------------------
# QByteArray — mutable bytes wrapper with PyQt5-compatible semantics
# ---------------------------------------------------------------------------


class QByteArray(bytearray):
    """Mutable byte array that mimics ``PyQt5.QtCore.QByteArray``.

    Inherits from :class:`bytearray` so the buffer protocol, slicing, and
    in-place mutation come for free — this lets the class be passed
    directly to ``hashlib.sha1`` / ``tgcrypto.ige256_encrypt`` and other
    functions that consume buffer-protocol bytes (which PyQt5's QByteArray
    also supports).

    The single extra bit of state we track is ``_null``: Qt distinguishes
    a *null* default-constructed array from an *empty* but non-null one,
    and the Qt 5.1 serialization format relies on that distinction (the
    null marker is ``0xFFFFFFFF``, the empty marker ``0x00000000``). Any
    mutation that adds content clears the null flag.
    """

    # bytearray subclasses cannot use __slots__; ``_null`` is set via
    # __init__ / mutation methods instead. Defining it as a class-level
    # default keeps ``getattr(self, "_null", ...)`` cheap and pickle-safe.

    def __init__(
        self,
        source: Union[bytes, bytearray, QByteArray, int, None] = None,
    ) -> None:
        # bytearray.__init__ does the actual byte loading, so it MUST be
        # called explicitly (otherwise the subclass instance stays empty).
        if source is None:
            super().__init__()
            self._null = True
        else:
            super().__init__(source)
            self._null = isinstance(source, QByteArray) and source._null

    # ---- inspection ------------------------------------------------------

    def size(self) -> int:
        return len(self)

    def isEmpty(self) -> bool:
        return len(self) == 0

    def isNull(self) -> bool:
        return getattr(self, "_null", False) and len(self) == 0

    def data(self) -> bytes:
        """Return a ``bytes`` snapshot (PyQt5 ``data()`` returns bytes)."""
        return bytes(self)

    # ---- mutation tweaks (clear _null on add) ---------------------------

    def resize(self, new_size: int) -> None:
        cur = len(self)
        if new_size < cur:
            del self[new_size:]
        elif new_size > cur:
            self.extend(b"\x00" * (new_size - cur))
        self._null = False

    def reserve(self, _capacity: int) -> None:
        # Capacity hint — no-op (bytearray grows on demand). ``reserve``
        # on PyQt5 does NOT clear the null flag.
        return None

    def clear(self) -> None:  # type: ignore[override]
        super().clear()
        self._null = True

    # ---- arithmetic (keep QByteArray type on +) -------------------------

    def __add__(self, other) -> QByteArray:  # type: ignore[override]
        if isinstance(other, (bytes, bytearray, memoryview)):
            return QByteArray(bytes(self) + bytes(other))
        return NotImplemented

    def __radd__(self, other) -> QByteArray:
        if isinstance(other, (bytes, bytearray, memoryview)):
            return QByteArray(bytes(other) + bytes(self))
        return NotImplemented

    # ---- slicing keeps QByteArray type ----------------------------------

    def __getitem__(self, key):  # type: ignore[override]
        result = super().__getitem__(key)
        if isinstance(key, slice):
            return QByteArray(bytes(result))
        return result

    # ---- repr -----------------------------------------------------------

    def __repr__(self) -> str:
        return f"QByteArray({bytes(self)!r})"


# ---------------------------------------------------------------------------
# QBuffer — cursor over a QByteArray
# ---------------------------------------------------------------------------


class QBuffer:
    """View/cursor over a :class:`QByteArray`.

    Mirrors the small subset of ``QBuffer`` the tdata code uses:

    * ``setBuffer(qba)`` — install backing storage (or ``None`` to detach).
    * ``open(mode)`` — set ReadOnly/WriteOnly and reset the position to 0.
    * ``close()``, ``isOpen()``.
    * ``seek(pos)``, ``pos()``, ``atEnd()``.
    * ``read(n)``, ``write(bytes)``.

    Writes mutate the backing :class:`QByteArray` in place.
    """

    __slots__ = ("_qba", "_mode", "_pos")

    def __init__(self, qba: Optional[QByteArray] = None) -> None:
        self._qba: Optional[QByteArray] = qba
        self._mode: int = int(QIODevice.OpenModeFlag.NotOpen)
        self._pos: int = 0

    def setBuffer(self, qba: Optional[QByteArray]) -> None:
        self._qba = qba
        self._pos = 0

    def buffer(self) -> Optional[QByteArray]:
        return self._qba

    def open(self, mode) -> bool:
        if self._qba is None:
            return False
        self._mode = int(mode)
        self._pos = 0
        return True

    def close(self) -> None:
        self._mode = int(QIODevice.OpenModeFlag.NotOpen)
        self._pos = 0

    def isOpen(self) -> bool:
        return self._mode != int(QIODevice.OpenModeFlag.NotOpen)

    def seek(self, pos: int) -> bool:
        if self._qba is None:
            return False
        # PyQt5 allows seeking past the end on WriteOnly; we follow.
        self._pos = max(0, int(pos))
        return True

    def pos(self) -> int:
        return self._pos

    def atEnd(self) -> bool:
        if self._qba is None:
            return True
        return self._pos >= len(self._qba)

    def bytesAvailable(self) -> int:
        if self._qba is None:
            return 0
        return max(0, len(self._qba) - self._pos)

    # --- read / write -----------------------------------------------------

    def read(self, n: int) -> bytes:
        if self._qba is None:
            return b""
        avail = len(self._qba) - self._pos
        if n < 0 or n > avail:
            n = max(0, avail)
        chunk = bytes(self._qba[self._pos : self._pos + n])
        self._pos += n
        return chunk

    def write(self, data: Union[bytes, bytearray, memoryview, QByteArray]) -> int:
        if self._qba is None:
            return 0
        if not isinstance(data, bytes):
            data = bytes(data)
        n = len(data)
        # Extend the backing array when writing past the current end.
        end = self._pos + n
        if end > len(self._qba):
            self._qba.extend(b"\x00" * (end - len(self._qba)))
        bytearray.__setitem__(self._qba, slice(self._pos, end), data)
        self._qba._null = False
        self._pos = end
        return n


# ---------------------------------------------------------------------------
# QDataStream — Qt 5.1 binary serialization, big-endian
# ---------------------------------------------------------------------------


class _Status(IntEnum):
    Ok = 0
    ReadPastEnd = 1
    ReadCorruptData = 2
    WriteFailed = 3


class _Version(IntEnum):
    # The tdata code only ever sets Qt_5_1; we expose the numeric value
    # PyQt5 hands out (=14). The wire format does not change between the
    # minor Qt versions we care about — everything here IS the Qt 5.1
    # format — so ``setVersion`` just records the value.
    Qt_5_1 = 14


class QDataStream:
    """Qt_5_1 big-endian binary stream.

    Implements only the methods the tdata code actually calls. Mirrors
    PyQt5's operator overloads (``<<`` / ``>>``) for :class:`QByteArray`.

    Construction modes:

    * ``QDataStream()`` — empty; attach via ``setDevice(qbuffer)``.
    * ``QDataStream(qba)`` — implicit ReadOnly over the given QByteArray.
    * ``QDataStream(qba, mode)`` — explicit ReadOnly/WriteOnly. WriteOnly
      mutates the backing QByteArray in place (so the caller's reference
      sees the written bytes, exactly like PyQt5).
    """

    Status = _Status
    Version = _Version

    __slots__ = ("_device", "_owned_buffer", "_version", "_status", "_mode")

    def __init__(
        self,
        data: Optional[Union[QByteArray, QBuffer]] = None,
        mode: Optional[int] = None,
    ) -> None:
        self._device: Optional[QBuffer] = None
        self._owned_buffer: Optional[QBuffer] = None
        self._version: int = int(_Version.Qt_5_1)
        self._status: int = int(_Status.Ok)
        self._mode: int = int(QIODevice.OpenModeFlag.NotOpen)

        if data is None:
            return

        if isinstance(data, QBuffer):
            self._device = data
            self._mode = data._mode
            return

        if isinstance(data, QByteArray):
            buf = QBuffer(data)
            open_mode = (
                int(mode) if mode is not None else int(QIODevice.OpenModeFlag.ReadOnly)
            )
            buf.open(open_mode)
            self._device = buf
            self._owned_buffer = buf
            self._mode = open_mode
            return

        raise TypeError(
            f"QDataStream: cannot wrap {type(data).__name__}; expected "
            "QByteArray or QBuffer"
        )

    # ---- configuration ---------------------------------------------------

    def setVersion(self, version: int) -> None:
        self._version = int(version)

    def version(self) -> int:
        return self._version

    def setDevice(self, device: Optional[QBuffer]) -> None:
        self._device = device
        if device is None:
            self._mode = int(QIODevice.OpenModeFlag.NotOpen)
        else:
            self._mode = device._mode

    def device(self) -> Optional[QBuffer]:
        return self._device

    def status(self) -> int:
        return self._status

    def resetStatus(self) -> None:
        self._status = int(_Status.Ok)

    def atEnd(self) -> bool:
        if self._device is None:
            return True
        return self._device.atEnd()

    def bytesAvailable(self) -> int:
        """Bytes still readable from the underlying device.

        Used by the map-reader's parser-DoS guard to cap attacker-controlled
        ``count`` fields before entering a fixed-size-per-iteration loop.
        Returns 0 if the stream has no device or the device is exhausted.
        """
        if self._device is None:
            return 0
        if hasattr(self._device, "bytesAvailable"):
            return int(self._device.bytesAvailable())
        return 0

    # ---- internal helpers -----------------------------------------------

    def _read_bytes(self, n: int) -> Optional[bytes]:
        """Read exactly *n* bytes or set ReadPastEnd and return ``None``."""
        if self._device is None:
            self._status = int(_Status.ReadPastEnd)
            return None
        data = self._device.read(n)
        if len(data) < n:
            self._status = int(_Status.ReadPastEnd)
            return None
        return data

    def _write_bytes(self, data: bytes) -> None:
        if self._device is None:
            self._status = int(_Status.WriteFailed)
            return
        self._device.write(data)

    # ---- primitive read --------------------------------------------------

    def readUInt8(self) -> int:
        b = self._read_bytes(1)
        if b is None:
            return 0
        return b[0]

    def readUInt16(self) -> int:
        b = self._read_bytes(2)
        if b is None:
            return 0
        return struct.unpack(">H", b)[0]

    def readUInt32(self) -> int:
        b = self._read_bytes(4)
        if b is None:
            return 0
        return struct.unpack(">I", b)[0]

    def readUInt64(self) -> int:
        b = self._read_bytes(8)
        if b is None:
            return 0
        return struct.unpack(">Q", b)[0]

    def readInt8(self) -> int:
        b = self._read_bytes(1)
        if b is None:
            return 0
        return struct.unpack(">b", b)[0]

    def readInt16(self) -> int:
        b = self._read_bytes(2)
        if b is None:
            return 0
        return struct.unpack(">h", b)[0]

    def readInt32(self) -> int:
        b = self._read_bytes(4)
        if b is None:
            return 0
        return struct.unpack(">i", b)[0]

    def readInt64(self) -> int:
        b = self._read_bytes(8)
        if b is None:
            return 0
        return struct.unpack(">q", b)[0]

    # ---- primitive write -------------------------------------------------

    def writeUInt8(self, v: int) -> None:
        self._write_bytes(struct.pack(">B", v & 0xFF))

    def writeUInt16(self, v: int) -> None:
        self._write_bytes(struct.pack(">H", v & 0xFFFF))

    def writeUInt32(self, v: int) -> None:
        self._write_bytes(struct.pack(">I", v & 0xFFFFFFFF))

    def writeUInt64(self, v: int) -> None:
        self._write_bytes(struct.pack(">Q", v & 0xFFFFFFFFFFFFFFFF))

    def writeInt8(self, v: int) -> None:
        v = ((v + 0x80) & 0xFF) - 0x80
        self._write_bytes(struct.pack(">b", v))

    def writeInt16(self, v: int) -> None:
        v = ((v + 0x8000) & 0xFFFF) - 0x8000
        self._write_bytes(struct.pack(">h", v))

    def writeInt32(self, v: int) -> None:
        v = ((v + 0x80000000) & 0xFFFFFFFF) - 0x80000000
        self._write_bytes(struct.pack(">i", v))

    def writeInt64(self, v: int) -> None:
        v = ((v + 0x8000000000000000) & 0xFFFFFFFFFFFFFFFF) - 0x8000000000000000
        self._write_bytes(struct.pack(">q", v))

    # ---- QString (UTF-16-BE, uint32 byte-length prefix) -----------------

    def writeQString(self, s: Optional[str]) -> None:
        if s is None:
            self._write_bytes(b"\xff\xff\xff\xff")
            return
        if s == "":
            self._write_bytes(b"\x00\x00\x00\x00")
            return
        payload = s.encode("utf-16-be")
        self._write_bytes(struct.pack(">I", len(payload)))
        self._write_bytes(payload)

    def readQString(self) -> str:
        size_b = self._read_bytes(4)
        if size_b is None:
            return ""
        size = struct.unpack(">I", size_b)[0]
        if size == 0xFFFFFFFF:
            # PyQt5 returns "" for both null and empty markers; match it.
            return ""
        if size == 0:
            return ""
        payload = self._read_bytes(size)
        if payload is None:
            return ""
        try:
            return payload.decode("utf-16-be")
        except UnicodeDecodeError:
            self._status = int(_Status.ReadCorruptData)
            return ""

    # ---- Raw (verbatim) bytes -------------------------------------------

    def writeRawData(self, data: Union[bytes, bytearray, memoryview, QByteArray]) -> int:
        if not isinstance(data, (bytes,)):
            data = bytes(data)
        self._write_bytes(data)
        return len(data)

    def readRawData(self, n: int) -> bytes:
        if self._device is None:
            self._status = int(_Status.ReadPastEnd)
            return b""
        data = self._device.read(n)
        if len(data) < n:
            self._status = int(_Status.ReadPastEnd)
        return data

    # ---- QByteArray operators -------------------------------------------

    def __lshift__(self, other) -> QDataStream:
        """``stream << qba`` — write QByteArray with uint32 size prefix.

        Accepts any buffer-protocol-like object (our :class:`QByteArray`,
        PyQt5's ``QByteArray``, ``bytes``, ``bytearray``) so the oracle
        tests can pass payloads through unchanged.
        """
        if isinstance(other, QByteArray):
            if other.isNull():
                self._write_bytes(b"\xff\xff\xff\xff")
                return self
            size = len(other)
            self._write_bytes(struct.pack(">I", size))
            if size > 0:
                self._write_bytes(bytes(other))
            return self
        # Fallback: any buffer-protocol payload (bytes / bytearray / PyQt5
        # QByteArray) is treated as a non-null array. The null distinction
        # only applies to our own :class:`QByteArray`. A PyQt5 default-
        # constructed QByteArray is detected via duck-typed isNull().
        try:
            data = bytes(other)
        except TypeError as exc:
            raise TypeError(
                f"QDataStream << expects QByteArray-like, got {type(other).__name__}"
            ) from exc
        is_null = False
        is_null_method = getattr(other, "isNull", None)
        if callable(is_null_method):
            try:
                is_null = bool(is_null_method()) and len(data) == 0
            except Exception:
                is_null = False
        if is_null:
            self._write_bytes(b"\xff\xff\xff\xff")
            return self
        self._write_bytes(struct.pack(">I", len(data)))
        if data:
            self._write_bytes(data)
        return self

    def __rshift__(self, other) -> QDataStream:
        """``stream >> qba`` — read QByteArray with uint32 size prefix.

        Mutates *other* in place (Qt semantics). After this call the target
        always has ``isNull()==False`` — matches PyQt5, where a null marker
        still produces an empty-but-not-null result.
        """
        if not isinstance(other, QByteArray):
            raise TypeError(
                f"QDataStream >> expects QByteArray, got {type(other).__name__}"
            )
        del other[:]
        other._null = False
        size_b = self._read_bytes(4)
        if size_b is None:
            return self
        size = struct.unpack(">I", size_b)[0]
        if size == 0xFFFFFFFF or size == 0:
            return self
        payload = self._read_bytes(size)
        if payload is None:
            return self
        other.extend(payload)
        return self


# ---------------------------------------------------------------------------
# QFile — open()-backed file wrapper used by storage.py
# ---------------------------------------------------------------------------


class QFile:
    """Minimal file wrapper.

    Behavior mirrors the subset the tdata code uses: open in
    ReadOnly/WriteOnly, ``read(n)`` returns bytes, ``write(b)`` writes
    bytes, ``size()`` returns the file size, ``close()`` closes. Errors
    during ``open()`` return False (matching Qt's "no exception, check the
    return value" idiom — see the fork note in ``Storage.ReadFile``).
    """

    __slots__ = ("_path", "_fh", "_mode", "_size")

    def __init__(self, path: str) -> None:
        self._path: str = str(path)
        self._fh = None
        self._mode: int = int(QIODevice.OpenModeFlag.NotOpen)
        self._size: int = 0

    def open(self, mode) -> bool:
        m = int(mode)
        self._mode = m
        try:
            if m & int(QIODevice.OpenModeFlag.WriteOnly):
                self._fh = open(self._path, "wb")
                self._size = 0
            elif m & int(QIODevice.OpenModeFlag.ReadOnly):
                self._fh = open(self._path, "rb")
                self._fh.seek(0, os.SEEK_END)
                self._size = self._fh.tell()
                self._fh.seek(0)
            else:
                return False
            return True
        except OSError:
            self._fh = None
            return False

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None

    def isOpen(self) -> bool:
        return self._fh is not None

    def read(self, n: int) -> bytes:
        if self._fh is None:
            return b""
        return self._fh.read(n)

    def write(self, data: Union[bytes, bytearray, QByteArray]) -> int:
        if self._fh is None:
            return 0
        if not isinstance(data, bytes):
            data = bytes(data)
        return self._fh.write(data)

    def size(self) -> int:
        if self._fh is not None:
            # Live size (write mode grows the file).
            cur = self._fh.tell()
            self._fh.seek(0, os.SEEK_END)
            sz = self._fh.tell()
            self._fh.seek(cur)
            return sz
        return self._size

    def bytesAvailable(self) -> int:
        # QIODevice contract parity with QBuffer (unused by the tdata code
        # today; kept so IO devices stay polymorphic for the stream).
        if self._fh is None:
            return 0
        try:
            return max(0, self.size() - self._fh.tell())
        except (ValueError, OSError):
            return 0


# ---------------------------------------------------------------------------
# QDir — pathlib-backed directory wrapper
# ---------------------------------------------------------------------------


class QDir:
    """Thin pathlib wrapper covering only the methods the tdata code uses
    (:meth:`exists`, :meth:`mkpath`).
    """

    __slots__ = ("_path",)

    def __init__(self, path: str) -> None:
        self._path = pathlib.Path(path)

    def exists(self) -> bool:
        return self._path.exists()

    def mkpath(self, path: str) -> bool:
        try:
            pathlib.Path(path).mkdir(parents=True, exist_ok=True)
            return True
        except OSError:
            return False

    @staticmethod
    def cleanPath(path: str) -> str:
        return os.path.normpath(path)


# ---------------------------------------------------------------------------
# QSysInfo — platform info (the tdata code uses Endian only)
# ---------------------------------------------------------------------------


class _Endian:
    """Carrier for ``QSysInfo.Endian.BigEndian`` / ``LittleEndian`` /
    ``ByteOrder``. Not an IntEnum because Qt exposes ``ByteOrder`` as a
    pseudo-member equal to the host's byte order, and IntEnum does not
    allow dynamic members after class creation.
    """

    BigEndian = 0
    LittleEndian = 1
    # Host byte order — fixed at import time to match the running platform.
    ByteOrder = BigEndian if struct.pack("=I", 1) == b"\x00\x00\x00\x01" else LittleEndian


class QSysInfo:
    """Carrier for ``Endian`` and a couple of platform helpers.

    The tdata write path consults
    ``QSysInfo.Endian.ByteOrder != QSysInfo.Endian.BigEndian`` to decide
    whether to byteswap a size field before md5'ing it (so the final hash
    matches whatever tdesktop produced on the same host).
    """

    Endian = _Endian

    @staticmethod
    def productType() -> str:
        sysname = platform.system().lower()
        if sysname == "darwin":
            return "macos"
        return sysname

    @staticmethod
    def prettyProductName() -> str:
        return platform.platform()


# ---------------------------------------------------------------------------
# Optional PyQt5 fallback backend
# ---------------------------------------------------------------------------
# The pure implementation above is the default and needs nothing but the
# stdlib. Setting TGMINT_TDATA_QT=1 (before the first import of
# ``tgmint.td``) swaps every name in this module for the real PyQt5
# classes instead — the ``[qt]`` extra keeps that path alive for
# cross-checking against Qt itself. The names must stay drop-in
# compatible; the oracle tests enforce exactly that.

if os.environ.get("TGMINT_TDATA_QT", "") == "1":  # pragma: no cover
    try:
        from PyQt5.QtCore import (  # noqa: F401
            QBuffer as _QtQBuffer,
            QByteArray as _QtQByteArray,
            QDataStream as _QtQDataStream,
            QDir as _QtQDir,
            QFile as _QtQFile,
            QIODevice as _QtQIODevice,
            QSysInfo as _QtQSysInfo,
        )
    except ImportError:
        # Requested but unavailable — fall through to the pure backend.
        pass
    else:
        QByteArray = _QtQByteArray  # type: ignore[misc,assignment]
        QDataStream = _QtQDataStream  # type: ignore[misc,assignment]
        QBuffer = _QtQBuffer  # type: ignore[misc,assignment]
        QIODevice = _QtQIODevice  # type: ignore[misc,assignment]
        QDir = _QtQDir  # type: ignore[misc,assignment]
        QFile = _QtQFile  # type: ignore[misc,assignment]
        QSysInfo = _QtQSysInfo  # type: ignore[misc,assignment]
