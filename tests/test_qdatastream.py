"""Byte-level tests for the pure-Python QDataStream (tgmint.td.qdatastream).

Two layers:

* deterministic round-trips of every stream operation the tdata code
  actually uses (enumerated by grepping td/ for ``stream.`` calls:
  int32/uint32/uint64/int64, QString, raw bytes, ``<</>>`` QByteArray,
  atEnd/status/device/setDevice), with the exact expected big-endian
  bytes asserted where practical;
* PyQt5 *oracle equivalence*: the same structures are serialized through
  our pure writer and through real PyQt5 ``QDataStream(Qt_5_1)``, and the
  bytes must be identical; plus cross-reads in both directions.

QVariant: the tdata format never serializes QVariants (td/ contains no
readQVariant/writeQVariant call and opentele-ng's port implements none),
so no QVariant surface exists to cover — documented here so the "every op
the tdata code uses" claim above is auditable.

The oracle tests are skipped when PyQt5 is not installed (the pure
round-trip layer must pass everywhere — it is the default backend).
"""
import os
import struct
import sys
import tempfile
import unittest

from tgmint.td.qdatastream import (
    QBuffer,
    QByteArray,
    QDataStream,
    QDir,
    QFile,
    QIODevice,
    QSysInfo,
)

try:
    from PyQt5.QtCore import QDataStream as QtQDataStream
    from PyQt5.QtCore import QByteArray as QtQByteArray
    from PyQt5.QtCore import QIODevice as QtQIODevice

    HAVE_PYQT5 = True
except ImportError:
    HAVE_PYQT5 = False


def pure_write(fn):
    """Serialize through the pure writer, return the produced bytes."""
    data = QByteArray()
    stream = QDataStream(data, QIODevice.OpenModeFlag.WriteOnly)
    stream.setVersion(QDataStream.Version.Qt_5_1)
    fn(stream)
    return bytes(data.data())


def pure_read(payload):
    """Wrap ``payload`` in a fresh pure read-only stream."""
    stream = QDataStream(QByteArray(payload))
    stream.setVersion(QDataStream.Version.Qt_5_1)
    return stream


def qt_write(fn):
    """Serialize through the PyQt5 writer, return the produced bytes."""
    data = QtQByteArray()
    stream = QtQDataStream(data, QtQIODevice.OpenModeFlag.WriteOnly)
    stream.setVersion(QtQDataStream.Version.Qt_5_1)
    fn(stream)
    return bytes(data.data())


def qt_read(payload):
    stream = QtQDataStream(QtQByteArray(payload))
    stream.setVersion(QtQDataStream.Version.Qt_5_1)
    return stream


class TestIntegerRoundTrips(unittest.TestCase):
    """Every fixed-width integer op, round-tripped through our stream."""

    def test_uint8(self):
        payload = pure_write(lambda s: s.writeUInt8(0xAB))
        self.assertEqual(payload, b"\xab")
        self.assertEqual(pure_read(payload).readUInt8(), 0xAB)

    def test_uint16(self):
        payload = pure_write(lambda s: s.writeUInt16(0xBEEF))
        self.assertEqual(payload, b"\xbe\xef")
        self.assertEqual(pure_read(payload).readUInt16(), 0xBEEF)

    def test_uint32(self):
        payload = pure_write(lambda s: s.writeUInt32(0xDEADBEEF))
        self.assertEqual(payload, b"\xde\xad\xbe\xef")  # big-endian
        self.assertEqual(pure_read(payload).readUInt32(), 0xDEADBEEF)

    def test_uint64(self):
        value = 0xCAFEBABEDEADBEEF
        payload = pure_write(lambda s: s.writeUInt64(value))
        self.assertEqual(payload, b"\xca\xfe\xba\xbe\xde\xad\xbe\xef")
        self.assertEqual(pure_read(payload).readUInt64(), value)

    def test_int8(self):
        payload = pure_write(lambda s: s.writeInt8(-2))
        self.assertEqual(payload, b"\xfe")
        self.assertEqual(pure_read(payload).readInt8(), -2)

    def test_int16(self):
        payload = pure_write(lambda s: s.writeInt16(-2))
        self.assertEqual(payload, b"\xff\xfe")
        self.assertEqual(pure_read(payload).readInt16(), -2)

    def test_int32(self):
        # -2 is the DcOptions version marker tdata writes
        payload = pure_write(lambda s: s.writeInt32(-2))
        self.assertEqual(payload, b"\xff\xff\xff\xfe")
        self.assertEqual(pure_read(payload).readInt32(), -2)

    def test_int32_extremes(self):
        for value in (0, 1, -1, 2**31 - 1, -(2**31)):
            payload = pure_write(lambda s, v=value: s.writeInt32(v))
            self.assertEqual(
                pure_read(payload).readInt32(),
                value,
                f"int32 round-trip failed for {value}",
            )

    def test_int64(self):
        # kWideIdsTag = -1 is written as int64 in mtp authorization
        payload = pure_write(lambda s: s.writeInt64(-1))
        self.assertEqual(payload, b"\xff" * 8)
        self.assertEqual(pure_read(payload).readInt64(), -1)

    def test_uint_wraparound_matches_twos_complement(self):
        # writeUInt64 of a negative Python int wraps like Qt's quint64 cast
        payload = pure_write(lambda s: s.writeUInt64(-1))
        self.assertEqual(payload, b"\xff" * 8)

    def test_mixed_sequence_like_tdata(self):
        # the shape of mtp authorization: int64, int64, int32, count, keys
        def write(stream):
            stream.writeInt64(-1)
            stream.writeInt64(1234567890123)
            stream.writeInt32(2)
            stream.writeInt32(1)
            stream.writeRawData(b"\x07" * 256)
            stream.writeInt32(5)
            stream.writeRawData(b"\x09" * 256)

        payload = pure_write(write)
        reader = pure_read(payload)
        self.assertEqual(reader.readInt64(), -1)
        self.assertEqual(reader.readInt64(), 1234567890123)
        self.assertEqual(reader.readInt32(), 2)
        self.assertEqual(reader.readInt32(), 1)
        self.assertEqual(reader.readRawData(256), b"\x07" * 256)
        self.assertEqual(reader.readInt32(), 5)
        self.assertEqual(reader.readRawData(256), b"\x09" * 256)
        self.assertTrue(reader.atEnd())
        self.assertEqual(reader.status(), QDataStream.Status.Ok)


class TestQString(unittest.TestCase):
    def test_ascii(self):
        text = "apv3.stel.com"
        payload = pure_write(lambda s: s.writeQString(text))
        # uint32 BE byte-length + UTF-16-BE payload
        expected = struct.pack(">I", len(text.encode("utf-16-be"))) + text.encode(
            "utf-16-be"
        )
        self.assertEqual(payload, expected)
        self.assertEqual(pure_read(payload).readQString(), text)

    def test_non_ascii(self):
        text = "héllo wörld ünïcode ☃"
        payload = pure_write(lambda s: s.writeQString(text))
        self.assertEqual(payload, struct.pack(">I", len(text.encode("utf-16-be"))) + text.encode("utf-16-be"))
        self.assertEqual(pure_read(payload).readQString(), text)

    def test_empty_and_null_markers(self):
        empty = pure_write(lambda s: s.writeQString(""))
        null = pure_write(lambda s: s.writeQString(None))
        self.assertEqual(empty, b"\x00\x00\x00\x00")
        self.assertEqual(null, b"\xff\xff\xff\xff")
        # PyQt5 collapses null/empty QString to "" on read — so do we
        self.assertEqual(pure_read(empty).readQString(), "")
        self.assertEqual(pure_read(null).readQString(), "")


class TestQByteArrayWire(unittest.TestCase):
    def test_payload_with_size_prefix(self):
        payload = pure_write(lambda s: s << QByteArray(b"TDF$"))
        self.assertEqual(payload, b"\x00\x00\x00\x04TDF$")

    def test_null_marker_for_default_constructed(self):
        # tdesktop's map header writes QByteArray() twice — the null
        # marker 0xFFFFFFFF is real wire data, distinct from empty
        payload = pure_write(lambda s: s << QByteArray())
        self.assertEqual(payload, b"\xff\xff\xff\xff")

    def test_explicit_empty_differs_from_null(self):
        payload = pure_write(lambda s: s << QByteArray(b""))
        self.assertEqual(payload, b"\x00\x00\x00\x00")

    def test_bytes_payload_is_non_null(self):
        payload = pure_write(lambda s: s << b"raw-bytes")
        self.assertEqual(payload, b"\x00\x00\x00\x09raw-bytes")

    def test_read_back(self):
        payload = pure_write(lambda s: s << QByteArray(b"salt" * 8))
        reader = pure_read(payload)
        out = QByteArray()
        reader >> out
        self.assertEqual(bytes(out.data()), b"salt" * 8)
        self.assertFalse(out.isNull())
        self.assertTrue(reader.atEnd())

    def test_read_null_marker_yields_empty_non_null(self):
        reader = pure_read(b"\xff\xff\xff\xff")
        out = QByteArray(b"stale")
        reader >> out
        self.assertEqual(out.size(), 0)
        self.assertFalse(out.isNull())  # PyQt5 semantics on read
        self.assertEqual(reader.status(), QDataStream.Status.Ok)

    def test_read_replaces_previous_content(self):
        # `stream >> qba` must clear the target first (Qt semantics)
        payload = pure_write(lambda s: s << QByteArray(b"new"))
        out = QByteArray(b"old-content")
        pure_read(payload) >> out
        self.assertEqual(bytes(out.data()), b"new")

    def test_chained_shifts_like_map_read(self):
        # MapData.read does: stream >> salt >> keyEncrypted >> mapEncrypted
        payload = pure_write(
            lambda s: (
                s << QByteArray(b"\x01" * 32),
                s << QByteArray(b"\x02" * 48),
                s << QByteArray(b"\x03" * 64),
            )
        )
        salt, key_enc, map_enc = QByteArray(), QByteArray(), QByteArray()
        pure_read(payload) >> salt >> key_enc >> map_enc
        self.assertEqual(salt.size(), 32)
        self.assertEqual(key_enc.size(), 48)
        self.assertEqual(map_enc.size(), 64)


class TestQByteArrayObject(unittest.TestCase):
    def test_null_vs_empty_state(self):
        self.assertTrue(QByteArray().isNull())
        self.assertTrue(QByteArray().isEmpty())
        self.assertFalse(QByteArray(b"").isNull())
        self.assertTrue(QByteArray(b"").isEmpty())
        self.assertFalse(QByteArray(b"x").isNull())

    def test_copy_preserves_null_flag(self):
        self.assertTrue(QByteArray(QByteArray()).isNull())
        self.assertFalse(QByteArray(QByteArray(b"")).isNull())

    def test_resize_grows_with_zeros_and_clears_null(self):
        arr = QByteArray()
        arr.resize(4)
        self.assertEqual(bytes(arr.data()), b"\x00\x00\x00\x00")
        self.assertFalse(arr.isNull())

    def test_resize_truncates(self):
        arr = QByteArray(b"abcdef")
        arr.resize(3)
        self.assertEqual(bytes(arr.data()), b"abc")

    def test_slice_and_concat_return_qbytearray(self):
        head = QByteArray(b"0123456789")[:4]
        self.assertIsInstance(head, QByteArray)
        joined = head + QByteArray(b"AB")
        self.assertIsInstance(joined, QByteArray)
        self.assertEqual(bytes(joined.data()), b"0123AB")

    def test_add_bytes(self):
        joined = QByteArray(b"0123") + b"AB"
        self.assertIsInstance(joined, QByteArray)
        self.assertEqual(bytes(joined.data()), b"0123AB")

    def test_buffer_protocol_consumers(self):
        import hashlib

        arr = QByteArray(b"hash me")
        self.assertEqual(hashlib.sha1(arr).hexdigest(), hashlib.sha1(b"hash me").hexdigest())

    def test_clear_resets_null(self):
        arr = QByteArray(b"x")
        arr.clear()
        self.assertTrue(arr.isNull())

    def test_equality_with_bytes(self):
        self.assertEqual(QByteArray(b"abc"), b"abc")
        self.assertNotEqual(QByteArray(b"abc"), b"abd")


class TestStreamState(unittest.TestCase):
    def test_past_end_sets_read_past_end(self):
        reader = pure_read(b"\x01\x02")  # 2 bytes only
        self.assertEqual(reader.readUInt32(), 0)  # short read -> 0
        self.assertEqual(reader.status(), QDataStream.Status.ReadPastEnd)

    def test_read_past_end_is_sticky(self):
        reader = pure_read(b"")
        reader.readInt32()
        reader.readInt32()
        self.assertEqual(reader.status(), QDataStream.Status.ReadPastEnd)

    def test_reset_status(self):
        reader = pure_read(b"")
        reader.readInt32()
        self.assertEqual(reader.status(), QDataStream.Status.ReadPastEnd)
        reader.resetStatus()
        self.assertEqual(reader.status(), QDataStream.Status.Ok)

    def test_at_end(self):
        reader = pure_read(b"\x01")
        self.assertFalse(reader.atEnd())
        reader.readUInt8()
        self.assertTrue(reader.atEnd())

    def test_write_without_device_sets_write_failed(self):
        stream = QDataStream()
        stream.writeInt32(1)
        self.assertEqual(stream.status(), QDataStream.Status.WriteFailed)

    def test_set_device_and_version_roundtrip(self):
        # the FileReadDescriptor pattern: buffer + setDevice + setVersion
        data = QByteArray()
        buf = QBuffer()
        buf.setBuffer(data)
        self.assertTrue(buf.open(QIODevice.OpenModeFlag.WriteOnly))
        stream = QDataStream()
        stream.setDevice(buf)
        stream.setVersion(QDataStream.Version.Qt_5_1)
        stream.writeInt32(75)  # the mtp blockId tdata checks
        stream.setDevice(None)
        self.assertIsNone(stream.device())

        reader_stream = QDataStream()
        read_buf = QBuffer()
        read_buf.setBuffer(data)
        read_buf.open(QIODevice.OpenModeFlag.ReadOnly)
        reader_stream.setDevice(read_buf)
        reader_stream.setVersion(QDataStream.Version.Qt_5_1)
        self.assertEqual(reader_stream.readInt32(), 75)

    def test_version_enum_value_matches_pyqt5_constant(self):
        # PyQt5 hands out 14 for Qt_5_1 — verified by probe and asserted
        # against the real enum when PyQt5 is present below.
        self.assertEqual(int(QDataStream.Version.Qt_5_1), 14)
        self.assertEqual(int(QDataStream.Status.Ok), 0)
        self.assertEqual(int(QDataStream.Status.ReadPastEnd), 1)
        self.assertEqual(int(QIODevice.OpenModeFlag.ReadOnly), 1)
        self.assertEqual(int(QIODevice.OpenModeFlag.WriteOnly), 2)


class TestQBuffer(unittest.TestCase):
    def test_seek_write_grows_backing_array(self):
        # the EncryptedDescriptor pattern: reserve/resize(4), seek(4), write
        data = QByteArray()
        data.resize(4)
        buf = QBuffer()
        buf.setBuffer(data)
        self.assertTrue(buf.open(QIODevice.OpenModeFlag.WriteOnly))
        self.assertTrue(buf.seek(4))
        buf.write(b"payload")
        self.assertEqual(bytes(data.data()), b"\x00" * 4 + b"payload")
        self.assertEqual(buf.pos(), 11)

    def test_read_respects_pos(self):
        data = QByteArray(b"0123456789")
        buf = QBuffer()
        buf.setBuffer(data)
        buf.open(QIODevice.OpenModeFlag.ReadOnly)
        buf.seek(2)
        self.assertEqual(buf.read(3), b"234")
        self.assertEqual(buf.bytesAvailable(), 5)

    def test_close_and_is_open(self):
        buf = QBuffer()
        buf.setBuffer(QByteArray())
        self.assertFalse(buf.isOpen())
        buf.open(QIODevice.OpenModeFlag.ReadOnly)
        self.assertTrue(buf.isOpen())
        buf.close()
        self.assertFalse(buf.isOpen())


class TestQFileAndQDir(unittest.TestCase):
    def test_qfile_write_read_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "maps")
            f = QFile(path)
            self.assertTrue(f.open(QIODevice.OpenModeFlag.WriteOnly))
            f.write(b"TDF$")
            f.write(b"\x00" * 4)
            self.assertEqual(f.size(), 8)
            f.close()

            g = QFile(path)
            self.assertTrue(g.open(QIODevice.OpenModeFlag.ReadOnly))
            self.assertEqual(g.size(), 8)
            self.assertEqual(g.read(4), b"TDF$")
            g.close()

    def test_qfile_open_missing_returns_false(self):
        self.assertFalse(QFile("/nonexistent/nope").open(QIODevice.OpenModeFlag.ReadOnly))

    def test_qdir_exists_mkpath(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(QDir(tmp).exists())
            sub = os.path.join(tmp, "a", "b")
            self.assertFalse(QDir(sub).exists())
            QDir(tmp).mkpath(sub)
            self.assertTrue(QDir(sub).exists())


class TestQSysInfo(unittest.TestCase):
    def test_endian_constants(self):
        # matches PyQt5: BigEndian=0, LittleEndian=1, ByteOrder=host order
        self.assertEqual(int(QSysInfo.Endian.BigEndian), 0)
        self.assertEqual(int(QSysInfo.Endian.LittleEndian), 1)
        self.assertIn(int(QSysInfo.Endian.ByteOrder), (0, 1))
        self.assertEqual(
            int(QSysInfo.Endian.ByteOrder),
            0 if struct.pack("=I", 1) == b"\x00\x00\x00\x01" else 1,
        )
        # storage.py's writeData byteswap branch relies on this comparison
        little = int(QSysInfo.Endian.ByteOrder) != int(QSysInfo.Endian.BigEndian)
        self.assertEqual(little, sys.byteorder == "little")


@unittest.skipIf(not HAVE_PYQT5, "PyQt5 not installed — oracle tests skipped")
class TestPyQt5OracleEquivalence(unittest.TestCase):
    """Our pure writer must emit byte-identical output to real PyQt5."""

    def _assert_same_bytes(self, write_fn):
        ours = pure_write(write_fn)
        theirs = qt_write(write_fn)
        self.assertEqual(ours, theirs, f"byte mismatch: ours={ours.hex()} qt={theirs.hex()}")

    def test_oracle_integers(self):
        self._assert_same_bytes(
            lambda s: (
                s.writeUInt8(0xAB),
                s.writeUInt16(0xBEEF),
                s.writeUInt32(0xDEADBEEF),
                s.writeUInt64(0xCAFEBABEDEADBEEF),
                s.writeInt8(-2),
                s.writeInt16(-300),
                s.writeInt32(-2),
                s.writeInt64(-(2**40)),
            )
        )

    def test_oracle_qstrings(self):
        self._assert_same_bytes(
            lambda s: (
                s.writeQString("https://t.me/"),
                s.writeQString("héllo ☃"),
                s.writeQString(""),
            )
        )

    def test_oracle_qbytearray_payloads(self):
        def write(stream):
            stream << QtQByteArray(b"TDF$")
            stream << QtQByteArray(b"")

        ours = pure_write(lambda s: (s << QByteArray(b"TDF$"), s << QByteArray(b"")))
        theirs = qt_write(write)
        self.assertEqual(ours, theirs)

    def test_oracle_null_qbytearray_marker(self):
        ours = pure_write(lambda s: s << QByteArray())
        theirs = qt_write(lambda s: s << QtQByteArray())
        self.assertEqual(ours, theirs)
        self.assertEqual(ours, b"\xff\xff\xff\xff")

    def test_oracle_raw_data(self):
        self._assert_same_bytes(
            lambda s: (
                s.writeRawData(b"\x00" * 256),
                s.writeRawData(b"trailing"),
            )
        )

    def test_oracle_full_mtp_authorization_shape(self):
        auth_key = bytes(range(256))

        def write(stream):
            stream.writeInt64(-1)  # kWideIdsTag
            stream.writeInt64(1234567890123)
            stream.writeInt32(2)  # MainDcId
            stream.writeInt32(1)  # key count
            stream.writeInt32(2)  # dcId
            stream.writeRawData(auth_key)
            stream.writeInt32(0)  # keysToDestroy count

        self._assert_same_bytes(write)

    def test_cross_read_pyqt5_written_bytes(self):
        # bytes written by REAL PyQt5 must parse identically with our reader
        auth_key = bytes(range(256))
        payload = qt_write(
            lambda s: (
                s.writeInt64(-1),
                s.writeInt64(987654321),
                s.writeInt32(4),
                s.writeInt32(2),
                s.writeInt32(4),
                s.writeRawData(auth_key),
                s.writeInt32(0),
                s.writeQString("apv3.stel.com"),
            )
        )
        reader = pure_read(payload)
        self.assertEqual(reader.readInt64(), -1)
        self.assertEqual(reader.readInt64(), 987654321)
        self.assertEqual(reader.readInt32(), 4)
        self.assertEqual(reader.readInt32(), 2)
        self.assertEqual(reader.readInt32(), 4)
        self.assertEqual(reader.readRawData(256), auth_key)
        self.assertEqual(reader.readInt32(), 0)
        self.assertEqual(reader.readQString(), "apv3.stel.com")
        self.assertEqual(reader.status(), QDataStream.Status.Ok)

    def test_cross_read_pure_written_bytes_by_pyqt5(self):
        # bytes written by OUR writer must parse identically with PyQt5
        payload = pure_write(
            lambda s: (
                s.writeUInt32(0x17),
                s.writeUInt64(0x1122334455667788),
                s.writeQString("tapv3.stel.com"),
            )
        )
        reader = qt_read(payload)
        self.assertEqual(reader.readUInt32(), 0x17)
        self.assertEqual(reader.readUInt64(), 0x1122334455667788)
        self.assertEqual(reader.readQString(), "tapv3.stel.com")
        self.assertEqual(int(reader.status()), 0)

    def test_cross_read_pyqt5_qbytearray_roundtrip(self):
        payload = qt_write(
            lambda s: (
                s << QtQByteArray(b"\x0a" * 32),
                s << QtQByteArray(),
                s << QtQByteArray(b"x"),
            )
        )
        a, b, c = QByteArray(), QByteArray(), QByteArray()
        pure_read(payload) >> a >> b >> c
        self.assertEqual(a.size(), 32)
        self.assertEqual(b.size(), 0)
        self.assertFalse(b.isNull())
        self.assertEqual(bytes(c.data()), b"x")

    def test_oracle_pyqt5_enum_values(self):
        self.assertEqual(int(QtQDataStream.Version.Qt_5_1), int(QDataStream.Version.Qt_5_1))
        self.assertEqual(int(QtQDataStream.Status.Ok), int(QDataStream.Status.Ok))
        self.assertEqual(
            int(QtQIODevice.OpenModeFlag.WriteOnly),
            int(QIODevice.OpenModeFlag.WriteOnly),
        )


if __name__ == "__main__":
    unittest.main()
