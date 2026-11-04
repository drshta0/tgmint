"""Official Telegram for Android app-data reader (read-only SOURCE codec).

The user story (docs/android-acquisition.md):
*"I'm logged into Telegram on my (rooted/emulated) Android device; I want
that account in Telethon / Pyrogram-family / GramJS / tdata without a new
login."*  This module reads the app's own storage — no crypto at all, the
auth key sits in ``tgnet.dat`` in the clear — and turns the selected
account into a :class:`~tgmint.codec.data.SessionData`.  It is a source
only: nothing here ever writes into an app data directory.

FORMAT SPEC (every field verified against the official client source,
DrKLO/Telegram @ ``f2908b14133bbffbf7ab04f641ecb5bfaf533242`` — "12.10.x",
2026-09-30; the format is stable since configVersion 5 / dc stream 13):

* ``files/tgnet.dat`` is one ``Config`` file: a little-endian ``u32``
  payload size followed by that many bytes
  (``TMessagesProj/jni/tgnet/Config.cpp:23-66`` — ``readConfig`` reads the
  size first; ``writeConfig`` writes size, payload, chmod 0660).  A crash
  mid-write leaves ``tgnet.dat.bak`` holding the previous complete config
  and the constructor *promotes the .bak over the main file*
  (``Config.cpp:17-28``); this reader does the same when the main file is
  missing.
* the payload is ``ConnectionsManager::saveConfigInternal``
  (``ConnectionsManager.cpp:444-471``; read back by ``loadConfig``,
  ``ConnectionsManager.cpp:364-416``; ``configVersion = 5`` at
  ``ConnectionsManager.h:140``): version, ``testBackend``, (v3)
  ``clientBlocked``, (v4) ``lastInitSystemLangcode``, ``hasCurrentDc``,
  then the current-dc block and one ``Datacenter`` stream per DC.
* each datacenter stream is ``Datacenter::serializeToStream``
  (``Datacenter.cpp:538-620``; read back by the stream constructor,
  ``Datacenter.cpp:47-160``; ``configVersion = 13`` at
  ``Datacenter.h:129``): version, dcId, ``lastInitVersion`` (= the app's
  versionCode, v3+), ``lastInitMediaVersion`` (v10+), four address arrays
  (v5+; one array before that) of ``{string ip, u32 port, i32 flags (v7+),
  string secret (v11+)}``, ``isCdnDatacenter`` (v6+), then the auth block:
  ``{u32 len, bytes authKeyPerm, i64 authKeyPermId, u32 len, bytes
  authKeyTemp, i64 authKeyTempId (v8+), u32 len, bytes authKeyMediaTemp,
  i64 authKeyMediaTempId (v12+), i32 authorized}``, then the server-salt
  arrays (media salts are v13+).
* scalars are the tgnet ``NativeByteBuffer`` wire codecs
  (``NativeByteBuffer.cpp:202-215, 302-330, 515-530, 555-580``): ints
  little-endian; ``bool`` is the TL constructor ``0x997275B5`` /
  ``0xBC799737``; strings/byte arrays are TL-length-prefixed
  (1 byte when < 254, else ``0xFE`` + 3 bytes) with 4-byte alignment; a
  bare ``readBytes(len)`` (the auth keys) has no prefix.
* per-account layout: account 0 lives in ``files/`` + prefs
  ``shared_prefs/userconfing.xml`` (the typo is upstream,
  ``UserConfig.java:411-416``); accounts 1+ in ``files/account<N>/`` +
  ``shared_prefs/userconfig<N>.xml`` (``FilePathDatabase.java:50``,
  ``MessagesStorage.java:312``; ``MAX_ACCOUNT_COUNT = 4`` at
  ``UserConfig.java:28`` — discovery globs ``account<N>`` anyway, so a
  future raise of that constant keeps working).
* ``userconfing.xml`` is an Android ``SharedPreferences`` XML map whose
  ``user`` key (``UserConfig.java:365-370``) holds standard Base64 (Java
  wraps it every 76 columns — whitespace is stripped before decoding) of
  a serialized ``TLRPC.User``.  Only the ``id`` is needed; it is parsed
  from the constructor prefix: current ``TL_user`` ``0xB1B8CC83`` =
  ``flags, flags2, id:int64``; the long-lived ``TL_user_layer184``
  ``0x215C4438`` (app 10.3.2 → 12.9.0 era, per ``git log -S`` on
  TLRPC.java) = ``flags, id:int64``; ``TL_userEmpty`` ``0xD3BC4B7A`` =
  ``id:int64``.  An unknown (future) constructor is not an error: the
  import keeps working with ``user_id=None``, the matrix's honest
  "source stored none we could read".

Prior art, with thanks: **AndroidTelePorter** (MIT, PyPI) reads the same
files — https://github.com/batreller/AndroidTelePorter — cross-checked
against it before this was written (it parses the ``user`` blob through
Telethon's TL machinery; this reader stays stdlib-only).  tgmint is not
the first Python Android-session importer and does not claim to be.

The app's local passcode never touches these files (it only stores a
verification hash), and there is nothing to decrypt; acquiring the files
at all is the hard part — see docs/android-acquisition.md for the
rooted-device / emulator recipes.  Own-account tooling only: one dump,
one selected account, no batch mode.
"""

from __future__ import annotations

import base64
import binascii
import re
import struct
import typing
import xml.etree.ElementTree as ElementTree
from pathlib import Path

from .data import CodecError, SessionData

__all__ = [
    "read",
    "read_tgnet_dat",
    "discover_accounts",
    "looks_like_dump",
    "PRESERVES",
    "SOURCE_FORMAT",
]

#: CLI/codec format name this module serves (a SOURCE only)
SOURCE_FORMAT = "android-dir"

#: fields of :class:`SessionData` this format genuinely preserves: the
#: auth key, its dc id and first endpoint, the account's user id, the
#: test-backend flag, and the official app's own api_id (see
#: :func:`_official_android_api_id`).
PRESERVES = frozenset(
    {"dc_id", "auth_key", "user_id", "server_address", "port", "test_mode", "api_id"}
)


#: the api_id the official Android app itself authenticates with (BuildVars
#: in the shipped APK 13.1.1, telegram.org/dl/android/apk). A session read
#: from the app's data dir was created under this id, so it is recorded as
#: provenance. Deliberately NOT ``API.TelegramAndroid.api_id``: that preset
#: uses 6, because Telegram refuses 4 for new logins from anything but the
#: real app (API_ID_PUBLISHED_FLOOD; see the note in tgmint/api.py).
OFFICIAL_APP_API_ID = 4


def _official_android_api_id() -> int:
    """The api_id the official Android app itself authenticates with."""
    return OFFICIAL_APP_API_ID

#: highest ``ConnectionsManager`` configVersion this reader understands
#: (``ConnectionsManager.h:140`` at the pinned commit; a *newer* one
#: means a future app changed the layout — refuse, don't guess)
CONFIG_VERSION = 5

#: highest datacenter stream version this reader understands
#: (``Datacenter.h:129`` at the pinned commit)
DC_STREAM_VERSION = 13

#: TL bool constructors (``NativeByteBuffer.cpp:202-215``)
_TRUE = 0x997275B5
_FALSE = 0xBC799737

#: known ``TLRPC.User`` constructor prefixes we can read ``id`` from
#: (see module docstring for the per-constructor field order)
_USER_CONSTRUCTORS = {
    0xB1B8CC83: 12,  # TL_user (current): constructor, flags, flags2, id:i64
    0x215C4438: 8,   # TL_user_layer184 (10.3.2-12.9.0): constructor, flags, id:i64
    0xD3BC4B7A: 4,   # TL_userEmpty: constructor, id:i64
}

#: ``account<N>/`` directories the app creates (``FilePathDatabase.java:50``)
_ACCOUNT_DIR = re.compile(r"^account(\d+)$")


class _Reader:
    """A cursor over one tgnet payload that fails as :class:`CodecError`.

    Every read checks its bounds first, so a truncated or garbage file
    surfaces as the codec's typed error — never a raw ``struct.error``,
    ``IndexError`` or ``EOFError`` from inside the parser.
    """

    def __init__(self, data: bytes, what: str) -> None:
        self._data = data
        self._pos = 0
        self._what = what

    def _take(self, count: int) -> bytes:
        if count < 0 or self._pos + count > len(self._data):
            raise CodecError(
                f"truncated or corrupt {self._what}: expected {count} more "
                f"bytes at offset {self._pos}, {len(self._data) - self._pos} left"
            )
        chunk = self._data[self._pos : self._pos + count]
        self._pos += count
        return chunk

    def _unpack(self, fmt: str) -> typing.Any:
        return struct.unpack(fmt, self._take(struct.calcsize(fmt)))[0]

    def uint32(self) -> int:
        return self._unpack("<I")

    def int32(self) -> int:
        return self._unpack("<i")

    def int64(self) -> int:
        return self._unpack("<q")

    def boolean(self) -> bool:
        value = self.uint32()
        if value == _TRUE:
            return True
        if value == _FALSE:
            return False
        raise CodecError(
            f"corrupt {self._what}: bad bool constructor "
            f"0x{value:08x} at offset {self._pos - 4} (expected TL true/false)"
        )

    def string_bytes(self) -> bytes:
        """One TL string / byte array (length prefix + alignment)."""
        first = self._take(1)[0]
        if first < 254:
            length, header = first, 1
        else:
            length = int.from_bytes(self._take(3), "little")
            header = 4
        payload = self._take(length)
        self._take(-(length + header) % 4)  # TL 4-byte alignment padding
        return payload

    def string(self) -> str:
        try:
            return self.string_bytes().decode("utf-8")
        except UnicodeDecodeError:
            raise CodecError(
                f"corrupt {self._what}: a string is not valid UTF-8 "
                f"at offset {self._pos}"
            ) from None

    def raw(self, count: int) -> bytes:
        """One bare ``readBytes(len)`` (no prefix) — the auth keys."""
        return self._take(count)


class _Address(typing.NamedTuple):
    address: str
    port: int


class _Datacenter(typing.NamedTuple):
    dc_id: int
    last_init_version: int
    ipv4: list[_Address]
    ipv6: list[_Address]
    is_cdn: bool
    auth_key_perm: bytes
    authorized: bool


class _TgnetConfig(typing.NamedTuple):
    config_version: int
    test_backend: bool
    lang_code: str
    current_dc_id: int
    datacenters: dict[int, _Datacenter]


def _read_datacenter(reader: _Reader) -> _Datacenter:
    """One ``Datacenter`` stream (``Datacenter.cpp:47-160`` mirror)."""
    version = reader.uint32()
    if not 2 <= version <= DC_STREAM_VERSION:
        raise CodecError(
            f"unsupported datacenter stream version {version} "
            f"(this reader understands 2-{DC_STREAM_VERSION}, per "
            "Datacenter.h at the pinned DrKLO commit)"
        )
    dc_id = reader.uint32()
    if version >= 3:
        last_init_version = reader.uint32()
    else:
        last_init_version = 0
    if version >= 10:
        reader.uint32()  # lastInitMediaVersion (the app's media versionCode)

    addresses: list[list[_Address]] = [[], [], [], []]
    for slot in range(4 if version >= 5 else 1):
        for _ in range(reader.uint32()):
            address = reader.string()
            port = reader.uint32()
            if version >= 7:
                reader.int32()  # flags (proxy/special modes)
            if version >= 9:
                reader.string_bytes()  # secret (hex until v11; unused here)
            if port > 0 and address:
                addresses[slot].append(_Address(address, port))

    is_cdn = reader.boolean() if version >= 6 else False

    length = reader.uint32()
    auth_key_perm = reader.raw(length) if length else b""
    reader.int64()  # authKeyPermId
    if version >= 8:
        length = reader.uint32()
        if length:
            reader.raw(length)  # authKeyTemp — per-connection, not the login
        reader.int64()  # authKeyTempId
    if version >= 12:
        length = reader.uint32()
        if length:
            reader.raw(length)  # authKeyMediaTemp
        reader.int64()  # authKeyMediaTempId

    authorized = reader.int32() != 0

    # serverSalts, then mediaServerSalts (v13+): valid_since, valid_until,
    # salt triples — not needed for a session import, only for advancing
    for _ in range(2 if version >= 13 else 1):
        for _ in range(reader.uint32()):
            reader.int32()
            reader.int32()
            reader.int64()

    return _Datacenter(
        dc_id=dc_id,
        last_init_version=last_init_version,
        ipv4=addresses[0],
        ipv6=addresses[1],
        is_cdn=is_cdn,
        auth_key_perm=auth_key_perm,
        authorized=authorized,
    )


def read_tgnet_dat(raw: bytes) -> _TgnetConfig:
    """Parse one ``tgnet.dat`` payload (framing included).

    Mirrors ``ConnectionsManager::loadConfig``
    (``ConnectionsManager.cpp:364-416``) over the ``Config.cpp`` framing.
    Accepts config versions 1-5 and datacenter stream versions 2-13 —
    the same ranges the native reader accepts at the pinned commit.

    Raises:
        CodecError: bad framing, an unsupported (future) version, or a
            truncated/garbage payload.
    """
    if len(raw) < 4:
        raise CodecError(
            "tgnet.dat is too short to hold its size prefix "
            f"({len(raw)} bytes)"
        )
    size = struct.unpack_from("<I", raw, 0)[0]
    payload = raw[4:]
    if size != len(payload):
        raise CodecError(
            f"tgnet.dat size prefix {size} does not match its payload "
            f"({len(payload)} bytes) — truncated or corrupt file"
        )
    reader = _Reader(payload, "tgnet.dat")

    version = reader.uint32()
    if not 1 <= version <= CONFIG_VERSION:
        raise CodecError(
            f"unsupported tgnet.dat config version {version} "
            f"(this reader understands 1-{CONFIG_VERSION}; a higher one "
            "means a newer app changed the layout)"
        )
    test_backend = reader.boolean()
    if version >= 3:
        reader.boolean()  # clientBlocked — never a reason to refuse a read
    lang_code = reader.string() if version >= 4 else ""

    if not reader.boolean():  # hasCurrentDc == false: nothing logged in
        raise CodecError(
            "tgnet.dat has no current datacenter — this app copy never "
            "signed in (hasCurrentDc is false)"
        )
    current_dc_id = reader.uint32()
    reader.int32()  # timeDifference
    reader.int32()  # lastDcUpdateTime
    reader.int64()  # pushSessionId
    if version >= 2:
        reader.boolean()  # registeredForInternalPush
    if version >= 5:
        reader.int32()  # lastServerTime
    for _ in range(reader.uint32()):  # sessionsToDestroy
        reader.int64()

    datacenters: dict[int, _Datacenter] = {}
    for _ in range(reader.uint32()):
        datacenter = _read_datacenter(reader)
        datacenters[datacenter.dc_id] = datacenter
    return _TgnetConfig(
        config_version=version,
        test_backend=test_backend,
        lang_code=lang_code,
        current_dc_id=current_dc_id,
        datacenters=datacenters,
    )


def _tgnet_path(files_dir: Path, index: int) -> typing.Optional[Path]:
    """The account's ``tgnet.dat``, falling back to its crash ``.bak``.

    ``Config.cpp:17-28``: the app promotes a leftover ``.bak`` over the
    main file, so a missing ``tgnet.dat`` with a present ``.bak`` is a
    complete (previous) config, not corruption.
    """
    directory = files_dir if index == 0 else files_dir / f"account{index}"
    for name in ("tgnet.dat", "tgnet.dat.bak"):
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def _prefs_path(prefs_dir: Path, index: int) -> Path:
    """The account's SharedPreferences XML (``UserConfig.java:411-416``)."""
    name = "userconfing.xml" if index == 0 else f"userconfig{index}.xml"
    return prefs_dir / name


def _read_user_id(path: Path) -> typing.Optional[int]:
    """Best-effort ``user_id`` from the account's SharedPreferences XML.

    The ``user`` key holds Base64 of a serialized ``TLRPC.User``
    (``UserConfig.java:218,365-370``); only the constructor prefix and
    ``id`` are parsed (see module docstring).  Returns ``None`` when the
    pref is absent, empty (logged out), undecodable, or in a constructor
    this reader does not know — the auth key is the import, the id is a
    bonus, and a wrong id must never be guessed.
    """
    try:
        root = ElementTree.parse(str(path)).getroot()
    except (ElementTree.ParseError, OSError):
        # missing or malformed prefs never fail the import: tgnet.dat is
        # the required artifact, the user id is best-effort
        return None
    for element in root.iter("string"):
        if element.get("name") == "user":
            blob = (element.text or "").strip()
            break
    else:
        return None
    if not blob:
        return None
    try:
        # Java's Base64.DEFAULT wraps output every 76 columns
        raw = base64.b64decode(re.sub(r"\s+", "", blob))
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 4:
        return None
    constructor = struct.unpack_from("<I", raw, 0)[0]
    offset = _USER_CONSTRUCTORS.get(constructor)
    if offset is None or offset + 8 > len(raw):
        # unknown (future) constructor, or a buffer too short for the
        # id field — userEmpty is legitimately only 12 bytes
        return None
    return struct.unpack_from("<q", raw, offset)[0]


def _locate(path: Path) -> tuple[Path, Path]:
    """Resolve a dump directory into its (files_dir, shared_prefs_dir).

    Accepts the app data directory itself (``files/`` + ``shared_prefs/``
    — what ``adb pull /data/data/org.telegram.messenger`` yields), the
    ``files/`` directory alone, or a flat folder holding a pulled
    ``tgnet.dat`` next to the prefs XML(s).
    """
    files_dir = path / "files" if (path / "files").is_dir() else path
    prefs_dir = path / "shared_prefs"
    if not prefs_dir.is_dir():
        prefs_dir = files_dir
    return files_dir, prefs_dir


def discover_accounts(path: typing.Union[str, Path]) -> list[int]:
    """List the account slots a dump actually contains, in order.

    Account 0 is present when ``tgnet.dat`` (or its ``.bak``) sits in the
    files dir; account N (1+) when ``account<N>/tgnet.dat`` does.  The
    official app holds at most ``MAX_ACCOUNT_COUNT`` slots
    (``UserConfig.java:28``: 4 at the pinned commit), but discovery globs
    instead of assuming, so a future raise keeps working.
    """
    files_dir, _prefs = _locate(Path(path))
    slots = []
    if _tgnet_path(files_dir, 0) is not None:
        slots.append(0)
    if files_dir.is_dir():
        for entry in files_dir.iterdir():
            match = _ACCOUNT_DIR.match(entry.name)
            if match and entry.is_dir() and _tgnet_path(files_dir, int(match.group(1))):
                slots.append(int(match.group(1)))
    return sorted(set(slots))


def looks_like_dump(path: typing.Union[str, Path]) -> bool:
    """True when `path` is a directory holding at least one ``tgnet.dat``.

    The format-inference hook (:func:`tgmint.codec.infer_source_format`)
    calls this so a dump directory passed without ``--from-format`` is
    recognized as an Android source rather than falling through to the
    telethon default.  Never raises.
    """
    try:
        return Path(path).is_dir() and bool(discover_accounts(path))
    except OSError:  # pragma: no cover - unreadable directory
        return False


def read(
    path: typing.Union[str, Path],
    *,
    account_index: typing.Optional[int] = None,
) -> SessionData:
    """Read one account out of an official-Android-app data dump.

    Args:
        path: the dump directory — the app data dir (``files/`` +
            ``shared_prefs/``), the ``files/`` dir alone, or a flat
            folder with a pulled ``tgnet.dat`` (+ prefs XML).
        account_index: which account slot to read (0 = the app's first
            account); ``None`` also means slot 0.  There is deliberately
            no "convert all" — own-account tooling, one account at a
            time.

    Returns:
        the selected account: dc id, the 256-byte permanent auth key,
        its first endpoint, user_id (when the prefs XML yielded one),
        test_mode from ``testBackend``, and the official app's own
        ``api_id`` (:data:`OFFICIAL_APP_API_ID`, so a
        session born here lands in Pyrogram-family destinations with
        the app's own identity instead of the matrix's 2040 placeholder).
        A dump from a *forked* client should pass its own ``api_id`` to
        :func:`~tgmint.codec.convert_session` explicitly.

    Raises:
        FileNotFoundError: ``path`` is not a directory.
        CodecError: no account slots / index out of range / the selected
            account is not authorized / a malformed or truncated file.
    """
    root = Path(path)
    if not root.is_dir():
        raise FileNotFoundError(f"android-dir does not exist: {root}")

    files_dir, prefs_dir = _locate(root)
    slots = discover_accounts(root)
    if not slots:
        raise CodecError(
            f"no tgnet.dat found under {root} (looked in {files_dir} and "
            "its account<N>/ subdirectories) — this is not an official "
            "Android app data dump, or nothing was pulled"
        )
    index = 0 if account_index is None else account_index
    if type(index) is not int or index < 0:
        raise CodecError("account_index must be a non-negative integer")
    if index not in slots:
        raise CodecError(
            f"account index {index} not present in this dump "
            f"(available: {slots})"
        )

    tgnet = _tgnet_path(files_dir, index)
    if tgnet is None:  # pragma: no cover - discover_accounts just listed it
        raise CodecError(f"account {index} disappeared between checks")
    try:
        raw = tgnet.read_bytes()
    except OSError as exc:
        raise CodecError(f"cannot read {tgnet}: {exc}") from None
    config = read_tgnet_dat(raw)

    datacenter = config.datacenters.get(config.current_dc_id)
    if datacenter is None:
        raise CodecError(
            f"tgnet.dat names DC {config.current_dc_id} as current but "
            f"has no stream for it (DCs present: "
            f"{sorted(config.datacenters)})"
        )
    if not datacenter.auth_key_perm:
        raise CodecError(
            f"account {index} has no permanent auth key on its current "
            f"DC {config.current_dc_id} — this slot is not signed in "
            "(or the dump predates the login)"
        )

    endpoint = (datacenter.ipv4 or datacenter.ipv6 or [None])[0]
    return SessionData(
        dc_id=config.current_dc_id,
        auth_key=datacenter.auth_key_perm,
        user_id=_read_user_id(_prefs_path(prefs_dir, index)),
        server_address=endpoint.address if endpoint else None,
        port=endpoint.port if endpoint else None,
        is_bot=False,  # the official app's own account, never a bot login
        test_mode=config.test_backend,
        api_id=_official_android_api_id(),
    ).validated()
