from __future__ import annotations
from .configs import *
from . import shared as td

import hashlib
import os
import tgcrypto

# if TYPE_CHECKING:
#     from ..tgmint import *


class Serialize(BaseObject):
    @staticmethod
    def bytearraySize(arr: QByteArray):
        return sizeof(uint32) + arr.size()

    @staticmethod
    def bytesSize(arr: bytes):
        return sizeof(uint32) + len(arr)

    @staticmethod
    def stringSize(arr: Optional[str]):
        """Byte size :meth:`QDataStream.writeQString` emits for ``arr``.

        QString is a uint32 byte-length prefix plus a UTF-16-BE payload, so
        the size is ``4 + len(arr.encode("utf-16-be"))`` — twice the
        character count only for BMP text (an astral character takes two
        UTF-16 code units). The old form (``4 + len + 2``) was wrong for
        every string (review finding #42); it survived because its only
        caller summed it into a value nobody read. ``None``/``""`` are the
        four-byte null/empty markers.
        """
        if not arr:
            return sizeof(uint32)
        return sizeof(uint32) + len(arr.encode("utf-16-be"))


class Storage(BaseObject):
    class ReadSettingsContext(BaseObject):  # pragma: no cover
        def __init__(self) -> None:

            self.fallbackConfigLegacyDcOptions: td.MTP.DcOptions = td.MTP.DcOptions(
                td.MTP.Environment.Production
            )
            self.fallbackConfigLegacyChatSizeMax = 0
            self.fallbackConfigLegacySavedGifsLimit = 0
            self.fallbackConfigLegacyStickersRecentLimit = 0
            self.fallbackConfigLegacyStickersFavedLimit = 0
            self.fallbackConfigLegacyMegagroupSizeMax = 0
            self.fallbackConfigLegacyTxtDomainString = ""
            self.fallbackConfig = QByteArray()

            self.cacheTotalSizeLimit = 0
            self.cacheTotalTimeLimit = 0
            self.cacheBigFileTotalSizeLimit = 0
            self.cacheBigFileTotalTimeLimit = 0

            self.themeKeyLegacy = FileKey(0)
            self.themeKeyDay = FileKey(0)
            self.themeKeyNight = FileKey(0)
            self.backgroundKeyDay = FileKey(0)
            self.backgroundKeyNight = FileKey(0)

            self.backgroundKeysRead = False
            self.tileDay = False
            self.tileNight = True
            self.tileRead = False

            self.langPackKey = FileKey(0)
            self.languagesKey = FileKey(0)

            self.mtpAuthorization = QByteArray()
            self.mtpLegacyKeys: typing.List[td.AuthKey] = []

            self.mtpLegacyMainDcId = 0
            self.mtpLegacyUserId = 0
            self.legacyRead = False

    class FileReadDescriptor(BaseObject):
        def __init__(self) -> None:
            self.__version = 0
            self.__data = QByteArray()
            self.__buffer = QBuffer()
            self.__stream = QDataStream()

        @property
        def data(self) -> QByteArray:
            return self.__data

        @data.setter
        def data(self, value):
            self.__data = value

        @property
        def version(self) -> int:
            return self.__version

        @version.setter
        def version(self, value):
            self.__version = value

        @property
        def buffer(self) -> QBuffer:
            return self.__buffer

        @property
        def stream(self) -> QDataStream:
            return self.__stream

    class EncryptedDescriptor(BaseObject):
        def __init__(self, size: int = None) -> None:
            self.__data = QByteArray()
            self.__buffer = QBuffer()
            self.__stream = QDataStream()

            # fork note: this used to be `if size:` — a size of 0 (an empty
            # map, a record with no fields) left the descriptor completely
            # uninitialised, so its stream had no device and every write
            # silently became a WriteFailed no-op: PrepareEncrypted then
            # produced a bogus record for a legitimately empty payload.
            # tdesktop has two constructors — the default one (used by
            # DecryptLocal, which installs the buffer itself) and the
            # sized one, which always initialises — so `size is not None`
            # is the faithful split. Note the sized form ALWAYS leaves the
            # 4-byte length prefix in the data (resize(4)), which is what
            # makes a size-0 payload a valid, decryptable record.
            if size is not None:
                size = max(0, int(size))
                fullSize = 4 + size
                if fullSize & 0x0F:
                    fullSize += 0x10 - (fullSize & 0x0F)

                self.__data.reserve(fullSize)
                self.__data.resize(4)
                self.__buffer.setBuffer(self.__data)
                self.__buffer.open(QIODevice.OpenModeFlag.WriteOnly)
                self.__buffer.seek(4)
                self.__stream.setDevice(self.__buffer)
                self.__stream.setVersion(QDataStream.Version.Qt_5_1)

        def finish(self) -> None:
            if self.__stream.device():
                self.__stream.setDevice(None)  # type: ignore
            if self.__buffer.isOpen():
                self.__buffer.close()
            self.__buffer.setBuffer(None)  # type: ignore

        @property
        def data(self) -> QByteArray:
            return self.__data

        @data.setter
        def data(self, value):
            self.__data = value

        @property
        def buffer(self) -> QBuffer:
            return self.__buffer

        @property
        def stream(self) -> QDataStream:
            return self.__stream

    class FileWriteDescriptor(BaseObject):
        def __init__(self, fileName: str, basePath: str, sync: bool = False) -> None:
            self.fileName = fileName
            self.basePath = basePath
            self.sync = sync
            self.init(fileName)

        def init(self, fileName: str):
            self.base = Storage.PathJoin(self.basePath, fileName)
            self.safeData = QByteArray()
            self.buffer = QBuffer()
            self.buffer.setBuffer(self.safeData)

            result = self.buffer.open(QIODevice.OpenModeFlag.WriteOnly)
            Expects(result, "Can not open buffer, something went wrong")

            self.stream = QDataStream()
            self.stream.setDevice(self.buffer)

            self.md5 = b""
            self.fullSize = 0

        def writeData(self, data: QByteArray):
            Expects(self.stream.device() != None, "stream.device is missing")

            self.stream << data
            len = 0xFFFFFFFF if data.isNull() else data.size()

            if QSysInfo.Endian.ByteOrder != QSysInfo.Endian.BigEndian:

                def qbswap(source: int) -> int:
                    return (
                        0
                        | ((source & 0x000000FF) << 24)
                        | ((source & 0x0000FF00) << 8)
                        | ((source & 0x00FF0000) >> 8)
                        | ((source & 0xFF000000) >> 24)
                    )

                len = qbswap(len)

            self.md5 += len.to_bytes(4, "little")
            self.md5 += data.data()
            self.fullSize += 4 + data.size()

        def writeEncrypted(self, data: Storage.EncryptedDescriptor, key: td.AuthKey):
            self.writeData(Storage.PrepareEncrypted(data, key))

        def finish(self):
            if not self.stream.device():
                return
            self.stream.setDevice(None)  # type: ignore

            self.md5 += self.fullSize.to_bytes(4, "little")
            self.md5 += APP_VERSION.to_bytes(4, "little")
            self.md5 += TDF_MAGIC
            self.md5 = hashlib.md5(self.md5).digest()

            self.buffer.close()

            finalData: bytes = self.safeData.data() + self.md5
            Storage.WriteFile(self.fileName, self.basePath, finalData)

    @staticmethod
    def PrepareEncrypted(data: EncryptedDescriptor, key: td.AuthKey) -> QByteArray:
        data.finish()

        toEncrypt = QByteArray(data.data)

        # prepare for encryption
        size = toEncrypt.size()
        fullSize = size
        if fullSize & 0x0F:
            fullSize += 0x10 - (fullSize & 0x0F)
            # pad with random bytes like tdesktop's base::RandomFill — the
            # padding is encrypted, but deterministic zero padding (what
            # QByteArray.resize() leaves behind) is a fingerprint tdesktop
            # files never had. Rebuild via python bytes to control the
            # padding content. The no-padding case is untouched.
            raw = bytes(toEncrypt.data()) + os.urandom(fullSize - size)
            toEncrypt = QByteArray(raw)

        # *(uint32*)toEncrypt.data() = size;
        toEncrypt = QByteArray(size.to_bytes(4, "little")) + toEncrypt[4:]

        hashData = hashlib.sha1(toEncrypt)
        encrypted = QByteArray(hashData.digest())

        encrypted.resize(0x10 + fullSize)  # 128bit of sha1 - key128, sizeof(data), data

        encrypted = encrypted[:0x10] + Storage.aesEncryptLocal(
            toEncrypt, key, encrypted
        )

        return encrypted

    @staticmethod
    def WriteFile(fileName: str, basePath: str, data: bytes):

        dir = QDir(basePath)
        if not dir.exists():
            dir.mkpath(basePath)

        file = QFile(Storage.PathJoin(basePath, fileName + "s"))
        if file.open(QIODevice.OpenModeFlag.WriteOnly):
            file.write(TDF_MAGIC)
            file.write(APP_VERSION.to_bytes(4, "little"))
            file.write(data)
            file.close()
            return True

        raise OpenTeleException(f"Could not write {fileName} to {basePath}")

    @staticmethod
    def ReadFile(fileName: str, basePath: str) -> FileReadDescriptor:

        # Candidate order is tdesktop's (storage/details/
        # storage_file_utilities.cpp, ReadFile): the modern "<base>s" wins
        # outright when it exists; otherwise fall back to the legacy pair
        # "<base>0"/"<base>1" and try the NEWER one (by mtime) first. When
        # only one of the legacy files exists, only that one is tried.
        # fork note: this used to try "s", "1", "0" unconditionally, which
        # read a stale backup ahead of the live file and tried files that
        # were never candidates in tdesktop.
        base = Storage.PathJoin(basePath, fileName)
        to_try: typing.List[str] = []
        modern = base + "s"
        if os.path.exists(modern):
            to_try = [modern]
        else:
            legacy0 = base + "0"
            legacy1 = base + "1"
            if os.path.exists(legacy0):
                if os.path.exists(legacy1):
                    try:
                        newer_first = os.path.getmtime(legacy0) < os.path.getmtime(
                            legacy1
                        )
                    except OSError:
                        newer_first = False
                    to_try = (
                        [legacy1, legacy0] if newer_first else [legacy0, legacy1]
                    )
                else:
                    to_try = [legacy0]
            else:
                to_try = [legacy1]

        tries_exception = None
        for path in to_try:
            # fork note: no try/except IOError here — QFile.open() signals
            # failure through its return value, it never raises Python
            # IOError; a real OSError (disk failure etc.) should propagate.
            file = QFile(path)
            if not file.open(QIODevice.OpenModeFlag.ReadOnly):
                tries_exception = TFileNotFound(f"Could not open {fileName}")
                continue

            magic = file.read(4)

            if magic != TDF_MAGIC:
                tries_exception = TDataInvalidMagic(
                    f"Invalid magic {magic} in file {fileName}"
                )
                file.close()
                continue

            version = int.from_bytes(file.read(4), "little")

            bytesdata = QByteArray(file.read(file.size()))

            dataSize = bytesdata.size() - 16

            # fork note: tdesktop skips a file whose payload is too short to
            # even carry the 16-byte md5 trailer ("could not read sign
            # part"). Without this guard a truncated file made the
            # int.to_bytes()/slice arithmetic below blow up with a bare
            # OverflowError instead of a TData exception.
            if dataSize < 0:
                tries_exception = TDataInvalidCheckSum(
                    f"File {fileName} is too short to carry a signature "
                    f"({bytesdata.size()} bytes)"
                )
                file.close()
                continue

            check_md5 = bytesdata.data()[:dataSize]
            check_md5 += int(dataSize).to_bytes(4, "little")
            check_md5 += int(version).to_bytes(4, "little")
            check_md5 += magic
            check_md5 = hashlib.md5(check_md5)

            md5 = bytesdata.data()[dataSize:]

            if check_md5.hexdigest() != md5.hex():
                tries_exception = TDataInvalidCheckSum(
                    f"Invalid checksum {check_md5.hexdigest()} in file {fileName}"
                )
                file.close()
                continue

            result = Storage.FileReadDescriptor()
            result.version = version

            bytesdata.resize(dataSize)
            result.data = bytesdata
            bytesdata = QByteArray()

            result.buffer.setBuffer(result.data)

            result.buffer.open(QIODevice.OpenModeFlag.ReadOnly)
            result.stream.setDevice(result.buffer)
            result.stream.setVersion(QDataStream.Version.Qt_5_1)

            file.close()
            return result

        raise tries_exception if tries_exception else TFileNotFound(
            f"Could not open {fileName}"
        )

    @staticmethod
    def ReadEncryptedFile(
        fileName: str, basePath: str, authKey: td.AuthKey
    ) -> FileReadDescriptor:

        result = Storage.ReadFile(fileName, basePath)
        encrypted = QByteArray()
        result.stream >> encrypted

        try:
            data = Storage.DecryptLocal(encrypted, authKey)
        except OpenTeleException as e:
            result.stream.setDevice(None)  # type: ignore
            if result.buffer.isOpen():
                result.buffer.close()
            result.buffer.setBuffer(None)  # type: ignore
            result.data = QByteArray()
            result.version = 0
            raise e

        result.stream.setDevice(None)  # type: ignore
        if result.buffer.isOpen():
            result.buffer.close()
        result.buffer.setBuffer(None)  # type: ignore
        result.data = data.data

        result.buffer.setBuffer(result.data)
        result.buffer.open(QIODevice.OpenModeFlag.ReadOnly)
        result.buffer.seek(data.buffer.pos())
        result.stream.setDevice(result.buffer)
        result.stream.setVersion(QDataStream.Version.Qt_5_1)

        return result

    @staticmethod
    def ReadSetting(
        blockId: int, stream: QDataStream, version: int, context: ReadSettingsContext
    ) -> bool:  # pragma: no cover

        if blockId == dbi.DcOptionOldOld:
            dcId = DcId(stream.readUInt32())
            stream.readQString()
            ip = stream.readQString()
            port = stream.readUInt32()
            ExpectStreamStatus(stream)

            context.fallbackConfigLegacyDcOptions.constructAddOne(
                dcId, td.MTP.DcOptions.Flag(0), ip, port, b""
            )
            context.legacyRead = True

        elif blockId == dbi.DcOptionOld:
            dcIdWithShift = ShiftedDcId(stream.readUInt32())
            flags = td.MTP.DcOptions.Flag(stream.readInt32())
            ip = stream.readQString()
            port = stream.readUInt32()

            ExpectStreamStatus(stream)

            context.fallbackConfigLegacyDcOptions.constructAddOne(
                dcIdWithShift, flags, ip, port, b""
            )
            context.legacyRead = True

        elif blockId == dbi.DcOptionsOld:
            serialized = QByteArray()
            stream >> serialized
            ExpectStreamStatus(stream)

            context.fallbackConfigLegacyDcOptions.constructFromSerialized(serialized)
            context.legacyRead = True

        elif blockId == dbi.ApplicationSettings:
            serialized = QByteArray()
            stream >> serialized
            ExpectStreamStatus(stream)

            # TO BE ADDED

        elif blockId == dbi.ChatSizeMaxOld:
            maxSize = stream.readInt32()
            ExpectStreamStatus(stream)

            context.fallbackConfigLegacyChatSizeMax = maxSize
            context.legacyRead = True

        elif blockId == dbi.SavedGifsLimitOld:
            limit = stream.readInt32()
            ExpectStreamStatus(stream)

            context.fallbackConfigLegacySavedGifsLimit = limit
            context.legacyRead = True

        elif blockId == dbi.StickersRecentLimitOld:
            limit = stream.readInt32()
            ExpectStreamStatus(stream)

            context.fallbackConfigLegacyStickersRecentLimit = limit
            context.legacyRead = True

        elif blockId == dbi.StickersFavedLimitOld:
            limit = stream.readInt32()
            ExpectStreamStatus(stream)

            context.fallbackConfigLegacyStickersFavedLimit = limit
            context.legacyRead = True

        elif blockId == dbi.MegagroupSizeMaxOld:
            maxSize = stream.readInt32()
            ExpectStreamStatus(stream)

            context.fallbackConfigLegacyMegagroupSizeMax = maxSize
            context.legacyRead = True

        elif blockId == dbi.User:
            userId = stream.readInt32()
            dcId = stream.readUInt32()
            ExpectStreamStatus(stream)

            context.mtpLegacyMainDcId = dcId
            context.mtpLegacyUserId = userId

        elif blockId == dbi.Key:
            dcId = DcId(stream.readInt32())
            key = stream.readRawData(256)
            ExpectStreamStatus(stream)

            context.mtpLegacyKeys.append(
                td.AuthKey(key, td.AuthKeyType.ReadFromFile, dcId)
            )

        elif blockId == dbi.MtpAuthorization:
            serialized = QByteArray()
            stream >> serialized
            ExpectStreamStatus(stream)

            context.mtpAuthorization = serialized

        return True

    @staticmethod
    def CreateLocalKey(
        salt: QByteArray, passcode: QByteArray = None
    ) -> td.AuthKey:
        if passcode is None:
            passcode = QByteArray()
        hashKey = hashlib.sha512(salt)
        hashKey.update(passcode)
        hashKey.update(salt)

        iterationsCount = 1 if passcode.isEmpty() else 100000
        return td.AuthKey(
            hashlib.pbkdf2_hmac("sha512", hashKey.digest(), salt, iterationsCount, 256)
        )

    @staticmethod
    def CreateLegacyLocalKey(
        salt: QByteArray, passcode: QByteArray = None
    ) -> td.AuthKey:
        if passcode is None:
            passcode = QByteArray()
        # tdesktop's CreateLegacyLocalKey (storage/details/
        # storage_file_utilities.cpp):
        #
        #   PKCS5_PBKDF2_HMAC_SHA1(passcode, salt,
        #       passcode.isEmpty() ? LocalEncryptNoPwdIterCount
        #                          : LocalEncryptIterCount, 256, key)
        #
        # with LocalEncryptIterCount = 4000 and LocalEncryptNoPwdIterCount
        # = 4 (config.h). The legacy map key is SHA-1 based, NOT the
        # SHA-512/100k of CreateLocalKey -- a different KDF family, so the
        # two are not interchangeable. fork note: this used to run
        # SHA-512 with 100000 iterations, i.e. a key no tdesktop build ever
        # derived, so legacy (passcode-only) map files could never be
        # opened. The argument order is (salt, passcode) here to match the
        # call sites; PBKDF2 gets password=passcode, salt=salt, as in C++.

        iterationsCount = 4 if passcode.isEmpty() else 4000
        return td.AuthKey(
            hashlib.pbkdf2_hmac(
                "sha1", passcode.data(), salt.data(), iterationsCount, 256
            )
        )

    @staticmethod
    def aesEncryptLocal(
        src: QByteArray, authKey: td.AuthKey, key128: QByteArray
    ) -> QByteArray:
        aesKey, aesIv = authKey.prepareAES_oldmtp(key128, False)
        encrypted = tgcrypto.ige256_encrypt(src, aesKey, aesIv)
        return QByteArray(encrypted)

    @staticmethod
    def aesDecryptLocal(
        src: QByteArray, authKey: td.AuthKey, key128: QByteArray
    ) -> QByteArray:
        aesKey, aesIv = authKey.prepareAES_oldmtp(key128, False)
        decrypted = tgcrypto.ige256_decrypt(src, aesKey, aesIv)
        return QByteArray(decrypted)

    @staticmethod
    def DecryptLocal(encrypted: QByteArray, authKey: td.AuthKey) -> EncryptedDescriptor:

        encryptedSize = encrypted.size()
        if (encryptedSize <= 16) or (encryptedSize & 0x0F):
            raise TDataBadEncryptedDataSize(f"Bad encrypted part size: {encryptedSize}")

        fullLen = encryptedSize - 16
        encryptedKey = encrypted[:16]
        encryptedData = encrypted[16:]

        decrypted = Storage.aesDecryptLocal(encryptedData, authKey, encryptedKey)
        checkHash = hashlib.sha1(decrypted).digest()[:16]
        if checkHash != encryptedKey:
            raise TDataBadDecryptKey(
                "Bad decrypt key, data not decrypted - incorrect password?"
            )

        dataLen = int.from_bytes(
            decrypted[:4], "little"
        )  # *(const uint32*)decrypted.constData();
        if (dataLen > decrypted.size()) or (dataLen <= fullLen - 16) or (dataLen < 4):
            raise TDataBadDecryptedDataSize(
                f"Bad decrypted part size: {encryptedSize}, fullLen: {fullLen}, decrypted size: {len(decrypted)}"
            )

        decrypted.resize(dataLen)
        result = Storage.EncryptedDescriptor()
        result.data = decrypted

        decrypted = QByteArray()

        result.buffer.setBuffer(result.data)
        result.buffer.open(QIODevice.OpenModeFlag.ReadOnly)
        result.buffer.seek(4)  # skip len
        result.stream.setDevice(result.buffer)
        result.stream.setVersion(QDataStream.Version.Qt_5_1)

        return result

    @staticmethod
    def ComposeDataString(dataName: str, index: int):
        # tdesktop (main/main_account.cpp, ComposeDataString): strip every
        # '#' from the base name, then append '#<index + 1>' for accounts
        # after the first. fork note: `result.replace(...)` on a str is a
        # no-op -- the stripped result was thrown away, so a keyFile that
        # already contained '#' produced "data#1#2" style names that do not
        # match what tdesktop/opentele would compute.
        result = dataName.replace("#", "")
        if index > 0:
            result += f"#{index + 1}"
        return result

    @staticmethod
    def ComputeDataNameKey(dataName: str) -> int:
        md5 = hashlib.md5(dataName.encode("utf-8")).digest()
        return int.from_bytes(md5, "little")

    @staticmethod
    def ToFilePart(val: int):
        result = ""
        for i in range(0, 0x10):
            v = val & 0xF
            if v < 0x0A:
                result += chr(ord("0") + v)
            else:
                result += chr(ord("A") + (v - 0x0A))
            val >>= 4
        return result

    @staticmethod
    def RandomGenerate(size: int) -> QByteArray:
        return QByteArray(os.urandom(size))

    @staticmethod
    def GetAbsolutePath(path: str = None) -> str:

        if path == None or path == "":
            path = os.getcwd()

        path = os.path.abspath(path)
        return path

    @staticmethod
    def PathJoin(path: str, filename: str) -> str:
        return os.path.join(path, filename)
