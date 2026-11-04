from __future__ import annotations

from .configs import *
from . import shared as td

import typing

from telethon.network.connection.connection import Connection
from telethon.network.connection.tcpfull import ConnectionTcpFull
from telethon.sessions.abstract import Session

import logging
import os

# if TYPE_CHECKING:
#     from ..tgmint import *


class MapData(BaseObject):  # nocov
    def __init__(self, basePath: str) -> None:

        self.basePath = basePath

        self._draftsMap: Dict[PeerId, FileKey] = {}
        self._draftCursorsMap: Dict[PeerId, FileKey] = {}
        self._draftsNotReadMap: Dict[PeerId, bool] = {}

        self._locationsKey = FileKey(0)
        self._trustedBotsKey = FileKey(0)
        self._installedStickersKey = FileKey(0)
        self._featuredStickersKey = FileKey(0)
        self._recentStickersKey = FileKey(0)
        self._favedStickersKey = FileKey(0)
        self._archivedStickersKey = FileKey(0)
        self._archivedMasksKey = FileKey(0)
        self._installedCustomEmojiKey = FileKey(0)
        self._featuredCustomEmojiKey = FileKey(0)
        self._archivedCustomEmojiKey = FileKey(0)
        self._searchSuggestionsKey = FileKey(0)
        # fork note: tdesktop stores these as QByteArray token data, not
        # FileKey (lskWebviewTokens = "data: QByteArray bots, QByteArray
        # other" in storage_account.cpp) — the reader below fills them via
        # `stream >>`. They stay empty on fresh instances, so nothing is
        # written for this key unless a map carrying tokens is re-saved.
        self._webviewStorageTokenBots = QByteArray()
        self._webviewStorageTokenOther = QByteArray()
        self._savedGifsKey = FileKey(0)
        self._recentStickersKeyOld = FileKey(0)
        self._legacyBackgroundKeyDay = FileKey(0)
        self._legacyBackgroundKeyNight = FileKey(0)

        # self._settingsKey = FileKey(0)
        # ! TO BE ADDED
        # fork note: upstream hardcoded 1851671142505648812 here ("MUST
        # HAVE OR CAN'T WRITE MAPDATA") — a settings key shared by every
        # tdata this library ever wrote. It is now random per instance;
        # reading existing tdata is unaffected because read() overwrites
        # this with the real settings key from the map file.
        self._settingsKey = FileKey(int.from_bytes(os.urandom(8), "little"))
        """MUST HAVE OR CAN'T WRITE MAPDATA, I'M WOKRING TO FIX THIS"""

        self._recentHashtagsAndBotsKey = FileKey(0)
        self._exportSettingsKey = FileKey(0)
        self._installedMasksKey = FileKey(0)
        self._recentMasksKey = FileKey(0)
        # fork note: map keys newer Telegram Desktop (5.x-6.x) writes —
        # read-side tolerance ported from opentele-ng (upstream issue
        # #120); see lskType in configs.py.
        self._roundPlaceholder = FileKey(0)
        self._inlineBotsDownloads = FileKey(0)
        self._mediaLastPlaybackPositions = FileKey(0)
        # lskBotStorages is a PeerId -> FileKey map, not a single key.
        self._botStoragesMap: Dict[PeerId, FileKey] = {}
        self._botStoragesNotReadMap: Dict[PeerId, bool] = {}
        self._prefsKey = FileKey(0)
        # fork note: the serialized own-user record (lskSelfSerialized,
        # 0x15) used to be parsed into a local and dropped, so a
        # load -> save round-trip silently lost the account's own peer.
        # It is carried on the instance and written back FIRST, which is
        # the position tdesktop uses (storage_account.cpp, writeMap).
        self._selfSerialized = QByteArray()
        # fork note: lskWalletEngineStorages (0x21) is a QString -> FileKey
        # map; read it so the map never desyncs, and keep it so a re-save
        # does not drop it (tdesktop writes it just before lskBotStorages).
        self._walletEngineStoragesMap: Dict[str, FileKey] = {}
        # tdesktop reads the two legacy wallet keys only to ClearKey() the
        # files they point at, and never writes those entries again; we
        # keep the values for inspection but deliberately do not re-emit
        # (and never delete files out of the folder we are reading).
        self._walletLegacyKey = FileKey(0)
        self._walletEngineLegacyKey = FileKey(0)

    kMaxMapListCount = 1 << 20
    """Ceiling for a counted map list (drafts, legacy images, ...).

    tdesktop does not cap these, it just trusts the stream: every entry it
    reads is 16-28 bytes, so a truncated/hostile file runs into
    ReadPastEnd quickly. Our reader cannot rely on that alone — the
    per-entry loops only check the stream status once per key TYPE, so a
    declared count of ~4G entries would spin the loop before the check
    ever runs. 1M entries is far beyond any real account yet bounded.
    """

    @staticmethod
    def _checkCount(stream: QDataStream, count: int, itemSize: int, what: str):
        """Reject an implausible list count before looping on it."""
        if count < 0 or count > MapData.kMaxMapListCount:
            raise TDataBadConfigData(
                f"implausible {what} count {count} in map data"
            )
        # a count can never need more bytes than the map has left; this
        # also turns a truncated map into a proper TData* error instead of
        # a long loop over zero-filled reads
        available = stream.bytesAvailable()
        if itemSize > 0 and (count * itemSize > available):
            raise TDataBadConfigData(
                f"truncated map data: {what} declares {count} entries "
                f"but only {available} bytes are left"
            )

    def read(self, localKey: td.AuthKey, legacyPasscode: QByteArray) -> None:

        try:
            mapData = td.Storage.ReadFile("map", self.basePath)
        except OpenTeleException as e:
            raise TDataReadMapDataFailed(
                "Could not read map data, find not found or couldn't be opened"
            ) from e

        legacySalt, legacyKeyEncrypted, mapEncrypted = (
            QByteArray(),
            QByteArray(),
            QByteArray(),
        )

        mapData.stream >> legacySalt >> legacyKeyEncrypted >> mapEncrypted

        ExpectStreamStatus(mapData.stream, "Could not stream data from mapData")

        if not localKey:

            # LocalEncryptSaltSize = 32
            Expects(
                legacySalt.size() == 32,
                TDataReadMapDataFailed(
                    f"Bad salt in map file, size: {legacySalt.size()}"
                ),
            )

            legacyPasscodeKey = td.Storage.CreateLegacyLocalKey(
                legacySalt, legacyPasscode
            )

            try:
                keyData = td.Storage.DecryptLocal(legacyKeyEncrypted, legacyPasscodeKey)
            except OpenTeleException as e:
                raise TDataReadMapDataIncorrectPasscode(
                    "Could not decrypt pass-protected key from map file, maybe bad password..."
                ) from e

            localKey = td.AuthKey.FromStream(keyData.stream)

        try:
            map = td.Storage.DecryptLocal(mapEncrypted, localKey)
        except OpenTeleException as e:
            raise TDataReadMapDataFailed("Could not decrypt map data") from e

        selfSerialized = QByteArray()
        draftsMap: dict[PeerId, FileKey] = {}
        draftCursorsMap: dict[PeerId, FileKey] = {}
        draftsNotReadMap: dict[PeerId, bool] = {}

        locationsKey = 0
        trustedBotsKey = 0
        recentStickersKeyOld = 0
        installedStickersKey = 0
        featuredStickersKey = 0
        recentStickersKey = 0
        favedStickersKey = 0
        archivedStickersKey = 0
        installedMasksKey = 0
        recentMasksKey = 0
        archivedMasksKey = 0
        installedCustomEmojiKey = 0
        featuredCustomEmojiKey = 0
        archivedCustomEmojiKey = 0
        searchSuggestionsKey = 0
        webviewStorageTokenBots = QByteArray()
        webviewStorageTokenOther = QByteArray()
        savedGifsKey = 0
        legacyBackgroundKeyDay = 0
        legacyBackgroundKeyNight = 0
        userSettingsKey = 0
        recentHashtagsAndBotsKey = 0
        exportSettingsKey = 0
        # newer Telegram Desktop map keys (read-side tolerance)
        roundPlaceholder = 0
        inlineBotsDownloads = 0
        mediaLastPlaybackPositions = 0
        botStoragesMap: dict[PeerId, FileKey] = {}
        botStoragesNotReadMap: dict[PeerId, bool] = {}
        prefsKey = 0
        # the two legacy wallet records (0x1F/0x20) are consumed straight
        # into the instance (see __init__); 0x21 is a map, accumulated here
        walletEngineStoragesMap: dict[str, FileKey] = {}

        is_finished = False

        while not is_finished and not map.stream.atEnd():
            keyType = map.stream.readUInt32()

            if keyType == lskType.lskDraft:
                count = map.stream.readUInt32()
                MapData._checkCount(map.stream, count, 16, "drafts")
                for i in range(count):
                    key = FileKey(map.stream.readUInt64())
                    peerIdSerialized = map.stream.readUInt64()
                    peerId = PeerId.FromSerialized(peerIdSerialized)
                    draftsMap[peerId] = key
                    draftsNotReadMap[peerId] = True

            elif keyType == lskType.lskSelfSerialized:
                map.stream >> selfSerialized

            elif keyType == lskType.lskDraftPosition:
                count = map.stream.readUInt32()
                MapData._checkCount(map.stream, count, 16, "draft cursors")
                for i in range(count):
                    key = FileKey(map.stream.readUInt64())
                    peerIdSerialized = map.stream.readUInt64()
                    peerId = PeerId.FromSerialized(peerIdSerialized)
                    draftCursorsMap[peerId] = key

            elif (
                (keyType == lskType.lskLegacyImages)
                or (keyType == lskType.lskLegacyStickerImages)
                or (keyType == lskType.lskLegacyAudios)
            ):
                count = map.stream.readUInt32()
                # key + first + second (uint64 each) + size (int32)
                MapData._checkCount(map.stream, count, 28, "legacy images")
                for i in range(count):
                    map.stream.readUInt64()
                    map.stream.readUInt64()
                    map.stream.readUInt64()
                    map.stream.readInt32()

            elif keyType == lskType.lskLocations:
                locationsKey = map.stream.readUInt64()

            elif keyType == lskType.lskReportSpamStatusesOld:
                map.stream.readUInt64()
                # ClearKey(reportSpamStatusesKey, _basePath);

            elif keyType == lskType.lskTrustedBots:
                trustedBotsKey = map.stream.readUInt64()

            elif keyType == lskType.lskRecentStickersOld:
                recentStickersKeyOld = map.stream.readUInt64()

            elif keyType == lskType.lskBackgroundOldOld:
                # tdesktop reads a single quint64 here (and hands it to the
                # night/day slot depending on the theme). fork note: this
                # used to do `map.stream >> legacyBackgroundKeyDay`, which
                # is the QByteArray operator — it raised TypeError (an int
                # is not a QByteArray), and TypeError is not an
                # OpenTeleException, so one legacy 0x08 entry aborted the
                # whole tdata load past every handler.
                legacyBackgroundKeyDay = map.stream.readUInt64()

            elif keyType == lskType.lskBackgroundOld:
                legacyBackgroundKeyDay = map.stream.readUInt64()
                legacyBackgroundKeyNight = map.stream.readUInt64()

            elif keyType == lskType.lskUserSettings:
                userSettingsKey = map.stream.readUInt64()

            elif keyType == lskType.lskRecentHashtagsAndBots:
                recentHashtagsAndBotsKey = map.stream.readUInt64()

            elif keyType == lskType.lskStickersOld:
                installedStickersKey = map.stream.readUInt64()

            elif keyType == lskType.lskStickersKeys:
                installedStickersKey = map.stream.readUInt64()
                featuredStickersKey = map.stream.readUInt64()
                recentStickersKey = map.stream.readUInt64()
                archivedStickersKey = map.stream.readUInt64()

            elif keyType == lskType.lskFavedStickers:
                favedStickersKey = map.stream.readUInt64()

            elif keyType == lskType.lskSavedGifsOld:
                key = map.stream.readUInt64()

            elif keyType == lskType.lskSavedGifs:
                savedGifsKey = map.stream.readUInt64()

            elif keyType == lskType.lskSavedPeersOld:
                key = map.stream.readUInt64()

            elif keyType == lskType.lskExportSettings:
                exportSettingsKey = map.stream.readUInt64()

            elif keyType == lskType.lskMasksKeys:
                installedMasksKey = map.stream.readUInt64()
                recentMasksKey = map.stream.readUInt64()
                archivedMasksKey = map.stream.readUInt64()

            elif keyType == lskType.lskCustomEmojiKeys:
                installedCustomEmojiKey = map.stream.readUInt64()
                featuredCustomEmojiKey = map.stream.readUInt64()
                archivedCustomEmojiKey = map.stream.readUInt64()

            elif keyType == lskType.lskSearchSuggestions:
                searchSuggestionsKey = map.stream.readUInt64()

            elif keyType == lskType.lskWebviewTokens:
                # fork note: this branch used to set the finished flag and
                # break out of the read loop — upstream treated 0x19 as an
                # end-of-map marker because the payload was unknown.
                # tdesktop actually stores two QByteArrays here (bots,
                # other), and stopping early made every map entry AFTER
                # the tokens silently unreadable.
                map.stream >> webviewStorageTokenBots
                map.stream >> webviewStorageTokenOther

            # newer Telegram Desktop map keys (read-side tolerance,
            # ported from opentele-ng — see lskType in configs.py)
            elif keyType == lskType.lskRoundPlaceholder:
                roundPlaceholder = map.stream.readUInt64()

            elif keyType == lskType.lskInlineBotsDownloads:
                inlineBotsDownloads = map.stream.readUInt64()

            elif keyType == lskType.lskMediaLastPlaybackPositions:
                mediaLastPlaybackPositions = map.stream.readUInt64()

            elif keyType == lskType.lskBotStorages:
                # map: uint32 count + count x (FileKey uint64, PeerId uint64)
                count = map.stream.readUInt32()
                # parser-DoS cap, in the spirit of the mtp-authorization
                # key-count check in _setMtpAuthorization: a corrupt or
                # hostile count must not spin the loop
                if count < 0 or count > 1024:
                    raise TDataBadConfigData(
                        f"implausible bot-storage count {count} in map data"
                    )
                for i in range(count):
                    bs_key = FileKey(map.stream.readUInt64())
                    bs_peerIdSerialized = map.stream.readUInt64()
                    bs_peerId = PeerId.FromSerialized(bs_peerIdSerialized)
                    botStoragesMap[bs_peerId] = bs_key
                    botStoragesNotReadMap[bs_peerId] = True

            elif keyType == lskType.lskPrefs:
                prefsKey = map.stream.readUInt64()

            # wallet keys (tdesktop storage_account.cpp) — 0x1F/0x20 are
            # legacy single-file keys whose payload is just the FileKey;
            # 0x21 is a counted QString -> FileKey map.
            elif keyType == lskType.lskWalletKey:
                # tdesktop then ClearKey()s the referenced file. We only
                # consume the payload: a converter must not delete files
                # out of the folder it is reading.
                self._walletLegacyKey = FileKey(map.stream.readUInt64())

            elif keyType == lskType.lskWalletEngineKey:
                self._walletEngineLegacyKey = FileKey(map.stream.readUInt64())

            elif keyType == lskType.lskWalletEngineStorages:
                # uint32 count + count x (FileKey uint64, QString key)
                count = map.stream.readUInt32()
                MapData._checkCount(
                    map.stream, count, 8 + 4, "wallet engine storages"
                )
                for i in range(count):
                    we_key = FileKey(map.stream.readUInt64())
                    we_entryKey = map.stream.readQString()
                    ExpectStreamStatus(
                        map.stream, "Could not read wallet engine storage entry"
                    )
                    walletEngineStoragesMap[we_entryKey] = we_key

            else:
                # tdesktop's reader has no default-consume path: an
                # unknown key type makes it fail the whole map read
                # (`default: return ReadMapResult::Failed`), because the
                # payload length is unknowable. fork note: we used to log
                # a warning and keep going, which left the stream 8+ bytes
                # behind the real entry boundary and parsed every
                # following map entry out of the middle of a payload.
                raise TDataBadConfigData(
                    f"Unknown key type {keyType} in encrypted map data"
                )

            ExpectStreamStatus(map.stream, "Could not stream data from mapData ")

        self.__localKey = localKey

        self._draftsMap = draftsMap
        self._draftCursorsMap = draftCursorsMap
        self._draftsNotReadMap = draftsNotReadMap

        self._locationsKey = locationsKey
        self._trustedBotsKey = trustedBotsKey
        self._recentStickersKeyOld = recentStickersKeyOld
        self._installedStickersKey = installedStickersKey
        self._featuredStickersKey = featuredStickersKey
        self._recentStickersKey = recentStickersKey
        self._favedStickersKey = favedStickersKey
        self._archivedStickersKey = archivedStickersKey
        self._savedGifsKey = savedGifsKey
        self._installedMasksKey = installedMasksKey
        self._recentMasksKey = recentMasksKey
        self._archivedMasksKey = archivedMasksKey
        self._installedCustomEmojiKey = installedCustomEmojiKey
        self._featuredCustomEmojiKey = featuredCustomEmojiKey
        self._archivedCustomEmojiKey = archivedCustomEmojiKey
        self._searchSuggestionsKey = searchSuggestionsKey
        self._webviewStorageTokenBots = webviewStorageTokenBots
        self._webviewStorageTokenOther = webviewStorageTokenOther
        self._legacyBackgroundKeyDay = legacyBackgroundKeyDay
        self._legacyBackgroundKeyNight = legacyBackgroundKeyNight
        self._settingsKey = userSettingsKey
        self._recentHashtagsAndBotsKey = recentHashtagsAndBotsKey
        self._exportSettingsKey = exportSettingsKey
        # newer Telegram Desktop map keys
        self._roundPlaceholder = roundPlaceholder
        self._inlineBotsDownloads = inlineBotsDownloads
        self._mediaLastPlaybackPositions = mediaLastPlaybackPositions
        self._botStoragesMap = botStoragesMap
        self._botStoragesNotReadMap = botStoragesNotReadMap
        self._prefsKey = prefsKey
        # fork note: keep the own-user record instead of dropping it, so a
        # load -> save round-trip does not lose it (prepareToWrite writes
        # it back). The two legacy wallet keys are dropped on purpose —
        # tdesktop reads them only to ClearKey() the referenced file and
        # never writes those entries again.
        self._selfSerialized = selfSerialized
        self._walletEngineStoragesMap = walletEngineStoragesMap
        self._oldMapVersion = mapData.version

    def prepareToWrite(self) -> td.Storage.EncryptedDescriptor:
        # Intended for internal usage only

        mapSize = 0

        # The serialized own-user record is the FIRST entry tdesktop writes
        # (storage_account.cpp, writeMap: `<< quint32(lskSelfSerialized) << self`).
        if not self._selfSerialized.isEmpty():
            mapSize += sizeof(uint32) + td.Serialize.bytearraySize(self._selfSerialized)
        if len(self._draftsMap) > 0:
            mapSize += sizeof(uint32) * 2 + len(self._draftsMap) * sizeof(uint64) * 2
        if len(self._draftCursorsMap) > 0:
            mapSize += (
                sizeof(uint32) * 2 + len(self._draftCursorsMap) * sizeof(uint64) * 2
            )
        if self._locationsKey:
            mapSize += sizeof(uint32) + sizeof(uint64)
        if self._trustedBotsKey:
            mapSize += sizeof(uint32) + sizeof(uint64)
        if self._recentStickersKeyOld:
            mapSize += sizeof(uint32) + sizeof(uint64)
        if (
            self._installedStickersKey
            or self._featuredStickersKey
            or self._recentStickersKey
            or self._archivedStickersKey
        ):
            mapSize += sizeof(uint32) + 4 * sizeof(uint64)

        if self._favedStickersKey:
            mapSize += sizeof(uint32) + sizeof(uint64)
        if self._savedGifsKey:
            mapSize += sizeof(uint32) + sizeof(uint64)
        if self._settingsKey:
            mapSize += sizeof(uint32) + sizeof(uint64)
        if self._recentHashtagsAndBotsKey:
            mapSize += sizeof(uint32) + sizeof(uint64)
        if self._exportSettingsKey:
            mapSize += sizeof(uint32) + sizeof(uint64)
        if self._installedMasksKey or self._recentMasksKey or self._archivedMasksKey:
            mapSize += sizeof(uint32) + 3 * sizeof(uint64)
        if self._installedCustomEmojiKey or self._featuredCustomEmojiKey or self._archivedCustomEmojiKey:
            mapSize += sizeof(uint32) + 3 * sizeof(uint64)
        if self._searchSuggestionsKey:
            mapSize += sizeof(uint32) + sizeof(uint64)
        # fork note: this used to be `if self._webviewStorageTokenBots or
        # ...: mapSize += sizeof(uint32) + 2 * sizeof(uint64)` — but the
        # fields were FileKeys while the wire format carries two
        # QByteArrays. Byte-count via Serialize.bytearraySize now; the
        # branch stays dead for fresh instances (both arrays empty).
        if not self._webviewStorageTokenBots.isEmpty() or not (
            self._webviewStorageTokenOther.isEmpty()
        ):
            mapSize += (
                sizeof(uint32)
                + td.Serialize.bytearraySize(self._webviewStorageTokenBots)
                + td.Serialize.bytearraySize(self._webviewStorageTokenOther)
            )
        # newer Telegram Desktop map keys
        if self._roundPlaceholder:
            mapSize += sizeof(uint32) + sizeof(uint64)
        if self._inlineBotsDownloads:
            mapSize += sizeof(uint32) + sizeof(uint64)
        if self._mediaLastPlaybackPositions:
            mapSize += sizeof(uint32) + sizeof(uint64)
        if len(self._walletEngineStoragesMap) > 0:
            mapSize += sizeof(uint32) * 2
            for we_entry_key in self._walletEngineStoragesMap:
                # uint64 FileKey + QString (uint32 byte-length + UTF-16)
                mapSize += sizeof(uint64) + sizeof(uint32) + 2 * len(we_entry_key)
        if len(self._botStoragesMap) > 0:
            mapSize += (
                sizeof(uint32) * 2 + len(self._botStoragesMap) * sizeof(uint64) * 2
            )
        if self._prefsKey:
            mapSize += sizeof(uint32) + sizeof(uint64)

        mapData = td.Storage.EncryptedDescriptor(mapSize)
        stream = mapData.stream

        # tdesktop writes the own-user record first; keep that position so
        # the byte layout matches (MapData::writeMap).
        if not self._selfSerialized.isEmpty():
            stream.writeUInt32(lskType.lskSelfSerialized)
            stream << self._selfSerialized

        if len(self._draftsMap) > 0:
            stream.writeUInt32(lskType.lskDraft)
            stream.writeUInt32(len(self._draftsMap))
            for key, value in self._draftsMap.items():
                stream.writeUInt64(value)
                stream.writeUInt64(PeerId(key).Serialize())

        if len(self._draftCursorsMap) > 0:
            stream.writeUInt32(lskType.lskDraftPosition)
            stream.writeUInt32(len(self._draftCursorsMap))
            for key, value in self._draftCursorsMap.items():
                stream.writeUInt64(value)
                stream.writeUInt64(PeerId(key).Serialize())

        if self._locationsKey:
            stream.writeUInt32(lskType.lskLocations)
            stream.writeUInt64(self._locationsKey)

        if self._trustedBotsKey:
            stream.writeUInt32(lskType.lskTrustedBots)
            stream.writeUInt64(self._trustedBotsKey)

        if self._recentStickersKeyOld:
            stream.writeUInt32(lskType.lskRecentStickersOld)
            stream.writeUInt64(self._recentStickersKeyOld)

        if (
            self._installedStickersKey
            or self._featuredStickersKey
            or self._recentStickersKey
            or self._archivedStickersKey
        ):
            stream.writeUInt32(lskType.lskStickersKeys)
            stream.writeUInt64(self._installedStickersKey)
            stream.writeUInt64(self._featuredStickersKey)
            stream.writeUInt64(self._recentStickersKey)
            stream.writeUInt64(self._archivedStickersKey)

        if self._favedStickersKey:
            stream.writeUInt32(lskType.lskFavedStickers)
            stream.writeUInt64(self._favedStickersKey)

        if self._savedGifsKey:
            stream.writeUInt32(lskType.lskSavedGifs)
            stream.writeUInt64(self._savedGifsKey)

        if self._settingsKey:
            stream.writeUInt32(lskType.lskUserSettings)
            stream.writeUInt64(self._settingsKey)

        if self._recentHashtagsAndBotsKey:
            stream.writeUInt32(lskType.lskRecentHashtagsAndBots)
            stream.writeUInt64(self._recentHashtagsAndBotsKey)

        if self._exportSettingsKey:
            stream.writeUInt32(lskType.lskExportSettings)
            stream.writeUInt64(self._exportSettingsKey)

        if self._installedMasksKey or self._recentMasksKey or self._archivedMasksKey:
            stream.writeUInt32(lskType.lskMasksKeys)
            stream.writeUInt64(self._installedMasksKey)
            stream.writeUInt64(self._recentMasksKey)
            stream.writeUInt64(self._archivedMasksKey)

        if self._installedCustomEmojiKey or self._featuredCustomEmojiKey or self._archivedCustomEmojiKey:
            stream.writeUInt32(lskType.lskCustomEmojiKeys)
            stream.writeUInt64(self._installedCustomEmojiKey)
            stream.writeUInt64(self._featuredCustomEmojiKey)
            stream.writeUInt64(self._archivedCustomEmojiKey)
        
        if self._searchSuggestionsKey:
            stream.writeUInt32(lskType.lskSearchSuggestions)
            stream.writeUInt64(self._searchSuggestionsKey)

        if not self._webviewStorageTokenBots.isEmpty() or not (
            self._webviewStorageTokenOther.isEmpty()
        ):
            stream.writeUInt32(lskType.lskWebviewTokens)
            stream << self._webviewStorageTokenBots
            stream << self._webviewStorageTokenOther

        # newer Telegram Desktop map keys
        if self._roundPlaceholder:
            stream.writeUInt32(lskType.lskRoundPlaceholder)
            stream.writeUInt64(self._roundPlaceholder)
        if self._inlineBotsDownloads:
            stream.writeUInt32(lskType.lskInlineBotsDownloads)
            stream.writeUInt64(self._inlineBotsDownloads)
        if self._mediaLastPlaybackPositions:
            stream.writeUInt32(lskType.lskMediaLastPlaybackPositions)
            stream.writeUInt64(self._mediaLastPlaybackPositions)
        if len(self._walletEngineStoragesMap) > 0:
            stream.writeUInt32(lskType.lskWalletEngineStorages)
            stream.writeUInt32(len(self._walletEngineStoragesMap))
            for we_entry_key, we_file_key in self._walletEngineStoragesMap.items():
                stream.writeUInt64(we_file_key)
                stream.writeQString(we_entry_key)
        if len(self._botStoragesMap) > 0:
            stream.writeUInt32(lskType.lskBotStorages)
            stream.writeUInt32(len(self._botStoragesMap))
            for peerId, fileKey in self._botStoragesMap.items():
                stream.writeUInt64(fileKey)
                stream.writeUInt64(PeerId(peerId).Serialize())
        if self._prefsKey:
            stream.writeUInt32(lskType.lskPrefs)
            stream.writeUInt64(self._prefsKey)

        return mapData


class StorageAccount(BaseObject):  # nocov
    """
    Storage account for reading and writing to tdata
    """

    def __init__(self, owner: Account, basePath: str, keyFile: str) -> None:
        """
        Create an instance of StorageAccount

        ### Arguments
            1. owner (Account):\n
                owner

            2. basePath (str):\n
                basePath

            3. dataName (str):\n
                dataName
        """

        self.__owner = owner
        self.__keyFile = keyFile
        self.__dataNameKey = td.Storage.ComputeDataNameKey(self.__keyFile)
        self.__baseGlobalPath = td.Storage.GetAbsolutePath(basePath)
        self.__basePath = td.Storage.PathJoin(
            self.__baseGlobalPath, td.Storage.ToFilePart(self.__dataNameKey)
        )
        self.__localKey = None

        self.__mapData = MapData(self.basePath)
        self.__config = td.MTP.Config(td.MTP.Environment.Production)
        # self.mtpData = MtpData()

    @property
    def owner(self) -> Account:
        """
        The TDesktop client that own this account
        """
        return self.__owner

    @property
    def localKey(self) -> Optional[td.AuthKey]:
        """
        The key use to encrypt/decrypt data
        """
        return self.__localKey

    @localKey.setter
    def localKey(self, value):
        # localKey setter is intended for internal usage
        self.__localKey = value

    @property
    def keyFile(self) -> str:
        return self.__keyFile

    @keyFile.setter
    def keyFile(self, value):
        self.__keyFile = value
        self.__dataNameKey = td.Storage.ComputeDataNameKey(self.__keyFile)
        self.baseGlobalPath = self.baseGlobalPath

    @property
    def baseGlobalPath(self) -> str:
        return self.__baseGlobalPath

    @baseGlobalPath.setter
    def baseGlobalPath(self, basePath):
        self.__baseGlobalPath = td.Storage.GetAbsolutePath(basePath)
        self.__basePath = td.Storage.PathJoin(
            self.__baseGlobalPath, td.Storage.ToFilePart(self.__dataNameKey)
        )

    @property
    def basePath(self) -> str:
        return self.__basePath

    @property
    def config(self) -> td.MTP.Config:
        return self.__config

    @property
    def mapData(self) -> MapData:
        return self.__mapData

    def start(self, localKey: td.AuthKey) -> td.MTP.Config:
        # Intended for internal usage only

        self.__localKey = localKey
        self.readMapWith(localKey)

        return (
            self.__config if self.owner.owner.kPerformanceMode else self.readMtpConfig()
        )

    def readMtpData(self):
        # Intended for internal usage only

        # mtp = ReadEncryptedFile(ToFilePart(self.__dataNameKey), self.__basePath, self.localKey)
        mtp = td.Storage.ReadEncryptedFile(td.Storage.ToFilePart(self.__dataNameKey), self.__baseGlobalPath, self.localKey)  # type: ignore

        # tdesktop (storage_account.cpp, Account::readMtpData) is a LOOP
        # over blocks: `while (!mtp.stream.atEnd())` reads a blockId, fails
        # the whole read on a bad stream status, and hands the block to
        # ReadSetting. fork note: this used to read exactly ONE block and
        # assume it had to be dbi.MtpAuthorization — any file carrying more
        # than one block (every legacy tgmint/tdesktop file does) lost
        # everything after the first, and a truncated stream was accepted
        # without ever checking the status.
        context = td.Storage.ReadSettingsContext()

        while not mtp.stream.atEnd():
            blockId = mtp.stream.readUInt32()
            ExpectStreamStatus(
                mtp.stream, "Could not read a block id from the mtp data"
            )

            Expects(
                td.Storage.ReadSetting(
                    blockId, mtp.stream, mtp.version, context
                ),
                TDataBadConfigData(
                    f"Could not read block {blockId} from the mtp data"
                ),
            )

        Expects(
            not context.mtpAuthorization.isEmpty(),
            TDataBadConfigData("No mtp authorization found in the mtp data"),
        )

        self.owner._setMtpAuthorization(context.mtpAuthorization)

    def readMtpConfig(self) -> td.MTP.Config:
        # Intended for internal usage only
        Expects(
            self.localKey != None,
            AccountAuthKeyNotFound("The localKey has not been initialized yet"),
        )

        try:
            file = td.Storage.ReadEncryptedFile("config", self.basePath, self.localKey)  # type: ignore
            serialized = QByteArray()
            file.stream >> serialized

            ExpectStreamStatus(file.stream, "Could not stream data from MtpConfig")

            self.__config = td.MTP.Config.FromSerialized(serialized)
            return self.__config
        except OpenTeleException:
            pass

        return td.MTP.Config(td.MTP.Environment.Production)

    def readMapWith(
        self, localKey: td.AuthKey, legacyPasscode: QByteArray = None
    ):
        # Intended for internal usage only
        if legacyPasscode is None:
            legacyPasscode = QByteArray()
        try:
            self.__mapData.read(localKey, legacyPasscode)
        except OpenTeleException:
            return False

        self.readMtpData()

    def writeMtpConfig(self, basePath: str) -> None:
        # Intended for internal usage only

        Expects(
            self.localKey != None,
            "localKey not found, have you initialized me correctly?",
        )
        Expects(basePath != None and basePath != "", "basePath can't be empty")

        serialized = self.owner.MtpConfig.Serialize()
        size = td.Serialize.bytearraySize(serialized)
        file = td.Storage.FileWriteDescriptor("config", basePath)
        data = td.Storage.EncryptedDescriptor(size)
        data.stream << serialized
        file.writeEncrypted(data, self.localKey)  # type: ignore
        file.finish()

    def writeMap(self, basePath: str) -> None:
        # Intended for internal usage only

        Expects(
            self.localKey != None,
            "localKey not found, have you initialized me correctly?",
        )
        Expects(basePath != None and basePath != "", "basePath can't be empty")

        map = td.Storage.FileWriteDescriptor("map", basePath)

        # i don't know what's the purpose of this, but it's in tdesktop source code
        map.writeData(QByteArray())
        map.writeData(QByteArray())

        mapDataEncrypted = self.mapData.prepareToWrite()
        map.writeEncrypted(mapDataEncrypted, self.localKey)  # type: ignore
        map.finish()

    def writeMtpData(self, baseGlobalPath: str, dataNameKey: int) -> None:
        # Intended for internal usage only

        Expects(
            self.localKey != None,
            "localKey not found, have you initialized me correctly?",
        )
        Expects(
            baseGlobalPath != None and baseGlobalPath != "",
            "baseGlobalPath can't be empty",
        )

        serialized = self.owner.serializeMtpAuthorization()
        size = sizeof(uint32) + td.Serialize.bytearraySize(serialized)
        mtp = td.Storage.FileWriteDescriptor(
            td.Storage.ToFilePart(dataNameKey), baseGlobalPath
        )
        data = td.Storage.EncryptedDescriptor(size)
        data.stream.writeInt32(dbi.MtpAuthorization)
        data.stream << serialized
        mtp.writeEncrypted(data, self.localKey)  # type: ignore
        mtp.finish()

    def _writeData(self, baseGlobalPath: str, keyFile: str = None) -> None:
        # Intended for internal usage only

        Expects(
            baseGlobalPath != None and baseGlobalPath != "",
            "baseGlobalPath can't be empty",
        )

        if keyFile != None and self.keyFile != keyFile:
            self.__keyFile = keyFile
            dataNameKey = td.Storage.ComputeDataNameKey(self.__keyFile)
        else:
            dataNameKey = self.__dataNameKey

        basePath = td.Storage.PathJoin(
            baseGlobalPath, td.Storage.ToFilePart(dataNameKey)
        )
        self.writeMap(basePath)

        if not self.owner.owner.kPerformanceMode:
            self.writeMtpConfig(basePath)

        self.writeMtpData(baseGlobalPath, dataNameKey)


class Account(BaseObject):
    """
    Telegram Desktop account

    ### Attributes:
        api (`API`):
            The API this acount is using.

        authKey (`AuthKey`):
            The authorization key used to authorize this acocunt.

        UserId (`int`):
            User ID of this account.

        MainDcId (`DcId`):
            The main Data Center ID this account connects to.

        basePath (`str`):
            The folder where tdata is stored.

        localKey (`AuthKey`):
            Key used to encrypt and decrypt tdata.

        owner (`TDesktop`):
            `td.TDesktop` client owner of this account.

        keyFile (`str`):
            See `td.TDesktop.keyFile`.

    """

    kWideIdsTag: int = int(~0)

    def __init__(
        self,
        owner: td.TDesktop,
        basePath: str = None,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        keyFile: str = None,
        index: int = 0,
    ) -> None:
        """
        Initialized a `TDesktop` account.

        You should use `TDesktop()` or `TDesktop.FromTelethon()` instead.
        Manually using `Account()` is not recommended. But this is here for your need anyway.

        ### Arguments:
            owner (`TDesktop`):
                `TDesktop` client owner of this account.

            basePath (`str`, default=None):
                The folder where `tdata` is stored.

            api (`API`, default=`TelegramDesktop`):
                Which API to use. Read more `[here](API)`.

            keyFile (`str`, default=None):
                See `TDesktop.keyFile`.

            index (`int`, default=0):
                Index of this account in the `TDesktop` client.

        ### Notes:
            TODO: `prepareToStart()` must be call after initalizing the object.

        """
        self.__owner = owner
        self.__localKey = None
        self.__authKey = None
        self.__telethonClient = None
        self.__isLoaded = False
        self.__isAuthorized = False
        self.__UserId = 0
        self.__MainDcId = DcId(0)

        self.__basePath = td.Storage.GetAbsolutePath(basePath)
        self.__keyFile = keyFile if (keyFile != None) else td.TDesktop.kDefaultKeyFile

        self.__mtpKeys: list[td.AuthKey] = []
        self.__mtpKeysToDestroy: list[td.AuthKey] = []
        self.api = api

        self._local = StorageAccount(
            self, self.basePath, td.Storage.ComposeDataString(self.__keyFile, index)
        )
        self.index = index

    @property
    def api(self) -> APIData:
        """
        The API this acount is using.
        """
        return self.__api

    @api.setter
    def api(self, value) -> None:
        self.__api = value
        if self.owner.api != self.api:
            self.owner.api = self.api

    @property
    def owner(self) -> td.TDesktop:
        """
        TDesktop client owner of this account.
        """
        return self.__owner

    @property
    def basePath(self) -> str:
        """
        The folder where tdata is stored.
        """
        return self.__basePath

    @property
    def keyFile(self) -> str:
        """
        See `TDesktop.keyFile`
        """
        return self.__keyFile

    @keyFile.setter
    def keyFile(self, value):
        self.__keyFile = value
        self._local.keyFile = td.Storage.ComposeDataString(value, self.index)

    @property
    def localKey(self) -> Optional[td.AuthKey]:
        """
        Key used to encrypt and decrypt tdata.
        """
        return self.__localKey

    @localKey.setter
    def localKey(self, value):
        self.__localKey = value
        self._local.localKey = value

    @property
    def authKey(self) -> Optional[td.AuthKey]:
        """
        The authorization key used to authorize this acocunt.
        """
        return self.__authKey

    @property
    def UserId(self) -> int:
        """
        User ID of this account.
        """
        return self.__UserId

    @property
    def MainDcId(self) -> DcId:
        """
        The main Data Center ID this account connects to.
        """
        return self.__MainDcId

    @property
    def MtpConfig(self) -> td.MTP.Config:
        return self._local.config

    @property
    def MapData(self) -> MapData:
        return self._local.mapData

    def isAuthorized(self) -> bool:
        return self.__isAuthorized

    def isLoaded(self) -> bool:
        return self.__isLoaded

    def start(self) -> bool:
        raise NotImplementedError()

    def prepareToStart(self, localKey: td.AuthKey) -> td.MTP.Config:
        """
        Prepare the account before starting it

        ### Arguments:
            localKey (`AuthKey`):
                `API`

        ### Returns:
            `MTP.Config`: [description]
        """

        self.__localKey = localKey
        self.__MtpConfig = self._local.start(localKey)
        return self.__MtpConfig

    def _setMtpAuthorizationCustom(
        self,
        dcId: DcId,
        userId: int,
        mtpKeys: List[td.AuthKey],
        mtpKeysToDestroy: List[td.AuthKey] = None,
    ):
        # Intended for internal usage only
        if mtpKeysToDestroy is None:
            mtpKeysToDestroy = []

        self.__MainDcId = dcId
        self.__UserId = userId
        self.__mtpKeys = mtpKeys

        for key in self.__mtpKeys:
            if key.dcId == self.MainDcId:
                self.__authKey = key
                break

        Expects(
            self.authKey != None,
            exception=TDataAuthKeyNotFound(
                "Could not find the main authKey, are you sure the data is correct?"
            ),
        )

        self.__isLoaded = True

    def _setMtpAuthorization(self, serialized: QByteArray):
        # Intended for internal usage only
        stream = QDataStream(serialized)
        stream.setVersion(QDataStream.Version.Qt_5_1)

        self.__UserId = stream.readInt32()
        self.__MainDcId = DcId(stream.readInt32())

        if ((self.__UserId << 32) | self.__MainDcId) == Account.kWideIdsTag:
            self.__UserId = stream.readUInt64()
            self.__MainDcId = DcId(stream.readInt32())

        Expects(
            stream.status() == QDataStream.Status.Ok,
            QDataStreamFailed("Could not read main fields from mtp authorization."),
        )

        def readKeys(keys: list[td.AuthKey]):

            key_count = stream.readInt32()
            Expects(
                stream.status() == QDataStream.Status.Ok,
                QDataStreamFailed("Could not read keys count from mtp authorization."),
            )

            # sanity cap — a corrupt/hostile file must not make us loop a
            # billion times (or a negative count, which range() skips
            # silently while leaving the stream misaligned)
            if key_count < 0 or key_count > 1024:
                raise TDataBadConfigData(
                    f"implausible key count {key_count} in mtp authorization"
                )

            for i in range(key_count):
                dcId = DcId(stream.readInt32())
                keys.append(
                    td.AuthKey.FromStream(stream, td.AuthKeyType.ReadFromFile, dcId)
                )
                # a truncated stream reads as empty bytes and stays "Ok" in
                # some Qt versions — check explicitly after every key
                Expects(
                    stream.status() == QDataStream.Status.Ok,
                    QDataStreamFailed(
                        "Could not read auth key from mtp authorization."
                    ),
                )

        self.__mtpKeys.clear()
        self.__mtpKeysToDestroy.clear()

        readKeys(self.__mtpKeys)
        readKeys(self.__mtpKeysToDestroy)

        for key in self.__mtpKeys:
            if key.dcId == self.MainDcId:
                self.__authKey = key
                break

        Expects(
            self.__authKey != None,
            exception=TDataAuthKeyNotFound(
                "Could not find authKey, the data might has been corrupted"
            ),
        )

        self.__isLoaded = True
        # TO BE ADDED
        # while (not mtp.stream.atEnd()):
        #     blockId = mtp.stream.readInt32()
        #     if mtp.stream.status() != 0:
        #         raise OpenTeleException(OpenTeleErrorCode.QDataStreamFailed, "Failed to stream mtpData")
        #     print(blockId)

    def serializeMtpAuthorization(self) -> QByteArray:
        # Intended for internal usage only
        Expects(self.isLoaded(), "Account data not loaded yet")

        def keysSize(list: list[td.AuthKey]):
            return 4 + len(list) * (4 + td.AuthKey.kSize)

        def writeKeys(stream: QDataStream, keys: list[td.AuthKey]):

            stream.writeInt32(len(keys))
            for key in keys:
                stream.writeInt32(key.dcId)
                stream.writeRawData(key.key)

        result = QByteArray()
        stream = QDataStream(result, QIODevice.OpenModeFlag.WriteOnly)
        stream.setVersion(QDataStream.Version.Qt_5_1)

        stream.writeInt64(Account.kWideIdsTag)
        stream.writeInt64(self.UserId)
        stream.writeInt32(self.MainDcId)

        writeKeys(stream, self.__mtpKeys)
        writeKeys(stream, self.__mtpKeysToDestroy)
        return result

    def _writeData(self, baseGlobalPath: str, keyFile: str = None) -> None:
        # Intended for internal usage only

        self._local._writeData(baseGlobalPath, keyFile)

    def SaveTData(
        self, basePath: str = None, passcode: str = None, keyFile: str = None
    ) -> None:
        """
        Save this account to a folder

        ### Arguments:
            basePath (`str`, default=`None`):
                The path to the folder. Defaults to None.

            passcode (`str`, default=`None`):
                Lock the data with a passcode. Defaults to None.

            keyFile (`str`, default=`None`):
                See `TDesktop.keyFile`

        ### Examples
            Add an account to `TDesktop` and save it to `tdata`:
        ```python
            telethonClient = TelegramClient("sessionFile", API_ID, API_HASH)
            td = TDesktop("new_tdata")
            account = Account.FromTelethon(telethonClient, owner=td) # add this account to td
            td.SaveTData()
        ```
        """

        if basePath == None:
            basePath = self.basePath

        basePath = td.Storage.GetAbsolutePath(basePath)

        if self.basePath == None:
            self.__basePath = basePath

        self.owner.SaveTData(basePath, passcode, keyFile)

    # @extend_class
    # class Account(Account):

    @typing.overload
    async def ToTelethon(
        self,
        session: Union[str, Session] = None,
        flag: Type[LoginFlag] = CreateNewSession,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: str = None,
    ) -> tl.TelegramClient:
        pass

    @typing.overload
    async def ToTelethon(
        self,
        session: Union[str, Session] = None,
        flag: Type[LoginFlag] = CreateNewSession,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: str = None,
        *,
        connection: type[Connection] = ConnectionTcpFull,
        use_ipv6: bool = False,
        proxy: Union[tuple, dict] = None,
        local_addr: Union[str, tuple] = None,
        timeout: int = 10,
        request_retries: int = 5,
        connection_retries: int = 5,
        retry_delay: int = 1,
        auto_reconnect: bool = True,
        sequential_updates: bool = False,
        flood_sleep_threshold: int = 60,
        raise_last_call_error: bool = False,
        loop: asyncio.AbstractEventLoop = None,
        base_logger: Union[str, logging.Logger] = None,
        receive_updates: bool = True,
    ) -> tl.TelegramClient:
        pass

    async def ToTelethon(
        self,
        session: Union[str, Session] = None,
        flag: Type[LoginFlag] = CreateNewSession,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: str = None,
        **kwargs,
    ) -> tl.TelegramClient:

        Expects(
            self.isLoaded(),
            TDAccountNotLoaded(
                "I'm not loaded yet, are you sure you're using me correctly?"
            ),
        )

        return await tl.TelegramClient.FromTDesktop(
            self, session=session, flag=flag, api=api, password=password, **kwargs
        )

    @staticmethod
    async def FromTelethon(
        telethonClient: tl.TelegramClient,
        flag: Type[LoginFlag] = CreateNewSession,
        api: Union[Type[APIData], APIData] = API.TelegramDesktop,
        password: str = None,
        owner: td.TDesktop = None,
    ):

        Expects(
            (flag == CreateNewSession) or (flag == UseCurrentSession),
            LoginFlagInvalid("LoginFlag invalid"),
        )

        if flag == CreateNewSession:
            if not telethonClient.is_connected():
                try:
                    await telethonClient.connect()
                except OSError as e:
                    raise TelethonUnauthorized(
                        "Could not connect telethon client to the server, please try to connect manually"
                    ) from e

                Expects(
                    await telethonClient.is_user_authorized(),
                    exception=TelethonUnauthorized(
                        "Telethon client is unauthorized, it need to be authorized first"
                    ),
                )

            copy = await telethonClient.QRLoginToNewClient(api=api, password=password)
            await copy.get_me()
        else:
            copy = telethonClient

        ss = copy.session
        authKey = ss.auth_key.key
        dcId = DcId(ss.dc_id)
        userId = copy.UserId
        authKey = td.AuthKey(authKey, td.AuthKeyType.ReadFromFile, dcId)
        
        if userId == None:
            await copy.connect()
            await copy.get_me()
            userId = copy.UserId
            
        newAccount = None

        if owner != None:

            Expects(
                owner.accountsCount < td.TDesktop.kMaxAccounts,
                exception=MaxAccountLimit(
                    f"You can't have more than {td.TDesktop.kMaxAccounts} accounts in one TDesktop clent.\n"
                    "Please create another instance of TDesktop or use Account.FromTelethon() to create an Account() independently"
                ),
            )

            index = owner.accountsCount
            newAccount = Account(
                owner=owner,
                basePath=owner.basePath,
                api=api,
                keyFile=owner.keyFile,
                index=index,
            )
            newAccount._setMtpAuthorizationCustom(dcId, userId, [authKey])  # type: ignore
            owner._addSingleAccount(newAccount)

        else:
            index = 0
            newOwner = td.TDesktop()
            newAccount = Account(owner=newOwner, api=api, index=index)
            newAccount._setMtpAuthorizationCustom(dcId, userId, [authKey])  # type: ignore
            newOwner._addSingleAccount(newAccount)

        return newAccount
