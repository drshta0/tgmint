from __future__ import annotations
import os

import platform

from collections import OrderedDict
from typing import Any, TypeVar, Union, Optional
from .devices import *
from .exception import *
from .utils import *
from .locales import pick_locale
from .layers import pick_app_version, pick_mobile_app_version

import typing


_T = TypeVar("_T")
_RT = TypeVar("_RT")


class BaseAPIMetaClass(BaseMetaClass):
    """Super high level tactic metaclass"""

    def __new__(
        cls: type[_T], clsName: str, bases: Tuple[type], attrs: dict[str, Any]
    ) -> _T:

        result = super().__new__(cls, clsName, bases, attrs)
        result._clsMakePID()  # type: ignore
        result.__str__ = BaseAPIMetaClass.__str__  # type: ignore

        return result

    @sharemethod
    def __str__(glob) -> str:

        if isinstance(glob, type):
            cls = glob
            result = f"{cls.__name__} {{\n"
        else:
            cls = glob.__class__
            result = f"{cls.__name__}() = {{\n"

        for attr, val in glob.__dict__.items():

            if (
                attr.startswith(f"_{cls.__base__.__name__}__")
                or attr.startswith(f"_{cls.__name__}__")
                or attr.startswith("__")
                and attr.endswith("__")
                or type(val) == classmethod
                or callable(val)
            ):
                continue

            result += f"    {attr}: {val}\n"

        return result + "}"


class APIData(metaclass=BaseAPIMetaClass):
    """
    API configuration to connect to `TelegramClient` and `TDesktop`

    ### Attributes:
        api_id (`int`):
            [API_ID](https://core.telegram.org/api/obtaining_api_id#obtaining-api-id)

        api_hash (`str`):
            [API_HASH](https://core.telegram.org/api/obtaining_api_id#obtaining-api-id)

        device_model (`str`):
            Device model name

        system_version (`str`):
            Operating System version

        app_version (`str`):
            Current app version

        lang_code (`str`):
            Language code of the client

        system_lang_code (`str`):
            Language code of operating system

        lang_pack (`str`):
            Language pack

    ### Methods:
        `Generate()`: Generate random device model and system version
    """

    # fork note: upstream kept a plain list here (`CustomInitConnectionList`)
    # that grew by one entry per APIData instance ever created — a leak
    # (verified: 10k instances -> 10k entries) — and findData scanned it
    # linearly. It is now an OrderedDict pid -> entry (class or instance)
    # with O(1) lookup, plus a set of pinned CLASS pids: classes are few
    # and must always resolve, so they are never evicted. Instance entries
    # are FIFO-evicted (insertion order) once they exceed _kMaxInstanceEntries.
    _pidRegistry: OrderedDict[int, Union[type[APIData], APIData]] = OrderedDict()
    _pinnedClassPids: set[int] = set()
    _instanceEntryCount: int = 0

    _kMaxInstanceEntries: int = 4096

    @classmethod
    def CustomInitConnectionList(cls) -> list[Union[type[APIData], APIData]]:
        """
        Backward-compat accessor: upstream exposed this NAME as a plain
        list attribute; it is now a classmethod returning a snapshot of
        the internal pid registry (which is bounded and dict-backed).
        Internal callers use findData()/the registry directly.
        """
        return list(cls._pidRegistry.values())

    api_id: int = None  # type: ignore
    api_hash: str = None  # type: ignore
    device_model: str = None  # type: ignore
    system_version: str = None  # type: ignore
    app_version: str = None  # type: ignore
    lang_code: str = None  # type: ignore
    system_lang_code: str = None  # type: ignore
    lang_pack: str = None  # type: ignore
    # fork addition: IANA zone for initConnection's
    # params.tz_offset — set by Generate(locale="auto") alongside the
    # coherent lang_code/system_lang_code pair; None = send no params.
    tz_zone: str = None  # type: ignore

    @typing.overload
    def __init__(self, api_id: int, api_hash: str) -> None:
        pass

    @typing.overload
    def __init__(
        self,
        api_id: int,
        api_hash: str,
        device_model: str = None,
        system_version: str = None,
        app_version: str = None,
        lang_code: str = None,
        system_lang_code: str = None,
        lang_pack: str = None,
        tz_zone: str = None,
    ) -> None:
        """
        Create your own customized API

        ### Arguments:
            api_id (`int`):
                [API_ID](https://core.telegram.org/api/obtaining_api_id#obtaining-api-id)

            api_hash (`str`):
                [API_HASH](https://core.telegram.org/api/obtaining_api_id#obtaining-api-id)

            device_model (`str`, default=`None`):
                `[Device model name](API.device_model)`

            system_version (`str`, default=`None`):
                `[Operating System version](API.system_version)`

            app_version (`str`, default=`None`):
                `[Current app version](API.app_version)`

            lang_code (`str`, default=`"en"`):
                `[Language code of the client](API.app_version)`

            system_lang_code (`str`, default=`"en"`):
                `[Language code of operating system](API.system_lang_code)`

            lang_pack (`str`, default=`""`):
                `[Language pack](API.lang_pack)`

            tz_zone (`str`, default=`None`):
                IANA zone name for `initConnection`'s `params.tz_offset`
                (`None` = send no timezone params). Part of the identity, so
                it survives `copy()` and participates in `==`/`hash()`.

        ### Warning:
            Use at your own risk!:
                Using the wrong API can lead to your account banned.
                If the session was created using an official API, you must continue using official APIs for that session.
                Otherwise that account is at risk of getting banned.
        """

    def __init__(
        self,
        api_id: int = None,
        api_hash: str = None,
        device_model: str = None,
        system_version: str = None,
        app_version: str = None,
        lang_code: str = None,
        system_lang_code: str = None,
        lang_pack: str = None,
        tz_zone: str = None,
    ) -> None:

        Expects(
            (self.__class__ != APIData) or (api_id != None and api_hash != None),
            NoInstanceMatched("No instace of API matches the arguments"),
        )

        cls = self.get_cls()

        self.api_id = api_id if api_id else cls.api_id
        self.api_hash = api_hash if api_hash else cls.api_hash
        self.device_model = device_model if device_model else cls.device_model
        self.system_version = system_version if system_version else cls.system_version
        self.app_version = app_version if app_version else cls.app_version
        self.system_lang_code = (
            system_lang_code if system_lang_code else cls.system_lang_code
        )
        self.lang_pack = lang_pack if lang_pack else cls.lang_pack
        self.lang_code = lang_code if lang_code else cls.lang_code
        # fork note: tz_zone is part of the identity (it is sent as
        # params.tz_offset), so it must be constructor-visible like every
        # other field — otherwise copy() silently demoted a minted identity
        # back to "sends no timezone".
        self.tz_zone = tz_zone if tz_zone else cls.tz_zone

        if self.device_model == None:
            system = platform.uname()

            if system.machine in ("x86_64", "AMD64"):
                self.device_model = "PC 64bit"
            elif system.machine in ("i386", "i686", "x86"):
                self.device_model = "PC 32bit"
            else:
                self.device_model = system.machine

        self._makePID()

    @sharemethod
    def copy(glob: Union[type[_T], _T] = _T) -> _T:  # type: ignore

        cls = glob if isinstance(glob, type) else glob.__class__

        return cls(
            glob.api_id,  # type: ignore
            glob.api_hash,  # type: ignore
            glob.device_model,  # type: ignore
            glob.system_version,  # type: ignore
            glob.app_version,  # type: ignore
            glob.lang_code,  # type: ignore
            glob.system_lang_code,  # type: ignore
            glob.lang_pack,  # type: ignore
            glob.tz_zone,  # type: ignore
        )  # type: ignore

    @sharemethod
    def get_cls(glob: Union[type[_T], _T]) -> type[_T]:  # type: ignore
        return glob if isinstance(glob, type) else glob.__class__

    @sharemethod
    def destroy(glob: Union[type[_T], _T]):  # type: ignore
        if isinstance(glob, type):
            return

        # fork note: intentionally does NOT deregister the instance from
        # the pid registry. The CustomInitConnectionRequest patch calls
        # data.destroy() right after every initConnection swap, while a
        # live TelegramClient may still hold that same APIData and look it
        # up by pid again — deregistering here would break those clients.
        # Instances leave the registry only via FIFO eviction (see
        # _makePID), which bounds memory without reusing pids that live
        # clients may still reference. (Class entries are pinned forever.)

    def __eq__(self, __o: APIData) -> bool:
        # fork note: upstream compared `type(__o) != APIData`, which is True
        # for every subclass *instance* — so equality was always False.
        # Compare the fingerprint fields instead (pid is random per instance).
        if not isinstance(__o, APIData):
            return NotImplemented
        return (
            self.api_id,
            self.api_hash,
            self.device_model,
            self.system_version,
            self.app_version,
            self.lang_code,
            self.system_lang_code,
            self.lang_pack,
            self.tz_zone,
        ) == (
            __o.api_id,
            __o.api_hash,
            __o.device_model,
            __o.system_version,
            __o.app_version,
            __o.lang_code,
            __o.system_lang_code,
            __o.lang_pack,
            __o.tz_zone,
        )

    def __hash__(self) -> int:
        # fork note: defining __eq__ without __hash__ made instances unhashable;
        # tz_zone is part of the identity, so it is hashed too (== and hash
        # must agree or dict/set lookups silently mix two identities)
        return hash(
            (
                self.api_id,
                self.api_hash,
                self.device_model,
                self.system_version,
                self.app_version,
                self.lang_code,
                self.system_lang_code,
                self.lang_pack,
                self.tz_zone,
            )
        )

    def __del__(self):
        self.destroy()

    @classmethod
    def _makePIDEnsure(cls) -> int:
        while True:
            pid = int.from_bytes(os.urandom(8), "little")
            if cls._pidRegistry.get(pid) is None:
                break
        return pid

    @classmethod
    def _clsMakePID(cls: type[APIData]):
        cls.pid = cls._makePIDEnsure()
        cls._pidRegistry[cls.pid] = cls
        # classes are few and looked up constantly — never evict them
        cls._pinnedClassPids.add(cls.pid)

    def _makePID(self):
        cls = self.get_cls()
        self.pid = cls._makePIDEnsure()
        cls._pidRegistry[self.pid] = self
        cls._instanceEntryCount += 1

        # bound the registry: FIFO-evict the OLDEST instance entry.
        # Pinned class entries are skipped (re-scanned cheaply — there are
        # only a handful of classes).
        while cls._instanceEntryCount > cls._kMaxInstanceEntries:
            for pid in cls._pidRegistry:
                if pid not in cls._pinnedClassPids:
                    del cls._pidRegistry[pid]
                    cls._instanceEntryCount -= 1
                    break

    @classmethod
    def Generate(cls: type[_T], unique_id: str = None, locale="auto") -> _T:
        """
        Generate random device model and system version

        ### Arguments:
            unique_id (`str`, default=`None`):
                The unique ID to generate - can be anything.\\
                This will be used to ensure that it will generate the same data everytime.\\
                If not set then the data will be randomized each time we runs it.

            locale (`str`, default=`"auto"`):
                Language realism: `"auto"` picks a coherent
                (lang_code, system_lang_code, tz_zone) triple, weighted and
                deterministic per `unique_id`; a lang_code like `"ru"`
                selects that locale directly; `None` keeps the legacy
                `en`/`en-US` defaults with no timezone.
        
        ### Raises:
            `NotImplementedError`: base `APIData` (or a preset with no device pool)

        ### Returns:
            `APIData`: Return a copy of the api with random device data

        ### Examples:
            Create a `TelegramClient` with custom API:
        ```python
            api = API.TelegramIOS.Generate(unique_id="new.session")
            client = TelegramClient(session="new.session" api=api)
            client.start()
        ```
        """
        if cls == API.TelegramAndroid or cls == API.TelegramAndroidX:
            deviceInfo = AndroidDevice.RandomDevice(unique_id)

        elif cls == API.TelegramIOS:
            deviceInfo = iOSDeivce.RandomDevice(unique_id)

        elif cls == API.TelegramMacOS:
            deviceInfo = macOSDevice.RandomDevice(unique_id)

        else:
            # (the web browser presets were removed outright:
            # their versions were unverifiable from public source by design)
            raise NotImplementedError(
                f"{cls.__name__} device not supported for randomize yet"
            )

        result = cls(device_model=deviceInfo.model, system_version=deviceInfo.version)
        return _applyLocale(result, locale, unique_id)

    @classmethod
    def findData(cls: type[_T], pid: int) -> Optional[_T]:
        # O(1) dict lookup; the entry can be a class or an instance
        return cls._pidRegistry.get(pid)


def _applyLocale(
    api: _T, locale, unique_id: Optional[str] = None
) -> _T:
    """
    Apply a coherent locale triple to a minted APIData instance.

    `locale` semantics:
        - "auto" (default in Generate): weighted, deterministic pick from
          tgmint.locales seeded by `unique_id` — the realistic option.
        - a lang_code like "ru": selects that locale's triple directly
          (unknown codes raise ValueError).
        - None/False: legacy behaviour — keep the class defaults
          ("en"/"en-US"), no timezone.

    Non-string, non-bool values (e.g. `1` or `0`) raise `ValueError` —
    they are compared by identity, since in Python `1 == True` and
    `0 == False` and silently accepting them would hide caller bugs.
    """
    if locale is None or locale is False:
        return api

    if locale is True or locale == "auto":
        triple = pick_locale(unique_id)
    else:
        from .locales import LOCALES

        matches = [t for t in LOCALES if t.lang_code == str(locale)]
        if not matches:
            raise ValueError(
                f"locale must be 'auto', None, or one of "
                f"{sorted({t.lang_code for t in LOCALES})}, got {locale!r}"
            )
        triple = matches[0]

    api.lang_code = triple.lang_code
    api.system_lang_code = triple.system_lang_code
    api.tz_zone = triple.tz_zone
    return api


def _mobileGenerate(
    cls: type[_T],
    platform: str,
    device_pool: type,
    unique_id: Optional[str],
    layer: Optional[int],
    locale,
) -> _T:
    """Shared body of the mobile presets' Generate.

    ``layer`` semantics mirror TelegramDesktop.Generate: when the caller
    says which TL layer the client will actually speak (e.g.
    ``telethon.tl.alltlobjects.LAYER`` — Telethon 1.43.2 speaks 224),
    ``app_version`` is picked from tgmint.layers' verified tables by the
    closest-lower rule instead of the newest release — e.g. layer 224
    resolves to Android ``12.3.0 (6377)``, because no Android release
    ever spoke 222-226 and the current 13.1.0 speaks 232 (the pair
    (13.1.0, 224) is impossible on a real device). ``layer=None`` keeps
    today's pinned-current behaviour; a layer below the table floor
    raises ValueError (see pick_mobile_app_version).
    """
    deviceInfo = device_pool.RandomDevice(unique_id)

    app_version = cls.app_version
    if layer is not None:
        app_version = pick_mobile_app_version(platform, int(layer), cls.app_version)

    result = cls(
        device_model=deviceInfo.model,
        system_version=deviceInfo.version,
        app_version=app_version,
    )
    return _applyLocale(result, locale, unique_id)


class API(BaseObject):
    """
    #### Built-in templates for Telegram API
    - **`tgmint`** offers the ability to use **`official APIs`**, which are used by `official apps`.
    - According to [Telegram TOS](https://core.telegram.org/api/obtaining_api_id#using-the-api-id): *all accounts that sign up or log in using unofficial Telegram API clients are automatically put under observation to avoid violations of the Terms of Service*.
    - It also uses the **[lang_pack](https://core.telegram.org/method/initConnection)** parameter, of which [telethon can't use](https://github.com/LonamiWebs/Telethon/blob/master/telethon/_client/telegrambaseclient.py#L192) because it's for official apps only.
    - Therefore, **there are no differences** between using `tgmint` and `official apps`, the server can't tell you apart.
    - You can use `TelegramClient.PrintSessions()` to check this out.

    ### Attributes:
        TelegramDesktop (`API`):
            Official Telegram for Desktop (Windows, macOS and Linux) [View on GitHub](https://github.com/telegramdesktop/tdesktop)

        TelegramAndroid (`API`):
            Official Telegram for Android [View on GitHub](https://github.com/DrKLO/Telegram)

        TelegramAndroidX (`API`):
            Official TelegramX for Android [View on GitHub](https://github.com/DrKLO/Telegram)

        TelegramIOS (`API`):
            Official Telegram for iOS [View on GitHub](https://github.com/TelegramMessenger/Telegram-iOS)

        TelegramMacOS (`API`):
            Official Telegram-Swift For MacOS [View on GitHub](https://github.com/overtake/TelegramSwift)

    ### Note:
        The web-browser presets (TelegramWeb_Z, TelegramWeb_K, Webogram)
        were removed: their versions could not be verified
        from public source by design, and stale-by-design presets are a
        detection liability.
    """

    class TelegramDesktop(APIData):
        """
        Official Telegram for Desktop (Windows, macOS and Linux)
        [View on GitHub](https://github.com/telegramdesktop/tdesktop)

        ### Attributes:
            api_id (`int`)           : `2040`
            api_hash (`str`)         : `"b18441a1ff607e10a989891a5462e627"`
            device_model (`str`)     : `"HP Pavilion 15"`
            system_version (`str`)   : `"Windows 11 x64"`
            app_version (`str`)      : `"7.3.3"`
            lang_code (`str`)        : `"en"`
            system_lang_code (`str`) : `"en-US"`
            lang_pack (`str`)        : `"tdesktop"`

        ### Methods:
            `Generate()`: Generate random device data for `Windows`, `macOS` and `Linux`

        ### Note:
            `Generate()` picks a platform-coherent `app_version`: the bare
            version on `Linux`, `"{version} x64"` on `Windows` and
            `"{version} arm64"` on Apple-Silicon `macOS` rows (bare on Intel
            macs), the way tdesktop's 64-bit builds report it.
        """

        api_id = 2040
        api_hash = "b18441a1ff607e10a989891a5462e627"
        device_model = "HP Pavilion 15"
        system_version = "Windows 11 x64"
        app_version = "7.3.3"  # refreshed 2026-10-24: live GitHub releases (via tgmint.versions fetchers)
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "tdesktop"

        @typing.overload
        @classmethod
        def Generate(
            cls: type[_T],
            system: str = None,
            unique_id: str = None,
            layer: int = None,
            locale="auto",
        ) -> _T:
            """
            Generate random TelegramDesktop devices
            ### Arguments:
                system (`str`, default=`None`):
                    Which OS to generate, either `"windows"`, `"macos"`, or `"linux"`
                    (case-insensitive).\\
                    The default is `None`, which picks one deterministically from
                    `unique_id` (and randomly when `unique_id` is also `None`).\\
                    `"random"` is the explicit spelling of that same pick — it is
                    deterministic per `unique_id`, not a per-call coin flip.\\
                    Any other value raises `ValueError` — nothing is silently
                    substituted.
            
                unique_id (`str`, default=`None`):
                    The unique ID to generate - can be anything.\\
                    This ID will be used to ensure that it will generate the same data every single time.\\
                    If not set then the data will be randomized each time we runs it.
            
                layer (`int`, default=`None`):
                    The TL layer the client will actually speak. When given,
                    `app_version` is picked from `tgmint.layers` so the
                    identity claims a release that genuinely spoke that layer
                    (e.g. `layer=224` -> `6.7.8`), NOT the newest release.
            
                locale (default=`"auto"`):
                    `"auto"` picks a coherent (lang_code, system_lang_code,
                    timezone) triple, deterministic per `unique_id`; a
                    lang_code like `"ru"` selects that locale; `None` keeps
                    the legacy `en`/`en-US` defaults with no timezone.
            
            ### Raises:
                `ValueError`: `system` is not one of `"windows"`, `"macos"`, `"linux"` (after lowercasing/trimming).

            ### Returns:
                `APIData`: Return a copy of the api with random device data
            
            ### Examples:
                Save a telethon session to tdata:
            ```python
                # unique_id will ensure that this data will always be the same (per unique_id).
                # You can use the session file name, or user_id as a unique_id.
                # If unique_id isn't specify, the device data will be randomized each time we runs it.
                oldAPI = API.TelegramDesktop.Generate(system="windows", unique_id="old.session")
                oldclient = TelegramClient("old.session", api=oldAPI)
                await oldClient.connect()

                # We can safely CreateNewSession with a different API.
                # Be aware that you should not use UseCurrentSession with a different API than the one that first authorized it.
                # You can print(newAPI) to see what it had generated.
                newAPI = API.TelegramDesktop.Generate("macos", "new_tdata")
                tdesk = oldclient.ToTDesktop(oldclient, flag=CreateNewSession, api=newAPI)

                # Save the new session to a folder named "new_tdata"
                tdesk.SaveTData("new_tdata")
            ```
            """

        @typing.overload
        @classmethod
        def Generate(
            cls: type[_T], system: str = "macos", unique_id: str = None, layer: int = None, locale="auto"
        ) -> _T:
            pass

        @typing.overload
        @classmethod
        def Generate(
            cls: type[_T], system: str = "linux", unique_id: str = None, layer: int = None, locale="auto"
        ) -> _T:
            pass

        @typing.overload
        @classmethod
        def Generate(
            cls: type[_T],
            system: str = "random",
            unique_id: str = None,
            layer: int = None,
            locale="auto",
        ) -> _T:
            pass

        @classmethod
        def Generate(
            cls: type[_T],
            system: str = None,
            unique_id: str = None,
            layer: int = None,
            locale="auto",
        ) -> _T:

            validList = ["windows", "macos", "linux"]

            # fork note: normalize BEFORE validating — upstream validated
            # first, so "Windows"/"MacOS" fell into the random-pick branch
            # and were silently replaced by a (deterministic-hash) system
            # the caller never asked for.
            system = system.lower().strip() if isinstance(system, str) else system

            if system == None or system == "random":
                # no preference — or the explicitly advertised "random"
                # wildcard, which used to raise ValueError even though the
                # overloads above document it. Same deterministic pick from
                # unique_id (random only when unique_id is None too), so
                # "random" stays reproducible per identity like the rest of
                # Generate().
                system = SystemInfo._hashtovalue(
                    SystemInfo._strtohashid(unique_id), validList
                )

            elif system not in validList:
                # fail loudly instead of silently substituting
                raise ValueError(
                    f"system must be one of {validList}, got {system!r}"
                )

            if system == "windows":
                deviceInfo = WindowsDevice.RandomDevice(unique_id)

            elif system == "macos":
                deviceInfo = macOSDevice.RandomDevice(unique_id)

            else:
                deviceInfo = LinuxDevice.RandomDevice(unique_id)

            # layer coherence: when the caller says which TL
            # layer the client will actually speak, claim an app_version
            # that really spoke that layer (tgmint.layers), NOT the newest
            # release — e.g. Telethon 1.43.2 speaks layer 224, whose
            # newest tdesktop is 6.7.8, not the current 7.x. Gap layers
            # resolve to the closest lower layer's version.
            base_version = cls.app_version
            if layer is not None:
                base_version = pick_app_version(
                    "tdesktop", int(layer), cls.app_version
                )

            # platform-coherent app_version: tdesktop's 64-bit builds append
            # the arch to the version — bare on Linux and Intel macs,
            # "x64" on Windows, "arm64" on Apple Silicon
            app_version = (
                f"{base_version} {deviceInfo.suffix}"
                if deviceInfo.suffix
                else base_version
            )

            result = cls(
                device_model=deviceInfo.model,
                system_version=deviceInfo.version,
                app_version=app_version,
            )
            return _applyLocale(result, locale, unique_id)

    class TelegramDesktopFlatpak(TelegramDesktop):
        """
        Official Telegram for Desktop as shipped by the Flathub build
        (a distinct api_id Telegram grants the Linux flatpak distribution;
        the binary's own "official api_id" whitelist is {2040, 611335,
        17349-test}).

        Verified 2026-11-01 against the installed flathub build (stable
        `7444df4f`, tdesktop commit `668a91bd`): the values are injected at
        build time via `-DTDESKTOP_API_ID` / `-DTDESKTOP_API_HASH` and are
        recorded in the app's embedded build manifest
        (`files/manifest.json`); in the stripped binary the hash sits
        plaintext at `.rodata` 0x76a1cb8 with the `0x95407` (611335)
        immediate at every use site.

        Everything else inherits from `TelegramDesktop` — same device
        pools, same `Generate()`.

        ### Attributes:
            api_id (`int`)           : `611335`
            api_hash (`str`)         : `"d524b414d21f4d37f08684c1df41ac9c"`
        """

        api_id = 611335
        api_hash = "d524b414d21f4d37f08684c1df41ac9c"

    class TelegramAndroid(APIData):
        """
        Official Telegram for Android
        [View on GitHub](https://github.com/DrKLO/Telegram)

        ### Attributes:
            api_id (`int`)           : `6`
            api_hash (`str`)         : `"eb06d4abfb49dc3eeb1aeb98ae0f581e"`
            device_model (`str`)     : `"Samsung SM-S928B"`
            system_version (`str`)   : `"SDK 35"`
            app_version (`str`)      : `"13.1.0 (7229)"`
            lang_code (`str`)        : `"en"`
            system_lang_code (`str`) : `"en-US"`
            lang_pack (`str`)        : `"android"`
        """

        api_id = 6
        api_hash = "eb06d4abfb49dc3eeb1aeb98ae0f581e"
        # NOT the pair the current APK ships. The shipped official APK
        # (13.1.1, telegram.org/dl/android/apk, BuildVars in classes.dex)
        # carries 4/"014b35b6...", but that pair is also in the public
        # DrKLO/Telegram source, and Telegram refuses it for new logins
        # from anything but the real app: auth.sendCode and
        # auth.exportLoginToken both return API_ID_PUBLISHED_FLOOD
        # (verified live 2026-11-04). The official 6/"eb06d4ab..." pair is
        # still accepted for both, so the preset uses it. Sessions the
        # real app created stay on 4 — see
        # tgmint.codec.android.OFFICIAL_APP_API_ID.
        device_model = "Samsung SM-S928B"
        system_version = "SDK 35"
        app_version = "13.1.0 (7229)"  # DrKLO wire string; "72291" is the split versionCode, not the printed build
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "android"

        @classmethod
        def Generate(
            cls: type[_T],
            unique_id: str = None,
            layer: int = None,
            locale="auto",
        ) -> _T:
            """
            Generate random Telegram for Android device data.

            ### Arguments:
                unique_id (`str`, default=`None`):
                    The unique ID to generate - can be anything.\\
                    This will be used to ensure that it will generate the same data everytime.\\
                    If not set then the data will be randomized each time we runs it.

                layer (`int`, default=`None`):
                    The TL layer the client will actually speak. When given,
                    `app_version` is picked from `tgmint.layers`' verified
                    DrKLO table by the closest-lower rule — e.g.
                    `layer=224` -> `12.3.0 (6377)` (no Android release ever
                    spoke 222-226; the current 13.1.0 speaks 232), NOT the
                    newest release. Pass the wire layer your framework
                    speaks (`telethon.tl.alltlobjects.LAYER`) for a coherent
                    identity; `None` keeps the pinned-current behaviour.
                    A layer below the table floor raises `ValueError`.

                locale (default=`"auto"`):
                    `"auto"` picks a coherent (lang_code, system_lang_code,
                    timezone) triple, deterministic per `unique_id`; a
                    lang_code like `"ru"` selects that locale; `None` keeps
                    the legacy `en`/`en-US` defaults with no timezone.

            ### Returns:
                `APIData`: Return a copy of the api with random device data
            """
            return _mobileGenerate(cls, "android", AndroidDevice, unique_id, layer, locale)

    class TelegramAndroidX(APIData):
        """
        Official TelegramX for Android
        [View on GitHub](https://github.com/DrKLO/Telegram)

        ### Attributes:
            api_id (`int`)           : `21724`
            api_hash (`str`)         : `"3e0cb5efcd52300aec5994fdfc5bdc16"`
            device_model (`str`)     : `"Google Pixel 9"`
            system_version (`str`)   : `"SDK 35"`
            app_version (`str`)      : `"0.29.1 (1817)"`
            lang_code (`str`)        : `"en"`
            system_lang_code (`str`) : `"en-US"`
            lang_pack (`str`)        : `"android"`
        """

        api_id = 21724
        api_hash = "3e0cb5efcd52300aec5994fdfc5bdc16"
        device_model = "Google Pixel 9"
        system_version = "SDK 35"
        app_version = "0.29.1 (1817)"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "android"

        @classmethod
        def Generate(
            cls: type[_T],
            unique_id: str = None,
            layer: int = None,
            locale="auto",
        ) -> _T:
            """
            Generate random Telegram X device data.

            `layer` mirrors `TelegramAndroid.Generate` — Telegram X shares
            DrKLO's TL lineage, so the same verified layer table applies;
            note the minted `app_version` is then a *mainline* version
            string (e.g. `12.3.0 (6377)`), a documented approximation for
            X's own 0.x.y scheme. `locale` wiring is identical.
            """
            return _mobileGenerate(cls, "androidx", AndroidDevice, unique_id, layer, locale)

    class TelegramIOS(APIData):
        """
        Official Telegram for iOS
        [View on GitHub](https://github.com/TelegramMessenger/Telegram-iOS)

        ### Attributes:
            api_id (`int`)           : `10840`
            api_hash (`str`)         : `"33c45224029d59cb3ad0c16134215aeb"`
            device_model (`str`)     : `"iPhone 16 Pro Max"`
            system_version (`str`)   : `"26.1"`
            app_version (`str`)      : `"13.1.1"`
            lang_code (`str`)        : `"en"`
            system_lang_code (`str`) : `"en-US"`
            lang_pack (`str`)        : `"ios"`
        """

        # api_id           = 8
        # api_hash         = "7245de8e747a0d6fbe11f7cc14fcc0bb"
        api_id = 10840
        api_hash = "33c45224029d59cb3ad0c16134215aeb"
        device_model = "iPhone 16 Pro Max"
        system_version = "26.1"
        app_version = "13.1.1"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "ios"

        @classmethod
        def Generate(
            cls: type[_T],
            unique_id: str = None,
            layer: int = None,
            locale="auto",
        ) -> _T:
            """
            Generate random Telegram for iOS device data.

            `layer` mirrors `TelegramAndroid.Generate` against the iOS
            table in `tgmint.layers` — verified first-hand only for the
            current schema (layer 232, Telegram-iOS commit 0d883288);
            the table is deliberately sparse, so a layer older than its
            floor raises `ValueError` instead of guessing. `locale`
            wiring is identical to the other presets.
            """
            return _mobileGenerate(cls, "ios", iOSDeivce, unique_id, layer, locale)

    class TelegramMacOS(APIData):
        """
        Official Telegram-Swift For MacOS
        [View on GitHub](https://github.com/overtake/TelegramSwift)

        ### Attributes:
            api_id (`int`)           : `2834`
            api_hash (`str`)         : `"68875f756c9b437a8b916ca3de215815"`
            device_model (`str`)     : `"MacBook Pro"`
            system_version (`str`)   : `"macOS 15.5"`
            app_version (`str`)      : `"11.14.1"`
            lang_code (`str`)        : `"en"`
            system_lang_code (`str`) : `"en-US"`
            lang_pack (`str`)        : `"macos"`
        """

        api_id = 2834
        api_hash = "68875f756c9b437a8b916ca3de215815"
        # api_id = 9                                    |
        # api_hash = "3975f648bb682ee889f35483bc618d1c" | Telegram for macOS uses this api, but it"s unofficial api, why?
        device_model = "MacBook Pro"
        system_version = "macOS 15.5"
        app_version = "11.14.1"
        lang_code = "en"
        system_lang_code = "en-US"
        lang_pack = "macos"



class LoginFlag(int):
    """
    Login flag for converting sessions between `TDesktop` and `TelegramClient`.

    ### Attributes:
        UseCurrentSession (LoginFlag): Use the current session.
        CreateNewSession (LoginFlag): Create a new session.

    ### Related:
        - `TDesktop.ToTelethon()`
        - `TDesktop.FromTelethon()`
        - `TelegramClient.ToTDesktop()`
        - `TelegramClient.FromTDesktop()`

    """


class UseCurrentSession(LoginFlag):
    """
    Use the current session.
    - Convert an already-logged in session of `Telegram Desktop` to `Telethon` and vice versa.
    - The "session" is just an 256-bytes `AuthKey` that get stored in `tdata folder` or Telethon `session files` [(under sqlite3 format)](https://docs.telethon.dev/en/latest/concepts/sessions.html?highlight=sqlite3#what-are-sessions).
    - `UseCurrentSession`'s only job is to read this key and convert it to one another.

    ### Warning:
        Use at your own risk!:
            You should only use the same consistant API through out the session.
            Don't use a same session with multiple different APIs, you might be banned.


    """


class CreateNewSession(LoginFlag):
    """
    Create a new session.
    - Use the `current session` to authorize the `new session` by [Login via QR code](https://core.telegram.org/api/qr-login).
    - This works just like when you signing into `Telegram` using `QR Login` on mobile devices.
    - Although `Telegram Desktop` doesn't let you authorize other sessions via `QR Code` *(or it doesn't have that feature)*, it is still available across all platforms `(``[APIs](API)``)`.

    ### Done:
        Safe to use:
            You can always use `CreateNewSessions` with any APIs, it can be different from the API that originally created the session.
    """
