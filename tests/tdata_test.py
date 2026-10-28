from tgmint.api import API, APIData

import typing as t


def test_random_api():

    API_TYPE = t.Union[APIData, t.Type[APIData]]

    def cmp(src: API_TYPE, dst: API_TYPE) -> bool:
        return (
            src.api_id == dst.api_id
            and src.api_hash == dst.api_hash
            and src.device_model == dst.device_model
            and src.system_version == dst.system_version
            and src.app_version == dst.app_version
            and src.lang_code == dst.lang_code
            and src.system_lang_code == dst.system_lang_code
            and src.lang_pack == dst.lang_pack
        )

    apis: t.List[API_TYPE] = [
        API.TelegramDesktop,
        API.TelegramAndroid,
        API.TelegramAndroidX,
        API.TelegramIOS,
        API.TelegramMacOS,
    ]
    for api in apis:
        assert cmp(api, api())

        check = False

        for x in range(10):
            check |= not cmp(api.Generate(), api.Generate())

        assert check

    assert cmp(
        API.TelegramDesktop.Generate("windows", "opentele"),
        API.TelegramDesktop.Generate("windows", "opentele"),
    )

    assert not cmp(
        API.TelegramDesktop.Generate("windows", "opentele"),
        API.TelegramDesktop.Generate("linux", "opentele"),
    )

    assert not cmp(
        API.TelegramDesktop.Generate("macos", "opentele"),
        API.TelegramDesktop.Generate("linux", "opentele"),
    )

    assert not cmp(
        API.TelegramDesktop.Generate("windows", "opentele"),
        API.TelegramDesktop.Generate("windows", "opentele2"),
    )
