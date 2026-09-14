# Changelog
All notable changes to this project will be documented in this file.

## [v1.15.1.post2] - 2026-09-14 (fork)

First release of the fork that is becoming **tgmint**. Import name is still `opentele`.

- Client fingerprint data refreshed to 2026-09 with cited sources (Telegram Desktop 7.2.8,
  Windows 11, glibc 2.35–2.41, macOS 12–26 + Apple Silicon, Android SDK 31–36, iOS ≤ 26).
- `OpenTeleException` now inherits `Exception` (was `BaseException`).
- `APIData.__eq__` compares the eight fingerprint fields (was always False); `__hash__` added.
- `opentele.td` loads lazily: PyQt5 is only required for tdata read/write (`[qt]` extra).
- Packaging: `pyproject.toml` (hatchling), `src/opentele/` layout, committed wheels removed.
- Includes upstream main's post-1.15.1 fixes (newer tdata map keys, awaitable `_on_login`).

## [v1.15](https://pypi.org/project/opentele/1.15/) - 2022-01-27

- Massive performance upgrade, UseCurrentSession is now 200x faster than before.
- `TDesktop` now has `PerformanceMode` which is enabled by default. It will now load and save tdata 200x faster.
- Huge performance boost when converting `TelegramClient` to `TDesktop`.
- Replace `inspect.stack()` with `inspect.currentframe()` in `OpenTeleException`. Using `inspect.stack()` is a stupid move, it's really slow.

## [v1.14](https://pypi.org/project/opentele/1.14/) - 2022-01-26

- `TelegramClient` will now use `TelegramDesktop` api by default.
- Fix a bug when saving tdata.

## [v1.13](https://pypi.org/project/opentele/1.13/) - 2022-01-21

- Fix `unique_id` not generated correctly in `API.Generate()`
- Added DC mismatched handling when authorizing a new client.

## [First Stable Release](https://pypi.org/project/opentele/1.13/) - 2022-01-20

- First stable release of opentele.