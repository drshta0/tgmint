"""tgmint command line — mint, inspect, audit, freshness, parity, convert,
verify, login-passkey, login-qr, profile, heal, bootstrap, cadence, doctor.

CLI v1. Zero new dependencies: argparse +
stdlib only, everything offline-safe except ``login-passkey``,
``login-qr``, ``heal --live`` and ``bootstrap`` without ``--dry-run``,
the commands that talk to Telegram (``convert``, ``profile`` and
``heal --force`` without ``--live`` stay offline).
Every command takes ``--json`` for machine-readable output; the human
format is stable but not a contract.

Exit codes (also shown in ``--help``)::

    0  success
    1  `audit` found problems in the fingerprint
    2  error: bad usage, unreadable sidecar, unknown preset/locale,
       or an optional module missing from this build (e.g. codec)

``verify`` overrides that trio with its own (documented in its
``--help``): 0 ok | 1 unreadable | 2 readable, with warnings.

Optional modules are imported lazily and probed defensively:
``tgmint.parity.describe_envelope`` (envelope builder, parallel work),
``tgmint.codec`` (session converter — ``convert_session``) and the
telethon-backed ``tgmint.tl`` / ``tgmint.passkeys`` pair used by
``login-passkey`` — the CLI must not crash when any of them is absent;
the command that needs one exits 2 with a "needs the … extra" message.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json as _json
import os
import platform
import shutil
import sys
import tempfile
import time
from typing import Any, Callable, Optional

from . import __version__
from .audit import audit_fingerprint
from .fingerprint import Fingerprint

EXIT_OK = 0
#: exit 1 belongs to `audit` ("problems found in the fingerprint") and to
#: `verify` ("unreadable" — its own trio); every other runtime failure is
#: EXIT_ERROR so a shell script can tell them apart without parsing text
EXIT_PROBLEMS = 1
EXIT_ERROR = 2

# preset name -> API.<class> (tgmint.api)
_PRESETS: dict[str, str] = {
    "desktop": "TelegramDesktop",
    "android": "TelegramAndroid",
    "android-x": "TelegramAndroidX",
    "ios": "TelegramIOS",
    "macos": "TelegramMacOS",
}

# ordered for --help; validated by argparse choices
_PRESET_ORDER = ["desktop", "android", "android-x", "ios", "macos"]

#: the platforms `tgmint bootstrap` has a source-verified sequence for
#: (mirrors tgmint.bootstrap.PLATFORMS; no import so the CLI stays light)
_BOOTSTRAP_PRESETS = ["android", "desktop"]

#: the platforms `tgmint cadence` has a source-verified keepalive for
#: (mirrors tgmint.cadence.PLATFORMS, same reason)
_CADENCE_PRESETS = ["android", "desktop"]

_CONVERT_FORMATS = [
    "telethon-session",
    "telethon-string",
    "pyrogram-session",
    "pyrogram-string",
    "gramjs-string",
    "tdata",
]

#: source formats additionally accept a `.tgmint` envelope ("profile")
#: and an official Android app data dump
#: ("android-dir"); both are readable, never
#: written by `convert`
_CONVERT_SOURCE_FORMATS = _CONVERT_FORMATS + ["profile", "android-dir"]

#: what `tgmint heal` may rewrite the session into, in place
_HEAL_FORMATS = [
    "telethon-session",
    "telethon-string",
    "pyrogram-session",
    "pyrogram-string",
    "gramjs-string",
]

_EXIT_EPILOG = "exit codes: 0 success | 1 audit found problems | 2 error"

#: `verify` documents its own exit trio in its --help: a readable session
#: with advisories is a *warning*, not the global "error" 2
_VERIFY_EPILOG = "exit codes: 0 ok | 1 unreadable | 2 readable, with warnings"

# fingerprint fields in canonical print order (all of them, incl.
# tz_zone/origin — an operator must see the whole identity)
_FIELD_ORDER = [
    "api_id",
    "api_hash",
    "device_model",
    "system_version",
    "app_version",
    "lang_code",
    "system_lang_code",
    "lang_pack",
    "tz_zone",
    "origin",
    "schema_version",
]


# ---------------------------------------------------------------------------
# small output helpers
# ---------------------------------------------------------------------------


def _print_json(payload: Any) -> None:
    """Machine-readable output. `default=str` keeps odd values printable."""
    print(_json.dumps(payload, indent=2, sort_keys=True, default=str))


def _print_fields(payload: dict[str, Any], order: list[str]) -> None:
    for key in order:
        if key in payload:
            print(f"  {key}: {payload[key]}")


def _fail(message: str) -> int:
    print(f"tgmint: {message}", file=sys.stderr)
    return EXIT_ERROR


def _is_api_id_published(exc: BaseException) -> bool:
    """True when Telegram refused the app id as published (anywhere in the chain)."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if type(exc).__name__ == "ApiIdPublishedFloodError" or any(
            marker in str(exc)
            for marker in ("API_ID_PUBLISHED_FLOOD", "API id was published")
        ):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def _login_error(what: str, exc: BaseException, preset: Optional[str] = None) -> str:
    """A login failure message, with a hint when the app id was refused."""
    message = f"{what} failed: {exc}"
    if _is_api_id_published(exc):
        message += (
            " — Telegram refuses this official app id for new logins from "
            "anything but the real app"
            + (f" (preset {preset!r})" if preset else "")
            + "; retry with a different --preset (e.g. desktop)"
        )
    return message


def _fail_json(
    args: argparse.Namespace, message: str, code: int = EXIT_ERROR
) -> int:
    """Error for a command whose failures are also machine-readable.

    The human line always goes to stderr (shell users and grep keep
    working); when ``--json`` was asked for, a
    ``{"ok": false, "command": ..., "error": ...}`` object joins it on
    stdout, so a caller parsing JSON never has to scrape stderr.
    """
    print(f"tgmint: {message}", file=sys.stderr)
    if getattr(args, "json", False):
        _print_json(
            {
                "ok": False,
                "command": getattr(args, "command", None),
                "error": message,
            }
        )
    return code


def _add_passphrase_options(parser: argparse.ArgumentParser) -> None:
    """Secrets never come from argv: an env var or stdin, never a flag.

    A passphrase on the command line lands in shell history and in the
    process list.  The two flags below are the whole menu; when neither is
    given and stdin is a terminal, the command prompts with ``getpass``.
    """
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--passphrase-env",
        metavar="VAR",
        help="read the passphrase from environment variable VAR "
        "(nothing secret on the command line)",
    )
    group.add_argument(
        "--passphrase-stdin",
        action="store_true",
        help="read the passphrase from the first line of stdin",
    )


def _resolve_passphrase(
    args: argparse.Namespace, *, purpose: str = "profile", confirm: bool = False
) -> Optional[str]:
    """Resolve the passphrase for one command; None means "none given".

    Raises ``ValueError`` (the CLI turns it into exit 2) when the chosen
    source cannot supply one.
    """
    var = getattr(args, "passphrase_env", None)
    if var:
        value = os.environ.get(var)
        if value is None:
            raise ValueError(
                f"--passphrase-env {var}: that environment variable is not set"
            )
        if not value:
            raise ValueError(f"--passphrase-env {var}: it is set but empty")
        return value
    if getattr(args, "passphrase_stdin", False):
        line = sys.stdin.readline() if sys.stdin is not None else ""
        value = line.rstrip("\r\n")
        if not value:
            raise ValueError("--passphrase-stdin: stdin gave an empty line")
        return value
    try:
        interactive = sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError):  # replaced/broken stdin
        interactive = False
    if not interactive:
        return None
    import getpass

    try:
        value = getpass.getpass(f"{purpose} passphrase (empty = none): ")
        if confirm and value:
            again = getpass.getpass("repeat passphrase: ")
            if again != value:
                raise ValueError("the two passphrases did not match")
    except (EOFError, OSError) as exc:
        raise ValueError(f"could not read a passphrase from the terminal ({exc})") from None
    return value or None


def _resolve_passcode(args: argparse.Namespace) -> Optional[str]:
    """The ``tdata`` passcode from ``--passcode-env`` (never argv).

    A folder passcode unlocks the same auth-key material a session file
    holds, so it is a secret with the same rule as a profile passphrase:
    it comes from an environment variable, never from the command line
    (argv lands in shell history and the process list).  ``None`` means
    "the flag was not given"; the caller decides whether it is needed.

    Raises ``ValueError`` (exit 2 at the CLI) when the named variable is
    unset or empty — a typo'd variable name must not read as "no passcode".
    """
    var = getattr(args, "passcode_env", None)
    if not var:
        return None
    value = os.environ.get(var)
    if value is None:
        raise ValueError(
            f"--passcode-env {var}: that environment variable is not set"
        )
    if not value:
        raise ValueError(f"--passcode-env {var}: it is set but empty")
    return value


def _load_sidecar(path: str) -> Optional[Fingerprint]:
    """Load a fingerprint sidecar, printing a clear error on failure.

    Returns None on error (the caller returns EXIT_ERROR), so a caller
    can't accidentally treat the failure as data.
    """
    try:
        return Fingerprint.load(path)
    except FileNotFoundError:
        _fail(f"{path}: no such sidecar file")
    except (ValueError, OSError, KeyError, TypeError) as exc:
        _fail(f"{path}: {exc}")
    return None


# ---------------------------------------------------------------------------
# minting (shared by `mint` and `parity`)
# ---------------------------------------------------------------------------


def _locale_value(raw: str) -> Optional[str]:
    """Translate the --locale flag into an API.Generate locale argument.

    "auto" -> "auto"; "none"/"legacy" -> None (legacy en/en-US, no tz);
    anything else must be a known lang code, else ValueError (the CLI
    turns that into exit code 2).
    """
    if raw == "auto":
        return "auto"
    if raw in ("none", "legacy"):
        return None
    from .locales import LOCALES

    codes = sorted({triple.lang_code for triple in LOCALES})
    if raw not in codes:
        raise ValueError(
            f"locale must be 'auto', 'none', or one of {codes}, got {raw!r}"
        )
    return raw


def _mint_api(
    preset: str,
    system: Optional[str] = None,
    layer: Optional[int] = None,
    unique_id: Optional[str] = None,
    locale: str = "auto",
):
    """Mint the APIData for `preset`. Raises ValueError on bad input."""
    from .api import API

    cls = getattr(API, _PRESETS[preset])
    locale_arg = _locale_value(locale)

    if preset == "desktop":
        # tdesktop's layer->version table: --layer makes the identity claim
        # a release that genuinely spoke it
        return cls.Generate(
            system=system, unique_id=unique_id, layer=layer, locale=locale_arg
        )

    if preset == "macos":
        # macOS stays pin-only (tgmint.layers has no verified macOS
        # table — the TelegramSwift source URL 404s, see layers.py), so
        # --layer is refused loudly instead of ignored or guessed from
        # invented data
        if layer is not None:
            raise ValueError(
                "--layer is not supported for the macos preset: no "
                "verified macOS layer table exists, so Generate stays "
                "pin-only (refusing beats inventing one)"
            )
        return cls.Generate(unique_id=unique_id, locale=locale_arg)

    # mobile presets have their own first-hand-verified layer tables; a
    # layer below the verified floor raises ValueError (refusing to mint
    # an impossible (app_version, layer) pair) — surfaced to the user.
    return cls.Generate(unique_id=unique_id, layer=layer, locale=locale_arg)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def _cmd_mint(args: argparse.Namespace) -> int:
    try:
        api = _mint_api(
            args.preset,
            system=args.system,
            layer=args.layer,
            unique_id=args.unique_id,
            locale=args.locale,
        )
    except (ValueError, NotImplementedError) as exc:
        return _fail(f"mint failed: {exc}")

    fp = Fingerprint.from_apidata(api)

    saved_to: Optional[str] = None
    if args.save:
        try:
            # Fingerprint.save -> sidecar.save_sidecar: temp file in the
            # same directory, fsync, atomic os.replace, mode 0600
            saved_to = str(fp.save(args.save))
        except OSError as exc:
            return _fail(f"--save {args.save} failed: {exc}")

    payload: dict[str, Any] = dict(fp.to_dict())
    payload["tz_offset"] = fp.tz_offset()
    payload["preset"] = args.preset
    if saved_to is not None:
        payload["saved_to"] = saved_to

    if args.json:
        _print_json(payload)
    else:
        print(f"minted {args.preset} fingerprint:")
        _print_fields(payload, _FIELD_ORDER)
        offset = payload["tz_offset"]
        offset_text = "not sent (no tz_zone)" if offset is None else offset
        print(f"  tz_offset: {offset_text}")
        if saved_to is not None:
            print(f"  saved_to: {saved_to}")
    return EXIT_OK


def _cmd_inspect(args: argparse.Namespace) -> int:
    fp = _load_sidecar(args.path)
    if fp is None:
        return EXIT_ERROR

    payload: dict[str, Any] = dict(fp.to_dict())
    payload["tz_offset"] = fp.tz_offset()
    payload["path"] = args.path

    if args.json:
        _print_json(payload)
    else:
        print(f"{args.path}:")
        _print_fields(payload, _FIELD_ORDER)
        offset = payload["tz_offset"]
        offset_text = "not sent (no tz_zone)" if offset is None else offset
        print(f"  tz_offset: {offset_text}")
    return EXIT_OK


def _cmd_audit(args: argparse.Namespace) -> int:
    fp = _load_sidecar(args.path)
    if fp is None:
        return EXIT_ERROR

    report = audit_fingerprint(fp)

    if args.json:
        _print_json(report)
    else:
        checks = report["checks"]
        print(f"audit of {args.path}:")
        print(f"  coherence: {checks['coherence']}")
        print(f"  tz:        {checks['tz']} ({report['tz']['detail']})")
        print(
            f"  staleness: {checks['staleness']} "
            f"({report['staleness']['detail']})"
        )
        for warning in report["warnings"]:
            print(f"warning: {warning}")
        for problem in report["problems"]:
            print(f"problem: {problem}")

    return EXIT_PROBLEMS if report["problems"] else EXIT_OK


def _cmd_freshness(args: argparse.Namespace) -> int:
    """Offline pin report — NEVER touches the network."""
    from . import versions

    cache_path = "<unknown>"
    cache_exists = False
    entries: dict[str, Any] = {}
    try:
        # versions-module helpers only: _load_cache reads a JSON file
        # (returning {} on any failure) — no fetch, no socket
        path = versions._cache_path()
        cache_path = str(path)
        cache = versions._load_cache(path)
        fetched_at = cache.get("fetched_at")
        cached_versions = cache.get("versions")
        now = time.time()
        if isinstance(cached_versions, dict) and cached_versions:
            cache_exists = True
            stamps = fetched_at if isinstance(fetched_at, dict) else {}
            for app in sorted(cached_versions):
                stamp = stamps.get(app)
                age = (
                    int(now - stamp)
                    if isinstance(stamp, (int, float))
                    else None
                )
                entries[app] = {
                    "version": cached_versions[app],
                    "age_seconds": age,
                    "fresh": (
                        age is not None
                        and 0 <= age < versions.CACHE_TTL_SECONDS
                    ),
                }
    except Exception:  # defensive: freshness must never fail the CLI
        entries = {}

    payload: dict[str, Any] = {
        "offline": True,
        "pinned": dict(versions.PINNED),
        "cache_ttl_seconds": versions.CACHE_TTL_SECONDS,
        "cache": {
            "path": cache_path,
            "exists": cache_exists,
            "entries": entries,
        },
    }

    if args.json:
        _print_json(payload)
    else:
        print("pinned app versions (offline):")
        for app in sorted(versions.PINNED):
            print(f"  {app:10} {versions.PINNED[app]}")
        state = "has entries" if cache_exists else "no cached entries"
        print(f"cache: {cache_path} ({state})")
        for app in sorted(entries):
            info = entries[app]
            age = info["age_seconds"]
            age_text = "age unknown" if age is None else f"age {age}s"
            fresh = "fresh" if info["fresh"] else "stale"
            print(
                f"  {app:10} {info['version']} ({age_text}, {fresh})"
            )
    return EXIT_OK


def _envelope_inline(api: Any, layer: Optional[int]) -> dict[str, Any]:
    """Build the initConnection envelope from a minted APIData.

    The 8 identity fields (api_id, api_hash, device_model,
    system_version, app_version, lang_code, system_lang_code, lang_pack)
    plus the computed tz_offset and the wire layer. api_hash is shown
    for completeness — it authenticates the session; it is not itself
    a serialized initConnection field.
    """
    fp = Fingerprint.from_apidata(api)
    offset = fp.tz_offset()  # computed for now, like the adapters do
    return {
        "layer": layer,
        "api_id": fp.api_id,
        "api_hash": fp.api_hash,
        "device_model": fp.device_model,
        "system_version": fp.system_version,
        "app_version": fp.app_version,
        "system_lang_code": fp.system_lang_code,
        "lang_pack": fp.lang_pack,
        "lang_code": fp.lang_code,
        "tz_offset": offset,
        "params": {"tz_offset": offset} if offset is not None else None,
    }


def _envelope_via_parity_module(
    api: Any, layer: Optional[int]
) -> Optional[dict[str, Any]]:
    """Use tgmint.parity.describe_envelope if that module exists.

    Probe defensively and fall back to the
    inline envelope on ANY failure. Never raises.
    """
    try:
        from tgmint.parity import describe_envelope
    except Exception:
        return None

    for kwargs in ({"layer": layer}, {}):
        try:
            result = describe_envelope(api, **kwargs)
        except TypeError:
            continue  # signature mismatch — try the next shape
        except Exception:
            return None  # module present but unhappy — inline fallback
        if isinstance(result, dict):
            return result
        return None
    return None


def _wire_layer(explicit: Optional[int]) -> Optional[int]:
    """The wire layer to report: the explicit ``--layer``, else ``None``.

    ``None`` is the honest answer, not a missing feature: ``parity``
    reverse-looks the layer of the minted ``app_version`` out of
    ``tgmint.layers`` (see :func:`tgmint.parity.describe_envelope`), so
    passing ``None`` lets that lookup say "unknown" when the version is
    not in a table.  Reporting telethon's own layer instead — the old
    fallback — claimed 224 for an iOS identity whose ``app_version``
    genuinely speaks 232+, i.e. it named a layer the impersonated client
    never spoke.
    """
    if explicit is not None:
        return int(explicit)
    return None


def _cmd_parity(args: argparse.Namespace) -> int:
    try:
        api = _mint_api(
            args.preset,
            system=args.system,
            layer=args.layer,
            unique_id=args.unique_id,
            locale=args.locale,
        )
    except (ValueError, NotImplementedError) as exc:
        return _fail(f"parity failed: {exc}")

    layer = _wire_layer(args.layer)
    envelope = _envelope_via_parity_module(api, layer)
    if envelope is None:
        envelope = _envelope_inline(api, layer)

    if args.json:
        _print_json(envelope)
    else:
        print("initConnection envelope (what would go on the wire):")
        for key in sorted(envelope):
            print(f"  {key}: {_json.dumps(envelope[key], default=str)}")
    return EXIT_OK


def _cmd_convert(args: argparse.Namespace) -> int:
    try:
        import tgmint.codec as codec
    except ImportError as exc:
        print(
            "tgmint: codec module not available in this build "
            f"({exc}); install a build with session-conversion support",
            file=sys.stderr,
        )
        return EXIT_ERROR

    convert = getattr(codec, "convert_session", None)
    if convert is None:
        return _fail_json(
            args,
            "codec module not available in this build "
            "(no convert_session entrypoint)",
        )

    # The passphrase source is validated whoever will read it: an unset
    # --passphrase-env is a usage error even when the source format turns
    # out not to need a passphrase (silently ignoring a flag the user
    # passed is how a typo'd variable name stays invisible), and a
    # "profile" source needs it before it can be read at all.
    passphrase = ""
    asked_for_one = bool(
        getattr(args, "passphrase_env", None)
        or getattr(args, "passphrase_stdin", False)
    )
    if args.from_format == "profile" or asked_for_one:
        try:
            passphrase = _resolve_passphrase(args, purpose="profile") or ""
        except ValueError as exc:
            return _fail_json(args, str(exc))

    # A tdata passcode is a secret like a passphrase, so it travels the
    # same way: through an environment variable, never argv.  Validated
    # whenever the flag is given (a typo'd variable name must not look
    # like "no passcode"), and only handed to the codec at all when a
    # tdata folder is one end of the conversion.
    passcode = ""
    if getattr(args, "passcode_env", None) or "tdata" in (
        args.from_format,
        args.to_format,
    ):
        try:
            passcode = _resolve_passcode(args) or ""
        except ValueError as exc:
            return _fail_json(args, str(exc))

    try:
        result = convert(
            args.from_path,
            args.from_format,
            args.to_path,
            args.to_format,
            passphrase=passphrase,
            passcode=passcode,
            variant=args.variant,
            account_index=args.account_index,
        )
    except Exception as exc:
        return _fail_json(args, f"convert failed: {exc}")

    if not isinstance(result, dict):
        return _fail_json(
            args,
            f"convert failed: codec returned {type(result).__name__}, "
            "expected a result dict",
        )

    payload = {
        "from": args.from_path,
        "from_format": args.from_format,
        "to": args.to_path,
        "to_format": args.to_format,
        "result": result,
    }
    if args.json:
        _print_json(payload)
    else:
        print(
            f"converted {args.from_path} ({args.from_format}) -> "
            f"{args.to_path} ({args.to_format})"
        )
        print(f"  dc_id: {result.get('dc_id')}")
        print(f"  output: {result.get('output')} ({result.get('output_kind')})")
        for note in result.get("notes", ()):
            print(f"  note: {note}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# verify — offline sanity check of one session / tdata folder / envelope
# ---------------------------------------------------------------------------

#: `verify` exit codes — its own trio (see the module docstring): 1 is the
#: file could not be read, 2 is "readable, with warnings" (not the global
#: "error" 2 the rest of the CLI uses)
EXIT_VERIFY_UNREADABLE = 1
EXIT_VERIFY_WARNINGS = 2

#: the SQLite half of format detection, tried before the string formats:
#: their required-column sets disambiguate them (kurigram's superset
#: schema is claimed by the pyrogram reader, which auto-detects the
#: variant; a vanilla telethon file lacks pyrogram's columns and vice
#: versa)
_VERIFY_SQLITE_ORDER = ["pyrogram-session", "telethon-session"]


def _verify_string_candidates(path: str) -> list[str]:
    """Order the string formats for a saved session-string file.

    Telethon and GramJS strings share the ``"1"`` version prefix, and a
    GramJS body whose hostname is 14 bytes long is structurally
    telethon-IPv6-shaped — the telethon reader would claim it and report
    a *wrong* auth key (the bytes it reads as the key start where the
    hostname ends).  The hostname-length field decides: in a GramJS body
    ``raw[1:3]`` equals the body length minus 261 (1 dc + 2 len + host +
    2 port + 256 key) and is 4..100.  Everything else keeps the full
    order — Telethon first (a real Telethon body's length is 263/275,
    which as a GramJS length prefix would mean a hostname of 2/14 bytes,
    and 2 is unwritable while 14 means an IPv6 starting ``::e:``, which
    no Telegram DC has).  Binary (non-UTF-8) files keep the full order
    too: every string reader refuses them quickly.
    """
    try:
        with open(path, encoding="utf-8") as fp:
            text = fp.read().strip()
        if text and text[0] == "1":
            from tgmint.codec.data import decode_b64

            raw = decode_b64(text[1:])
            host_len = int.from_bytes(raw[1:3], "big")
            if 4 <= host_len <= 100 and len(raw) == 261 + host_len:
                return ["gramjs-string"]
    except (OSError, UnicodeDecodeError, ValueError):
        pass
    return ["telethon-string", "gramjs-string", "pyrogram-string"]


def _verify_permissions(path: str) -> tuple[dict[str, Any], list[str]]:
    """Mode report + warnings for one credential path (file or tdata tree).

    A session file is a credential, so the whole path must be private:
    files 0600, a tdata directory 0700 — the modes the codec's own
    writers publish.  Only group/other access warns (``mode & 0o077``); a
    mode *stricter* than 0600 (e.g. 0400) is still private and stays
    quiet.  The chmod bits are a POSIX concept, so on other platforms the
    mode is reported but never warned about.
    """
    warnings: list[str] = []
    mode = os.stat(path).st_mode & 0o777
    if os.path.isdir(path):
        files = files_open = 0
        for root, _directories, filenames in os.walk(path):
            for name in filenames:
                member = os.path.join(root, name)
                if os.path.islink(member):
                    continue
                files += 1
                if os.name == "posix" and os.stat(member).st_mode & 0o077:
                    files_open += 1
        report: dict[str, Any] = {
            "kind": "tdata-directory",
            "mode": f"{mode:04o}",
            "files": files,
            "files_group_or_other_accessible": files_open,
        }
        if os.name == "posix":
            if mode & 0o077:
                warnings.append(
                    f"directory mode {mode:04o}: group/other can enter the "
                    f"tdata folder (chmod 700 {path})"
                )
            if files_open:
                warnings.append(
                    f"{files_open} of {files} files in the tdata folder are "
                    "group/other-accessible — the auth key sits in key_datas "
                    "(chmod 600 the files)"
                )
        return report, warnings
    report = {"kind": "file", "mode": f"{mode:04o}"}
    if os.name == "posix" and mode & 0o077:
        warnings.append(
            f"file mode {mode:04o}: group/other can access this session "
            f"file (chmod 600 {path})"
        )
    return report, warnings


def _cmd_verify(args: argparse.Namespace) -> int:
    """Open one session/tdata/envelope OFFLINE and report what it holds.

    Never touches the network and never prints the auth key — only two
    hashes of it (the MTProto ``auth_key_id``, ``sha1(key)[-8:]``, and a
    full SHA-256), so a report can be filed and compared without
    exposing the credential.  Exit codes: 0 ok | 1 unreadable |
    2 readable, with warnings (codec placeholder identity fields,
    group/world-accessible file permissions).
    """
    try:
        import tgmint.codec as codec
    except ImportError as exc:
        return _fail_json(
            args,
            f"verify needs the codec module ({exc})",
            EXIT_VERIFY_UNREADABLE,
        )

    path = args.path
    if not os.path.exists(path):
        return _fail_json(
            args, f"{path}: no such file or directory", EXIT_VERIFY_UNREADABLE
        )

    # format: an explicit --from-format wins; else detect — a directory
    # is a tdata folder, a *.tgmint name an envelope, anything else runs
    # the reader chain (SQLite pair first, then the sniffed string order)
    explicit = args.from_format
    if explicit:
        candidates = [explicit]
    elif os.path.isdir(path):
        candidates = ["tdata"]
    elif str(path).endswith(".tgmint"):
        candidates = ["profile"]
    else:
        candidates = _VERIFY_SQLITE_ORDER + _verify_string_candidates(path)
    detected = explicit is None

    # secrets are validated whenever their flag is given (a typo'd
    # variable name must not look like "none given") and resolved only
    # when a reader may want them — the same policy as `convert`
    passcode = ""
    if getattr(args, "passcode_env", None) or "tdata" in candidates:
        try:
            passcode = _resolve_passcode(args) or ""
        except ValueError as exc:
            return _fail_json(args, str(exc), EXIT_VERIFY_UNREADABLE)

    passphrase = ""
    asked_for_one = bool(
        getattr(args, "passphrase_env", None)
        or getattr(args, "passphrase_stdin", False)
    )
    if "profile" in candidates or asked_for_one:
        try:
            passphrase = _resolve_passphrase(args, purpose="profile") or ""
        except ValueError as exc:
            return _fail_json(args, str(exc), EXIT_VERIFY_UNREADABLE)

    data = None
    used_format: Optional[str] = None
    last_error: Optional[BaseException] = None
    for fmt in candidates:
        try:
            data = codec.read_session(
                path, fmt, passcode=passcode, passphrase=passphrase
            )
            used_format = fmt
            break
        except Exception as exc:  # any reader failure means "unreadable"
            last_error = exc
    if data is None:
        if len(candidates) == 1:
            detail = f"not readable as {candidates[0]} ({last_error})"
            if candidates[0] == "tdata" and not passcode:
                detail += (
                    " — if the folder has a local passcode, pass "
                    "--passcode-env VAR"
                )
        else:
            detail = (
                f"could not read this as any known session format "
                f"({last_error})"
            )
        return _fail_json(
            args, f"{path}: {detail}", EXIT_VERIFY_UNREADABLE
        )

    # hashes only — the key itself never reaches the output
    auth_key_id = hashlib.sha1(data.auth_key).digest()[-8:].hex()
    auth_key_sha256 = hashlib.sha256(data.auth_key).hexdigest()

    warnings: list[str] = []
    placeholders: list[str] = []
    if data.user_id == codec._PLACEHOLDER_USER_ID:
        placeholders.append("user_id")
        warnings.append(
            f"user_id {data.user_id} is the codec's placeholder (Telegram's "
            "service account), not this account's id — the source format "
            "stored none"
        )
    if data.api_id == codec._PLACEHOLDER_API_ID:
        placeholders.append("api_id")
        warnings.append(
            f"api_id {data.api_id} is Telegram Desktop's official app id — "
            "the codec's placeholder, not the account's real api_id"
        )
    permissions, permission_warnings = _verify_permissions(path)
    warnings.extend(permission_warnings)

    payload: dict[str, Any] = {
        "ok": True,
        "command": "verify",
        "path": path,
        "format": used_format,
        "detected": detected,
        "dc_id": data.dc_id,
        "user_id": data.user_id,
        "api_id": data.api_id,
        "test_mode": bool(data.test_mode),
        "auth_key_id": auth_key_id,
        "auth_key_sha256": auth_key_sha256,
        "placeholders": placeholders,
        "permissions": permissions,
        "warnings": warnings,
    }
    if args.json:
        _print_json(payload)
    else:
        suffix = " (detected)" if detected else ""
        print(f"{path}: {used_format}{suffix}")
        print(f"  dc_id: {data.dc_id}")
        user_text = "not stored" if data.user_id is None else data.user_id
        api_text = "not stored" if data.api_id is None else data.api_id
        print(f"  user_id: {user_text}")
        print(f"  api_id: {api_text}")
        print(f"  test_mode: {bool(data.test_mode)}")
        print(f"  auth_key_id: {auth_key_id}")
        print(f"  auth_key_sha256: {auth_key_sha256}")
        mode_text = permissions["mode"]
        if permissions["kind"] == "tdata-directory":
            mode_text += f", {permissions['files']} files"
        print(f"  permissions: {mode_text}")
        for warning in warnings:
            print(f"warning: {warning}")
        print("ok" if not warnings else f"ok, {len(warnings)} warning(s)")
    if warnings:
        return EXIT_VERIFY_WARNINGS
    return EXIT_OK


class _LoginPasskeyRefusal(Exception):
    """A refusal inside ``login-passkey`` (exit 2), not a runtime failure.

    Raised for things like an output path ``convert_session`` refuses to
    overwrite — a usage/refusal condition the user can fix, distinct from
    a login that genuinely failed (exit 1, runtime error).
    """


async def _login_passkey_flow(
    api: Any, args: argparse.Namespace, passkey_path: str
) -> dict[str, Any]:
    """Sign in over the network, then write the session in ``args.to_format``.

    Everything here is network-bound (``asyncio.run`` calls it from the
    synchronous handler). The Telethon session lives in a private temp
    directory that is removed on the way out — passkey logins are one
    step in a bridge, not a session to keep; the requested ``--to``
    output is the only artifact that survives.
    """
    import inspect

    import tgmint.codec as codec

    from . import tl as tgmint_tl
    from .passkeys import login_with_passkey

    tmpdir = tempfile.mkdtemp(prefix="tgmint-login-passkey-")
    try:
        session_path = os.path.join(tmpdir, "login.session")
        # a fresh sqlite session in a temp location: the client is born
        # with the minted fingerprint (api=APIData) and nothing else
        client = tgmint_tl.TelegramClient(session_path, api=api)
        try:
            await client.connect()
            me = await login_with_passkey(
                client,
                path=passkey_path,
                password=args.password,
                origin=args.origin,
            )
            user_id = getattr(me, "id", None)
            dc_id = getattr(client.session, "dc_id", None)
            # flush the auth key to the sqlite file BEFORE converting:
            # the conversion reads that file, not the live session
            saved = client.session.save()
            if inspect.isawaitable(saved):
                await saved
        finally:
            try:
                await client.disconnect()
            except Exception:  # already closed / never connected
                pass

        try:
            # the identity learned at login travels into the conversion:
            # without it the codec fills pyrogram/gramjs destinations with
            # the placeholder user_id 777000 / api_id 2040, which is not
            # this account's identity even though the login knew it
            converted = codec.convert_session(
                session_path,
                "telethon-session",
                args.to_path,
                args.to_format,
                user_id=user_id,
                api_id=getattr(api, "api_id", None),
            )
        except FileExistsError as exc:
            raise _LoginPasskeyRefusal(
                f"--to {args.to_path}: output already exists — "
                "convert_session never overwrites an existing session "
                f"({exc}); the login succeeded, re-run with a new --to path"
            ) from None

        if not isinstance(converted, dict):
            raise RuntimeError(
                f"codec returned {type(converted).__name__}, "
                "expected a result dict"
            )
        return {
            "user_id": user_id,
            "dc_id": dc_id,
            "converted": converted,
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _cmd_login_passkey(args: argparse.Namespace) -> int:
    """Log in with a passkey and write the session in any supported format."""
    passkey_path = args.passkey

    # --- refusals first: never open a socket for a request we can reject
    if not os.path.exists(passkey_path):
        return _fail_json(args, f"--passkey {passkey_path}: no such file")
    if not os.path.isfile(passkey_path):
        return _fail_json(
            args, f"--passkey {passkey_path}: not a regular file"
        )
    if os.path.exists(args.to_path):
        return _fail_json(
            args,
            f"--to {args.to_path}: output already exists — refusing to "
            "overwrite it (session conversion never overwrites; pick a new "
            "path or move the old one away)",
        )

    # --- the identity the new session is born with (reused, not copied:
    #     `mint`, `parity` and this command mint through _mint_api)
    try:
        api = _mint_api(
            args.preset,
            system=args.system,
            layer=args.layer,
            unique_id=args.unique_id,
            locale=args.locale,
        )
    except (ValueError, NotImplementedError) as exc:
        return _fail_json(args, f"login-passkey failed: {exc}")

    # --- optional modules: a build without telethon must fail cleanly
    try:
        import tgmint.tl  # noqa: F401
        from .passkeys import PasskeyError as _PasskeyError
        from .passkeys import PasskeyStore
    except ImportError as exc:
        return _fail_json(
            args,
            "login-passkey needs the telethon extra (tgmint.tl / "
            f"tgmint.passkeys are not importable: {exc}); install tgmint "
            "together with telethon to use this command",
        )

    # a corrupted/foreign passkey file is a refusal, not a failed login
    try:
        PasskeyStore.load(passkey_path)
    except _PasskeyError as exc:
        return _fail_json(args, f"--passkey {passkey_path}: {exc}")
    except (ValueError, KeyError, TypeError, OSError) as exc:
        return _fail_json(
            args,
            f"--passkey {passkey_path}: not a usable passkey store ({exc})",
        )

    # --- the network part
    try:
        result = asyncio.run(_login_passkey_flow(api, args, passkey_path))
    except _LoginPasskeyRefusal as exc:
        return _fail_json(args, str(exc), EXIT_ERROR)
    except ImportError as exc:
        return _fail_json(
            args,
            "login-passkey needs the passkeys extra (cryptography is "
            f"required to sign the assertion: {exc}); install tgmint's "
            "passkeys dependencies",
        )
    except Exception as exc:  # login/convert failure -> runtime error (2)
        return _fail_json(
            args, _login_error("login-passkey", exc, args.preset), EXIT_ERROR
        )

    converted = result["converted"]
    payload: dict[str, Any] = {
        "target": args.to_path,
        "to_format": args.to_format,
        "user_id": result["user_id"],
        "dc_id": result["dc_id"],
        "preset": args.preset,
        "api_id": api.api_id,
        "passkey": passkey_path,
        "conversion": converted,
    }
    if args.json:
        _print_json(payload)
    else:
        print(
            f"logged in with passkey {passkey_path} "
            f"(user_id {result['user_id']}, dc_id {result['dc_id']})"
        )
        print(f"wrote {args.to_path} ({args.to_format})")
        for note in converted.get("notes", ()):
            print(f"  note: {note}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# login-qr — mint a session by confirming a QR from your own logged-in device
# ---------------------------------------------------------------------------

class _LoginQrRefusal(Exception):
    """A refusal inside ``login-qr`` (exit 2), not a runtime failure."""


def _prompt_2fa_password() -> str:
    """Ask for the 2FA cloud password on a real terminal, refuse otherwise."""
    if not sys.stdin.isatty():
        raise _LoginQrRefusal(
            "the account has a 2FA cloud password and none was given: pass "
            "--password (the interactive prompt needs a terminal; stdin is "
            "not a tty here)"
        )
    import getpass

    password = getpass.getpass("2FA cloud password: ")
    if not password:
        raise _LoginQrRefusal("no password entered")
    return password


def _qr_render_callback(args: argparse.Namespace) -> Callable[[Any], None]:
    """What ``login-qr`` shows for every fresh token: the QR, then the URL."""
    from . import qrrender

    def render(token) -> None:
        print("Scan with the Telegram app on your phone:")
        print("  Settings > Devices > Link Desktop Device")
        print(f"(or open {token.url})")
        try:
            qr = qrrender.encode(token.url, error="M")
        except qrrender.QrTooLongError:
            print("  (URL too long for the built-in encoder; open the link)")
            return
        print(qrrender.render_text(qr.matrix, invert=args.invert))
        print(f"(valid for {token.expires_in}s; a fresh code follows expiry)")

    return render


async def _login_qr_flow(api: Any, args: argparse.Namespace) -> Dict[str, Any]:
    """Show the QR, wait for the scan, then write the session like login-passkey."""
    import inspect

    import tgmint.codec as codec

    from . import qrlogin
    from . import tl as tgmint_tl
    from .passkeys_core import TwoFactorRequired

    tmpdir = tempfile.mkdtemp(prefix="tgmint-login-qr-")
    try:
        session_path = os.path.join(tmpdir, "login.session")
        # born with the minted fingerprint, unauthorized, one connection
        client = tgmint_tl.TelegramClient(session_path, api=api)
        try:
            await client.connect()
            try:
                me = await qrlogin.login_with_qr(
                    client,
                    render=_qr_render_callback(args),
                    timeout=args.timeout,
                )
            except TwoFactorRequired:
                # the ceremony stopped on the connection it ended on (after
                # a migrate, the account's home DC): finish there
                password = args.password or _prompt_2fa_password()
                me = await qrlogin.finish_with_password(client, password)
            user_id = getattr(me, "id", None)
            dc_id = getattr(client.session, "dc_id", None)
            # flush the auth key to the sqlite file BEFORE converting: the
            # conversion reads that file, not the live session
            saved = client.session.save()
            if inspect.isawaitable(saved):
                await saved
        finally:
            try:
                await client.disconnect()
            except Exception:  # already closed / never connected
                pass

        try:
            converted = codec.convert_session(
                session_path,
                "telethon-session",
                args.to_path,
                args.to_format,
                user_id=user_id,
                api_id=getattr(api, "api_id", None),
            )
        except FileExistsError as exc:
            raise _LoginQrRefusal(
                f"--to {args.to_path}: output already exists — "
                "convert_session never overwrites an existing session "
                f"({exc}); the login succeeded, re-run with a new --to path"
            ) from None

        if not isinstance(converted, dict):
            raise RuntimeError(
                f"codec returned {type(converted).__name__}, "
                "expected a result dict"
            )
        return {
            "user_id": user_id,
            "dc_id": dc_id,
            "converted": converted,
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _cmd_login_qr(args: argparse.Namespace) -> int:
    """Log in with the QR code and write the session in any supported format."""
    # --- refusals first: never open a socket for a request we can reject
    if os.path.exists(args.to_path):
        return _fail_json(
            args,
            f"--to {args.to_path}: output already exists — refusing to "
            "overwrite it (session conversion never overwrites; pick a new "
            "path or move the old one away)",
        )

    # --- the identity the new session is born with
    try:
        api = _mint_api(
            args.preset,
            system=args.system,
            layer=args.layer,
            unique_id=args.unique_id,
            locale=args.locale,
        )
    except (ValueError, NotImplementedError) as exc:
        return _fail_json(args, f"login-qr failed: {exc}")

    # --- optional modules: a build without telethon must fail cleanly
    try:
        import tgmint.tl  # noqa: F401
        from . import qrlogin  # noqa: F401
        from . import qrrender  # noqa: F401
    except ImportError as exc:
        return _fail_json(
            args,
            "login-qr needs the telethon extra (tgmint.tl / tgmint.qrlogin "
            f"are not importable: {exc}); install tgmint together with "
            "telethon to use this command",
        )

    # --- the network part (interactive: the QR must be scanned)
    try:
        result = asyncio.run(_login_qr_flow(api, args))
    except _LoginQrRefusal as exc:
        return _fail_json(args, str(exc), EXIT_ERROR)
    except TimeoutError as exc:
        return _fail_json(args, f"login-qr: {exc}", EXIT_ERROR)
    except Exception as exc:  # login/convert failure -> runtime error (2)
        return _fail_json(
            args, _login_error("login-qr", exc, args.preset), EXIT_ERROR
        )

    converted = result["converted"]
    payload: Dict[str, Any] = {
        "target": args.to_path,
        "to_format": args.to_format,
        "user_id": result["user_id"],
        "dc_id": result["dc_id"],
        "preset": args.preset,
        "api_id": api.api_id,
        "conversion": converted,
    }
    if args.json:
        _print_json(payload)
    else:
        print(
            f"logged in with the scanned QR "
            f"(user_id {result['user_id']}, dc_id {result['dc_id']})"
        )
        print(f"wrote {args.to_path} ({args.to_format})")
        for note in converted.get("notes", ()):
            print(f"  note: {note}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# profile — the portable identity envelope (.tgmint)
# ---------------------------------------------------------------------------


def _cmd_profile_seal(args: argparse.Namespace) -> int:
    """Bundle session + fingerprint + passkey into one (optionally sealed) file."""
    try:
        import tgmint.codec as codec
        from tgmint import profile as profile_module
        from tgmint.sidecar import sidecar_path_for
    except ImportError as exc:  # pragma: no cover - defensive
        return _fail_json(args, f"profile seal needs the codec and profile modules ({exc})")

    out = args.out
    if os.path.exists(out) or os.path.islink(out):
        return _fail_json(
            args,
            f"--out {out}: output already exists — refusing to overwrite it "
            "(pick a new path or move the old one away)",
        )

    fmt = args.from_format
    # The passphrase is resolved BEFORE the read, because a "profile"
    # source may itself be sealed: reading it needs that passphrase, and
    # the same one seals the envelope we write back, so re-sealing a
    # sealed profile works instead of telling the user to pass a
    # passphrase they just passed.
    try:
        passphrase = _resolve_passphrase(args, purpose="profile seal", confirm=True)
    except ValueError as exc:
        return _fail_json(args, str(exc))

    # an envelope source is re-sealed as the format it records, keeping
    # the identity and the passkey it carries unless the flags override
    # them: the only way re-sealing a sealed profile can work at all
    opened = None
    try:
        if fmt in codec.PROFILE_FORMATS:
            opened = profile_module.open_profile(
                args.session, passphrase=passphrase or None
            )
            session = opened.session
            seal_format = opened.session_format or "telethon-string"
        else:
            session = codec.read_session(
                args.session, fmt, passphrase=passphrase or ""
            )
            seal_format = fmt
    except FileNotFoundError as exc:
        return _fail_json(args, f"--session {args.session}: {exc}")
    except Exception as exc:
        return _fail_json(args, f"--session {args.session}: {exc}")

    # the recorded identity: explicit --fingerprint wins, then the envelope
    # being re-sealed, then the session's own sidecar (sticky identity)
    # when one exists
    fingerprint = None
    fingerprint_path: Optional[str] = args.fingerprint
    fingerprint = opened.fingerprint if opened is not None else None
    if fingerprint_path is None and fingerprint is None:
        candidate = sidecar_path_for(args.session)
        if os.path.isfile(str(candidate)):
            fingerprint_path = str(candidate)
    if fingerprint_path:
        try:
            fingerprint = Fingerprint.load(fingerprint_path)
        except FileNotFoundError:
            return _fail_json(
                args, f"--fingerprint {fingerprint_path}: no such sidecar file"
            )
        except (ValueError, OSError, KeyError, TypeError) as exc:
            return _fail_json(args, f"--fingerprint {fingerprint_path}: {exc}")

    passkey = opened.passkey if opened is not None else None
    if args.passkey:
        if not os.path.isfile(args.passkey):
            return _fail_json(args, f"--passkey {args.passkey}: no such file")
        try:
            with open(args.passkey, encoding="utf-8") as fp:
                passkey = _json.load(fp)
        except (OSError, ValueError) as exc:
            return _fail_json(
                args, f"--passkey {args.passkey}: not a passkey store ({exc})"
            )

    try:
        container = profile_module.seal(
            session,
            seal_format,
            fingerprint=fingerprint,
            passkey=passkey,
            passphrase=passphrase,
            note=args.note or "",
        )
        profile_module.write_profile(container, out)
    except FileExistsError as exc:
        return _fail_json(args, str(exc))
    except ValueError as exc:  # ProfileError is a CodecError is a ValueError
        return _fail_json(args, f"profile seal failed: {exc}")
    except OSError as exc:  # unreadable dir, full disk, permissions
        return _fail_json(args, f"profile seal failed: {exc}")

    if passkey is not None and not passphrase:
        print(
            "tgmint: warning: this profile is not sealed, so the passkey's "
            "private key sits in it in plaintext — pass a passphrase (or "
            "keep this file as safe as the passkey itself)",
            file=sys.stderr,
        )

    payload: dict[str, Any] = {
        "ok": True,
        "command": "profile seal",
        "out": out,
        "sealed": bool(passphrase),
        "session": args.session,
        "source_format": fmt,
        "session_format": seal_format,
        "dc_id": session.dc_id,
        "user_id": session.user_id,
        "fingerprint": fingerprint_path,
        "passkey": args.passkey,
        "note": args.note or "",
    }
    if args.json:
        _print_json(payload)
    else:
        state = "sealed with a passphrase" if passphrase else "plaintext"
        print(f"wrote {out} ({state})")
        print(f"  session_format: {seal_format}")
        print(f"  dc_id: {session.dc_id}")
        print(f"  user_id: {session.user_id}")
        print(f"  fingerprint: {fingerprint_path or 'none'}")
        print(f"  passkey: {args.passkey or 'none'}")
    return EXIT_OK


def _cmd_profile_open(args: argparse.Namespace) -> int:
    """Open a profile and write its session out in any codec format."""
    try:
        import tgmint.codec as codec
        from tgmint import profile as profile_module
    except ImportError as exc:  # pragma: no cover - defensive
        return _fail_json(args, f"profile open needs the codec and profile modules ({exc})")

    try:
        passphrase = _resolve_passphrase(args, purpose="profile")
    except ValueError as exc:
        return _fail_json(args, str(exc))

    try:
        summary = profile_module.inspect_profile(args.profile, passphrase=passphrase)
    except FileNotFoundError as exc:
        return _fail_json(args, str(exc))
    except ValueError as exc:
        # ProfileError messages already name the file
        return _fail_json(args, str(exc))

    if os.path.exists(args.to_path) or os.path.islink(args.to_path):
        return _fail_json(
            args,
            f"--to {args.to_path}: output already exists — refusing to "
            "overwrite it (session conversion never overwrites; pick a new "
            "path or move the old one away)",
        )

    try:
        converted = codec.convert_session(
            args.profile,
            "profile",
            args.to_path,
            args.to_format,
            passphrase=passphrase or "",
        )
    except FileExistsError as exc:
        return _fail_json(args, str(exc))
    except Exception as exc:
        return _fail_json(args, f"profile open failed: {exc}")

    payload: dict[str, Any] = {
        "ok": True,
        "command": "profile open",
        "profile": args.profile,
        "to": args.to_path,
        "to_format": args.to_format,
        "sealed": summary["sealed"],
        "summary": summary,
        "conversion": converted,
    }
    if args.json:
        _print_json(payload)
    else:
        print(f"opened {args.profile}")
        print(f"  session_format: {summary['session_format']}")
        print(f"  dc_id: {summary['dc_id']}")
        print(f"  user_id: {summary['user_id']}")
        print(f"wrote {args.to_path} ({args.to_format})")
        for note in converted.get("notes", ()):
            print(f"  note: {note}")
    return EXIT_OK


def _cmd_profile_inspect(args: argparse.Namespace) -> int:
    """JSON summary of a profile: formats, identity, passkey, sealed or not."""
    try:
        from tgmint import profile as profile_module
    except ImportError as exc:  # pragma: no cover - defensive
        return _fail_json(args, f"profile inspect needs the profile module ({exc})")

    try:
        passphrase = _resolve_passphrase(args, purpose="profile")
    except ValueError as exc:
        return _fail_json(args, str(exc))

    try:
        summary = profile_module.inspect_profile(args.profile, passphrase=passphrase)
    except FileNotFoundError as exc:
        return _fail_json(args, str(exc))
    except ValueError as exc:
        # ProfileError messages already name the file
        return _fail_json(args, str(exc))

    if args.json:
        _print_json(summary)
        return EXIT_OK

    if summary["sealed"]:
        print(
            f"{summary['path']} [{summary['format']}] sealed "
            f"({summary.get('kdf')}, {summary.get('iterations')} iterations)"
        )
    else:
        print(f"{summary['path']} [{summary['format']}] plaintext")
    if summary["locked"]:
        print(
            "  locked: a passphrase is required to read the contents "
            "(use --passphrase-env VAR or --passphrase-stdin)"
        )
        return EXIT_OK
    print(f"  session_format: {summary['session_format']}")
    print(f"  dc_id: {summary['dc_id']}")
    print(f"  user_id: {summary['user_id']}")
    fp = summary["fingerprint"] or {}
    if fp:
        print(
            f"  fingerprint: api_id {fp.get('api_id')}, "
            f"{fp.get('device_model')}, {fp.get('app_version')} "
            f"(origin {fp.get('origin')})"
        )
    else:
        print("  fingerprint: none")
    passkey = summary["passkey"]
    if passkey:
        print(
            f"  passkey: yes ({passkey.get('name')}, "
            f"user_handle {passkey.get('user_handle')}, "
            f"sign_count {passkey.get('sign_count')})"
        )
    else:
        print("  passkey: none")
    meta = summary.get("meta") or {}
    if meta:
        print(f"  created: {meta.get('created')} (tgmint {meta.get('tgmint')})")
        if meta.get("note"):
            print(f"  note: {meta['note']}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# heal — session repair with the passkey
# ---------------------------------------------------------------------------


def _heal_source_format(args: argparse.Namespace) -> str:
    """The source format heal will read: ``--from-format``, else inferred.

    Inferred with the codec when the build has it, else with the same
    ``.tgmint`` suffix rule — the passphrase prompt below must not appear
    for a plain session, so this decision cannot wait for the read.
    """
    if args.from_format:
        return args.from_format
    try:
        import tgmint.codec as codec

        return codec.infer_source_format(args.session)
    except Exception:  # pragma: no cover - codec absent in this build
        return "profile" if str(args.session).endswith(".tgmint") else "telethon-session"


def _cmd_heal(args: argparse.Namespace) -> int:
    """Probe one session and, when its auth key is dead, re-login + rewrite."""
    from .heal import HealRefusal, heal_session

    if not os.path.exists(args.session):
        return _fail_json(args, f"SESSION {args.session}: no such file")
    if not os.path.isfile(args.passkey):
        return _fail_json(args, f"--passkey {args.passkey}: no such file")

    try:
        if importlib.util.find_spec("telethon") is None:  # pragma: no cover
            raise ImportError("telethon is not installed")
    except ImportError as exc:
        return _fail_json(
            args,
            "heal needs the telethon extra (tgmint.tl / tgmint.passkeys are "
            f"not usable: {exc}); install tgmint together with telethon",
        )

    # a passphrase only means something for a sealed .tgmint envelope; a
    # plain session must not prompt for one (bootstrap gates the same way)
    source_format = _heal_source_format(args)
    try:
        if source_format in ("profile",) or getattr(args, "passphrase_env", None) or getattr(
            args, "passphrase_stdin", False
        ):
            passphrase = _resolve_passphrase(args, purpose="profile")
        else:
            passphrase = None
    except ValueError as exc:
        return _fail_json(args, str(exc))

    try:
        report = asyncio.run(
            heal_session(
                args.session,
                passkey_path=args.passkey,
                session_format=args.from_format,
                to_format=args.to_format,
                out=args.out,
                api_preset=args.api_preset,
                passphrase=passphrase,
                password=args.password,
                live=args.live,
                force=args.force,
            )
        )
    except FileNotFoundError as exc:
        return _fail_json(args, str(exc))
    except HealRefusal as exc:
        return _fail_json(args, str(exc), EXIT_ERROR)
    except Exception as exc:  # HealError included
        return _fail_json(args, _login_error("heal", exc), EXIT_ERROR)

    payload: dict[str, Any] = {
        "ok": True,
        "command": "heal",
        "session": report["session"],
        "session_format": report["session_format"],
        "to_format": report["to_format"],
        "output": report.get("output"),
        "in_place": report.get("in_place"),
        "filled": report.get("filled", []),
        "action": report["action"],
        "passkey": report["passkey"],
        "probe": report["probe"],
        "identity": report["identity"],
        "old": report["old"],
        "new": report["new"],
        "auth_key_changed": report["auth_key_changed"],
        "notes": report.get("notes", []),
    }
    if args.json:
        _print_json(payload)
    else:
        probe = report["probe"]
        if report["action"] == "noop":
            print(
                f"{report['session']}: alive, nothing changed "
                f"(user_id {report['old']['user_id']}, "
                f"dc_id {report['old']['dc_id']})"
            )
            print(f"  probe: {probe.get('reason')}")
        else:
            print(
                f"{report['session']}: healed with passkey {report['passkey']} "
                f"(user_id {report['old']['user_id']} -> "
                f"{report['new']['user_id']}, dc_id {report['old']['dc_id']} -> "
                f"{report['new']['dc_id']})"
            )
            print(f"  rewrote: {report['output']} ({report['to_format']})")
            if not report.get("in_place", True):
                print(f"  in place: no — the source session was left untouched")
            print(f"  identity: {report['identity']['source']}")
            if probe.get("performed"):
                print(f"  probe: {probe.get('reason')}")
        for note in report.get("notes", ()):
            print(f"  note: {note}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# bootstrap — opt-in replay of the official post-auth startup batch
# ---------------------------------------------------------------------------


def _bootstrap_platform(args: argparse.Namespace) -> str:
    """Resolve ``--preset`` (``auto`` included) to a platform key.

    An explicit ``--preset android|desktop`` wins.  ``auto`` reads the
    fingerprint sidecar recorded next to the session (`tgmint mint --save`'s
    sticky identity) and asks :func:`tgmint.bootstrap.platform_for` which
    family it belongs to, so a session that already carries an identity
    does not need the platform spelled out twice.

    Raises ``BootstrapError`` (exit 2 from the command) when nothing
    names a family.
    """
    from .bootstrap import BootstrapError, platform_for

    preset = getattr(args, "preset", "auto")
    if preset in ("android", "desktop"):
        return preset

    session = getattr(args, "session", None)
    if not session:
        raise BootstrapError(
            "cannot infer the platform: no --session to read an identity "
            "from (--dry-run --preset android|desktop only needs the preset)"
        )
    try:
        from .sidecar import sidecar_path_for

        path = str(sidecar_path_for(session))
    except Exception as exc:  # pragma: no cover - sidecar is in the package
        raise BootstrapError(f"cannot infer the platform: {exc}") from None
    if not os.path.isfile(path):
        raise BootstrapError(
            f"cannot infer the platform: no fingerprint sidecar at {path}; "
            "pass --preset android|desktop"
        )
    try:
        from .fingerprint import Fingerprint

        fingerprint = Fingerprint.load(path)
    except (ValueError, OSError, KeyError) as exc:
        raise BootstrapError(f"{path}: not a usable fingerprint ({exc})") from None
    return platform_for(fingerprint)


#: which ``--api-preset`` values are consistent with each replay platform
#: (an android replay presenting a desktop identity is exactly the kind of
#: incoherence tgmint exists to avoid)
_PLATFORM_API_PRESETS: dict[str, tuple] = {
    "android": ("android", "android-x"),
    "desktop": ("desktop",),
}


def _bootstrap_recorded_fingerprint(session: Optional[str]):
    """The sidecar identity recorded next to ``session`` -> (fp, path|None).

    ``(None, None)`` when there is no session or no sidecar: only then may
    a replay mint a fresh identity.
    """
    if not session:
        return None, None
    from .bootstrap import BootstrapError

    try:
        from .sidecar import sidecar_path_for

        path = str(sidecar_path_for(session))
    except Exception:  # pragma: no cover - sidecar is in the package
        return None, None
    if not os.path.isfile(path):
        return None, None
    try:
        return Fingerprint.load(path), path
    except (ValueError, OSError, KeyError, TypeError) as exc:
        raise BootstrapError(f"{path}: not a usable fingerprint ({exc})") from None


def _bootstrap_api(platform: str, api_preset: Optional[str], session: Optional[str] = None):
    """The identity the live replay presents -> ``(api, identity)``.

    The *recorded* identity (the session's fingerprint sidecar) wins,
    because Telegram remembers the device a session signed in with and a
    replay is supposed to look like that same client continuing to use its
    own account; a fresh identity is minted only when nothing was
    recorded.  ``identity`` is the report dict (``source``/``path``).

    Raises:
        BootstrapError: ``--api-preset`` names a family the replay
            platform cannot be (an android replay is never a desktop
            client), or the recorded identity belongs to another family.
        ValueError: an unknown preset (unreachable through argparse).
    """
    from .api import API
    from .bootstrap import BootstrapError, platform_for

    allowed = _PLATFORM_API_PRESETS.get(platform, (platform,))
    if api_preset is not None and api_preset not in allowed:
        raise BootstrapError(
            f"--api-preset {api_preset} does not match the {platform} replay "
            f"(a {platform} client presents one of {list(allowed)}); drop "
            "--api-preset to use the recorded identity, or change --preset "
            "to the platform you meant"
        )

    fingerprint, recorded_path = _bootstrap_recorded_fingerprint(session)
    if fingerprint is not None:
        recorded_platform = platform_for(fingerprint)
        if recorded_platform != platform:
            raise BootstrapError(
                f"{recorded_path}: the recorded identity is a "
                f"{recorded_platform} one, but this replay is {platform}; "
                "refusing to present an identity from another client family "
                "(move the sidecar away, or replay the family it records)"
            )
        # reused, not copied: heal builds the same APIData for the same
        # reason (present the identity the session was born with)
        from .heal import _api_from_fingerprint

        return _api_from_fingerprint(fingerprint), {
            "source": "recorded",
            "path": recorded_path,
        }

    name = _PRESETS.get(api_preset or platform)
    if name is None:
        raise ValueError(
            f"unknown api preset {api_preset!r}; expected one of {_PRESET_ORDER}"
        )
    return getattr(API, name).Generate(), {"source": "minted", "path": None}


def _bootstrap_failure(args: argparse.Namespace, exc: BootstrapError) -> int:
    """Report a fatal replay failure *and* what actually got sent.

    The replay attaches its partial report to the error
    (:func:`tgmint.bootstrap._fatal_error`); a caller that only saw "the
    replay failed" would have to guess which steps reached Telegram, so
    the partial report goes out with the error in --json mode.
    """
    report = getattr(exc, "report", None)
    if not report:
        return _fail_json(args, str(exc), EXIT_ERROR)
    print(f"tgmint: {exc}", file=sys.stderr)
    if getattr(args, "json", False):
        _print_json(
            {
                "ok": False,
                "command": getattr(args, "command", None),
                "error": str(exc),
                "stopped_at": getattr(exc, "stopped_at", None),
                "partial_report": report,
            }
        )
    return EXIT_ERROR


async def _bootstrap_replay(client, *, platform: str, include_cosmetic: bool) -> dict[str, Any]:
    """Connect, replay the startup batch, disconnect (always)."""
    from .bootstrap import replay_startup

    try:
        await client.connect()
        return await replay_startup(
            client, platform=platform, include_cosmetic=include_cosmetic
        )
    finally:
        try:
            await client.disconnect()
        except Exception:  # pragma: no cover - best effort teardown
            pass


def _cmd_cadence(args: argparse.Namespace) -> int:
    """Print the official keepalive cadence next to what a framework can set."""
    try:
        from .cadence import PLATFORMS, CadenceError, describe
    except ImportError as exc:  # pragma: no cover - defensive
        return _fail_json(args, f"cadence needs the cadence module ({exc})")

    presets = [args.preset] if getattr(args, "preset", None) else list(PLATFORMS)
    try:
        reports = [describe(preset) for preset in presets]
    except CadenceError as exc:
        return _fail_json(args, str(exc), EXIT_ERROR)

    if args.json:
        _print_json({"ok": True, "command": "cadence", "presets": reports})
        return EXIT_OK

    for position, report in enumerate(reports):
        if position:
            print()
        official = report["official"]
        print(
            f"{report['platform']}: Telegram "
            f"{report['platform'].capitalize()} {report['client_version']} sends "
            f"ping_delay_disconnect every {official['ping_interval']:g}s, "
            f"disconnect_delay {official['disconnect_delay']}s"
        )
        print(f"  source: {official['source']}")
        for framework, knobs in report["frameworks"].items():
            ping = knobs["ping_interval"]
            delay = knobs["disconnect_delay"]
            default = ping["framework_default"]
            now = f"{default:g}s" if default is not None else "never"
            applied = ping.get("applied_value", official["ping_interval"])
            how = (
                f" -> {applied:g}s via {ping['attribute']}"
                if ping["settable"]
                else " (not settable)"
            )
            print(f"  {framework:<8} ping {now}{how}")
            if ping.get("socket_read_timeout") is not None:
                print(
                    f"  {'':<8} socket read timeout 10s -> "
                    f"{ping['socket_read_timeout']:g}s (the framework's own "
                    "read timeout, not the server)"
                )
            shipped = delay["framework_default"]
            shipped = f"{shipped:g}s" if shipped is not None else "never sent"
            verdict = "settable" if delay["settable"] else "not settable"
            print(f"  {'':<8} disconnect_delay {shipped} ({verdict})")
    print()
    print(
        "plan only: nothing is applied here. tgmint.cadence.apply(client, "
        "platform) sets what a framework allows, in-process."
    )
    return EXIT_OK


def _cmd_bootstrap(args: argparse.Namespace) -> int:
    """Print the plan (--dry-run) or replay it against one live session."""
    try:
        from .bootstrap import BootstrapError, describe, replay_startup
    except ImportError as exc:  # pragma: no cover - defensive
        return _fail_json(args, f"bootstrap needs the bootstrap module ({exc})")

    include_cosmetic = bool(getattr(args, "include_cosmetic", False))

    # live mode is the only mode that needs a session, and saying so is a
    # better error than "cannot infer the platform"
    if not args.dry_run and not getattr(args, "session", None):
        return _fail_json(
            args,
            "bootstrap without --dry-run needs a session: pass --session PATH "
            "(or --dry-run to only print the plan)",
            EXIT_ERROR,
        )

    try:
        platform = _bootstrap_platform(args)
    except BootstrapError as exc:
        return _fail_json(args, str(exc), EXIT_ERROR)
    except Exception as exc:  # pragma: no cover - defensive
        return _fail_json(args, f"bootstrap failed: {exc}", EXIT_ERROR)

    try:
        info = describe(platform, include_cosmetic=include_cosmetic)
    except BootstrapError as exc:
        return _fail_json(args, str(exc), EXIT_ERROR)

    if args.dry_run:
        # no session, no client, no socket: the plan only
        try:
            report = asyncio.run(
                replay_startup(
                    None,
                    platform=platform,
                    include_cosmetic=include_cosmetic,
                    dry_run=True,
                )
            )
        except BootstrapError as exc:
            return _fail_json(args, str(exc), EXIT_ERROR)
        payload: dict[str, Any] = {
            "ok": True,
            "command": "bootstrap",
            "dry_run": True,
            "preset": getattr(args, "preset", "auto"),
            "client_version": info["client_version"],
            "cosmetic_steps": info["cosmetic_steps"],
        }
        payload.update(report)
        if args.json:
            _print_json(payload)
        else:
            print(
                f"{report['platform']} startup plan "
                f"(Telegram {report['platform'].capitalize()} "
                f"{info['client_version']}): {len(report['steps'])} steps"
            )
            for entry in report["steps"]:
                print(f"  {entry['step']:2} {entry['method']} ({entry['phase']})")
            if not include_cosmetic and info["cosmetic_steps"]:
                print(
                    f"  note: {info['cosmetic_steps']} cosmetic steps left out; "
                    "--include-cosmetic adds them"
                )
        return EXIT_OK

    try:
        if importlib.util.find_spec("telethon") is None:  # pragma: no cover
            raise ImportError("telethon is not installed")
    except ImportError as exc:
        return _fail_json(
            args,
            "bootstrap needs the telethon extra (tgmint.tl is not usable: "
            f"{exc}); install tgmint together with telethon",
        )

    try:
        import tgmint.codec as codec

        source_format = args.from_format or codec.infer_source_format(args.session)
        passphrase = ""
        if source_format in codec.PROFILE_FORMATS:
            passphrase = _resolve_passphrase(args, purpose="profile") or ""
        session = codec.read_session(
            args.session, args.from_format, passphrase=passphrase
        )
    except ValueError as exc:
        return _fail_json(args, str(exc))
    except FileNotFoundError as exc:
        return _fail_json(args, str(exc))
    except Exception as exc:
        return _fail_json(args, f"--session {args.session}: {exc}")

    try:
        api, identity = _bootstrap_api(platform, args.api_preset, args.session)
    except BootstrapError as exc:
        return _fail_json(args, str(exc), EXIT_ERROR)
    except (ValueError, NotImplementedError) as exc:
        return _fail_json(args, f"bootstrap failed: {exc}")

    from .bootstrap import make_client

    try:
        client = make_client(api=api, data=session)
    except Exception as exc:
        return _fail_json(args, f"bootstrap failed: {exc}", EXIT_ERROR)
    try:
        report = asyncio.run(
            _bootstrap_replay(
                client, platform=platform, include_cosmetic=include_cosmetic
            )
        )
    except BootstrapError as exc:
        return _bootstrap_failure(args, exc)
    except Exception as exc:
        return _fail_json(args, f"bootstrap failed: {exc}", EXIT_ERROR)

    payload = {
        "ok": True,
        "command": "bootstrap",
        "dry_run": False,
        "preset": getattr(args, "preset", "auto"),
        "session": args.session,
        "session_format": source_format,
        "api_preset": args.api_preset or platform,
        "identity": identity,
        "client_version": info["client_version"],
        "cosmetic_steps": info["cosmetic_steps"],
    }
    payload.update(report)

    if args.json:
        _print_json(payload)
    else:
        skipped = [e for e in report["steps"] if e["status"] == "skipped"]
        print(
            f"{args.session}: replayed {report['platform']} startup "
            f"(Telegram {report['platform'].capitalize()} {info['client_version']})"
        )
        print(
            f"  {report['sent']} sent, {len(skipped)} skipped, "
            f"{len(report['errors'])} failed, {len(report['steps'])} steps"
        )
        source = "recorded identity" if identity["source"] == "recorded" else "minted identity"
        print(f"  identity: {source}" + (f" ({identity['path']})" if identity["path"] else ""))
        for entry in report["steps"]:
            if entry["status"] in ("skipped", "error"):
                print(f"  {entry['status']:7} {entry['method']}: {entry['detail']}")
    return EXIT_OK


def _module_version(name: str) -> Optional[str]:
    """Installed version of an optional module, or None if absent."""
    try:
        module = __import__(name)
    except ImportError:
        return None
    version = getattr(module, "__version__", None)
    return str(version) if version else "present (no __version__)"


def _environment_report() -> dict[str, Any]:
    from .versions import PINNED

    telethon = _module_version("telethon")
    layer = None
    if telethon is not None:
        try:
            from telethon.tl.alltlobjects import LAYER as layer  # type: ignore
        except Exception:
            layer = None

    system_zones = False
    try:
        from zoneinfo import ZoneInfo

        ZoneInfo("Europe/Berlin")
        system_zones = True
    except Exception:
        system_zones = False

    return {
        "tgmint": __version__,
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
        },
        "telethon": {"version": telethon, "wire_layer": layer},
        "tzdata": {
            "system_zones": system_zones,
            "tzdata_package": _module_version("tzdata"),
        },
        "extras": {
            name: _module_version(name)
            for name in ("PyQt5", "cryptography", "pyrogram")
        },
        "pinned": dict(PINNED),
    }


def _cmd_doctor(args: argparse.Namespace) -> int:
    report = _environment_report()

    if args.json:
        _print_json(report)
    else:
        py = report["python"]
        print(f"tgmint {report['tgmint']}")
        print(f"python {py['version']} ({py['implementation']})")
        telethon = report["telethon"]
        if telethon["version"] is None:
            print("telethon: not installed")
        else:
            print(
                f"telethon {telethon['version']} "
                f"(wire layer {telethon['wire_layer']})"
            )
        tz = report["tzdata"]
        zones = "OK" if tz["system_zones"] else "MISSING"
        pkg = tz["tzdata_package"] or "not installed"
        print(f"tzdata: system zones {zones}; tzdata package: {pkg}")
        extras = ", ".join(
            f"{name}={info or 'not installed'}"
            for name, info in sorted(report["extras"].items())
        )
        print(f"extras: {extras}")
        print("pinned versions:")
        for app in sorted(report["pinned"]):
            print(f"  {app:10} {report['pinned'][app]}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def _add_json(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json",
        action="store_true",
        help="print machine-readable JSON instead of human text",
    )


def _add_mint_options(
    parser: argparse.ArgumentParser,
    preset_required: bool = True,
    preset_default: Optional[str] = None,
) -> None:
    parser.add_argument(
        "--preset",
        required=preset_required,
        default=preset_default,
        choices=_PRESET_ORDER,
        help="official client family to impersonate"
        + ("" if preset_required else " (default: desktop)"),
    )
    parser.add_argument(
        "--system",
        metavar="OS",
        help="desktop only: windows | macos | linux "
        "(default: deterministic pick from --unique-id)",
    )
    parser.add_argument(
        "--locale",
        default="auto",
        metavar="auto|none|CODE",
        help="'auto' = weighted coherent triple (default); 'none' = legacy "
        "en/en-US with no timezone; or a lang code like 'ru'",
    )
    parser.add_argument(
        "--layer",
        type=int,
        metavar="N",
        help="claim an app_version that genuinely spoke TL layer N "
        "(desktop and the android/ios presets have verified layer tables "
        "and honour it; macos has none and refuses --layer)",
    )
    parser.add_argument(
        "--unique-id",
        dest="unique_id",
        metavar="ID",
        help="stable seed — the same ID mints the same identity every time",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tgmint",
        description=(
            "Official-client fingerprint minting and session tooling. "
            "Every command accepts --json for machine-readable output."
        ),
        epilog=_EXIT_EPILOG,
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"tgmint {__version__}",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser(
        "mint",
        help="mint a Fingerprint from an official preset",
        description=(
            "Mint a complete client identity (device, OS, app version, "
            "locale triple, timezone) and optionally save it as an "
            "atomic sidecar for sticky reuse."
        ),
        epilog=_EXIT_EPILOG,
    )
    _add_mint_options(p)
    p.add_argument(
        "--save",
        metavar="PATH",
        help="write the fingerprint to this sidecar path "
        "(atomic write, mode 0600)",
    )
    _add_json(p)

    p = sub.add_parser(
        "inspect",
        help="print every field of a saved sidecar",
        description="Load a fingerprint sidecar and print all its fields.",
        epilog=_EXIT_EPILOG,
    )
    p.add_argument("path", help="sidecar file written by `mint --save`")
    _add_json(p)

    p = sub.add_parser(
        "audit",
        help="coherence + staleness + tz sanity of a sidecar",
        description=(
            "Audit a saved fingerprint: coherence (Fingerprint.validate), "
            "staleness against the pinned official releases, timezone "
            "sanity. Exits 1 when problems are found."
        ),
        epilog=_EXIT_EPILOG,
    )
    p.add_argument("path", help="sidecar file to audit")
    _add_json(p)

    p = sub.add_parser(
        "freshness",
        help="offline: pinned versions + cache age",
        description=(
            "Print the compiled-in PINNED version table and, when a "
            "version cache exists, its age. Never touches the network."
        ),
        epilog=_EXIT_EPILOG,
    )
    _add_json(p)

    p = sub.add_parser(
        "parity",
        help="print the initConnection envelope that would go on the wire",
        description=(
            "Mint a preset and print the exact initConnection envelope: "
            "the identity fields including lang_pack, the computed "
            "tz_offset, and the wire layer. Uses tgmint.parity when "
            "available, else builds the envelope inline."
        ),
        epilog=_EXIT_EPILOG,
    )
    _add_mint_options(p)
    _add_json(p)

    p = sub.add_parser(
        "convert",
        help="convert sessions between formats (needs the codec module)",
        description=(
            "Convert a session file/string you own between telethon, "
            "pyrogram, gramjs and tdata formats — offline, no login, no "
            "network; the auth_key is the only secret moved. Sources may "
            "also be a .tgmint envelope ('profile') or an official "
            "Android app data dump ('android-dir'). Requires the "
            "optional codec module; when it is absent this command exits 2. "
            "Secrets never come from argv: a sealed profile's passphrase "
            "arrives via --passphrase-env/--passphrase-stdin and a tdata "
            "folder's passcode via --passcode-env."
        ),
        epilog=_EXIT_EPILOG,
    )
    p.add_argument(
        "--from",
        dest="from_path",
        required=True,
        metavar="PATH",
        help="source session file (or string) to convert from",
    )
    p.add_argument(
        "--from-format",
        dest="from_format",
        required=True,
        choices=_CONVERT_SOURCE_FORMATS,
        help="source format ('profile' reads a .tgmint envelope; "
        "'android-dir' reads an official Android app data dump — "
        "see docs/android-acquisition.md)",
    )
    p.add_argument(
        "--to",
        dest="to_path",
        required=True,
        metavar="PATH",
        help="destination file to convert to",
    )
    p.add_argument(
        "--to-format",
        dest="to_format",
        required=True,
        choices=_CONVERT_FORMATS,
        help="destination format",
    )
    p.add_argument(
        "--passcode-env",
        metavar="VAR",
        help="tdata only: read the folder's local passcode from environment "
        "variable VAR (a passcode is a secret, so it never comes from argv)",
    )
    p.add_argument(
        "--account-index",
        dest="account_index",
        type=int,
        metavar="N",
        help="tdata/android-dir sources only: which account of a "
        "multi-account folder/dump to read (default: its main account)",
    )
    p.add_argument(
        "--variant",
        choices=["pyrogram", "kurigram"],
        default="pyrogram",
        help="pyrogram-session destinations only: which fork's SQLite schema "
        "to write (default: pyrogram)",
    )
    _add_passphrase_options(p)
    _add_json(p)

    p = sub.add_parser(
        "verify",
        help="offline check of one session file, tdata folder or .tgmint",
        description=(
            "Open ONE session you own — a session file, a saved session "
            "string, a tdata folder or a .tgmint envelope — completely "
            "offline and report what it holds: the format, dc_id, user_id "
            "and api_id when stored, the auth-key fingerprint as two "
            "hashes (the MTProto auth_key_id and a full SHA-256 — the key "
            "itself is never printed), codec placeholder values (user_id "
            "777000 / api_id 2040), and the file permissions. Without "
            "--from-format the format is detected: a directory is read as "
            "tdata, a *.tgmint name as an envelope, anything else runs "
            "the reader chain. Secrets never come from argv: a tdata "
            "passcode arrives via --passcode-env, a sealed envelope's "
            "passphrase via --passphrase-env/--passphrase-stdin. Exit "
            "codes: 0 ok | 1 unreadable | 2 readable, with warnings "
            "(placeholders, or group/world-accessible permissions)."
        ),
        epilog=_VERIFY_EPILOG,
    )
    p.add_argument(
        "path",
        help="the session file, saved session-string file, tdata folder "
        "or .tgmint envelope to check",
    )
    p.add_argument(
        "--from-format",
        dest="from_format",
        choices=_CONVERT_SOURCE_FORMATS,
        help="the format to read PATH as (default: detected — a directory "
        "is tdata, *.tgmint an envelope, else the reader chain)",
    )
    p.add_argument(
        "--passcode-env",
        metavar="VAR",
        help="tdata only: read the folder's local passcode from environment "
        "variable VAR (a passcode is a secret, so it never comes from argv)",
    )
    _add_passphrase_options(p)
    _add_json(p)

    p = sub.add_parser(
        "login-passkey",
        help="log in with a passkey and write the session in any format",
        description=(
            "Bridge: log in with a tgmint software passkey for a session "
            "you own, then write the resulting session in any supported "
            "format (telethon, pyrogram, gramjs, tdata). The client is "
            "created with a freshly minted fingerprint, so the new session "
            "is born with a coherent tgmint identity instead of stock "
            "python-telethon's. It touches the network only for the "
            "passkey sign-in; the conversion afterwards is "
            "offline. Needs telethon (the telethon extra); when tgmint.tl "
            "or telethon is missing this command exits 2. The output path "
            "is never overwritten — an existing file is refused with exit 2."
        ),
        epilog=_EXIT_EPILOG,
    )
    p.add_argument(
        "--passkey",
        required=True,
        metavar="FILE",
        help="passkey store to sign in with — a session you own "
        "(written by tgmint.passkeys.register_passkey)",
    )
    p.add_argument(
        "--password",
        metavar="2FA",
        help="the account's 2FA cloud password, when it has one",
    )
    p.add_argument(
        "--origin",
        metavar="ORIGIN",
        help="WebAuthn origin the passkey was registered under "
        "(default: the store's own origin)",
    )
    _add_mint_options(p, preset_required=False, preset_default="desktop")
    p.add_argument(
        "--to",
        dest="to_path",
        required=True,
        metavar="PATH",
        help="destination session file (or tdata folder) to write",
    )
    p.add_argument(
        "--to-format",
        dest="to_format",
        required=True,
        choices=_CONVERT_FORMATS,
        help="destination format of the logged-in session",
    )
    _add_json(p)

    p = sub.add_parser(
        "login-qr",
        help="log in by scanning a QR and write the session in any format",
        description=(
            "Acquire: show a tg://login QR, wait until YOU confirm it from "
            "your own logged-in Telegram app (Settings > Devices > Link "
            "Desktop Device), then write the resulting session in any "
            "supported format (telethon, pyrogram, gramjs, tdata). The "
            "client is created with a freshly minted fingerprint, so the "
            "new session is born with a coherent tgmint identity. The QR "
            "is rendered by tgmint's own pure-Python encoder (no extra "
            "dependency; the URL is printed too). Handles the "
            "loginTokenMigrateTo DC switch (with rollback) and 2FA "
            "(--password, or an interactive prompt). This is an "
            "interactive, single-account command: nothing here ever "
            "touches an account but the one that scanned. One of the two "
            "network commands (login-passkey is the other); the "
            "conversion afterwards is offline. Needs telethon (the "
            "telethon extra); when tgmint.tl or telethon is missing this "
            "command exits 2. The output path is never overwritten — an "
            "existing file is refused with exit 2."
        ),
        epilog=_EXIT_EPILOG,
    )
    p.add_argument(
        "--password",
        metavar="2FA",
        help="the account's 2FA cloud password, when it has one "
        "(default: prompt when needed on a terminal)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        metavar="SECONDS",
        help="overall budget to wait for the scan; an expired code is "
        "refreshed inside it (default: 300)",
    )
    p.add_argument(
        "--invert",
        action="store_true",
        help="render the QR light-on-dark (some terminals scan better "
        "inverted)",
    )
    _add_mint_options(p, preset_required=False, preset_default="desktop")
    p.add_argument(
        "--to",
        dest="to_path",
        required=True,
        metavar="PATH",
        help="destination session file (or tdata folder) to write",
    )
    p.add_argument(
        "--to-format",
        dest="to_format",
        required=True,
        choices=_CONVERT_FORMATS,
        help="destination format of the logged-in session",
    )
    _add_json(p)

    profile_parser = sub.add_parser(
        "profile",
        help="the portable identity envelope (.tgmint): seal, open, inspect",
        description=(
            "One file that is an account: the session, the identity it was "
            "born with, and (optionally) the passkey that recovers it. "
            "`seal` bundles, `open` writes the session out in any codec "
            "format, `inspect` prints a secret-free summary. Sealing uses "
            "AES-256-GCM under a PBKDF2-SHA256 key and needs the passkeys "
            "extra (cryptography); an unsealed profile needs nothing. "
            "Passphrases never come from argv: use --passphrase-env or "
            "--passphrase-stdin, or type one at the prompt."
        ),
        epilog=_EXIT_EPILOG,
    )
    profile_sub = profile_parser.add_subparsers(
        dest="profile_command", metavar="SUBCOMMAND"
    )

    sp = profile_sub.add_parser(
        "seal",
        help="bundle a session (+ fingerprint, + passkey) into a .tgmint",
        description=(
            "Read a session you own and write a .tgmint envelope: the "
            "session in its own format, the fingerprint sidecar when one "
            "exists (or --fingerprint), and the passkey store when "
            "--passkey is given. Add a passphrase to seal it. The output "
            "is never overwritten and is written mode 0600."
        ),
        epilog=_EXIT_EPILOG,
    )
    sp.add_argument(
        "--session",
        required=True,
        metavar="PATH",
        help="session to bundle (a session file, string file, tdata "
        "folder, or .tgmint envelope)",
    )
    sp.add_argument(
        "--from-format",
        dest="from_format",
        required=True,
        choices=_CONVERT_SOURCE_FORMATS,
        help="format of --session",
    )
    sp.add_argument(
        "--passkey",
        metavar="FILE",
        help="passkey store to bundle (the file register_passkey wrote)",
    )
    sp.add_argument(
        "--fingerprint",
        metavar="FILE",
        help="fingerprint sidecar to bundle (default: the session's own "
        "sidecar, when one sits next to it)",
    )
    sp.add_argument(
        "--out",
        required=True,
        metavar="FILE",
        help="the .tgmint file to create (never overwritten)",
    )
    sp.add_argument(
        "--note",
        metavar="TEXT",
        help="free-text note stored in the envelope's meta block",
    )
    _add_passphrase_options(sp)
    _add_json(sp)

    sp = profile_sub.add_parser(
        "open",
        help="open a .tgmint and write its session in any format",
        description=(
            "Open an envelope and write the session it carries out in any "
            "codec format. A sealed envelope needs its passphrase. The "
            "output path is never overwritten."
        ),
        epilog=_EXIT_EPILOG,
    )
    sp.add_argument("profile", help="the .tgmint envelope to open")
    sp.add_argument(
        "--to",
        dest="to_path",
        required=True,
        metavar="PATH",
        help="where to write the session (never overwritten)",
    )
    sp.add_argument(
        "--to-format",
        dest="to_format",
        required=True,
        choices=_CONVERT_FORMATS,
        help="format of the written session",
    )
    _add_passphrase_options(sp)
    _add_json(sp)

    sp = profile_sub.add_parser(
        "inspect",
        help="print a secret-free JSON summary of a .tgmint",
        description=(
            "Summarize an envelope: container format, sealed or not, which "
            "session format, the authorization's dc_id/user_id, whether a "
            "fingerprint and a passkey are bundled, and the meta block. "
            "A sealed envelope without a passphrase is reported as locked "
            "instead of failing."
        ),
        epilog=_EXIT_EPILOG,
    )
    sp.add_argument("profile", help="the .tgmint envelope to inspect")
    _add_passphrase_options(sp)
    _add_json(sp)

    p = sub.add_parser(
        "heal",
        help="repair one dead session with its passkey (network)",
        description=(
            "Repair ONE session you own whose auth key the server no longer "
            "accepts: probe it, sign back in with a stored tgmint passkey "
            "on a client minted from the recorded fingerprint, and rewrite "
            "the session with the fresh auth key. By default it is an "
            "in-place, same-format rewrite; --out writes the fresh session "
            "somewhere else, and it becomes REQUIRED as soon as --to-format "
            "differs from the source format — converting in place would "
            "destroy the original format while the file name kept claiming "
            "it. Without --live nothing is "
            "probed and --force is required. There is no batch mode and no "
            "'heal everything' switch on purpose: one account, one session, "
            "invoked by its owner. Needs telethon; the passkey ceremony "
            "needs the passkeys extra. Exit codes: 0 alive (no change) or "
            "healed | 1 reserved for audit problems | 2 refused, or the "
            "login/heal failed."
        ),
        epilog=_EXIT_EPILOG,
    )
    p.add_argument("session", metavar="SESSION", help="the session to repair")
    p.add_argument(
        "--passkey",
        required=True,
        metavar="FILE",
        help="passkey store that can sign back into this account",
    )
    p.add_argument(
        "--from-format",
        dest="from_format",
        choices=_CONVERT_SOURCE_FORMATS,
        help="format of SESSION (default: inferred — .tgmint -> profile, "
        "else telethon-session)",
    )
    p.add_argument(
        "--to-format",
        dest="to_format",
        choices=_HEAL_FORMATS + ["profile"],
        help="format to rewrite the session in (default: same as the "
        "source; a .tgmint envelope is rewritten as an envelope). Changing "
        "the format requires --out: in-place rewrite is same-format only",
    )
    p.add_argument(
        "--out",
        metavar="PATH",
        help="write the healed session here instead of in place (never "
        "overwritten); required with a --to-format that differs from the "
        "source format",
    )
    p.add_argument(
        "--api-preset",
        dest="api_preset",
        default="desktop",
        choices=_PRESET_ORDER,
        help="identity to mint when neither the envelope nor a sidecar "
        "recorded one (default: desktop)",
    )
    p.add_argument(
        "--password",
        metavar="2FA",
        help="the account's 2FA cloud password, when it has one",
    )
    p.add_argument(
        "--live",
        action="store_true",
        help="probe the session first; an alive session is left untouched",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="re-login even without a probe (or when the probe is "
        "inconclusive) — never overrides an alive session",
    )
    _add_passphrase_options(p)
    _add_json(p)

    p = sub.add_parser(
        "bootstrap",
        help="replay the official post-auth startup batch (network: live mode)",
        description=(
            "Replay the requests the official client sends right after "
            "authorization, in the order its source proves, for one platform "
            "preset (android 12.10.6 / desktop 7.3.3; read out of the trees, "
            "see docs/bootstrap.md). Read-only only: the sequence is gated by "
            "an allowlist and account.updateStatus / account.registerDevice "
            "/ auth.* are refused outright, and initConnection is never "
            "touched because it is fixed at connect time. --dry-run prints "
            "the plan without a session and never connects; live mode reads "
            "ONE session you own, connects with the identity the session "
            "recorded (its fingerprint sidecar) — minting a fresh one only "
            "when none exists — replays, and disconnects. No batch mode, no "
            "daemon. Exit codes: 0 done (per-request failures are reported, "
            "not fatal) | 1 reserved for audit problems | 2 bad usage, no "
            "platform to infer, or the replay failed."
        ),
        epilog=_EXIT_EPILOG,
    )
    p.add_argument(
        "--preset",
        default="auto",
        choices=["auto"] + list(_BOOTSTRAP_PRESETS),
        help="which official client to imitate; 'auto' reads the platform "
        "from the session's fingerprint sidecar (default: auto)",
    )
    p.add_argument(
        "--session",
        metavar="SESSION",
        help="the session to replay into (live mode; not needed for --dry-run)",
    )
    p.add_argument(
        "--from-format",
        dest="from_format",
        choices=_CONVERT_SOURCE_FORMATS,
        help="format of --session (default: inferred — .tgmint -> profile, "
        "else telethon-session)",
    )
    p.add_argument(
        "--api-preset",
        dest="api_preset",
        choices=_PRESET_ORDER,
        help="identity to mint when the session has no fingerprint sidecar "
        "(default: the family the platform preset names — android or "
        "desktop); a value from another client family is refused",
    )
    p.add_argument(
        "--include-cosmetic",
        dest="include_cosmetic",
        action="store_true",
        help="also send the cosmetic fan-out (sticker packs, dice emoji, "
        "reactions); off by default",
    )
    p.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="print the plan and exit; never connects and needs no session",
    )
    _add_passphrase_options(p)
    _add_json(p)

    p = sub.add_parser(
        "cadence",
        help="the official keepalive cadence vs the framework defaults (offline)",
        description=(
            "Print the keepalive cadence the official clients actually use - "
            "Android 12.10.6 pings ping_delay_disconnect every 19 s with "
            "disconnect_delay 35 (ConnectionsManager.cpp:295,1786), Desktop "
            "7.3.3 every 30 s with 60 (session_private.cpp:40-42) - next to "
            "what Telethon (plain PING every 60 s) and the Pyrogram family "
            "(PING_DELAY_DISCONNECT every 5 s, delay 25) ship with, and what "
            "of that tgmint can change per framework. Pure plan: no session, "
            "no socket, no client is touched; tgmint.cadence.apply() is the "
            "only thing that sets a knob, and it does so in-process. Matching "
            "a cadence removes one tell among many: this is not ban evasion."
        ),
        epilog=_EXIT_EPILOG,
    )
    p.add_argument(
        "--preset",
        choices=list(_CADENCE_PRESETS),
        help="which official client's cadence (default: both, android first)",
    )
    _add_json(p)

    p = sub.add_parser(
        "doctor",
        help="environment report (python, telethon, tzdata, extras, pins)",
        description=(
            "Report the runtime environment: python version, telethon "
            "version and its wire layer, tzdata availability, optional "
            "extras (PyQt5, cryptography, pyrogram) and the pinned "
            "official-client versions."
        ),
        epilog=_EXIT_EPILOG,
    )
    _add_json(p)

    return parser


_PROFILE_HANDLERS: dict[str, Callable[[argparse.Namespace], int]] = {
    "seal": _cmd_profile_seal,
    "open": _cmd_profile_open,
    "inspect": _cmd_profile_inspect,
}


def _cmd_profile(args: argparse.Namespace) -> int:
    """Dispatch `tgmint profile <seal|open|inspect>`."""
    sub = getattr(args, "profile_command", None)
    handler = _PROFILE_HANDLERS.get(sub or "")
    if handler is None:
        print(
            "tgmint: profile needs a subcommand: seal, open, or inspect",
            file=sys.stderr,
        )
        return EXIT_ERROR
    # name the real command in --json errors ("profile seal", not "profile")
    args.command = f"profile {sub}"
    return handler(args)


_HANDLERS: dict[str, Callable[[argparse.Namespace], int]] = {
    "mint": _cmd_mint,
    "inspect": _cmd_inspect,
    "audit": _cmd_audit,
    "freshness": _cmd_freshness,
    "parity": _cmd_parity,
    "convert": _cmd_convert,
    "verify": _cmd_verify,
    "login-passkey": _cmd_login_passkey,
    "login-qr": _cmd_login_qr,
    "profile": _cmd_profile,
    "heal": _cmd_heal,
    "bootstrap": _cmd_bootstrap,
    "cadence": _cmd_cadence,
    "doctor": _cmd_doctor,
}


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point. `argv` defaults to ``sys.argv[1:]``.

    Returns the process exit code (see the module docstring for the
    contract); ``python -m tgmint`` wires this into ``sys.exit``.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return EXIT_ERROR

    handler = _HANDLERS[args.command]
    try:
        return handler(args)
    except BrokenPipeError:  # e.g. `tgmint doctor | head`
        try:
            sys.stdout.close()
        except Exception:
            pass
        return EXIT_ERROR
