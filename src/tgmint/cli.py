"""tgmint command line — mint, inspect, audit, freshness, parity, convert, doctor.

CLI v1. Zero new dependencies: argparse +
stdlib only, everything offline-safe except an explicit ``convert``.
Every command takes ``--json`` for machine-readable output; the human
format is stable but not a contract.

Exit codes (also shown in ``--help``)::

    0  success
    1  `audit` found problems in the fingerprint
    2  error: bad usage, unreadable sidecar, unknown preset/locale,
       or an optional module missing from this build (e.g. codec)

Optional modules are imported lazily and probed defensively:
``tgmint.parity.describe_envelope`` (envelope builder, parallel work)
and ``tgmint.codec`` (session converter, parallel work) — the CLI must
not crash when either is absent.
"""

from __future__ import annotations

import argparse
import json as _json
import platform
import sys
import time
from typing import Any, Callable, Dict, List, Optional

from . import __version__
from .audit import audit_fingerprint
from .fingerprint import Fingerprint

EXIT_OK = 0
EXIT_PROBLEMS = 1
EXIT_ERROR = 2

# preset name -> API.<class> (tgmint.api)
_PRESETS: Dict[str, str] = {
    "desktop": "TelegramDesktop",
    "android": "TelegramAndroid",
    "android-x": "TelegramAndroidX",
    "ios": "TelegramIOS",
}

# ordered for --help; validated by argparse choices
_PRESET_ORDER = ["desktop", "android", "android-x", "ios"]

_CONVERT_FORMATS = [
    "telethon-session",
    "telethon-string",
    "pyrogram-session",
    "pyrogram-string",
    "tdata",
]

_EXIT_EPILOG = "exit codes: 0 success | 1 audit found problems | 2 error"

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


def _print_fields(payload: Dict[str, Any], order: List[str]) -> None:
    for key in order:
        if key in payload:
            print(f"  {key}: {payload[key]}")


def _fail(message: str) -> int:
    print(f"tgmint: {message}", file=sys.stderr)
    return EXIT_ERROR


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

    payload: Dict[str, Any] = dict(fp.to_dict())
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

    payload: Dict[str, Any] = dict(fp.to_dict())
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
    entries: Dict[str, Any] = {}
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

    payload: Dict[str, Any] = {
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


def _envelope_inline(api: Any, layer: Optional[int]) -> Dict[str, Any]:
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
) -> Optional[Dict[str, Any]]:
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
    """The wire layer to report: explicit --layer, else telethon's."""
    if explicit is not None:
        return int(explicit)
    try:
        from .layers import telethon_layer

        return telethon_layer()
    except Exception:
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
        return _fail(
            "codec module not available in this build "
            "(no convert_session entrypoint)"
        )

    try:
        result = convert(
            args.from_path, args.from_format, args.to_path, args.to_format
        )
    except TypeError:
        # keyword-spelled variant, in case the codec lands with that shape
        try:
            result = convert(
                src=args.from_path,
                src_format=args.from_format,
                dst=args.to_path,
                dst_format=args.to_format,
            )
        except Exception as exc:
            return _fail(f"convert failed: {exc}")
    except Exception as exc:
        return _fail(f"convert failed: {exc}")

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
        print(f"  result: {result}")
    return EXIT_OK


def _module_version(name: str) -> Optional[str]:
    """Installed version of an optional module, or None if absent."""
    try:
        module = __import__(name)
    except ImportError:
        return None
    version = getattr(module, "__version__", None)
    return str(version) if version else "present (no __version__)"


def _environment_report() -> Dict[str, Any]:
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


def _add_mint_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--preset",
        required=True,
        choices=_PRESET_ORDER,
        help="official client family to impersonate",
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
        help="desktop only: claim an app_version that genuinely spoke TL "
        "layer N (ignored for mobile presets for now)",
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
            "Convert a session file/string between telethon, pyrogram "
            "and tdata formats. Requires the optional codec module; "
            "when it is absent this command exits 2."
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
        choices=_CONVERT_FORMATS,
        help="source format",
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


_HANDLERS: Dict[str, Callable[[argparse.Namespace], int]] = {
    "mint": _cmd_mint,
    "inspect": _cmd_inspect,
    "audit": _cmd_audit,
    "freshness": _cmd_freshness,
    "parity": _cmd_parity,
    "convert": _cmd_convert,
    "doctor": _cmd_doctor,
}


def main(argv: Optional[List[str]] = None) -> int:
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
