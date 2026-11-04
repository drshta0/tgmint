"""
Per-account fingerprint sidecar store — the "sticky identity" discipline.

A minted fingerprint is only safe to reuse if it is
*remembered* per account, so every session keeps wearing the identity it
was born with (an account whose device/app_version changes on every
login is exactly the anomaly to avoid). The sidecar is a
small JSON file stored next to the session file (see
``sidecar_path_for``) and written with the same atomic-and-private
discipline as the passkey store in ``passkeys.py``.

This module is deliberately dict-based: the ``Fingerprint`` dataclass
lives in another module and is glued onto this store there. ``save_sidecar`` stamps ``schema_version`` on everything it
writes so that migration stays detectable later.
"""
from __future__ import annotations

import json
import os
import pathlib

__all__ = ["SCHEMA_VERSION", "save_sidecar", "load_sidecar", "sidecar_path_for"]

SCHEMA_VERSION = 1


def save_sidecar(path, data: dict) -> pathlib.Path:
    """Atomically write ``data`` as a sidecar JSON file, mode 0600.

    Requirements copied from ``PasskeyStore.save`` (passkeys.py): the
    payload is stamped with ``schema_version`` (overwriting any value the
    caller carried), written to a temp file in the SAME directory created
    via ``os.open(..., O_WRONLY|O_CREAT|O_TRUNC, 0o600)`` so it is
    private from its first byte, fsync'd, then swapped into place with
    ``os.replace`` (atomic on POSIX, works on Windows) — and finally
    chmod'ed 0600, which also tightens pre-existing 0644 files being
    overwritten. Parent directories are created if missing.

    Returns the final path.
    """
    path = pathlib.Path(path)
    payload = dict(data)  # stamped on a copy — the caller's dict is untouched
    payload["schema_version"] = SCHEMA_VERSION

    directory = os.path.dirname(os.path.abspath(str(path)))
    os.makedirs(directory, exist_ok=True)
    tmp = os.path.join(directory, f".{os.path.basename(str(path))}.tmp.{os.getpid()}")

    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    replaced = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, indent=2)
            fp.write("\n")
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp, str(path))
        replaced = True
    finally:
        if not replaced:
            # the atomic swap never happened — don't leave the
            # half-written temp file behind
            try:
                os.unlink(tmp)
            except OSError:
                pass
        # covers pre-existing files that may have looser permissions.
        # (Unlike passkeys.py, guarded: if the swap failed and no old
        # file exists, there is nothing to chmod — don't let a
        # FileNotFoundError from the cleanup mask the real error.)
        try:
            os.chmod(str(path), 0o600)
        except OSError:
            pass
    return path


def load_sidecar(path) -> dict:
    """Read a sidecar written by ``save_sidecar``.

    Raises ``FileNotFoundError`` if the file is missing. Raises
    ``ValueError`` if ``schema_version`` is absent or differs from
    ``SCHEMA_VERSION`` (the message names the path and both versions),
    or if the file is not valid JSON.
    """
    path = pathlib.Path(path)
    with open(path, encoding="utf-8") as fp:
        data = json.load(fp)

    version = data.get("schema_version") if isinstance(data, dict) else None
    if version != SCHEMA_VERSION:
        raise ValueError(
            f"{path}: unsupported sidecar schema_version "
            f"{version!r} (expected {SCHEMA_VERSION}) — written by a "
            "different tgmint version?"
        )
    return data


def sidecar_path_for(session_path) -> pathlib.Path:
    """The sidecar path for a session file/directory.

    ``"foo.session"`` -> ``"foo.fingerprint.json"`` next to it (same
    directory; a ``.session`` / ``.session.sqlite`` / ``.tdata`` suffix
    is replaced). Anything else — including a bare ``tdata`` *directory*
    name — gets ``".fingerprint.json"`` appended, so the sidecar always
    sits next to the thing it describes.
    """
    path = pathlib.Path(session_path)
    name = path.name
    # longest-first so ".session.sqlite" is not half-matched
    for suffix in (".session.sqlite", ".session", ".tdata"):
        if name.endswith(suffix):
            return path.with_name(name[: -len(suffix)] + ".fingerprint.json")
    return path.with_name(name + ".fingerprint.json")
