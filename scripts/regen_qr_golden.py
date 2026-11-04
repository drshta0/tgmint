#!/usr/bin/env python3
"""Regenerate the QR encoder's golden fixtures from the reference encoders.

The built-in QR encoder (``tgmint.qrrender``) is verified offline against
the two most-used pure-Python QR libraries, both MIT:

* **``qrcode``** (pypi.org/project/qrcode) is the matrix oracle: this script
  records its module matrices for a sweep of inputs — every version 1-10 at
  levels L and M at their exact byte-mode capacity boundary, realistic
  ``tg://login`` URLs, and all eight data masks of one input per level —
  into ``tests/golden/qr/qr_vectors.json``, which ``tests/test_qrrender.py``
  asserts ``tgmint.qrrender.encode`` reproduces module for module.
* **``segno``** (pypi.org/project/segno), when installed, is a second
  opinion on version assignment only (which version a payload length maps
  to at each level — an independent check of the capacity tables). segno's
  *matrices* are deliberately not pinned: when the data stream lands on a
  codeword boundary after the terminator, segno adds a full zero pad
  codeword before the 0xEC/0x11 alternation, where ISO/IEC 18004 and the
  ``qrcode`` library (and this encoder) start the alternation directly —
  every decoder stops at the terminator, but the matrices differ.

While generating, the script verifies every vector against the built-in
encoder and exits non-zero on any mismatch — running it IS the
verification. The test suite never imports either library: they are
generation-time oracles, and their outputs are committed.

Usage::

    pip install qrcode segno
    python scripts/regen_qr_golden.py [--out tests/golden/qr/qr_vectors.json]
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys

import qrcode
import qrcode.util

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
)

from tgmint import qrrender  # noqa: E402

try:
    import segno
except ImportError:  # the second opinion is optional
    segno = None

_LEVELS = {"L": qrcode.constants.ERROR_CORRECT_L, "M": qrcode.constants.ERROR_CORRECT_M}


def _qrcode_matrix(data: str, level: str, mask=None, version=None):
    code = qrcode.QRCode(
        version=version,
        error_correction=_LEVELS[level],
        mask_pattern=mask,
        border=0,
    )
    code.add_data(qrcode.util.QRData(data, mode=qrcode.util.MODE_8BIT_BYTE))
    code.make(fit=False)
    rows = [
        "".join("1" if cell else "0" for cell in row) for row in code.modules
    ]
    return rows


def _segno_version(data: str, level: str):
    qr = segno.make(
        data, error=level.lower(), boost_error=False, micro=False, mode="byte"
    )
    return qr.version


def _vectors() -> list:
    vectors = []

    # 1) capacity boundaries: every version 1-10 at L and M, payload at the
    #    exact byte-mode capacity of that version (my table's boundary)
    for level in ("L", "M"):
        for version in range(1, 11):
            capacity = qrrender._byte_capacity(version, level)
            vectors.append(
                {
                    "kind": "capacity",
                    "input": "A" * capacity,
                    "level": level,
                    "mask": None,
                    "expect_version": version,
                }
            )

    # 2) one-past-the-boundary for a few versions: the next version must
    #    absorb it (version 10's boundary raises QrTooLongError instead)
    for level in ("L", "M"):
        for version in (1, 2, 3, 6, 9):
            capacity = qrrender._byte_capacity(version, level)
            vectors.append(
                {
                    "kind": "capacity-plus-one",
                    "input": "A" * (capacity + 1),
                    "level": level,
                    "mask": None,
                    "expect_version": version + 1,
                }
            )

    # 3) realistic tg://login URLs (base64url tokens of assorted lengths)
    import base64

    for token_len in (10, 16, 20, 24, 32, 42, 63):
        token = base64.urlsafe_b64encode(bytes(range(token_len))).decode().rstrip("=")
        for level in ("L", "M"):
            vectors.append(
                {
                    "kind": "login-url",
                    "input": "tg://login?token={}".format(token),
                    "level": level,
                    "mask": None,
                }
            )

    # 4) all eight masks of one input per level (pins the format
    #    information for every mask, not just penalty-chosen ones)
    for level in ("L", "M"):
        for mask in range(8):
            vectors.append(
                {
                    "kind": "mask-forced",
                    "input": "tg://login?token=YWFhYWFhYWFhYWFhYWFhYQ",
                    "level": level,
                    "mask": mask,
                }
            )

    return vectors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        default=os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "tests",
            "golden",
            "qr",
            "qr_vectors.json",
        ),
    )
    args = parser.parse_args()

    vectors = _vectors()
    failures = []
    for vector in vectors:
        level, mask = vector["level"], vector.get("mask")
        record = _qrcode_matrix(vector["input"], level, mask=mask)
        vector["qrcode"] = {"rows": record}
        if segno is not None:
            vector["segno_version"] = _segno_version(vector["input"], level)
            if (
                "expect_version" in vector
                and vector["segno_version"] != vector["expect_version"]
            ):
                failures.append(
                    "{} L{} len={}: segno assigned version {}, expected {} "
                    "(capacity table disagreement)".format(
                        vector["kind"], level, len(vector["input"]),
                        vector["segno_version"], vector["expect_version"],
                    )
                )
        if "expect_version" in vector:
            vector["qrcode"]["version"] = vector["expect_version"]

        # verify the built-in encoder against the oracle, right here
        try:
            mine = qrrender.encode(vector["input"], error=level, mask=mask)
            rows = [
                "".join("1" if cell else "0" for cell in row) for row in mine.matrix
            ]
            if rows != record:
                differing = sum(
                    1
                    for a, b in zip(rows, record)
                    for ca, cb in zip(a, b)
                    if ca != cb
                )
                failures.append(
                    "{} L{} mask={} len={}: matrix differs in {} modules "
                    "(mine v{} mask {})".format(
                        vector["kind"], level, mask, len(vector["input"]),
                        differing, mine.version, mine.mask,
                    )
                )
            if "expect_version" in vector and mine.version != vector["expect_version"]:
                failures.append(
                    "{} L{} len={}: version {} != expected {}".format(
                        vector["kind"], level, len(vector["input"]),
                        mine.version, vector["expect_version"],
                    )
                )
        except qrrender.QrTooLongError:
            if vector.get("expect_version") != 11:
                failures.append(
                    "{} L{} len={}: built-in refused a payload the oracle "
                    "encoded".format(
                        vector["kind"], level, len(vector["input"])
                    )
                )

    payload = {
        "_source": (
            "matrices recorded from the qrcode library (pypi.org/project/"
            "qrcode, MIT) by scripts/regen_qr_golden.py; offline golden "
            "inputs for tgmint.qrrender — the test suite never imports "
            "qrcode/segno"
        ),
        "_qrcode_version": getattr(qrcode, "__version__", "?"),
        "_segno_version": getattr(segno, "__version__", None),
        "_generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "_iso_reference": "ISO/IEC 18004:2006",
        "vectors": vectors,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=1, sort_keys=False)
        fp.write("\n")

    print("{} vectors -> {}".format(len(vectors), args.out))
    if failures:
        print("\n{} MISMATCH(ES):".format(len(failures)), file=sys.stderr)
        for failure in failures:
            print("  - " + failure, file=sys.stderr)
        return 1
    print("all vectors match the qrcode library module for module")
    return 0


if __name__ == "__main__":
    sys.exit(main())
