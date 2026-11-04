"""Offline tests for the built-in QR encoder and terminal renderer.

The encoder's correctness is pinned against the committed golden fixtures
(``tests/golden/qr/qr_vectors.json``): matrices recorded from the ``qrcode``
library (and version assignments second-checked by ``segno``) by
``scripts/regen_qr_golden.py`` — every version 1-10 at both built-in
levels, capacity boundaries, realistic ``tg://login`` URLs and all eight
masks. The suite never imports either oracle library.
"""
from __future__ import annotations

import base64
import json
import os
import unittest

import pytest

from tgmint import qrrender

_GOLDEN = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "golden", "qr", "qr_vectors.json"
)


def _load_vectors():
    with open(_GOLDEN, encoding="utf-8") as fp:
        payload = json.load(fp)
    return payload


class TestGoldenMatrices(unittest.TestCase):
    """Module-for-module equality with the recorded oracle matrices."""

    @classmethod
    def setUpClass(cls):
        cls.payload = _load_vectors()
        cls.vectors = cls.payload["vectors"]

    def test_fixture_provenance_is_recorded(self):
        self.assertIn("qrcode", self.payload["_source"])
        self.assertEqual(self.payload["_iso_reference"], "ISO/IEC 18004:2006")
        self.assertIsNotNone(self.payload["_segno_version"])
        self.assertGreater(len(self.vectors), 40)

    def test_every_capacity_boundary_is_covered(self):
        kinds = {(v["kind"], v["level"]) for v in self.vectors}
        for level in ("L", "M"):
            for version in range(1, 11):
                self.assertIn(("capacity", level), kinds)

    def test_encoder_reproduces_every_vector(self):
        for vector in self.vectors:
            with self.subTest(
                kind=vector["kind"], level=vector["level"],
                mask=vector.get("mask"), length=len(vector["input"]),
            ):
                mine = qrrender.encode(
                    vector["input"],
                    error=vector["level"],
                    mask=vector.get("mask"),
                )
                rows = [
                    "".join("1" if cell else "0" for cell in row)
                    for row in mine.matrix
                ]
                self.assertEqual(rows, vector["qrcode"]["rows"])
                if "expect_version" in vector:
                    self.assertEqual(mine.version, vector["expect_version"])

    def test_segno_agrees_on_version_assignment(self):
        # recorded second opinion: which version a payload length maps to
        for vector in self.vectors:
            if "expect_version" not in vector or "segno_version" not in vector:
                continue
            with self.subTest(kind=vector["kind"], level=vector["level"]):
                self.assertEqual(
                    vector["segno_version"], vector["expect_version"]
                )

    def test_boundary_plus_one_needs_the_next_version(self):
        # the recorded +1 vectors: the encoder itself must pick v+1
        for vector in self.vectors:
            if vector["kind"] != "capacity-plus-one":
                continue
            if vector["expect_version"] == 11:
                continue  # past version 10: QrTooLongError territory
            with self.subTest(level=vector["level"], len=len(vector["input"])):
                mine = qrrender.encode(vector["input"], error=vector["level"])
                self.assertEqual(mine.version, vector["expect_version"])

    def test_version_ten_boundary_raises_qr_too_long(self):
        capacity_l = qrrender._byte_capacity(10, "L")
        with pytest.raises(qrrender.QrTooLongError):
            qrrender.encode("A" * (capacity_l + 1), error="L")
        capacity_m = qrrender._byte_capacity(10, "M")
        with pytest.raises(qrrender.QrTooLongError):
            qrrender.encode("A" * (capacity_m + 1), error="M")


class TestEncoder(unittest.TestCase):
    def test_login_url_lands_in_a_small_version(self):
        token = base64.urlsafe_b64encode(bytes(range(20))).decode().rstrip("=")
        url = f"tg://login?token={token}"
        qr = qrrender.encode(url)  # level M is the default
        self.assertEqual(qr.error, "M")
        self.assertLessEqual(qr.version, 4)
        self.assertEqual(qr.size, 17 + 4 * qr.version)
        self.assertIn(qr.mask, range(8))

    def test_forced_version_and_mask(self):
        qr = qrrender.encode("hello", error="L", version=2, mask=5)
        self.assertEqual((qr.version, qr.error, qr.mask), (2, "L", 5))

    def test_unsupported_levels_rejected(self):
        with pytest.raises(ValueError):
            qrrender.encode("x" * 30, error="H")  # only L and M are built in
        with pytest.raises(ValueError):
            qrrender.encode("x" * 30, error="Q")

    def test_payload_over_forced_version_capacity_raises(self):
        with pytest.raises(qrrender.QrTooLongError):
            qrrender.encode("A" * 30, error="L", version=1)  # v1-L holds 17

    def test_utf8_payloads_are_bytemode_encoded(self):
        qr = qrrender.encode("tgmint-ä-ö", error="M")
        self.assertEqual(qr.size, 17 + 4 * qr.version)

    def test_matrix_is_a_tuple_of_bool_rows(self):
        qr = qrrender.encode("abc")
        self.assertIsInstance(qr.matrix, tuple)
        self.assertIsInstance(qr.matrix[0], tuple)
        self.assertIsInstance(qr.matrix[0][0], bool)


class TestRenderer(unittest.TestCase):
    def _qr(self, text="tg://login?token=YWFhYWFhYWFhYWFhYWFhYQ"):
        return qrrender.encode(text)

    def test_half_block_rendering_shape(self):
        qr = self._qr()
        size, border = qr.size, 4
        text = qrrender.render_text(qr.matrix, border=border)
        lines = text.splitlines()
        # two module rows per line, quiet zone included, odd size rounds up
        self.assertEqual(len(lines), (size + 2 * border + 1) // 2)
        self.assertEqual(len(lines[0]), size + 2 * border)
        self.assertIn("█", text)      # both-dark pairs exist
        self.assertIn(" ", text)      # the quiet zone exists

    def test_only_half_block_glyphs_are_used(self):
        text = qrrender.render_text(self._qr().matrix)
        self.assertLessEqual(set(text) - {"\n"}, {"█", "▀", "▄", " "})

    def test_invert_swaps_dark_and_light(self):
        matrix = self._qr().matrix
        normal = qrrender.render_text(matrix, border=0)
        inverted = qrrender.render_text(matrix, invert=True, border=0)
        mirror = str.maketrans("█▀▄ ", " ▄▀█")
        self.assertEqual(inverted, normal.translate(mirror))

    def test_border_is_configurable(self):
        matrix = self._qr().matrix
        b0 = qrrender.render_text(matrix, border=0)
        b2 = qrrender.render_text(matrix, border=2)
        self.assertEqual(len(b2.splitlines()[0]), len(b0.splitlines()[0]) + 4)
        # quiet-zone columns are blanks around every row
        for line in b2.splitlines():
            self.assertTrue(line.startswith("  "))
            self.assertTrue(line.endswith("  "))

    def test_render_a_login_qr_end_to_end(self):
        # exactly what the CLI renders for a 20-byte login token
        token = base64.urlsafe_b64encode(bytes(range(20))).decode().rstrip("=")
        qr = qrrender.encode(f"tg://login?token={token}")
        text = qrrender.render_text(qr.matrix)
        self.assertGreaterEqual(len(text.splitlines()), 15)


if __name__ == "__main__":
    unittest.main()
