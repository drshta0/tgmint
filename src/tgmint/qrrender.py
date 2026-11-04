"""A pure-Python QR encoder and terminal renderer — no new dependency.

``tgmint login-qr`` needs exactly one image: a QR of ``tg://login?token=...``
in the terminal. Pulling in a QR library for that would be tgmint's first
non-MTProto dependency, so this module implements the slice of ISO/IEC
18004 the use case needs:

* byte mode only (the login URL is ASCII),
* error-correction levels ``L`` and ``M`` (the default is ``M``),
* versions 1-10 (a ``tg://login`` URL is ~43 bytes — version 3-4; version 10
  fits 271/213 bytes at L/M),
* all eight data masks with the ISO penalty rules, choosing the cheapest
  (ties: the lowest mask number, like ``segno``).

Longer inputs raise :class:`QrTooLongError` — the caller falls back to
printing the URL (the CLI's behavior), never a truncated code.

Correctness is pinned offline against the two most-used pure-Python QR
libraries (both MIT): ``scripts/regen_qr_golden.py`` records the
``qrcode`` library's matrices for a sweep of inputs — every version 1-10
at both levels at their exact capacity boundary, realistic login URLs,
and all eight masks — into ``tests/golden/qr/qr_vectors.json``, and
``tests/test_qrrender.py`` asserts this encoder reproduces them module
for module; ``segno`` second-checks which version each payload length
maps to (an independent read of the capacity tables). segno's own
matrices are deliberately not pinned: it adds an extra zero pad codeword
when the data stream lands on a codeword boundary after the terminator —
decodable (the terminator ends the message) but not the ISO/IEC 18004
form the ``qrcode`` library and this encoder emit. The suite never
imports either library: they are generation-time oracles, their recorded
outputs are what runs in CI.

The renderer draws two module rows per terminal line with the Unicode half
blocks ``▀ ▄ █`` and a four-module quiet zone, so a 25x25 code is 13 lines
of 33 characters.

Sources: ISO/IEC 18004:2006 (QR Code spec) for the construction rules,
mask formulas and penalty scoring; the capacity / error-correction block
tables as published with it and mirrored in every QR implementation (e.g.
https://www.thonky.com/qr-code-tutorial/error-correction-table); the gf(256)
Reed-Solomon arithmetic over the primitive polynomial 0x11D.
"""
from __future__ import annotations

import dataclasses
from typing import Optional, Union

__all__ = [
    "QrTooLongError",
    "QrCode",
    "encode",
    "render_text",
    "ERROR_LEVELS",
]


class QrTooLongError(ValueError):
    """The input does not fit versions 1-10 at the requested level."""


#: error-correction level indicator bits (ISO/IEC 18004:2006 §8.4)
ERROR_LEVELS = {"L": 0b01, "M": 0b00, "Q": 0b11, "H": 0b10}
_SUPPORTED_LEVELS = ("L", "M")

# --- gf(256) arithmetic (primitive polynomial 0x11D) -----------------------

_GF_EXP: list[int] = [0] * 512
_GF_LOG: list[int] = [0] * 256


def _init_gf() -> None:
    value = 1
    for power in range(255):
        _GF_EXP[power] = value
        _GF_LOG[value] = power
        value <<= 1
        if value & 0x100:
            value ^= 0x11D
    for power in range(255, 512):
        _GF_EXP[power] = _GF_EXP[power - 255]


_init_gf()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs_generator(ec_len: int) -> list[int]:
    """The degree-``ec_len`` Reed-Solomon generator polynomial."""
    poly = [1]
    for i in range(ec_len):
        # multiply poly by (x - alpha^i): poly*x (append the zero of the
        # higher degree) plus alpha^i*poly aligned one degree lower (j+1)
        shifted = poly + [0]
        for j in range(len(poly)):
            shifted[j + 1] ^= _gf_mul(poly[j], _GF_EXP[i])
        poly = shifted
    return poly


def _rs_remainder(data: list[int], ec_len: int) -> list[int]:
    """The ``ec_len`` error-correction codewords for ``data``."""
    generator = _rs_generator(ec_len)
    work = list(data) + [0] * ec_len
    for start in range(len(data)):
        factor = work[start]
        if factor == 0:
            continue
        for offset in range(1, len(generator)):
            work[start + offset] ^= _gf_mul(generator[offset], factor)
    return work[len(data):]


# --- version tables (ISO/IEC 18004:2006 Tables 1-3; L and M, versions 1-10) --
#
# per version: (total codewords, ec codewords per block, block structure as
# (group blocks, data codewords per block) tuples)
_QR_VERSIONS: dict[str, list[tuple[int, int, tuple[tuple[int, int], ...]]]] = {
    "L": [
        (26, 7, ((1, 19),)),
        (44, 10, ((1, 34),)),
        (70, 15, ((1, 55),)),
        (100, 20, ((1, 80),)),
        (134, 26, ((1, 108),)),
        (172, 18, ((2, 68),)),
        (196, 20, ((2, 78),)),
        (242, 24, ((2, 97),)),
        (292, 30, ((2, 116),)),
        (346, 18, ((2, 68), (2, 69))),
    ],
    "M": [
        (26, 10, ((1, 16),)),
        (44, 16, ((1, 28),)),
        (70, 26, ((1, 44),)),
        (100, 18, ((2, 32),)),
        (134, 24, ((2, 43),)),
        (172, 16, ((4, 27),)),
        (196, 18, ((4, 31),)),
        (242, 22, ((2, 38), (2, 39))),
        (292, 22, ((3, 36), (2, 37))),
        (346, 26, ((4, 43), (1, 44))),
    ],
}

#: alignment-pattern center coordinates per version (Table 3)
_ALIGNMENT: list[list[int]] = [
    [],  # version 1 has none
    [6, 18],
    [6, 22],
    [6, 26],
    [6, 30],
    [6, 34],
    [6, 22, 38],
    [6, 24, 42],
    [6, 26, 46],
    [6, 28, 50],
]


def _data_codewords(version: int, level: str) -> int:
    _, _, blocks = _QR_VERSIONS[level][version - 1]
    return sum(count * per for count, per in blocks)


def _byte_capacity(version: int, level: str) -> int:
    """How many byte-mode characters fit (mode + count + terminator)."""
    count_bits = 8 if version <= 9 else 16
    available = _data_codewords(version, level) * 8
    return (available - 4 - count_bits) // 8


def _pick_version(payload: bytes, level: str) -> int:
    for version in range(1, 11):
        if len(payload) <= _byte_capacity(version, level):
            return version
    raise QrTooLongError(
        f"{len(payload)} bytes do not fit QR versions 1-10 at level {level} "
        f"(max {_byte_capacity(10, level)}); falling back to printing the URL"
    )


# --- bit buffer --------------------------------------------------------------

class _Bits:
    def __init__(self) -> None:
        self.bits: list[int] = []

    def put(self, value: int, length: int) -> None:
        for shift in range(length - 1, -1, -1):
            self.bits.append((value >> shift) & 1)

    def pad_to_codewords(self, total_bits: int) -> None:
        # terminator (up to 4 zero bits), bit padding to a byte, then the
        # standard 0xEC / 0x11 alternating pad codewords
        for _ in range(min(4, total_bits - len(self.bits))):
            self.bits.append(0)
        while len(self.bits) % 8:
            self.bits.append(0)
        pad = 0xEC
        codewords = total_bits // 8
        while len(self.bits) < codewords * 8:
            self.put(pad, 8)
            pad = 0xEC if pad == 0x11 else 0x11

    def bytes(self) -> list[int]:
        return [
            int("".join(str(b) for b in self.bits[i:i + 8]), 2)
            for i in range(0, len(self.bits), 8)
        ]


def _interleave(data: list[int], level: str, version: int) -> list[int]:
    """Split into blocks, add RS codewords, interleave per the spec."""
    total, ec_per_block, structure = _QR_VERSIONS[level][version - 1]
    blocks: list[list[int]] = []
    position = 0
    for count, per in structure:
        for _ in range(count):
            blocks.append(data[position:position + per])
            position += per
    ec_blocks = [_rs_remainder(block, ec_per_block) for block in blocks]
    out: list[int] = []
    max_len = max(len(block) for block in blocks)
    for i in range(max_len):
        for block in blocks:
            if i < len(block):
                out.append(block[i])
    for i in range(ec_per_block):
        for block in ec_blocks:
            out.append(block[i])
    assert len(out) == total, (len(out), total, version, level)
    return out


# --- matrix construction -------------------------------------------------------

def _mask_bit(mask: int, row: int, col: int) -> bool:
    if mask == 0:
        return (row + col) % 2 == 0
    if mask == 1:
        return row % 2 == 0
    if mask == 2:
        return col % 3 == 0
    if mask == 3:
        return (row + col) % 3 == 0
    if mask == 4:
        return (row // 2 + col // 3) % 2 == 0
    if mask == 5:
        return (row * col) % 2 + (row * col) % 3 == 0
    if mask == 6:
        return ((row * col) % 2 + (row * col) % 3) % 2 == 0
    return ((row + col) % 2 + (row * col) % 3) % 2 == 0


def _format_bits(level: str, mask: int) -> int:
    """The 15-bit format information (BCH(15,5), masked with 0x5412)."""
    value = (ERROR_LEVELS[level] << 3) | mask
    bch = value << 10
    generator = 0x537
    for shift in range(4, -1, -1):
        if bch & (1 << (shift + 10)):
            bch ^= generator << shift
    return ((value << 10) | (bch & 0x3FF)) ^ 0x5412


def _version_bits(version: int) -> int:
    """The 18-bit version information, BCH(18,6) — versions 7 and up."""
    bch = version << 12
    generator = 0x1F25
    for shift in range(5, -1, -1):
        if bch & (1 << (shift + 12)):
            bch ^= generator << shift
    return (version << 12) | (bch & 0xFFF)


def _place_format(matrix: list[list[bool]], reserved: list[list[bool]],
                  size: int, bits: Optional[int] = None) -> None:
    """Both copies of the format information; every module is reserved,
    including the light ones (the data walk must never touch them).

    ``bits=None`` is the mask-selection *test* build: every format module
    is written light, which is how the ``qrcode`` oracle scores its
    candidates (the format bits depend on the mask, so they are left out
    of that comparison).

    Position p (0 = most significant bit) -> its module, per ISO/IEC
    18004:2006 fig. 25 — the MSB sits at (8, 0) and the column-8 run of
    the second copy stops ABOVE the dark module (size-8, 8).
    """

    def dark(row: int, col: int, pos: int) -> None:
        matrix[row][col] = (
            bits is not None and ((bits >> (14 - pos)) & 1) == 1
        )
        reserved[row][col] = True

    for i in range(6):
        dark(8, i, i)
    dark(8, 7, 6)
    dark(8, 8, 7)
    dark(7, 8, 8)
    for i in range(9, 15):
        dark(14 - i, 8, i)
    for i in range(7):
        dark(size - 1 - i, 8, i)
    for i in range(7, 15):
        dark(8, size - 15 + i, i)


def _build_matrix(version: int, level: str, codewords: list[int], mask: int,
                  *, test_format: bool = False) -> list[list[bool]]:
    size = 17 + 4 * version
    # True = dark module
    matrix = [[False] * size for _ in range(size)]
    reserved = [[False] * size for _ in range(size)]

    def set_module(row: int, col: int, dark: bool) -> None:
        matrix[row][col] = dark
        reserved[row][col] = True

    # finder patterns + separators (three corners): a 7x7 ring-with-center
    # and a one-module light separator ring around it
    for row, col in ((0, 0), (0, size - 7), (size - 7, 0)):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                r, c = row + dr, col + dc
                if 0 <= r < size and 0 <= c < size:
                    in_core = 0 <= dr <= 6 and 0 <= dc <= 6
                    on_edge = dr in (0, 6) or dc in (0, 6)
                    center = 2 <= dr <= 4 and 2 <= dc <= 4
                    set_module(r, c, in_core and (on_edge or center))

    # timing patterns
    for i in range(8, size - 8):
        set_module(6, i, i % 2 == 0)
        set_module(i, 6, i % 2 == 0)

    # alignment patterns (skip the three that would touch a finder)
    centers = _ALIGNMENT[version - 1]
    for row in centers:
        for col in centers:
            near_finder = (
                (row < 9 and col < 9)
                or (row < 9 and col > size - 10)
                or (row > size - 10 and col < 9)
            )
            if near_finder:
                continue
            for dr in (-2, -1, 0, 1, 2):
                for dc in (-2, -1, 0, 1, 2):
                    ring = max(abs(dr), abs(dc))
                    set_module(row + dr, col + dc, ring != 1)

    # dark module + format information (every format module is reserved).
    # test_format leaves them light for the mask-selection comparison, the
    # same way the golden oracle builds its test matrices.
    set_module(size - 8, 8, not test_format)
    _place_format(
        matrix, reserved, size,
        None if test_format else _format_bits(level, mask),
    )

    # version information (versions 7+): two 3x6 blocks
    if version >= 7:
        bits = _version_bits(version)
        for i in range(18):
            bit = ((bits >> i) & 1) == 1
            row, col = i // 3, i % 3
            set_module(row, col + size - 11, bit)   # top-right block
            set_module(col + size - 11, row, bit)   # bottom-left block

    # data placement: two-column strips, right to left, skipping column 6
    bit_index = 0
    total_bits = len(codewords) * 8
    upward = True
    col = size - 1
    while col > 0:
        if col == 6:
            col -= 1
            continue
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for c in (col, col - 1):
                if reserved[row][c]:
                    continue
                bit = False
                if bit_index < total_bits:
                    bit = ((codewords[bit_index // 8] >> (7 - bit_index % 8)) & 1) == 1
                bit_index += 1
                if _mask_bit(mask, row, c):
                    bit = not bit
                matrix[row][c] = bit
        upward = not upward
        col -= 2

    return matrix


# --- penalty scoring (ISO/IEC 18004:2006 §8.8.2) ------------------------------

def _penalty(matrix: list[list[bool]]) -> int:
    """ISO/IEC 18004:2006 §8.8.2 penalty, rule for rule.

    The four rules are scored exactly the way the ``qrcode`` library (the
    committed golden oracle) scores them, so the auto-mask choice matches
    its on every recorded vector: runs score ``length - 2`` for
    ``length >= 5``, 2x2 blocks 3, each finder-like ``1011101`` with a
    four-module light run on a side 40 (scanned as the two full 11-module
    patterns, including the library's skip-after-dark-tail, which makes
    overlapping occurrences non-counting), and the dark proportion
    ``10 * int(abs(percent - 50) // 5)``.
    """
    size = len(matrix)
    score = 0

    # rule 1: runs of five or more same-color modules in rows and columns
    runs: dict[int, int] = {}
    lines = [matrix[r] for r in range(size)]
    lines += [[matrix[r][c] for r in range(size)] for c in range(size)]
    for line in lines:
        length = 0
        previous = line[0]
        for cell in line:
            if cell == previous:
                length += 1
            else:
                if length >= 5:
                    runs[length] = runs.get(length, 0) + 1
                length = 1
                previous = cell
        if length >= 5:
            runs[length] = runs.get(length, 0) + 1
    score += sum(count * (length - 2) for length, count in runs.items())

    # rule 2: 2x2 blocks of one color (3 each). When the two right-hand
    # corners disagree, the next column cannot complete a block either, so
    # the library skips it (iterator-identical, no count change).
    for row in range(size - 1):
        line = matrix[row]
        nxt = matrix[row + 1]
        col = 0
        while col < size - 1:
            top_right = line[col + 1]
            if top_right != nxt[col + 1]:
                col += 2
                continue
            if top_right == line[col] and top_right == nxt[col]:
                score += 3
            col += 1

    # rule 3: the two 11-module patterns 1011101+0000 and 0000+1011101
    # (40 each, rows and columns); after examining a window whose last
    # module is dark, the library skips the next position (Horspool skip),
    # which is why overlapping occurrences do not double-count
    for axis in range(2):
        for fixed in range(size):
            pos = 0
            while pos <= size - 11:
                window = tuple(
                    matrix[fixed][pos + k] if axis == 0
                    else matrix[pos + k][fixed]
                    for k in range(11)
                )
                if _finder_like(window):
                    score += 40
                if window[10]:
                    pos += 2
                else:
                    pos += 1

    # rule 4: dark-module proportion deviation from 50%
    dark = sum(sum(1 for cell in row if cell) for row in matrix)
    percent = dark * 100 / (size * size)
    score += 10 * int(abs(percent - 50) // 5)
    return score


def _finder_like(window: tuple[bool, ...]) -> bool:
    """Rule 3's two patterns: ``1011101 0000`` and ``0000 1011101``."""
    dark = (True, False, True, True, True, False, True)
    light = (False, False, False, False)
    return (
        window[:7] == dark and window[7:] == light
    ) or (
        window[:4] == light and window[4:] == dark
    )


# --- the public encoder ---------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class QrCode:
    """One encoded QR: the module matrix plus the parameters chosen."""

    matrix: tuple[tuple[bool, ...], ...]
    version: int
    error: str
    mask: int

    @property
    def size(self) -> int:
        return len(self.matrix)


def _build(payload: bytes, level: str, version: Optional[int] = None,
           mask: Optional[int] = None) -> QrCode:
    if level not in _SUPPORTED_LEVELS:
        raise ValueError(f"error level {level!r} is not built in (L or M)")
    data = bytes(payload if isinstance(payload, bytes) else payload.encode("utf-8"))
    version = version or _pick_version(data, level)
    if not 1 <= version <= 10:
        raise ValueError(f"only versions 1-10 are built in, got {version}")
    if len(data) > _byte_capacity(version, level):
        raise QrTooLongError(
            f"{len(data)} bytes exceed version {version} level {level} "
            f"capacity {_byte_capacity(version, level)}"
        )
    count_bits = 8 if version <= 9 else 16
    bits = _Bits()
    bits.put(0b0100, 4)  # byte mode
    bits.put(len(data), count_bits)
    for byte in data:
        bits.put(byte, 8)
    total, _, _ = _QR_VERSIONS[level][version - 1]
    bits.pad_to_codewords(_data_codewords(version, level) * 8)
    codewords = _interleave(bits.bytes(), level, version)
    assert len(codewords) == total

    if mask is not None:
        if not 0 <= mask <= 7:
            raise ValueError(f"mask must be 0-7, got {mask}")
        built = _build_matrix(version, level, codewords, mask)
    else:
        # cheapest of the eight ISO masks; ties keep the lowest number.
        # Candidates are scored on the test build (format info light),
        # exactly like the qrcode oracle's best_mask_pattern.
        best: Optional[tuple[int, int, list[list[bool]]]] = None
        for candidate in range(8):
            score = _penalty(
                _build_matrix(
                    version, level, codewords, candidate, test_format=True
                )
            )
            if best is None or score < best[0]:
                best = (score, candidate, None)
        assert best is not None
        mask = best[1]
        built = _build_matrix(version, level, codewords, mask)
    return QrCode(
        matrix=tuple(tuple(row) for row in built),
        version=version,
        error=level,
        mask=mask,
    )


def encode(data: Union[str, bytes], *, error: str = "M",
           version: Optional[int] = None, mask: Optional[int] = None) -> QrCode:
    """Encode ``data`` (byte mode) into a QR of versions 1-10.

    Picks the smallest version that fits at ``error`` level ("L" or "M")
    unless ``version`` is forced, and the cheapest of the eight ISO masks
    unless ``mask`` is forced (ties: the lowest mask number).  Raises
    :class:`QrTooLongError` when even version 10 is not enough — callers
    fall back to showing the raw text.
    """
    return _build(
        data if isinstance(data, bytes) else data.encode("utf-8"),
        error.upper(),
        version,
        mask,
    )


# --- terminal rendering -----------------------------------------------------------

_HALF_BLOCKS = {
    (True, True): "█",
    (True, False): "▀",
    (False, True): "▄",
    (False, False): " ",
}


def render_text(matrix: Union[list[list[bool]], tuple[tuple[bool, ...], ...]],
                *, invert: bool = False, border: int = 4) -> str:
    """Render a module matrix as terminal half-block text.

    ``True`` in the matrix is a dark module.  Two module rows become one
    text line (``▀ ▄ █``) inside a ``border``-module quiet zone (light:
    blanks, or blocks when ``invert=True``).  ``invert=True`` swaps dark and
    light — for light-on-dark terminals that often scans better.
    """
    modules = [tuple(row) for row in matrix]
    inner = len(modules)
    size = inner + 2 * border

    def dark_at(row: int, col: int) -> bool:
        r, c = row - border, col - border
        inside = 0 <= r < inner and 0 <= c < inner
        if not inside:
            return invert  # the quiet zone is light (blank unless inverted)
        return not modules[r][c] if invert else modules[r][c]

    lines = []
    for row in range(0, size, 2):
        cells = [
            _HALF_BLOCKS[(dark_at(row, col), dark_at(row + 1, col))]
            for col in range(size)
        ]
        lines.append("".join(cells))
    return "\n".join(lines)
