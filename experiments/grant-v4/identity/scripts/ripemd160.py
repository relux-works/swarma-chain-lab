"""Dependency-free RIPEMD-160 for the independent identity reader.

Implements the published pseudocode, using 32-bit words in two parallel lanes:
https://homes.esat.kuleuven.be/~bosselae/ripemd/rmd160.txt
This one-shot implementation is for bounded offline checks, not secret inputs.
"""

import struct

_MASK = 0xffffffff
_LEFT_WORDS = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8),
    (3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12),
    (1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2),
    (4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13),
)
_RIGHT_WORDS = (
    (5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12),
    (6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2),
    (15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13),
    (8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14),
    (12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11),
)
_LEFT_SHIFTS = (
    (11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8),
    (7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12),
    (11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5),
    (11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12),
    (9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6),
)
_RIGHT_SHIFTS = (
    (8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6),
    (9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11),
    (9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5),
    (15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8),
    (8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11),
)
_LEFT_CONSTANTS = (0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e)
_RIGHT_CONSTANTS = (0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0)


def _rotate(word, count):
    word &= _MASK
    return ((word << count) | (word >> (32 - count))) & _MASK


def _round(group, x, y, z):
    if group == 0:
        return x ^ y ^ z
    if group == 1:
        return (x & y) | (~x & z)
    if group == 2:
        return (x | ~y) ^ z
    if group == 3:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def ripemd160(data):
    """Return the 20 digest bytes for a byte string, without a hash provider."""
    bit_length = len(data) * 8
    padded = data + b"\x80" + bytes((55 - len(data)) % 64)
    padded += struct.pack("<Q", bit_length)
    state = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)
    for offset in range(0, len(padded), 64):
        words = struct.unpack_from("<16I", padded, offset)
        a, b, c, d, e = state
        aa, bb, cc, dd, ee = state
        for group in range(5):
            for step in range(16):
                value = a + _round(group, b, c, d) + words[_LEFT_WORDS[group][step]] + _LEFT_CONSTANTS[group]
                value = (_rotate(value, _LEFT_SHIFTS[group][step]) + e) & _MASK
                a, b, c, d, e = e, value, b, _rotate(c, 10), d
                value = aa + _round(4 - group, bb, cc, dd) + words[_RIGHT_WORDS[group][step]] + _RIGHT_CONSTANTS[group]
                value = (_rotate(value, _RIGHT_SHIFTS[group][step]) + ee) & _MASK
                aa, bb, cc, dd, ee = ee, value, bb, _rotate(cc, 10), dd
        state = (
            (state[1] + c + dd) & _MASK,
            (state[2] + d + ee) & _MASK,
            (state[3] + e + aa) & _MASK,
            (state[4] + a + bb) & _MASK,
            (state[0] + b + cc) & _MASK,
        )
    return struct.pack("<5I", *state)
