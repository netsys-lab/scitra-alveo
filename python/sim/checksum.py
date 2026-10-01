# SPDX-License-Identifier: AGPL-3.0-or-later

import array
from scapy.utils import checksum_endian_transform


def ones_complement_sum16(pkt: bytes) -> int:
    ary = array.array("H", pkt if len(pkt) % 2 == 0 else pkt + b"\x00")
    s = sum(ary)
    while (s & ~0xffff) != 0:
        s = (s >> 16) + (s & 0xffff)
    return checksum_endian_transform(s) & 0xffff
