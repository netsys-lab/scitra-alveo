# SPDX-License-Identifier: AGPL-3.0-or-later

from typing import Tuple
from ipaddress import IPv4Address, IPv6Address, IPv6Network

from .scion import IsdAsn


SCION_PREFIX_LEN = 8
SCION_PREFIX = 0xfc << (128 - SCION_PREFIX_LEN)
SCION_NETWORK = IPv6Network((SCION_PREFIX, SCION_PREFIX_LEN))

def _parse_hex(raw: str, length: int) -> int:
    def parse(raw: str):
        if raw == "":
            return 0, 0
        n = 0
        groups = [int(group, base=16) for group in raw.split(":")]
        for group in groups:
            if 0 <= group <= 0xffff:
                n <<= 16
                n |= group
            else:
                raise ValueError("invalid hex string")
        return n, len(groups)

    n = 0
    parts = raw.split("::")
    if len(parts) > 2:
        raise ValueError(":: may appear only once")

    length_groups = (length + 15) // 16
    n_lo, _ = parse(parts[-1])
    n_hi, groups_hi = parse(parts[-2]) if len(parts) > 1 else (0, 0)

    if length_groups - groups_hi < 0:
        raise ValueError("invalid number of groups")
    n_hi <<= (16 * (length_groups - groups_hi))
    n = n_hi | n_lo
    if n.bit_length() > length:
        raise ValueError("number too large")
    return n


def encode_ia(ia: IsdAsn) -> Tuple[int, int]:
    """Encode SCION ISD-ASN address to an IPv6 prefix"""
    if not 0 <= ia.isd < 2**12:
        raise ValueError("ISD cannot be encoded")
    if int(ia.asn) < 2**19:
        ip = SCION_PREFIX | (ia.isd << 108) | (int(ia.asn) << 88)
        prefix_len = 40
    elif 0x2_0000_0000 <= int(ia.asn) <= 0x2_ffff_ffff:
        ip = SCION_PREFIX | (ia.isd << 108) | (0xe << 104) | ((int(ia.asn) & 0xffff_ffff) << 72)
        prefix_len = 56
    else:
        raise ValueError("ASN cannot be encoded")
    return ip, prefix_len


def encode_ipv4(ia: IsdAsn, interface: IPv4Address) -> IPv6Address:
    """Encode SCION ISD-ASN and IPv4 address to SCION-IPv4-mapped IPv6 address"""
    ip, _ = encode_ia(ia)
    ip |= 0xffff << 32
    ip |= int.from_bytes(interface.packed, "big")
    return IPv6Address(ip)


def encode_ipv6(ia: IsdAsn, local_prefix: int, subnet: int, interface: int|str,
                subnet_bits: int = 8) -> IPv6Address:
    """Encode SCION ISD-ASN and IPv6 interface to SCION-mapped IPv6 address"""
    ip, prefix_len = encode_ia(ia)
    local_prefix_len = 64 - prefix_len

    assert local_prefix.bit_length() <= (local_prefix_len - subnet_bits)
    assert subnet.bit_length() <= subnet_bits
    local_prefix = (local_prefix << subnet_bits) | (subnet & ~(~0 << subnet_bits))

    ip |= local_prefix << 64
    if isinstance(interface, str):
        ip |= _parse_hex(interface, 64)
    else:
        assert interface < 2**64
        ip |= interface
    return IPv6Address(ip)
