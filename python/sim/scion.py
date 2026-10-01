# SPDX-License-Identifier: AGPL-3.0-or-later

from typing import Tuple, Union


class Asn:
    """Represents an AS number (without the ISD part)."""
    BITS = 48
    MAX_VALUE = (1 << BITS) - 1
    BGP_ASN_BITS = 32
    MAX_BGP_ASN = (1 << BGP_ASN_BITS) - 1
    GROUP_BITS = 16
    GROUP_MAX_VALUE = (1 << GROUP_BITS) - 1

    def __init__(self, initializer: Union[int, str]):
        """Initialize from an ASN string or a numerical representation.

        ### Exceptions ###
        ValueError: Initializer not recognized as a valid ASN.
        """
        if isinstance(initializer, int):
            if initializer < 0 or initializer > self.MAX_VALUE:
                raise ValueError("Invalid ASN. (Out of range)")
            self.asn_int = initializer
        elif isinstance(initializer, str):
            parts = initializer.split(":")
            if len(parts) == 1:
                # Expect decimal AS number (BGP style)
                self.asn_int = int(parts[0])
                if self.asn_int < 0 or self.asn_int > self.MAX_BGP_ASN:
                    raise ValueError("Invalid decimal ASN.")
            elif len(parts) == 3:
                # Hexadecimal AS number in three 16 bit groups
                self.asn_int = 0
                for group in parts:
                    self.asn_int <<= self.GROUP_BITS
                    group_value = int(group, base=16)
                    if group_value < 0 or group_value > self.GROUP_MAX_VALUE:
                        raise ValueError("Invalid hexadecimal ASN. (Invalid group value)")
                    self.asn_int |= group_value
            else:
                raise ValueError("Invalid ASN. (Wrong number of colon-separated groups)")
        else:
            raise ValueError("Invalid initializer type for ASN.")

    def __int__(self):
        return self.asn_int

    def __str__(self):
        if self.asn_int <= self.MAX_BGP_ASN:
            # BGP style ASN
            return str(self.asn_int)
        else:
            # SCION style hexadecimal ASN in three groups
            return "%x:%x:%x" % (
                (self.asn_int >> 2 * self.GROUP_BITS) & self.GROUP_MAX_VALUE,
                (self.asn_int >> self.GROUP_BITS) & self.GROUP_MAX_VALUE,
                (self.asn_int) & self.GROUP_MAX_VALUE
            )

    def __repr__(self):
        return 'ASN("%s")' % self.__str__()

    @classmethod
    def from_bytes(cls, bytes) -> 'Asn':
        return Asn(int.from_bytes(bytes[:cls.BITS // 8], byteorder='big'))

    def to_bytes(self) -> bytes:
        return self.asn_int.to_bytes(self.BITS // 8, byteorder='big')

    def __eq__(self, other):
        if type(self) != type(other):
            return False
        else:
            return self.asn_int == other.asn_int

    def __hash__(self):
        return hash(self.asn_int)


class IsdAsn:
    def __init__(self, init: Union[int, str, Tuple[int, Asn]]):
        """SCION AS address.
        """
        if isinstance(init, int):
            self.isd = (init >> 16) & 0xffff
            self.asn = Asn(init & Asn.MAX_VALUE)
        elif isinstance(init, str):
            isd, asn = _split_isd_asn(init)
            self.isd = int(isd)
            self.asn = Asn(asn)
        elif isinstance(init, tuple):
            self.isd, self.asn = init
        else:
            raise ValueError("invalid initializer type for IsdAsn")

    def __int__(self):
        return (self.isd << Asn.BITS) | int(self.asn)

    def __str__(self):
        return f"{self.isd}-{self.asn}"

    def __repr__(self):
        return f"IsdAsn({self})"

    def __hash__(self):
        return hash((self.isd, self.asn))


def _split_isd_asn(s: str) -> Tuple[str, str]:
    hyphen = s.index("-")
    return s[:hyphen], s[hyphen+1:]
