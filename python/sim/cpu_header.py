# SPDX-License-Identifier: AGPL-3.0-or-later

from scapy.fields import BitField, ByteField
from scapy.packet import Packet, bind_layers
from scapy_scion.layers.scion import UDP

CPU_PORT = 13666
TO_CPU_REASON_INGRESS_SCMP = 1
TO_CPU_REASON_EGRESS_SCMP = 2
TO_CPU_REASON_EGRESS_ICMP = 3
TO_CPU_REASON_EGRESS_NEW_FLOW = 4


class CPUMetadata(Packet):
    """Metadata for CPU"""

    name = "CPU Metadata"

    fields_desc = [
        ByteField("reason", default=0),
        BitField("reserved", size=24, default=0),
    ]


bind_layers(UDP, CPUMetadata, dport=CPU_PORT)
