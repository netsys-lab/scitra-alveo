#!/bin/env python

import argparse
from ipaddress import IPv4Address, IPv6Address
from typing import Dict, List

from sim.addr_mapping import encode_ipv4, encode_ipv6
from sim.scion import IsdAsn

from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.inet6 import (
    ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6ND_NA, ICMPv6PacketTooBig, IPv6,
)
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.sendrecv import sendp

from scapy_scion.layers.scion import (
    SCION, UDP, EmptyPath, HopField, InfoField, SCIONPath,
)
from scapy_scion.layers.scmp import (
    SCMP, ScmpEchoReply, ScmpEchoRequest, ScmpPacketTooBig,
)


ALVEO_MAC = "00:0a:35:6f:15:ce"
CONNECTX_MAC = "08:c0:eb:d1:d0:36"

ALVEO_IP4 = "10.80.0.1"
CONNECTX_IP4 = "10.80.0.2"

LOCAL_AS = IsdAsn("1-64513")
REMOTE_AS = IsdAsn("1-64514")
REMOTE_IP4 = IPv4Address("127.0.0.1")
BR_PORT = 32768

# ARP request from ConnectX for Alveo
pkt_arp = Ether(dst="ff:ff:ff:ff:ff:ff", src=CONNECTX_MAC)
pkt_arp /= ARP(hwsrc=CONNECTX_MAC, psrc=CONNECTX_IP4, pdst=ALVEO_IP4)


# ICMP echo request (not translatable)
pkt_icmp_echo = Ether(dst=ALVEO_MAC, src=CONNECTX_MAC)
pkt_icmp_echo /= IP(dst=ALVEO_IP4, src=CONNECTX_IP4)
pkt_icmp_echo /= ICMP(id=0xa1e0, seq=1)


# SCION packet from remote AS
pkt_scion = Ether(dst=ALVEO_MAC, src=CONNECTX_MAC)
pkt_scion /= IP(dst=ALVEO_IP4, src=CONNECTX_IP4)
pkt_scion /= UDP(dport=32000, sport=BR_PORT)
pkt_scion /= SCION(
    dst_isd = LOCAL_AS.isd,
    dst_asn = int(LOCAL_AS.asn),
    src_isd = REMOTE_AS.isd,
    src_asn = int(REMOTE_AS.asn),
    dst_host = ALVEO_IP4,
    src_host = REMOTE_IP4,
    path = SCIONPath(
        seg0_len=2,
        seg1_len=2,
        seg2_len=0,
        info_fields=[
            InfoField(), InfoField()
        ],
        hop_fields=[
            HopField(), HopField(), HopField(), HopField()
        ]
    )
)
pkt_scion /= UDP(dport=32000, sport=8000)
pkt_scion /= r"PAYLOAD"


packets: Dict[str, List[Packet]] = {
    "arp": [pkt_arp],
    "echo": [pkt_icmp_echo],
    "scion": [pkt_scion],
}
packets["all"] = [x for xs in packets.values() for x in xs]


def main():
    parser = argparse.ArgumentParser("Send test packets to OpenNIC Shell")
    parser.add_argument("-i", "--interface", default="enp129s0np0",
        help="Network interface that is directly connected to the FPGA")
    parser.add_argument("packet", choices=list(packets.keys()),
        help="Type of packet to send. 'all' sends all available packets.")
    args = parser.parse_args()

    for p in packets[args.packet]:
        print(f"Sending {p.summary()}")
        sendp(p, iface=args.interface)


if __name__ == "__main__":
    main()
