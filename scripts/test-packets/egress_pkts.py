#!/bin/env python

import argparse
from typing import Dict, List
from ipaddress import IPv4Address, IPv6Address

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
GATEWAY_MAC = "ff:ff:ff:ff:ff:ff"

# ARP request from Alveo for ConnectX
pkt_arp = Ether(dst="ff:ff:ff:ff:ff:ff", src=ALVEO_MAC)
pkt_arp /= ARP(hwsrc=ALVEO_MAC, psrc=ALVEO_IP4, pdst=CONNECTX_IP4)


# ICMP echo request (not translatable)
pkt_icmp_echo = Ether(dst=CONNECTX_MAC, src=ALVEO_MAC)
pkt_icmp_echo /= IP(dst=CONNECTX_IP4, src=ALVEO_IP4)
pkt_icmp_echo /= ICMP(id=0xa1e0, seq=1)


# Translatable IPv6 packet (not AS local)
pkt_translate = Ether(dst=GATEWAY_MAC, src=ALVEO_MAC)
pkt_translate /= IPv6(dst=encode_ipv4(REMOTE_AS, REMOTE_IP4),
                      src=encode_ipv4(LOCAL_AS, IPv4Address(ALVEO_IP4)))
pkt_translate /= UDP(dport=8000, sport=32000)
pkt_translate /= r"PAYLOAD"


packets: Dict[str, List[Packet]] = {
    "arp": [pkt_arp],
    "echo": [pkt_icmp_echo],
    "translate": [pkt_translate],
}
packets["all"] = [x for xs in packets.values() for x in xs]


def main():
    parser = argparse.ArgumentParser("Send test packets from OpenNIC Shell")
    parser.add_argument("-i", "--interface", default="enp179s0",
        help="ONIC network interface")
    parser.add_argument("packet", choices=list(packets.keys()),
        help="Type of packet to send. 'all' sends all available packets.")
    args = parser.parse_args()

    for p in packets[args.packet]:
        print(f"Sending {p.summary()}")
        sendp(p, iface=args.interface)


if __name__ == "__main__":
    main()
