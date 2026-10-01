# SPDX-License-Identifier: AGPL-3.0-or-later

from sim import base
from sim.checksum import ones_complement_sum16

from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.inet6 import ICMPv6EchoReply, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy_scion.layers.scion import UDP


class IngrClassifierTest(base.BMVitisP4TestCase):

    def setUp(self):
        super().setUp("build/egress-checksum.json")

    @base.dump_log_on_fail
    def test_arp(self):
        """Test ARP packets"""
        in_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:02") / ARP()
        in_pkt = Ether(bytes(in_pkt))
        in_meta = {
            "metadata_t.payload_chksum": 0,
        }

        out_pkts, _ = self.runtime.send_packets([in_pkt], [in_meta])
        out = out_pkts[0]
        self.assertGreater(len(out), 0, "packet dropped")
        self.assertPacket(Ether(out), in_pkt, "packet corrupted")

    @base.dump_log_on_fail
    def test_ipv4(self):
        """Test checksum calculation in IPv4 packets"""
        in_pkt = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkt /= IP(dst="10.0.0.1", src="10.0.0.2", chksum=0)
        in_pkts = [
            Ether(bytes(in_pkt / TCP(dport=43000, sport=44000, chksum=0) / Raw(b"payload"))),
            Ether(bytes(in_pkt / UDP(dport=43000, sport=44000, chksum=0) / Raw(b"payload"))),
            Ether(bytes(in_pkt / ICMP(chksum=0))),
        ]
        in_meta = [
            {
                "metadata_t.payload_chksum":
                    ones_complement_sum16(bytes(pkt[IP].payload)),
            } for pkt in in_pkts
        ]

        # Compute expected checksums
        expected = []
        for pkt in in_pkts:
            del pkt[IP].chksum
            del pkt[IP].payload.chksum
            expected.append(Ether(bytes(pkt)))

        out_pkts, _ = self.runtime.send_packets(in_pkts, in_meta)
        self.assertEqual(len(out_pkts), len(expected))
        for out, exp in zip(out_pkts, expected):
            self.assertGreater(len(out), 0, "packet dropped")
            self.assertPacket(Ether(out), exp, "packet corrupted")

    @base.dump_log_on_fail
    def test_ipv6(self):
        """Test checksum calculation in IPv6 packets"""
        in_pkt = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkt /= IPv6(dst="fd00:f00d:cafe::1", src="fd00:f00d:cafe::2")
        in_pkts = [
            Ether(bytes(in_pkt / TCP(dport=43000, sport=44000, chksum=0) / Raw(b"payload"))),
            Ether(bytes(in_pkt / UDP(dport=43000, sport=44000, chksum=0) / Raw(b"payload"))),
            Ether(bytes(in_pkt / ICMPv6EchoReply(cksum=0))),
        ]
        expected = [
            Ether(bytes(in_pkt / TCP(dport=43000, sport=44000) / Raw(b"payload"))),
            Ether(bytes(in_pkt / UDP(dport=43000, sport=44000) / Raw(b"payload"))),
            Ether(bytes(in_pkt / ICMPv6EchoReply())),
        ]
        in_meta = [
            {
                "metadata_t.payload_chksum":
                    ones_complement_sum16(bytes(pkt[IPv6].payload)),
            } for pkt in in_pkts
        ]

        out_pkts, _ = self.runtime.send_packets(in_pkts, in_meta)
        self.assertEqual(len(out_pkts), len(expected))
        for out, exp in zip(out_pkts, expected):
            self.assertGreater(len(out), 0, "packet dropped")
            self.assertPacket(Ether(out), exp, "packet corrupted")
