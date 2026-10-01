# SPDX-License-Identifier: AGPL-3.0-or-later

from sim import base

from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.inet6 import ICMPv6EchoReply, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy_scion.layers.scion import SCION, UDP, HopField, InfoField, SCIONPath

CNT_DROPPED = 0
CNT_OTHER = 1
CNT_TOTAL_IPV4 = 2
CNT_TOTAL_IPV6 = 3
CNT_SCION_IPV4 = 4
CNT_SCION_IPV6 = 5


class IngrClassifierTest(base.BMVitisP4TestCase):

    def setUp(self):
        super().setUp("build/ingress-classifier.json")

    def program_tables(self):
        self.runtime.table_add("tab_local_addr_ipv4", ["10.0.0.1"], "NoAction", [])
        self.runtime.table_add("tab_local_addr_ipv6", ["fd00:f00d:cafe::1"], "NoAction", [])
        self.runtime.table_add("tab_static_ports_ipv4", ["31000"], "static_ipv4_is_scion", [])
        self.runtime.table_add("tab_static_ports_ipv6", ["31000"], "static_ipv6_is_scion", [])
        self.runtime.table_add("tab_dynamic_ports_ipv4", [
            "10.0.0.2",
            "44026",
            "80"
        ], "dynamic_ipv4_is_scion", [hex(0)])
        self.runtime.table_add("tab_dynamic_ports_ipv6", [
            "fd00:f00d:cafe::2",
            "48026",
            "80"
        ], "dynamic_ipv6_is_scion", [hex(0)])

    @base.dump_log_on_fail
    def test_arp(self):
        """Test ARP packets"""
        in_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:02") / ARP()
        in_pkt = Ether(bytes(in_pkt))
        in_meta = {"metadata_t.tuser_size": len(in_pkt)}

        self.program_tables()
        out_pkts, out_meta = self.runtime.send_packets([in_pkt], [in_meta])
        out = out_pkts[0]
        meta = out_meta[0]
        self.assertGreater(len(out), 0, "packet dropped")
        self.assertPacket(Ether(out), in_pkt, "packet corrupted")
        self.assertEqual(meta["metadata_t.tuser_size"], len(in_pkt), "wrong size metadata")
        self.assertEqual(meta["metadata_t.is_scion"], 0, "packet misclassified")
        self.assertEqual(meta["metadata_t.payload_offset"], 1023, "wrong payload offset")
        self.assertEqual(self.runtime.counter_read("cnt_packets", CNT_OTHER), 1)

    @base.dump_log_on_fail
    def test_pass_ipv4(self):
        """Test IPv4 packet that don't contain a SCION header"""
        in_pkt = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkt /= IP(dst="10.0.0.1", src="10.0.0.2")
        in_pkts = [
            Ether(bytes(in_pkt / TCP(dport=80, sport=44000) / Raw(b"payload"))),
            Ether(bytes(in_pkt / UDP(dport=80, sport=44000) / Raw(b"payload"))),
            Ether(bytes(in_pkt / ICMP())),
        ]
        in_meta = [{"metadata_t.tuser_size": len(pkt)} for pkt in in_pkts]

        self.program_tables()
        out_pkts, out_meta = self.runtime.send_packets(in_pkts, in_meta)
        self.assertEqual(len(out_pkts), len(in_pkts))
        for out, meta, exp in zip(out_pkts, out_meta, in_pkts):
            self.assertPacket(Ether(out), exp, "packet corrupted")
            self.assertEqual(meta["metadata_t.tuser_size"], len(exp), "wrong size metadata")
            self.assertEqual(meta["metadata_t.is_scion"], 0, "packet misclassified")
            self.assertEqual(meta["metadata_t.payload_offset"], 34, "wrong payload offset")
        self.assertEqual(self.runtime.counter_read("cnt_packets", CNT_TOTAL_IPV4), 3)
        self.assertEqual(self.runtime.counter_read("cnt_packets", CNT_TOTAL_IPV6), 0)

    @base.dump_log_on_fail
    def test_pass_ipv6(self):
        """Test IPv6 packets that don't contain a SCION header"""
        in_pkt = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkt /= IPv6(dst="fd00:f00d:cafe::1", src="fd00:f00d:cafe::2")
        in_pkts = [
            Ether(bytes(in_pkt / TCP(dport=80, sport=44000) / Raw(b"payload"))),
            Ether(bytes(in_pkt / UDP(dport=80, sport=44000) / Raw(b"payload"))),
            Ether(bytes(in_pkt / ICMPv6EchoReply())),
        ]
        in_meta = [{"metadata_t.tuser_size": len(pkt)} for pkt in in_pkts]

        self.program_tables()
        out_pkts, out_meta = self.runtime.send_packets(in_pkts, in_meta)
        self.assertEqual(len(out_pkts), len(in_pkts))
        for out, meta, exp in zip(out_pkts, out_meta, in_pkts):
            self.assertPacket(Ether(out), exp, "packet corrupted")
            self.assertEqual(meta["metadata_t.tuser_size"], len(exp), "wrong size metadata")
            self.assertEqual(meta["metadata_t.is_scion"], 0, "packet misclassified")
            self.assertEqual(meta["metadata_t.payload_offset"], 54, "wrong payload offset")
        self.assertEqual(self.runtime.counter_read("cnt_packets", CNT_TOTAL_IPV4), 0)
        self.assertEqual(self.runtime.counter_read("cnt_packets", CNT_TOTAL_IPV6), 3)

    def test_corruptIPv4(self):
        """Test whether packets with incorrect IPv4 header are dropped"""
        in_pkt = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkt /= IP(dst="10.0.0.1", src="10.0.0.2", chksum=0)
        in_pkt /= UDP(dport=80, sport=44000)
        in_pkt /= Raw(b"payload")
        in_pkt = Ether(bytes(in_pkt))
        in_meta = {"metadata_t.size": len(in_pkt)}

        self.program_tables()
        out, out_meta = self.runtime.send_packets([in_pkt], [in_meta])
        self.assertEqual(len(out[0]), 0, "packet should have been dropped")
        self.assertEqual(self.runtime.counter_read("cnt_packets", CNT_DROPPED), 1)

    @base.dump_log_on_fail
    def test_static_ports(self):
        """SCION packets to be classified as such due to a static mapping"""
        in_pkts = [None, None]
        # IPv4
        in_pkts[0] = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkts[0] /= IP(dst="10.0.0.1", src="10.0.0.2")
        in_pkts[0] /= UDP(dport=31000, sport=44000)
        in_pkts[0] /= SCION(
            path=SCIONPath(
                seg0_len=3,
                seg1_len=0,
                seg2_len=0,
                info_fields=[
                    InfoField(flags="C")
                ],
                hop_fields=[
                    HopField(cons_ingress=1, cons_egress=2),
                    HopField(cons_ingress=1, cons_egress=2),
                    HopField(cons_ingress=1, cons_egress=2)
                ]
            )
        )
        in_pkts[0] /= in_pkts[0]/UDP(dport=80)/Raw("payload")
        in_pkts[0] = Ether(bytes(in_pkts[0]))

        # IPv6
        in_pkts[1] = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkts[1] /= IPv6(dst="fd00:f00d:cafe::1", src="fd00:f00d:cafe::2")
        in_pkts[1] /= UDP(dport=31000, sport=48026)
        in_pkts[1] /= SCION(
            path=SCIONPath(
                seg0_len=3,
                seg1_len=0,
                seg2_len=0,
                info_fields=[
                    InfoField(flags="C")
                ],
                hop_fields=[
                    HopField(cons_ingress=1, cons_egress=2),
                    HopField(cons_ingress=1, cons_egress=2),
                    HopField(cons_ingress=1, cons_egress=2)
                ]
            )
        )
        in_pkts[1] /= in_pkts[1]/UDP(dport=80)/Raw("payload")
        in_pkts[1] = Ether(bytes(in_pkts[1]))

        self.program_tables()
        in_meta = [{"metadata_t.tuser_size": len(pkt)} for pkt in in_pkts]
        out, out_meta = self.runtime.send_packets(in_pkts, in_meta)
        for i in range(len(in_pkts)):
            self.assertPacket(Ether(out[i]), in_pkts[i], "packet corrupted")
            self.assertEqual(out_meta[i]["metadata_t.is_scion"], 1, "packet misclassified")

        for meta, pkt in zip(out_meta, in_pkts):
            self.assertEqual(meta["metadata_t.tuser_size"], len(pkt), "wrong size metadata")

        self.assertEqual(out_meta[0]["metadata_t.payload_offset"], 34, "wrong payload offset")
        self.assertEqual(out_meta[1]["metadata_t.payload_offset"], 54, "wrong payload offset")

        self.assertEqual(out_meta[0]["metadata_t.hop_fields"], 3, "wrong payload offset")
        self.assertEqual(out_meta[1]["metadata_t.hop_fields"], 3, "wrong payload offset")

        self.assertEqual(self.runtime.counter_read("cnt_packets", CNT_TOTAL_IPV4), 1)
        self.assertEqual(self.runtime.counter_read("cnt_packets", CNT_TOTAL_IPV6), 1)
        self.assertEqual(self.runtime.counter_read("cnt_packets", CNT_SCION_IPV4), 1)
        self.assertEqual(self.runtime.counter_read("cnt_packets", CNT_SCION_IPV6), 1)
        self.assertEqual(self.runtime.counter_read("cnt_dynamic_ipv4_hit", 0), 0)
        self.assertEqual(self.runtime.counter_read("cnt_dynamic_ipv6_hit", 0), 0)

    @base.dump_log_on_fail
    def test_dynamic_ports(self):
        """SCION packets to be classified as such due to a dynamic mapping"""
        in_pkts = [None, None]
        # IPv4
        in_pkts[0] = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkts[0] /= IP(dst="10.0.0.1", src="10.0.0.2")
        in_pkts[0] /= UDP(dport=80, sport=44026)
        in_pkts[0] /= SCION(
            path=SCIONPath(
                seg0_len=3,
                seg1_len=0,
                seg2_len=0,
                info_fields=[
                    InfoField(flags="C")
                ],
                hop_fields=[
                    HopField(cons_ingress=1, cons_egress=2),
                    HopField(cons_ingress=1, cons_egress=2),
                    HopField(cons_ingress=1, cons_egress=2)
                ]
            )
        )
        in_pkts[0] /= in_pkts[0]/UDP(dport=80)/Raw("payload")
        in_pkts[0] = Ether(bytes(in_pkts[0]))

        # IPv6
        in_pkts[1] = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkts[1] /= IPv6(dst="fd00:f00d:cafe::1", src="fd00:f00d:cafe::2")
        in_pkts[1] /= UDP(dport=80, sport=48026)
        in_pkts[1] /= SCION(
            path=SCIONPath(
                seg0_len=3,
                seg1_len=0,
                seg2_len=0,
                info_fields=[
                    InfoField(flags="C")
                ],
                hop_fields=[
                    HopField(cons_ingress=1, cons_egress=2),
                    HopField(cons_ingress=1, cons_egress=2),
                    HopField(cons_ingress=1, cons_egress=2)
                ]
            )
        )
        in_pkts[1] /= in_pkts[1]/UDP(dport=80)/Raw("payload")
        in_pkts[1] = Ether(bytes(in_pkts[1]))

        self.program_tables()
        in_meta = [{"metadata_t.tuser_size": len(pkt)} for pkt in in_pkts]
        out, out_meta = self.runtime.send_packets(in_pkts, in_meta)
        for i in range(len(in_pkts)):
            self.assertPacket(Ether(out[i]), in_pkts[i], "packet corrupted")
            self.assertEqual(out_meta[i]["metadata_t.is_scion"], 1, "packet misclassified")

        for meta, pkt in zip(out_meta, in_pkts):
            self.assertEqual(meta["metadata_t.tuser_size"], len(pkt), "wrong size metadata")

        self.assertEqual(out_meta[0]["metadata_t.payload_offset"], 34, "wrong payload offset")
        self.assertEqual(out_meta[1]["metadata_t.payload_offset"], 54, "wrong payload offset")

        self.assertEqual(out_meta[0]["metadata_t.hop_fields"], 3, "wrong payload offset")
        self.assertEqual(out_meta[1]["metadata_t.hop_fields"], 3, "wrong payload offset")

        self.assertEqual(self.runtime.counter_read("cnt_packets", CNT_TOTAL_IPV4), 1)
        self.assertEqual(self.runtime.counter_read("cnt_packets", CNT_TOTAL_IPV6), 1)
        self.assertEqual(self.runtime.counter_read("cnt_packets", CNT_SCION_IPV4), 1)
        self.assertEqual(self.runtime.counter_read("cnt_packets", CNT_SCION_IPV6), 1)
        self.assertEqual(self.runtime.counter_read("cnt_dynamic_ipv4_hit", 0), 1)
        self.assertEqual(self.runtime.counter_read("cnt_dynamic_ipv6_hit", 0), 1)
