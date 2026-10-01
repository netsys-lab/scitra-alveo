# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime

from sim import base
from sim.addr_mapping import IPv4Address, encode_ipv4, encode_ipv6
from sim.scion import IsdAsn
from sim.checksum import ones_complement_sum16
from sim.cpu_header import CPU_PORT, TO_CPU_REASON_INGRESS_SCMP, CPUMetadata

from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.inet6 import (
    ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6PacketTooBig, IPv6,
)
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy_scion.layers.scion import (
    SCION, UDP, EndToEndExt, HopByHopExt, HopField, InfoField, PadNOption,
    SCIONPath,
)
from scapy_scion.layers.scmp import (
    SCMP, ScmpEchoReply, ScmpEchoRequest, ScmpPacketTooBig, ScmpParameterProblem,
)

CNT_DROP_PARSER = 0
CNT_DROP_CHKSUM = 1
CNT_DROP_SRC_ADDR = 2
CNT_DROP_DST_ADDR = 3

CNT_NOT_TRANSLATED = 0
CNT_TO_CPU = 1
CNT_SCMP = 2
CNT_UDP = 3
CNT_TCP = 4


class IngrTranslatorTest(base.BMVitisP4TestCase):

    dst_ia = IsdAsn("63-2:0:1")
    src_ia = IsdAsn("20-2:2:1")
    long_path = SCIONPath(
        seg0_len=3,
        seg1_len=2,
        seg2_len=2,
        info_fields=[
            InfoField(flags="C", timestamp=datetime.fromtimestamp(1721748372)),
            InfoField(flags="C", timestamp=datetime.fromtimestamp(1721748372)),
            InfoField(flags="", timestamp=datetime.fromtimestamp(1721748372)),
        ],
        hop_fields=[
            HopField(cons_ingress=1, cons_egress=2),
            HopField(cons_ingress=3, cons_egress=4),
            HopField(cons_ingress=5, cons_egress=6),
            HopField(cons_ingress=7, cons_egress=8),
            HopField(cons_ingress=9, cons_egress=10),
            HopField(cons_ingress=11, cons_egress=12),
            HopField(cons_ingress=13, cons_egress=14),
        ]
    )

    def setUp(self):
        super().setUp("build/ingress-translator.json", thrift_port=9900)

    def program_tables(self):
        self.runtime.table_add("tab_dest_ia",
            [hex(self.dst_ia.isd), hex(int(self.dst_ia.asn))], "NoAction", [])
        self.runtime.table_add("tab_source_translation_46",
            [hex(0), hex(0)], "translateSource46BGP", [])
        self.runtime.table_add("tab_source_translation_46",
            [hex(0), hex(2)], "translateSource46SCION", [])
        self.runtime.table_add("tab_dest_translation_46",
            [hex(0), hex(0)], "translateDest46BGP", [])
        self.runtime.table_add("tab_dest_translation_46",
            [hex(0), hex(2)], "translateDest46SCION", [])
        self.runtime.table_add("tab_scmp",
            [hex(2)], "scmpTranslate", []) # packet too big
        self.runtime.table_add("tab_scmp",
            [hex(128)], "scmpTranslate", []) # echo request
        self.runtime.table_add("tab_scmp",
            [hex(129)], "scmpTranslate", []) # echo reply

    @base.dump_log_on_fail
    def test_arp(self):
        """Test ARP packets"""
        in_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:02") / ARP()
        in_meta = {
            "metadata_t.tuser_size": len(in_pkt),
            "metadata_t.is_scion": 0,
            "metadata_t.hop_fields": 0,
            "metadata_t.payload_chksum": 0,
        }
        in_pkt = Ether(bytes(in_pkt))

        self.program_tables()
        out_pkts, out_meta = self.runtime.send_packets([in_pkt], [in_meta])
        out, meta = out_pkts[0], out_meta[0]
        self.assertGreater(len(out), 0, "packet dropped")
        self.assertPacket(Ether(out), in_pkt, "packet corrupted")
        self.assertEqual(meta["metadata_t.tuser_size"], len(in_pkt))
        self.assertEqual(self.runtime.counter_read("cntTranslated", CNT_NOT_TRANSLATED), 1)

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
        in_meta = [
            {
                "metadata_t.tuser_size": len(pkt),
                "metadata_t.is_scion": 0,
                "metadata_t.hop_fields": 0,
                "metadata_t.payload_chksum":
                    ones_complement_sum16(bytes(pkt[IP].payload)),
            } for pkt in in_pkts
        ]

        self.program_tables()
        out_pkts, out_meta = self.runtime.send_packets(in_pkts, in_meta)
        self.assertEqual(len(out_pkts), len(in_pkts))
        for out, meta, exp in zip(out_pkts, out_meta, in_pkts):
            self.assertGreater(len(out), 0, "packet dropped")
            self.assertPacket(Ether(out), exp, "packet corrupted")
            self.assertEqual(meta["metadata_t.tuser_size"], len(exp))
        self.assertEqual(self.runtime.counter_read("cntTranslated", CNT_NOT_TRANSLATED), 3)

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
        in_meta = [
            {
                "metadata_t.tuser_size": len(pkt),
                "metadata_t.is_scion": 0,
                "metadata_t.hop_fields": 0,
                "metadata_t.payload_chksum":
                    ones_complement_sum16(bytes(pkt[IPv6].payload)),
            } for pkt in in_pkts
        ]

        self.program_tables()
        out_pkts, out_meta = self.runtime.send_packets(in_pkts, in_meta)
        self.assertEqual(len(out_pkts), len(in_pkts))
        for out, meta, exp in zip(out_pkts, out_meta, in_pkts):
            self.assertGreater(len(out), 0, "packet dropped")
            self.assertPacket(Ether(out), exp, "packet corrupted")
            self.assertEqual(meta["metadata_t.tuser_size"], len(exp))
        self.assertEqual(self.runtime.counter_read("cntTranslated", CNT_NOT_TRANSLATED), 3)

    @base.dump_log_on_fail
    def test_corrupted_ipv4(self):
        """Test IPv4 packets with damaged payload"""
        src_ip = IPv4Address("10.8.0.1")
        dst_ip = IPv4Address("10.0.0.1")
        br_port = 30042

        path = SCIONPath(
            seg0_len=2,
            seg1_len=0,
            seg2_len=0,
            info_fields=[
                InfoField(flags="C", timestamp=datetime.fromtimestamp(1721748372)),
            ],
            hop_fields=[
                HopField(cons_ingress=1, cons_egress=2),
                HopField(cons_ingress=3, cons_egress=4),
            ]
        )

        scion = SCION(
            dst_isd = self.dst_ia.isd,
            dst_asn = int(self.dst_ia.asn),
            src_isd = self.src_ia.isd,
            src_asn = int(self.src_ia.asn),
            dst_host = dst_ip,
            src_host = src_ip,
            path =  path,
        )

        in_pkt = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkt /= IP(dst="10.0.0.1", src="10.0.0.2")
        in_pkts = [
            Ether(bytes(in_pkt / TCP(dport=80, sport=44000) / Raw(b"payload"))),
            Ether(bytes(in_pkt / UDP(dport=80, sport=44000) / Raw(b"payload"))),
            Ether(bytes(in_pkt / UDP(sport=br_port, dport=44000) / scion / UDP() / Raw(b"payload"))),
            Ether(bytes(in_pkt / ICMP())),
        ]
        in_meta = [
            {
                "metadata_t.tuser_size": len(pkt),
                "metadata_t.is_scion": 1 if pkt.haslayer(SCION) else 0,
                "metadata_t.hop_fields": 0,
                "metadata_t.payload_chksum":
                    ones_complement_sum16(bytes(pkt[IP].payload)) + 1, # corrupted payload
            } for pkt in in_pkts
        ]

        self.program_tables()
        out_pkts, _ = self.runtime.send_packets(in_pkts, in_meta)
        for out in out_pkts:
            self.assertEqual(len(out), 0, "unexpected packet")
        self.assertEqual(self.runtime.counter_read("cntDropped", CNT_DROP_CHKSUM), 4)

    @base.dump_log_on_fail
    def test_corrupted_ipv6(self):
        """Test IPv6 packets with damaged payload"""
        src_ip = encode_ipv4(self.src_ia, IPv4Address("10.8.0.1"))
        dst_ip = encode_ipv6(self.dst_ia, 0, 0xff, "::1")
        br_port = 30042

        path = SCIONPath(
            seg0_len=2,
            seg1_len=0,
            seg2_len=0,
            info_fields=[
                InfoField(flags="C", timestamp=datetime.fromtimestamp(1721748372)),
            ],
            hop_fields=[
                HopField(cons_ingress=1, cons_egress=2),
                HopField(cons_ingress=3, cons_egress=4),
            ]
        )

        scion = SCION(
            dst_isd = self.dst_ia.isd,
            dst_asn = int(self.dst_ia.asn),
            src_isd = self.src_ia.isd,
            src_asn = int(self.src_ia.asn),
            dst_host = dst_ip,
            src_host = src_ip,
            path =  path,
        )

        in_pkt = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkt /= IP(dst="10.0.0.1", src="10.0.0.2")
        in_pkts = [
            Ether(bytes(in_pkt / TCP(dport=80, sport=44000) / Raw(b"payload"))),
            Ether(bytes(in_pkt / UDP(dport=80, sport=44000) / Raw(b"payload"))),
            Ether(bytes(in_pkt / UDP(sport=br_port, dport=44000) / scion / UDP() / Raw(b"payload"))),
            Ether(bytes(in_pkt / ICMP())),
        ]
        in_meta = [
            {
                "metadata_t.tuser_size": len(pkt),
                "metadata_t.is_scion": 1 if pkt.haslayer(SCION) else 0,
                "metadata_t.hop_fields": 0,
                "metadata_t.payload_chksum":
                    ones_complement_sum16(bytes(pkt[IP].payload)) + 1, # corrupted payload
            } for pkt in in_pkts
        ]

        self.program_tables()
        out_pkts, _ = self.runtime.send_packets(in_pkts, in_meta)
        for out in out_pkts:
            self.assertEqual(len(out), 0, "unexpected packet")
        self.assertEqual(self.runtime.counter_read("cntDropped", CNT_DROP_CHKSUM), 4)

    @base.dump_log_on_fail
    def test_scion46(self):
        """Test translation with an IPv4 underlay"""
        src_ip = IPv4Address("10.8.0.1")
        dst_ip = IPv4Address("10.0.0.1")
        br_ip = "10.0.0.2"
        br_port = 30042

        ether = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        underlay = ether / IP(src=br_ip, dst=dst_ip)
        underlay /= UDP(sport=br_port, dport=44000)
        payload = Raw("payload")

        scion = SCION(
            dst_isd = self.dst_ia.isd,
            dst_asn = int(self.dst_ia.asn),
            src_isd = self.src_ia.isd,
            src_asn = int(self.src_ia.asn),
            dst_host = dst_ip,
            src_host = src_ip,
            path = self.long_path,
        )

        in_pkt = underlay / scion
        in_pkt /= HopByHopExt(options=[PadNOption(data=b"\x00\x00\x00\x00")])
        in_pkt /= EndToEndExt(options=[PadNOption(data=b"\x00\x00\x00\x00")])
        in_pkt /= UDP(sport=32000, dport=80) / payload

        in_meta = {
            "metadata_t.tuser_size": len(in_pkt),
            "metadata_t.is_scion": 1,
            "metadata_t.hop_fields": len(self.long_path.hop_fields),
            "metadata_t.payload_chksum": ones_complement_sum16(bytes(in_pkt[UDP]))
        }

        out_exp = ether / IPv6(
            src=encode_ipv4(self.src_ia, src_ip),
            dst=encode_ipv4(self.dst_ia, dst_ip),
            fl=in_pkt[0].fl,
            hlim=8
        ) / UDP(
            sport=32000, dport=80, chksum=0
        ) / payload

        self.program_tables()
        out, meta = self.runtime.send_packets([in_pkt], [in_meta])
        self.assertGreater(len(out[0]), 0, "packet dropped")
        self.assertPacket(Ether(out[0]), Ether(bytes(out_exp)))
        self.assertEqual(meta[0]["metadata_t.tuser_size"], len(out_exp))
        self.assertEqual(self.runtime.counter_read("cntTranslated", CNT_UDP), 1)

    @base.dump_log_on_fail
    def test_scion66(self):
        """Test translation with an IPv6 underlay"""
        src_ip = encode_ipv4(self.src_ia, IPv4Address("10.8.0.1"))
        dst_ip = encode_ipv6(self.dst_ia, 0, 0xff, "::1")
        br_ip = "fd00::2"
        br_port = 30042

        ether = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        underlay = ether / IPv6(src=br_ip, dst=dst_ip)
        underlay /= UDP(sport=br_port, dport=44000)
        payload = Raw("payload")

        scion = SCION(
            dst_isd = self.dst_ia.isd,
            dst_asn = int(self.dst_ia.asn),
            src_isd = self.src_ia.isd,
            src_asn = int(self.src_ia.asn),
            dst_host = dst_ip,
            src_host = src_ip,
            path = self.long_path,
        )

        in_pkt = underlay / scion
        in_pkt /= HopByHopExt(options=[PadNOption(data=b"\x00\x00\x00\x00")])
        in_pkt /= EndToEndExt(options=[PadNOption(data=b"\x00\x00\x00\x00")])
        in_pkt /= UDP(sport=32000, dport=80) / payload
        in_meta = {
            "metadata_t.tuser_size": len(in_pkt),
            "metadata_t.is_scion": 1,
            "metadata_t.hop_fields": len(self.long_path.hop_fields),
            "metadata_t.payload_chksum": ones_complement_sum16(bytes(in_pkt[UDP]))
        }

        out_exp = ether / IPv6(
            src=src_ip,
            dst=dst_ip,
            fl=scion.fl,
            hlim=8)
        out_exp /= UDP(sport=32000, dport=80, chksum=0) / payload

        self.program_tables()
        out, meta = self.runtime.send_packets([in_pkt], [in_meta])
        self.assertGreater(len(out[0]), 0, "packet dropped")
        self.assertPacket(Ether(out[0]), Ether(bytes(out_exp)))
        self.assertEqual(meta[0]["metadata_t.tuser_size"], len(out_exp))
        self.assertEqual(self.runtime.counter_read("cntTranslated", CNT_UDP), 1)

    @base.dump_log_on_fail
    def test_scmp_to_cpu(self):
        """Test forwarding of SCMP messages to controller"""
        src_ip = encode_ipv4(self.src_ia, IPv4Address("10.8.0.1"))
        dst_ip = encode_ipv6(self.dst_ia, 0, 0xff, "::1")
        br_ip = "fd00::2"
        br_port = 30042

        ether = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        underlay = ether / IPv6(src=br_ip, dst=dst_ip)
        underlay /= UDP(sport=br_port, dport=44000)
        scmp = SCMP(message=ScmpParameterProblem())

        scion = SCION(
            dst_isd = self.dst_ia.isd,
            dst_asn = int(self.dst_ia.asn),
            src_isd = self.src_ia.isd,
            src_asn = int(self.src_ia.asn),
            dst_host = dst_ip,
            src_host = src_ip,
            path = self.long_path,
        )

        in_pkt = underlay / scion
        in_pkt /= HopByHopExt(options=[PadNOption(data=b"\x00\x00\x00\x00")])
        in_pkt /= EndToEndExt(options=[PadNOption(data=b"\x00\x00\x00\x00")])
        in_pkt /= scmp
        in_meta = {
            "metadata_t.tuser_size": len(in_pkt),
            "metadata_t.is_scion": 1,
            "metadata_t.hop_fields": len(self.long_path.hop_fields),
            "metadata_t.payload_chksum": ones_complement_sum16(bytes(in_pkt[UDP]))
        }

        out_exp = Ether(dst=ether.src, src=ether.dst) / IPv6(
            src=src_ip,
            dst=src_ip,
            fl=scion.fl,
            hlim=8)
        out_exp /= UDP(sport=0, dport=CPU_PORT, chksum=0)
        out_exp /= CPUMetadata(reason=TO_CPU_REASON_INGRESS_SCMP) / scmp

        self.program_tables()
        out, meta = self.runtime.send_packets([in_pkt], [in_meta])
        self.assertGreater(len(out[0]), 0, "packet dropped")
        self.assertPacket(Ether(out[0]), Ether(bytes(out_exp)))
        self.assertEqual(meta[0]["metadata_t.tuser_size"], len(out_exp))
        self.assertEqual(self.runtime.counter_read("cntTranslated", CNT_TO_CPU), 1)

    @base.dump_log_on_fail
    def test_scmp_translation(self):
        """Test translation of SCMP to ICMP"""

        src_ip = encode_ipv4(self.src_ia, IPv4Address("10.8.0.1"))
        dst_ip = encode_ipv6(self.dst_ia, 0, 0xff, "::1")
        br_ip = "fd00::2"
        br_port = 30042

        path = SCIONPath(
            seg0_len=2,
            seg1_len=0,
            seg2_len=0,
            info_fields=[
                InfoField(flags="C", timestamp=datetime.fromtimestamp(1721748372)),
            ],
            hop_fields=[
                HopField(cons_ingress=1, cons_egress=2),
                HopField(cons_ingress=3, cons_egress=4),
            ]
        )

        scion = SCION(
            dst_isd = self.dst_ia.isd,
            dst_asn = int(self.dst_ia.asn),
            src_isd = self.src_ia.isd,
            src_asn = int(self.src_ia.asn),
            dst_host = dst_ip,
            src_host = src_ip,
            path =  path,
        )

        ether = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkt = ether / IPv6(src=br_ip, dst=dst_ip)
        in_pkt /= UDP(sport=br_port, dport=44000) / scion
        in_pkts = [
            Ether(bytes(in_pkt / SCMP(message=ScmpPacketTooBig(mtu=1280)))),
            Ether(bytes(in_pkt / SCMP(message=ScmpEchoRequest(id=5, seq=0)))),
            Ether(bytes(in_pkt / SCMP(message=ScmpEchoReply(id=5, seq=0)))),
        ]
        in_meta = [
            {
                "metadata_t.tuser_size": len(pkt),
                "metadata_t.is_scion": 1,
                "metadata_t.hop_fields": len(pkt[SCION].path.hop_fields),
                "metadata_t.payload_chksum":
                    ones_complement_sum16(bytes(pkt[IPv6].payload)),
            } for pkt in in_pkts
        ]

        out_exp = ether / IPv6(
            src=src_ip,
            dst=dst_ip,
            fl=scion.fl,
            hlim=8)
        expected = [
            Ether(bytes(out_exp / ICMPv6PacketTooBig(mtu=1280, cksum=0))),
            Ether(bytes(out_exp / ICMPv6EchoRequest(id=5, seq=0, cksum=0))),
            Ether(bytes(out_exp / ICMPv6EchoReply(id=5, seq=0, cksum=0))),
        ]

        self.program_tables()
        out_pkts, out_meta = self.runtime.send_packets(in_pkts, in_meta)
        self.assertEqual(len(out_pkts), len(in_pkts))
        for out, meta, exp in zip(out_pkts, out_meta, expected):
            self.assertGreater(len(out), 0, "packet dropped")
            self.assertPacket(Ether(out), exp)
            self.assertEqual(meta["metadata_t.tuser_size"], len(exp))
        self.assertEqual(self.runtime.counter_read("cntTranslated", CNT_SCMP), 3)
