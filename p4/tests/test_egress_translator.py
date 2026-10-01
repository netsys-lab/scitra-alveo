# SPDX-License-Identifier: AGPL-3.0-or-later

import ipaddress
from datetime import datetime
from typing import List, Union

from sim import base
from sim.addr_mapping import IPv4Address, IPv6Address, encode_ipv4, encode_ipv6
from sim.scion import IsdAsn
from sim.cpu_header import (
    CPU_PORT, TO_CPU_REASON_EGRESS_ICMP, TO_CPU_REASON_EGRESS_NEW_FLOW, CPUMetadata)

from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.inet6 import (
    ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6ND_NA, ICMPv6PacketTooBig, IPv6,
)
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy_scion.layers.scion import (
    SCION, UDP, EmptyPath, HopField, InfoField, SCIONPath,
)
from scapy_scion.layers.scmp import (
    SCMP, ScmpEchoReply, ScmpEchoRequest, ScmpPacketTooBig,
)

CNT_DROP_PARSER = 0
CNT_DROP_MTU_EXCEEDED = 1


IPAddress = Union[IPv4Address, IPv6Address]

class FlowID:
    def __init__(self,
                 dst_ia: IsdAsn,
                 dst_ip: IPAddress,
                 is_tcp: bool,
                 dst_port: int,
                 src_port: int):
        self.dst_ia = dst_ia
        self.dst_ip = dst_ip
        self.is_tcp = is_tcp
        self.dst_port = dst_port
        self.src_port = src_port

    def to_table_key(self) -> List[bytes]:
        return [
            hex(self.dst_ia.isd),
            hex(int(self.dst_ia.asn)),
            "1" if isinstance(self.dst_ip, IPv4Address) else "0",
            "1" if self.is_tcp else "0",
            hex(int.from_bytes(self.dst_ip.packed[-4:])),
            hex(self.dst_port),
            hex(self.src_port)
        ]


class EgrTranslatorTest(base.BMVitisP4TestCase):

    def setUp(self):
        super().setUp("build/egress-translator.json", thrift_port=9900)

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

    short_path = SCIONPath(
        seg0_len=2,
        seg1_len=2,
        seg2_len=0,
        info_fields=[
            InfoField(flags="C", timestamp=datetime.fromtimestamp(1721748372)),
            InfoField(flags="C", timestamp=datetime.fromtimestamp(1721748372)),
        ],
        hop_fields=[
            HopField(cons_ingress=1, cons_egress=2),
            HopField(cons_ingress=3, cons_egress=4),
            HopField(cons_ingress=5, cons_egress=6),
            HopField(cons_ingress=7, cons_egress=8),
        ]
    )

    def insert_path(self, slot: int, flow: FlowID, path: SCIONPath, br: int, mps: int = 1440):
        self.runtime.table_add("tab_flow",
            flow.to_table_key(),
            "set_path", [
                hex(slot),
                hex(br),
                hex(len(bytes(path)) // 4),
                hex(mps)
            ])
        self.runtime.table_add("tab_path_meta",
            [hex(slot)], "set_path_meta",
            [
                hex(path.curr_inf),
                hex(path.curr_hf),
                hex(path.seg0_len),
                hex(path.seg1_len),
                hex(path.seg2_len),
            ]
        )
        for i, info in enumerate(path.info_fields):
            self.runtime.table_add(f"tab_inf_{i}",
                [hex(slot)], f"set_inf_{i}",
                [hex(int.from_bytes(bytes(info)))])
        for i, hop in enumerate(path.hop_fields):
            self.runtime.table_add(f"tab_hf_{i}",
                [hex(slot)], f"set_hop_{i}",
                [hex(int.from_bytes(bytes(hop)))])

    @base.dump_log_on_fail
    def test_arp(self):
        """Test ARP packets"""
        in_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:02") / ARP()
        in_pkt = Ether(bytes(in_pkt))
        in_meta = {"metadata_t.tuser_size": len(in_pkt)}

        out_pkts, out_meta = self.runtime.send_packets([in_pkt], [in_meta])
        out = out_pkts[0]
        meta = out_meta[0]
        self.assertGreater(len(out), 0, "packet dropped")
        self.assertPacket(Ether(out), in_pkt, "packet corrupted")
        self.assertEqual(meta["metadata_t.axis_tdest"], 0, "wrong destination")
        self.assertEqual(meta["metadata_t.tuser_size"], len(in_pkt), "wrong size metadata")
        self.assertEqual(meta["metadata_t.payload_offset"], 0, "wrong payload offset")
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 0), 1)

    @base.dump_log_on_fail
    def test_pass_ipv4(self):
        """Test forwarding non-SCION IPv4 packets"""
        in_pkt = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkt /= IP(dst="10.0.0.1", src="10.0.0.2")
        in_pkts = [
            Ether(bytes(in_pkt / TCP(dport=80, sport=44000) / Raw(b"payload"))),
            Ether(bytes(in_pkt / UDP(dport=80, sport=44000) / Raw(b"payload"))),
            Ether(bytes(in_pkt / ICMP())),
        ]
        in_meta = [{"metadata_t.tuser_size": len(pkt)} for pkt in in_pkts]

        out_pkts, out_meta = self.runtime.send_packets(in_pkts, in_meta)
        self.assertEqual(len(out_pkts), len(in_pkts))
        for out, meta, exp in zip(out_pkts, out_meta, in_pkts):
            self.assertGreater(len(out), 0, "packet dropped")
            exp[IP].payload.chksum = 0 # Checksum must be null during checksum computation
            self.assertPacket(Ether(out), exp, "packet corrupted")
            self.assertEqual(meta["metadata_t.axis_tdest"], 0, "wrong destination")
            self.assertEqual(meta["metadata_t.tuser_size"], len(exp), "wrong size metadata")
            self.assertEqual(meta["metadata_t.payload_offset"], 34, "wrong payload offset")
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 0), 3)

    @base.dump_log_on_fail
    def test_pass_ipv6(self):
        """Test IPv6 packets that don't contain a SCION header"""
        in_pkt = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkt /= IPv6(dst="fd00:f00d:cafe::1", src="fd00:f00d:cafe::2")
        in_pkts = [
            Ether(bytes(in_pkt / TCP(dport=80, sport=44000) / Raw(b"payload"))),
            Ether(bytes(in_pkt / UDP(dport=80, sport=44000) / Raw(b"payload"))),
            Ether(bytes(in_pkt / ICMPv6ND_NA())),
        ]
        in_meta = [{"metadata_t.tuser_size": len(pkt)} for pkt in in_pkts]
        expected = [
            # Checksum must be null during checksum computation
            Ether(bytes(in_pkt / TCP(dport=80, sport=44000, chksum=0) / Raw(b"payload"))),
            Ether(bytes(in_pkt / UDP(dport=80, sport=44000, chksum=0) / Raw(b"payload"))),
            Ether(bytes(in_pkt / ICMPv6ND_NA(cksum=0))),
        ]

        out_pkts, out_meta = self.runtime.send_packets(in_pkts, in_meta)
        self.assertEqual(len(out_pkts), len(in_pkts))
        for out, meta, exp in zip(out_pkts, out_meta, expected):
            self.assertGreater(len(out), 0, "packet dropped")
            self.assertPacket(Ether(out), exp, "packet corrupted")
            self.assertEqual(meta["metadata_t.axis_tdest"], 0, "wrong destination")
            self.assertEqual(meta["metadata_t.tuser_size"], len(exp), "wrong size metadata")
            self.assertEqual(meta["metadata_t.payload_offset"], 54, "wrong payload offset")
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 0), 3)

    @base.dump_log_on_fail
    def test_local_ipv6(self):
        """Test translating with an IPv6 host in the local AS as destination"""

        local_ia = IsdAsn("63-2:0:1")
        src_ip = encode_ipv6(local_ia, 0, 0, 1)
        src_port = 3000
        dst_ip = encode_ipv6(local_ia, 0, 1, 255)
        dst_port = 4000

        fl = FlowID(local_ia, dst_ip, True, dst_port, src_port)
        self.runtime.table_add("tab_flow", fl.to_table_key(), "set_empty_path", [hex(1440)])

        ether = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        ipv6 = IPv6(src=src_ip, dst=dst_ip, fl=1)
        payload = TCP(sport=src_port, dport=dst_port) / Raw("ipv6_local")
        in_pkt = ether / ipv6 / payload
        in_meta = {"metadata_t.tuser_size": len(in_pkt)}

        underlay = IPv6(src=src_ip, dst=dst_ip)
        underlay /= UDP(sport=src_port, dport=dst_port, chksum=0)
        scion = SCION(
            fl = ipv6.fl,
            dst_isd = local_ia.isd,
            dst_asn = int(local_ia.asn),
            src_isd = local_ia.isd,
            src_asn = int(local_ia.asn),
            dst_host = dst_ip,
            src_host = src_ip,
            path = EmptyPath()
        )

        out_exp = Ether(bytes(ether / underlay / scion / payload))
        out_exp[TCP].chksum = 0

        out, out_meta = self.runtime.send_packets([in_pkt], [in_meta])
        self.assertGreater(len(out[0]), 0, "packet dropped")
        self.assertPacket(Ether(out[0]), out_exp)
        self.assertEqual(out_meta[0]["metadata_t.axis_tdest"], 0, "wrong destination")
        self.assertEqual(out_meta[0]["metadata_t.tuser_size"], len(out_exp), "wrong size metadata")
        self.assertEqual(out_meta[0]["metadata_t.payload_offset"], 54, "wrong payload offset")
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 0), 1)

    @base.dump_log_on_fail
    def test_local_ipv4(self):
        """Test translating with an IPv4 host in the local AS as destination"""

        local_ia = IsdAsn("63-2:0:1")
        src_ip = IPv4Address("10.0.0.1")
        src_ipv6 = encode_ipv4(local_ia, src_ip)
        src_port = 3000
        dst_ip = IPv4Address("10.8.0.1")
        dst_ipv6 = encode_ipv4(local_ia, dst_ip)
        dst_port = 4000

        fl = FlowID(local_ia, dst_ip, True, dst_port, src_port)
        self.runtime.table_add("tab_flow", fl.to_table_key(), "set_empty_path", [hex(1460)])

        ether = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        ipv6 = IPv6(src=src_ipv6, dst=dst_ipv6, fl=1)
        payload = TCP(sport=src_port, dport=dst_port) / Raw("ipv4_local")
        in_pkt = ether / ipv6 / payload
        in_meta = {"metadata_t.tuser_size": len(in_pkt)}

        underlay = IP(src=src_ip, dst=dst_ip, flags="DF", chksum=0)
        underlay /= UDP(sport=src_port, dport=dst_port, chksum=0)
        scion = SCION(
            fl = ipv6.fl,
            dst_isd = local_ia.isd,
            dst_asn = int(local_ia.asn),
            src_isd = local_ia.isd,
            src_asn = int(local_ia.asn),
            dst_host = dst_ip,
            src_host = src_ip,
            path = EmptyPath()
        )

        out_exp = Ether(bytes(ether / underlay / scion / payload))
        out_exp[TCP].chksum = 0

        out, out_meta = self.runtime.send_packets([in_pkt], [in_meta])
        self.assertGreater(len(out[0]), 0, "packet dropped")
        self.assertPacket(Ether(out[0]), out_exp)
        self.assertEqual(out_meta[0]["metadata_t.axis_tdest"], 0, "wrong destination")
        self.assertEqual(out_meta[0]["metadata_t.tuser_size"], len(out_exp), "wrong size metadata")
        self.assertEqual(out_meta[0]["metadata_t.payload_offset"], 34, "wrong payload offset")
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 0), 1)

    @base.dump_log_on_fail
    def test_scion66(self):
        """Test IPv6 to SCION/IPv6 translation"""

        local_ia = IsdAsn("63-2:0:1")
        remote_ia = IsdAsn("63-2:0:2")
        src_ip = encode_ipv6(local_ia, 0, 0, 1)
        src_port = 3000
        dst_ip = encode_ipv6(remote_ia, 0, 1, 255)
        dst_port = 4000
        br_mac = "00:00:00:00:00:03"
        br_ip = "fd00:f00d:cafe::1"
        br_port = 30001

        ether = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        ipv6 = IPv6(src=src_ip, dst=dst_ip, fl=1)
        payload = TCP(sport=src_port, dport=dst_port) / Raw("payload")
        in_pkt = Ether(bytes(ether / ipv6 / payload))
        in_meta = {"metadata_t.tuser_size": len(in_pkt)}

        scion = SCION(
            fl = ipv6.fl,
            dst_isd = remote_ia.isd,
            dst_asn = int(remote_ia.asn),
            src_isd = local_ia.isd,
            src_asn = int(local_ia.asn),
            dst_host = dst_ip,
            src_host = src_ip,
            path = self.long_path
        )
        expected = Ether(dst=br_mac, src=ether.src)
        expected /= IPv6(src=src_ip, dst=br_ip)
        expected /= UDP(sport=src_port, dport=br_port, chksum=0)
        expected /= scion / payload
        expected[TCP].chksum = 0
        expected = Ether(bytes(expected))

        br = 1
        self.runtime.table_add("tab_next_hop",
            [hex(br)], "forward_to_br_v6",
            [br_mac, str(src_ip), str(br_ip), hex(br_port)])
        fl = FlowID(remote_ia, dst_ip, True, dst_port, src_port)
        self.insert_path(1, fl, self.long_path, br)

        out, out_meta = self.runtime.send_packets([in_pkt], [in_meta])
        self.assertGreater(len(out[0]), 0, "packet dropped")
        self.assertPacket(Ether(out[0]), expected)
        self.assertEqual(out_meta[0]["metadata_t.axis_tdest"], 0, "wrong destination")
        self.assertEqual(out_meta[0]["metadata_t.tuser_size"], len(expected), "wrong size metadata")
        self.assertEqual(out_meta[0]["metadata_t.payload_offset"], 54, "wrong payload offset")
        self.assertEqual(self.runtime.counter_read("cnt_flow_hit", 1), 1)
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 0), 1)

    @base.dump_log_on_fail
    def test_scion64(self):
        """Test IPv6 to SCION/IPv4 translation"""

        local_ia = IsdAsn("63-2:0:1")
        remote_ia = IsdAsn("63-2:0:2")
        src_ip = IPv4Address("10.0.0.1")
        src_ipv6 = encode_ipv4(local_ia, src_ip)
        src_port = 3000
        dst_ip = IPv4Address("10.8.0.1")
        dst_ipv6 = encode_ipv4(remote_ia, dst_ip)
        dst_port = 4000

        br_mac = "00:00:00:00:00:03"
        br_ip = "10.0.0.255"
        br_port = 30001

        ether = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        ipv6 = IPv6(src=src_ipv6, dst=dst_ipv6, fl=1)
        payload = TCP(sport=src_port, dport=dst_port) / Raw("payload")
        in_pkt = ether / ipv6 / payload
        in_meta = {"metadata_t.tuser_size": len(in_pkt)}

        scion = SCION(
            fl = ipv6.fl,
            dst_isd = remote_ia.isd,
            dst_asn = int(remote_ia.asn),
            src_isd = local_ia.isd,
            src_asn = int(local_ia.asn),
            dst_host = dst_ip,
            src_host = src_ip,
            path = self.long_path
        )
        expected = Ether(dst=br_mac, src=ether.src)
        expected /= IP(src=src_ip, dst=br_ip, flags="DF", chksum=0)
        expected /= UDP(sport=src_port, dport=br_port, chksum=0)
        expected /= scion / payload
        expected[TCP].chksum = 0
        expected = Ether(bytes(expected))

        br = 1
        self.runtime.table_add("tab_next_hop",
            [hex(br)], "forward_to_br_v4",
            [br_mac, str(src_ip), str(br_ip), hex(br_port)])
        fl = FlowID(remote_ia, dst_ip, True, dst_port, src_port)
        self.insert_path(1, fl, self.long_path, br)

        out, out_meta = self.runtime.send_packets([in_pkt], [in_meta])
        self.assertGreater(len(out[0]), 0, "packet dropped")
        self.assertPacket(Ether(out[0]), expected)
        self.assertEqual(out_meta[0]["metadata_t.axis_tdest"], 0, "wrong destination")
        self.assertEqual(out_meta[0]["metadata_t.tuser_size"], len(expected), "wrong size metadata")
        self.assertEqual(out_meta[0]["metadata_t.payload_offset"], 34, "wrong payload offset")
        self.assertEqual(self.runtime.counter_read("cnt_flow_hit", 1), 1)
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 0), 1)

    @base.dump_log_on_fail
    def test_destination_rule(self):
        """Test translating a regular IPv6 address to SCION"""

        local_ia = IsdAsn("63-2:0:1")
        remote_ia = IsdAsn("63-2:0:2")
        src_ip = "10.0.0.1"
        src_ipv6 = "fd00:f00d:cafe::1"
        src_port = 3000
        dst_ipv6 = "fd00:f00d:cafe::2"
        dst_port = 4000

        br_mac = "00:00:00:00:00:03"
        br_ip = "10.0.0.255"
        br_port = 30001

        ether = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        payload = TCP(sport=src_port, dport=dst_port) / Raw("payload")
        in_pkts = [
            Ether(bytes(ether / IPv6(src=src_ipv6, dst=dst_ipv6) / payload)),
        ]
        in_meta = [{"metadata_t.tuser_size": len(pkt)} for pkt in in_pkts]

        scion = SCION(
            dst_isd = remote_ia.isd,
            dst_asn = int(remote_ia.asn),
            src_isd = local_ia.isd,
            src_asn = int(local_ia.asn),
            dst_host = dst_ipv6,
            src_host = src_ipv6,
            path = self.short_path
        )
        out_pkt = Ether(dst=br_mac, src=ether.src)
        out_pkt /= IP(src=src_ip, dst=br_ip, flags="DF", chksum=0)
        out_pkt /= UDP(sport=src_port, dport=br_port, chksum=0) / scion
        expected = [
            Ether(bytes(out_pkt / payload))
        ]

        br = 1
        self.runtime.table_add("tab_next_hop",
            [hex(br)], "forward_to_br_v4",
            [br_mac, str(src_ip), str(br_ip), hex(br_port)])
        fl = FlowID(remote_ia, ipaddress.ip_address(dst_ipv6), True, dst_port, src_port)
        self.insert_path(1, fl, self.short_path, br)
        self.runtime.table_add("tab_src_addr",
            [src_ipv6], "set_scion_src", [hex(local_ia.isd), hex(int(local_ia.asn)), src_ipv6])
        self.runtime.table_add("tab_dst_host",
            [dst_ipv6], "set_scion_dest", [hex(remote_ia.isd), hex(int(remote_ia.asn)), dst_ipv6])

        from scapy.packet import bind_layers
        bind_layers(UDP, SCION, dport=br_port)

        out_pkts, out_meta = self.runtime.send_packets(in_pkts, in_meta)
        for out, meta, exp in zip(out_pkts, out_meta, expected):
            self.assertGreater(len(out), 0, "packet dropped")
            self.assertPacket(Ether(out), exp)
            self.assertEqual(meta["metadata_t.axis_tdest"], 0, "wrong destination")
            self.assertEqual(meta["metadata_t.tuser_size"], len(exp), "wrong size metadata")
            self.assertEqual(meta["metadata_t.payload_offset"], 34, "wrong payload offset")
        self.assertEqual(self.runtime.counter_read("cnt_flow_hit", 1), 1)
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 0), len(in_pkts))

    @base.dump_log_on_fail
    def test_no_path4(self):
        """Test sending to CPU when no path to destination is available"""

        local_ia = IsdAsn("1-64513")
        remote_ia = IsdAsn("1-64514")
        src_ip = encode_ipv4(local_ia, IPv4Address("10.80.0.1"))
        src_port = 3000
        dst_ip = encode_ipv4(remote_ia, IPv4Address("127.0.0.1"))
        dst_port = 4000

        ether = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        ipv6 = IPv6(src=src_ip, dst=dst_ip, fl=1)
        payload = UDP(sport=src_port, dport=dst_port) / Raw("payload")
        in_pkt = Ether(bytes(ether / ipv6 / payload))
        in_meta = {"metadata_t.tuser_size": len(in_pkt)}

        expected = Ether(dst=ether.src, src=ether.dst) / IPv6(src=src_ip, dst=src_ip, fl=1)
        expected /= UDP(sport=src_port, dport=CPU_PORT, chksum=0)
        expected /= CPUMetadata(reason=TO_CPU_REASON_EGRESS_NEW_FLOW) / payload
        expected = Ether(bytes(expected))

        out, out_meta = self.runtime.send_packets([in_pkt], [in_meta])
        self.assertGreater(len(out[0]), 0, "packet dropped")
        self.assertPacket(Ether(out[0]), expected)
        self.assertEqual(out_meta[0]["metadata_t.axis_tdest"], 1, "wrong destination")
        self.assertEqual(out_meta[0]["metadata_t.tuser_size"], len(expected), "wrong size metadata")
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 0), 0)
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 1), 1)

    @base.dump_log_on_fail
    def test_no_path6(self):
        """Test sending to CPU when no path to destination is available"""

        local_ia = IsdAsn("63-2:0:1")
        remote_ia = IsdAsn("63-2:0:2")
        src_ip = encode_ipv6(local_ia, 0, 0, 1)
        src_port = 3000
        dst_ip = encode_ipv6(remote_ia, 0, 1, 255)
        dst_port = 4000

        ether = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        ipv6 = IPv6(src=src_ip, dst=dst_ip, fl=1)
        payload = TCP(sport=src_port, dport=dst_port) / Raw("payload")
        in_pkt = Ether(bytes(ether / ipv6 / payload))
        in_meta = {"metadata_t.tuser_size": len(in_pkt)}

        expected = Ether(dst=ether.src, src=ether.dst) / IPv6(src=src_ip, dst=src_ip, fl=1)
        expected /= UDP(sport=src_port, dport=CPU_PORT, chksum=0)
        expected /= CPUMetadata(reason=TO_CPU_REASON_EGRESS_NEW_FLOW) / payload
        expected = Ether(bytes(expected))

        out, out_meta = self.runtime.send_packets([in_pkt], [in_meta])
        self.assertGreater(len(out[0]), 0, "packet dropped")
        self.assertPacket(Ether(out[0]), expected)
        self.assertEqual(out_meta[0]["metadata_t.axis_tdest"], 1, "wrong destination")
        self.assertEqual(out_meta[0]["metadata_t.tuser_size"], len(expected), "wrong size metadata")
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 0), 0)
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 1), 1)

    @base.dump_log_on_fail
    def test_icmp(self):
        """Test ICMP to SCMP translation"""

        local_ia = IsdAsn("63-2:0:1")
        remote_ia = IsdAsn("63-2:0:2")
        src_ip = encode_ipv6(local_ia, 0, 0, 1)
        dst_ip = encode_ipv6(remote_ia, 0, 1, 255)
        br_mac = "00:00:00:00:00:03"
        br_ip = "fd00:f00d:cafe::1"
        br_port = 30001

        ether = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkt = ether / IPv6(src=src_ip, dst=dst_ip)
        in_pkts = [
            Ether(bytes(in_pkt / ICMPv6PacketTooBig(mtu=1280))),
            Ether(bytes(in_pkt / ICMPv6EchoRequest(id=5, seq=0))),
            Ether(bytes(in_pkt / ICMPv6EchoReply(id=5, seq=0))),
            Ether(bytes(in_pkt / ICMPv6ND_NA())),
        ]
        in_meta = [{"metadata_t.tuser_size": len(pkt)} for pkt in in_pkts]

        scion = SCION(
            dst_isd = remote_ia.isd,
            dst_asn = int(remote_ia.asn),
            src_isd = local_ia.isd,
            src_asn = int(local_ia.asn),
            dst_host = dst_ip,
            src_host = src_ip,
            path = self.short_path
        )
        out_pkt = Ether(dst=br_mac, src=ether.src)
        out_pkt /= IPv6(src=src_ip, dst=br_ip)
        out_pkt /= UDP(sport=0, dport=br_port, chksum=0) / scion
        to_cpu = Ether(dst=ether.src, src=ether.dst) / IPv6(src=src_ip, dst=src_ip, hlim=255)
        to_cpu /= UDP(sport=0, dport=CPU_PORT, chksum=0)
        expected = [
            Ether(bytes(out_pkt / SCMP(message=ScmpPacketTooBig(mtu=1280), chksum=0))),
            Ether(bytes(out_pkt / SCMP(message=ScmpEchoRequest(id=5, seq=0), chksum=0))),
            Ether(bytes(out_pkt / SCMP(message=ScmpEchoReply(id=5, seq=0), chksum=0))),
            Ether(bytes(
                to_cpu / CPUMetadata(reason=TO_CPU_REASON_EGRESS_ICMP) / ICMPv6ND_NA(cksum=0))),

        ]
        exp_dest = [0, 0, 0, 1]

        br = 1
        self.runtime.table_add("tab_next_hop",
            [hex(br)], "forward_to_br_v6",
            [br_mac, str(src_ip), str(br_ip), hex(br_port)])
        fl = FlowID(remote_ia, dst_ip, False, 0, 0)
        self.insert_path(1, fl, self.short_path, br)
        self.runtime.table_add("tab_icmp", [hex(0), hex(2)], "icmpTranslate", []) # packet too big
        self.runtime.table_add("tab_icmp", [hex(0), hex(128)], "icmpTranslate", []) # echo request
        self.runtime.table_add("tab_icmp", [hex(0), hex(129)], "icmpTranslate", []) # echo reply
        self.runtime.table_add("tab_icmp", [hex(0), hex(136)], "icmpToCPU", []) # ND-NA

        out_pkts, out_meta = self.runtime.send_packets(in_pkts, in_meta)
        self.assertEqual(len(out_pkts), len(in_pkts))
        for out, meta, exp, dest in zip(out_pkts, out_meta, expected, exp_dest):
            self.assertGreater(len(out), 0, "packet dropped")
            self.assertPacket(Ether(out), exp)
            self.assertEqual(meta["metadata_t.axis_tdest"], dest, "wrong destination")
            self.assertEqual(meta["metadata_t.tuser_size"], len(exp), "wrong size metadata")
            self.assertEqual(meta["metadata_t.payload_offset"], 54, "wrong payload offset")
        self.assertEqual(self.runtime.counter_read("cnt_flow_hit", 1), 3)
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 0), 3)
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 1), 1)

    @base.dump_log_on_fail
    def test_packet_too_big(self):
        """Test generating PacketTooBig responses and dropping large packets"""

        local_ia = IsdAsn("63-2:0:1")
        remote_ia = IsdAsn("63-2:0:2")
        src_ip = encode_ipv6(local_ia, 0, 0, 1)
        src_port = 3000
        dst_ip = encode_ipv6(remote_ia, 0, 1, 255)
        dst_port = 4000
        br_mac = "00:00:00:00:00:03"
        br_ip = "fd00:f00d:cafe::1"
        br_port = 30001

        ether = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        tcp_short = TCP(sport=src_port, dport=dst_port)
        tcp_long = TCP(sport=src_port + 1, dport=dst_port)
        in_pkts = [
            Ether(bytes(ether / IPv6(src=src_ip, dst=dst_ip) / tcp_short / Raw(1400*"\x00"))),
            Ether(bytes(ether / IPv6(src=src_ip, dst=dst_ip) / tcp_long / Raw(1400*"\x00"))),
        ]
        in_meta = [{"metadata_t.tuser_size": len(pkt)} for pkt in in_pkts]

        expected = Ether(dst=ether.src, src=ether.dst)
        expected /= IPv6(src=dst_ip, dst=src_ip, plen=1428)
        expected /= ICMPv6PacketTooBig(mtu=1376, cksum=0)
        expected = Ether(bytes(expected))

        br = 1
        self.runtime.table_add("tab_next_hop",
            [hex(br)], "forward_to_br_v6",
            [br_mac, str(src_ip), str(br_ip), hex(br_port)])
        fl_short = FlowID(remote_ia, dst_ip, True, dst_port, src_port)
        fl_long = FlowID(remote_ia, dst_ip, True, dst_port, src_port + 1)
        self.insert_path(1, fl_short, self.short_path, br, 1200)
        self.insert_path(2, fl_long, self.long_path, br, 1000)

        out_pkts, out_meta = self.runtime.send_packets(in_pkts, in_meta)
        self.assertGreater(len(out_pkts[0]), 0, "packet dropped")
        out = Ether(out_pkts[0])
        self.assertTrue(out.haslayer(ICMPv6PacketTooBig))
        out[ICMPv6PacketTooBig].remove_payload()
        self.assertPacket(out, expected)
        self.assertEqual(out_meta[0]["metadata_t.axis_tdest"], 1, "wrong destination")
        self.assertEqual(out_meta[0]["metadata_t.tuser_size"], 1482, "wrong size metadata")
        self.assertEqual(len(out_pkts[1]), 0, "packet should have been dropped")
        self.assertEqual(self.runtime.counter_read("cnt_flow_hit", 1), 1)
        self.assertEqual(self.runtime.counter_read("cnt_flow_hit", 2), 1)
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 0), 0)
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 1), 1)
        self.assertEqual(self.runtime.counter_read("cnt_dropped", CNT_DROP_MTU_EXCEEDED), 1)

    @base.dump_log_on_fail
    def test_mss_clamping(self):
        """Test TCP MSS clamping"""

        local_ia = IsdAsn("63-2:0:1")
        remote_ia = IsdAsn("63-2:0:2")
        src_ip = encode_ipv6(local_ia, 0, 0, 1)
        src_port = 3000
        dst_ip = encode_ipv6(remote_ia, 0, 1, 255)
        dst_port = 4000
        br_mac = "00:00:00:00:00:03"
        br_ip = "fd00:f00d:cafe::1"
        br_port = 30001

        ether = Ether(dst="00:00:00:00:00:01", src="00:00:00:00:00:02")
        in_pkt = ether / IPv6(src=src_ip, dst=dst_ip)
        in_pkt /= TCP(sport=src_port, dport=dst_port, flags="S", options=[("MSS", 1440)])
        in_meta = {"metadata_t.tuser_size": len(in_pkt)}

        scion = SCION(
            dst_isd = remote_ia.isd,
            dst_asn = int(remote_ia.asn),
            src_isd = local_ia.isd,
            src_asn = int(local_ia.asn),
            dst_host = dst_ip,
            src_host = src_ip,
            path = self.long_path
        )
        expected = Ether(dst=br_mac, src=ether.src)
        expected /= IPv6(src=src_ip, dst=br_ip)
        expected /= UDP(sport=src_port, dport=br_port, chksum=0) / scion
        expected /= TCP(sport=src_port, dport=dst_port, flags="S", chksum=0,
            options=[("MSS", 980)])
        expected = Ether(bytes(expected))

        br = 1
        self.runtime.table_add("tab_next_hop",
            [hex(br)], "forward_to_br_v6",
            [br_mac, str(src_ip), str(br_ip), hex(br_port)])
        fl = FlowID(remote_ia, dst_ip, True, dst_port, src_port)
        self.insert_path(1, fl, self.long_path, br, 1000)

        out_pkts, out_meta = self.runtime.send_packets([in_pkt], [in_meta])
        out = Ether(out_pkts[0])
        meta = out_meta[0]
        self.assertPacket(out, expected)
        self.assertEqual(meta["metadata_t.axis_tdest"], 0, "wrong destination")
        self.assertEqual(out_meta[0]["metadata_t.tuser_size"], len(expected), "wrong size metadata")
        self.assertEqual(meta["metadata_t.payload_offset"], 54, "wrong payload offset")
        self.assertEqual(self.runtime.counter_read("cnt_flow_hit", 1), 1)
        self.assertEqual(self.runtime.counter_read("cnt_tdest", 0), 1)
