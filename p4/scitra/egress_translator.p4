// SPDX-License-Identifier: AGPL-3.0-or-later

#include <core.p4>
#include <xsa.p4>

include(`include/limits.p4')
include(`include/headers.p4')
include(`include/cpu_header.p4')
include(`include/address_mapping.p4')

typedef bit<10> payload_offset_t;

struct metadata_t
{
    // 0 for out to the network, 1 for return to host
    bit<1>  axis_tdest;
    bit<16> tuser_size;

    payload_offset_t payload_offset;

    // not part of the external interface
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
}

struct headers_t
{
    ethernet_h ether;
    // Underlay
    ipv4_h ipv4;
    ipv6_h ipv6;
    udp_h  outer_udp;
    // To CPU
    cpu_h cpu;
    // SCION
    sc_common_h       scion_common;
    sc_host_addr_4_h  scion_dst_host_4;
    sc_host_addr_16_h scion_dst_host_16;
    sc_host_addr_4_h  scion_src_host_4;
    sc_host_addr_16_h scion_src_host_16;
    // Path
    sc_path_meta_h path_meta;
    sc_info_h      path_info0;
    sc_info_h      path_info1;
    sc_info_h      path_info2;
    sc_hop_blob_h  path_hop0;
    sc_hop_blob_h  path_hop1;
    sc_hop_blob_h  path_hop2;
    sc_hop_blob_h  path_hop3;
    sc_hop_blob_h  path_hop4;
    sc_hop_blob_h  path_hop5;
    sc_hop_blob_h  path_hop6;
    sc_hop_blob_h  path_hop7;
    sc_hop_blob_h  path_hop8;
    sc_hop_blob_h  path_hop9;
    sc_hop_blob_h  path_hop10;
    sc_hop_blob_h  path_hop11;
    sc_hop_blob_h  path_hop12;
    sc_hop_blob_h  path_hop13;
    sc_hop_blob_h  path_hop14;
    sc_hop_blob_h  path_hop15;
    // Upper layer headers
    icmp6_h   cmp; // also used for ICMPv4 which we don't translate
    udp_h     udp;
    tcp_h     tcp;
    tcp_mss_h tcp_mss;
}

////////////
// Parser //
////////////

parser EgrTransParser(
    packet_in                 pkt,
    out   headers_t           hdr,
    inout metadata_t          meta,
    inout standard_metadata_t smeta)
{
    state start {
        // Clear input metadata that we will never read
        meta.payload_offset = 0;
        meta.axis_tdest = 0;
        meta.l4_src_port = 0;
        meta.l4_dst_port = 0;

        pkt.extract(hdr.ether);
        transition select (hdr.ether.etype) {
            ETHER_TYPE_IPV4: ipv4;
            ETHER_TYPE_IPV6: ipv6;
            default        : accept;
        }
    }

    state ipv4 {
        pkt.extract(hdr.ipv4);

        // don't parse fragments or IPv4 options
        transition select (hdr.ipv4.frag_offset, hdr.ipv4.ihl, hdr.ipv4.protocol) {
            (0, 5, IP_PROTO_ICMP): icmp;
            (0, 5, IP_PROTO_TCP ): tcp;
            (0, 5, IP_PROTO_UDP ): udp;
            default              : accept;
        }
    }

    state ipv6 {
        pkt.extract(hdr.ipv6);

        transition select (hdr.ipv6.next_hdr) {
            IP_PROTO_ICMPv6: icmp;
            IP_PROTO_TCP   : tcp;
            IP_PROTO_UDP   : udp;
            default        : accept;
        }
    }

    state icmp {
        pkt.extract(hdr.cmp);
        transition accept;
    }

    state tcp {
        pkt.extract(hdr.tcp);
        meta.l4_src_port = hdr.tcp.src;
        meta.l4_dst_port = hdr.tcp.dst;
        transition select (hdr.tcp.data_offset) {
            5: accept; // no options
            _: tcp_opt;
        }
    }

    state tcp_opt {
        // Extract the first option, check type in control
        pkt.extract(hdr.tcp_mss);
        transition accept;
    }

    state udp {
        pkt.extract(hdr.udp);
        meta.l4_src_port = hdr.udp.src;
        meta.l4_dst_port = hdr.udp.dst;
        transition accept;
    }
}

////////////////
// Processing //
////////////////

typedef bit<10> PathIndex_t;
typedef bit<4> NextHop_t;

#define MAX_FLOWS 4096
#define NEXT_HOP_TABLE_SIZE 16

#define tab_path_meta() \
    action set_path_meta(bit<2> curr_inf, bit<6> curr_hf, bit<6> seg0, bit<6> seg1, bit<6> seg2) { \
        hdr.path_meta.setValid(); \
        hdr.path_meta.curr_inf = curr_inf; \
        hdr.path_meta.curr_hf = curr_hf; \
        hdr.path_meta.rsv = 0; \
        hdr.path_meta.seg0_len = seg0; \
        hdr.path_meta.seg1_len = seg1; \
        hdr.path_meta.seg2_len = seg2; \
    } \
    table tab_path_meta { \
        key = { \
            path_index : exact; \
        } \
        actions = { \
            set_path_meta; \
        } \
        direct_match = true; \
    }

#define DECLARE_PATH_META_TABLES() \
    tab_path_meta()

#define INSERT_PATH_META() \
    tab_path_meta.apply();

#define tab_inf(index) \
    action set_inf_ ## index(bit<64> inf) { \
        hdr.path_info ## index.setValid(); \
        hdr.path_info ## index.rsv1    = inf[63:58]; \
        hdr.path_info ## index.peering = inf[57:57]; \
        hdr.path_info ## index.cons    = inf[56:56]; \
        hdr.path_info ## index.rsv2    = inf[55:48]; \
        hdr.path_info ## index.seg_id  = inf[47:32]; \
        hdr.path_info ## index.tstamp  = inf[31:0]; \
    } \
    table tab_inf_ ## index { \
        key = { \
            path_index : exact; \
        } \
        actions = { \
            NoAction; \
            set_inf_ ## index; \
        } \
        const default_action = NoAction(); \
        direct_match = true; \
    }

#define DECLARE_INF_TABLES() \
    tab_inf(0) \
    tab_inf(1) \
    tab_inf(2)

#define INSERT_INF_FIELDS() \
    tab_inf_0.apply(); \
    tab_inf_1.apply(); \
    tab_inf_2.apply()

#define tab_hf(index) \
    action set_hop_ ## index(bit<96> hf) { \
        hdr.path_hop ## index.setValid(); \
        hdr.path_hop ## index.data = hf; \
    } \
    table tab_hf_ ## index { \
        key = { \
            path_index   : exact; \
        } \
        actions = { \
            NoAction; \
            set_hop_ ## index; \
        } \
        const default_action = NoAction(); \
        direct_match = true; \
    }

#define DECLARE_HF_TABLES() \
    tab_hf(0) \
    tab_hf(1) \
    tab_hf(2) \
    tab_hf(3) \
    tab_hf(4) \
    tab_hf(5) \
    tab_hf(6) \
    tab_hf(7) \
    tab_hf(8) \
    tab_hf(9) \
    tab_hf(10) \
    tab_hf(11) \
    tab_hf(12) \
    tab_hf(13) \
    tab_hf(14) \
    tab_hf(15)

#define INSERT_HOP_FIELDS() \
    tab_hf_0.apply(); \
    tab_hf_1.apply(); \
    tab_hf_2.apply(); \
    tab_hf_3.apply(); \
    tab_hf_4.apply(); \
    tab_hf_5.apply(); \
    tab_hf_6.apply(); \
    tab_hf_7.apply(); \
    tab_hf_8.apply(); \
    tab_hf_9.apply(); \
    tab_hf_10.apply(); \
    tab_hf_11.apply(); \
    tab_hf_12.apply(); \
    tab_hf_13.apply(); \
    tab_hf_14.apply(); \
    tab_hf_15.apply();

const bit<1> CNT_DROP_PARSER = 0;
const bit<1> CNT_DROP_MTU_EXCEEDED = 1;

control EgrTransProcessing(
    inout headers_t           hdr,
    inout metadata_t          meta,
    inout standard_metadata_t smeta)
{
    // === Global Variables ===

    bit<1> not_translated = 0;
    bool   had_ipv6 = false;
    bool   had_cmp = false;
    bit<9> icmp_type = 0;
    bit<128> dst_host = 0;      // IPv4 or IPv6 destination for flow table
    PathIndex_t path_index = 0; // index of the selected path, empty path is 0
    NextHop_t next_hop_br = 0;  // next hop border router for outgoing packets
    bit<16> max_payload = 0;    // maximum SCION payload size

    // === Externs ===

    // Counters
    Counter<bit<32>, bit<1>>(2, CounterType_t.PACKETS) cnt_dropped;
    Counter<bit<32>, bit<1>>(2, CounterType_t.PACKETS) cnt_tdest;

    // === Global Actions ===

    action dropPacket() {
        smeta.drop = 1;
        not_translated = 1;
    }

    action newFlowToCPU() {
        meta.axis_tdest = 1;

        mac_addr_t temp = hdr.ether.dst;
        hdr.ether.dst = hdr.ether.src;
        hdr.ether.src = temp;

        hdr.ipv6.next_hdr = IP_PROTO_UDP;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + UDP_HDR_SIZE_BYTES + CPU_HDR_SIZE_BYTES;
        hdr.ipv6.dst = hdr.ipv6.src;

        hdr.outer_udp.setValid();
        hdr.outer_udp.src = meta.l4_src_port;
        hdr.outer_udp.dst = CPU_PORT;
        hdr.outer_udp.length = hdr.ipv6.payload_len;
        hdr.outer_udp.chksum = 0;

        hdr.cpu.setValid();
        hdr.cpu = { TO_CPU_REASON_EGRESS_NEW_FLOW, 0 };

        not_translated = 1;
    }

    // Send an ICMP PacketTooBig response back to the sending socket.
    action returnPacketTooBig(bit<16> mtu) {
        meta.axis_tdest = 1;

        mac_addr_t mac = hdr.ether.dst;
        hdr.ether.dst = hdr.ether.src;
        hdr.ether.src = mac;

        hdr.ipv6.next_hdr = IP_PROTO_ICMPv6;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 8;
        bit<128> ip = hdr.ipv6.dst;
        hdr.ipv6.dst = hdr.ipv6.src;
        hdr.ipv6.src = ip;

        hdr.cmp.setValid();
        hdr.cmp.type = ICMP6_TYPE_PacketTooBig;
        hdr.cmp.code = 0;
        hdr.cmp.chksum = 0;
        hdr.cmp.param1 = 0;
        hdr.cmp.param2 = mtu;

        not_translated = 1;
    }

    action setPayloadOffset(payload_offset_t offset) {
        meta.payload_offset = offset;
    }

    // === Path Insertion Tables ===
    // Tables indexed by path_index that contain the SCION path.

    DECLARE_PATH_META_TABLES()
    DECLARE_INF_TABLES()
    DECLARE_HF_TABLES()

    // === Source Address Rewriting ===
    // Select a source host address for the SCION header if the source address
    // in the IPv6 header is not a SCION-mapped IPv6 already.
    // TODO: Translate back on ingress path
    // TODO: IPv4 to SCION translation

    action set_scion_src(sc_isd_t isd, sc_asn_t asn, bit<128> ip) {
        hdr.scion_src_host_16.setValid();
        hdr.scion_common.src_isd = isd;
        hdr.scion_common.src_asn = asn;
        hdr.scion_src_host_16.addr = ip;
        hdr.scion_common.host_type_len[3:0] = 4w3;
        hdr.scion_common.hdr_len = hdr.scion_common.hdr_len + 4;
    }

    table tab_src_addr {
        key = {
            hdr.ipv6.src : exact;
        }
        actions = {
            set_scion_src;
            NoAction;
        }
        const default_action = NoAction();
        size = 8;
    }

    // === Special Destination Table ===
    // This table allows mapping arbitrary IPv6 addresses to a SCION destination.
    // Entries correspond to SCION packets translated to IP that did not have a
    // SCION-mapped IPv6 address or plain IPv4 address in the source host field.
    // TODO: IPv4 to SCION translation

    action set_scion_dest(sc_isd_t isd, sc_asn_t asn, bit<128> ip) {
        hdr.scion_dst_host_16.setValid();
        hdr.scion_common.dst_isd = isd;
        hdr.scion_common.dst_asn = asn;
        hdr.scion_dst_host_16.addr = ip;
        dst_host = ip;
        hdr.scion_common.host_type_len[7:4] = 4w3;
        hdr.scion_common.hdr_len = hdr.scion_common.hdr_len + 4;
    }

    table tab_dst_host {
        key = {
            hdr.ipv6.dst : exact;
        }
        actions = {
            set_scion_dest;
            NoAction;
        }
        const default_action = NoAction();
        size = 128;
    }

    // === Flow Table ===
    // Maps flows to SCION paths. Contains metadata on all paths installed in
    // the data plane. The actual path is stored in the info and hop field
    // tables indexed by the ID returned from this table.
    // MPS is the maximum SCION payload size possible on the path.

    Counter<bit<32>, PathIndex_t>(MAX_FLOWS, CounterType_t.PACKETS) cnt_flow_hit;

    action set_path(PathIndex_t path, NextHop_t nh, bit<8> length, bit<16> mps) {
        hdr.scion_common.path_type = PATH_TYPE_SCION;
        hdr.scion_common.hdr_len = hdr.scion_common.hdr_len + length;
        path_index = path;
        next_hop_br = nh;
        max_payload = mps;
        cnt_flow_hit.count(path);
    }

    action set_empty_path(bit<16> mps) {
        hdr.scion_common.path_type = PATH_TYPE_EMPTY;
        path_index = 0;
        next_hop_br = 0;
        max_payload = mps;
    }

    table tab_flow {
        key = {
            hdr.scion_common.dst_isd       : exact;
            hdr.scion_common.dst_asn       : exact;
            hdr.scion_dst_host_4.isValid() : exact;
            hdr.tcp.isValid()              : exact;
            dst_host[31:0]                 : exact; // TODO: Match full length
            meta.l4_dst_port               : exact;
            meta.l4_src_port               : exact;
        }
        actions = {
            set_path;
            set_empty_path;
            NoAction;
        }
        const default_action = NoAction();
        size = MAX_FLOWS;
    }

    // === Next Hop Table ===
    // Addresses of neighboring SCION routers we can send packets to.

    action forward_to_br_v4(mac_addr_t mac, bit<32> src_ip, bit<32> dst_ip, bit<16> port) {
        hdr.ipv6.setInvalid();
        hdr.ipv4.setValid();
        hdr.outer_udp.setValid();

        hdr.ether.etype = ETHER_TYPE_IPV4;
        hdr.ether.dst = mac;
        hdr.ipv4.src = src_ip;
        hdr.ipv4.dst = dst_ip;
        hdr.outer_udp.dst = port;
    }

    action forward_to_br_v6(mac_addr_t mac, bit<128> src_ip, bit<128> dst_ip, bit<16> port) {
        hdr.ipv4.setInvalid();
        hdr.ipv6.setValid();
        hdr.outer_udp.setValid();

        hdr.ether.etype = ETHER_TYPE_IPV6;
        hdr.ether.dst = mac;
        hdr.ipv6.src = src_ip;
        hdr.ipv6.dst = dst_ip;
        hdr.outer_udp.dst = port;
    }

    table tab_next_hop {
        key = {
            next_hop_br : exact;
        }
        actions = {
            forward_to_br_v4;
            forward_to_br_v6;
            NoAction;
        }
        const default_action = NoAction();
        direct_match = true;
    }

    // === ICMP Translation Table ===
    // Either translate ICMP to SCMP directly or forward to the CPU.

    action icmpTranslate() {
        hdr.scion_common.next_hdr = IP_PROTO_SCMP;
    }

    action icmpToCPU() {
        meta.axis_tdest = 1;

        mac_addr_t temp = hdr.ether.dst;
        hdr.ether.dst = hdr.ether.src;
        hdr.ether.src = temp;

        hdr.ipv6.next_hdr = IP_PROTO_UDP;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + UDP_HDR_SIZE_BYTES + CPU_HDR_SIZE_BYTES;
        hdr.ipv6.dst = hdr.ipv6.src;

        hdr.outer_udp.setValid();
        hdr.outer_udp.src = meta.l4_src_port;
        hdr.outer_udp.dst = CPU_PORT;
        hdr.outer_udp.length = hdr.ipv6.payload_len;
        hdr.outer_udp.chksum = 0;

        hdr.cpu.setValid();
        hdr.cpu = { TO_CPU_REASON_EGRESS_ICMP, 0 };

        not_translated = 1;
    }

    table tab_icmp {
        key = {
            not_translated : exact;
            icmp_type      : exact;
        }
        actions = {
            icmpTranslate;
            icmpToCPU;
            NoAction;
        }
        const default_action = NoAction();
        size = 16;
    }

    // === Main ===
    apply {
        // Check parser errors
        if (smeta.parser_error != error.NoError) {
            cnt_dropped.count(CNT_DROP_PARSER);
            dropPacket();
        }

        // Drop packets that are too large for the checksum unit
        if (meta.tuser_size > MAX_PACKET_SIZE) {
            dropPacket();
        }

        had_ipv6 = hdr.ipv6.isValid();
        had_cmp = hdr.cmp.isValid();

        if (hdr.ipv6.isValid()) {
            // Initialize SCION common header
            hdr.scion_common.setValid();
            hdr.scion_common.version = 0;
            hdr.scion_common.qos = 0;
            hdr.scion_common.flow_id = hdr.ipv6.flow_label;
            hdr.scion_common.next_hdr = hdr.ipv6.next_hdr;
            hdr.scion_common.hdr_len = SC_COMMON_HDR_SIZE_BYTES / 4;
            hdr.scion_common.payload_len = hdr.ipv6.payload_len;
            hdr.scion_common.host_type_len = 0;
            hdr.scion_common.rsv = 0;

            // Set source addresses
            if (!tab_src_addr.apply().hit) {
                // NOTE: Since we're dealing with a limited set of possible
                // source addresses, tab_src_addr alone would be enough.
                if (extract_prefix(hdr.ipv6.src) == SCION_PREFIX) {
                    // TODO: Should we check if the source ISD-ASN is correct?
                    hdr.scion_common.src_isd = (bit<16>)(extract_isd(hdr.ipv6.src));
                    sc_asn_t asn;
                    bit<24> local_prefix;
                    if (hdr.ipv6.src[107:107] == 0) { // BGP ASN
                        asn = 29w0 ++ hdr.ipv6.src[106:88];
                        local_prefix = extract_network_bgp(hdr.ipv6.src);
                    } else { // if (hdr.ipv6.src[107:104] == 14) // Public SCION ASN
                        asn = 16w2 ++ hdr.ipv6.src[103:72];
                        local_prefix = 16w0 ++ extract_network_sci(hdr.ipv6.src);
                    }
                    hdr.scion_common.src_asn = asn;
                    if (local_prefix == 0 && extract_host_prefix(hdr.ipv6.src) == 32w0xffff) {
                        // IPv4 source
                        // TODO: Figure out how to translate responses
                        hdr.scion_src_host_4.setValid();
                        hdr.scion_src_host_4.addr = extract_host_v4(hdr.ipv6.src);
                        hdr.scion_common.host_type_len[3:0] = 4w0;
                        hdr.scion_common.hdr_len = hdr.scion_common.hdr_len + 1;
                    } else {
                        // IPv6 source
                        hdr.scion_src_host_16.setValid();
                        hdr.scion_src_host_16.addr = hdr.ipv6.src;
                        hdr.scion_common.host_type_len[3:0] = 4w3;
                        hdr.scion_common.hdr_len = hdr.scion_common.hdr_len + 4;
                    }
                } else {
                    not_translated = 1;
                }
            }

            // Check if there is a special translation rule for the destination
            if (!tab_dst_host.apply().hit) {
                // If not, try and decode the destination address as SCION-mapped IPv6
                if (extract_prefix(hdr.ipv6.dst) == SCION_PREFIX) {
                    hdr.scion_common.dst_isd = (bit<16>)(extract_isd(hdr.ipv6.dst));
                    sc_asn_t asn;
                    bit<24> local_prefix;
                    if (hdr.ipv6.dst[107:107] == 0) { // BGP ASN
                        asn = 29w0 ++ hdr.ipv6.dst[106:88];
                        local_prefix = extract_network_bgp(hdr.ipv6.dst);
                    } else { // if (hdr.ipv6.dst[107:104] == 14) // Public SCION ASN
                        asn = 16w2 ++ hdr.ipv6.dst[103:72];
                        local_prefix = 16w0 ++ extract_network_sci(hdr.ipv6.dst);
                    }
                    hdr.scion_common.dst_asn = asn;
                    if (local_prefix == 0 && extract_host_prefix(hdr.ipv6.dst) == 32w0xffff) {
                        // SCION-IPv4
                        hdr.scion_dst_host_4.setValid();
                        hdr.scion_dst_host_4.addr = extract_host_v4(hdr.ipv6.dst);
                        dst_host = 96w0 ++ extract_host_v4(hdr.ipv6.dst);
                        hdr.scion_common.host_type_len[7:4] = 4w0;
                        hdr.scion_common.hdr_len = hdr.scion_common.hdr_len + 1;
                    } else {
                        // SCION-IPv6
                        hdr.scion_dst_host_16.setValid();
                        hdr.scion_dst_host_16.addr = hdr.ipv6.dst;
                        dst_host = hdr.ipv6.dst;
                        hdr.scion_common.host_type_len[7:4] = 4w3;
                        hdr.scion_common.hdr_len = hdr.scion_common.hdr_len + 4;
                    }
                }
                else {
                    not_translated = 1;
                }
            }

            // Translate ICMP
            if (hdr.cmp.isValid()) {
                icmp_type = (bit<9>)hdr.cmp.type;
                tab_icmp.apply();
            }

            if (not_translated == 0) {
                if (!tab_flow.apply().hit) {
                    newFlowToCPU();
                } else {
                    if (hdr.ipv6.payload_len > max_payload) {
                        // Path MTU exceeded
                        bit<16> mtu = IPV6_HDR_SIZE_BYTES + UDP_HDR_SIZE_BYTES
                            + ((bit<16>)hdr.scion_common.hdr_len << 2) + max_payload;
                        // Send PMTU response only if new MTU is valid for IPv6
                        // and the original packet wasn't already ICMP, as this
                        // would require adding a second ICMP header.
                        if (mtu >= IPV6_MIN_MTU && !hdr.cmp.isValid()) {
                            returnPacketTooBig(mtu);
                        } else {
                            cnt_dropped.count(CNT_DROP_MTU_EXCEEDED);
                            dropPacket();
                        }
                    }
                    else if (hdr.scion_common.path_type == PATH_TYPE_EMPTY) {
                        // AS-local destination
                        if (hdr.scion_dst_host_4.isValid()) {
                            if (!hdr.scion_src_host_4.isValid()) {
                                // ERROR: Destination requires IPv4, but source address is IPv6
                                not_translated = 1;
                            } else {
                                hdr.ipv6.setInvalid();
                                hdr.ipv4.setValid();
                                hdr.ether.etype = ETHER_TYPE_IPV4;
                                hdr.ipv4.src = hdr.scion_src_host_4.addr;
                                hdr.ipv4.dst = hdr.scion_dst_host_4.addr;
                                hdr.outer_udp.setValid();
                                hdr.outer_udp.src = meta.l4_src_port;
                                hdr.outer_udp.dst = meta.l4_dst_port;
                            }
                        } else {
                            if (!hdr.scion_src_host_16.isValid()) {
                                // ERROR: Destination requires IPv6, but source address is IPv4
                                not_translated = 1;
                            } else {
                                hdr.ipv4.setInvalid();
                                hdr.ipv6.setValid();
                                hdr.ether.etype = ETHER_TYPE_IPV6;
                                hdr.ipv6.src = hdr.scion_src_host_16.addr;
                                hdr.ipv6.dst = hdr.scion_dst_host_16.addr;
                                hdr.outer_udp.setValid();
                                hdr.outer_udp.src = meta.l4_src_port;
                                hdr.outer_udp.dst = meta.l4_dst_port;
                            }
                        }
                        // TODO: Control program must ensure that neighbor entries exist or the
                        // kernel won't have a MAC.
                    } else {
                        // Send to border router
                        tab_next_hop.apply();
                        hdr.outer_udp.src = meta.l4_src_port;
                    }
                    if (not_translated == 0) {
                        // Calculate outer UDP payload length
                        hdr.outer_udp.length = UDP_HDR_SIZE_BYTES
                            + ((bit<16>)hdr.scion_common.hdr_len << 2) + hdr.scion_common.payload_len;
                        hdr.outer_udp.chksum = 0;

                        // Initialize the underlay IP header
                        if (hdr.ipv4.isValid()) {
                            hdr.ipv4.version = 4;
                            hdr.ipv4.ihl = 5;
                            hdr.ipv4.diffserv = 0;
                            hdr.ipv4.total_len = hdr.outer_udp.length + IPV4_HDR_MIN_SIZE_BYTES;
                            hdr.ipv4.id = 1;
                            hdr.ipv4.flags = 3w2; // don't fragment
                            hdr.ipv4.frag_offset = 0;
                            hdr.ipv4.ttl = 64;
                            hdr.ipv4.protocol = IP_PROTO_UDP;
                            hdr.ipv4.chksum = 0;
                        }
                        if (hdr.ipv6.isValid()) {
                            hdr.ipv6.version = 6;
                            hdr.ipv6.traffic_class = 0;
                            hdr.ipv6.flow_label = 0;
                            hdr.ipv6.payload_len = hdr.outer_udp.length;
                            hdr.ipv6.next_hdr = IP_PROTO_UDP;
                            hdr.ipv6.hop_limit = 64;
                        }
                    }
                }
            }
        } else {
            not_translated = 1;
        }

        if (not_translated == 1) {
            // Undo SCION headers
            hdr.scion_common.setInvalid();
            hdr.scion_src_host_4.setInvalid();
            hdr.scion_src_host_16.setInvalid();
            hdr.scion_dst_host_4.setInvalid();
            hdr.scion_dst_host_16.setInvalid();
        } else {
            // Insert path
            INSERT_PATH_META();
            INSERT_INF_FIELDS();
            INSERT_HOP_FIELDS();
            // TCP MSS Clamping
            if (hdr.tcp_mss.isValid() && hdr.tcp_mss.type == TCP_OPT_TYPE_MSS) {
                hdr.tcp_mss.mss = max_payload - TCP_HDR_SIZE_BYTES;
            }
        }

        // Adjust packet size metadata
        if (hdr.cmp.isValid() && !had_cmp) meta.tuser_size = meta.tuser_size + 8;
        if (hdr.ipv4.isValid() && had_ipv6) {
            meta.tuser_size = meta.tuser_size + IPV4_HDR_MIN_SIZE_BYTES - IPV6_HDR_SIZE_BYTES;
        }

        if (hdr.outer_udp.isValid()) meta.tuser_size = meta.tuser_size + UDP_HDR_SIZE_BYTES;
        if (hdr.cpu.isValid()) meta.tuser_size = meta.tuser_size + CPU_HDR_SIZE_BYTES;

        if (hdr.scion_common.isValid()) meta.tuser_size = meta.tuser_size + SC_COMMON_HDR_SIZE_BYTES;
        if (hdr.scion_dst_host_4.isValid()) meta.tuser_size = meta.tuser_size + 4;
        if (hdr.scion_dst_host_16.isValid()) meta.tuser_size = meta.tuser_size + 16;
        if (hdr.scion_src_host_4.isValid()) meta.tuser_size = meta.tuser_size + 4;
        if (hdr.scion_src_host_16.isValid()) meta.tuser_size = meta.tuser_size + 16;

        if (hdr.path_meta.isValid()) meta.tuser_size = meta.tuser_size + 4;
        if (hdr.path_info0.isValid()) meta.tuser_size = meta.tuser_size + 8;
        if (hdr.path_info1.isValid()) meta.tuser_size = meta.tuser_size + 8;
        if (hdr.path_info2.isValid()) meta.tuser_size = meta.tuser_size + 8;

        if (hdr.path_hop0.isValid()) meta.tuser_size = meta.tuser_size + 12;
        if (hdr.path_hop1.isValid()) meta.tuser_size = meta.tuser_size + 12;
        if (hdr.path_hop2.isValid()) meta.tuser_size = meta.tuser_size + 12;
        if (hdr.path_hop3.isValid()) meta.tuser_size = meta.tuser_size + 12;
        if (hdr.path_hop4.isValid()) meta.tuser_size = meta.tuser_size + 12;
        if (hdr.path_hop5.isValid()) meta.tuser_size = meta.tuser_size + 12;
        if (hdr.path_hop6.isValid()) meta.tuser_size = meta.tuser_size + 12;
        if (hdr.path_hop7.isValid()) meta.tuser_size = meta.tuser_size + 12;
        if (hdr.path_hop8.isValid()) meta.tuser_size = meta.tuser_size + 12;
        if (hdr.path_hop9.isValid()) meta.tuser_size = meta.tuser_size + 12;
        if (hdr.path_hop10.isValid()) meta.tuser_size = meta.tuser_size + 12;
        if (hdr.path_hop11.isValid()) meta.tuser_size = meta.tuser_size + 12;
        if (hdr.path_hop12.isValid()) meta.tuser_size = meta.tuser_size + 12;
        if (hdr.path_hop13.isValid()) meta.tuser_size = meta.tuser_size + 12;
        if (hdr.path_hop14.isValid()) meta.tuser_size = meta.tuser_size + 12;
        if (hdr.path_hop15.isValid()) meta.tuser_size = meta.tuser_size + 12;

        // Clear L4 header checksum
        // Inner L4 checksum is usually not used in SCION.
        // If this packet was not translated we must ensure the checksum is zero
        // before we send the packet to the checksum unit.
        if (hdr.cmp.isValid()) {
            hdr.cmp.chksum = 0;
        }
        if (hdr.tcp.isValid()) {
            hdr.tcp.chksum = 0;
        }
        if (hdr.udp.isValid()) {
            hdr.udp.chksum = 0;
        }

        // Set payload offset for checksum unit
        if (hdr.ipv4.isValid()) {
            setPayloadOffset(ETH_HDR_SIZE_BYTES + IPV4_HDR_MIN_SIZE_BYTES);
        } else if (hdr.ipv6.isValid()) {
            setPayloadOffset(ETH_HDR_SIZE_BYTES + IPV6_HDR_SIZE_BYTES);
        }

        if (smeta.drop == 0) {
            cnt_tdest.count(meta.axis_tdest);
        }

        // Clear metadata that is not part of the external interface
        meta.l4_src_port = 0;
        meta.l4_dst_port = 0;
    }
}

//////////////
// Deparser //
//////////////

control EgrTransDeparser(
    packet_out                pkt,
    in    headers_t           hdr,
    inout metadata_t          meta,
    inout standard_metadata_t smeta)
{
    apply {
        pkt.emit(hdr);
    }
}

//////////
// Main //
//////////

XilinxPipeline(
    EgrTransParser(),
    EgrTransProcessing(),
    EgrTransDeparser()
) main;
