// SPDX-License-Identifier: AGPL-3.0-or-later

#include <core.p4>
#include <xsa.p4>

include(`include/limits.p4')
include(`include/headers.p4')

typedef bit<10> payload_offset_t;

struct metadata_t
{
    bit<16>          tuser_size;
    bit<1>           is_scion;
    bit<6>           hop_fields;
    payload_offset_t payload_offset;
}

struct headers_t
{
    ethernet_h ether;
    // Underlay
    ipv4_h     ipv4;
    ipv6_h     ipv6;
    udp_h      udp;
    // SCION
    sc_common_h       scion_common;
    sc_host_addr_4_h  scion_dst_host_4;
    sc_host_addr_16_h scion_dst_host_16;
    sc_host_addr_4_h  scion_src_host_4;
    sc_host_addr_16_h scion_src_host_16;
    sc_path_meta_h    path_meta;
}

////////////
// Parser //
////////////

parser IngrClassParser(
    packet_in                 pkt,
    out   headers_t           hdr,
    inout metadata_t          meta,
    inout standard_metadata_t smeta)
{
    state start {
        // Clear input metadata that we will never read
        meta.is_scion = 0;
        meta.hop_fields = 0;
        meta.payload_offset = 10w1023;

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
            (0, 5, IP_PROTO_UDP): udp;
            default             : accept; // definitely not SCION
        }
    }

    state ipv6 {
        pkt.extract(hdr.ipv6);

        transition select (hdr.ipv6.next_hdr) {
            IP_PROTO_UDP: udp;
            default     : accept; // definitely not SCION
        }
    }

    state udp {
        pkt.extract(hdr.udp);
        // Continue parsing as if the packet has a SCION payload
        pkt.extract(hdr.scion_common);
        transition select (hdr.scion_common.host_type_len) {
            0x00 &&& 0xf0: dst_host_4;
            0x30 &&& 0xf0: dst_host_16;
        }
    }

    state dst_host_4 {
        pkt.extract(hdr.scion_dst_host_4);
        transition select (hdr.scion_common.host_type_len) {
            0x00 &&& 0x0f: src_host_4;
            0x03 &&& 0x0f: src_host_16;
        }
    }

    state dst_host_16 {
        pkt.extract(hdr.scion_dst_host_16);
        transition select (hdr.scion_common.host_type_len) {
            0x00 &&& 0x0f: src_host_4;
            0x03 &&& 0x0f: src_host_16;
        }
    }

    state src_host_4 {
        pkt.extract(hdr.scion_src_host_4);
        transition path;
    }

    state src_host_16 {
        pkt.extract(hdr.scion_src_host_16);
        transition path;
    }

    state path {
        transition select (hdr.scion_common.path_type) {
            PATH_TYPE_SCION: scion_path;
            default        :  accept;
        }
    }

    state scion_path {
        pkt.extract(hdr.path_meta);
        transition accept;
    }
}

////////////////
// Processing //
////////////////

const bit<3> CNT_DROPPED = 0;
const bit<3> CNT_OTHER = 1;
const bit<3> CNT_TOTAL_IPV4 = 2;
const bit<3> CNT_TOTAL_IPV6 = 3;
const bit<3> CNT_SCION_IPV4 = 4;
const bit<3> CNT_SCION_IPV6 = 5;

control IngrClassProcessing(
    inout headers_t           hdr,
    inout metadata_t          meta,
    inout standard_metadata_t smeta)
{
    // === Externs ===

    // Counters
    Counter<bit<32>, bit<3>>(6, CounterType_t.PACKETS) cnt_packets;

    // IPv4 header checksum verification
    Checksum<bit<16>>(HashAlgorithm_t.ONES_COMPLEMENT16) ipv4_chksum;
    bit<16> expected_chksum;

    /// == Global Actions ===

    action dropPacket() {
        smeta.drop = 1;
    }

    // === Local IP Match Table (IPv4 Underlay) ===
    // Match the packet's destination against local IP addresses used for SCION.

    table tab_local_addr_ipv4 {
        key = {
            hdr.ipv4.dst : exact;
        }
        actions = {
            NoAction;
        }
        const default_action = NoAction();
        size = 8;
    }

    // === Local IP Match Table (IPv6 Underlay) ===
    // Match the packet's destination against local IP addresses used for SCION.

    table tab_local_addr_ipv6 {
        key = {
            hdr.ipv6.dst : exact;
        }
        actions = {
            NoAction;
        }
        const default_action = NoAction();
        size = 8;
    }

    // === Static Port Mapping Table (IPv4 Underlay) ====
    // This table statically associates UDP ports with SCION.
    // Example: All UDP traffic on port 31000 should be treated as SCION.

    action static_ipv4_is_scion() {
        meta.is_scion = 1;
        cnt_packets.count(CNT_SCION_IPV4);
    }

    table tab_static_ports_ipv4 {
        key = {
            hdr.udp.dst : exact;
        }
        actions = {
            static_ipv4_is_scion;
            NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }

    // === Static Port Mapping Table (IPv6 Underlay) ====
    // This table statically associates UDP ports with SCION.
    // Example: All UDP traffic on port 31000 should be treated as SCION.

    action static_ipv6_is_scion() {
        meta.is_scion = 1;
        cnt_packets.count(CNT_SCION_IPV6);
    }

    table tab_static_ports_ipv6 {
        key = {
            hdr.udp.dst : exact;
        }
        actions = {
            static_ipv6_is_scion;
            NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }

    // === Dynamic Port Mapping Table (IPv4 Underlay) ===
    // This contains temporary ports on which we expect a response from another
    // SCION host. Matches both the destination port (local port) and the source
    // IP and port (remote host).

    Counter<bit<1>, bit<13>>(8192, CounterType_t.PACKETS) cnt_dynamic_ipv4_hit;

    action dynamic_ipv4_is_scion(bit<13> index) {
        meta.is_scion = 1;
        cnt_dynamic_ipv4_hit.count(index);
        cnt_packets.count(CNT_SCION_IPV4);
    }

    table tab_dynamic_ports_ipv4 {
        key = {
            hdr.ipv4.src : exact;
            hdr.udp.src  : exact;
            hdr.udp.dst  : exact;
        }
        actions = {
            dynamic_ipv4_is_scion;
            NoAction;
        }
        const default_action = NoAction();
        size = 8192;
    }

    // === Dynamic Port Mapping Table (IPv6 Underlay) ===
    // This contains temporary ports on which we expect a response from another
    // SCION host. Matches both the destination port (local port) and the source
    // IP and port (remote host).

    Counter<bit<1>, bit<13>>(8192, CounterType_t.PACKETS) cnt_dynamic_ipv6_hit;

    action dynamic_ipv6_is_scion(bit<13> index) {
        meta.is_scion = 1;
        cnt_dynamic_ipv6_hit.count(index);
        cnt_packets.count(CNT_SCION_IPV6);
    }

    table tab_dynamic_ports_ipv6 {
        key = {
            hdr.ipv6.src : exact;
            hdr.udp.src  : exact;
            hdr.udp.dst  : exact;
        }
        actions = {
            dynamic_ipv6_is_scion;
            NoAction;
        }
        const default_action = NoAction();
        size = 8192;
    }

    // The next core in the packet pipeline will calculate the checksum of the
    // packet starting from the calculated offset so we can verify the UDP
    // checksum afterwards.
    action setPayloadOffset(payload_offset_t offset) {
        meta.payload_offset = offset;
    }

    // === Main ===
    apply {
        // Ignore parser errors (packet might be too short if it was not SCION).
        // If it could be SCION, sum up the segment lengths for use in the
        // ingress translator's parser.

        // Drop packets that are too large for the checksum unit
        if (meta.tuser_size > MAX_PACKET_SIZE) {
            dropPacket();
            return;
        }

        // Calculate total number of hop fields for ingress translator parser
        if (hdr.path_meta.isValid()) {
            meta.hop_fields = hdr.path_meta.seg0_len
                + hdr.path_meta.seg1_len + hdr.path_meta.seg2_len;
        }

        if (hdr.ipv4.isValid()) {
            cnt_packets.count(CNT_TOTAL_IPV4);
            ipv4_chksum.apply({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.id,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src,
                hdr.ipv4.dst
            }, expected_chksum);
            if (hdr.ipv4.chksum != expected_chksum) {
                cnt_packets.count(CNT_DROPPED);
                dropPacket();
                return;
            }
            setPayloadOffset(ETH_HDR_SIZE_BYTES + IPV4_HDR_MIN_SIZE_BYTES);
            if (hdr.udp.isValid()) {
                if (tab_local_addr_ipv4.apply().hit) {
                    if (!tab_static_ports_ipv4.apply().hit) {
                        tab_dynamic_ports_ipv4.apply();
                    }
                }
            }
        } else if (hdr.ipv6.isValid()) {
            cnt_packets.count(CNT_TOTAL_IPV6);
            setPayloadOffset(ETH_HDR_SIZE_BYTES + IPV6_HDR_SIZE_BYTES);
            if (hdr.udp.isValid()) {
                if (tab_local_addr_ipv6.apply().hit) {
                    if (!tab_static_ports_ipv6.apply().hit) {
                    tab_dynamic_ports_ipv6.apply();
                    }
                }
            }
        } else {
            cnt_packets.count(CNT_OTHER);
        }
    }
}

//////////////
// Deparser //
//////////////

control IngrClassDeparser(
    packet_out                pkt,
    in    headers_t           hdr,
    inout metadata_t          meta,
    inout standard_metadata_t smeta)
{
    apply {
        pkt.emit(hdr);
    }
}

//////////////
// Pipeline //
//////////////

XilinxPipeline(
    IngrClassParser(),
    IngrClassProcessing(),
    IngrClassDeparser()
) main;
