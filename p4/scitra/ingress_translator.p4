// SPDX-License-Identifier: AGPL-3.0-or-later

#include <core.p4>
#include <xsa.p4>

include(`include/headers.p4')
include(`include/cpu_header.p4')
include(`include/address_mapping.p4')

struct metadata_t
{
    // Sideband size data from AXI stream
    bit<16> tuser_size;
    // Whether the packet has a SCION header
    bit<1>  is_scion;
    // hop_fields is the total number of hop fields in the packet. Valid if is_scion == 1
    bit<6>  hop_fields;
    // Output from checksum unit
    bit<16> payload_chksum;
}

struct scion_t {
    sc_common_h       common;
    sc_host_addr_4_h  dst_host_4;
    sc_host_addr_16_h dst_host_16;
    sc_host_addr_4_h  src_host_4;
    sc_host_addr_16_h src_host_16;
}

struct sc_path_t {
    sc_path_meta_h meta;
    sc_info_h      info0;
    sc_info_h      info1;
    sc_info_h      info2;
}

header sc_hop_blob32_h {
    bit<(32*SC_HOP_FIELD_BITS)> data;
}

header sc_hop_blob16_h {
    bit<(16*SC_HOP_FIELD_BITS)> data;
}

header sc_hop_blob8_h {
    bit<(8*SC_HOP_FIELD_BITS)> data;
}

header sc_hop_blob4_h {
    bit<(4*SC_HOP_FIELD_BITS)> data;
}

header sc_hop_blob2_h {
    bit<(2*SC_HOP_FIELD_BITS)> data;
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
    sc_path_meta_h  path_meta;
    sc_info_h       path_info0;
    sc_info_h       path_info1;
    sc_info_h       path_info2;
    sc_hop_blob32_h path_hf32;
    sc_hop_blob16_h path_hf16;
    sc_hop_blob8_h  path_hf8;
    sc_hop_blob4_h  path_hf4;
    sc_hop_blob2_h  path_hf2;
    sc_hop_blob_h   path_hf;
    // SCION Extensions
    sc_ext_h  scion_hbh_ext;
    sc_opts_h scion_hbh_opts;
    sc_ext_h  scion_e2e_ext;
    sc_opts_h scion_e2e_opts;
    // Upper layer headers
    tcp_h  tcp;
    udp_h  udp;
    scmp_h cmp; // (S|I)CMP
}

////////////
// Parser //
////////////

error {
    EmptyPath,   // Path is empty but shouldn't be
    TooManyHops  // Path contains too many hop fields
}

parser IngrTransParser(
    packet_in                 pkt,
    out   headers_t           hdr,
    inout metadata_t          meta,
    inout standard_metadata_t smeta)
{
    state start {
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
            (0, 5, IP_PROTO_UDP): outer_udp;
            default             : accept;
        }
    }

    state ipv6 {
        pkt.extract(hdr.ipv6);

        transition select (hdr.ipv6.next_hdr) {
            IP_PROTO_UDP: outer_udp;
            default     : accept;
        }
    }

    state outer_udp {
        pkt.extract(hdr.outer_udp);
        transition select (meta.is_scion) {
            0: accept;
            1: scion;
        }
    }

    ///////////
    // SCION //
    ///////////

    state scion {
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

    //////////
    // Path //
    //////////

    state path {
        transition select (hdr.scion_common.path_type) {
            PATH_TYPE_SCION: scion_path;
            default        :  accept;
        }
    }

    state scion_path {
        pkt.extract(hdr.path_meta);
        verify(hdr.path_meta.seg0_len != 0, error.EmptyPath);
        transition info_field0;
    }

    state info_field0 {
        pkt.extract(hdr.path_info0);
        transition select (hdr.path_meta.seg1_len) {
            0       : hop_fields;
            default : info_field1;
        }
    }

    state info_field1 {
        pkt.extract(hdr.path_info1);
        transition select (hdr.path_meta.seg2_len) {
            0       : hop_fields;
            default : info_field2;
        }
    }

    state info_field2 {
        pkt.extract(hdr.path_info2);
        transition hop_fields;
    }

    state hop_fields {
        transition select (meta.hop_fields) {
            0x20 &&& 0x20: hop_fields_discard_32;
            default      : hop_fields_32;
        }
    }

    state hop_fields_discard_32 {
        pkt.extract(hdr.path_hf32);

        transition select (meta.hop_fields) {
            0x10 &&& 0x10: hop_fields_discard_16;
            default      : hop_fields_16;
        }
    }

    state hop_fields_32 {
        transition select (meta.hop_fields) {
            0x10 &&& 0x10: hop_fields_discard_16;
            default      : hop_fields_16;
        }
    }

    state hop_fields_discard_16 {
        pkt.extract(hdr.path_hf16);

        transition select (meta.hop_fields) {
            0x08 &&& 0x08: hop_fields_discard_8;
            default      : hop_fields_8;
        }
    }

    state hop_fields_16 {
        transition select (meta.hop_fields) {
            0x08 &&& 0x08: hop_fields_discard_8;
            default      : hop_fields_8;
        }
    }

    state hop_fields_discard_8 {
        pkt.extract(hdr.path_hf8);

        transition select (meta.hop_fields) {
            0x04 &&& 0x04: hop_fields_discard_4;
            default      : hop_fields_4;
        }
    }

    state hop_fields_8 {
        transition select (meta.hop_fields) {
            0x04 &&& 0x04: hop_fields_discard_4;
            default      : hop_fields_4;
        }
    }

    state hop_fields_discard_4 {
        pkt.extract(hdr.path_hf4);

        transition select (meta.hop_fields) {
            0x02 &&& 0x02: hop_fields_discard_2;
            default      : hop_fields_2;
        }
    }

    state hop_fields_4 {
        transition select (meta.hop_fields) {
            0x02 &&& 0x02: hop_fields_discard_2;
            default      : hop_fields_2;
        }
    }

    state hop_fields_discard_2 {
        pkt.extract(hdr.path_hf2);

        transition select (meta.hop_fields) {
            0x01 &&& 0x01: hop_fields_discard_1;
            default      : scion_extensions;
        }
    }

    state hop_fields_2 {
        transition select (meta.hop_fields) {
            0x01 &&& 0x01: hop_fields_discard_1;
            default      : scion_extensions;
        }
    }

    state hop_fields_discard_1 {
        pkt.extract(hdr.path_hf);
        transition scion_extensions;
    }

    state scion_extensions {
        transition select (hdr.scion_common.next_hdr) {
            IP_PROTO_TCP        : tcp;
            IP_PROTO_UDP        : udp;
            IP_PROTO_HopByHopExt: hbh_ext;
            IP_PROTO_End2EndExt : e2e_ext;
            IP_PROTO_SCMP       : scmp;
            default             : accept;
        }
    }

    state hbh_ext {
        pkt.extract(hdr.scion_hbh_ext);
        pkt.extract(hdr.scion_hbh_opts, ((bit<32>)hdr.scion_hbh_ext.ext_len * 32) + 16);
        transition select (hdr.scion_hbh_ext.next_hdr) {
            IP_PROTO_TCP        : tcp;
            IP_PROTO_UDP        : udp;
            IP_PROTO_End2EndExt : e2e_ext;
            IP_PROTO_SCMP       : scmp;
            default             : accept;
        }
    }

    state e2e_ext {
        pkt.extract(hdr.scion_e2e_ext);
        pkt.extract(hdr.scion_e2e_opts, ((bit<32>)hdr.scion_e2e_ext.ext_len * 32) + 16);
        transition select (hdr.scion_e2e_ext.next_hdr) {
            IP_PROTO_TCP        : tcp;
            IP_PROTO_UDP        : udp;
            IP_PROTO_SCMP       : scmp;
            default             : accept;
        }
    }

    state tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    state scmp {
        pkt.extract(hdr.cmp);
        transition accept;
    }
}

////////////////
// Processing //
////////////////

const bit<2> CNT_DROP_PARSER = 0;
const bit<2> CNT_DROP_CHKSUM = 1;
const bit<2> CNT_DROP_SRC_ADDR = 2;
const bit<2> CNT_DROP_DST_ADDR = 3;

const bit<3> CNT_NOT_TRANSLATED = 0;
const bit<3> CNT_TO_CPU = 1;
const bit<3> CNT_SCMP = 2;
const bit<3> CNT_UDP = 3;
const bit<3> CNT_TCP = 4;

control IngrTransProcessing(
    inout headers_t           hdr,
    inout metadata_t          meta,
    inout standard_metadata_t smeta)
{
    // === Variables ===

    bit<16> discard_bytes = 0;
    bit<16> checksum = 0;
    bit<128> new_ipv6_src = 0;
    bit<128> new_ipv6_dst = 0;

    // === Externs ===

    // Counters
    Counter<bit<32>, bit<2>>(4, CounterType_t.PACKETS) cntDropped;
    Counter<bit<32>, bit<3>>(5, CounterType_t.PACKETS) cntTranslated;

    // Checksum verification
    Checksum<bit<16>>(HashAlgorithm_t.ONES_COMPLEMENT16) chksum_ext;

    /// == Global Actions ===

    action dropPacket() {
        smeta.drop = 1;
    }

    // === Destination IA Table ===
    // Table for dropping packets with the wrong ISD-ASN destination address.

    table tab_dest_ia {
        key = {
            hdr.scion_common.dst_isd : exact;
            hdr.scion_common.dst_asn : exact;
        }
        actions = {
            dropPacket;
            NoAction;
        }
        const default_action = NoAction();
        size = 8;
    }

    // === Source SCION-IPv4 to IPv6 translation table ===
    // Translates the SCION-IPv4 source address to a SCION-mapped IPv6.
    // The match key is used to make sure the address is mappable, drop the
    // packet if not. (TODO: Revisit what to do with untranslatable packets)
    // The table must contain two entries:
    // 0, 0 => translateSource46BGP
    // 0, 2 => translateSource46SCION

    // for BGP-style ASNs
    action translateSource46BGP() {
        extract_prefix(new_ipv6_src) = SCION_PREFIX;
        extract_isd(new_ipv6_src) = hdr.scion_common.src_isd[MAPPED_ISD_BITS-1:0];
        extract_asn_bgp(new_ipv6_src) = 1w0 ++ hdr.scion_common.src_asn[MAPPED_AS_BITS_BGP-1:0];
        extract_network_bgp(new_ipv6_src) = 0;
        extract_host_prefix(new_ipv6_src) = 0xffff;
        extract_host_v4(new_ipv6_src) = hdr.scion_src_host_4.addr;
    }

    // for SCION-style public ASNs
    action translateSource46SCION() {
        extract_prefix(new_ipv6_src) = SCION_PREFIX;
        extract_isd(new_ipv6_src) = hdr.scion_common.src_isd[MAPPED_ISD_BITS-1:0];
        extract_asn_sci(new_ipv6_src) = 4w14 ++ hdr.scion_common.src_asn[MAPPED_AS_BITS_SCI-1:0];
        extract_network_sci(new_ipv6_src) = 0;
        extract_host_prefix(new_ipv6_src) = 0xffff;
        extract_host_v4(new_ipv6_src) = hdr.scion_src_host_4.addr;
    }

    table tab_source_translation_46 {
        key = {
            hdr.scion_common.src_isd[15:MAPPED_ISD_BITS] : exact;
            hdr.scion_common.src_asn[47:32]              : exact;
        }
        actions = {
            translateSource46BGP;
            translateSource46SCION;
            dropPacket;
        }
        const default_action = dropPacket();
        size = 2;
    }

    // === Destination SCION-IPv4 to IPv6 translation table ===
    // Translates the SCION-IPv4 destination address to a SCION-mapped IPv6.
    // The match key is used to make sure the address is mappable, drop the
    // packet if not. (TODO: Revisit what to do with untranslatable packets)
    // The table must contain a two entries:
    // 0, 0 => translateSource46BGP
    // 0, 2 => translateSource46SCION

    // for BGP-style ASNs
    action translateDest46BGP() {
        extract_prefix(new_ipv6_dst) = SCION_PREFIX;
        extract_isd(new_ipv6_dst) = hdr.scion_common.dst_isd[MAPPED_ISD_BITS-1:0];
        extract_asn_bgp(new_ipv6_dst) = 1w0 ++ hdr.scion_common.dst_asn[MAPPED_AS_BITS_BGP-1:0];
        extract_network_bgp(new_ipv6_dst) = 0;
        extract_host_prefix(new_ipv6_dst) = 0xffff;
        extract_host_v4(new_ipv6_dst) = hdr.scion_dst_host_4.addr;
    }

    // for SCION-style public ASNs
    action translateDest46SCION() {
        extract_prefix(new_ipv6_dst) = SCION_PREFIX;
        extract_isd(new_ipv6_dst) = hdr.scion_common.dst_isd[MAPPED_ISD_BITS-1:0];
        extract_asn_sci(new_ipv6_dst) = 4w14 ++ hdr.scion_common.dst_asn[MAPPED_AS_BITS_SCI-1:0];
        extract_network_sci(new_ipv6_dst) = 0;
        extract_host_prefix(new_ipv6_dst) = 0xffff;
        extract_host_v4(new_ipv6_dst) = hdr.scion_dst_host_4.addr;
    }

    table tab_dest_translation_46 {
        key = {
            hdr.scion_common.dst_isd[15:MAPPED_ISD_BITS] : exact;
            hdr.scion_common.dst_asn[47:32]              : exact;
        }
        actions = {
            translateDest46BGP;
            translateDest46SCION;
            dropPacket;
        }
        const default_action = dropPacket();
        size = 2;
    }

    // === SCMP Translation Table ===
    // Either translate SCMP to ICMP directly or forward to the CPU.

    action scmpTranslate() {
        hdr.ipv6.next_hdr = IP_PROTO_ICMPv6;
        cntTranslated.count(CNT_SCMP);
    }

    // Encapsulate in UDP and divert to controller
    action scmpToCPU() {
        mac_addr_t temp = hdr.ether.dst;
        hdr.ether.dst = hdr.ether.src;
        hdr.ether.src = temp;

        hdr.ipv6.next_hdr = IP_PROTO_UDP;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + UDP_HDR_SIZE_BYTES + CPU_HDR_SIZE_BYTES;

        hdr.ipv6.dst = hdr.ipv6.src;

        hdr.outer_udp.setValid();
        hdr.outer_udp.src = 0;
        hdr.outer_udp.dst = CPU_PORT;
        hdr.outer_udp.length = hdr.ipv6.payload_len;
        hdr.outer_udp.chksum = 0;

        hdr.cpu.setValid();
        hdr.cpu = { TO_CPU_REASON_INGRESS_SCMP, 0 };

        meta.tuser_size = meta.tuser_size + UDP_HDR_SIZE_BYTES + CPU_HDR_SIZE_BYTES;

        cntTranslated.count(CNT_TO_CPU);
    }

    table tab_scmp {
        key = {
            hdr.cmp.type : exact;
        }
        actions = {
            scmpTranslate;
            scmpToCPU;
        }
        const default_action = scmpToCPU();
        direct_match = true;
    }

    // === Main ===
    apply {
        // Check parser errors
        if (smeta.parser_error != error.NoError) {
            cntDropped.count(CNT_DROP_PARSER);
            dropPacket();
        }

        // Checksum
        if (hdr.ipv4.isValid()) {
            if (hdr.ipv4.protocol == IP_PROTO_ICMP) {
                chksum_ext.apply({
                    meta.payload_chksum
                }, checksum);
            } else {
                chksum_ext.apply({
                    hdr.ipv4.src,
                    hdr.ipv4.dst,
                    8w0,
                    hdr.ipv4.protocol,
                    hdr.ipv4.total_len - 4 * (bit<16>)hdr.ipv4.ihl,
                    meta.payload_chksum
                }, checksum);
            }
        } else if (hdr.ipv6.isValid()) {
            chksum_ext.apply({
                hdr.ipv6.src,
                hdr.ipv6.dst,
                hdr.ipv6.payload_len, // NOTE: revisit when we allow IPv6 extension headers
                8w0,
                hdr.ipv6.next_hdr, // NOTE: revisit when we allow IPv6 extension headers
                meta.payload_chksum
            }, checksum);
        }
        if (checksum != 0) {
            cntDropped.count(CNT_DROP_CHKSUM);
            dropPacket();
        }

        // SCION to IP header translation
        if (hdr.scion_common.isValid()) {
            // Check if destination IA is correct
            tab_dest_ia.apply();

            // Adjust packet size metadata
            meta.tuser_size = meta.tuser_size - UDP_HDR_SIZE_BYTES - SC_COMMON_HDR_SIZE_BYTES;

            if (hdr.ipv4.isValid()) meta.tuser_size = meta.tuser_size - IPV4_HDR_MIN_SIZE_BYTES;
            if (!hdr.ipv6.isValid()) meta.tuser_size = meta.tuser_size + IPV6_HDR_SIZE_BYTES;

            if (hdr.scion_dst_host_4.isValid()) meta.tuser_size = meta.tuser_size - 4;
            if (hdr.scion_dst_host_16.isValid()) meta.tuser_size = meta.tuser_size - 16;
            if (hdr.scion_src_host_4.isValid()) meta.tuser_size = meta.tuser_size - 4;
            if (hdr.scion_src_host_16.isValid()) meta.tuser_size = meta.tuser_size - 16;

            if (hdr.path_meta.isValid()) meta.tuser_size = meta.tuser_size - 4;
            if (hdr.path_info0.isValid()) meta.tuser_size = meta.tuser_size - 8;
            if (hdr.path_info1.isValid()) meta.tuser_size = meta.tuser_size - 8;
            if (hdr.path_info2.isValid()) meta.tuser_size = meta.tuser_size - 8;

            if (hdr.path_hf32.isValid()) meta.tuser_size = meta.tuser_size - 384;
            if (hdr.path_hf16.isValid()) meta.tuser_size = meta.tuser_size - 192;
            if (hdr.path_hf8.isValid()) meta.tuser_size = meta.tuser_size - 96;
            if (hdr.path_hf4.isValid()) meta.tuser_size = meta.tuser_size - 48;
            if (hdr.path_hf2.isValid()) meta.tuser_size = meta.tuser_size - 24;
            if (hdr.path_hf.isValid()) meta.tuser_size = meta.tuser_size - 12;

            if (hdr.scion_hbh_ext.isValid()) {
                bit<16> hbh_len = 2 + ((bit<16>)hdr.scion_hbh_ext.ext_len * 4) + 2;
                meta.tuser_size = meta.tuser_size - hbh_len;
            }
            if (hdr.scion_e2e_ext.isValid()) {
                bit<16> e2e_len = 2 + ((bit<16>)hdr.scion_e2e_ext.ext_len * 4) + 2;
                meta.tuser_size = meta.tuser_size - e2e_len;
            }

            // Check and translate source address
            if (hdr.scion_src_host_4.isValid()) {
                tab_source_translation_46.apply();
            } else if (hdr.scion_src_host_16.isValid()) {
                sc_asn_t asn;
                if (hdr.scion_src_host_16.addr[107:107] == 0) { // BGP ASN
                    asn = 29w0 ++ hdr.scion_src_host_16.addr[106:88];
                } else { // if (hdr.scion_src_host_16.addr[107:104] == 14) { // Public SCION ASN
                    asn = 16w2 ++ hdr.scion_src_host_16.addr[103:72];
                }
                if (extract_prefix(hdr.scion_src_host_16.addr) == SCION_PREFIX
                 && hdr.scion_common.src_isd == (bit<16>)(extract_isd(hdr.scion_src_host_16.addr))
                 && hdr.scion_common.src_asn == asn) {
                    new_ipv6_src = hdr.scion_src_host_16.addr;
                } else {
                    cntDropped.count(CNT_DROP_SRC_ADDR);
                    dropPacket();
                }
            }

            // Check destination address
            if (hdr.scion_dst_host_4.isValid()) {
                if (hdr.ipv4.isValid() && hdr.ipv4.dst == hdr.scion_dst_host_4.addr) {
                    tab_dest_translation_46.apply();
                } else {
                    cntDropped.count(CNT_DROP_DST_ADDR);
                    dropPacket();
                }
            } else if (hdr.scion_dst_host_16.isValid()) {
                if (hdr.ipv6.isValid() && hdr.ipv6.dst == hdr.scion_dst_host_16.addr) {
                    new_ipv6_dst = hdr.scion_dst_host_16.addr;
                } else {
                    cntDropped.count(CNT_DROP_DST_ADDR);
                    dropPacket();
                }
            }

            // Prepare new IPv6 header
            hdr.ipv4.setInvalid();
            hdr.ipv6.setValid();
            hdr.outer_udp.setInvalid();
            hdr.ether.etype = ETHER_TYPE_IPV6;
            hdr.ipv6.setValid();
            hdr.ipv6.version = 6;
            hdr.ipv6.traffic_class = hdr.scion_common.qos;
            hdr.ipv6.flow_label = hdr.scion_common.flow_id;
            hdr.ipv6.hop_limit = 8;
            hdr.ipv6.src = new_ipv6_src;
            hdr.ipv6.dst = new_ipv6_dst;
            hdr.ipv6.payload_len = hdr.scion_common.payload_len;
            if (hdr.scion_hbh_ext.isValid()) {
                bit<16> hbh_len = ((bit<16>)hdr.scion_hbh_ext.ext_len + 1) << 2;
                hdr.ipv6.payload_len = hdr.ipv6.payload_len - hbh_len;
            }
            if (hdr.scion_e2e_ext.isValid()) {
                bit<16> e2e_len = ((bit<16>)hdr.scion_e2e_ext.ext_len + 1) << 2;
                hdr.ipv6.payload_len = hdr.ipv6.payload_len - e2e_len;
            }

            if (hdr.udp.isValid()) {
                hdr.ipv6.next_hdr = IP_PROTO_UDP;
                hdr.udp.chksum = 0; // not checked by host
                cntTranslated.count(CNT_UDP);
            } else if (hdr.tcp.isValid()) {
                hdr.ipv6.next_hdr = IP_PROTO_TCP;
                hdr.tcp.chksum = 0; // not checked by host
                cntTranslated.count(CNT_TCP);
            } else if (hdr.cmp.isValid()) { // SCMP
                tab_scmp.apply();
                hdr.cmp.chksum = 0; // not checked by host
            }
        } else {
            cntTranslated.count(CNT_NOT_TRANSLATED);
        }

        // Clear output metadata that is no longer useful
        meta.is_scion = 0;
        meta.hop_fields = 0;
        meta.payload_chksum = 0;
    }
}

//////////////
// Deparser //
//////////////

control IngrTransDeparser(
    packet_out                pkt,
    in    headers_t           hdr,
    inout metadata_t          meta,
    inout standard_metadata_t smeta)
{
    apply {
        pkt.emit(hdr.ether);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.outer_udp);
        pkt.emit(hdr.cpu);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.cmp);
    }
}

//////////
// Main //
//////////

XilinxPipeline(
    IngrTransParser(),
    IngrTransProcessing(),
    IngrTransDeparser()
) main;
