#line 1 "scitra/ingress_translator.p4"
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <core.p4>
#include <xsa.p4>

#line 1 "scitra/include/headers.p4"
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef _SCITRA_HEADERS_GUARD
#define _SCITRA_HEADERS_GUARD

//////////////////////
// Standard Headers //
//////////////////////

#define ETH_HDR_SIZE_BYTES 14
#define IPV4_HDR_MIN_SIZE_BYTES 20
#define IPV6_HDR_SIZE_BYTES 40
#define UDP_HDR_SIZE_BYTES 8
#define TCP_HDR_SIZE_BYTES 20
#define IPV6_MIN_MTU 1280

typedef bit<48> mac_addr_t;

typedef bit<16> ether_type;
const ether_type ETHER_TYPE_IPV4 = 0x0800;
const ether_type ETHER_TYPE_ARP  = 0x0806;
const ether_type ETHER_TYPE_IPV6 = 0x86DD;

typedef bit<8> ip_proto_t;
const ip_proto_t IP_PROTO_ICMP        = 1;
const ip_proto_t IP_PROTO_TCP         = 6;
const ip_proto_t IP_PROTO_UDP         = 17;
const ip_proto_t IP_PROTO_IPv6Frag    = 44;
const ip_proto_t IP_PROTO_ICMPv6      = 58;
const ip_proto_t IP_PROTO_HopByHopExt = 200; // SCION
const ip_proto_t IP_PROTO_End2EndExt  = 201; // SCION
const ip_proto_t IP_PROTO_SCMP        = 202; // SCION
const ip_proto_t IP_PROTO_BFD         = 203; // SCION

typedef bit<8> icmp6_type;
const icmp6_type ICMP6_TYPE_DestUnreach   = 1;
const icmp6_type ICMP6_TYPE_PacketTooBig  = 2;
const icmp6_type ICMP6_TYPE_TimeExceeded  = 3;
const icmp6_type ICMP6_TYPE_ParamProblem  = 4;
const icmp6_type ICMP6_TYPE_EchoRequest   = 128;
const icmp6_type ICMP6_TYPE_EchoReply     = 129;
const icmp6_type ICMP6_TYPE_RouterSolicit = 133;
const icmp6_type ICMP6_TYPE_RouterAdvert  = 134;
const icmp6_type ICMP6_TYPE_NeighSolicit  = 135;
const icmp6_type ICMP6_TYPE_NeighAdvert   = 136;
const icmp6_type ICMP6_TYPE_Redirect      = 137;

typedef bit<8> tcp_opt_type;
const tcp_opt_type TCP_OPT_TYPE_EOL = 0;
const tcp_opt_type TCP_OPT_TYPE_NOP = 1;
const tcp_opt_type TCP_OPT_TYPE_MSS = 2;

header ethernet_h {
    mac_addr_t dst;
    mac_addr_t src;
    ether_type etype;
}

header ipv4_h {
    bit<4>     version;
    bit<4>     ihl;
    bit<8>     diffserv;
    bit<16>    total_len;
    bit<16>    id;
    bit<3>     flags;
    bit<13>    frag_offset;
    bit<8>     ttl;
    ip_proto_t protocol;
    bit<16>    chksum;
    bit<32>    src;
    bit<32>    dst;
}

header ipv6_h {
    bit<4>     version;
    bit<8>     traffic_class;
    bit<20>    flow_label;
    bit<16>    payload_len;
    ip_proto_t next_hdr;
    bit<8>     hop_limit;
    bit<128>   src;
    bit<128>   dst;
}

header ipv6_opt_frag_h {
    ip_proto_t next_hdr;
    bit<8>     rsv1;
    bit<13>    frag_offset;
    bit<2>     rsv2;
    bit<1>     more_fragments;
}

header icmp6_h {
    icmp6_type type;
    bit<8>     code;
    bit<16>    chksum;
    bit<16>    param1;
    bit<16>    param2;
}

header udp_h {
    bit<16> src;
    bit<16> dst;
    bit<16> length;
    bit<16> chksum;
}

header tcp_h {
    bit<16> src;
    bit<16> dst;
    bit<32> seq_num;
    bit<32> ack_num;
    bit<4>  data_offset;
    bit<4>  reserved;
    bit<6>  flags;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> wnd;
    bit<16> chksum;
    bit<16> urgent;
}

header tcp_mss_h {
    tcp_opt_type type;   // must be MSS
    bit<8>       length; // must be 4
    bit<16>      mss;
}

///////////////////
// SCION Headers //
///////////////////

#define SC_COMMON_HDR_SIZE_BYTES 28

typedef bit<8> sc_path_type;
const sc_path_type PATH_TYPE_EMPTY   = 0;
const sc_path_type PATH_TYPE_SCION   = 1;
const sc_path_type PATH_TYPE_ONE_HOP = 2;
const sc_path_type PATH_TYPE_EPIC    = 3;
const sc_path_type PATH_TYPE_COLIBRI = 4;

typedef bit<8> scmp_type;
const scmp_type SCMP_DestUnreach  = 1;
const scmp_type SCMP_PacketTooBig = 2;
const scmp_type SCMP_ParamProblem = 4;
const scmp_type SCMP_ExtIfaceDown = 5;
const scmp_type SCMP_IntConnDown  = 6;
const scmp_type SCMP_EchoRequest  = 128;
const scmp_type SCMP_EchoReply    = 129;
const scmp_type SCMP_TraceRequest = 130;
const scmp_type SCMP_TraceReply   = 131;

typedef bit<16> sc_isd_t;
typedef bit<48> sc_asn_t;

header sc_common_h {
    // Common SCION header
    bit<4>       version;       // header version (= 0)
    bit<8>       qos;           // traffic class
    bit<20>      flow_id;       // mandatory flow id
    ip_proto_t   next_hdr;      // next header type
    bit<8>       hdr_len;       // header length in units of 4 bytes
    bit<16>      payload_len;   // payload length in bytes
    sc_path_type path_type;     // path type
    bit<8>       host_type_len; // DT, DL, ST, SL
    bit<16>      rsv;           // reserved

    // Common address header
    sc_isd_t dst_isd;
    sc_asn_t dst_asn;
    sc_isd_t src_isd;
    sc_asn_t src_asn;
}

// 4 byte host address
header sc_host_addr_4_h {
    bit<32> addr;
}

// 16 byte host address
header sc_host_addr_16_h {
    bit<128> addr;
}

header scmp_h {
    scmp_type type;
    bit<8>    code;
    bit<16>   chksum;
    bit<16>   param1;
    bit<16>   param2;
}

/////////////////////////
// Standard SCION Path //
/////////////////////////

#define SC_MAX_HOP_FIELDS 63
#define SC_HOP_FIELD_BITS 96
//const int SC_PATH_META_BYTES  = 4;  // 1 * 4 byte
//const int SC_INFO_FIELD_BYTES = 8;  // 2 * 4 byte
//const int SC_HOP_FIELD_BYTES  = 12; // 3 * 4 byte

// SCION Path meta header
header sc_path_meta_h {
    bit<2> curr_inf; // index of the current info field
    bit<6> curr_hf;  // index of the current hop field
    bit<6> rsv;      // reserved
    bit<6> seg0_len; // number of hop fields in path segment 0
    bit<6> seg1_len; // number of hop fields in path segment 1
    bit<6> seg2_len; // number of hop fields in path segment 2
}

// Info field
header sc_info_h {
    bit<6>  rsv1;    // reserved
    bit<1>  peering; // peering hop
    bit<1>  cons;    // path in construction direction (1) or against construction direction (0)
    bit<8>  rsv2;    // reserved
    bit<16> seg_id;  // segment ID for MAC chaining
    bit<32> tstamp;  // timestamp
}

header sc_info_blob_h {
    bit<64> data;
}

// Hop field
header sc_hop_h {
    bit<6>  rsv;      // reserved
    bit<1>  ig_alert; // ingress router alert
    bit<1>  eg_alert; // egress router alert
    bit<8>  exp_time; // expiration time
    bit<16> ig_if;    // AS ingress IFID
    bit<16> eg_if;    // AS egress IFID
    bit<48> mac;      // message authentication code
}

header sc_hop_blob_h {
    bit<96> data;
}

/////////////////////////////
// SCION Extension Headers //
/////////////////////////////

#define MAC_OPTION_LENGTH 64

header sc_ext_h {
    ip_proto_t next_hdr;
    bit<8>     ext_len;
}

header sc_opts_h {
    varbit<MAC_OPTION_LENGTH> options;
}

#endif // _SCITRA_HEADERS_GUARD
#line 6 "scitra/ingress_translator.p4"

#line 1 "scitra/include/cpu_header.p4"
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef _CPU_HEADER_GUARD
#define _CPU_HEADER_GUARD

#define CPU_PORT 13666
#define CPU_HDR_SIZE_BYTES 4

typedef bit<8> to_cpu_reason_t;
const to_cpu_reason_t TO_CPU_REASON_INGRESS_SCMP = 1;
const to_cpu_reason_t TO_CPU_REASON_EGRESS_SCMP = 2;
const to_cpu_reason_t TO_CPU_REASON_EGRESS_ICMP = 3;
const to_cpu_reason_t TO_CPU_REASON_EGRESS_NEW_FLOW = 4;

header cpu_h
{
    to_cpu_reason_t reason;
    bit<24>         reserved;
};

#endif // _CPU_HEADER_GUARD
#line 7 "scitra/ingress_translator.p4"

#line 1 "scitra/include/address_mapping.p4"
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef _SCITRA_ADDR_MAPPING_GUARD
#define _SCITRA_ADDR_MAPPING_GUARD

#define MAPPED_ISD_BITS 12
#define MAPPED_AS_BITS_BGP 19
#define MAPPED_AS_BITS_SCI 32
#define SCION_PREFIX 8w0xfc

#define extract_prefix(ip) ip[127:120]
#define extract_isd(ip) ip[119:108]

#define extract_asn_bgp(ip) ip[107:88]
#define extract_network_bgp(ip) ip[87:64]

#define extract_asn_sci(ip) ip[107:72]
#define extract_network_sci(ip) ip[71:64]

#define extract_host_prefix(ip) ip[63:32]
#define extract_host_v4(ip) ip[31:0]
#define extract_host_v6(ip) ip[63:0]

#endif // _SCITRA_ADDR_MAPPING_GUARD
#line 8 "scitra/ingress_translator.p4"


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

    // Encapsulate in UDP and  to controller
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
