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
