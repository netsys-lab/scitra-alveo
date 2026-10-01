// SPDX-License-Identifier: AGPL-3.0-or-later

#include <core.p4>
#include <xsa.p4>

include(`include/headers.p4')

struct metadata_t
{
    bit<16> payload_chksum;
}

struct headers_t
{
    ethernet_h ether;
    ipv4_h     ipv4;
    ipv6_h     ipv6;
    icmp6_h    icmp;
    tcp_h      tcp;
    udp_h      udp;
}

////////////
// Parser //
////////////

parser EgrChksumParser(
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
        pkt.extract(hdr.icmp);
        transition accept;
    }

    state tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

////////////////
// Processing //
////////////////

control EgrChksumProcessing(
    inout headers_t           hdr,
    inout metadata_t          meta,
    inout standard_metadata_t smeta)
{
    // === Externs ===

    Checksum<bit<16>>(HashAlgorithm_t.ONES_COMPLEMENT16) ipv4_chksum;
    InternetChecksum() l4_checksum;

    // === Global Actions ===

    action dropPacket() {
        smeta.drop = 1;
    }

    // === Main ===
    apply {
        // Check parser errors
        if (smeta.parser_error != error.NoError) {
            dropPacket();
        }

        l4_checksum.add(meta.payload_chksum);

        if (hdr.ipv4.isValid()) {
            // Compute IPv4 header checksum
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
            }, hdr.ipv4.chksum);
            if (hdr.icmp.isValid()) {
                l4_checksum.get(hdr.icmp.chksum);
            } else if (hdr.tcp.isValid()) {
                l4_checksum.add({
                    hdr.ipv4.src,
                    hdr.ipv4.dst,
                    8w0,
                    hdr.ipv4.protocol,
                    hdr.ipv4.total_len - IPV4_HDR_MIN_SIZE_BYTES // TODO: revisit if we allow IPv4 options
                });
                l4_checksum.get(hdr.tcp.chksum);
            } else if (hdr.udp.isValid()) {
                l4_checksum.add({
                    hdr.ipv4.src,
                    hdr.ipv4.dst,
                    8w0,
                    hdr.ipv4.protocol,
                    hdr.udp.length
                });
                l4_checksum.get(hdr.udp.chksum);
            }
        } else if (hdr.ipv6.isValid()) {
            // IPv6 pseudo-header
            l4_checksum.add({
                hdr.ipv6.src,
                hdr.ipv6.dst,
                hdr.ipv6.payload_len, // TODO: revisit if we allow IPv6 extension headers
                8w0,
                hdr.ipv6.next_hdr // TODO: revisit if we allow IPv6 extension headers
            });
            if (hdr.icmp.isValid()) {
                l4_checksum.get(hdr.icmp.chksum);
            } else if (hdr.tcp.isValid()) {
                l4_checksum.get(hdr.tcp.chksum);
            } else if (hdr.udp.isValid()) {
                l4_checksum.get(hdr.udp.chksum);
            }
        }
    }
}

//////////////
// Deparser //
//////////////

control EgrChksumDeparser(
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
    EgrChksumParser(),
    EgrChksumProcessing(),
    EgrChksumDeparser()
) main;
