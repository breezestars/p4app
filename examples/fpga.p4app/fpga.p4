#include <core.p4>
#include <v1model.p4>

#include "header.p4"
#include "parser.p4"

control egress(inout headers hdr,
               inout metadata meta,
               inout standard_metadata_t standard_metadata) {

    apply { }
}

control ingress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }

    action encap(bit<32> tunnel_DstIp, bit<32> tunnel_SrcIp,
                 bit<16> identification, bit<8> dscp, bit<8> ttl,
                 bit<16> udp_DstPort, bit<16> udp_SrcPort,
                 bit<8> gtp_Flags, bit<8> gtp_msgType) {

        //Set destination MAC Address
        bit<48> dmac = 48w0x00e04c68032b;

        //Set output port to OF_SW
        standard_metadata.egress_spec = 1;

        //Set ethernet Source Address and Destination Address
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.srcAddr[43:40] = 4w0b0001;
        hdr.ethernet.dstAddr = dmac;

        //Push outer IPv4 header, outer UDP header and GTP header
        hdr.o_ipv4.setValid();
        hdr.o_udp.setValid();
        hdr.gtp.setValid();

        //Set outer IPv4 header
        hdr.o_ipv4.version = hdr.ipv4.version;
        hdr.o_ipv4.ihl = hdr.ipv4.ihl;
        hdr.o_ipv4.diffserv = dscp;
        hdr.o_ipv4.totalLen = hdr.ipv4.totalLen + IPV4_HDR_SIZE +
                                      UDP_HDR_SIZE + GTP_HDR_SIZE;
        hdr.o_ipv4.identification = identification;
        hdr.o_ipv4.flags = hdr.ipv4.flags;
        hdr.o_ipv4.fragOffset = hdr.ipv4.fragOffset;
        hdr.o_ipv4.ttl = ttl;
        hdr.o_ipv4.protocol = 0x0011;
        hdr.o_ipv4.hdrChecksum = hdr.ipv4.hdrChecksum;
        hdr.o_ipv4.srcAddr = tunnel_SrcIp;
        hdr.o_ipv4.dstAddr = tunnel_DstIp;

        //Set outer UDP header
        hdr.o_udp.srcPort = udp_SrcPort;
        hdr.o_udp.dstPort = udp_DstPort;
        hdr.o_udp.length = hdr.ipv4.totalLen + UDP_HDR_SIZE + GTP_HDR_SIZE;

        //Set GTP header
        hdr.gtp.gtpFlags = gtp_Flags;
        hdr.gtp.msgType = gtp_msgType;
        hdr.gtp.totalLen = hdr.ipv4.totalLen;
        hdr.gtp.teid = hdr.ethernet.srcAddr[31:0];
    }

    action decap() {
        //Set destination MAC Address
        bit<48> dmac = 48w0x00e04c68032b;

        //Set output port to OF_SW
        standard_metadata.egress_spec = 2;

        //Set ethernet Source Address and Destination Address
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.srcAddr[43:40] = 4w0b0001;
        hdr.ethernet.srcAddr[31:0] = hdr.gtp.teid;
        hdr.ethernet.dstAddr = dmac;

        //Pop outer IPv4 header, outer UDP header and GTP header
        hdr.ipv4.setInvalid();
        hdr.udp.setInvalid();
        hdr.gtp.setInvalid();
    }

    action DebugAction() {
        hdr.ethernet.dstAddr[15:0]=16w0xeeee;
        standard_metadata.egress_spec = 1;
        NoAction();
    }

    table GTP_TUNNEL {
        key = {
            meta.ingress_metadata.tunnel_vp: exact;
        }
        actions = {
            encap;
            drop;
        }
        size = 2048;
        default_action = drop();
    }
    apply {
        if (hdr.ethernet.isValid()){
            if(hdr.ethernet.dstAddr[43:40]==4w0b0000) {
                meta.ingress_metadata.tunnel_vp[11:8] = hdr.ethernet.dstAddr[47:44];
                meta.ingress_metadata.tunnel_vp[7:0] = hdr.ethernet.dstAddr[39:32];
                GTP_TUNNEL.apply();
            }else {
                decap();
            }
        }
    }
}

V1Switch(
ParserImpl(),
verifyChecksum(),
ingress(),
egress(),
computeChecksum(),
DeparserImpl()
) main;
