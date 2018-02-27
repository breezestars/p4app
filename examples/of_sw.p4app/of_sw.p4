#include <core.p4>
#include <v1model.p4>

#include "header.p4"
#include "parser.p4"

control egress(inout headers hdr,
               inout metadata meta,
               inout standard_metadata_t standard_metadata) {

    apply {}
}

control ingress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }

    action setNhopIdx(bit<8> nhop_idx) {
        meta.ingress_metadata.nhopIsValid = 1;
        meta.ingress_metadata.nhop_index = nhop_idx;
    }

    action setBearer(bit<8> bearer) {
        meta.ingress_metadata.bearerIsValid = 1;
        meta.ingress_metadata.bearer = bearer;
    }

    action nextHopForward(bit<48> srcAddr, bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        if (port != 9w3){
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        }
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;

    }

    action NoActionSetBearer() {
        meta.ingress_metadata.bearerIsValid = 1;
        meta.ingress_metadata.bearer = 8w0b00000000;
        NoAction();
    }

    action DebugAction() {
        hdr.ethernet.dstAddr[15:0]=16w0xeeee;
        standard_metadata.egress_spec = 1;
        NoAction();
    }

    table MY_MAC {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            NoAction;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table TNL_TERM {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dstPort: exact;
        }
        actions = {
            setNhopIdx;
            NoAction;
            drop;
        }
        size = 1024;
        default_action = NoAction();
    }

    table BEARER_CLASSIFY {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            setBearer;
            NoActionSetBearer;
            drop;
        }
        size = 1024;
        default_action = NoActionSetBearer();
    }

    table IPV4_LPM {
        key = {
            meta.ingress_metadata.bearer: exact;
            hdr.ipv4.dstAddr: ternary;
        }
        actions = {
            setNhopIdx;
            NoAction;
            drop;
        }
        size = 1024;
        default_action = NoAction();
    }

    table NEXT_HOP {
        key = {
            meta.ingress_metadata.nhop_index: exact;
        }
        actions = {
            nextHopForward;
            NoAction;
            drop;
            DebugAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ethernet.isValid()) {
            MY_MAC.apply();
            TNL_TERM.apply();
            if (meta.ingress_metadata.nhopIsValid != 1) {
                BEARER_CLASSIFY.apply();
                IPV4_LPM.apply();
            }
            NEXT_HOP.apply();
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
