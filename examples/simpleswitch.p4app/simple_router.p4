#include <core.p4>
#include <v1model.p4>

#include "header.p4"
#include "parser.p4"

control ingress(inout headers hdr, inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    action _drop() {
        mark_to_drop();
    }

    action set_nhop(bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }

    action set_mac(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table ipv4_lpm {
        actions = {
            _drop;
            set_nhop;
            NoAction;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
        default_action = NoAction();
    }

    table arp_forward{
        actions = {
            _drop;
            set_mac;
            NoAction;
        }
        key = {
            hdr.arp_ipv4.target_ip: lpm;
        }
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }else
        {
            arp_forward.apply();
        }
    }
}

control egress(inout headers hdr, inout metadata meta,
               inout standard_metadata_t standard_metadata) {
    apply {
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
