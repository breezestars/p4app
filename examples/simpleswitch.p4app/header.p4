#ifndef __HEADER_H__
#define __HEADER_H__ 1

struct ingress_metadata_t {
    bit<32> nhop_ipv4;
}

struct intrinsic_metadata_t {
    bit<48> ingress_global_timestamp;
    bit<32> lf_field_list;
    bit<16> mcast_grp;
    bit<16> egress_rid;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header arp_t {
    bit<16>  hard_type;
    bit<16>  prot_type;
    bit<8>  hard_size;
    bit<8>  prot_size;
    bit<16>  op;
}

header arp_ipv4_t {
    bit<48> sender_mac;
    bit<32> sender_ip;
    bit<48> target_mac;
    bit<32> target_ip;
}


struct metadata {
    ingress_metadata_t   ingress_metadata;
    intrinsic_metadata_t intrinsic_metadata;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    arp_t      arp;
    arp_ipv4_t arp_ipv4;
}

#endif // __HEADER_H__
