/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// NOTE: new type added here
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_TUN  = 0x1212;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// NOTE: added new header type
header tunnel_t {
    bit<16> tunnel_id;
    bit<8>  vcount;
    bit<8>  _pad;
    bit<16> innerEtherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header validation_t { 
    bit<16> hop_value; 
    bit<16> _pad; 
}

struct metadata_t {
    /* empty */
}

// NOTE: Added new header type to headers struct
struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tunnel_t   tunnel;
    validation_t v0;
    validation_t v1;
    validation_t v2;
    validation_t v3;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// TODO: Update the parser to parse the myTunnel header as well
parser MyParser(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_TUN  : parse_tunnel;
            TYPE_IPV4 : parse_ipv4;
            default   : accept;
        }
    }
    state parse_ipv4 { packet.extract(hdr.ipv4); transition accept; }
    state parse_tunnel { packet.extract(hdr.tunnel); transition parse_v; }

    state parse_v {
        transition select(hdr.tunnel.vcount) {
            0: after_v;
            1: v1;  
            2: v2; 
            3: v3;
            default: v4;

        }
    }
    state v1 { packet.extract(hdr.v0); transition after_v; }
    state v2 { packet.extract(hdr.v0); packet.extract(hdr.v1); transition after_v; }
    state v3 { packet.extract(hdr.v0); packet.extract(hdr.v1); packet.extract(hdr.v2); transition after_v; }
    state v4 { packet.extract(hdr.v0); packet.extract(hdr.v1); packet.extract(hdr.v2); packet.extract(hdr.v3); transition after_v; }

    state after_v {
        transition select(hdr.tunnel.innerEtherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers_t hdr,
                         inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.ipv4.isValid()) {
            verify_checksum(hdr.ipv4.isValid(),
                { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen,
                  hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl,
                  hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
                hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        }
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers_t hdr,
                  inout metadata_t meta, 
                  inout standard_metadata_t standard_metadata) {
                  
    const bit<8> MAX = 4;

    action set_port(bit<9> port) { standard_metadata.egress_spec = port; }

    action set_tunnel(bit<16> tid, bit<16> first_hop) {
        hdr.tunnel.setValid();
        hdr.tunnel.tunnel_id     = tid;
        hdr.tunnel.vcount        = 0;
        hdr.tunnel.innerEtherType= hdr.ethernet.etherType;
        hdr.ethernet.etherType   = TYPE_TUN;
        if (hdr.tunnel.vcount < MAX) {
          if (hdr.tunnel.vcount == 0)      { hdr.v0.setValid(); hdr.v0.hop_value = first_hop; }
          else if (hdr.tunnel.vcount == 1) { hdr.v1.setValid(); hdr.v1.hop_value = first_hop; }
          else if (hdr.tunnel.vcount == 2) { hdr.v2.setValid(); hdr.v2.hop_value = first_hop; }
          else                             { hdr.v3.setValid(); hdr.v3.hop_value = first_hop; }
          hdr.tunnel.vcount = hdr.tunnel.vcount + 1;
        }    
 
    }

    action push_and_fwd(bit<9> port, bit<16> hop) {
        if (hdr.tunnel.isValid() && hdr.tunnel.vcount < MAX) {
            if (hdr.tunnel.vcount == 0)      { hdr.v0.setValid(); hdr.v0.hop_value = hop; }
            else if (hdr.tunnel.vcount == 1) { hdr.v1.setValid(); hdr.v1.hop_value = hop; }
            else if (hdr.tunnel.vcount == 2) { hdr.v2.setValid(); hdr.v2.hop_value = hop; }
            else                             { hdr.v3.setValid(); hdr.v3.hop_value = hop; }
            hdr.tunnel.vcount = hdr.tunnel.vcount + 1;
        }
        standard_metadata.egress_spec = port;
    }

    action egress_check(bit<16> threshold, bit<9> out_port,
                        bit<48> new_dmac, bit<48> new_smac) {
        bit<32> sum=0;
        if (hdr.v0.isValid()) sum = sum + (bit<32>)hdr.v0.hop_value;
        if (hdr.v1.isValid()) sum = sum + (bit<32>)hdr.v1.hop_value;
        if (hdr.v2.isValid()) sum = sum + (bit<32>)hdr.v2.hop_value;
        if (hdr.v3.isValid()) sum = sum + (bit<32>)hdr.v3.hop_value;


        if (sum >= (bit<32>)threshold) {
            hdr.ethernet.dstAddr = new_dmac;
            hdr.ethernet.srcAddr = new_smac;
            hdr.ethernet.etherType = hdr.tunnel.innerEtherType;
            hdr.v0.setInvalid(); hdr.v1.setInvalid(); hdr.v2.setInvalid(); hdr.v3.setInvalid();
            hdr.tunnel.setInvalid();
            standard_metadata.egress_spec = out_port;
        } else {
            mark_to_drop(standard_metadata);
        }
    }

    table ingress_classify {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.ipv4.diffserv: ternary;
        }
        actions = { set_tunnel; NoAction; }
        size = 1024;
        default_action = NoAction();
    }

    table tunnel_fwd {
        key = { hdr.tunnel.tunnel_id: exact; }
        actions = { set_port; NoAction; }
        size = 1024; default_action = NoAction();
    }

    table tunnel_transit {
        key = { hdr.tunnel.tunnel_id: exact; }
        actions = { push_and_fwd; NoAction; }
        size = 1024; default_action = NoAction();
    }

    table egress_policy {
        key = { hdr.tunnel.tunnel_id: exact; }
        actions = { egress_check; NoAction; }
        size = 256; default_action = NoAction();
    }

    apply {
        if (!hdr.tunnel.isValid()) {
            if (ingress_classify.apply().hit) { tunnel_fwd.apply(); return; }
        } else {
            if (egress_policy.apply().hit) { return; }
            if (!tunnel_transit.apply().hit) { tunnel_fwd.apply(); }
            return;
        }
        mark_to_drop(standard_metadata);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers_t hdr,
                 inout metadata_t meta, 
                 inout standard_metadata_t standard_metadata) { apply { } }

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers_t hdr,
                          inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.ipv4.isValid()) {
            update_checksum(hdr.ipv4.isValid(),
                { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen,
                  hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl,
                  hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
                hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        }
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet,
                   in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        if (hdr.tunnel.isValid()) {
            packet.emit(hdr.tunnel);
            if (hdr.v0.isValid()) packet.emit(hdr.v0);
            if (hdr.v1.isValid()) packet.emit(hdr.v1);
            if (hdr.v2.isValid()) packet.emit(hdr.v2);
            if (hdr.v3.isValid()) packet.emit(hdr.v3);

        }
        if (hdr.ipv4.isValid()) packet.emit(hdr.ipv4);
    }
}


/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
  MyParser(),
  MyVerifyChecksum(), 
  MyIngress(), 
  MyEgress(), 
  MyComputeChecksum(), 
  MyDeparser()
) main;
