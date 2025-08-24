// tunnel.p4 - Programma P4 per progetto: tunnel, IPv4 forwarding, proof-of-transit

#include <core.p4>

// Header Tunnel Domain
header tunnel_hdr_t {
    bit<8>  tunnel_id;
    bit<32> pot_tag; // PoT tag (es hash, marker, oppure counter)
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

typedef struct {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tunnel_hdr_t tunnel;
} headers_t;

typedef struct {} metadata_t;

parser MyParser(packet_in pkt, out headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            0x0908: parse_tunnel; // EtherType custom per tunnel
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
    state parse_tunnel {
        pkt.extract(hdr.tunnel);
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control MyIngress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t smeta) {
    action ipv4_forward(bit<48> dst_mac, bit<9> port) {
        hdr.ethernet.dstAddr = dst_mac;
        smeta.egress_spec = port;
    }
    action encap_tunnel(bit<8> tunnel_id, bit<32> new_tag, bit<48> dst_mac, bit<9> port) {
        hdr.tunnel.setValid();
        hdr.tunnel.tunnel_id = tunnel_id;
        hdr.tunnel.pot_tag = new_tag; // inserisci PoT marker
        hdr.ethernet.dstAddr = dst_mac;
        smeta.egress_spec = port;
    }
    action decap_tunnel(bit<48> dst_mac, bit<9> port) {
        hdr.tunnel.setInvalid();
        hdr.ethernet.dstAddr = dst_mac;
        smeta.egress_spec = port;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            encap_tunnel;
            decap_tunnel;
            NoAction;
        }
        size = 64;
    }

    // Proof-of-Transit: ogni switch del dominio aggiorna il tag
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

control MyEgress(...) { /* ... */ }

control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        if (hdr.tunnel.isValid()) {
            pkt.emit(hdr.tunnel);
        }
        pkt.emit(hdr.ipv4);
    }
}

V1Switch(MyParser(), MyIngress(), MyEgress(), MyDeparser())
