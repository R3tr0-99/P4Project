/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> ETYPE_IPV4   = 0x0800;
const bit<16> ETYPE_TUNNEL = 0x1212;  

const int MAX_STACK = 8;          

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
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

header tunnel_h {
    bit<16> tunnel_id;
    bit<8>  count;     
    bit<8>  rsvd;
}

header validation_h {
    bit<16> hop_value;
    bit<16> rsvd;
}

struct headers_t {
    ethernet_t        ethernet;
    tunnel_h          tunnel;
    validation_h      v0;
    validation_h      v1;
    validation_h      v2;
    validation_h      v3;
    validation_h      v4;
    validation_h      v5;
    validation_h      v6;
    validation_h      v7;
    ipv4_t            ipv4;
}

struct metadata_t {
    bit<1> tunnel_chosen;
    bit<1> egress_chosen;
    bit<16> sum;
}
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETYPE_IPV4   : parse_ipv4;
            ETYPE_TUNNEL : parse_tunnel;
            default      : accept;
        }
    }

    state parse_tunnel {
        packet.extract(hdr.tunnel);
        transition parse_stack;
    }

       state parse_stack {
        transition select(hdr.tunnel.count) {
            0: parse_ipv4;
            default: parse_stack0;
        }
    }

    state parse_stack0 {
        packet.extract(hdr.v0);
        hdr.tunnel.count = hdr.tunnel.count - 1;
        transition select(hdr.tunnel.count) { 0: parse_ipv4; default: parse_stack1; }
    }
    state parse_stack1 {
        packet.extract(hdr.v1);
        hdr.tunnel.count = hdr.tunnel.count - 1;
        transition select(hdr.tunnel.count) { 0: parse_ipv4; default: parse_stack2; }
    }
    state parse_stack2 {
        packet.extract(hdr.v2);
        hdr.tunnel.count = hdr.tunnel.count - 1;
        transition select(hdr.tunnel.count) { 0: parse_ipv4; default: parse_stack3; }
    }
    state parse_stack3 {
        packet.extract(hdr.v3);
        hdr.tunnel.count = hdr.tunnel.count - 1;
        transition select(hdr.tunnel.count) { 0: parse_ipv4; default: parse_stack4; }
    }
    state parse_stack4 {
        packet.extract(hdr.v4);
        hdr.tunnel.count = hdr.tunnel.count - 1;
        transition select(hdr.tunnel.count) { 0: parse_ipv4; default: parse_stack5; }
    }
    state parse_stack5 {
        packet.extract(hdr.v5);
        hdr.tunnel.count = hdr.tunnel.count - 1;
        transition select(hdr.tunnel.count) { 0: parse_ipv4; default: parse_stack6; }
    }
    state parse_stack6 {
        packet.extract(hdr.v6);
        hdr.tunnel.count = hdr.tunnel.count - 1;
        transition select(hdr.tunnel.count) { 0: parse_ipv4; default: parse_stack7; }
    }
    state parse_stack7 {
        packet.extract(hdr.v7);
        hdr.tunnel.count = hdr.tunnel.count - 1;
        transition parse_ipv4;
    }


    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata)
{
    action drop() {
        mark_to_drop(standard_metadata);
    }

    /* ---- Actions ---- */

    action set_tunnel(bit<16> tid, bit<16> ingress_hop) {
        meta.tunnel_chosen = 1;
        hdr.tunnel.setValid();
        hdr.tunnel.tunnel_id = tid;
        hdr.tunnel.count = 0;
        hdr.ethernet.etherType = ETYPE_TUNNEL;

        if (ingress_hop != 0) {
            if (!hdr.v0.isValid()) {
                hdr.v0.setValid();
                hdr.v0.hop_value = ingress_hop;
                hdr.tunnel.count = hdr.tunnel.count + 1;
            }
        }
        // EtherType sarà impostato nel deparser se tunnel è valido
    }

    action set_port(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action push_and_fwd(bit<9> port, bit<16> hop_value) {
        /* Append validazione */

        if (!hdr.v0.isValid())      { hdr.v0.setValid(); hdr.v0.hop_value = hop_value; }
        else if (!hdr.v1.isValid()) { hdr.v1.setValid(); hdr.v1.hop_value = hop_value; }
        else if (!hdr.v2.isValid()) { hdr.v2.setValid(); hdr.v2.hop_value = hop_value; }
        else if (!hdr.v3.isValid()) { hdr.v3.setValid(); hdr.v3.hop_value = hop_value; }
        else if (!hdr.v4.isValid()) { hdr.v4.setValid(); hdr.v4.hop_value = hop_value; }
        else if (!hdr.v5.isValid()) { hdr.v5.setValid(); hdr.v5.hop_value = hop_value; }
        else if (!hdr.v6.isValid()) { hdr.v6.setValid(); hdr.v6.hop_value = hop_value; }
        else if (!hdr.v7.isValid()) { hdr.v7.setValid(); hdr.v7.hop_value = hop_value; }



        /* Aggiorna il contatore nel tunnel per la parsificazione futura */
        hdr.tunnel.count = hdr.tunnel.count + 1;

        /* Porta di uscita */
        standard_metadata.egress_spec = port;
    }

    action egress_check(bit<16> threshold, bit<9> out_port,
                        bit<48> smac, bit<48> dmac)
    {
        meta.sum = 0;
        if (hdr.v0.isValid()) meta.sum = meta.sum + hdr.v0.hop_value;
        if (hdr.v1.isValid()) meta.sum = meta.sum + hdr.v1.hop_value;
        if (hdr.v2.isValid()) meta.sum = meta.sum + hdr.v2.hop_value;
        if (hdr.v3.isValid()) meta.sum = meta.sum + hdr.v3.hop_value;
        if (hdr.v4.isValid()) meta.sum = meta.sum + hdr.v4.hop_value;
        if (hdr.v5.isValid()) meta.sum = meta.sum + hdr.v5.hop_value;
        if (hdr.v6.isValid()) meta.sum = meta.sum + hdr.v6.hop_value;
        if (hdr.v7.isValid()) meta.sum = meta.sum + hdr.v7.hop_value;


        if (meta.sum >= threshold) {
            /* Decapsulazione: invalida tunnel e stack */
            hdr.tunnel.setInvalid();
            if (hdr.v0.isValid()) hdr.v0.setInvalid();
            if (hdr.v1.isValid()) hdr.v1.setInvalid();
            if (hdr.v2.isValid()) hdr.v2.setInvalid();
            if (hdr.v3.isValid()) hdr.v3.setInvalid();
            if (hdr.v4.isValid()) hdr.v4.setInvalid();
            if (hdr.v5.isValid()) hdr.v5.setInvalid();
            if (hdr.v6.isValid()) hdr.v6.setInvalid();
            if (hdr.v7.isValid()) hdr.v7.setInvalid();


            /* Riscrivi MAC e imposta la porta */
            hdr.ethernet.etherType = ETYPE_IPV4;
            hdr.ethernet.srcAddr = smac;
            hdr.ethernet.dstAddr = dmac;
            standard_metadata.egress_spec = out_port;
            meta.egress_chosen = 1;
        } else {
            mark_to_drop(standard_metadata);
            meta.egress_chosen = 1; // per saltare eventuale transit
        }
    }

    action set_nhop(bit<32> nhop, bit<9> port) {
        // opzionale: forwarding IPv4 classico (se vuoi fuori dal tunnel)
        standard_metadata.egress_spec = port;
    }

    /* ---- Tables ---- */

    table ingress_classify {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.diffserv : ternary;
        }
        actions = {
            set_tunnel;
            @defaultonly drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table tunnel_fwd {
        key = {
            hdr.tunnel.tunnel_id : exact;
        }
        actions = { set_port; NoAction; }
        size = 1024;
        default_action = NoAction();
    }

    table tunnel_transit {
        key = {
            hdr.tunnel.tunnel_id : exact;
        }
        actions = { push_and_fwd; NoAction; }
        size = 2048;
        default_action = NoAction();
    }

    table egress_policy {
        key = {
            hdr.tunnel.tunnel_id : exact;
        }
        actions = { egress_check; NoAction; }
        size = 1024;
        default_action = NoAction();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = { set_nhop; drop; NoAction; }
        size = 1024;
        default_action = NoAction();
    }

    /* ---- Apply logic ---- */

    apply {
        meta.tunnel_chosen = 0;
        meta.egress_chosen = 0;
        meta.sum = 0;

        if (hdr.tunnel.isValid()) {
            /* Siamo dentro il tunnel domain */
            /* Se questo nodo è egress per il tunnel_id corrente, applica la policy */
            egress_policy.apply();
            if (meta.egress_chosen == 0) {
                /* Non egress: transito */
                tunnel_transit.apply();
            }
        } else if (hdr.ipv4.isValid()) {
            /* Nodo di ingresso (o traffico fuori tunnel) */
            ingress_classify.apply();
            if (meta.tunnel_chosen == 1) {
                /* abbiamo creato il tunnel: decidi la porta in base al tunnel_id */
                tunnel_fwd.apply();
            } else {
                /* fallback: IPv4 classico (opzionale) */
                ipv4_lpm.apply();
            }
        } else {
            /* Non IPv4: droppa */
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata)
{ apply { } }

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        if (hdr.ipv4.isValid()) {
            update_checksum(
                hdr.ipv4.isValid(),
                { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen,
                  hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset,
                  hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
                hdr.ipv4.hdrChecksum,
                HashAlgorithm.csum16
            );
        }
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet,
                   in headers_t hdr)
{
    apply {
        /* EtherType coerente con la presenza del tunnel */
        if (hdr.tunnel.isValid()) {
            packet.emit(hdr.ethernet);
            packet.emit(hdr.tunnel);
            /* emetti gli header di validazione presenti in ordine di stack */
            if (hdr.v0.isValid()) packet.emit(hdr.v0);
            if (hdr.v1.isValid()) packet.emit(hdr.v1);
            if (hdr.v2.isValid()) packet.emit(hdr.v2);
            if (hdr.v3.isValid()) packet.emit(hdr.v3);
            if (hdr.v4.isValid()) packet.emit(hdr.v4);
            if (hdr.v5.isValid()) packet.emit(hdr.v5);
            if (hdr.v6.isValid()) packet.emit(hdr.v6);
            if (hdr.v7.isValid()) packet.emit(hdr.v7);
            packet.emit(hdr.ipv4);
        } else {
            packet.emit(hdr.ethernet);
            if (hdr.ipv4.isValid()) {
                packet.emit(hdr.ipv4);
            }
        }
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
