/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// NOTE: new type added here
const bit<16> TYPE_TUNNEL = 0x1212;  //EtherType of our tunnel
const bit<16> TYPE_IPV4 = 0x800;

//Max number of validation_h in the stack
const bit<8> MAX_STACK = 10;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<16> tid_t;


header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// NOTE: added new header type for the tunnel: ID + stack lenght
header tunnel_h_t {
    bit<16> tunnel_id;
    bit<16> stack_len;
    bit<8> rsvd;
}

//Header validation for the proof of transit
header validation_h_t {
    bit<16> hop_value;
    bit<16> rsvd;
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

struct parser_md_t {
    bit<8> remaining; //Number of validation_h to extract
}

struct ingress_md_t {} //Space for future extension

struct egress_md_t {
    bit<32> sum; //Sum of the hop_value
    bit<32> thresh; //Threshold for the tunnel_id
}

struct metadata {
    parser_md_t p;
    ingress_md_t ig;
    egress_md_t eg;
}

// NOTE: Added new header type to headers struct
struct headers {
    ethernet_t ethernet;
    tunnel_h_t tunnel_h;
    validation_h_t[MAX_STACK] vstack;
    ipv4_t ipv4;
}

error { //List of possible errors
    NoError,
    StackOverflow,
    IPv4HeaderTooShort
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// TODO: Update the parser to parse the myTunnel header as well
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_TUNNEL : parse_tunnel_h;
            TYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_tunnel_h {
        packet.extract(hdr.tunnel_h);
        verify(hdr.tunnel_h.stack_len <= MAX_STACK, error.StackOverflow);
        meta.p.remaining = hdr.tunnel_h.stack_len;
        transition select(meta.p.remaining) {
            0 : parse_ipv4;
            default : parse_validation_loop;
        }
    }

    state parse_validation_loop {
        packet.extract(hdr.vstack.next);
        meta.p.remaining = meta.p.remaining - 1;
        transition select(meta.p.remaining) {
            0 : parse_ipv4;
            default : parse_validation_loop;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.ihl >= 5, error.IPv4HeaderTooShort);
        transition accept;
    }


}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    //Simple forwarding using IPv4
    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    
    //Table without tunneling
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 2048;
        default_action = drop();
    }

    
    //Creation of tunnel_h + initialization of the stack with 1 validation_h
    action set_tunnel(bit<16> tid, bit<9> port, bit<16> initial_hop) {
        hdr.tunnel_h.setValid();
        hdr.tunnel_h.tunnel_id = tid;
        hdr.tunnel_h.stack_len = 1;
        hdr.ethernet.etherType = TYPE_TUNNEL;

        hdr.vstack.push_front(1);
        hdr.vstack[0].hop_value = initial_hop;

        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    }


    //Matching policy on IPv4 src, dst and DSCP for starting the tunnel
    table ipv4_classify {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: lpm;
            hdr.ipv4.diffserv[7:2]: exact;  //For the DSCP we need the 6 highest bit
        }
        actions = {
            set_tunnel;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    //Append of validation_h and forward on port
    action append_and_fwd(egressSpec_t port, bit<16> hop_value) {
        verify(hdr.tunnel_h.stack_len < MAX_STACK, error.StackOverflow);
        hdr.vstack.push_front(1);
        hdr.vstack[0].hop_value = hop_value;
        hdr.tunnel_h.stack_len = hdr.tunnel_h.stack_len + 1;
        standard_metadata.egress_spec = port;
    }


    //Forwarding on tunnel_id with append of the value
    table tunnel_fwd{
        key = {
            hdr.tunnel_h.tunnel_id: exact;
        }
        actions = {
            append_and_fwd;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    // TODO: also remember to add table entries!


    apply {
        // TODO: Update control flow
        if (hdr.ipv4.isValid() && !hdr.tunnel_h.isValid()) {
            if(!ipv4_classify.apply().hit) {
                ipv4_lpm.apply();
            }
        }

        if (hdr.tunnel_h.isValid()){
            tunnel_fwd.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action set_threshold(bit<16> t) {
        meta.eg.thresh = t;
    }

    
    //Threshold for the egress
    table tunnel_threshold {
        key = {
            hdr.tunnel_h.tunnel_id: exact;
        }
        actions = {
            set_threshold;
            NoAction;
        }
        size = 1024;
        default_action = set_threshold(0); //For default the threshold is null
    }


    action set_egress(bit<9> port) {
        standard_metadata.egress_spec = port;
    }


    //After the pop of the header final IPv4 to the host port
    table ipv4_lpm_egress {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_egress;
            drop;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }


    apply{
        tunnel_threshold.apply();

        //Sum of the stack
        meta.eg.sum = 0;
        if(hdr.vstack[0].isValid()){ meta.eg.sum = meta.eg.sum + (bit<32>) hdr.vstack[0].hop_value;}
        if(hdr.vstack[1].isValid()){ meta.eg.sum = meta.eg.sum + (bit<32>) hdr.vstack[1].hop_value;}
        if(hdr.vstack[2].isValid()){ meta.eg.sum = meta.eg.sum + (bit<32>) hdr.vstack[2].hop_value;}
        if(hdr.vstack[3].isValid()){ meta.eg.sum = meta.eg.sum + (bit<32>) hdr.vstack[3].hop_value;}
        if(hdr.vstack[4].isValid()){ meta.eg.sum = meta.eg.sum + (bit<32>) hdr.vstack[4].hop_value;}
        if(hdr.vstack[5].isValid()){ meta.eg.sum = meta.eg.sum + (bit<32>) hdr.vstack[5].hop_value;}
        if(hdr.vstack[6].isValid()){ meta.eg.sum = meta.eg.sum + (bit<32>) hdr.vstack[6].hop_value;}
        if(hdr.vstack[7].isValid()){ meta.eg.sum = meta.eg.sum + (bit<32>) hdr.vstack[7].hop_value;}
        if(hdr.vstack[8].isValid()){ meta.eg.sum = meta.eg.sum + (bit<32>) hdr.vstack[8].hop_value;}
        if(hdr.vstack[9].isValid()){ meta.eg.sum = meta.eg.sum + (bit<32>) hdr.vstack[9].hop_value;}

        //Pop and IPv4 forward or DROP
        if(meta.eg.sum >= (bit<32>) meta.eg.thresh) {
            if (hdr.vstack[0].isValid()){ hdr.vstack[0].setInvalid();} 
            if (hdr.vstack[1].isValid()){ hdr.vstack[1].setInvalid();} 
            if (hdr.vstack[2].isValid()){ hdr.vstack[2].setInvalid();} 
            if (hdr.vstack[3].isValid()){ hdr.vstack[3].setInvalid();} 
            if (hdr.vstack[4].isValid()){ hdr.vstack[4].setInvalid();} 
            if (hdr.vstack[5].isValid()){ hdr.vstack[5].setInvalid();} 
            if (hdr.vstack[6].isValid()){ hdr.vstack[6].setInvalid();} 
            if (hdr.vstack[7].isValid()){ hdr.vstack[7].setInvalid();} 
            if (hdr.vstack[8].isValid()){ hdr.vstack[8].setInvalid();} 
            if (hdr.vstack[9].isValid()){ hdr.vstack[9].setInvalid();} 
            hdr.tunnel_h.setInvalid();
            hdr.ethernet.etherType = TYPE_IPV4;
            ipv4_lpm_egress.apply();
        }
        else {
            mark_to_drop(standard_metadata);
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        if (hdr.tunnel_h.isValid()) {
            packet.emit(hdr.tunnel_h);
            if (hdr.vstack[0].isValid()) { packet.emit(hdr.vstack[0]);}
            if (hdr.vstack[1].isValid()) { packet.emit(hdr.vstack[1]);}
            if (hdr.vstack[2].isValid()) { packet.emit(hdr.vstack[2]);}
            if (hdr.vstack[3].isValid()) { packet.emit(hdr.vstack[3]);}
            if (hdr.vstack[4].isValid()) { packet.emit(hdr.vstack[4]);}
            if (hdr.vstack[5].isValid()) { packet.emit(hdr.vstack[5]);}
            if (hdr.vstack[6].isValid()) { packet.emit(hdr.vstack[6]);}
            if (hdr.vstack[7].isValid()) { packet.emit(hdr.vstack[7]);}
            if (hdr.vstack[8].isValid()) { packet.emit(hdr.vstack[8]);}
            if (hdr.vstack[9].isValid()) { packet.emit(hdr.vstack[9]);}
        }
        if (hdr.ipv4.isValid()) {
            packet.emit(hdr.ipv4);
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
