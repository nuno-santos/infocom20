/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
/*Number of concurrent flows to measure*/
const bit<32> flowNum = 100;
/*Number of counters for each flow*/
const bit<32> flowCounters = 25;

/*Diferent seeds for each row*/
const bit<32> seed1 = 12345678;
const bit<32> seed2 = 87654321;
const bit<32> seed3 = 43215678;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> idx_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    bit<32> hashPos;
    bit<32> hashValue;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
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

    /*Only one array is used for each row of all sketches. Each flow has flowCounters counters in the array, so we need only advance flowCounters * (index of sketch)*/
    /*We use registers instead of counters because the entire array of registers can be verified at once using bmv2's runtime_CLI*/
    register<bit<32>>(flowNum*flowCounters) row1;
    register<bit<32>>(flowNum*flowCounters) row2;
    register<bit<32>>(flowNum*flowCounters) row3;
    
    /*Used for the CM-PF implementation*/
    register<bit<32>>(flowNum) hashmap;
    
    action drop() {
        mark_to_drop();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        
        /*Regular forwarding logic*/
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        bit<32> value;

        bit<16> base = 0;
        bit<32> pos;
        bit<32> position;

        if (hdr.ipv4.isValid()) {

            ipv4_lpm.apply();

            /*Currently only uses the ip src address to hash*/
            /* Reduces IP to smaller identifier, otherwise it tends to throw an error when writing to the hashmap. Not an ideal solution.*/
            bit<32> tmp = hdr.ipv4.srcAddr << 16;
            tmp = tmp >> 16;

            /*Get position in HashMap*/
            hash(pos,
            HashAlgorithm.crc32,
            base,
            { tmp },
            flowNum);

            /*Read HashMap on that position*/
            hashmap.read(meta.hashValue, pos);

            /*Add identifier to HashMap if empty*/
            if (meta.hashValue == 0) {
                meta.hashValue = hdr.ipv4.srcAddr << 16;
                meta.hashValue = meta.hashValue >> 16;
                hashmap.write(pos, meta.hashValue);
            }

            /*If value in HashMap is the same as the ip src address, increment counters*/
            /*Currently without access to the source code, it is impossible to implement a way to divide the packet size into buckets
                since neither division, modulo or while loops can be perfomed in p4 runtime without implementing a pseudo-hash function to do so*/
            if (meta.hashValue - tmp == 0) {

                /* First Row*/
                hash(position,
                HashAlgorithm.crc32,
                base,
                { standard_metadata.packet_length, seed1},
                flowCounters);
                position = position + (flowCounters * pos);

                row1.read(value, position);
                row1.write(position, value+1);


                /*Second Row*/
                hash(position,
                HashAlgorithm.crc32,
                base,
                { standard_metadata.packet_length, seed2 },
                flowCounters);
                position = position + (flowCounters * pos);

                row2.read(value, position);
                row2.write(position, value+1);

                /*Third Row*/

                hash(position,
                HashAlgorithm.crc32,
                base,
                { standard_metadata.packet_length, seed3 },
                flowCounters);
                position = position + (flowCounters * pos);

                row3.read(value, position);
                row3.write(position, value+1);
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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
        packet.emit(hdr.ipv4);
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