/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"


/*************************************************************************
*********************** R E G I S T E R S  ***********************************
*************************************************************************/


register<bit<32>>(MAX_PORTS) pres_byte_cnt_reg;
register<bit<32>>(MAX_PORTS) past_byte_cnt_reg;
register<bit<32>>(MAX_PORTS) packets_cnt_reg;

register<time_t>(MAX_PORTS) gather_last_seen_reg;

const bit<48> gather_window = 1000000; // 1 Seg = 1000000 microseg



/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


time_t max(in time_t v1,in time_t v2){
    if(v1 > v2) return v1;
    else return v2;
}

time_t min(in time_t v1, in time_t v2){
    if(v1 < v2) return v1;
    else return v2;
}



/* If 'gather_window' is smaller or equal to the time elapsed since last time data was added to tos field, do it again
    Also divides data if data cant be represented with 8 bits */
void insert_telemetry(inout metadata meta, inout standard_metadata_t standard_metadata, in bit<32> pres_amt_bytes,
                                in bit<32> amt_packets){

        time_t gather_last_seen;
        gather_last_seen_reg.read(gather_last_seen, (bit<32>)standard_metadata.egress_spec);

        time_t now = standard_metadata.ingress_global_timestamp;
        if(amt_packets == 1){
            gather_last_seen = now;
            gather_last_seen_reg.write((bit<32>)standard_metadata.egress_spec, now);
        }

        if(now - gather_last_seen >= gather_window){
            meta.telemetry_amt_bytes = pres_amt_bytes;
            meta.telemetry_time = (bit<64>)(now - gather_last_seen);
            meta.flow_id = (bit<8>)standard_metadata.egress_spec;


            pres_byte_cnt_reg.write((bit<32>)standard_metadata.egress_spec, 0);
            past_byte_cnt_reg.write((bit<32>)standard_metadata.egress_spec, 0);

            gather_last_seen_reg.write((bit<32>)standard_metadata.egress_spec, now);

            meta.cloned = 1;
        }
}


// Pacote é enviado por uma porta e logo em seguida recebe a confirmação antes de enviar outro
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    /* Fowards an ipv4 packet and counts the amount of bytes/packets */
    action ipv4_forward(mac_addr_t dst_addr, egress_spec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dst_addr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();

            if(hdr.udp.isValid()){
                bit<32> amt_packets;bit<32> amt_bytes;

                packets_cnt_reg.read(amt_packets, (bit<32>)standard_metadata.egress_spec);
                amt_packets = amt_packets+1;
                packets_cnt_reg.write((bit<32>)standard_metadata.egress_spec, amt_packets);

                pres_byte_cnt_reg.read(amt_bytes, (bit<32>)standard_metadata.egress_spec);
                amt_bytes = amt_bytes+standard_metadata.packet_length;
                pres_byte_cnt_reg.write((bit<32>)standard_metadata.egress_spec,  amt_bytes);

                /** Collects metadata */
                insert_telemetry(meta, standard_metadata, amt_bytes, amt_packets);
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

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action clone_forward(mac_addr_t dst_addr, ipv4_addr_t ipv4_dst_adr) {
        hdr.ethernet.dst_addr = dst_addr;
        hdr.ipv4.dst_addr = ipv4_dst_adr;
    }

    table clone_table{
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            clone_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if(hdr.ipv4.isValid()){
            if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE){
                clone_table.apply();

                truncate(HEADERS_SIZE);
                hdr.ipv4.total_len = 28;
                hdr.udp.len = 8;

                hdr.telemetry.setValid();
                if(hdr.telemetry.isValid()){
                    hdr.ethernet.ether_type = TYPE_TELEMETRY;
                    hdr.telemetry.next_header_type = TYPE_IPV4;
                    hdr.telemetry.flow_id = meta.flow_id;
                    hdr.telemetry.amt_bytes = meta.telemetry_amt_bytes;
                    hdr.telemetry.time = meta.telemetry_time;
                }

            }else if(meta.cloned == 1){
                clone3(CloneType.E2E, REPORT_MIRROR_SESSION_ID, {meta.telemetry_time, meta.telemetry_amt_bytes});
                meta.cloned = 0;

            }
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
              hdr.ipv4.tos,
              hdr.ipv4.total_len,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.frag_offset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_addr,
              hdr.ipv4.dst_addr },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
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
