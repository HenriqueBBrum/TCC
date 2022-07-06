/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"


/***************************************************************/

const bit<48> obs_window = 1000000; // 1 Seg = 1000000 microseg
const bit<48> max_t = 10000000;

const bit<48> alfa = 2;

/***************************************************************/

const bit<64> div = 0x1999999A; /// used to divide a number by 10
const bit<64> div_100 = 0x28F5C29;
const bit<32> mean_n = 8;
const bit<8> div_shift = 3;

/*************************************************************************
*********************** R E G I S T E R S  *******************************
*************************************************************************/


register<bit<32>>(MAX_PORTS) telemetry_byte_cnt_reg;
register<bit<32>>(MAX_PORTS) pres_byte_cnt_reg;
register<bit<32>>(MAX_PORTS) past_byte_cnt_reg;

register<bit<32>>(MAX_PORTS) packets_cnt_reg;

register<time_t>(MAX_PORTS) obs_last_seen_reg;

register<time_t>(MAX_PORTS) gather_last_seen_reg;
register<time_t>(MAX_PORTS) gather_window_reg; // Caso o fluxo seja caracterizado pela sua porta, cada fluxo teria seu proprio tempo de coleta

register<bit<32>>(MAX_PORTS) delta_reg;
register<bit<32>>(MAX_PORTS) n_last_values;
register<bit<32>>(MAX_PORTS) count_reg;



/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout my_metadata meta){
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



void update_deltas(inout standard_metadata_t s_m, in bit<32> comparator, inout bit<32> delta){
    bit<32> ct; bit<32> sum;
    count_reg.read(ct, (bit<32>)s_m.egress_spec);
    n_last_values.read(sum, (bit<32>)s_m.egress_spec);

    if(ct==mean_n){
        bit<32> mean; bit<32> old_m;
        mean = sum >> div_shift;

        delta = (bit<32>)((div*(bit<64>)mean)>>32);

        delta_reg.write((bit<32>)s_m.egress_spec, delta);
        sum = 0;
        ct = 0;
    }

    sum = sum + comparator; ct = ct + 1;

    n_last_values.write((bit<32>)s_m.egress_spec, sum);
    count_reg.write((bit<32>)s_m.egress_spec, ct);
}



/* Updates gather_windows according to the amount of bytes counted since last time it was updated */
void update_telemetry_insertion_time(inout standard_metadata_t standard_metadata, in bit<32> pres_amt_bytes, inout bit<32> delta){
    time_t obs_last_seen; time_t gather_window;

    obs_last_seen_reg.read(obs_last_seen, (bit<32>)standard_metadata.egress_spec);
    gather_window_reg.read(gather_window, (bit<32>)standard_metadata.egress_spec);
    if(gather_window == 0){
        gather_window = 1000000;
        gather_window_reg.write((bit<32>)standard_metadata.egress_spec, gather_window);
    }

    bit<32> past_amt_bytes;
    past_byte_cnt_reg.read(past_amt_bytes, (bit<32>)standard_metadata.egress_spec);

    time_t now = standard_metadata.ingress_global_timestamp;
    if(obs_last_seen == 0){
        obs_last_seen = now;
        obs_last_seen_reg.write((bit<32>)standard_metadata.egress_spec, now);
    }

    if(now - obs_last_seen >= obs_window){
        int<32> delta_bytes = (int<32>)pres_amt_bytes - (int<32>)past_amt_bytes;
        if(delta_bytes > (int<32>)delta || delta_bytes < -1*((int<32>)delta)){
            gather_window = obs_window; // Decreases time if bytes difference was bigger than expected
        }else{
            gather_window = min(max_t, (gather_window*alfa)); // Increases time if bytes difference was smaller than expected
        }

        update_deltas(standard_metadata, pres_amt_bytes, delta);

        past_byte_cnt_reg.write((bit<32>)standard_metadata.egress_spec, pres_amt_bytes);
        pres_byte_cnt_reg.write((bit<32>)standard_metadata.egress_spec, 0);

        gather_window_reg.write((bit<32>)standard_metadata.egress_spec, gather_window);
        obs_last_seen_reg.write((bit<32>)standard_metadata.egress_spec, now);
    }
}




/* If 'gather_window' is smaller or equal to the time elapsed since last time data was added to tos field, do it again
    Also divides data if data cant be represented with 8 bits */
void save_telemetry(inout my_metadata meta, inout standard_metadata_t standard_metadata, in bit<32> tel_amt_bytes,
                                in bit<32> amt_packets){
        time_t gather_last_seen; time_t gather_window;
        gather_last_seen_reg.read(gather_last_seen, (bit<32>)standard_metadata.egress_spec);
        gather_window_reg.read(gather_window, (bit<32>)standard_metadata.egress_spec);

        time_t now = standard_metadata.ingress_global_timestamp;
        if(gather_last_seen == 0){
            gather_last_seen = now;
            gather_last_seen_reg.write((bit<32>)standard_metadata.egress_spec, now);
        }
        if(now - gather_last_seen >= gather_window){
            meta.telemetry_amt_bytes = tel_amt_bytes;
            meta.telemetry_time = (bit<64>)(now - gather_last_seen);
            meta.flow_id = (bit<8>)standard_metadata.egress_spec;

            telemetry_byte_cnt_reg.write((bit<32>)standard_metadata.egress_spec, 0);
            gather_last_seen_reg.write((bit<32>)standard_metadata.egress_spec, now);

            meta.cloned = 1;
        }
}


// Pacote é enviado por uma porta e logo em seguida recebe a confirmação antes de enviar outro
control MyIngress(inout headers hdr,
                  inout my_metadata meta,
                  inout standard_metadata_t standard_metadata){

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(mac_addr_t dst_addr, egress_spec_t port){
        standard_metadata.egress_spec = port;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dst_addr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm{
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

    apply{
        if (hdr.ipv4.isValid()){
            ipv4_lpm.apply();

            if(hdr.udp.isValid()){
                bit<32> amt_packets;bit<32> tel_amt_bytes;bit<32> pres_amt_bytes;

                packets_cnt_reg.read(amt_packets, (bit<32>)standard_metadata.egress_spec);
                amt_packets = amt_packets+1;
                packets_cnt_reg.write((bit<32>)standard_metadata.egress_spec, amt_packets);

                pres_byte_cnt_reg.read(pres_amt_bytes, (bit<32>)standard_metadata.egress_spec);
                pres_amt_bytes = pres_amt_bytes+standard_metadata.packet_length;
                pres_byte_cnt_reg.write((bit<32>)standard_metadata.egress_spec,  pres_amt_bytes);

                telemetry_byte_cnt_reg.read(tel_amt_bytes, (bit<32>)standard_metadata.egress_spec);
                tel_amt_bytes = tel_amt_bytes+standard_metadata.packet_length;
                telemetry_byte_cnt_reg.write((bit<32>)standard_metadata.egress_spec,  tel_amt_bytes);

                bit<32> delta = 0;
                delta_reg.read(delta, (bit<32>)standard_metadata.egress_spec);

                if(delta == 0){
                    delta = BASE_DELTA;
                    delta_reg.write((bit<32>)standard_metadata.egress_spec, delta);
                }

                /** Observation window, updates gather window value*/
                update_telemetry_insertion_time(standard_metadata, pres_amt_bytes, delta);

                /** Gathering window, changes tos value to amt of bytes passed since last window*/
                save_telemetry(meta, standard_metadata, tel_amt_bytes, amt_packets);

            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout my_metadata meta,
                 inout standard_metadata_t standard_metadata){

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
        if(hdr.ipv4.isValid() && hdr.udp.isValid()){
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
                clone_preserving_field_list(CloneType.E2E, REPORT_MIRROR_SESSION_ID, COPY_INDEX);
                meta.cloned = 0;
            }
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout my_metadata meta){
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
