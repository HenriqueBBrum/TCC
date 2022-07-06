/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/



parser MyParser(packet_in packet,
                out headers hdr,
                inout my_metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_TELEMETRY: parse_telemtry;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_telemtry {
        packet.extract(hdr.telemetry);
        transition select(hdr.telemetry.next_header_type) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp{
        packet.extract(hdr.udp);
        transition accept;
    }

}




/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr){
    apply {
        packet.emit(hdr);
    }
}
