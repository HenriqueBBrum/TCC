#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

#define MAX_PORTS 10
#define HEADERS_SIZE 57


const bit<32> REPORT_MIRROR_SESSION_ID = 500;


const bit<8> TYPE_UDP = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_TELEMETRY = 0X6666;



typedef bit<9>  egress_spec_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<48> time_t;




/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16>   ether_type;
}

header telemetry_t{
    bit<16> next_header_type;
    bit<8> flow_id;
    bit<32> amt_bytes;
    bit<64> time;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
    bit<16>   total_len;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   frag_offset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

struct metadata {
    bit<1> cloned;
    bit<8> flow_id;
    bit<32> telemetry_amt_bytes;
    bit<64> telemetry_time;
}

struct headers {
    ethernet_t   ethernet;
    telemetry_t  telemetry;
    ipv4_t       ipv4;
    udp_t        udp;
}
