import matplotlib.pyplot as plt
import math
import csv
import argparse
import json
import os
import numpy as np

nic_for_incoming_pkts = "s1-eth1"
nic_for_exiting_pkts = "s1-eth2"


def calculate_avg_pkt_processing_delay(pkts_file):
    time_delay = 0
    sz = 0
    s = 0

    with open(pkts_file) as csvfile:
        data = csv.DictReader(csvfile, delimiter=',')
        d = {}
        for row in data:
            if row['ip.id'] in d:
                time_delay+=abs(float(row['frame.time_epoch'])-d[row['ip.id']])
                sz = sz+1
            else:
                d[row['ip.id']] = float(row['frame.time_epoch'])
                s = s +1

    # incoming.sort()
    # exiting.sort()
    # print(incoming, "\n", exiting)
    # for i in range(0, len(exiting)):
    #     if exiting[i]-incoming[i]>0.1:
    #         print(pkts_file,exiting[i],incoming[i])
    #     time_delay += (exiting[i]-incoming[i])
    #

    print(sz, time_delay, s)
    return time_delay/sz, sz

def main():
    parser = argparse.ArgumentParser()


    parser.add_argument('pkts_pcapng_file_dynamic', type=str,  help = "Pcapng file with info about packets from two interfaces using dynamic telemetry")
    # parser.add_argument('pkts_pcapng_file_static', type=str, help = "Pcapng file with info about packets from two interfaces using static telemetry")
    # parser.add_argument('pkts_pcapng_file_no_method', type=str, help = "Pcapng file with info about packets from two interfaces")


    args = parser.parse_args()
    #aux_1 = args.pkts_pcapng_file.split("/")

    output_csv_dynamic = "processing_time_pkts_dynamic.csv"
    output_csv_static = "processing_time_pkts_static.csv"
    output_csv_no_method = "processing_time_pkts_no_method.csv"

    if args.pkts_pcapng_file_dynamic:
         os.system("tshark -r "+args.pkts_pcapng_file_dynamic+" -T fields -e frame.number -e frame.interface_name -e frame.time_epoch -e ip.id -E header=y -E separator=, > "+output_csv_dynamic)

    # if args.pkts_pcapng_file_static:
    #     os.system("tshark -r "+args.pkts_pcapng_file_static+" -T fields -e frame.number -e frame.interface_name -e frame.time_epoch -e ip.id -E header=y -E separator=, > "+output_csv_static)
    #
    # if args.pkts_pcapng_file_no_method:
    #     os.system("tshark -r "+args.pkts_pcapng_file_no_method+" -T fields -e frame.number -e frame.interface_name -e frame.time_epoch -e ip.id -E header=y -E separator=, > "+output_csv_no_method)


    with open('results.csv', "a") as csvfile:
        headers = ['type', 'time']
        writer = csv.DictWriter(csvfile, delimiter=',', lineterminator='\n',fieldnames=headers)

        if not csvfile:
            writer.writeheader()  # file doesn't exist yet, write a header

        writer.writerow({'type': "dynamic", 'time': calculate_avg_pkt_processing_delay(output_csv_dynamic)})
        # writer.writerow({'type': "static", 'time': calculate_avg_pkt_processing_delay(output_csv_static)})
        # writer.writerow({'type': "no_monitoring", 'time': calculate_avg_pkt_processing_delay(output_csv_no_method)})


    # print("Avg time delay for dynamic : "+str(calculate_avg_pkt_processing_delay(output_csv_dynamic))+" seconds")
    # print("Avg time delay for static : "+str(calculate_avg_pkt_processing_delay(output_csv_static))+" seconds")
    #
    #


if __name__ == '__main__':
    main()
