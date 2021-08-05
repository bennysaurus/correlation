#!/bin/python

# Copyright (C) 2021, Benjamin Nunns
# License: MIT license, see file LICENSE for detail.

import sys
import os
import dpkt

def remove_suffix(input_string, suffix):
    if suffix and input_string.endswith(suffix):
        return input_string[:-len(suffix)]
    return input_string

# Parse multiple pcaps and correlate their times together.
# Obviously requires highly accurate timing such as a single capture point or syncronised times.

if len(sys.argv) < 3:
    print("Usage: correlate.py cap_name1=cap_file1.pcap cap_name2=cap_file2.pcap", file=sys.stderr)
    print("Minimum of 2 captures, up to available RAM usage.", file=sys.stderr)
    exit()

captures = []
for arg in sys.argv[1:]:
    capture = {'cap_name': arg.split('=')[0], 'cap_file': arg.split('=')[1]}
    captures.append(capture)
    print("Added file: ", capture)

# Initial loop as a sanity check
for capture in captures:
    if os.path.isfile(capture.get('cap_file')) != True:
        print("Invalid file ", capture.get('cap_file'))
        exit()

packetDict = dict()

for capture in captures:
    cap_name = capture.get('cap_name')

    f = open(capture.get('cap_file'),'rb')
    pcap = dpkt.pcap.Reader(f)

    print("Parsing ", cap_name)
    counter=0
    tcpcounter=0

    for ts, pkt in pcap:

        counter += 1
        eth = dpkt.ethernet.Ethernet(pkt) 

        #Filter non-ethernet packets
        if not isinstance(eth.data, dpkt.IP):
            continue

        ip=eth.data

        # Filter non-TCP packets
        if ip.p != dpkt.ip.IP_PROTO_TCP: 
            continue
        
        tcpcounter += 1
        tcp = ip.data

        timestamp = ts
        corr_key = int(str(ip.id) + str(tcp.seq))

        item = {'cap_name': cap_name, 'counter': counter, 'timestamp': ts}


        if corr_key in packetDict.keys():
            plist = packetDict[corr_key]
            plist.append(item)
            packetDict.update({corr_key: plist})
        
        else:
            plist = [item]
            #print(pc)
            packetDict.update({corr_key: plist})

for group in packetDict.values():
    cap_names = ''
    prev_ts = 0
    ts_builder = ''
    
    for item in sorted(group, key=lambda k: k['timestamp']):
        cap_names += item['cap_name'] + "(" + str(item['counter']) + ")->"
        
        if prev_ts == 0:
            ts_builder = str(item['timestamp']) + ","
        
        else:
            ts_builder += str(item['timestamp'] - prev_ts) + ","
            
        prev_ts = item['timestamp']

    output = remove_suffix(cap_names,'->') + "," + remove_suffix(ts_builder,',')
    print(output)

print("Total number of packets in the pcap file: ", counter, file=sys.stderr)
print("Total number of tcp packets: ", tcpcounter, file=sys.stderr)
