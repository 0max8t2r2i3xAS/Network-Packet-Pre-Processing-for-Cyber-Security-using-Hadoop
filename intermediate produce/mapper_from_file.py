#!/usr/bin/env python3

import sys
import dpkt
import socket
import io

input_stream = sys.stdin.buffer


def pcap_mapper():
    
    for filename in input_stream:
        filename = filename.strip().replace(b'\x00', b'').decode('utf-8')
        try:
            with open(filename, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                for ts, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if isinstance(eth.data, dpkt.ip.IP):
                            
                            ip = eth.data
                            source_ip = socket.inet_ntoa(ip.src)
                            dest_ip = socket.inet_ntoa(ip.dst)
                            packet_length = ip.len
                            ts = ts  # Add this line to get the timestamp
                            sys.stdout.write('{},{},{},{}\t1\n'.format(source_ip, dest_ip, packet_length. ts))
                            sys.stdout.flush()
                            #print('{},{},{},{}\t1'.format(source_ip, dest_ip, packet_length,ts))  # Ensure this matches expected reducer input
                    except Exception as e:
                        sys.stderr.write("ERROR: " + str(e) + "\n")
                        continue
        except IOError as ex:
            sys.stderr.write("ERROR: " + str(ex) + "\n")
            continue

if __name__ == '__main__':
    try:
        sys.stderr.write("Running mapper\n")
        pcap_mapper()
    except Exception as e:
        sys.stderr.write("ERROR: " + str(e) + "\n")
        sys.exit(1)