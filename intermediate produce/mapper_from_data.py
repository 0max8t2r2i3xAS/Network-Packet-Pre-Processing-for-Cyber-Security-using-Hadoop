#!/usr/bin/env python3

import sys
import dpkt
import socket

def pcap_mapper():
    pcap_reader = dpkt.pcap.Reader(sys.stdin.buffer)
    for ts, buf in pcap_reader:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                source_ip = socket.inet_ntoa(ip.src)
                dest_ip = socket.inet_ntoa(ip.dst)
                packet_length = ip.len
                print('{},{},{}\t1'.format(source_ip, dest_ip, packet_length))
        except Exception as e:
            print(str(e), file=sys.stderr)

if __name__ == '__main__':
    pcap_mapper()