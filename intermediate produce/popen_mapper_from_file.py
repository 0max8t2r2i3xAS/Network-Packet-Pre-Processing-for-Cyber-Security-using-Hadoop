#!/usr/bin/env python3

import sys
import dpkt
import socket
import io
from subprocess import Popen, PIPE


input_stream = sys.stdin.buffer


def pcap_mapper():
    previous_ts = None
    
    for filename in input_stream:
        filename = filename.strip().replace(b'\x00', b'').decode('utf-8')
        try:
            with Popen(["/usr/local/hadoop/bin/hadoop", "fs", "-cat", filename], stdout=PIPE) as f:
                pcap = dpkt.pcap.Reader(f.stdout)
                for ts, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        
                        if isinstance(eth.data, dpkt.ip.IP):
                            ip = eth.data
                            source_ip = socket.inet_ntoa(ip.src)
                            dest_ip = socket.inet_ntoa(ip.dst)
                            packet_length = ip.len
                            ts = ts  # Add this line to get the timestamp
                            flow_duration = ts - previous_ts if previous_ts else 0
                            previous_ts = ts
                            header_length = len(eth)
                            source_port = 0
                            destination_port = 0
                            protocol_type = 0
                            protocol_name = ""

                            if isinstance(ip.data, dpkt.tcp.TCP):
                                tcp = ip.data
                                source_port = tcp.sport
                                destination_port = tcp.dport
                                protocol_type = 6
                                protocol_name = "TCP"
                            elif isinstance(ip.data, dpkt.udp.UDP):
                                udp = ip.data
                                source_port = udp.sport
                                destination_port = udp.dport
                                protocol_type = 17
                                protocol_name = "UDP"
                            elif isinstance(ip.data, dpkt.icmp.ICMP):
                                protocol_type = 1
                                protocol_name = "ICMP"

                            sys.stdout.write('{},{},{},{},{},{},{},{},{}\t1\n'.format(
                                ts, flow_duration, header_length, source_ip, dest_ip, source_port, destination_port, protocol_type, protocol_name))
                            sys.stdout.flush()
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