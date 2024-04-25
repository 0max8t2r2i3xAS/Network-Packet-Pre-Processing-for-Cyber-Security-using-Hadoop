#!/usr/bin/env python3
import sys

def pcap_reducer():
    current_key = None
    total_packets = 0
    total_bytes = 0

    for line in sys.stdin:
        line = line.strip()
        try:
            # Splitting the line into components
            line = line.replace('\t', ',')  # Remove null bytes
            parts = line.split(',')
            if len(parts) < 10:
                continue  # Skip lines that don't have enough data

            timestamp, duration, packet_size, src_ip, dest_ip, src_port, dest_port, protocol_type, protocol, count = parts[:10]

            # Construct a key from source IP, destination IP, and protocol
            key = (src_ip, dest_ip, protocol.strip())

            # Try to parse packet size and count
            packet_size = int(packet_size)
            count = int(count)

            # Check if the key has changed (new data group)
            if current_key == key:
                total_packets += count
                total_bytes += packet_size * count  # Total bytes = size per packet * number of packets
            else:
                if current_key:
                    # Output the result for the previous group
                    output_result(timestamp, duration, packet_size, src_ip, dest_ip, src_port, dest_port, protocol_type, protocol, total_packets, total_bytes,count)
                current_key = key
                total_packets = count
                total_bytes = packet_size * count

        except ValueError as e:
            # Optionally handle or log the error
            sys.stderr.write("ERROR parsing line: {}\n".format(line))
            sys.stderr.write("ERROR: {}\n".format(e))
            continue

    # Don't forget to output the last group
    if current_key:
        output_result(timestamp, duration, packet_size, src_ip, dest_ip, src_port, dest_port, protocol_type, protocol, total_packets, total_bytes,count)

def output_result(timestamp, duration, packet_size, src_ip, dest_ip, src_port, dest_port, protocol_type, protocol, total_packets, total_bytes,count):
    #sys.stdout.write("From {} to {} over {}: Total Packets: {}, Total Bytes: {}\n".format(
    #    src_ip, dest_ip, protocol, total_packets, total_bytes))
    sys.stdout.write("{},{},{},{},{},{},{},{},{},{},{}\t{}\n".format(
        timestamp, duration, packet_size, src_ip, dest_ip, src_port, dest_port, protocol_type, protocol, total_packets, total_bytes,count))
    sys.stdout.flush()

if __name__ == '__main__':
    pcap_reducer()