#!/usr/bin/env python3

import sys

def pcap_reducer():
    current_key = None
    current_count = 0
    for line in sys.stdin:
        line = line.strip()
        if '\t' not in line:
            continue  # Skip lines without tab characters
        key, count = line.split('\t', 1)
        try:
            count = int(count)
        except ValueError:
            continue  # Skip lines where count is not an integer

        if current_key == key:
            current_count += count
        else:
            if current_key:
                sys.stdout.write('{}\t{}\n'.format(current_key, current_count))
                sys.stdout.flush()
                #print('{}\t{}'.format(current_key, current_count))
            current_key = key
            current_count = count

    if current_key:
        sys.stdout.write('{}\t{}\n'.format(current_key, current_count))
        sys.stdout.flush()
        #print('{}\t{}'.format(current_key, current_count))

if __name__ == '__main__':
    sys.stderr.write("Running reducer\n")
    pcap_reducer()
