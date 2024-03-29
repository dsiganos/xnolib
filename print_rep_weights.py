#!/usr/bin/env python3

# script to print the rep weights captured by the script record_rep_weights.py
# Example usage: print_rep_weights.py < rep_weights_live.bin

import sys
from binascii import hexlify, unhexlify
import nanolib

f = sys.stdin.buffer

data = f.read(16)
assert len(data) == 16
block_height = int.from_bytes(data, byteorder='big')
print('block_height: %s (%s)' % (hexlify(data), block_height))

count = 0
total_weight = 0
while True:
    data = f.read(32+16)
    if len(data) == 0:
        break
    assert len(data) == 32+16
    acc = nanolib.get_account_id(public_key=hexlify(data[:32]), prefix='nano_')
    weight = int.from_bytes(data[32:], byteorder='big')
    print('%s: %s' % (acc, weight))
    count += 1
    total_weight += weight

print("wrote %d rep weights" % count)
print("total weight %d" % total_weight)
