#!/bin/env python3

# Read a block from stdin and validate its signature and proof of work.
# Currently only json format is supported

import sys

import block
import pynanocoin


def to_pass_fail(status: bool) -> str:
    return 'PASS' if status == True else 'FAIL'

json_block = sys.stdin.read()
print('Input Data:')
print(json_block)

blk = block.Block.parse_from_json_string(json_block)
print(blk)

pow_status = pynanocoin.verify_pow(blk)
sig_status = pynanocoin.valid_block(pynanocoin.livectx, blk)

print('POW       check: %s' % to_pass_fail(pow_status))
print('Signature check: %s' % to_pass_fail(sig_status))
