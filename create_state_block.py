#!/bin/env python3

import argparse
import binascii
import ed25519_blake2b

import block

live_threshold = 0xfffffff800000000
beta_threshold = 0xfffff00000000000
min_threshold = live_threshold

def parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')

    parser.add_argument('privkey',
                        help='private key to sign the block with, in raw form (32 bytes)')

    parser.add_argument('account',
                        help='account public key in raw form (32 bytes)')

    parser.add_argument('previous',
                        help='previous link in raw form (32 bytes)')

    parser.add_argument('representative',
                        help='account representative in raw form (32 bytes)')

    parser.add_argument('balance',
                        help='balance in raw units')

    parser.add_argument('link',
                        help='link in raw form (32 bytes)')

    return parser.parse_args()


args = parse_args()

account = binascii.unhexlify(args.account)
previous = binascii.unhexlify(args.previous)
representative = binascii.unhexlify(args.representative)
balance = int(args.balance)
link = binascii.unhexlify(args.link)

# create the block without generate and pow
blk = block.block_state(account, previous, representative, balance, link, None, None)

# sign the block
privkey = binascii.unhexlify(args.privkey)
signing_key = ed25519_blake2b.SigningKey(privkey)
blk.sign(signing_key)

# generate pow for block
if args.beta:
    min_threshold = beta_threshold
blk.generate_work(min_threshold)

print(blk.to_json())
