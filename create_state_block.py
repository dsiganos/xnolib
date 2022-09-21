#!/usr/bin/env python3

import argparse
import binascii
import ed25519_blake2b

import block

live_threshold = 0xfffffff800000000
beta_threshold = 0xfffff00000000000
min_threshold = live_threshold


def create_state_block(signing_key, min_threshold, account, previous, representative, balance, link):
    # create the block without signature and pow
    blk = block.block_state(account, previous, representative, balance, link, None, None)

    # sign the block
    blk.sign(signing_key)

    # generate pow for block
    blk.generate_work(min_threshold)

    return blk


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

# construct the signing object
privkey = binascii.unhexlify(args.privkey)
signing_key = ed25519_blake2b.SigningKey(privkey)

# choose the difficulty threshold
if args.beta:
    min_threshold = beta_threshold

# create the block
blk = create_state_block(signing_key, min_threshold, account, previous, representative, balance, link)

print(blk.to_json())
