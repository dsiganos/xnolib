#!/bin/env python3
import random
import socket
import argparse

from peercrawler import get_random_peer
from pynanocoin import *

def parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')

    parser.add_argument('-p', '--peer',
                        help='peer to contact for frontiers (if not set, one is randomly from peer crawler)')
    parser.add_argument('-a', '--account', type=str, default=None,
                        help='The account you want to pull blocks from')
    return parser.parse_args()


def main():
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx

    account = ctx["genesis_pub"]
    if args.account is not None:
        if len(args.account) == 64:
            account = args.account
        else:
            account = acctools.account_key(args.account).hex()

    if args.peer:
        peeraddr, peerport = parse_endpoint(args.peer, default_port=ctx['peerport'])
    else:
        peer = get_random_peer(ctx, lambda p: p.score >= 1000)
        peeraddr, peerport = str(peer.ip), peer.port

    print('Connecting to [%s]:%s' % (peeraddr, peerport))
    with get_connected_socket_endpoint(peeraddr, peerport) as s:
        blocks = get_account_blocks(ctx, s, account)

        blockman = block_manager(ctx, None, None)
        blocks_pulled = len(blocks)
        while len(blocks) != 0:
            block = blocks.pop()
            print(block)
            blockman.process(block)

        print(blockman)
        print("blocks pulled: %d" % blocks_pulled)


class TestPullBlocks(unittest.TestCase):
    def test_pull_blocks(self):
        ctx = livectx

        epochv2 = {
            'account': binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA'),
            'prev': binascii.unhexlify('6875C0DBFE5C44D8F8CFF431BC69ED5587C68F89F0663F2BC1FBBFCB46DC5989'),
            'rep': binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA'),
            'bal': 325586539664609129644855132177,
            'link': binascii.unhexlify('65706F636820763220626C6F636B000000000000000000000000000000000000'),
            'sign': binascii.unhexlify(
                'B0FD724D1B341C7FB117AC51EB6B8D0BD56F424E7188F31718321C8B0CAEC92AE402D382917D65E9ECC741B3B31203569E9FB7B898EC4A08BEBCE859EA24BB0E'),
            'work': 0x494DBB4E8BD688AA
        }

        open_block = {
            'source': binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA'),
            'rep': binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA'),
            'account': binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA'),
            'sign': binascii.unhexlify('9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02'),
            'work': int.from_bytes(binascii.unhexlify('62F05417DD3FB691'), 'big')
        }

        ev2 = block_state(epochv2['account'], epochv2['prev'], epochv2['rep'], epochv2['bal'],
                          epochv2['link'], epochv2['sign'], epochv2['work'])
        ob = block_open(open_block['source'], open_block['rep'], open_block['account'], open_block['sign'],
                        open_block['work'])

        account = ctx["genesis_pub"]
        peeraddr = '::ffff:94.130.12.236'
        peerport = 7075
        with get_connected_socket_endpoint(peeraddr, peerport) as s:
            blocks = get_account_blocks(ctx, s, account)
            self.assertEqual(ev2, blocks[0])
            self.assertEqual(ob, blocks[43])

            blockman = block_manager(ctx, None, None)
            blocks_pulled = len(blocks)
            while len(blocks) != 0:
                block = blocks.pop()
                blockman.process(block)

            print(blockman)
            print("blocks pulled: %d" % blocks_pulled)

        self.assertEqual(len(blockman.accounts[0].blocks), 44)
        self.assertEqual(len(blockman.accounts), 1)
        self.assertEqual(len(blockman.processed_blocks), 44)


if __name__ == "__main__":
    main()
