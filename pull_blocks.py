#!/bin/env python3
import random
import socket
import argparse

import peercrawler
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

    if args.peer is not None:
        peeraddr, peerport = parse_endpoint(args.peer)
        if peerport is None:
            peerport = ctx['peerport']
        peer = Peer(ip_addr(ipaddress.IPv6Address(peeraddr)), peerport, 1000)
    else:
        _, peers = peercrawler.get_peers_from_service(ctx)
        assert peers
        peer = random.choice([x for x in peers if x.score >= 1000])

    account = ctx["genesis_pub"]

    if args.account is not None:
        if len(args.account) == 64:
            account = args.account
        else:
            account = acctools.account_key(args.account).hex()

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(3)
        print('connecting to %s' % peer)
        s.connect((str(peer.ip), peer.port))

        blocks = get_account_blocks(ctx, s, account)

        blockman = block_manager(ctx, None, None)
        blocks_pulled = len(blocks)
        while len(blocks) != 0:
            block = blocks.pop()
            print(block)
            blockman.process(block)

        print(blockman)
        print("blocks pulled: %d" % blocks_pulled)

if __name__ == "__main__":
    main()
