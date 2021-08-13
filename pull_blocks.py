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
    return parser.parse_args()


def main():
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx

    if args.peer:
        peer = Peer(ip_addr(ipaddress.IPv6Address(args.peer)), ctx['peerport'], 1000)
    else:
        _, peers = peercrawler.get_peers_from_service(ctx)
        assert peers
        peer = random.choice([x for x in peers if x.score >= 1000])

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(3)
        print('connecting to %s' % peer)
        s.connect((str(peer.ip), peer.port))

        blocks = get_account_blocks(ctx, s, ctx["genesis_pub"])

        blockman = block_manager(ctx, None, None)
        while len(blocks) != 0:
            block = blocks.pop()
            print(block)
            blockman.process(block)

        print(blockman)

if __name__ == "__main__":
    main()
