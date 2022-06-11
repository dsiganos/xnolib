#!/bin/env python3

import sys
import acctools
from pynanocoin import *
from confirm_req import *
from frontier_request import *
from pull_n_accounts import store_frontiers_handler


def parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                        help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                        help='use test network')

    parser.add_argument('-p', '--peer',
                        help='peer to contact for frontiers (if not set, one is randomly selected using DNS)')

    parser.add_argument('-H', '--hashes_only', action='store_true', default=False,
                        help='print only the block hashes')

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx

    if args.peer is not None:
        peeraddr, peerport = parse_endpoint(args.peer, default_port=ctx['peerport'])
        print('Connecting to [%s]:%s' % (peeraddr, peerport))
    else:
        peer = get_random_peer(ctx, lambda p: p.score >= 1000 and p.ip.is_ipv4() and p.is_voting)
        print('Using peer %s' % peer)
        peeraddr = str(peer.ip)
        peerport = peer.port

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(10)
        s.connect((peeraddr, peerport))

        count = 0
        for f in iterate_frontiers_from_stdin():
            blocks = get_account_blocks(ctx, s, f.account)
            print('ACCOUNT: %s %s' % (hexlify(f.account), acctools.to_account_addr(f.account)))

            for b in blocks:
                count += 1
                if args.hashes_only:
                    print(hexlify(b.hash()))
                else:
                    print('%s: %s' % (count, b))

    print('all blocks printed')


if __name__ == "__main__":
    main()
