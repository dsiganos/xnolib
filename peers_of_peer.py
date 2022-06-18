#!/bin/env python3

# This script is a way to discover the peers of a remote node.
# This script connects to a peer repeadedly to get a keepalive packet.
# It collects the peers in the keepalive packets and then prints them at the end.

import argparse

import peercrawler
from pynanocoin import *
from peer import Peer


def parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                        help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                        help='use test network')

    parser.add_argument('-c', '--count', type=int, default=150,
                        help='number of times to connect to get a keepalive packet')

    parser.add_argument('-p', '--peer',
                        help='peer to contact for frontiers (if not set, one is randomly selected using DNS)')

    return parser.parse_args()


def main():
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx

    if args.peer is not None:
        peeraddr, peerport = parse_endpoint(args.peer, default_port=ctx['peerport'])
        print('Connecting to [%s]:%s' % (peeraddr, peerport))
        peer = Peer(ip_addr(peeraddr), peerport)
    else:
        peer = peercrawler.get_random_peer(ctx, lambda p: p.score >= 1000 and p.ip.is_ipv4())
        print('Using peer %s' % peer)
        peeraddr = str(peer.ip)
        peerport = peer.port

    peerman = peercrawler.peer_manager(ctx, verbosity=1)
    peers = []

    for i in range(args.count):
        print('.', flush=True, end='')
        new_peers = peerman.get_peers_from_peer(peer, no_telemetry=True, no_confirm_req=True)
        peers.extend(new_peers)

    for p in peers:
        print(p)


if __name__ == "__main__":
    main()
