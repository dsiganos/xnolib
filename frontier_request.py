#!/bin/env python3

import binascii
import random
import socket
import argparse
import lmdb
import peercrawler
from exceptions import *

from pynanocoin import *


class frontier_request:
    def __init__(self, ctx, start_account=b'\x00'*32, maxage=0xffffffff, maxacc=0xffffffff, confirmed=False):
        self.header = message_header(ctx['net_id'], [18, 18, 18], message_type(8), 2 if confirmed else 0)
        self.start_account = start_account
        self.maxage = maxage
        self.maxacc = maxacc
        self.confirmed = confirmed

    def serialise(self):
        data = self.header.serialise_header()
        data += self.start_account
        data += self.maxage.to_bytes(4, 'little')
        data += self.maxacc.to_bytes(4, 'little')
        return data


class frontier_entry:
    def __init__(self, account, frontier_hash):
        self.account = account
        self.frontier_hash = frontier_hash

    def is_end_marker(self):
        return self.account == (b'\x00' * 32) and self.frontier_hash == (b'\x00' * 32)

    def __str__(self):
        string = "%s\n" % get_account_id(self.account)
        string += "%s\n" % binascii.hexlify(self.frontier_hash).decode("utf-8").upper()
        return string


def read_frontier_response(s):
    data = read_socket(s, 64)
    if data is None or len(data) < 64:
        raise PyNanoCoinException('failed to read frontier response, data=%s', data)
    return frontier_entry(data[0:32], data[32:])


fork1 = binascii.unhexlify(b'7D6FE3ABD8E2F7598911E13DC9C5CD2E71210C1FBD90D503C7A2041FBF58EEFD')
fork2 = binascii.unhexlify(b'CC83DA473B2B1BA277F64359197D4A36866CC84A7D43B1F65457324497C75F75')


def parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')

    parser.add_argument('-a', '--all', action='store_true', default=False,
                        help='Download frontiers from all peers')

    parser.add_argument('-c', '--count', type=int, default=0xffffffff,
                        help='number of frontiers to download, if not set, all frontiers are downloaded')
    parser.add_argument('-m', '--maxage', type=int, default=0xffffffff,
                        help='maxage of frontiers')
    parser.add_argument('-n', '--notconfirmed', action='store_true', default=False,
                        help='also download not confirmed blocks')
    parser.add_argument('-s', '--start_acc', default='00'*32,
                        help='start account')

    parser.add_argument('-p', '--peer',
                        help='peer to contact for frontiers (if not set, one is randomly selected using DNS)')
    parser.add_argument('--db',
                        help='save frontiers in databases in the folder named by the argument')
    return parser.parse_args()


def read_all_frontiers(s, frontier_handler):
    counter = 1
    while True:
        frontier = read_frontier_response(s)

        if frontier.is_end_marker():
            return

        frontier_handler(counter, frontier)
        counter += 1


def print_handler(counter, frontier):
    print(counter, hexlify(frontier.frontier_hash), hexlify(frontier.account), get_account_id(frontier.account))


def frontier_to_db(tx, counter, frontier):
    tx.put(frontier.account, frontier.frontier_hash)


def get_frontiers_from_peer(peer, frontier_req, use_db):
    assert isinstance(frontier_req, frontier_request)

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(3)
        print('connecting to %s', peer)
        s.connect((str(peer.ip), peer.port))

        #peer = ip_addr.from_string(peerstr)
        if use_db:
            os.makedirs(use_db, exist_ok=True)
            filename = '%s/%s:%s' % (use_db, str(peer.ip), str(peer.port))
            lmdb_env = lmdb.open(filename, subdir=False, max_dbs=10000, map_size=10*1000*1000*1000)
            with lmdb_env.begin(write=True) as tx:
                s.send(frontier_req.serialise())
                read_all_frontiers(s, lambda c, f: tx.put(f.account, f.frontier_hash))
            lmdb_env.close()
        else:
            s.send(frontier_req.serialise())
            read_all_frontiers(s, print_handler)


def main():
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx

    confirmed = not args.notconfirmed

    frontier_req = frontier_request(ctx = ctx,
                                    start_account = binascii.unhexlify(args.start_acc),
                                    maxage = args.maxage,
                                    maxacc = args.count,
                                    confirmed = confirmed)

    if args.all:
        _, peers = peercrawler.get_peers_from_service()
        assert peers
    else:
        if args.peer:
            peers = [peer(ip_addr(ipaddress.IPv6Address(args.peer)), ctx['peerport'])]
        else:
            peer = random.choice(get_all_dns_addresses(ctx['peeraddr']))
            peers = [peer(ip_addr(ipaddress.IPv6Address(peer)), ctx['peerport'])]

    for peer in peers:
        if peer.score <= 0:
            continue

        try:
            get_frontiers_from_peer(peer, frontier_req, args.db)
        except OSError as e:
            # peer was connectable but some other error happpened, score it with 1
            peer.deduct_score(200)
            print('Exception %s: %s' % (type(e), e))
        except PyNanoCoinException as e:
            # peer was connectable but some other error happpened, score it with 1
            peer.deduct_score(200)
            print('Exception %s: %s' % (type(e), e))


if __name__ == "__main__":
    main()
