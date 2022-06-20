#!/bin/env python3

from __future__ import annotations

import sys
import binascii
import random
import socket
import argparse
import time

import lmdb
import peercrawler
import acctools
from exceptions import *
from pynanocoin import *
from peer import Peer


class frontier_request:
    def __init__(self, hdr: message_header, start_account: bytes = b'\x00'*32, maxage: int = 0xffffffff,
                 maxacc: int = 0xffffffff):
        assert (len(start_account) == 32)
        assert (isinstance(hdr, message_header))
        self.header = hdr
        self.start_account = start_account
        self.maxage = maxage
        self.maxacc = maxacc
        self.confirmed = True if self.header.ext == 2 else False

    def serialise(self) -> bytes:
        data = self.header.serialise_header()
        data += self.start_account
        data += self.maxage.to_bytes(4, 'little')
        data += self.maxacc.to_bytes(4, 'little')
        return data

    @classmethod
    def parse(cls, hdr: message_header, data: bytes):
        start_account = data[0:32]
        maxage = int.from_bytes(data[32:36], 'big')
        maxacc = int.from_bytes(data[36:], 'big')
        return frontier_request(hdr, start_account=start_account, maxage=maxage, maxacc=maxacc)

    @classmethod
    def generate_header(cls, ctx: dict, confirmed: bool = True) -> message_header:
        return message_header(ctx['net_id'], [18, 18, 18], message_type(8), 2 if confirmed else 0)

    def __str__(self):
        string = str(self.header) + "\n"
        string += "Start account: %s\n" % hexlify(self.start_account)
        string += "max age: %d\n" % self.maxage
        string += "max accounts: %d\n" % self.maxacc
        string += "confirmed: %s\n" % self.confirmed
        return string

    def __eq__(self, other):
        if not isinstance(other, frontier_request):
            return False
        elif not self.start_account == other.start_account:
            return False
        elif not self.header == other.header:
            return False
        elif not self.maxage == other.maxage:
            return False
        elif not self.maxacc == other.maxacc:
            return False
        return True


class frontier_entry:
    def __init__(self, account: bytes, frontier_hash: bytes):
        assert len(account) == 32
        self.account = account
        self.frontier_hash = frontier_hash

    def is_end_marker(self) -> bool:
        return self.account == (b'\x00' * 32) and self.frontier_hash == (b'\x00' * 32)

    def serialise(self) -> bytes:
        data = b''
        data += self.account
        data += self.frontier_hash
        return data

    def __str__(self):
        string = "%s\n" % acctools.to_account_addr(self.account)
        string += "%s" % binascii.hexlify(self.frontier_hash).decode("utf-8").upper()
        return string


def iterate_frontiers_from_stdin() -> frontier_entry:
    while True:
        data = sys.stdin.buffer.read(64)
        if data is None or len(data) < 64:
            #raise PyNanoCoinException('failed to read frontier response, data=%s', data)
            return
        yield frontier_entry(data[0:32], data[32:])


def read_frontier_response(s: socket.socket) -> frontier_entry:
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

    parser.add_argument('--binary', action='store_true', default=False,
                        help='Print frontiers in binary form (if printing)')

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


def read_all_frontiers(s: socket.socket, frontier_handler) -> None:
    counter = 1
    while True:
        starttime = time.time()
        frontier = read_frontier_response(s)
        endtime = time.time()
        readtime = endtime - starttime
        if frontier.is_end_marker():
            return

        frontier_handler(counter, frontier, readtime)
        counter += 1


def binary_print_handler(counter: int, frontier: frontier_entry, readtime: int) -> None:
    sys.stdout.buffer.write(frontier.serialise())


def text_print_handler(counter: int, frontier: frontier_entry, readtime: int) -> None:
    print(counter, hexlify(frontier.frontier_hash),
          hexlify(frontier.account), acctools.to_account_addr(frontier.account))


def frontier_to_db(tx: lmdb.Transaction, counter: int, frontier: frontier_entry) -> None:
    tx.put(frontier.account, frontier.frontier_hash)


def get_frontiers_from_peer(peer: Peer, frontier_req: frontier_request, use_db: str, print_handler) -> None:
    assert isinstance(frontier_req, frontier_request)

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(3)
        if print_handler is not binary_print_handler:
            print('connecting to %s' % peer)
        s.connect((str(peer.ip), peer.port))

        #peer = ip_addr.from_string(peerstr)
        if use_db:
            os.makedirs(use_db, exist_ok=True)
            filename = '%s/%s:%s' % (use_db, str(peer.ip), str(peer.port))
            lmdb_env = lmdb.open(filename, subdir=False, max_dbs=10000, map_size=10*1000*1000*1000)
            with lmdb_env.begin(write=True) as tx:
                s.send(frontier_req.serialise())
                read_all_frontiers(s, lambda cnt, f, readtime: tx.put(f.account, f.frontier_hash))
            lmdb_env.close()
        else:
            s.send(frontier_req.serialise())
            read_all_frontiers(s, print_handler)


def main() -> None:
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx

    account = args.start_acc
    if len(account) != 64:
        account = acctools.account_key(args.start_acc).hex()

    confirmed = not args.notconfirmed
    hdr = frontier_request.generate_header(ctx, confirmed)
    frontier_req = frontier_request(hdr,
                                    start_account = unhexlify(account),
                                    maxage = args.maxage,
                                    maxacc = args.count)

    if args.all:
        peers = peercrawler.get_peers_from_service(ctx)
        peers = [ p for p in peers if p.score >= 1000 ]
        assert peers
    else:
        if args.peer is not None:
            peeraddr, peerport = parse_endpoint(args.peer, default_port=ctx['peerport'])
            peers = [peer_from_endpoint(peeraddr, peerport)]
        else:
            peers = peercrawler.get_peers_from_service(ctx)
            peers = list(filter(lambda p: p.score >= 1000, peers))
            peers = [random.choice(peers)]

    print_handler = binary_print_handler if args.binary else text_print_handler

    for peer in peers:
        try:
            get_frontiers_from_peer(peer, frontier_req, args.db, print_handler)
        except (OSError, PyNanoCoinException) as e:
            # peer was connectable but some other error happpened, score it with 1
            peer.deduct_score(200)
            print('Exception %s: %s' % (type(e), e))


if __name__ == "__main__":
    main()
