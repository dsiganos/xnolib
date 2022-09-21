#!/usr/bin/env python3

import sys
import lmdb
import binascii
import ipaddress
import argparse

from pynanocoin import parse_endpoint, ip_addr


class PeersTable:
    def __init__(self, filename):
        self.filename = filename


    def print_peers(self):
        with lmdb.open(self.filename, subdir=False, max_dbs=10000, map_size=10*1000*1000*1000) as env:
            peers_db = env.open_db(b'peers')
            with env.begin() as tx:
                for key, value in tx.cursor(db=peers_db):
                    print(PeersTable.parse_entry(key))


    def delete_peers(self):
        with lmdb.open(self.filename, subdir=False, max_dbs=10000, map_size=10*1000*1000*1000) as env:
            peers_db = env.open_db(b'peers')
            with env.begin(write=True) as tx:
                peers = []
                for key, value in tx.cursor(db=peers_db):
                    peers.append(key)
                for peer in peers:
                    print('Deleting peer %s' % PeersTable.parse_entry(peer))
                    tx.delete(peer, db=peers_db)


    def add_peer(self, peer_str):
        assert peer_str is not None
        ipaddr_str, port = parse_endpoint(peer_str, default_port=7075)
        data = ip_addr(ipaddr_str).serialise() + port.to_bytes(2, "big")
        assert len(data) == 18

        with lmdb.open(self.filename, subdir=False, max_dbs=10000, map_size=10*1000*1000*1000) as env:
            peers_db = env.open_db(b'peers')
            print('Adding peer [%s]:%s' % (ipaddr_str, port))
            with env.begin(write=True) as tx:
                with tx.cursor(db=peers_db) as curs:
                    rc = curs.put(data, b'')
                    assert rc


    def delete_peer(self, peer_str):
        assert peer_str is not None
        ipaddr_str, port = parse_endpoint(peer_str, default_port=7075)
        data = ip_addr(ipaddr_str).serialise() + port.to_bytes(2, "big")
        assert len(data) == 18

        with lmdb.open(self.filename, subdir=False, max_dbs=10000, map_size=10*1000*1000*1000) as env:
            peers_db = env.open_db(b'peers')
            with env.begin(write=True) as tx:
                peer = None
                for key, value in tx.cursor(db=peers_db):
                    if key == data:
                        peer = key
                        break
                if peer is not None:
                    print('Deleting peer %s' % PeersTable.parse_entry(peer))
                    tx.delete(peer, db=peers_db)
                else:
                    print('Cannot find peer %s to delete' % PeersTable.parse_entry(data))


    def parse_entry(data):
        assert len(data) == 18
        ipv6 = ipaddress.IPv6Address(data[:-2])
        port = int.from_bytes(data[-2:], "big")
        ipstr = str(ipv6)
        if ipv6.ipv4_mapped:
            ipstr = '::ffff:' + str(ipv6.ipv4_mapped)
        return '[%s]:%s' % (ipstr, port)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dataldb', default='data.ldb',
                        help='data.ldb path')
    parser.add_argument('-p', '--peer',
                        help='peer to add or delete')
    parser.add_argument('command',
            help='print, add, delete or delall')
    return parser.parse_args()


def main():
    args = parse_args()

    peers_table = PeersTable(args.dataldb);

    if args.command == 'print':
        peers_table.print_peers()
    elif args.command == 'delall':
        peers_table.delete_peers()
    elif args.command == 'add':
        peers_table.add_peer(args.peer)
    elif args.command == 'delete':
        if args.peer is None:
            print('Must specify peer to delete, to delete all peers, use the command delall')
            sys.exit(1)
        peers_table.delete_peer(args.peer)
    else:
        print('Unknown command %s', args.command)


if __name__ == "__main__":
    main()
