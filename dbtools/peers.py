#!/bin/env python3

import lmdb
import binascii
import ipaddress
import argparse


def parse_entry(data):
    assert len(data) == 18
    ipv6 = ipaddress.IPv6Address(data[:-2])
    port = int.from_bytes(data[-2:], "big")
    ipstr = str(ipv6)
    if ipv6.ipv4_mapped:
        ipstr = '::ffff:' + str(ipv6.ipv4_mapped)
    return '[%s]:%s' % (ipstr, port)


def print_peers(filename):
    with lmdb.open(filename, subdir=False, max_dbs=10000, map_size=10*1000*1000*1000) as env:
        peers_db = env.open_db(b'peers')
        with env.begin() as tx:
            for key, value in tx.cursor(db=peers_db):
                print(parse_entry(key))


def delete_peers(filename):
    with lmdb.open(filename, subdir=False, max_dbs=10000, map_size=10*1000*1000*1000) as env:
        peers_db = env.open_db(b'peers')
        with env.begin(write=True) as tx:
            peers = []
            for key, value in tx.cursor(db=peers_db):
                peers.append(key)
            for peer in peers:
                print('Deleting peer %s' % parse_entry(key))
                tx.delete(peer, db=peers_db)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dataldb', default='data.ldb',
                        help='data.ldb path')
    parser.add_argument('command',
            help='command: print or delete')
    return parser.parse_args()


def main():
    args = parse_args()
    if args.command == 'print':
        print_peers(args.dataldb)
    elif args.command == 'delete':
        delete_peers(args.dataldb)
    else:
        print('Uknown command %s', args.command)


if __name__ == "__main__":
    main()
