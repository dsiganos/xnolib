#!/bin/env python3

import binascii
import random
import socket
import argparse
from exceptions import *

from pynanocoin import message_header, network_id, message_type, livectx, betactx, read_socket, get_all_dns_addresses, \
    get_account_id, get_initial_connected_socket, hexlify, get_account_id


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
    parser.add_argument('-b', '--beta', action='store_true', default=False,
                        help='use beta network')
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
    return parser.parse_args()


def main():
    args = parse_args()
    print(args)

    ctx = betactx if args.beta else livectx
    confirmed = not args.notconfirmed

    s = get_initial_connected_socket(ctx, args.peer)
    assert s
    s.settimeout(60)

    frontier = frontier_request(ctx = ctx,
                                start_account = binascii.unhexlify(args.start_acc),
                                maxage = args.maxage,
                                maxacc = args.count,
                                confirmed = confirmed)
    s.send(frontier.serialise())

    counter = 1
    while True:
        frontier = read_frontier_response(s)

        if frontier.is_end_marker():
            return

        print(counter, hexlify(frontier.frontier_hash), hexlify(frontier.account), get_account_id(frontier.account))
        counter += 1


if __name__ == "__main__":
    main()
