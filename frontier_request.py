#!/bin/env python3

import binascii
import random
import socket
from exceptions import *

from nanolib import message_header, network_id, message_type, livectx, read_socket, get_all_dns_addresses, \
    get_account_id, get_initial_connected_socket, hexlify, get_account_id


class frontier_request:
    def __init__(self, start_account=b'\x00'*32, maxage=0xffffffff, maxacc=0xffffffff, confirmed=False):
        self.header = message_header(network_id(67), [18, 18, 18], message_type(8), 2 if confirmed else 0)
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


def main():
    ctx = livectx

    s = get_initial_connected_socket(ctx)
    assert s
    s.settimeout(60)

    frontier = frontier_request(fork2, maxacc=1, confirmed=True)
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
