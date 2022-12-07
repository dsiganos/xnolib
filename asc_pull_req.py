#!/usr/bin/env python3

from __future__ import annotations

import sys
import time
import argparse
import datetime

import common
import constants
from pynanocoin import *
from msg_handshake import node_handshake_id
from peercrawler import *
import confirm_ack


class asc_pull_type:
	invalid = 0
	blocks = 1
	account_info = 2


def type_to_string(t: asc_pull_type):
    if t == asc_pull_type.invalid:
        return 'invalid'
    elif t == asc_pull_type.blocks:
        return 'blocks'
    elif t == asc_pull_type.account_info:
        return 'account_info'
    else:
        return 'unknown'


class asc_pull_req:

    def __init__(self, hdr: message_header):
        self.hdr = hdr
        self.type = asc_pull_type.account_info
        self.id = 0

    def serialise(self) -> bytes:
        data = self.hdr.serialise_header()
        data += self.type.to_bytes(1, "big")
        data += self.id.to_bytes(8, "big")
        return data


class asc_pull_req_account_info(asc_pull_req):

    def __init__(self, hdr: message_header, hash_or_acc: bytes):
        super().__init__(hdr)
        self.hdr.ext = 32
        self.type = asc_pull_type.account_info
        self.id = 0
        self.hash_or_acc = hash_or_acc

    def serialise(self) -> bytes:
        data = super().serialise()
        data += self.hash_or_acc
        return data


class asc_pull_req_blocks(asc_pull_req):

    def __init__(self, hdr: message_header, hash_or_acc: bytes, count: int):
        super().__init__(hdr)
        self.hdr.ext = 33
        self.type = asc_pull_type.blocks
        self.id = 0
        self.hash_or_acc = hash_or_acc
        self.count = count

    def serialise(self) -> bytes:
        data = super().serialise()
        data += self.hash_or_acc
        data += self.count.to_bytes(1, "big")
        return data


class asc_pull_ack:

    def __init__(self, hdr: message_header, type_, id_):
        self.hdr = hdr
        self.type_ = type_
        self.id_ = id_

    def __str__(self):
        type_str = type_to_string(self.type_)
        return 'Type=%s(%s) ID=%s' % (type_str, self.type_, self.id_)

    @classmethod
    def parse(cls, hdr: message_header, data: bytes):
        assert len(data) >= 9
        type_ = int.from_bytes(data[0:1], "big")
        id_ = int.from_bytes(data[1:9], "big")
        if type_ == asc_pull_type.account_info:
            assert len(data) == 9 + 144
            payload = asc_pull_ack_account_info_payload.parse(data[9:])
            return asc_pull_ack_with_payload(hdr, type_, id_, payload)
        elif type_ == asc_pull_type.blocks:
            payload = asc_pull_ack_blocks_payload.parse(data[9:])
            return asc_pull_ack_with_payload(hdr, type_, id_, payload)
        else:
            return asc_pull_ack(hdr, type_, id_)


class asc_pull_ack_account_info_payload:

    def __init__(self, acc: bytes, acc_open: bytes, acc_head: bytes, block_count: int,
                 conf_frontier: bytes, conf_height: int):
        self.acc = acc
        self.acc_open = acc_open
        self.acc_head = acc_head
        self.block_count = block_count
        self.conf_frontier = conf_frontier
        self.conf_height = conf_height

    def __str__(self):
        s  = 'Account:       %s\n' % hexlify(self.acc)
        s += 'Acc Open:      %s\n' % hexlify(self.acc_open)
        s += 'Acc Head:      %s\n' % hexlify(self.acc_head)
        s += 'Conf Frontier: %s\n' % hexlify(self.conf_frontier)
        s += 'Block Count:   %s\n' % self.block_count
        s += 'Conf Height:   %s'   % self.conf_height
        return s

    @classmethod
    def parse(cls, data: bytes):
        assert len(data) == 144
        acc           = data[0:32]
        acc_open      = data[32:64]
        acc_head      = data[64:96]
        block_count   = int.from_bytes(data[96:104], "big")
        conf_frontier = data[104:136]
        conf_height   = int.from_bytes(data[136:144], "big")
        return asc_pull_ack_account_info_payload(acc, acc_open, acc_head, block_count, conf_frontier, conf_height)


class asc_pull_ack_blocks_payload:

    def __init__(self, blocks):
        self.blocks = blocks

    def __str__(self):
        s = ''
        for b in self.blocks:
            s += str(b)
        return s

    @classmethod
    def parse(cls, data: bytes):
        i = 0
        total_bytes_consumed = 0
        blocks = []
        while True:
            data_to_process = data[total_bytes_consumed:]
            block, bytes_consumed = Block.parse_type_and_block_from_bytes(data_to_process)
            total_bytes_consumed += bytes_consumed
            if block is None:
                break
            blocks.append(block)
            i += 1
        return asc_pull_ack_blocks_payload(blocks)


class asc_pull_ack_with_payload(asc_pull_ack):

    def __init__(self, hdr: message_header, type_, id_, payload):
        super().__init__(hdr, type_, id_)
        self.payload = payload

    def __str__(self):
        s = super().__str__() + '\n'
        s += str(self.payload)
        return s


def read_asc_pull_acks(ctx: dict, s: socket.socket) -> bool:
    # wait for an asc_pull_ack
    hdr, data = get_next_hdr_payload(s)
    print(hdr)
    while hdr.msg_type != message_type(message_type_enum.asc_pull_ack):
        hdr, data = get_next_hdr_payload(s)
        print(hdr)

    # process the asc pull ack
    return asc_pull_ack.parse(hdr, data)


def do_asc_pull_account_info(ctx: dict, s: socket.socket, start: bytes) -> bool:
    hdr = message_header(ctx['net_id'], [19, 19, 18], message_type(message_type_enum.asc_pull_req), 0)
    print('Requesting hash or account: %s' % hexlify(start))
    req = asc_pull_req_account_info(hdr, start)
    s.sendall(req.serialise())
    ack = read_asc_pull_acks(ctx, s)
    print(ack)


def do_asc_pull_blocks(ctx: dict, s: socket.socket, start: bytes, count: int) -> bool:
    hdr = message_header(ctx['net_id'], [19, 19, 18], message_type(message_type_enum.asc_pull_req), 0)
    print('Requesting hash or account: %s count=%s' % (hexlify(start), count))
    req = asc_pull_req_blocks(hdr, start, count)
    s.sendall(req.serialise())
    ack = read_asc_pull_acks(ctx, s)
    print(ack)
    print('Pulled %s blocks' % len(ack.payload.blocks))


def main() -> None:
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx

    if args.peer is not None:
        peeraddr, peerport = parse_endpoint(args.peer, default_port=ctx['peerport'])

    else:
        peer = get_random_peer(ctx, lambda p: p.score >= 1000 and p.ip.is_ipv4() and p.telemetry and p.telemetry.protocol_ver >= 19)
        peeraddr = str(peer.ip)
        peerport = peer.port

    if args.start is not None:
        start = binascii.unhexlify(args.start)
    else:
        start = binascii.unhexlify(ctx['genesis_pub'])

    print('Connecting to [%s]:%s' % (peeraddr, peerport))
    with get_connected_socket_endpoint(peeraddr, peerport) as s:
        signing_key, verifying_key = node_handshake_id.keypair()
        node_handshake_id.perform_handshake_exchange(ctx, s, signing_key, verifying_key)
        print('handshake done')
        s.settimeout(10)

        if args.accinfo:
            do_asc_pull_account_info(ctx, s, start)
        else:
            do_asc_pull_blocks(ctx, s, start, args.count)


def parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')

    parser.add_argument('-p', '--peer',
                        help='peer to contact for frontiers (if not set, one is randomly selected using DNS)')

    parser.add_argument('-s', '--start', type=str,
                        help='hash or account to pull')

    parser.add_argument('-i', '--accinfo', action='store_true', default=False,
                        help='request account info')

    parser.add_argument('-c', '--count', type=int, default=128,
                        help='Max number of blocks to pull')

    return parser.parse_args()


if __name__ == '__main__':
    main()
