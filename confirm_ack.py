#!/bin/env python3

from __future__ import annotations

import sys
import time
import argparse

from pynanocoin import *
from msg_handshake import node_handshake_id
from peercrawler import *
import datetime


class vote_common:
    def __init__(self, account: bytes, sig: bytes, seq: int):
        assert len(account) == 32
        assert len(sig) == 64
        assert isinstance(seq, int)
        self.account = account
        self.sig = sig
        self.seq = seq

    @classmethod
    def parse(cls, data: bytes):
        assert (len(data) == 104)
        account = data[0:32]
        sig = data[32:96]
        seq = int.from_bytes(data[96:], 'little')
        return vote_common(account, sig, seq)

    def serialise(self) -> bytes:
        data = self.account
        data += self.sig
        data += self.seq.to_bytes(8, 'little')
        return data

    def __str__(self):
        #print(type(self.account))
        #print(repr(self.account))
        #print(hexlify(self.account))
        string  = 'Account: %s\n' % hexlify(self.account)
        string += '         %s\n' % acctools.to_account_addr(self.account)
        string += 'Signature: %s\n' % hexlify(self.sig)

        if self.seq == 0xffffffffffffffff:
            string += 'Sequence: %s(%s) [final vote]\n' % (self.seq, hex(self.seq))
        else:
            ts = datetime.datetime.fromtimestamp(self.seq / 1000)
            string += 'Sequence: %s(%s) [%s]\n' % (self.seq, hex(self.seq), ts)
        return string


class confirm_ack:
    @classmethod
    def parse(self, hdr: message_header, data: bytes):
        assert isinstance(hdr, message_header)
        if hdr.block_type() == block_type_enum.not_a_block:
            return confirm_ack_hash.parse(hdr, data)
        else:
            return confirm_ack_block.parse(hdr, data)


class confirm_ack_hash(confirm_ack):
    def __init__(self, hdr: message_header, common: vote_common, hashes: list[bytes]):
        assert(isinstance(hdr, message_header))
        assert(isinstance(common, vote_common))
        self.hdr = hdr
        self.common = common
        self.hashes = hashes

        # adjust the header to match the type and number of hashes
        hdr.set_item_count(len(hashes))
        hdr.set_block_type(block_type_enum.not_a_block)

    @classmethod
    def parse(cls, hdr: message_header, data: bytes):
        assert(isinstance(hdr, message_header))
        common = vote_common.parse(data[0:104])

        item_count = hdr.count_get()
        hashes_data = data[104:]
        assert((len(hashes_data)/32) == item_count)

        hashes = []
        for i in range(0, item_count):
            _hash = hashes_data[:32]
            hashes_data = hashes_data[32:]
            hashes.append(_hash)

        return confirm_ack_hash(hdr, common, hashes)

    def serialise(self) -> bytes:
        data = self.hdr.serialise_header()
        data += self.common.serialise()
        for h in self.hashes:
            assert len(h) == 32
            data += h
        return data

    def hash(self) -> bytes:
        hasher = blake2b(digest_size=32)
        hasher.update('vote '.encode('ascii'))

        for h in self.hashes:
            hasher.update(h)

        hasher.update(self.common.seq.to_bytes(8, 'little'))
        return hasher.digest()

    def is_valid(self) -> bool:
        hasher = blake2b(digest_size=32)
        hasher.update('vote '.encode('ascii'))

        for h in self.hashes:
            hasher.update(h)

        hasher.update(self.common.seq.to_bytes(8, 'little'))

        return verify(hasher.digest(), self.common.sig, self.common.account)

    def __str__(self):
        string = ''
        string += str(self.hdr)
        string += '\n'
        string += str(self.common)
        string += '%s signature\n' % 'Valid' if self.is_valid() else 'INVALID'
        string += 'Hashes: \n'
        for h in self.hashes:
            string += '   '
            string += hexlify(h)
            string += '\n'
        return string


# TODO: This confirm ack also has a vote_common field
class confirm_ack_block(confirm_ack):
    def __init__(self, hdr: message_header, common: vote_common, block):
        assert(isinstance(hdr, message_header))
        assert(isinstance(common, vote_common))
        self.hdr = hdr
        self.common = common
        self.block = block

    @classmethod
    def parse(cls, hdr: message_header, data: bytes):
        common = vote_common.parse(data[0:104])
        assert(isinstance(hdr, message_header))
        block_type = hdr.block_type()
        assert(block_type in range(2, 7))
        assert(len(data) == block_length_by_type(block_type) + 104)
        block = None
        if block_type == 2:
            block = block_send.parse(data[104:])
        elif block_type == 3:
            block = block_receive.parse(data[104:])
        elif block_type == 4:
            block = block_open.parse(data[104:])
        elif block_type == 5:
            block = block_change.parse(data[104:])
        elif block_type == 6:
            block = block_state.parse(data[104:])
        return confirm_ack_block(hdr, common, block)

    def is_valid(self) -> bool:
        hasher = blake2b(digest_size=32)
        hasher.update('vote '.encode('ascii'))

        hasher.update(self.block.hash())

        hasher.update(self.common.seq.to_bytes(8, 'little'))

        return verify(hasher.digest(), self.common.sig, self.common.account)

    def __str__(self):
        string = ''
        string += str(self.hdr)
        string += '\n'
        string += str(self.block)


class confirm_ack_thread(threading.Thread):
    def __init__(self, ctx: dict, peeraddr: str, peerport: int, data: bytes):
        threading.Thread.__init__(self, daemon=True)
        self.ctx = ctx
        self.peeraddr = peeraddr
        self.peerport = peerport
        self.data = data

    def run(self) -> None:
        print('Starting confirm ack thread')
        print('Connecting to [%s]:%s' % (self.peeraddr, self.peerport))
        with get_connected_socket_endpoint(self.peeraddr, self.peerport) as s:
            s.settimeout(10)
            signing_key, verifying_key = node_handshake_id.keypair()
            peer_id = node_handshake_id.perform_handshake_exchange(self.ctx, s, signing_key, verifying_key)
            print('Local Node ID: %s' % acctools.to_account_addr(verifying_key.to_bytes(), prefix='node_'))
            print('Peer  Node ID: %s' % acctools.to_account_addr(peer_id, prefix='node_'))

            while True:
                s.send(self.data)
        print('confirm ack thread ended')


def main():
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx
    
    peeraddr, peerport = parse_endpoint(args.peer, default_port=ctx['peerport'])

    hdr = message_header(ctx['net_id'], [18, 18, 18], message_type(message_type_enum.confirm_ack), 0)
    common = vote_common(b'\x0A' * 32, b'\x00' * 64, 0xFFFFFFFFFFFFFFFF)
    hashes = [b'\x02' * 32, b'\x03' * 32]
    ack = confirm_ack_hash(hdr, common, hashes)
    print(ack)

    peeraddr, peerport = parse_endpoint(args.peer, default_port=ctx['peerport'])

    threads = []
    for i in range(4):
        t = confirm_ack_thread(ctx, peeraddr, peerport, ack.serialise())
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


def parse_args():
    parser = argparse.ArgumentParser()

    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument('-b', '--beta', action='store_true', default=False,
                        help='use beta network')
    group2.add_argument('-t', '--test', action='store_true', default=False,
                        help='use test network')

    parser.add_argument('peer',
                        help='peer to contact')

    return parser.parse_args()


if __name__ == '__main__':
    main()
