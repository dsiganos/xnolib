#!/bin/env python3

import sys
import time
import argparse

from pynanocoin import *


class hash_pair:
    def __init__(self, hsh, root):
        assert len(hsh) == 32 and len(root) == 32
        self.hsh = hsh
        self.root = root

    def __str__(self):
        string =  "  Hash: %s\n" % hexlify(self.hsh)
        string += "  Root: %s\n" % hexlify(self.root)
        return string

    def serialise(self):
        return self.hsh + self.root

    @classmethod
    def parse(self, data):
        assert len(data) == 64
        return hash_pair(data[0:32], data[32:64])

class confirm_req_hash:
    def __init__(self, hdr, hash_pairs):
        assert(isinstance(hdr, message_header))
        assert(len(hash_pairs) > 0)
        hdr.set_item_count(len(hash_pairs))
        hdr.set_block_type(block_type_enum.not_a_block)
        self.hdr = hdr
        self.hash_pairs = hash_pairs

    @classmethod
    def parse(self, hdr, data):
        assert  isinstance(hdr, message_header)
        assert(len(data) / 64 == hdr.count_get())

        hash_pairs = []
        for i in range(0, hdr.count_get()):
            hash_pairs.append(hash_pair.parse(data[0:64]))
            data = data[64:]

        return confirm_req_hash(hdr, hash_pairs)

    def serialise(self):
        data = self.hdr.serialise_header()
        for h in self.hash_pairs:
            data += h.serialise()
        return data

    def is_response(self, ack):
        assert(isinstance(ack, confirm_ack_block) or isinstance(ack, confirm_ack_hash))
        if isinstance(ack, confirm_ack_hash):
            for h in self.hash_pairs:
                if h.hsh not in ack.hashes:
                    return False

        elif isinstance(ack, confirm_ack_block):
            assert(len(self.hash_pairs) == 1)
            for h in self.hash_pairs:
                if h.hsh != ack.block.hash():
                    return False

        return True

    def __str__(self):
        string = str(self.hdr) + "\n"
        for i in range(1, len(self.hash_pairs) + 1):
            string += "Pair %d:\n" % i
            string += str(self.hash_pairs[i-1])
        return string


class confirm_req_block:
    def __init__(self, hdr, block):
        # TODO: Fill in the headers block_type and item count here
        # Block has to be an instance of a block class
        assert(isinstance(hdr, message_header))
        block_type = block.get_type_int()
        self.hdr = hdr
        self.hdr.set_block_type(block_type)
        self.hdr.set_item_count(1)
        self.block = block

    def serialise(self):
        assert(self.hdr.block_type() in range(2, 7))
        data = self.hdr.serialise_header()
        data += self.block.serialise(False)
        return data

    def is_response(self, ack):
        assert(isinstance(ack, confirm_ack_block) or isinstance(ack, confirm_ack_hash))

        if isinstance(ack, confirm_ack_block):
            if self.block.hash() != ack.block.hash():
                return False

        if isinstance(ack, confirm_ack_hash):
            if self.block.hash() not in ack.hashes:
                return False

        return True

    def __str__(self):
        string = str(self.hdr) + "\n"
        string += str(self.block)
        return string


class vote_common:
    def __init__(self, account, sig, seq):
        assert(isinstance(seq, int))
        self.account = account
        self.sig = sig
        self.seq = seq

    @classmethod
    def parse(cls, data):
        assert (len(data) == 104)
        account = data[0:32]
        sig = data[32:96]
        seq = int.from_bytes(data[96:], "little")
        return vote_common(account, sig, seq)

    def __str__(self):
        final_str = ''
        if self.seq == 0xffffffffffffffff:
            final_str = ' [final vote]'
        string = "Account: %s\n" % hexlify(self.account)
        string += "Signature: %s\n" % hexlify(self.sig)
        string += "Sequence: %s(%s)%s\n" % (self.seq, hex(self.seq), final_str)
        return string


class confirm_ack_hash:
    def __init__(self, hdr, common, hashes):
        assert(isinstance(hdr, message_header))
        assert(isinstance(common, vote_common))
        self.hdr = hdr
        self.common = common
        self.hashes = hashes

    @classmethod
    def parse(cls, hdr, data):
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

    def __str__(self):
        string = ""
        string += str(self.hdr)
        string += "\n"
        string += str(self.common)
        string += "Hashes: \n"
        for h in self.hashes:
            string += "   "
            string += hexlify(h)
            string += "\n"
        return string


class confirm_ack_block:
    def __init__(self, hdr, block):
        assert(isinstance(hdr, message_header))
        self.hdr = hdr
        self.block = block

    @classmethod
    def parse(cls, hdr, data):
        assert(isinstance(hdr, message_header))
        block_type = hdr.block_type()
        assert(block_type in range(2, 7))
        assert(len(data) == block_length_by_type(block_type))
        block = None
        if block_type == 2:
            block = block_send.parse(data)
        elif block_type == 3:
            block = block_receive.parse(data)
        elif block_type == 4:
            block = block_open.parse(data)
        elif block_type == 5:
            block = block_change.parse(data)
        elif block_type == 6:
            block = block_state.parse(data)
        return confirm_ack_block(hdr, block)

    def __str__(self):
        string = ""
        string += str(self.hdr)
        string += "\n"
        string += str(self.block)


def get_next_confirm_ack(s):
    hdr, data = get_next_hdr_payload(s)
    while hdr.msg_type != message_type(5):
        hdr, data = get_next_hdr_payload(s)
    return hdr, data


def send_confirm_req_block(ctx, s):
    block = block_open(ctx["genesis_block"]["source"], ctx["genesis_block"]["representative"],
                       ctx["genesis_block"]["account"], ctx["genesis_block"]["signature"],
                       ctx["genesis_block"]["work"])

    print("The block we send hash: %s" % hexlify(block.hash()))

    outcome = confirm_block(ctx, block, s)

    if not outcome:
        print("block %s not confirmed!" % hexlify(block.hash()))
    else:
        print("block %s confirmed!" % hexlify(block.hash()))


def send_confirm_req_hash(ctx, s):
    block = block_open(ctx["genesis_block"]["source"], ctx["genesis_block"]["representative"],
                       ctx["genesis_block"]["account"], ctx["genesis_block"]["signature"],
                       ctx["genesis_block"]["work"])

    # print(block)

    outcome = confirm_blocks_by_hash(ctx, [block], s)

    if not outcome:
        print("blocks not confirmed!")
    else:
        print("blocks confirmed")


def search_for_response(s, req):
    assert(isinstance(req, confirm_req_block) or isinstance(req, confirm_req_hash))
    starttime = time.time()
    while time.time() - starttime <= 15:
        hdr, data = get_next_confirm_ack(s)
        if hdr.block_type() == 1:
            ack = confirm_ack_hash.parse(hdr, data)
            if req.is_response(ack):
                print("Found response!")
                return ack
        else:
            ack = confirm_ack_block.parse(hdr, data)
            if req.is_response(ack):
                print("Found response!")
                return ack

    return None


def convert_blocks_to_hash_pairs(blocks):
    pairs = []
    for b in blocks:
        pair = hash_pair(b.hash(), b.root())
        pairs.append(pair)
    return pairs


def confirm_block(ctx, block, s):
    hdr = message_header(ctx["net_id"], [18, 18, 18], message_type(4), 0)
    req = confirm_req_block(hdr, block)
    s.send(req.serialise())

    resp = search_for_response(s, req)

    if resp is None:
        return False
    else:
        return True


def confirm_blocks_by_hash(ctx, blocks, s):
    assert(isinstance(blocks, list))
    hdr = message_header(ctx["net_id"], [18, 18, 18], message_type(4), 0)
    pairs = convert_blocks_to_hash_pairs(blocks)
    req = confirm_req_hash(hdr, pairs)
    s.send(req.serialise())

    resp = search_for_response(s, req)

    return resp is not None


def confirm_req_peer(ctx, do_block, peeraddr=None):
    if peeraddr:
        peer = Peer(ip_addr(ipaddress.IPv6Address(peeraddr)), ctx['peerport'], 1000)
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(3)
        s.connect((str(peer.ip), peer.port))
    else:
        s, _ = get_initial_connected_socket(ctx)

    perform_handshake_exchange(ctx, s)
    print('handshake done')

    s.settimeout(10)
    if do_block:
        send_confirm_req_block(ctx, s)
    else:
        send_confirm_req_hash(ctx, s)


def main():
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx

    confirm_req_peer(ctx, args.block, args.peer)


def parse_args():
    parser = argparse.ArgumentParser()

    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument('-B', '--block', action="store_true", default=False)
    group1.add_argument('-H', '--hash', action="store_true", default=False)

    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument('-b', '--beta', action='store_true', default=False,
                        help='use beta network')
    group2.add_argument('-t', '--test', action='store_true', default=False,
                        help='use test network')

    parser.add_argument('-p', '--peer',
                        help='peer to contact for frontiers (if not set, one is randomly selected using DNS)')

    return parser.parse_args()


if __name__ == "__main__":
    main()