#!/bin/env python3

import sys
import time

from nanolib import *


class hash_pair:
    def __init__(self, first, second):
        assert(len(first) == 32 and len(second) == 32)
        self.first = first
        self.second = second

    def __str__(self):
        string =  "  First: %s\n" % hexlify(self.first)
        string += "  Second: %s\n" % hexlify(self.second)
        return string

    def serialise(self):
        data = self.first
        data += self.second
        return data


class confirm_req_hash:
    def __init__(self, hdr, hash_pairs):
        assert(isinstance(hdr, message_header))
        assert(hdr.count_get() == len(hash_pairs))
        self.hdr = hdr
        self.hash_pairs = hash_pairs

    @classmethod
    def parse(self, hdr, data):
        assert(isinstance(hdr, message_header))
        item_count = hdr.count_get()
        assert(len(data) / 64 == item_count)

        hash_pairs = []
        for i in range(0, item_count):
            first = data[0:32]
            second = data[32:64]
            pair = hash_pair(first, second)
            hash_pairs.append(pair)
            data = data[64:]

        return confirm_req_hash(hdr, hash_pairs)

    def serialise(self):
        data = self.hdr.serialise_header()
        for h in self.hash_pairs:
            data += h.serialise()
        return data

    def __str__(self):
        string = str(self.hdr) + "\n"
        for i in range(1, len(self.hash_pairs) + 1):
            string += "Pair %d:\n" % i
            string += str(self.hash_pairs[i-1])
        return string


class confirm_req_block:
    def __init__(self, hdr, block):
        assert(isinstance(hdr, message_header))
        self.hdr = hdr
        self.block = block

    def serialise(self):
        assert(self.hdr.block_type() in range(2, 7))
        data = self.hdr.serialise_header()
        data += block.serialise(False)
        return data

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
        string = "Account: %s\n" % hexlify(self.account)
        string += "Signature: %s\n" % hexlify(self.sig)
        string += "Sequence: %s\n" % self.seq
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
        string += str(hdr)
        string += "\n"
        string += str(block)


def get_next_confirm_ack(s):
    hdr, data = get_next_hdr_payload(s)
    while hdr.msg_type != message_type(5):
        hdr, data = get_next_hdr_payload(s)
    return hdr, data


# block = block_open(genesis_block_open["source"], genesis_block_open["representative"],
#                    genesis_block_open["account"], genesis_block_open["signature"],
#                    genesis_block_open["work"])

test_block_send = {
    "prev" : binascii.unhexlify('4A039AD482C917C266A3D4A2C97849CE69173B6BC775AFC779B9EA5CE446426F'),
    "dest" : binascii.unhexlify('42DD308BA91AA225B9DD0EF15A68A8DD49E2940C6277A4BFAC363E1C8BF14279'),
    "bal"  : 205676479325586539664609129644855132177,
    "sig"  : binascii.unhexlify('30A5850305AA61185008D4A732AA8527682D239D85457368B6A581F517D5F8C0078DB99B5741B79CC29880387292B64F668C964BE1B50790D3EC7D948396D007'),
    "work" : binascii.unhexlify('EDFD7157025EA461')
}

block = block_send(test_block_send["prev"], test_block_send["dest"], test_block_send["bal"],
                   test_block_send["sig"], test_block_send["work"])

header = message_header(network_id(67), [18, 18, 18], message_type(4), 0)
header.set_block_type(block_type_enum.send)
header.set_item_count(1)

msg = confirm_req_block(header, block)
print("The block we send hash: %s" % hexlify(block.hash()))

ctx = livectx
s = get_initial_connected_socket(ctx)
s.settimeout(20)
perform_handshake_exchange(s)
s.send(msg.serialise())

hdr, data = get_next_hdr_payload(s)
confirm_req = confirm_req_hash.parse(hdr, data)
print("First confirm_req (always) received: ")
print(confirm_req)

confirm_acks = []

starttime = time.time()
while time.time() - starttime <= 15:
    hdr, data = get_next_confirm_ack(s)
    if hdr.block_type() == 1:
        ack = confirm_ack_hash.parse(hdr, data)
        confirm_acks.append(ack)
        if block.hash() in ack.hashes:
            print("Found the block hash we sent!")
            print(ack)
            print("breaking!")
            sys.exit(0)
    else:
        ack = confirm_ack_block.parse(hdr, data)
        confirm_acks.append(ack)
        if block.hash() == ack.block.hash():
            print("Found the block hash we sent!")
            print(ack)
            print("breaking!")
            sys.exit(0)

print("No response found!")
# for a in confirm_acks:
#     print(a)
