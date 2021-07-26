#!/bin/env python3

import sys
import time
import argparse

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

    def is_response(self, confirm_ack):
        assert(isinstance(confirm_ack, confirm_ack_block) or isinstance(confirm_ack, confirm_ack_hash))
        if isinstance(confirm_ack, confirm_ack_hash):
            for h in self.hash_pairs:
                if h.first not in confirm_ack.hashes:
                    return False

        elif isinstance(confirm_ack, confirm_ack_block):
            assert(len(self.hash_pairs) == 1)
            for h in self.hash_pairs:
                if h.first != confirm_ack.block.hash():
                    return False

        return True

    def __str__(self):
        string = str(self.hdr) + "\n"
        for i in range(1, len(self.hash_pairs) + 1):
            string += "Pair %d:\n" % i
            string += str(self.hash_pairs[i-1])
        return string


class confirm_req_block:
    def __init__(self, hdr, block, block_type):
        # TODO: Fill in the headers block_type and item count here
        # Block has to be an instance of a block class
        assert(isinstance(hdr, message_header))
        assert(isinstance(block_type, int))
        self.hdr = hdr
        self.hdr.set_block_type(block_type)
        self.hdr.set_item_count(1)
        self.block = block

    def serialise(self):
        assert(self.hdr.block_type() in range(2, 7))
        data = self.hdr.serialise_header()
        data += self.block.serialise(False)
        return data

    def is_response(self, confirm_ack):
        assert(isinstance(confirm_ack, confirm_ack_block) or isinstance(confirm_ack, confirm_ack_hash))

        if isinstance(confirm_ack, confirm_ack_block):
            if self.block.hash() != confirm_ack.block.hash():
                return False

        if isinstance(confirm_ack, confirm_ack_hash):
            if self.block.hash() not in confirm_ack.hashes:
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
        string += str(self.hdr)
        string += "\n"
        string += str(self.block)


def check_confirm_req_response(confirm_req, confirm_ack):
    # TODO: Check this
    assert(isinstance(confirm_req, confirm_req_hash) or isinstance(confirm_req, confirm_req_block))
    assert(isinstance(confirm_ack, confirm_ack_hash) or isinstance(confirm_ack, confirm_ack_block))
    return confirm_req.is_response(confirm_ack)


def get_next_confirm_ack(s):
    hdr, data = get_next_hdr_payload(s)
    while hdr.msg_type != message_type(5):
        hdr, data = get_next_hdr_payload(s)
    return hdr, data


def send_confirm_req_block(s):
    test_block_send = {
        "prev": binascii.unhexlify('4A039AD482C917C266A3D4A2C97849CE69173B6BC775AFC779B9EA5CE446426F'),
        "dest": binascii.unhexlify('42DD308BA91AA225B9DD0EF15A68A8DD49E2940C6277A4BFAC363E1C8BF14279'),
        "bal": 205676479325586539664609129644855132177,
        "sig": binascii.unhexlify(
            '30A5850305AA61185008D4A732AA8527682D239D85457368B6A581F517D5F8C0078DB99B5741B79CC29880387292B64F668C964BE1B50790D3EC7D948396D007'),
        "work": binascii.unhexlify('EDFD7157025EA461')
    }

    block = block_send(test_block_send["prev"], test_block_send["dest"], test_block_send["bal"],
                       test_block_send["sig"], test_block_send["work"])

    header = message_header(network_id(67), [18, 18, 18], message_type(4), 0)

    req = confirm_req_block(header, block, block_type_enum.send)
    print("The block we send hash: %s" % hexlify(block.hash()))
    s.send(req.serialise())

    search_for_response(s, req)


def send_confirm_req_hash(s):
    header = message_header(network_id(67), [18, 18, 18], message_type(4), 0)
    header.set_item_count(1)
    header.set_block_type(1)
    big_acc_block_open = {
        "source": binascii.unhexlify('A170D51B94E00371ACE76E35AC81DC9405D5D04D4CEBC399AEACE07AE05DD293'),
        "rep": binascii.unhexlify('2399A083C600AA0572F5E36247D978FCFC840405F8D4B6D33161C0066A55F431'),
        "account": binascii.unhexlify('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5'),
        "sig": binascii.unhexlify('E950FFDF0C9C4DAF43C27AE3993378E4D8AD6FA591C24497C53E07A3BC80468539B0A467992A916F0DDA6F267AD764A3C1A5BDBD8F489DFAE8175EEE0E337402'),
        "work": binascii.unhexlify('E997C097A452A1B1')
    }
    block = block_open(big_acc_block_open["source"], big_acc_block_open["rep"], big_acc_block_open["account"],
                       big_acc_block_open["sig"], big_acc_block_open["work"])
    # print(block)

    # block_hash = binascii.unhexlify('4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05')
    # root = binascii.unhexlify('4A039AD482C917C266A3D4A2C97849CE69173B6BC775AFC779B9EA5CE446426F')

    # block_hash = binascii.unhexlify('991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948')
    # root = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')

    # block_hash = block.hash()
    # root = block.root()

    block_hash = binascii.unhexlify('991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948')
    root = genesis_block_open["account"]

    pairs = [hash_pair(block_hash, root)]
    req = confirm_req_hash(header, pairs)
    print(req)
    s.send(req.serialise())
    search_for_response(s, req)


def search_for_response(s, req):
    assert(isinstance(req, confirm_req_block) or isinstance(req, confirm_req_hash))
    starttime = time.time()
    while time.time() - starttime <= 15:
        hdr, data = get_next_confirm_ack(s)
        if hdr.block_type() == 1:
            ack = confirm_ack_hash.parse(hdr, data)
            if req.is_response(ack):
                print("Found response!")
                print(ack)
                sys.exit(0)
        else:
            ack = confirm_ack_block.parse(hdr, data)
            if req.is_response(ack):
                print("Found response!")
                print(ack)
                sys.exit(0)


    print("No response found!")


def convert_blocks_to_hash_pairs(blocks):
    pairs = []
    for b in blocks:
        hash_pair(b.hash(), b.root())
    return pairs


def main():
    ctx = livectx
    s = get_initial_connected_socket(ctx)
    s.settimeout(20)
    perform_handshake_exchange(s)

    args = parse_args()
    print(args)
    if args.block:
        send_confirm_req_block(s)
    elif args.hashes:
        send_confirm_req_hash(s)
    else:
        print("Please specify either -B or -H for sending a confirm_req using a block or hashes respectively")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-B', '--block', action="store_true", required=False, default=False)
    parser.add_argument('-H', '--hashes', action="store_true", required=False, default=False)
    return parser.parse_args()



if __name__ == "__main__":
    main()
