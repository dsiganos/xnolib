#!/bin/env python3

from hashlib import blake2b
import binascii
import ipaddress
import socket
import base64
import dns.resolver
import random

import ed25519_blake2


class ParseErrorBadMagicNumber(Exception): pass


class ParseErrorBadNetworkId(Exception): pass


class ParseErrorBadMessageType(Exception): pass


class ParseErrorBadIPv6(Exception): pass


class ParseErrorBadMessageBody(Exception): pass


class ParseErrorBadBlockSend(Exception): pass


class ParseErrorBadBlockReceive(Exception): pass


class ParseErrorBadBlockOpen(Exception): pass


class ParseErrorBadBlockChange(Exception): pass


class ParseErrorBadBlockChange(Exception): pass


class ParseErrorBadBlockState(Exception): pass


class ParseErrorBadBulkPullResponse(Exception): pass


class BadBlockHash(Exception): pass


class SocketClosedByPeer(Exception): pass


class InvalidBlockHash(Exception): pass


def account_id_to_name(acc_id_bin):
    assert (len(acc_id_bin) == 32)

    genesis_live = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
    genesis_beta = binascii.unhexlify('259A43ABDB779E97452E188BA3EB951B41C961D3318CA6B925380F4D99F0577A')
    burn = b'\x00' * 32

    named_accounts = {
        genesis_live : 'genesis live',
        genesis_beta : 'genesis beta',
        burn : 'burn',
    }

    return named_accounts.get(acc_id_bin, '')


def get_all_dns_addresses(url):
    result = dns.resolver.resolve(url, 'A')
    return [x.to_text() for x in result]


# this function expects account to be a 32 byte bytearray
def get_account_id(account, prefix='nano_'):
    assert (len(account) == 32)

    RFC_3548 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    ENCODING = b"13456789abcdefghijkmnopqrstuwxyz"

    h = blake2b(digest_size=5)
    h.update(account)
    checksum = h.digest()

    # prefix account to make it even length for base32, add checksum in reverse byte order
    account2 = b'\x00\x00\x00' + account + checksum[::-1]

    # use the optimized base32 lib to speed this up
    encode_account = base64.b32encode(account2)

    # simply translate the result from RFC3548 to Nano's encoding, snip off the leading useless bytes
    encode_account = encode_account.translate(bytes.maketrans(RFC_3548, ENCODING))[4:]

    label = account_id_to_name(account)
    if label != '':
        label = ' (' + label + ')'

    # add prefix, label and return
    return prefix + encode_account.decode() + label


class block_type_enum:
    invalid = 0
    not_a_block = 1
    send = 2
    receive = 3
    open = 4
    change = 5
    state = 6


class message_type_enum:
    invalid = 0x0
    not_a_type = 0x1
    keepalive = 0x2
    publish = 0x3
    confirm_req = 0x4
    confirm_ack = 0x5
    bulk_pull = 0x6
    bulk_push = 0x7
    frontier_req = 0x8
    # deleted 0x9
    node_id_handshake = 0x0a
    bulk_pull_account = 0x0b
    telemetry_req = 0x0c
    telemetry_ack = 0x0d


class network_id:
    def __init__(self, rawbyte):
        self.parse_header(int(rawbyte))

    def parse_header(self, rawbyte):
        # if not (rawbyte in [ord('A'), ord('B'), ord('C')]):
        #     raise ParseErrorBadNetworkId()
        self.id = rawbyte

    def __str__(self):
        return chr(self.id)


class message_type:
    def __init__(self, data):
        self.parse_type(data)

    def parse_type(self, data):
        # if not (data in range(2, 13)):
        #      raise ParseErrorBadMessageType()
        self.type = data

    def __str__(self):
        return str(self.type)


class message_header:

    def __init__(self, net_id, versions, msg_type, ext):
        self.ext = ext
        self.net_id = net_id
        self.ver_max = versions[0]
        self.ver_using = versions[1]
        self.ver_min = versions[2]
        self.msg_type = msg_type

    def serialise_header(self):
        header = b""
        header += ord('R').to_bytes(1, "big")
        header += ord(str(self.net_id)).to_bytes(1, "big")
        header += self.ver_max.to_bytes(1, "big")
        header += self.ver_using.to_bytes(1, "big")
        header += self.ver_min.to_bytes(1, "big")
        header += self.msg_type.type.to_bytes(1, "big")
        header += (00).to_bytes(1, "big")
        header += (00).to_bytes(1, "big")
        return header

    # this need to become a class method
    @classmethod
    def parse_header(cls, data):
        # if data[0] != ord('R'):
        #     raise ParseErrorBadMagicNumber()
        ext = []
        net_id = network_id(data[1])
        versions = []
        versions.append(data[2])
        versions.append(data[3])
        versions.append(data[4])
        msg_type = message_type(data[5])
        ext.append(data[6])
        ext.append(data[7])
        return message_header(net_id, versions, msg_type, ext)

    def __eq__(self, other):
        if str(self) == str(other):
            return True

    def __str__(self):
        str = "NetID:%s, " % self.net_id
        str += "VerMax:%s, " % self.ver_max
        str += "VerUsing:%s, " % self.ver_using
        str += "VerMin:%s, " % self.ver_min
        str += "MsgType:%s, " % self.msg_type
        str += "Extensions:%s, %s" % (self.ext[0], self.ext[1])
        return str


class ipv6addresss:
    def __init__(self, ip):
        self.ip = ip

    @classmethod
    def parse_address(cls, data):
        if len(data) < 16:
            raise ParseErrorBadIPv6
        address_int = int.from_bytes(data[0:16], "big")
        return ipv6addresss(ipaddress.IPv6Address(address_int))

    def __str__(self):
        return str(self.ip)


# A class representing a peer, stores its address, port and provides the means to convert
# it into a readable string format
class peer_address:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def serialise(self):
        data = b""
        data += self.ip.ip.packed
        data += self.port.to_bytes(2, "little")
        return data

    def __str__(self):
        string = "["
        string += str(self.ip) + "]:"
        string += str(self.port)
        return string


# Creates, stores and manages all of the peer_address objects (from the raw data)
class peers():
    def __init__(self, peers):
        self.peers = peers

    @classmethod
    def parse_peers(cls, rawdata):
        if len(rawdata) % 18 != 0:
            raise ParseErrorBadMessageBody()
        no_of_peers = int(len(rawdata) / 18)
        start_index = 0
        end_index = 18
        peers_list = []
        for i in range(0, no_of_peers):
            ip = ipv6addresss.parse_address(rawdata[start_index:end_index - 2])
            port = int.from_bytes(rawdata[end_index - 2:end_index], "little")
            p = peer_address(ip, port)
            peers_list.append(p)
            start_index = end_index
            end_index += 18
        return peers(peers_list)

    def serialise(self):
        data = b""
        for i in range(0, len(self.peers)):
            data += self.peers[i].serialise()
        return data

    def __eq__(self, other):
        if str(self) == str(other):
            return True

    def __str__(self):
        string = ""
        for i in range(0, len(self.peers)):
            string += "Peer %d:" % (i + 1)
            string += str(self.peers[i])
            string += "\n"
        return string


class message_keepmealive:
    def __init__(self, net_id):
        self.header = message_header(net_id, [18, 18, 18], message_type(2), [0, 0])
        ip1 = peer_address(ipv6addresss(ipaddress.IPv6Address("::ffff:9df5:d11e")), 54000)
        ip2 = peer_address(ipv6addresss(ipaddress.IPv6Address("::ffff:18fb:4f64")), 54000)
        ip3 = peer_address(ipv6addresss(ipaddress.IPv6Address("::ffff:405a:48c2")), 54000)
        ip4 = peer_address(ipv6addresss(ipaddress.IPv6Address("::ffff:9538:2eec")), 54000)
        ip5 = peer_address(ipv6addresss(ipaddress.IPv6Address("::ffff:2e04:4970")), 54000)
        ip6 = peer_address(ipv6addresss(ipaddress.IPv6Address("::ffff:68cd:cd53")), 54000)
        ip7 = peer_address(ipv6addresss(ipaddress.IPv6Address("::ffff:b3a2:bdef")), 54000)
        ip8 = peer_address(ipv6addresss(ipaddress.IPv6Address("::ffff:74ca:6b61")), 54000)
        peer_list = [ip1, ip2, ip3, ip4, ip5, ip6, ip7, ip8]
        self.peers = peers(peer_list)

    def serialise(self):
        data = self.header.serialise_header()
        data += self.peers.serialise()
        return data

    def __str__(self):
        string = str(self.header)
        string += "\n" + str(self.peers)
        return string

    def __eq__(self, other):
        if str(self) == str(other):
            return True
        return False


class message_bulk_pull:
    def __init__(self, block_hash, net_id):
        self.header = message_header(net_id, [18, 18, 18], message_type(6), [0, 0])
        self.public_key = binascii.unhexlify(block_hash)

    def serialise(self):
        data = self.header.serialise_header()
        data += self.public_key
        data += (0).to_bytes(32, "big")
        return data


class block_send:
    def __init__(self, prev, dest, bal, sig, work):
        self.previous = prev
        self.destination = dest
        self.balance = bal
        self.signature = sig
        self.work = work
        self.ancillary = {
            "account": None,
            "next": None
        }

    def hash(self):
        data = b"".join([
            self.previous,
            self.destination,
            self.balance
        ])
        return blake2b(data, digest_size=32).hexdigest().upper()

    def str_ancillary_data(self):
        string = ""
        hexacc = binascii.hexlify(self.ancillary["account"]).decode("utf-8").upper()
        string += "Acc : %s\n" % hexacc
        string += "      %s\n" % get_account_id(self.ancillary["account"])
        string += "Next: %s\n" % binascii.hexlify(self.ancillary["next"]).decode("utf-8").upper()


    def __str__(self):
        string = "------------- Block Send -------------\n"
        string += "Hash: %s\n" % self.hash()
        string += "Prev: %s\n" % binascii.hexlify(self.previous).decode("utf-8").upper()
        string += "Dest: %s\n" % binascii.hexlify(self.destination).decode("utf-8").upper()
        string += "      %s\n" % get_account_id(self.destination)
        string += "Bal:  %d\n" % int(self.balance.hex(), 16)
        string += "Sign: %s\n" % binascii.hexlify(self.signature).decode("utf-8").upper()
        string += "Work: %s\n" % binascii.hexlify(self.work).decode("utf-8").upper()
        return string


class block_receive:
    def __init__(self, prev, source, sig, work):
        self.previous = prev
        self.source = source
        self.signature = sig
        self.work = work
        self.ancillary = {
            "account": None,
            "next": None
        }

# TODO: Remember to reverse the order of the work if you implement serialisation!
    def hash(self):
        data = b"".join([
            self.previous,
            self.source
        ])
        return blake2b(data, digest_size=32).hexdigest().upper()

    def str_ancillary_data(self):
        string = ""
        hexacc = binascii.hexlify(self.ancillary["account"]).decode("utf-8").upper()
        string += "Acc : %s\n" % hexacc
        string += "      %s\n" % get_account_id(self.ancillary["account"])
        string += "Next: %s\n" % binascii.hexlify(self.ancillary["next"]).decode("utf-8").upper()


    def __str__(self):
        string = "------------- Block Receive -------------\n"
        string += "Hash: %s\n" % self.hash()
        string += "Prev: %s\n" % binascii.hexlify(self.previous).decode("utf-8").upper()
        string += "Src:  %s\n" % binascii.hexlify(self.source).decode("utf-8").upper()
        string += "Sign: %s\n" % binascii.hexlify(self.signature).decode("utf-8").upper()
        string += "Work: %s\n" % binascii.hexlify(self.work).decode("utf-8").upper()

        return string


class block_open:
    def __init__(self, source, rep, account, sig, work):
        self.source = source
        self.representative = rep
        self.account = account
        self.signature = sig
        self.work = work
        self.ancillary = {
            "previous": None,
            "next": None
        }

    def hash(self):
        data = b"".join([
            self.source,
            self.representative,
            self.account
        ])
        return blake2b(data, digest_size=32).hexdigest().upper()

    def str_ancillary_data(self):
        string = ""
        string += "Prev: %s" % binascii.hexlify(self.ancillary["previous"]).decode("utf-8").upper()
        string += "Next: %s\n" % binascii.hexlify(self.ancillary["next"]).decode("utf-8").upper()

    def __str__(self):
        hexacc = binascii.hexlify(self.account).decode("utf-8").upper()
        string = "------------- Block Open -------------\n"
        string += "Hash: %s\n" % self.hash()
        string += "Src:  %s\n" % binascii.hexlify(self.source).decode("utf-8").upper()
        string += "Repr: %s\n" % binascii.hexlify(self.representative).decode("utf-8").upper()
        string += "Acc : %s\n" % hexacc
        string += "      %s\n" % get_account_id(self.account)
        string += "Sign: %s\n" % binascii.hexlify(self.signature).decode("utf-8").upper()
        string += "Work: %s\n" % binascii.hexlify(self.work).decode("utf-8").upper()
        return string


class block_change:
    def __init__(self, prev, rep, sig, work):
        self.previous = prev
        self.representative = rep
        self.signature = sig
        self.work = work
        self.ancillary = {
            "account": None,
            "next": None
        }

    def hash(self):
        data = b"".join([
            self.previous,
            self.representative
        ])
        return blake2b(data, digest_size=32).hexdigest().upper()

    def str_ancillary_data(self):
        string = ""
        hexacc = binascii.hexlify(self.ancillary["account"]).decode("utf-8").upper()
        string += "Acc : %s\n" % hexacc
        string += "      %s\n" % get_account_id(self.ancillary["account"])
        string += "Next: %s\n" % binascii.hexlify(self.ancillary["next"]).decode("utf-8").upper()

    def __str__(self):
        string = "------------- Block Change -------------\n"
        string += "Hash: %s\n" % self.hash()
        string += "Prev: %s\n" % binascii.hexlify(self.previous).decode("utf-8").upper()
        string += "Repr: %s\n" % binascii.hexlify(self.representative).decode("utf-8").upper()
        string += "Sign: %s\n" % binascii.hexlify(self.signature).decode("utf-8").upper()
        string += "Work: %s\n" % binascii.hexlify(self.work).decode("utf-8").upper()


class block_state:
    def __init__(self, account, prev, rep, bal, link, sig, work):
        self.account = account
        self.previous = prev
        self.representative = rep
        self.balance = bal
        self.link = link
        self.signature = sig
        self.work = work
        self.ancillary = {
            "next": None
        }

    def hash(self):
        STATE_BLOCK_HEADER_BYTES = (b'\x00' * 31) + b'\x06'
        data = b"".join([
            STATE_BLOCK_HEADER_BYTES,
            self.account,
            self.previous,
            self.representative,
            self.balance,
            self.link

        ])
        return blake2b(data, digest_size=32).hexdigest().upper()

    def __str__(self):
        hexacc = binascii.hexlify(self.account).decode("utf-8").upper()
        string = "------------- Block State -------------\n"
        string += "Hash: %s\n" % self.hash()
        string += "Acc:  %s\n" % hexacc
        string += "      %s\n" % get_account_id(self.account)
        string += "Prev: %s\n" % binascii.hexlify(self.previous).decode("utf-8").upper()
        string += "Repr: %s\n" % binascii.hexlify(self.representative).decode("utf-8").upper()
        string += "Bal:  %d\n" % int(self.balance.hex(), 16)
        string += "Link: %s\n" % binascii.hexlify(self.link).decode("utf-8").upper()
        string += "Sign: %s\n" % binascii.hexlify(self.signature).decode("utf-8").upper()
        string += "Work: %s\n" % binascii.hexlify(self.work).decode("utf-8").upper()
        return string


class blocks_manager:
    def __init__(self, queue):
        self.accounts_raw = []
        self.accounts = []
        self.blocks = []
        self.validate_blocks(queue)
        self.assign_account_ids()
        self.make_accounts()
        self.assign_blocks_next()

    def traverse_backwards(self, block):
        traversal_order = []
        i = self.blocks.index(block)

        while i is not None:
            traversal_order.append(i)
            i = self.find_prev(self.blocks[i], self.blocks)

        return traversal_order

    def find_prev(self, block, blocks):
        if isinstance(block, block_open):
            prev = binascii.hexlify(block.source).decode("utf-8").upper()
        else:
            prev = binascii.hexlify(block.previous).decode("utf-8").upper()

        index = 0
        for b in blocks:
            hash = b.hash()
            if prev == hash:
                return index
            index += 1

        return None

    def find_block_by_hash(self, block_hash):
        for b in self.blocks:
            if b.hash() == block_hash:
                return b
        return None

    def assign_account_ids(self):
        for b in self.blocks:
            if (isinstance(b, block_state) or isinstance(b, block_open)):
                continue
            elif b.ancillary["account"] is not None:
                continue
            b.ancillary["account"] = self.find_account_id(b)

    def find_account_id(self, block):
        prev = binascii.hexlify(block.previous).decode("utf-8").upper()
        prev_block = self.find_block_by_hash(prev)
        if not (isinstance(prev_block, block_open) or isinstance(prev_block, block_state)):
            return self.find_account_id(prev_block)
        return prev_block.account

    def validate_blocks(self, queue):
        for i in range(0, len(queue)):
            block = queue.pop(0)
            if valid_block(block):
                self.blocks.append(block)

    def make_accounts(self):
        self.get_all_accounts()
        for a in self.accounts_raw:
            current_blocks = []
            for b in self.blocks:
                if isinstance(b, block_open) or isinstance(b, block_state):
                    account = b.account
                else:
                    account = b.ancillary["account"]
                if a == account:
                    current_blocks.append(b)
            self.accounts.append(nano_account(current_blocks, self.find_first_block(current_blocks),
                                              self.find_last_block(current_blocks)))

    def get_all_accounts(self):
        for b in self.blocks:
            if isinstance(b, block_open) or isinstance(b, block_state):
                account = b.account
            else:
                account = b.ancillary["account"]
            if account not in self.accounts_raw:
                self.accounts_raw.append(account)

    def find_first_block(self, blocks):
        index = 0
        block = None
        while index is not None:
            block = blocks[index]
            index = self.find_prev(block, blocks)
        return block

    def assign_blocks_next(self):
        for b in self.blocks:
            i = self.find_prev(b, self.blocks)
            #TODO: Remember to review this section, not sure if this works properly!
            if i is None:
                continue
            if self.blocks[i].ancillary["next"] is None:
                self.blocks[i].ancillary["next"] = binascii.unhexlify(b.hash())

    def find_next(self, block, blocks):
        if block.ancillary["next"] is None:
            return -1
        next = binascii.hexlify(block.ancillary["next"]).decode("utf-8").upper()
        for b in blocks:
            if b.hash() == next:
                return blocks.index(b)
        return -1

    def find_last_block(self, blocks):
        index = 0
        while index != -1:
            block = blocks[index]
            index = self.find_next(block, blocks)

        return block

    def __str__(self):
        string = "------------------- container ---------------------\n"
        for i in range(0, len(self.blocks)):
            string += str(self.blocks[i])
        string += "---------------------------------------------------"
        return string


class nano_account:
    def __init__(self, blocks, first, last):
        self.blocks = blocks
        self.first = first
        self.last = last
        self.no_of_blocks = len(blocks)

    def get_balance(self, block):
        if isinstance(block, block_send):
            return block.balance

    def is_subset(self, account):
        for b in self.blocks:
            if b not in account.blocks:
                return False
        return True

    def find_prev(self, block):
        if isinstance(block, block_open):
            prev = binascii.hexlify(block.source).decode("utf-8").upper()
        else:
            prev = binascii.hexlify(block.previous).decode("utf-8").upper()
        for b in self.blocks:
            if b.hash() == prev:
                return b
        return None

    def find_next(self, block):
        if block.ancillary["next"] is None:
            return None
        next = binascii.hexlify(block.ancillary["next"]).decode("utf-8").upper()
        for b in self.blocks:
            if b.hash() == next:
                return b
        raise InvalidBlockHash()

    def __str__(self):
        assert(len(self.blocks) >= 1)
        string = "------------- Nano Account Start -------------\n\n"
        for b in self.blocks[::-1]:
            string += str(b) + '\n'
        string += "------------- Nano Account End   -------------\n"
        return string

    # TODO: balance at any point
    # TODO: how many blocks
    # TODO: next / previous block
    # TODO: first block
    # TODO: last block

betactx = {
    'peeraddr': "peering-beta.nano.org",
    'peerport': 54000,
    'genesis_pub': '259A43ABDB779E97452E188BA3EB951B41C961D3318CA6B925380F4D99F0577A',
}

livectx = {
    'net_id': network_id(67),
    'peeraddr': "peering.nano.org",
    'peerport': 7075,
    'genesis_pub': 'E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA',
    'random_block': '6E5404423E7DDD30A0287312EC79DFF5B2841EADCD5082B9A035BCD5DB4301B6'
}


def read_socket(socket, bytes):
    data = b''
    while len(data) != bytes:
        data += socket.recv(1)
    return data


def read_block_send(s):
    data = read_socket(s, 152)
    block = block_send(data[:32], data[32:64], data[64:80], data[80:144], data[144:][::-1])
    return block


def read_block_receive(s):
    data = read_socket(s, 136)
    block = block_receive(data[:32], data[32:64], data[64:128], data[128:][::-1])
    return block


def read_block_open(s):
    data = read_socket(s, 168)
    block = block_open(data[:32], data[32:64], data[64:96], data[96:160], data[160:][::-1])
    return block


def read_block_change(s):
    data = read_socket(s, 136)
    block = block_change(data[:32], data[32:64], data[64:128], data[128:][::-1])
    return block


def read_block_state(s):
    data = read_socket(s, 216)
    block = block_state(data[:32], data[32:64], data[64:96], data[96:112], data[112:144], data[144:208],
                        data[208:])
    return block


def read_blocks_from_socket(s):
    blocks = []
    while True:
        block_type = s.recv(1)
        if len(block_type) == 0:
            print('socket closed by peer')
            break

        if block_type[0] == block_type_enum.send:
            block = read_block_send(s)
        elif block_type[0] == block_type_enum.receive:
            block = read_block_receive(s)
        elif block_type[0] == block_type_enum.open:
            block = read_block_open(s)
        elif block_type[0] == block_type_enum.change:
            block = read_block_change(s)
        elif block_type[0] == block_type_enum.state:
            block = read_block_state(s)
        elif block_type[0] == block_type_enum.invalid:
            print('received block type invalid')
            break
        elif block_type[0] == block_type_enum.not_a_block:
            print('received block type not a block')
            break
        else:
            print('received unknown block type %s' % block_type_enum[0])
            break

        blocks.append(block)
    return blocks


def pow_validate(work, prev):
    # It didn't want to create bytearrays with the raw bytes so I had to use the list()
    work = bytearray(list(work))
    prev = bytearray(list(prev))
    h = blake2b(digest_size=8)
    work.reverse()
    h.update(work)
    h.update(prev)
    final = bytearray(h.digest())
    final.reverse()
    return final > b'\xFF\xFF\xFF\xC0\x00\x00\x00\x00'


def verify(hash, signature, public_key=b'\xe8\x92\x08\xdd\x03\x8f\xbb&\x99\x87h\x96!\xd5"\x92\xae\x9c5\x94\x1at\x84un\xcc\xed\x92\xa6P\x93\xba'):
    try:
        ed25519_blake2.checkvalid(signature, hash, public_key)
    except ed25519_blake2.SignatureMismatch:
        return False
    return True


def verify_pow(block):
    if isinstance(block, block_open):
        return pow_validate(block.work, block.source)
    else:
        return pow_validate(block.work, block.previous)


def valid_block(block):
    work_valid = verify_pow(block)
    sig_valid = verify(binascii.unhexlify(block.hash()), block.signature)
    return work_valid and sig_valid


ctx = livectx
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
s.connect((peeraddr, ctx['peerport']))
print('Connected to %s:%s' % s.getpeername())
s.settimeout(2)

keepalive = message_keepmealive(ctx['net_id'])
req = keepalive.serialise()
s.send(req)
bulk_pull = message_bulk_pull(ctx['genesis_pub'], network_id(67))
req = bulk_pull.serialise()
s.send(req)

blocks = read_blocks_from_socket(s)

manager = blocks_manager(blocks)

print(manager.accounts[0].last)

# TODO: Remove all -1
# TODO: Make sure you can print every block from anywhere
# TODO: Store account public key not ID
# TODO: Give every class a __str__
# TODO: Not sure if it should be possible to traverse the block open, look into it!
# TODO: Bugs while setting the -1 to None fix them