#!/bin/env python3

from hashlib import blake2b
import binascii
from binascii import unhexlify
import base64
import json
import unittest

import ed25519_blake2b

import acctools
from net import *
from common import *
from exceptions import *


class block_type_enum:
    invalid = 0
    not_a_block = 1
    send = 2
    receive = 3
    open = 4
    change = 5
    state = 6


def block_length_by_type(blktype: int) -> int:
    lengths = {
        2: 152,
        3: 136,
        4: 168,
        5: 136,
        6: 216
    }
    return lengths[blktype]


class Block:

    @classmethod
    def parse_from_json_string(cls, json_str: str):
        json_obj = json.loads(json_str)
        type_str = json_obj['type']
        if type_str == 'send':
            return block_send.parse_from_json(json_obj)
        if type_str == 'receive':
            return block_receive.parse_from_json(json_obj)
        if type_str == 'open':
            return block_open.parse_from_json(json_obj)
        if type_str == 'change':
            return block_change.parse_from_json(json_obj)
        if type_str == 'state':
            return block_state.parse_from_json(json_obj)
        raise ParseErrorInvalidTypeInJson(json_str)

    @classmethod
    def read_block_from_socket(cls, s: socket.socket):
        block = None

        block_type = s.recv(1)
        if len(block_type) == 0:
            raise SocketClosedByPeer("Socket was closed by the peer whilst waiting for block type")

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
        elif block_type[0] == block_type_enum.not_a_block:
            pass
            # print('received block type not a block')

        else:
            print('received unknown block type %s' % int.from_bytes(block_type, 'big'))

        return block

class block_send:
    def __init__(self, prev: bytes, dest: bytes, bal: int, sig: bytes, work: int):
        assert(isinstance(bal, int))
        assert (isinstance(work, int))
        self.previous = prev
        self.destination = dest
        self.balance = bal
        self.signature = sig
        self.work = work
        self.ancillary = {
            "account": None,
            "next": None,
            "amount_sent": None,
            "peers" : set(),
        }

    def get_account(self) -> bytes:
        return self.ancillary["account"]

    def get_previous(self) -> bytes:
        return self.previous

    def get_next(self) -> bytes:
        return self.ancillary['next']

    def get_balance(self) -> int:
        return self.balance

    def root(self) -> bytes:
        return self.previous

    def get_type_int(self) -> int:
        return block_type_enum.send

    def get_amount_sent_str(self) -> str:
        if self.ancillary["amount_sent"] is not None:
            return str(self.ancillary["amount_sent"] / (10**30))
        else:
            return 'None'

    def get_account_str(self) -> str:
        hexacc = None
        acc_id = None
        if self.ancillary["account"] is not None:
            hexacc = hexlify(self.ancillary["account"])
            acc_id = acctools.to_account_addr(self.ancillary["account"])
        return hexacc, acc_id

    def hash(self) -> bytes:
        data = b"".join([
            self.previous,
            self.destination,
            self.balance.to_bytes(16, "big")
        ])
        return blake2b(data, digest_size=32).digest()

    def serialise(self, include_block_type: bool) -> bytes:
        data = b''
        if include_block_type:
            data += (2).to_bytes(1, "big")
        data += self.previous
        data += self.destination
        data += self.balance.to_bytes(16, "big")
        data += self.signature
        data += self.work.to_bytes(8, "little")
        return data

    @classmethod
    def parse_from_json(cls, json_obj: dict):
        assert(json_obj['type'] == 'send')
        prev = binascii.unhexlify(json_obj['previous'])
        dest = acctools.account_key(json_obj['destination'])
        bal = int(json_obj['balance'], 16)
        sig = binascii.unhexlify(json_obj['signature'])
        work = int.from_bytes(binascii.unhexlify(json_obj['work']), "big")
        return block_send(prev, dest, bal, sig, work)

    @classmethod
    def parse(cls, data: bytes):
        assert(len(data) == block_length_by_type(2))
        prev = data[0:32]
        dest = data[32:64]
        bal = int.from_bytes(data[64:80], "big")
        sig = data[80:144]
        work = int.from_bytes(data[144:], "little")
        return block_send(prev, dest, bal, sig, work)

    def __str__(self):
        string = "------------- Block Send -------------\n"
        string += "Hash : %s\n" % hexlify(self.hash())
        string += "Prev : %s\n" % hexlify(self.previous)
        string += "Dest : %s\n" % hexlify(self.destination)
        string += "       %s\n" % acctools.to_account_addr(self.destination)
        string += "Bal  : %f\n" % (self.balance / (10**30))
        string += "Sign : %s\n" % hexlify(self.signature)
        string += "Work : %s\n" % hexlify(self.work.to_bytes(8, "big"))
        string += "Acc  : %s\n      %s\n" % (self.get_account_str())
        string += "Next : %s\n" % hexlify(self.ancillary["next"])
        string += "Sent : %s\n" % self.get_amount_sent_str()
        string += "Peers: %s" % self.ancillary['peers']
        return string

    def __hash__(self):
        return hash((self.previous, self.destination,
                     self.balance.to_bytes(16, "big"), self.signature,
                     self.work.to_bytes(8, "little")))

    def __eq__(self, other):
        if not isinstance(other, block_send):
            return False
        elif self.previous != other.previous:
            assert (self.hash() != other.hash())
            return False
        elif self.destination != other.destination:
            assert (self.hash() != other.hash())
            return False
        elif self.balance != other.balance:
            assert (self.hash() != other.hash())
            return False
        elif self.signature != other.signature:
            assert (self.hash() != other.hash())
            return False
        elif self.work != other.work:
            assert (self.hash() != other.hash())
            return False
        elif self.ancillary != other.ancillary:
            assert (self.hash() != other.hash())
            return False
        return True


class block_receive:
    def __init__(self, prev: bytes, source: bytes, sig: bytes, work: int):
        assert (isinstance(work, int))
        self.previous = prev
        self.source = source
        self.signature = sig
        self.work = work
        self.ancillary = {
            "account": None,
            "next": None,
            "balance": None,
            "peers" : set(),
        }

    def get_account(self) -> bytes:
        return self.ancillary["account"]

    def get_previous(self) -> bytes:
        return self.previous

    def get_next(self) -> bytes:
        return self.ancillary['next']

    def get_balance(self) -> int:
        return self.ancillary["balance"]

    def root(self) -> bytes:
        return self.previous

    def get_type_int(self) -> int:
        return block_type_enum.receive

# TODO: Remember to reverse the order of the work if you implement serialisation!
    def hash(self) -> bytes:
        data = b"".join([
            self.previous,
            self.source
        ])
        return blake2b(data, digest_size=32).digest()

    def str_ancillary_data(self) -> str:
        if self.ancillary["account"] is not None:
            hexacc = hexlify(self.ancillary["account"])
            account = acctools.to_account_addr(self.ancillary["account"])
        else:
            hexacc = None
            account = self.ancillary["account"]
        if self.ancillary["next"] is not None:
            next = hexlify(self.ancillary["next"])
        else:
            next = self.ancillary["next"]
        if self.ancillary["balance"] is not None:
            balance = self.ancillary["balance"] / (10 ** 30)
        else:
            balance = -1
        string = ""
        string += "Acc  : %s\n" % hexacc
        string += "       %s\n" % account
        string += "Next : %s\n" % next
        string += "Bal  : %f\n" % balance
        return string

    def serialise(self, include_block_type: bool) -> bytes:
        data = b''
        if include_block_type:
            data += (3).to_bytes(1, "big")
        data += self.previous
        data += self.source
        data += self.signature
        data += self.work.to_bytes(8, "little")
        return data

    @classmethod
    def parse_from_json(cls, json_obj: dict):
        assert(json_obj['type'] == 'receive')
        prev = binascii.unhexlify(json_obj['previous'])
        source = binascii.unhexlify(json_obj['source'])
        sig = binascii.unhexlify(json_obj['signature'])
        work = int.from_bytes(binascii.unhexlify(json_obj['work']), "big")
        return block_receive(prev, source, sig, work)

    @classmethod
    def parse(cls, data: bytes):
        assert(len(data) == block_length_by_type(3))
        prev = data[0:32]
        source = data[32:64]
        sig = data[64:128]
        work = int.from_bytes(data[128:], "little")
        return block_receive(prev, source, sig, work)

    def __str__(self):
        string = "------------- Block Receive -------------\n"
        string += "Hash : %s\n" % hexlify(self.hash())
        string += "Prev : %s\n" % hexlify(self.previous)
        string += "Src  : %s\n" % hexlify(self.source)
        string += "Sign : %s\n" % hexlify(self.signature)
        string += "Work : %s\n" % hexlify(self.work.to_bytes(8, "big"))
        string += self.str_ancillary_data()
        string += "Peers: %s" % self.ancillary['peers']
        return string

    def __hash__(self):
        return hash((self.previous, self.source))

    def __eq__(self, other):
        if not isinstance(other, block_receive):
            return False
        elif self.previous != other.previous:
            assert (self.hash() != other.hash())
            return False
        elif self.source != other.source:
            assert (self.hash() != other.hash())
            return False
        elif self.signature != other.signature:
            assert (self.hash() != other.hash())
            return False
        elif self.work != other.work:
            assert (self.hash() != other.hash())
            return False
        elif self.ancillary != other.ancillary:
            assert (self.hash() != other.hash())
            return False
        return True


class block_open:
    def __init__(self, source: bytes, rep: bytes, account: bytes, sig: bytes, work: int):
        assert (isinstance(work, int))
        self.source = source
        self.representative = rep
        self.account = account
        self.signature = sig
        self.work = work
        self.ancillary = {
            "previous": None,
            "next": None,
            "balance": None,
            "peers" : set(),
        }

    def get_previous(self) -> bytes:
        if self.source == self.account:
            # genesis block
            assert self.source == self.representative
            # assert self.source == livectx['genesis_pub'] or self.source == betactx['genesis_pub']
            return None
        else:
            # it is a regular open block and it has a source
            return self.source

    def get_next(self) -> bytes:
        return self.ancillary['next']

    def get_account(self) -> bytes:
        return self.account

    def get_balance(self) -> bytes:
        return self.ancillary["balance"]

    def root(self) -> bytes:
        return self.account

    def get_type_int(self) -> int:
        return block_type_enum.open

    def hash(self) -> bytes:
        data = b"".join([
            self.source,
            self.representative,
            self.account
        ])
        return blake2b(data, digest_size=32).digest()

    def str_ancillary_data(self) -> str:
        if self.ancillary["previous"] is not None:
            previous = hexlify(self.ancillary["previous"])
        else:
            previous = self.ancillary["previous"]
        if self.ancillary["next"] is not None:
            next = hexlify(self.ancillary["next"])
        else:
            next = self.ancillary["next"]
        if self.ancillary["balance"] is not None:
            balance = self.ancillary["balance"] / (10 ** 30)
        else:
            balance = -1
        string  = "Prev : %s\n" % previous
        string += "Next : %s\n" % next
        string += "Bal  : %f\n" % balance
        return string

    def serialise(self, include_block_type: bool) -> bytes:
        data = b''
        if include_block_type:
            data += (4).to_bytes(1, "big")
        data += self.source
        data += self.representative
        data += self.account
        data += self.signature
        data += self.work.to_bytes(8, "little")
        return data

    @classmethod
    def parse_from_json(cls, json_obj: dict):
        assert(json_obj['type'] == 'open')
        source = binascii.unhexlify(json_obj['source'])
        rep = acctools.account_key(json_obj['representative'])
        acc = acctools.account_key(json_obj['account'])
        sig = binascii.unhexlify(json_obj['signature'])
        work = int.from_bytes(binascii.unhexlify(json_obj['work']), "big")
        return block_open(source, rep, acc, sig, work)


    @classmethod
    def parse(cls, data: bytes):
        assert(len(data) == block_length_by_type(4))
        source = data[0:32]
        rep = data[32:64]
        acc = data[64:96]
        sig = data[96:160]
        work = int.from_bytes(data[160:], "little")
        return block_open(source, rep, acc, sig, work)

    def __str__(self):
        hexacc = hexlify(self.account)
        string = "------------- Block Open -------------\n"
        string += "Hash : %s\n" % hexlify(self.hash())
        string += "Src  : %s\n" % hexlify(self.source)
        string += "Repr : %s\n" % hexlify(self.representative)
        string += "Acc  : %s\n" % hexacc
        string += "       %s\n" % acctools.to_account_addr(self.account)
        string += "Sign : %s\n" % hexlify(self.signature)
        string += "Work : %s\n" % hexlify(self.work.to_bytes(8, "big"))
        string += self.str_ancillary_data()
        string += "Peers: %s" % self.ancillary['peers']
        return string

    def __eq__(self, other):
        if not isinstance(other, block_open):
            return False
        elif self.source != other.source:
            assert (self.hash() != other.hash())
            return False
        elif self.representative != other.representative:
            assert (self.hash() != other.hash())
            return False
        elif self.account != other.account:
            assert (self.hash() != other.hash())
            return False
        elif self.signature != other.signature:
            assert (self.hash() != other.hash())
            return False
        elif self.work != other.work:
            assert (self.hash() != other.hash())
            return False

        return True

    def __hash__(self):
        return hash((self.source, self.representative, self.account))


class block_change:
    def __init__(self, prev: bytes, rep: bytes, sig: bytes, work: int):
        assert (isinstance(work, int))
        self.previous = prev
        self.representative = rep
        self.signature = sig
        self.work = work
        self.ancillary = {
            "account": None,
            "next": None,
            "balance": None,
            "peers" : set(),
        }

    def get_account(self) -> bytes:
        return self.ancillary["account"]

    def get_previous(self) -> bytes:
        return self.previous

    def get_next(self) -> bytes:
        return self.ancillary['next']

    def get_balance(self) -> int:
        return self.ancillary["balance"]

    def root(self) -> bytes:
        return self.previous

    def get_type_int(self) -> int:
        return block_type_enum.change

    def hash(self) -> bytes:
        data = b"".join([
            self.previous,
            self.representative
        ])
        return blake2b(data, digest_size=32).digest()

    def str_ancillary_data(self) -> str:
        if self.ancillary["account"] is not None:
            hexacc = hexlify(self.ancillary["account"])
            account = acctools.to_account_addr(self.ancillary["account"])
        else:
            hexacc = None
            account = self.ancillary["account"]
        if self.ancillary["next"] is not None:
            next = hexlify(self.ancillary["next"])
        else:
            next = self.ancillary["next"]
        if self.ancillary["balance"] is not None:
            balance = self.ancillary["balance"] / (10 ** 30)
        else:
            balance = -1
        string = ""
        string += "Acc  : %s\n" % hexacc
        string += "       %s\n" % account
        string += "Next : %s\n" % next
        string += "Bal  : %f" % balance
        return string

    def serialise(self, include_block_type: bool) -> bytes:
        data = b''
        if include_block_type:
            data += (5).to_bytes(1, "big")
        data += self.previous
        data += self.representative
        data += self.signature
        data += self.work.to_bytes(8, "little")
        return data

    @classmethod
    def parse_from_json(cls, json_obj: dict):
        assert(json_obj['type'] == 'change')
        prev = binascii.unhexlify(json_obj['previous'])
        rep = acctools.account_key(json_obj['representative'])
        sig = binascii.unhexlify(json_obj['signature'])
        work = int.from_bytes(binascii.unhexlify(json_obj['work']), "big")
        return block_change(prev, rep, sig, work)

    @classmethod
    def parse(cls, data: bytes):
        assert(len(data) == block_length_by_type(5))
        prev = data[0:32]
        rep = data[32:64]
        sig = data[64:128]
        work = int.from_bytes(data[128:], "little")
        return block_change(prev, rep, sig, work)

    def __str__(self):
        string = "------------- Block Change -------------\n"
        string += "Hash : %s\n" % hexlify(self.hash())
        string += "Prev : %s\n" % hexlify(self.previous)
        string += "Repr : %s\n" % hexlify(self.representative)
        string += "Sign : %s\n" % hexlify(self.signature)
        string += "Work : %s\n" % hexlify(self.work.to_bytes(8, "big"))
        string += self.str_ancillary_data()
        string += "Peers: %s" % self.ancillary['peers']
        return string

    def __hash__(self):
        return hash((self.previous, self.representative))

    def __eq__(self, other):
        if not isinstance(other, block_change):
            return False
        elif self.previous != other.previous:
            assert (self.hash() != other.hash())
            return False
        elif self.representative != other.representative:
            assert (self.hash() != other.hash())
            return False
        elif self.signature != other.signature:
            assert (self.hash() != other.hash())
            return False
        elif self.work != other.work:
            assert (self.hash() != other.hash())
            return False
        elif self.ancillary != other.ancillary:
            assert (self.hash() != other.hash())
            return False
        return True


class block_state:
    def __init__(self, account: bytes, prev: bytes, rep: bytes, bal: int, link: bytes, sig: bytes, work: int):
        assert(isinstance(work, int))
        self.account = account
        self.previous = prev
        self.representative = rep
        self.balance = bal
        self.link = link
        self.signature = sig
        self.work = work
        self.ancillary = {
            "next": None,
            "peers" : set(),
            "type": block_type_enum.not_a_block
        }

    def get_previous(self) -> bytes:
        return self.previous

    def get_next(self) -> bytes:
        return self.ancillary['next']

    def get_account(self) -> bytes:
        return self.account

    def get_balance(self) -> int:
        return self.balance

    def get_type_int(self) -> int:
        return block_type_enum.state

    def root(self) -> bytes:
        if int.from_bytes(self.previous, "big") == 0:
            return self.account
        else:
            return self.previous

    def set_type(self, block_type: int) -> None:
        assert block_type in range(block_type_enum.invalid, block_type_enum.state + 1)
        self.ancillary["type"] = block_type

    def hash(self) -> bytes:
        STATE_BLOCK_HEADER_BYTES = (b'\x00' * 31) + b'\x06'
        data = b"".join([
            STATE_BLOCK_HEADER_BYTES,
            self.account,
            self.previous,
            self.representative,
            self.balance.to_bytes(16, "big"),
            self.link

        ])
        return blake2b(data, digest_size=32).digest()

    def serialise(self, include_block_type: bool) -> bytes:
        data = b''
        if include_block_type:
            data += (6).to_bytes(1, "big")
        data += self.account
        data += self.previous
        data += self.representative
        data += self.balance.to_bytes(16, "big")
        data += self.link
        data += self.signature

        # Block states proof of work is received and sent in big endian
        data += self.work.to_bytes(8, "big")
        return data

    def is_epoch_v2_block(self) -> bool:
        if self.link[0:14] == b'epoch v2 block':
            return True
        return False

    def is_epoch_v1_block(self) -> bool:
        if self.link[0:14] == b'epoch v1 block':
            return True
        return False

    def sign(self, signing_key: ed25519_blake2b.keys.SigningKey) -> None:
        self.signature = signing_key.sign(self.hash())

    def generate_work(self, min_difficulty: int) -> None:
        root_int = int.from_bytes(self.root(), byteorder='big')
        self.work = pow.find_pow_for_root_and_difficulty(root_int, min_difficulty)

    @classmethod
    def parse(cls, data: bytes):
        assert(len(data) == block_length_by_type(6))
        account = data[0:32]
        prev = data[32:64]
        rep = data[64:96]
        bal = int.from_bytes(data[96:112], "big")
        link = data[112:144]
        sig = data[144:208]
        # Block states proof of work is received and sent in big endian
        work = int.from_bytes(data[208:], "big")
        return block_state(account, prev, rep, bal, link, sig, work)

    @classmethod
    def parse_from_json(cls, json_obj: dict):
        assert(json_obj['type'] == 'state')
        account = acctools.account_key(json_obj['account'])
        prev = binascii.unhexlify(json_obj['previous'])
        rep = acctools.account_key(json_obj['representative'])
        bal = int(json_obj['balance'])
        if len(json_obj['link']) == 64:
            link = binascii.unhexlify(json_obj['link'])
        else:
            link = acctools.account_key(json_obj['link'])
        sig = binascii.unhexlify(json_obj['signature'])
        work = int.from_bytes(binascii.unhexlify(json_obj['work']), "big")
        return block_state(account, prev, rep, bal, link, sig, work)

    def to_json(self) -> str:
        jsonblk = {
            'type'            : 'state',
            'account'         : acctools.to_account_addr(self.account),
            'previous'        : hexlify(self.previous),
            'representative'  : acctools.to_account_addr(self.representative),
            'balance'         : str(self.balance),
            'link'            : hexlify(self.link),
            'link_as_account' : acctools.to_account_addr(self.link),
            'signature'       : hexlify(self.signature),
            'work'            : hexlify(self.work.to_bytes(8, "big"))
        }
        return json.dumps(jsonblk, indent=4)

    def link_to_string(self) -> str:
        if self.link.startswith(b'epoch'):
            return self.link.decode('ascii').replace('\x00', '')
        else:
            return hexlify(self.link)

    def __str__(self):
        hexacc = binascii.hexlify(self.account).decode("utf-8").upper()
        string = "------------- Block State -------------\n"
        string += "Hash : %s\n" % hexlify(self.hash())
        string += "Acc  : %s\n" % hexacc
        string += "       %s\n" % acctools.to_account_addr(self.account)
        string += "Prev : %s\n" % hexlify(self.previous)
        string += "Repr : %s\n" % hexlify(self.representative)
        string += "       %s\n" % acctools.to_account_addr(self.representative)
        string += "Bal  : %s\n" % (self.balance / (10**30))
        string += "Link : %s\n" % self.link_to_string()
        string += "Sign : %s\n" % hexlify(self.signature)
        string += "Work : %s\n" % hexlify(self.work.to_bytes(8, "big"))
        string += "Next : %s\n" % hexlify(self.ancillary["next"])
        string += "Peers: %s" % self.ancillary['peers']
        return string

    def __hash__(self):
        return hash((self.account, self.previous, self.representative,
                     self.balance, self.link))

    def __eq__(self, other):
        if not isinstance(other, block_state):
            return False
        elif self.account != other.account:
            assert (self.hash() != other.hash())
            return False
        elif self.previous != other.previous:
            assert (self.hash() != other.hash())
            return False
        elif self.representative != other.representative:
            assert (self.hash() != other.hash())
            return False
        elif self.balance != other.balance:
            assert (self.hash() != other.hash())
            return False
        elif self.link != other.link:
            assert (self.hash() != other.hash())
            return False
        elif self.signature != other.signature:
            assert (self.hash() != other.hash())
            return False
        elif self.work != other.work:
            assert (self.hash() != other.hash())
            return False
        elif self.ancillary != other.ancillary:
            assert (self.hash() != other.hash())
            return False

        return True


def read_block_send(s: socket.socket):
    data = read_socket(s, 152)
    block = block_send.parse(data)
    return block


def read_block_receive(s: socket.socket):
    data = read_socket(s, 136)
    block = block_receive.parse(data)
    return block


def read_block_open(s: socket.socket):
    data = read_socket(s, 168)
    block = block_open.parse(data)
    return block


def read_block_change(s: socket.socket):
    data = read_socket(s, 136)
    block = block_change.parse(data)
    return block


def read_block_state(s: socket.socket):
    data = read_socket(s, 216)
    block = block_state.parse(data)
    return block


class TestBlock(unittest.TestCase):
    def setUp(self):
        pass

    def test_parse_block_state_from_json_string(self):
        json_str = '''{
            "type": "state",
            "account": "nano_31fr1qtbrfnujcspx5xq61uxgjf9j6rzckdj1kdn61y3h53nxr7911dzetk3",
            "previous": "C2BC9E7EA387E73E9EF7AF805386B3188EC71567BA3F58031E8CA04BF0B56317",
            "representative": "nano_3testing333before333adoption333333333333333333333333y71t3kt9",
            "balance": "999999999999998367700000",
            "link": "DD573D46AD23730FF0557F59247C92CEE695D5DA347D2AA592DC08716B580DA8",
            "link_as_account": "nano_3qcq9o5ctaum3zr7czts6jyb7mq8kqcxnf5x7cks7q1ag7ooi5farai51dpi",
            "signature": "073C1A87469F79A55A94EC94F587D463DB617BB235EC00796EEACCFAD6C19E4D7524B0D236E46A2766E68FD813E29F0CB1B76656B94A3ED646CE2AE30F904905",
            "work": "27f60f8a95403ae1"
        }'''
        block = Block.parse_from_json_string(json_str)
        assert block.account == unhexlify('81B805F49C369B8AB36E8FB72037D745A78931F5497104974203C178C34EE0A7')
        assert block.previous == unhexlify('C2BC9E7EA387E73E9EF7AF805386B3188EC71567BA3F58031E8CA04BF0B56317')
        assert block.representative == unhexlify('E999D428E08429636B86042142EB6D42B4084210842108421084210842108421')
        assert block.balance == 999999999999998367700000
        assert block.link == unhexlify('DD573D46AD23730FF0557F59247C92CEE695D5DA347D2AA592DC08716B580DA8')
        assert block.signature == unhexlify('073C1A87469F79A55A94EC94F587D463DB617BB235EC00796EEACCFAD6C19E4D7524B0D236E46A2766E68FD813E29F0CB1B76656B94A3ED646CE2AE30F904905')
        assert block.work == int.from_bytes(unhexlify('27f60f8a95403ae1'), "big")

    def test_parse_block_open_from_json_string(self):
        json_str = '''{
            "type": "open",
            "source": "BAB41488D29BC00DBA3A00988CC6B9F57AE416F2C9EE140AC703EBE26403CE3F",
            "representative": "nano_16k5pimotz9zehjk795wa4qcx54mtusk8hc5mdsjgy57gnhbj3hj6zaib4ic",
            "account": "nano_191hygw18kqyg5hpbgb3r8i5gt9gfbcjf5pp73rt9ry9ugtm96jihpkkq1pd",
            "work": "42d4cb97af728160",
            "signature": "13BFC64C86388B9494CDDCCAF6727A0399C1B73EDD22509F01D3BBD2800C23F346BA71B050F5F28B52B43077663F23E48EAE883E82038686BFC3FBA72C77E00E"
        }'''
        block = Block.parse_from_json_string(json_str)
        assert block.account == unhexlify('1c0ff3b8034afe70df64b921c1a03768ee6a55168ed62871a3e3c7dbb5339230')
        assert block.source == unhexlify('BAB41488D29BC00DBA3A00988CC6B9F57AE416F2C9EE140AC703EBE26403CE3F')
        assert block.representative == unhexlify('1243b4275d7cff63e3229c7c40aeae8c53d6f3233d439af3177865751e9885f1')
        assert block.signature == unhexlify('13BFC64C86388B9494CDDCCAF6727A0399C1B73EDD22509F01D3BBD2800C23F346BA71B050F5F28B52B43077663F23E48EAE883E82038686BFC3FBA72C77E00E')
        assert block.work == int.from_bytes(unhexlify('42d4cb97af728160'), "big")

    def test_parse_block_send_from_json_string(self):
        json_str = '''{
            "type": "send",
            "previous": "887F40C7A6C089C5CE02A6074C37C602D7CBA1DFB0E972BCC88DA6DA82E62B22",
            "destination": "nano_31a51k53fdzam7bhrgi4b67py9o7wp33rec1hi7k6z1wsgh8oagqs7bui9p1",
            "balance": "00000000033B2E3C9FD0803CE7FFFFFD",
            "work": "5c4ec550bde046ad",
            "signature": "9C8380DF84EFA599E4BBD989862C20EEA40B2E7DE5327C41A38B7869EAB598FB5786658F45176FC1973E7D0DE40AEF10FB6961D54D0DD7CDBE9A6122266C1907"
        }'''
        block = Block.parse_from_json_string(json_str)
        assert block.previous == unhexlify('887F40C7A6C089C5CE02A6074C37C602D7CBA1DFB0E972BCC88DA6DA82E62B22')
        assert block.destination == unhexlify('8103048616afe89952fc3a02490b6f1ea5e5821c31407c0b227c1ccb9e6aa1d7')
        assert block.balance == 0x33B2E3C9FD0803CE7FFFFFD
        assert block.signature == unhexlify('9C8380DF84EFA599E4BBD989862C20EEA40B2E7DE5327C41A38B7869EAB598FB5786658F45176FC1973E7D0DE40AEF10FB6961D54D0DD7CDBE9A6122266C1907')
        assert block.work == int.from_bytes(unhexlify('5c4ec550bde046ad'), "big")

    def test_parse_block_receive_from_json_string(self):
        json_str = '''{
            "type": "receive",
            "previous": "B758785AD694E5EF4F379FB07EB12F709970D7082F5860340FC9D925C7BA490F",
            "source": "EA58282857C97856AE0A05396C0AA4708520304546A032E57C79D3A5B4BD0B47",
            "work": "8994d174f087691b",
            "signature": "A0D84921B7843C2C74103B5637EB7D3AB669F6143183626413CDD9F219B66C1542401B89E34F2F5A68FD6C1ADEA753F8FCF76071711C8B1944F7ECBBCE2B0501"
        }'''
        block = Block.parse_from_json_string(json_str)
        assert block.previous == unhexlify('B758785AD694E5EF4F379FB07EB12F709970D7082F5860340FC9D925C7BA490F')
        assert block.source == unhexlify('EA58282857C97856AE0A05396C0AA4708520304546A032E57C79D3A5B4BD0B47')
        assert block.signature == unhexlify('A0D84921B7843C2C74103B5637EB7D3AB669F6143183626413CDD9F219B66C1542401B89E34F2F5A68FD6C1ADEA753F8FCF76071711C8B1944F7ECBBCE2B0501')
        assert block.work == int.from_bytes(unhexlify('8994d174f087691b'), "big")
        assert block.hash() == unhexlify('00000197D6E981AB3EC5469BFBFFDF20F43CC6E955C0A38F295501AD64B86B0D')

    def test_parse_block_change_from_json_string(self):
        json_str = '''{
            "type": "change",
            "previous": "E0FCC51E9DCED5631E52CEA35FF47B88FC4A741C43B9B739030E1C594F06F17C",
            "representative": "nano_16k5pimotz9zehjk795wa4qcx54mtusk8hc5mdsjgy57gnhbj3hj6zaib4ic",
            "work": "c751c45e591dd7a7",
            "signature": "60A88EAECB32EDC1B5120F1B0A4C4342B661761C379404FF24D6F43998D080E0214BCBC60434A1A7DC353FF44D16D9942912123F9FA7EC99FE1467E8F854ED0D"
        }'''
        block = Block.parse_from_json_string(json_str)
        assert block.previous == unhexlify('E0FCC51E9DCED5631E52CEA35FF47B88FC4A741C43B9B739030E1C594F06F17C')
        assert block.representative == unhexlify('1243b4275d7cff63e3229c7c40aeae8c53d6f3233d439af3177865751e9885f1')
        assert block.signature == unhexlify('60A88EAECB32EDC1B5120F1B0A4C4342B661761C379404FF24D6F43998D080E0214BCBC60434A1A7DC353FF44D16D9942912123F9FA7EC99FE1467E8F854ED0D')
        assert block.work == int.from_bytes(unhexlify('c751c45e591dd7a7'), "big")
        assert block.hash() == unhexlify('000255E568174DBBEAFF997BF31E0344F4EEA52FC22197825C5574E13296CA00')


if __name__ == '__main__':
    unittest.main()
