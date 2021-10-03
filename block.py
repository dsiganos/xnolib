from hashlib import blake2b
import binascii
import base64

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


def block_length_by_type(blktype):
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
    def parse_from_json_string(cls, json_string):
        pass

    @classmethod
    def read_block_from_socket(cls, s):
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
    def __init__(self, prev, dest, bal, sig, work):
        assert(isinstance(bal, int))
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

    def get_account(self):
        return self.ancillary["account"]

    def get_previous(self):
        return self.previous

    def get_next(self):
        return self.ancillary['next']

    def get_balance(self):
        return self.balance

    def root(self):
        return self.previous

    def get_type_int(self):
        return block_type_enum.send

    def get_amount_sent_str(self):
        if self.ancillary["amount_sent"] is not None:
            return str(self.ancillary["amount_sent"] / (10**30))
        else:
            return 'None'

    def get_account_str(self):
        hexacc = None
        acc_id = None
        if self.ancillary["account"] is not None:
            hexacc = hexlify(self.ancillary["account"])
            acc_id = acctools.to_account_addr(self.ancillary["account"])
        return hexacc, acc_id

    def hash(self):
        data = b"".join([
            self.previous,
            self.destination,
            self.balance.to_bytes(16, "big")
        ])
        return blake2b(data, digest_size=32).digest()

    def serialise(self, include_block_type):
        data = b''
        if include_block_type:
            data += (2).to_bytes(1, "big")
        data += self.previous
        data += self.destination
        data += self.balance.to_bytes(16, "big")
        data += self.signature
        data += self.work[::-1]
        return data

    @classmethod
    def parse(cls, data):
        assert(len(data) == block_length_by_type(2))
        prev = data[0:32]
        dest = data[32:64]
        bal = int.from_bytes(data[64:80], "big")
        sig = data[80:144]
        work = data[144:][::-1]
        return block_send(prev, dest, bal, sig, work)

    def __str__(self):
        string = "------------- Block Send -------------\n"
        string += "Hash : %s\n" % hexlify(self.hash())
        string += "Prev : %s\n" % hexlify(self.previous)
        string += "Dest : %s\n" % hexlify(self.destination)
        string += "       %s\n" % acctools.to_account_addr(self.destination)
        string += "Bal  : %f\n" % (self.balance / (10**30))
        string += "Sign : %s\n" % hexlify(self.signature)
        string += "Work : %s\n" % hexlify(self.work)
        string += "Acc  : %s\n      %s\n" % (self.get_account_str())
        string += "Next : %s\n" % hexlify(self.ancillary["next"])
        string += "Sent : %s\n" % self.get_amount_sent_str()
        string += "Peers: %s" % self.ancillary['peers']
        return string

    def __hash__(self):
        return hash((self.previous, self.destination,
                     self.balance.to_bytes(16, "big"), self.signature,
                     self.work))

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
    def __init__(self, prev, source, sig, work):
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

    def get_account(self):
        return self.ancillary["account"]

    def get_previous(self):
        return self.previous

    def get_next(self):
        return self.ancillary['next']

    def get_balance(self):
        return self.ancillary["balance"]

    def root(self):
        return self.previous

    def get_type_int(self):
        return block_type_enum.receive

# TODO: Remember to reverse the order of the work if you implement serialisation!
    def hash(self):
        data = b"".join([
            self.previous,
            self.source
        ])
        return blake2b(data, digest_size=32).digest()

    def str_ancillary_data(self):
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

    def serialise(self, include_block_type):
        data = b''
        if include_block_type:
            data += (3).to_bytes(1, "big")
        data += self.previous
        data += self.source
        data += self.signature
        data += self.work[::-1]
        return data

    @classmethod
    def parse(cls, data):
        assert(len(data) == block_length_by_type(3))
        prev = data[0:32]
        source = data[32:64]
        sig = data[64:128]
        work = data[128:][::-1]
        return block_receive(prev, source, sig, work)

    def __str__(self):
        string = "------------- Block Receive -------------\n"
        string += "Hash : %s\n" % hexlify(self.hash())
        string += "Prev : %s\n" % hexlify(self.previous)
        string += "Src  : %s\n" % hexlify(self.source)
        string += "Sign : %s\n" % hexlify(self.signature)
        string += "Work : %s\n" % hexlify(self.work)
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
    def __init__(self, source, rep, account, sig, work):
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

    def get_previous(self):
        if self.source == self.account:
            # genesis block
            assert self.source == self.representative
            assert self.source == livectx['genesis_pub'] or self.source == betactx['genesis_pub']
            return None
        else:
            # it is a regular open block and it has a source
            return self.source

    def get_next(self):
        return self.ancillary['next']

    def get_account(self):
        return self.account

    def get_balance(self):
        return self.ancillary["balance"]

    def root(self):
        return self.account

    def get_type_int(self):
        return block_type_enum.open

    def hash(self):
        data = b"".join([
            self.source,
            self.representative,
            self.account
        ])
        return blake2b(data, digest_size=32).digest()

    def str_ancillary_data(self):
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

    def serialise(self, include_block_type):
        data = b''
        if include_block_type:
            data += (4).to_bytes(1, "big")
        data += self.source
        data += self.representative
        data += self.account
        data += self.signature
        data += self.work[::-1]
        return data

    @classmethod
    def parse(cls, data):
        assert(len(data) == block_length_by_type(4))
        source = data[0:32]
        rep = data[32:64]
        acc = data[64:96]
        sig = data[96:160]
        work = data[160:][::-1]
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
        string += "Work : %s\n" % hexlify(self.work)
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
    def __init__(self, prev, rep, sig, work):
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

    def get_account(self):
        return self.ancillary["account"]

    def get_previous(self):
        return self.previous

    def get_next(self):
        return self.ancillary['next']

    def get_balance(self):
        return self.ancillary["balance"]

    def root(self):
        return self.previous

    def get_type_int(self):
        return block_type_enum.change

    def hash(self):
        data = b"".join([
            self.previous,
            self.representative
        ])
        return blake2b(data, digest_size=32).digest()

    def str_ancillary_data(self):
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

    def serialise(self, include_block_type):
        data = b''
        if include_block_type:
            data += (5).to_bytes(1, "big")
        data += self.previous
        data += self.representative
        data += self.signature
        data += self.work[::-1]
        return data

    @classmethod
    def parse(cls, data):
        assert(len(data) == block_length_by_type(5))
        prev = data[0:32]
        rep = data[32:64]
        sig = data[64:128]
        work = data[128:][::-1]
        return block_change(prev, rep, sig, work)

    def __str__(self):
        string = "------------- Block Change -------------\n"
        string += "Hash : %s\n" % hexlify(self.hash())
        string += "Prev : %s\n" % hexlify(self.previous)
        string += "Repr : %s\n" % hexlify(self.representative)
        string += "Sign : %s\n" % hexlify(self.signature)
        string += "Work : %s\n" % hexlify(self.work)
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
    def __init__(self, account, prev, rep, bal, link, sig, work):
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
        }

    def get_previous(self):
        return self.previous

    def get_next(self):
        return self.ancillary['next']

    def get_account(self):
        return self.account

    def get_balance(self):
        return self.balance

    def get_type_int(self):
        return block_type_enum.state

    def root(self):
        if int.from_bytes(self.previous, "big") == 0:
            return self.account
        else:
            return self.previous

    def hash(self):
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

    def serialise(self, include_block_type):
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
        data += self.work
        return data

    def is_epoch_v2_block(self):
        if self.link[0:14] == b'epoch v2 block':
            return True
        return False

    def is_epoch_v1_block(self):
        if self.link[0:14] == b'epoch v1 block':
            return True
        return False

    @classmethod
    def parse(cls, data):
        assert(len(data) == block_length_by_type(6))
        account = data[0:32]
        prev = data[32:64]
        rep = data[64:96]
        bal = int.from_bytes(data[96:112], "big")
        link = data[112:144]
        sig = data[144:208]
        # Block states proof of work is received and sent in big endian
        work = data[208:]
        return block_state(account, prev, rep, bal, link, sig, work)

    def __str__(self):
        hexacc = binascii.hexlify(self.account).decode("utf-8").upper()
        string = "------------- Block State -------------\n"
        string += "Hash : %s\n" % hexlify(self.hash())
        string += "Acc  : %s\n" % hexacc
        string += "       %s\n" % acctools.to_account_addr(self.account)
        string += "Prev : %s\n" % hexlify(self.previous)
        string += "Repr : %s\n" % hexlify(self.representative)
        string += "Bal  : %f\n" % (self.balance / (10**30))
        string += "Link : %s\n" % hexlify(self.link)
        string += "Sign : %s\n" % hexlify(self.signature)
        string += "Work : %s\n" % hexlify(self.work)
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


def read_block_send(s):
    data = read_socket(s, 152)
    block = block_send.parse(data)
    return block


def read_block_receive(s):
    data = read_socket(s, 136)
    block = block_receive.parse(data)
    return block


def read_block_open(s):
    data = read_socket(s, 168)
    block = block_open.parse(data)
    return block


def read_block_change(s):
    data = read_socket(s, 136)
    block = block_change.parse(data)
    return block


def read_block_state(s):
    data = read_socket(s, 216)
    block = block_state.parse(data)
    return block
