import ipaddress
import os
import random
import socket
from hashlib import blake2b
import binascii
import base64
import dns.resolver
import ed25519_blake2
import ed25519_blake2b
import git

import acctools
from exceptions import *


def writefile(filename, content):
    with open(filename, "w") as f:
        f.write(content)


def hexlify(data):
    if data is None: return 'None'
    return binascii.hexlify(data).decode("utf-8").upper()


def parse_ipv6(data):
    if len(data) != 16:
        raise ParseErrorBadIPv6()
    return ipaddress.IPv6Address(data)


# return a list of ipv4 mapped ipv6 strings
def get_all_dns_addresses(addr):
    result = dns.resolver.resolve(addr, 'A')
    return ['::ffff:' + x.to_text() for x in result]


# return DNS adresses as Peer objects
def get_all_dns_addresses_as_peers(addr, peerport, score):
    addresses = get_all_dns_addresses(addr)
    return [ Peer(ip_addr(ipaddress.IPv6Address(a)), peerport, score) for a in addresses ]


def confirm_req_size(block_type, i_count):
    if block_type == message_type_enum.not_a_block:
        size = 64 * i_count
    else:
        assert(i_count == 1)
        size = block_length_by_type.get(block_type)
    return size


def confirm_ack_size(block_type, i_count):
    size = 104
    if block_type == message_type_enum.not_a_block:
        size += i_count * 32
    else:
        assert(i_count == 1)
        size += block_length_by_type.get(block_type)
    return size


class ip_addr:
    def __init__(self, ipv6 = ipaddress.IPv6Address(0)):
        assert isinstance(ipv6, ipaddress.IPv6Address)
        self.ipv6 = ipv6

    @classmethod
    def from_string(cls, ipstr):
        assert isinstance(ipstr, str)
        a = ipaddress.ip_address(ipstr)
        if a.version == 4:
            ipstr = '::ffff:' + str(a)
        ipv6 = ipaddress.IPv6Address(ipstr)
        return ip_addr(ipv6)

    def serialise(self):
        return self.ipv6.packed

    def __str__(self):
        if self.ipv6.ipv4_mapped:
            return '::ffff:' + str(self.ipv6.ipv4_mapped)
        return str(self.ipv6)

    def __eq__(self, other):
        if not isinstance(other, ip_addr):
            return False
        return self.ipv6 == other.ipv6

    def __hash__(self):
        return hash(self.ipv6)


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
    not_a_block = 0x1
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


def message_type_enum_to_str(msg_type):
    return next(name for name, value in vars(message_type_enum).items() if value == msg_type)


class network_id:
    def __init__(self, rawbyte):
        self.parse_header(int(rawbyte))

    def parse_header(self, rawbyte):
        if not (rawbyte in [ord('X'), ord('B'), ord('C')]):
            raise ParseErrorBadNetworkId()
        self.id = rawbyte

    def __str__(self):
        return chr(self.id)

    def __eq__(self, other):
        if not isinstance(other, network_id):
            return False
        elif self.id != other.id:
            return False
        return True


class message_type:
    def __init__(self, num):
        if not (num in range(0, 14)):
             raise ParseErrorBadMessageType()
        self.type = num

    def __str__(self):
        return '%s(%s)' % (str(self.type), message_type_enum_to_str(self.type))

    def __eq__(self, other):
        if not isinstance(other, message_type):
            return False
        return self.type == other.type


class message_header:

    def __init__(self, net_id, versions, msg_type, ext):
        self.ext = ext
        self.net_id = net_id
        self.ver_max = versions[0]
        self.ver_using = versions[1]
        self.ver_min = versions[2]
        self.msg_type = msg_type
        assert isinstance(self.msg_type, message_type)

    def serialise_header(self):
        header = b""
        header += ord('R').to_bytes(1, "big")
        header += ord(str(self.net_id)).to_bytes(1, "big")
        header += self.ver_max.to_bytes(1, "big")
        header += self.ver_using.to_bytes(1, "big")
        header += self.ver_min.to_bytes(1, "big")
        header += self.msg_type.type.to_bytes(1, "big")
        header += self.ext.to_bytes(2, "little")
        return header

    def is_handshake_query(self):
        return self.ext& 1

    def is_handshake_response(self):
        return self.ext& 2

    def count_get(self):
        COUNT_MASK = 0xf000
        return (self.ext & COUNT_MASK) >> 12

    def block_type(self):
        BLOCK_TYPE_MASK = 0x0f00
        return (self.ext & BLOCK_TYPE_MASK) >> 8

    def set_block_type(self, block_type):
        assert(isinstance(block_type, int))
        block_type = block_type << 8
        self.ext = self.ext & 0xf0ff
        self.ext = self.ext | block_type

    def set_item_count(self, count):
        assert(isinstance(count, int))
        count = count << 12
        self.ext = self.ext & 0x0fff
        self.ext = self.ext | count



    @classmethod
    def parse_header(cls, data):
        assert(len(data) == 8)
        if data[0] != ord('R'):
            raise ParseErrorBadMagicNumber()
        net_id = network_id(data[1])
        versions = [data[2], data[3], data[4]]
        msg_type = message_type(data[5])
        ext = int.from_bytes(data[6:], "little")
        return message_header(net_id, versions, msg_type, ext)

    def telemetry_ack_size(self):
        telemetry_size_mask = 0x3ff
        return self.ext & telemetry_size_mask

    def payload_length_bytes(self):
        if self.msg_type == message_type(message_type_enum.bulk_pull):
            print('we do not yet support a bulk pull')
            assert(0)

        elif self.msg_type == message_type(message_type_enum.bulk_push):
            return 0

        elif self.msg_type == message_type(message_type_enum.telemetry_req):
            return 0

        elif self.msg_type == message_type(message_type_enum.frontier_req):
            return 32 + 4 + 4

        elif self.msg_type == message_type(message_type_enum.bulk_pull_account):
            return 32 + 16 + 1

        elif self.msg_type == message_type(message_type_enum.keepalive):
            return 8 * (16 + 2);

        elif self.msg_type == message_type(message_type_enum.publish):
            return block_length_by_type(self.block_type())

        elif self.msg_type == message_type(message_type_enum.confirm_ack):
            return confirm_ack_size(self.block_type(), self.count_get());

        elif self.msg_type == message_type(message_type_enum.confirm_req):
            return confirm_req_size(self.block_type(), self.count_get());

        elif self.msg_type == message_type(message_type_enum.node_id_handshake):
            return node_id_handshake_size(self.is_handshake_query(), self.is_handshake_response());

        elif self.msg_type == message_type(message_type_enum.telemetry_ack):
            return self.telemetry_ack_size()

        else:
            print('unhandled message type: %s' % self.msg_type)
            assert(0);

    def __eq__(self, other):
        if str(self) == str(other):
            return True

    def __str__(self):
        str  = "NetID: %s, " % self.net_id
        str += "VerMaxUsingMin: %s/%s/%s, " % (self.ver_max, self.ver_using, self.ver_min)
        str += "MsgType: %s, " % self.msg_type
        str += "Extensions: %s" % hexlify(self.ext.to_bytes(2, "big"))
        return str


# A class representing a peer, stores its address, port and provides the means to convert
# it into a readable string format
class Peer:
    def __init__(self, ip = ip_addr(), port = 0, score = -1, is_voting = False):
        assert isinstance(ip, ip_addr)
        self.ip = ip
        self.port = port
        self.peer_id = None
        self.is_voting = is_voting
        self.aux = {}

        # sideband info, not used for equality and hashing
        self.score = score

    def serialise(self):
        data = b""
        data += self.ip.serialise()
        data += self.port.to_bytes(2, "little")
        return data

    def is_valid(self):
        data = self.ip.serialise()
        data += self.port.to_bytes(2, "little")
        if int.from_bytes(data[0:16], "big") == 0:
            return False
        elif int.from_bytes(data[16:], "little") == 0:
            return False
        return True

    def deduct_score(self, score):
        if self.score - score < 0:
            self.score = 0
        else:
            self.score -= score

    @classmethod
    def parse_peer(cls, data):
        assert(len(data) == 18)
        ip = parse_ipv6(data[0:16])
        port = int.from_bytes(data[16:], "little")
        return Peer(ip_addr(ip), port)

    def __str__(self):
        return '%s:%s (score:%s, is_voting: %s)' % (str(self.ip), self.port, self.score, self.is_voting)

    def __eq__(self, other):
        return self.ip == other.ip and self.port == other.port

    def __hash__(self):
        return hash((self.ip, self.port))


class message_keepalive:
    def __init__(self, hdr, peers=None):
        self.header = hdr
        self.header.msg_type = message_type(message_type_enum.keepalive)
        if peers is None:
            self.peers = []
            for i in range(0, 8):
                self.peers.append(Peer())
        else:
            self.peers = peers

    def serialise(self):
        data = self.header.serialise_header()
        for p in self.peers:
            data += p.serialise()
        return data

    def __str__(self):
        string = '%s\n' % self.header
        for p in self.peers:
            string += "%s\n" % str(p)
        return string

    def __eq__(self, other):
        if str(self) == str(other):
            return True
        return False

    @classmethod
    def parse_payload(cls, hdr, rawdata):
        assert(len(rawdata) % 18 == 0)
        no_of_peers = int(len(rawdata) / 18)
        start_index = 0
        end_index = 18
        peers_list = []
        for i in range(0, no_of_peers):
            p = Peer.parse_peer(rawdata[start_index:end_index])
            peers_list.append(p)
            start_index = end_index
            end_index += 18
        return message_keepalive(hdr, peers_list)


class message_bulk_pull:
    def __init__(self, hdr, start, finish=None, count=None):
        self.header = hdr
        self.count = count
        self.public_key = binascii.unhexlify(start)
        if finish is not None:
            self.finish = binascii.unhexlify(finish)
        else:
            self.finish = (0).to_bytes(32, "big")
        if count is not None:
            assert(hdr.ext == 1)

    def serialise(self):
        data = self.header.serialise_header()
        data += self.public_key
        data += self.finish
        if self.count is not None:
            data += self.generate_extended_params()
        return data

    def generate_extended_params(self):
        assert(self.count is not None)
        data = (0).to_bytes(1, "big")
        data += self.count.to_bytes(4, "little")
        data += (0).to_bytes(3, "big")
        return data


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


class block_manager:
    def __init__(self, ctx, workdir, gitrepo):
        self.ctx = ctx
        self.accounts = []
        self.processed_blocks = []
        self.unprocessed_blocks = set()
        self.trust_open_blocks = True
        self.workdir = workdir
        self.gitrepo = gitrepo

        # create genesis account and block
        open_block = block_open(ctx["genesis_block"]["source"], ctx["genesis_block"]["representative"],
                                ctx["genesis_block"]["account"], ctx["genesis_block"]["signature"],
                                ctx["genesis_block"]["work"])
        open_block.ancillary["balance"] = 0xffffffffffffffffffffffffffffffff
        self.accounts.append(nano_account(self, open_block))

        #TODO: Make a method which can get the next undiscovered account

    def next_acc_iter(self):
        for a in self.accounts:
            for block_hash, b in a.blocks.items():
                if not (isinstance(b, block_send) or isinstance(b, block_state)):
                    continue
                elif isinstance(b, block_send):
                    if not self.account_exists(b.destination):
                        yield b.destination
                elif isinstance(b, block_state):
                    if b.link == b'\x00' * 32:
                        continue
                    if not self.account_exists(b.link):
                        yield b.link
        yield None

    def process_one(self, block):
        success = False
        if isinstance(block, block_open):
            success = self.process_block_open(block)
        elif isinstance(block, block_send):
            success = self.process_block_send(block)
        elif isinstance(block, block_change):
            success = self.process_block_change(block)
        elif isinstance(block, block_receive):
            self.process_block_receive(block)
        elif isinstance(block, block_state):
            success = self.process_block_state(block)
        else:
            success = self.process_block(block)
        return success

    def process(self, block):
        success = self.process_one(block)
        if success:
            self.process_unprocessed_blocks()
        return success

    def process_block_state(self, block):
        #print('process_block_state %s' % hexlify(block.hash()))

        # check block
#        if not valid_block(block):
#            return False

        # is it open block and do we trust all open blocks
        if block.previous == b'\x00' * 32 and self.trust_open_blocks:
            # check if account exists
            if self.account_exists(block.get_account()):
                print('state open block (%s) for already opened account %s' %
                     (hexlify(block.hash()), acctools.to_account_addr(block.account)))
                return True

            # create the account
            acc = nano_account(self, block)
            self.accounts.append(acc)
            print('Opened new account\n%s' % acc)
            return True

        # find the previous block
        prevblk, acc = self.find_ledger_block_by_hash(block.previous)
        if prevblk is None:
            #print('cannot find previous block (%s) of state block (%s)' %
            #    (hexlify(block.previous), hexlify(block.hash())))
            self.unprocessed_blocks.add(block)
            return False

        # check if it is an epoch block
        if block.link.startswith(b'epoch') and prevblk.get_balance() == block.get_balance():
            print('Epoch block')
            print(block)

        acc.add_block(block, previous=prevblk.hash())
        return True

    def process_block_open(self, block):
        # check block
        # FIXME: this breaks with test network genesis open block
        #if not valid_block(block):
        #    print('Invalid block with hash %s' % hexlify(block.hash()))
        #    return False

        # check if account exists
        if self.account_exists(block.get_account()):
            print('open block (%s) for already opened account %s' %
                (hexlify(block.hash()), acctools.to_account_addr(block.account)))
            return True

        # do we trust all open blocks?
        if self.trust_open_blocks:
            # with an open block, we do not know the balance and there is no way
            # to know it without pulling an indeterminate number of blocks/accounts
            # so setting it to zero for now since we are focused on forks when trusting open blocks
            block.ancillary["balance"] = 0
            # create the account
            acc = nano_account(self, block)
            self.accounts.append(acc)
            print('Opened new account\n%s' % acc)
            return True

        # find the associated send block
        srcblk, _ = self.find_ledger_block_by_hash(block.source)
        if srcblk is None:
            print('cannot find source block (%s) of open block (%s)' %
                (hexlify(block.source), hexlify(block.hash())))
            self.unprocessed_blocks.add(block)
            return False

        # we have a source block, set the opening balance
        block.ancillary["balance"] = srcblk.ancillary["amount_sent"]

        # create the account
        acc = nano_account(self, block)
        self.accounts.append(acc)
        print('Opened new account\n%s' % acc)

        return True

    def process_block_send(self, block):
        assert block.previous

        # check block
#        if not valid_block(block):
#            return False

        # find the previous block
        prevblk, acc = self.find_ledger_block_by_hash(block.previous)
        if prevblk is None:
            print('cannot find previous block (%s) of send block (%s)' %
                (hexlify(block.previous), hexlify(block.hash())))
            self.unprocessed_blocks.add(block)
            return False

        # we have a previous block, set the amount_sent and account
        block.ancillary["amount_sent"] = prevblk.get_balance() - block.balance
        block.ancillary["account"] = prevblk.get_account()

        # add block to the account
        acc.add_block(block, previous=prevblk.hash())
        return True

    def process_block_receive(self, block):
        assert(isinstance(block, block_receive))
        prevblk, acc = self.find_ledger_block_by_hash(block.previous)
        if prevblk is None:
            print('cannot find previous block (%s) of receive block (%s)' %
                  (hexlify(block.previous), hexlify(block.hash())))
            self.unprocessed_blocks.add(block)
            return False

        scrblk, _ = self.find_ledger_block_by_hash(block.source)
        if scrblk is None:
            print("cannot find source block (%s) of reveive block (%s)" %
                (hexlify(block.source), hexlify(block.hash())))
            self.unprocessed_blocks.add(block)
            return False

        block.ancillary["balance"] = prevblk.get_balance()
        block.ancillary["balance"] += scrblk.ancillary["amount_sent"]
        block.ancillary["account"] = prevblk.get_account()
        acc.add_block(block, previous=prevblk.hash())

        return True

    def process_block_change(self, block):
        assert block.previous

        # check block
#        if not valid_block(block):
#            return False

        # find the previous block
        prevblk, acc = self.find_ledger_block_by_hash(block.previous)
        if prevblk is None:
            print('cannot find previous block (%s) of send block (%s)' %
                (hexlify(block.previous), hexlify(block.hash())))
            self.unprocessed_blocks.add(block)
            return False

        # we have a previous block, set the balance and account
        block.ancillary["account"] = prevblk.get_account()
        block.ancillary["balance"] = prevblk.get_balance()

        # add block to the account
        acc.add_block(block, previous=prevblk.hash())
        return True

    # find a block by hash that is part of the local ledger
    def find_ledger_block_by_hash(self, hsh):
        for acc in self.accounts:
            blk = acc.find_block_by_hash(hsh)
            if blk: return blk, acc
        return None, None

    def process_block(self, block):
        assert not isinstance(block, block_send)
        print('process block ', hexlify(block.hash()))
        print('    prev:', hexlify(block.previous))
        account_pk = self.find_blocks_account(block)
        if account_pk is not None:
            block.ancillary["account"] = account_pk
            if not valid_block(block):
                return False
            self.find_prev_block(block).ancillary["next"] = block.hash()
        else:
            self.unprocessed_blocks.add(block)
            print('process block no account_pk')
            return False

        n_account = self.find_nano_account(account_pk)
        if n_account is None:
            self.unprocessed_blocks.add(block)
            print('process block no account')
            return False

        if isinstance(block, block_send):
            amount = self.find_amount_sent(block)
            if amount is not None:
                block.ancillary["amount_sent"] = amount
            else:
                self.unprocessed_blocks.add(block)
                print(block)
                print('process block no amount')
                return False

        if block.get_balance() is None:
            balance = self.find_balance(block)
            if balance is not None:
                block.ancillary["balance"] = balance
            else:
                self.unprocessed_blocks.add(block)
                print('process block no balance')
                return False

        n_account.add_block(block)
        print('process block done')
        return True

    def find_amount_sent(self, block):
        for b in self.processed_blocks:
            if b.hash() == block.get_previous():
                if b.get_balance() is not None:
                    before = b.get_balance()
                    after = block.get_balance()
                    amount = before - after
                    return amount
                else:
                    return None

    def find_balance(self, block):
        if isinstance(block, block_open):
            assert False
            for b in self.processed_blocks:
                if b.hash() == block.get_previous():
                    return b.ancillary["amount_sent"]
        elif isinstance(block, block_receive):
            before = int.from_bytes(self.find_prev_block(block).get_balance(), "big")
            for b in self.processed_blocks:
                if b.hash() == block.source:
                    amount = b.ancillary["amount_sent"]
                    return before + amount
        elif isinstance(block, block_change):
            for b in self.processed_blocks:
                if b.hash() == block.get_previous():
                    return b.get_balance()
        return None

    def account_exists(self, account):
        for a in self.accounts:
            if a.account == account:
                return True
        return False

    def find_blocks_account(self, block):
        if block.get_account() is not None:
            return block.get_account()
        for b in self.processed_blocks:
            if b.hash() == block.get_previous():
                assert(b.get_account() is not None)
                return b.get_account()
        return None

    def find_nano_account(self, account_pk):
        for a in self.accounts:
            if a.account == account_pk:
                return a
        return None

    # try to process unprocessed blocks, if there is a success try again until there no more successes
    def process_unprocessed_blocks(self):
        blocks_processed = []
        try_again = True
        count = 0

        while try_again:
            try_again = False

            # try to process each block
            for blk in self.unprocessed_blocks:
                if self.process_one(blk):
                    count += 1
                    try_again = True
                    blocks_processed.append(blk.hash())

            # remove blocks that are successfully processed from unprocessed list
            self.unprocessed_blocks = set(filter(
                lambda blk: not (blk.hash() in blocks_processed),
                self.unprocessed_blocks
            ))

        if count > 0:
            print('process_unprocessed_blocks] processed %s blocks, %s left' % (count, len(self.unprocessed_blocks)))

    def find_prev_block(self, block):
        hash = block.get_previous()
        for b in self.processed_blocks:
            if b.hash() == hash:
                return b

    def str_processed_blocks(self):
        string = ""
        for b in self.processed_blocks:
            string += str(b)
            string += "\n"
        return string

    def str_unprocessed_blocks(self):
        string = ""
        for b in self.unprocessed_blocks:
            string += str(b)
            string += "\n"
        return string

    def __str__(self):
        string = "------------- Blocks Manager -------------\n"
        string += "Blocks Processed: %d\n" % len(self.processed_blocks)
        string += "Unprocessed Blocks: %d\n" % len(self.unprocessed_blocks)
        string += "Accounts:\n\n"
        for a in self.accounts:
            string += "    Public Key : %s\n" % hexlify(a.account)
            string += "    ID         : %s\n\n" % acctools.to_account_addr(a.account)
        return string


class nano_account:
    def __init__(self, blockman, open_block):
        self.first = open_block
        self.workdir = blockman.workdir
        self.gitrepo = blockman.gitrepo
        # print(open_block)
        self.account = open_block.get_account()
        self.isforked = False
        #self.heads = [open_blocks]
        self.blocks = {}
        self._add_block(open_block, None)

    # add a block to account, if previous is set then check for forks
    def add_block(self, block, previous):
        if block.hash() in self.blocks:
            if self.workdir:
                merged_block = self.blocks[block.hash()]
                merged_block.ancillary['peers'].update(block.ancillary['peers'])
                hashstr = hexlify(merged_block.hash())
                filename = '%s/%s' % (self.workdir, hashstr)
                writefile(filename, str(merged_block) + '\n')
            #print('block (%s) already exists in account %s' %
            #    (hexlify(block.hash()), acctools.to_account_addr(block.get_account())))
            return

        # if previous is none then it must be a starting block
        if previous is None:
            assert len(self.blocks) == 0
            self._add_block(block)
            return

        # it is not a starting block, look for previous and check for forks
        prevblk = self.blocks[previous]
        assert prevblk
        prev_next = prevblk.get_next()
        if prev_next:
            print('FORK DETECTED: block: %s previous: %s previous_next: %s' %
                (hexlify(block.hash()), hexlify(previous), hexlify(prev_next)))
            self.isforked = True
            self._add_block(block, prevblk)
        else:
            print('added block: %s to account %s' %
                (hexlify(block.hash()), acctools.to_account_addr(self.account)))
            self._add_block(block, prevblk)
            prevblk.ancillary['next'] = block.hash()

    def _add_block(self, block, prevblk):
        self.blocks[block.hash()] = block
        hashstr = hexlify(block.hash())
        if self.workdir:
            filename = '%s/%s' % (self.workdir, hashstr)
            writefile(filename, str(block) + '\n')
        if self.gitrepo:
            if prevblk is None:
                self.gitrepo.git.checkout(orphan=hashstr)
            else:
                self.gitrepo.git.checkout('-m', '-b', hashstr, hexlify(prevblk.hash()))
            self.gitrepo.git.add('.')
            print('git commit')
            self.gitrepo.git.commit('-m', '.')
            print('git commit done')

    def find_block_by_hash(self, hsh):
        return self.blocks.get(hsh, None)

#    # This method is used for debugging: checking order
#    def traverse_backwards(self):
#        block = self.blocks[-1]
#        traversal = []
#        while block is not None:
#            traversal.append(self.blocks.index(block))
#            block = self.find_prev(block)
#        return traversal

#    # This method is used for debugging: checking order
#    def traverse_forwards(self):
#        block = self.blocks[0]
#        traversal = []
#        while block is not None:
#            traversal.append(self.blocks.index(block))
#            block = self.find_next(block)
#        return traversal

    def find_prev(self, block):
        prevhash = block.get_previous()
        return self.blocks.get(prevhash, None)

    def find_next(self, block):
        if block.ancillary["next"] is None:
            return None
        nexthash = block.ancillary["next"]
        return self.blocks.get(nexthash, None)

    def get_last_block(self):
        assert self.first
        currblk = self.first

        while True:
            nexthash = currblk.get_next()
            if nexthash is None:
                break

            nextblk = self.blocks.get(nexthash, None)
            if nextblk is None:
                break

            currblk = nextblk

        return currblk

    def str_blocks(self):
        string = ""
        for b in self.blocks.values():
            string += str(b)
            string += "\n"
        return string

#    # Checks if itself is a subset of another account
#    def is_subset(self, account):
#        for b in self.blocks:
#            if b not in account.blocks:
#                return False
#        return True

#    def check_forks(self):
#        for b1 in self.blocks:
#            for b2 in self.blocks:
#                if b1 == b2:
#                    continue
#                elif b1.previous == b2.previous:
#                    return b1, b2
#        return None, None

#    def get_balance(self, block):
#        return block.get_balance()

    def __str__(self):
        lastblk = self.get_last_block()
        string = "------------- Nano Account -------------\n"
        string += "Account : %s\n" % hexlify(self.account)
        string += "        : %s\n" % acctools.to_account_addr(self.account)
        string += "Blocks  : %d\n" % len(self.blocks)
        string += "First   : %s\n" % hexlify(self.first.hash())
        string += "Last    : %s\n" % hexlify(lastblk.hash())
        string += "Balance : %f\n" % (lastblk.get_balance() / (10**30))
        string += "isforked: %s\n" % self.isforked
        return string


def read_socket(socket, numbytes):
    try:
        data = b''
        while len(data) < numbytes:
            data += socket.recv(1)
            if len(data) == 0:
                raise SocketClosedByPeer('read_socket: data=%s' % data)
        return data
    except OSError as msg:
        print('read_socket] Error whilst reading %d bytes' % numbytes)
        print('  %s bytes in buffer: %s "%s"' % (len(data), hexlify(data), data))
        print(msg)
        return None


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


def read_block_from_socket(s):
    block = None

    block_type = s.recv(1)
    if len(block_type) == 0:
        print('socket closed by peer')
        return block

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
        print('received block type not a block')
    else:
        print('received unknown block type %s' % block_type_enum[0])

    return block


def read_bulk_pull_response(s):
    blocks = []
    while True:
        block = read_block_from_socket(s)
        if block is None:
            break
        blocks.append(block)
    return blocks


def readall(s):
    data = b''
    while True:
        try:
            recvd = s.recv(1)
            if recvd == b'': raise SocketClosedByPeer
            data += recvd
        except (socket.timeout, SocketClosedByPeer):
            if len(data) > 0:
                return data
            else:
                return None


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


def verify(hash, signature, public_key):
    try:
        ed25519_blake2.checkvalid(signature, hash, public_key)
    except ed25519_blake2.SignatureMismatch:
        return False
    return True


def verify_pow(block):
    if isinstance(block, block_open):
        return pow_validate(block.work, block.account)
    else:
        return pow_validate(block.work, block.previous)


def valid_block(ctx, block):
    if isinstance(block, block_state):
        if block.is_epoch_v2_block():
            sig_valid = verify(block.hash(), block.signature, binascii.unhexlify(ctx["epoch_v2_signing_account"]))
        elif block.is_epoch_v1_block():
            sig_valid = verify(block.hash(), block.signature, binascii.unhexlify(ctx["genesis_pub"]))
    else:
        if block.get_account() is None:
            raise VerificationErrorNoAccount()
        sig_valid = verify(block.hash(), block.signature, block.get_account())

    work_valid = verify_pow(block)
    print(sig_valid)
    print(work_valid)
    return work_valid and sig_valid



# wait for the next message, parse the header but not the payload
# the header is retruned as an object and the payload as raw bytes
def get_next_hdr_payload(s):
    # read and parse header
    data = read_socket(s, 8)
    if data is None:
        raise CommsError()
    header = message_header.parse_header(data)

    # we can determine the size of the payload from the header
    size = header.payload_length_bytes()

    # read and parse payload
    data = read_socket(s, size)
    return header, data


def get_initial_connected_socket(ctx, peers=None):
    if peers is None or len(peers) == 0:
        peers = get_all_dns_addresses(ctx['peeraddr'])
        random.shuffle(peers)
    for peeraddr in peers:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(3)
        try:
            s.connect((peeraddr, ctx['peerport']))
            print('Connected to [%s]:%s' % (s.getpeername()[0], s.getpeername()[1]))
            return s, peeraddr
        except socket.error as e:
            print('Failed to connect to %s' % peeraddr)
            print(e)

    print('Failed to connect to any of the peering servers')
    return None, None


def get_account_blocks(ctx, s, account):
    hdr = message_header(ctx["net_id"], [18, 18, 18], message_type(6), 0)
    if isinstance(account, bytes):
        account = hexlify(account)
    bulk_pull = message_bulk_pull(hdr, account)
    s.send(bulk_pull.serialise())
    return read_bulk_pull_response(s)


def block_length_by_type(blktype):
    lengths = {
        2: 152,
        3: 136,
        4: 168,
        5: 136,
        6: 216
    }
    return lengths[blktype]


def extensions_to_count(extensions):
    COUNT_MASK = 0xf000
    return (extensions & COUNT_MASK) >> 12


def extensions_to_block_type(extensions):
    BLOCK_TYPE_MASK = 0x0f00
    return (extensions & BLOCK_TYPE_MASK) >> 8


def extensions_to_extented_params(extensions):
    EXTENDED_PARAM_MASK = 0x0001
    return extensions & EXTENDED_PARAM_MASK


def node_id_handshake_size(is_query, is_response):
    size = 0
    if is_query:
        size += 32
    if is_response:
        size += 32 + 64
    return size


live_genesis_block = {
    "hash": binascii.unhexlify("991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948"),
    "source": binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA'),
    "representative": binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA'),
    "account": binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA'),
    "signature": binascii.unhexlify('9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02'),
    "work": binascii.unhexlify('62F05417DD3FB691')
}

beta_genesis_block = {
    "hash": binascii.unhexlify("01A92459E69440D5C1088D3B31F4CA678BE944BAB3776C2E6B7665E9BD99BD5A"),
    "source": binascii.unhexlify("259A43ABDB779E97452E188BA3EB951B41C961D3318CA6B925380F4D99F0577A"),
    "representative": binascii.unhexlify("259A43ABDB779E97452E188BA3EB951B41C961D3318CA6B925380F4D99F0577A"),
    "account": binascii.unhexlify("259A43ABDB779E97452E188BA3EB951B41C961D3318CA6B925380F4D99F0577A"),
    "signature": binascii.unhexlify("4BD7F96F9ED2721BCEE5EAED400EA50AD00524C629AE55E9AFF11220D2C1B00C3D4B3BB770BF67D4F8658023B677F91110193B6C101C2666931F57046A6DB806"),
    "work": binascii.unhexlify("79D4E27DC873C6F2")
}

test_genesis_block = {
    "hash": binascii.unhexlify("B1D60C0B886B57401EF5A1DAA04340E53726AA6F4D706C085706F31BBD100CEE"),
    "source": binascii.unhexlify("45C6FF9D1706D61F0821327752671BDA9F9ED2DA40326B01935AB566FB9E08ED"),
    "representative": binascii.unhexlify("45C6FF9D1706D61F0821327752671BDA9F9ED2DA40326B01935AB566FB9E08ED"),
    "account": binascii.unhexlify("45C6FF9D1706D61F0821327752671BDA9F9ED2DA40326B01935AB566FB9E08ED"),
    "signature": binascii.unhexlify("15049467CAEE3EC768639E8E35792399B6078DA763DA4EBA8ECAD33B0EDC4AF2E7403893A5A602EB89B978DABEF1D6606BB00F3C0EE11449232B143B6E07170E"),
    "work": binascii.unhexlify("BC1EF279C1A34EB1")
}


livectx = {
    'net_id': network_id(ord('C')),
    'peeraddr': "peering.nano.org",
    'peerport': 7075,
    'peercrawlerport': 7070,
    'genesis_pub': 'E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA',
    'another_pub': '059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5',
    'random_block': '6E5404423E7DDD30A0287312EC79DFF5B2841EADCD5082B9A035BCD5DB4301B6',
    'epoch_v2_signing_account': 'dd24a9200d4bf8247981e4ac63dbde38fd2319386970a26d02ecc98c79975db1',
    'genesis_block': live_genesis_block
}


betactx = {
    'net_id': network_id(ord('B')),
    'peeraddr': "peering-beta.nano.org",
    'peerport': 54000,
    'peercrawlerport': 7071,
    'genesis_pub': '259A43ABDB779E97452E188BA3EB951B41C961D3318CA6B925380F4D99F0577A',
    'epoch_v2_signing_account': '259A43ABDB779E97452E188BA3EB951B41C961D3318CA6B925380F4D99F0577A',
    'genesis_block': beta_genesis_block
}


testctx = {
    'net_id': network_id(ord('X')),
    'peeraddr': "peering-test.nano.org",
    'peerport': 17075,
    'peercrawlerport': 7072,
    'genesis_pub': '45C6FF9D1706D61F0821327752671BDA9F9ED2DA40326B01935AB566FB9E08ED',
    'epoch_v2_signing_account': '45C6FF9D1706D61F0821327752671BDA9F9ED2DA40326B01935AB566FB9E08ED',
    'genesis_block': test_genesis_block
}

