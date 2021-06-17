from protocol import Nano
from kaitaistruct import KaitaiStream, BytesIO
from hashlib import blake2b
import binascii
import ipaddress
import socket



class ParseErrorBadMagicNumber(Exception):
    pass


class ParseErrorBadNetworkId(Exception):
    pass


class ParseErrorBadMessageType(Exception):
    pass


class ParseErrorBadIPv6(Exception):
    pass


class ParseErrorBadMessageBody(Exception):
    pass


class SocketClosedByPeer(Exception):
    pass


class ParseErrorBadBlockSend(Exception):
    pass


class ParseErrorBadBlockReceive(Exception):
    pass


class ParseErrorBadBlockOpen(Exception):
    pass


class ParseErrorBadBlockChange(Exception):
    pass


class ParseErrorBadBlockChange(Exception):
    pass


class ParseErrorBadBlockState(Exception):
    pass


class ParseErrorBadBulkPullResponse(Exception):
    pass


class BadBlockHash(Exception):
    pass


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
    def __init__(self, ctx):
        self.header = message_header(ctx['net_id'], [18, 18, 18], message_type(6), [0, 0])
        self.public_key = binascii.unhexlify(ctx['genesis_pub'])

    def serialise(self):
        data = self.header.serialise_header()
        data += self.public_key
        data += (0).to_bytes(32, "big")
        return data


class block_send:
    def __init__(self, prev, dest, bal, sig, work):
        self.prev = prev
        self.dest = dest
        self.bal = bal
        self.sig = sig
        self.work = work

    def __str__(self):
        string = "------------- Block Send -------------\n"
        string += "Previous Node: %s\n" % hex(self.prev)
        string += "Destination Node: %s\n" % hex(self.dest)
        string += "Balance: %d\n" % self.bal
        string += "Signature: %s\n" % hex(self.sig)
        string += "Proof of Work: %s" % hex(self.work)
        return string


class block_receive:
    def __init__(self, prev, source, sig, work):
        self.prev = prev
        self.source = source
        self.sig = sig
        self.work = work

    def __str__(self):
        string = "------------- Block Receive -------------\n"
        string += "Previous Node: %s\n" % hex(self.prev)
        string += "Source Node: %s\n" % hex(self.source)
        string += "Signature: %s\n" % hex(self.sig)
        string += "Proof of Work: %s" % hex(self.work)
        return string


class block_open:
    def __init__(self, source, rep, account, sig, work):
        self.source = source
        self.rep = rep
        self.account = account
        self.sig = sig
        self.work = work

    def __str__(self):
        string = "------------- Block Send -------------\n"
        string += "Source Node: %s\n" % hex(self.source)
        string += "Representative Node: %s\n" % hex(self.rep)
        string += "Account: %s\n" % hex(self.account)
        string += "Signature: %s\n" % hex(self.sig)
        string += "Proof of Work: %s" % hex(self.work)
        return string


class block_change:
    def __init__(self, prev, rep, sig, work):
        self.prev = prev
        self.rep = rep
        self.sig = sig
        self.work = work

    def __str__(self):
        string = "------------- Block Send -------------\n"
        string += "Previous Node: %s\n" % hex(self.prev)
        string += "Representative Node: %s\n" % hex(self.rep)
        string += "Signature: %s\n" % hex(self.sig)
        string += "Proof of Work: %s" % hex(self.work)


class block_state:
    def __init__(self, account, prev, rep, bal, link, sig, work):
        self.account = account
        self.prev = prev
        self.rep = rep
        self.bal = bal
        self.link = link
        self.sig = sig
        self.work = work

    def __str__(self):
        string = "------------- Block State -------------\n"
        string += "Account: %s\n" % hex(self.account)
        string += "Previous: %s\n" % hex(self.prev)
        string += "Representative: %s\n" % hex(self.rep)
        string += "Balance: %s\n" % hex(self.bal)
        string += "Link: %s\n" % hex(self.link)
        string += "Signature: %s\n" % hex(self.sig)
        string += "Work: %s\n" % hex(self.work)
        return string


class blocks_container:
    def __init__(self, blocks):
        self.blocks = blocks

    def traverse_backwards(self):
        pass

    def find_prev(self, block):
        for b in self.blocks:
            if block.previous == self.compute_hash(b) and block != b:
                return b
        raise BadBlockHash()

    def compute_hash(self, block):
        if isinstance(block, Nano.BlockSend):
            sum = block.previous + block.destination + block.balance + block.signature + block.work
            return blake2b(sum)
        elif isinstance(block, Nano.BlockState):
            sum = int(block.previous) + int.from_bytes(block.representative[0:], "big") + int.from_bytes(block.account[0:], "big") + int.from_bytes(block.work[0:], "big") + int.from_bytes(block.signature[0:], "big") + int.from_bytes(block.balance[0:], "big")
            sum += block.link
            return blake2b(sum)
        elif isinstance(block, Nano.BlockChange):
            sum = block.previous + block.representative + block.signature + block.work
            return blake2b(sum)


    def __str__(self):
        string = "---------------------------------------------------\n"
        for i in range(0, len(self.blocks)):
            string += str(self.blocks[i])
        string += "---------------------------------------------------"
        return string


# ********** Everything relevant to hashing and traversing the chain starts here **********

def hash_block_state(block):
    data = b"".join([
        STATE_BLOCK_HEADER_BYTES,
        block.account,
        block.previous,
        block.representative,
        block.balance,
        block.link

    ])
    return blake2b(data, digest_size=32).hexdigest().upper()

def hash_block_send(block):
    data = b"".join([
        block.previous,
        block.destination,
        block.balance
    ])
    return blake2b(data, digest_size=32).hexdigest().upper()

def hash_block_change(block):
    if isinstance(block, Nano.BlockChange):
        data = b"".join([
            block.previous,
            block.representative
        ])
        return blake2b(data, digest_size=32).hexdigest().upper()

def traverse_backwards(block, blocks):
    prev = binascii.hexlify(block.previous).decode("utf-8").upper()
    hash = ""
    index = 0
    for b in blocks:
        if isinstance(b, Nano.BlockState):
            hash = hash_block_state(b)
        elif isinstance(b, Nano.BlockSend):
            hash = hash_block_send(b)
        elif isinstance(b, Nano.BlockChange):
            hash = hash_block_change(b)
        if prev == hash:
            return index
        index += 1
    return -1

betactx = {
    'peeraddr'    : "peering-beta.nano.org",
    'peerport'    : 54000,
    'genesis_pub' : '259A43ABDB779E97452E188BA3EB951B41C961D3318CA6B925380F4D99F0577A',
}

livectx = {
    'net_id': network_id(67),
    'peeraddr'    : "peering.nano.org",
    'peerport'    : 7075,
    'genesis_pub' : 'E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA',
}

STATE_BLOCK_HEADER_BYTES = binascii.unhexlify(
    "0000000000000000000000000000000000000000000000000000000000000006")

ctx = livectx

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((ctx['peeraddr'], ctx['peerport']))
keepalive = message_keepmealive(ctx['net_id'])
req = keepalive.serialise()
s.send(req)
bulk_pull = message_bulk_pull(ctx)
req = bulk_pull.serialise()
s.send(req)

if True:
    import time

    data = s.recv(1000000)
    time.sleep(1)
    data += s.recv(1000000)

    bio = BytesIO(data)
    kio = KaitaiStream(bio)
    n = Nano.BulkPullResponse(kio)
    blocks = []
    for e in n.entry:
         blocks.append(e.block.block)
            
    i = 0
    traversal_order = []
    while True:
        traversal_order.append(i)
        i = traverse_backwards(blocks[i], blocks)
        if i == -1:
            break

    print(traversal_order)



    # bytes = BytesIO(binascii.unhexlify("e89208dd038fbb269987689621d52292ae9c35941a7484756ecced92a65093baeccb8cb65cd3106eda8ce9aa893fead497a91bca903890cbd7a5c59f06ab9113e89208dd038fbb269987689621d52292ae9c35941a7484756ecced92a65093ba000000041c06df91d202b70a4000001165706f636820763120626c6f636b00000000000000000000000000000000000057bfe93f4675fc16df0ccfc7ee4f78cc68047b5c14e2e2eed243f17348d8bab3cca04f8cbc2d291b4ddec5f7a74c1be1e872df78d560c46365eb15270a1d12010f78168d5b30191d"))
    # kio = KaitaiStream(bytes)
    # block = Nano.BlockState(kio)
    # blockHash = hash_block_state(block)
