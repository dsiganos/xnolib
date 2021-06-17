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




# *********** Everything traversal and hash related starts here ***********


class blocks_container:
    def __init__(self, blocks):
        self.blocks = blocks


    def hash_block_state(self, block):
        data = b"".join([
            STATE_BLOCK_HEADER_BYTES,
            block.account,
            block.previous,
            block.representative,
            block.balance,
            block.link

        ])
        return blake2b(data, digest_size=32).hexdigest().upper()


    def hash_block_send(self, block):
        data = b"".join([
            block.previous,
            block.destination,
            block.balance
        ])
        return blake2b(data, digest_size=32).hexdigest().upper()


    def hash_block_change(self, block):
        data = b"".join([
            block.previous,
            block.representative
        ])
        return blake2b(data, digest_size=32).hexdigest().upper()


    def hash_block_open(self, block):
        data = b"".join([
            block.source,
            block.representative,
            block.account
        ])
        return blake2b(data, digest_size=32).hexdigest().upper()


    def hash_block_receive(self, block):
        data = b"".join([
            block.previous,
            block.source
        ])
        return blake2b(data, digest_size=32).hexdigest().upper()


    def traverse_backwards(self, block):
        traversal_order = []
        i = self.blocks.index(block)

        while i != -1:
            traversal_order.append(i)
            i = self.find_prev(self.blocks[i])

        return traversal_order


    def find_prev(self, block):
        if isinstance(block, Nano.BlockOpen):
            prev = binascii.hexlify(block.source).decode("utf-8").upper()
        else: prev = binascii.hexlify(block.previous).decode("utf-8").upper()

        index = 0
        hash = ""

        for b in self.blocks:
            if isinstance(b, Nano.BlockState):
                hash = self.hash_block_state(b)
            elif isinstance(b, Nano.BlockSend):
                hash = self.hash_block_send(b)
            elif isinstance(b, Nano.BlockChange):
                hash = self.hash_block_change(b)
            elif isinstance(b, Nano.BlockOpen):
                hash = self.hash_block_open(b)
            elif isinstance(b, Nano.BlockReceive):
                hash = self.hash_block_receive(b)
            if prev == hash:
                return index
            index += 1

        return -1


    def __str__(self):
        string = "---------------------------------------------------\n"
        for i in range(0, len(self.blocks)):
            string += str(self.blocks[i])
        string += "---------------------------------------------------"
        return string



betactx = {
    'peeraddr'    : "peering-beta.nano.org",
    'peerport'    : 54000,
    'genesis_pub' : '259A43ABDB779E97452E188BA3EB951B41C961D3318CA6B925380F4D99F0577A',
}

livectx = {
    'net_id': network_id(67),
    'peeraddr'    : "peering.nano.org",
    'peerport'    : 7075,
    'genesis_pub' : '6E5404423E7DDD30A0287312EC79DFF5B2841EADCD5082B9A035BCD5DB4301B6',
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
        #print(e.block.block)

    container = blocks_container(blocks)
    print(container.traverse_backwards(container.blocks[0]))
