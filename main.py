import binascii
import ipaddress


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

class network_id:
    def __init__(self, rawbyte):
        self.parse_header(rawbyte)

    def parse_header(self, rawbyte):
        if not (rawbyte in [ord('A'), ord('B'), ord('C')]):
            raise ParseErrorBadNetworkId()
        self.id = rawbyte

    def __str__(self):
        return chr(self.id)


class message_type:
    def __init__(self, data):
        self.parse_type(data)

    def parse_type(self, data):
        if (data != 2):
            raise ParseErrorBadMessageType
        self.type = data

    def __str__(self):
        return str(self.type)

class message_header:

    def __init__(self, net_id, versions, msg_type):
        self.ext = []
        self.net_id = net_id
        self.ver_max = versions[0]
        self.ver_using = versions[1]
        self.ver_min = versions[2]
        self.msg_type = msg_type
        # TODO: extensions

    def serialise_header(self):
        header = b""
        header += ord('R').to_bytes(1, "big")
        header += ord(self.net_id).to_bytes(1, "big")
        # FIXME: you have the version data, use it
        for i in range(0, 3):
            header += (34).to_bytes(1, "big")
        header += self.message_type.to_bytes(1, "big")
        header += (00).to_bytes(1, "big")
        header += (00).to_bytes(1, "big")
        return header

    # this need to become a class method
    def parse_header(self, data):
        if data[0] != ord('R'):
            raise ParseErrorBadMagicNumber()
        self.net_id = network_id(data[1])
        self.ver_max = data[2]
        self.ver_using = data[3]
        self.ver_min = data[4]
        self.msg_type = message_type(data[5])

    def __str__(self):
        str  = "NetID:%s, "    % self.net_id
        str += "VerMax:%s, "   % self.ver_max
        str += "VerUsing:%s, " % self.ver_using
        str += "VerMin:%s, "   % self.ver_min
        str += "MsgType:%s, "    % self.msg_type
        str += "Extensions:%s, %s" % (self.ext[0], self.ext[1])
        return str

class ipv6addresss:
    def __init__(self, data):
        self.data = data
        self.parse_address()

    def parse_address(self):
        if len(self.data) < 16:
            raise ParseErrorBadIPv6
        address_int = int.from_bytes(self.data[0:16], "big")
        self.address = ipaddress.IPv6Address(address_int)

    def __str__(self):
        return str(self.address)


# A class representing a peer, stores its address, port and provides the means to convert
# it into a readable string format
class peer_address:
    def __init__(self,ip, port):
        self.ip = ip
        self.port = port

    def __str__(self):
        string = "["
        string += str(self.ip) + "]:"
        string += str(self.port)
        return string

# Creates, stores and manages all of the peer_address objects (from the raw data)
class peers():
    def __init__(self, data):
        if len(data) % 18 != 0:
            raise ParseErrorBadMessageBody
        self.data = data
        self.peers = []
        self.parse_peers()

    def parse_peers(self):
        no_of_peers = int(len(self.data) / 18)
        start_index = 0
        end_index = 18
        for i in range(0, no_of_peers):
            ip = ipv6addresss(self.data[start_index:end_index-2])
            port = int.from_bytes(self.data[end_index-2:end_index], "little")
            p = peer_address(ip, port)
            self.peers.append(p)
            start_index = end_index
            end_index += 18

    def __str__(self):
        string = ""
        for i in range(0, len(self.peers)):
            string += "Peer %d:" % (i+1)
            string += str(self.peers[i])
            string += "\n"
        return string


input_stream = "524122222202000000000000000000000000ffff9df5d11ef0d200000000000000000000ffff18fb4f64f0d200000000000000000000ffff405a48c2f0d200000000000000000000ffff95382eecf0d200000000000000000000ffff2e044970f0d200000000000000000000ffff68cdcd53f0d200000000000000000000ffffb3a2bdeff0d200000000000000000000ffff74ca6b61f0d2"
data = binascii.unhexlify(input_stream)
h = message_header(data)
b = peers(data[8:])
print(h)
print(b)
