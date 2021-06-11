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

class network_id:
    def __init__(self, rawbyte):
        self.parse_header(int(rawbyte))

    def parse_header(self, rawbyte):
        #print(rawbyte)
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
            raise ParseErrorBadMessageType()
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
        if data[0] != ord('R'):
            raise ParseErrorBadMagicNumber()
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

    def __str__(self):
        str  = "NetID:%s, "    % self.net_id
        str += "VerMax:%s, "   % self.ver_max
        str += "VerUsing:%s, " % self.ver_using
        str += "VerMin:%s, "   % self.ver_min
        str += "MsgType:%s, "    % self.msg_type
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
    def __init__(self,ip, port):
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

    def __str__(self):
        string = ""
        for i in range(0, len(self.peers)):
            string += "Peer %d:" % (i+1)
            string += str(self.peers[i])
            string += "\n"
        return string
