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

    def __init__(self, data):
        self.ext = []
        self.parse_header(data)

    def parse_header(self, data):
        if data[0] != ord('R'):
            raise ParseErrorBadMagicNumber()
        self.net_id = network_id(data[1])
        self.ver_max = data[2]
        self.ver_using = data[3]
        self.ver_min = data[4]
        self.msg_type = message_type(data[5])
        self.ext.append(data[6])
        self.ext.append(data[7])


    def __str__(self):
        str  = "NetID:%s, "    % self.net_id
        str += "VerMax:%s, "   % self.ver_max
        str += "VerUsing:%s, " % self.ver_using
        str += "VerMin:%s, "   % self.ver_min
        str += "MsgType:%s, "    % self.msg_type
        str += "Extensions:%s, %s" % (self.ext[0], self.ext[1])
        # TODO: extensions
        return str

class ipv6addresss:
    def __init__(self, data):
        self.data = data
        self.parse_address()

    def parse_address(self):
        if len(data) < 16:
            raise ParseErrorBadIPv6
        address_int = int.from_bytes(self.data[0:16], "big")
        self.address = ipaddress.IPv6Address(address_int)

    def __str__(self):
        return str(self.address)


class message_body():
    def __init__(self, data):
        if len(data) < 18:
            raise ParseErrorBadMessageBody
        self.data = data
        self.parse_peer()

    def parse_peer(self):
        self.ip = ipv6addresss(data[:16])
        self.port = int.from_bytes(data[16:18], "little")

    def __str__(self):
        string = "Peer: ["
        string += str(self.ip) + "]:"
        string += str(self.port)
        return string




input_stream = "524212121202000000000000000000000000ffff9df5d11ef0d200000000000000000000ffff18fb4f64f0d200000000000000000000ffff405a48c2f0d200000000000000000000ffff95382eecf0d200000000000000000000ffff2e044970f0d200000000000000000000ffff68cdcd53f0d200000000000000000000ffffb3a2bdeff0d200000000000000000000ffff74ca6b61f0d2"

data = binascii.unhexlify(input_stream)
h = message_header(data)
b = message_body(data[8:26])
print(h)
print(b)
