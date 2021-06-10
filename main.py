import binascii

class ParseErrorBadMagicNumber(Exception):
    pass

class ParseErrorBadNetworkId(Exception):
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

class message_header:

    def __init__(self, data):
        self.parse_header(data)

    def parse_header(self, data):
        if data[0] != ord('R'):
            raise ParseErrorBadMagicNumber()
        self.net_id = network_id(data[1])
        self.ver_max = data[2]
        self.ver_using = data[3]
        self.ver_min = data[4]
        self.msg_type = data[5]
        # TODO: extensions

    def __str__(self):
        str  = "NetID:%s, "    % self.net_id
        str += "VerMax:%s, "   % self.ver_max
        str += "VerUsing:%s, " % self.ver_using
        str += "VerMin:%s, "   % self.ver_min
        str += "MsgType:%s"    % self.msg_type
        # TODO: extensions
        return str

input_stream = "524212121202000000000000000000000000ffff9df5d11ef0d200000000000000000000ffff18fb4f64f0d200000000000000000000ffff405a48c2f0d200000000000000000000ffff95382eecf0d200000000000000000000ffff2e044970f0d200000000000000000000ffff68cdcd53f0d200000000000000000000ffffb3a2bdeff0d200000000000000000000ffff74ca6b61f0d2"

data = binascii.unhexlify(input_stream)
h = message_header(data)
print(h)
