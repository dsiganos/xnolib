from deserialisng import message_header, peers
from ipaddress import IPv6Address

class message:
    def __init__(self, network_id, type):
        self.network_id = network_id
        self.message_type = type
        self.peers = []

    def serialise_header(self):
        header = b""
        header += ord('R').to_bytes(1, "big")
        header += ord(self.network_id).to_bytes(1, "big")
        for i in range(0, 3):
            header += (34).to_bytes(1, "big")
        header += self.message_type.to_bytes(1, "big")
        header += (00).to_bytes(1, "big")
        header += (00).to_bytes(1, "big")
        return header

    def serialise_peers(self):
        ip1 = IPv6Address("9499:9e4a:798a:c0cf:a7d8:4b21:28fc:9a60")
        ip2 = IPv6Address("9499:9e4a:798a:c0cf:a7d8:4321:28fc:9aab")
        ip3 = IPv6Address("b0e3:be9e:561d:f25a:4f1a:5ecd:5bb7:3ec9")
        ip4 = IPv6Address("765c:3365:3411:ea58:4f63:38aa:d466:1ea8")
        port = (5400).to_bytes(2, "little")
        body = b""
        body += ip1.packed + port
        body += ip2.packed + port
        body += ip3.packed + port
        body += ip4.packed + port
        return body



m = message('A', 2)
h = message_header(m.serialise_header())
p = peers(m.serialise_peers())
print(h)
print(p)
