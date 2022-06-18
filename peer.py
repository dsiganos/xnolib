import binascii
import ipaddress
import time
from typing import Union

from _logger import VERBOSE, get_logger
from net import parse_ipv6
import telemetry_req

logger = get_logger()

class ip_addr:
    def __init__(self, ipv6: Union[str, ipaddress.IPv6Address] = ipaddress.IPv6Address(0)):
        if isinstance(ipv6, str):
            self.ipv6 = ipaddress.IPv6Address(ipv6)
        else:
            self.ipv6 = ipv6
        assert isinstance(self.ipv6, ipaddress.IPv6Address)

    @classmethod
    def from_string(cls, ipstr: str):
        assert isinstance(ipstr, str)
        a = ipaddress.ip_address(ipstr)
        if a.version == 4:
            ipstr = '::ffff:' + str(a)
        ipv6 = ipaddress.IPv6Address(ipstr)
        return ip_addr(ipv6)

    def serialise(self) -> bytes:
        return self.ipv6.packed

    def is_ipv4(self) -> bool:
        return self.ipv6.ipv4_mapped is not None

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


# A class representing a peer, stores its address, port and provides the means to convert
# it into a readable string format
class Peer:
    def __init__(self, ip: ip_addr = ip_addr(), port: int = 0, score: int = -1, is_voting: bool = False,
                 last_seen: int = int(time.time()), incoming: bool =False):
        assert isinstance(ip, ip_addr)
        self.ip = ip
        self.port = port
        self.peer_id = None
        self.is_voting = is_voting
        self.telemetry = None
        self.aux = {}
        self.last_seen = last_seen
        self.incoming = incoming

        # sideband info, not used for equality and hashing
        self.score = score

    def serialise(self) -> bytes:
        data = b""
        data += self.ip.serialise()
        data += self.port.to_bytes(2, "little")
        return data

    def deduct_score(self, score: int) -> None:
        self.score = max(0, self.score - score)

    def merge(self, peer: "Peer") -> None:
        assert self == peer

        self.last_seen = peer.last_seen

        if peer.telemetry is not None:
            self.telemetry = peer.telemetry
        if peer.incoming is False:
            self.incoming = False
        if peer.is_voting is True:
            self.is_voting = True

        logger.log(VERBOSE, f"Merged peer {peer}")

    @classmethod
    def parse_peer(cls, data: bytes):
        assert(len(data) == 18)
        ip = parse_ipv6(data[0:16])
        port = int.from_bytes(data[16:], "little")
        return Peer(ip_addr(ip), port)

    @classmethod
    def from_json(self, json_peer):
        # Add 'incoming' argument when peer service code gets updated
        peer = Peer(ip_addr(json_peer['ip']), json_peer['port'], json_peer['score'], json_peer['is_voting'],
                    json_peer['last_seen'])
        if json_peer['telemetry'] is not None:
            peer.telemetry = telemetry_req.telemetry_ack.from_json(json_peer['telemetry'])
        if json_peer['peer_id']:
            peer.peer_id = binascii.unhexlify(json_peer['peer_id'])
        return peer

    def __str__(self):
        sw_ver = ''
        if self.telemetry:
            sw_ver = ' v' + self.telemetry.get_sw_version()
        return '%s:%s (score:%s, is_voting: %s%s)' % (str(self.ip), self.port, self.score, self.is_voting, sw_ver)

    def __eq__(self, other):
        return self.ip == other.ip and self.port == other.port

    def __hash__(self):
        return hash((self.ip, self.port))