import binascii
import ipaddress
import json
import time
import unittest
from typing import Union

from _logger import VERBOSE, get_logger
from net import parse_ipv6

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
        from telemetry_req import telemetry_ack
        # Add 'incoming' argument when peer service code gets updated
        peer = Peer(ip_addr(json_peer['ip']), json_peer['port'], json_peer['score'], json_peer['is_voting'],
                    json_peer['last_seen'])
        if json_peer['telemetry'] is not None:
            peer.telemetry = telemetry_ack.from_json(json_peer['telemetry'])
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


class TestPeer(unittest.TestCase):
    def test_peer_from_json(self):
        example_json = """{
    "ip": "::ffff:135.181.141.91",
    "port": 7075,
    "peer_id": "F3D02EFA6F40123FD2B787B1CB5982F39A4485CC25A222C416FE6B9B61515707",
    "is_voting": false,
    "telemetry": {
        "hdr": {
            "ext": 202,
            "net_id": 67,
            "ver_max": 18,
            "ver_using": 18,
            "ver_min": 18,
            "msg_type": 13
        },
        "sig_verified": true,
        "sig": "C019739E66E763FE1673BFE850867972E73F896D5F7B452FB259A0281A2D7168BC1CF7894B7BA7BD6DF97BA5FB5000D97A192AAF0D455B3CFFC7819CC936280B",
        "node_id": "F3D02EFA6F40123FD2B787B1CB5982F39A4485CC25A222C416FE6B9B61515707",
        "block_count": 158979360,
        "cemented_count": 158658193,
        "unchecked_count": 7,
        "account_count": 29645164,
        "bandwidth_cap": 0,
        "peer_count": 228,
        "protocol_ver": 18,
        "uptime": 884,
        "genesis_hash": "991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948",
        "major_ver": 23,
        "minor_ver": 4,
        "patch_ver": 0,
        "pre_release_ver": 99,
        "maker_ver": 111,
        "timestamp": 1655358225428,
        "active_difficulty": 18446744039349813248
    },
    "aux": {},
    "last_seen": 1655358541,
    "score": 1000
}
"""
        json_peer = json.loads(example_json)
        peer = Peer.from_json(json_peer)

        self.assertEqual(peer.ip, ip_addr("::ffff:135.181.141.91"))
        self.assertEqual(peer.port, 7075)
        self.assertEqual(peer.is_voting, False)
        self.assertEqual(peer.aux, {})
        self.assertEqual(peer.last_seen, 1655358541)
        self.assertEqual(peer.score, 1000)
