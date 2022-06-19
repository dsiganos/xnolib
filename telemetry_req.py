#!/bin/env python3

import struct
import argparse

from pynanocoin import *
from msg_handshake import *
import peercrawler


class telemetry_req:
    def __init__(self, ctx: dict):
        self.header = message_header(ctx['net_id'], [18, 18, 18], message_type(message_type_enum.telemetry_req), 0)

    def serialise(self) -> bytes:
        return self.header.serialise_header()


class telemetry_ack:
    def __init__(self, hdr: message_header, signature: bytes, node_id: bytes, block_count: int, cemented_count: int,
                 unchecked_count: int, account_count: int, bandwidth_cap: int,
                 peer_count: int, protocol_ver: int, uptime: int, genesis_hash: bytes, major_ver: int,
                 minor_ver: int, patch_ver: int, pre_release_ver: int, maker_ver: int,
                 timestamp: int, active_difficulty: int):
        self.hdr = hdr
        self.sig_verified = False
        self.sig = signature
        self.node_id = node_id
        self.block_count = block_count
        self.cemented_count = cemented_count
        self.unchecked_count = unchecked_count
        self.account_count = account_count
        self.bandwidth_cap = bandwidth_cap
        self.peer_count = peer_count
        self.protocol_ver = protocol_ver
        self.uptime = uptime
        self.genesis_hash = genesis_hash
        self.major_ver = major_ver
        self.minor_ver = minor_ver
        self.patch_ver = patch_ver
        self.pre_release_ver = pre_release_ver
        self.maker_ver = maker_ver
        self.timestamp = timestamp
        self.active_difficulty = active_difficulty

    def __str__(self):
        string =  'Signature: %s\n' % hexlify(self.sig)
        string += 'Node ID: %s\n' % hexlify(self.node_id)
        string += '         %s\n' % acctools.to_account_addr(self.node_id, 'node_')
        string += 'Block Count: %d\n' % self.block_count
        string += 'Cemented Count: %d\n' % self.cemented_count
        string += 'Unchecked Count: %d\n' % self.unchecked_count
        string += 'Account Count: %d\n' % self.account_count
        string += 'Bandwidth Cap: %d\n' % self.bandwidth_cap
        string += 'Peer Count: %d\n' % self.peer_count
        string += 'Protocol Version: %d\n' % self.protocol_ver
        string += 'Uptime: %d s\n' % self.uptime
        string += 'Genesis Hash: %s\n' % hexlify(self.genesis_hash)
        string += 'Major Version: %d\n' % self.major_ver
        string += 'Minor Version: %d\n' % self.minor_ver
        string += 'Patch Version: %d\n' % self.patch_ver
        string += 'Pre-release Version: %d\n' % self.pre_release_ver
        string += 'Maker Version: %d\n' % self.maker_ver
        string += 'Timestamp: %d ms\n' % self.timestamp
        string += 'Active Difficulty: %s (%s)\n' % (self.active_difficulty, hex(self.active_difficulty))
        string += '%s signature' % 'Valid' if self.sig_verified else 'INVALID'
        return string

    def get_sw_version(self) -> str:
        return '%s.%s.%s.%s' % (self.major_ver, self.minor_ver, self.patch_ver, self.pre_release_ver)

    def serialize_without_signature(self) -> bytes:
        data = struct.pack('>32sQQQQQIBQ32sBBBBBQQ', \
            self.node_id, \
            self.block_count, \
            self.cemented_count, \
            self.unchecked_count, \
            self.account_count, \
            self.bandwidth_cap, \
            self.peer_count, \
            self.protocol_ver, \
            self.uptime, \
            self.genesis_hash, \
            self.major_ver, \
            self.minor_ver, \
            self.patch_ver, \
            self.pre_release_ver, \
            self.maker_ver, \
            self.timestamp, \
            self.active_difficulty)
        return data

    def serialize(self) -> bytes:
        data = self.hdr.serialise_header()
        data += struct.pack('64s', self.sig)
        data += self.serialize_without_signature()
        return data

    def sign(self, signing_key: ed25519_blake2b.keys.SigningKey) -> None:
        self.sig = signing_key.sign(self.serialize_without_signature())

    @classmethod
    def parse(self, hdr: message_header, data: bytes):
        if len(data) != 202:
            raise BadTelemetryReply('message len not 202, data=%s', data)
        unpacked = struct.unpack('>64s32sQQQQQIBQ32sBBBBBQQ', data)
        sig                 = unpacked[0]
        node_id             = unpacked[1]
        block_count         = unpacked[2]
        cemented_count      = unpacked[3]
        unchecked_count     = unpacked[4]
        account_count       = unpacked[5]
        bandwidth_cap       = unpacked[6]
        peer_count          = unpacked[7]
        protocol_ver        = unpacked[8]
        uptime              = unpacked[9]
        genesis_hash        = unpacked[10]
        major_ver           = unpacked[11]
        minor_ver           = unpacked[12]
        patch_ver           = unpacked[13]
        pre_release_ver     = unpacked[14]
        maker_ver           = unpacked[15]
        timestamp           = unpacked[16]
        active_difficulty   = unpacked[17]
        tack = telemetry_ack(hdr, sig, node_id, block_count, cemented_count, unchecked_count,
                             account_count, bandwidth_cap, peer_count, protocol_ver, uptime,
                             genesis_hash, major_ver, minor_ver, patch_ver, pre_release_ver, maker_ver,
                             timestamp, active_difficulty)
        tack.sig_verified = verify(data[64:], data[0:64], node_id)
        return tack

    @classmethod
    def from_json(self, json_tel: dict):
        return telemetry_ack(message_header.from_json(json_tel['hdr']),
                             binascii.unhexlify(json_tel['sig']),
                             binascii.unhexlify(json_tel['node_id']),
                             json_tel['block_count'],
                             json_tel['cemented_count'],
                             json_tel['unchecked_count'],
                             json_tel['account_count'],
                             json_tel['bandwidth_cap'],
                             json_tel['peer_count'],
                             json_tel['protocol_ver'],
                             json_tel['uptime'],
                             binascii.unhexlify(json_tel['genesis_hash']),
                             json_tel['major_ver'],
                             json_tel['minor_ver'],
                             json_tel['patch_ver'],
                             json_tel['pre_release_ver'],
                             json_tel['maker_ver'],
                             json_tel['timestamp'],
                             json_tel['active_difficulty']
                             )


def parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')


    group1 = parser.add_mutually_exclusive_group(required=False)
    group1.add_argument('-a', '--allpeers', action='store_true', default=False,
                        help='contact all known peers for telemetry')
    group1.add_argument('-p', '--peer',
                        help='peer to contact for frontiers (if not set, one is randomly selected using DNS)')

    return parser.parse_args()


def do_telemetry_req(ctx: dict, peeraddr: str, peerport: int) -> None:
    with get_connected_socket_endpoint(peeraddr, peerport) as s:
        signing_key, verifying_key = node_handshake_id.keypair()
        peer_id = node_handshake_id.perform_handshake_exchange(ctx, s, signing_key, verifying_key)
        print('Local Node ID: %s' % acctools.to_account_addr(verifying_key.to_bytes(), prefix='node_'))
        print('Peer  Node ID: %s' % acctools.to_account_addr(peer_id, prefix='node_'))

        req = telemetry_req(ctx)
        s.send(req.serialise())

        hdr, data = get_next_hdr_payload(s)
        while hdr.msg_type != message_type(13):
            hdr, data = get_next_hdr_payload(s)
        print(hdr)

        resp = telemetry_ack.parse(hdr, data)
        print(resp)


def main() -> None:
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx

    peer_tuples = []

    if args.peer:
        peer_tuples.append(parse_endpoint(args.peer, default_port=ctx['peerport']))
    elif args.allpeers:
        peers = peercrawler.get_peers_from_service(ctx)
        for peer in peers:
            peer_tuples.append((str(peer.ip), peer.port))
    else:
        peer = peercrawler.get_random_peer(ctx, lambda p: p.score >= 1000)
        peer_tuples.append((str(peer.ip), peer.port))

    for peeraddr, peerport in peer_tuples:
        print('Connecting to %s:%s' % (peeraddr, peerport))
        try:
            do_telemetry_req(ctx, peeraddr, peerport)
        except (OSError, PyNanoCoinException) as e:
            print('Exception %s: %s' % (type(e), e))
            if (not args.allpeers):
                raise


class TestTelemetry(unittest.TestCase):
    def test_telemetry_ack_from_json(self):
        example_json = """
{
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
}"""
        tel = telemetry_ack.from_json(json.loads(example_json))

        self.assertEqual(tel.sig,
                         binascii.unhexlify("C019739E66E763FE1673BFE850867972E73F896D5F7B452FB259A0281A2D7168BC1CF7894B7BA7BD6DF97BA5FB5000D97A192AAF0D455B3CFFC7819CC936280B"))
        self.assertEqual(tel.node_id, binascii.unhexlify("F3D02EFA6F40123FD2B787B1CB5982F39A4485CC25A222C416FE6B9B61515707"))
        self.assertEqual(tel.block_count, 158979360)
        self.assertEqual(tel.cemented_count, 158658193)
        self.assertEqual(tel.unchecked_count, 7)
        self.assertEqual(tel.account_count, 29645164)
        self.assertEqual(tel.bandwidth_cap, 0)
        self.assertEqual(tel.peer_count, 228)
        self.assertEqual(tel.protocol_ver, 18)
        self.assertEqual(tel.uptime, 884)
        self.assertEqual(tel.genesis_hash,
                         binascii.unhexlify("991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948"))
        self.assertEqual(tel.major_ver, 23)
        self.assertEqual(tel.minor_ver, 4)
        self.assertEqual(tel.patch_ver, 0)
        self.assertEqual(tel.pre_release_ver, 99)
        self.assertEqual(tel.maker_ver, 111)
        self.assertEqual(tel.timestamp, 1655358225428)
        self.assertEqual(tel.active_difficulty, 18446744039349813248)


if __name__ == '__main__':
    main()
