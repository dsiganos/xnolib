#!/bin/env python3

import struct
import argparse

from pynanocoin import *
from msg_handshake import *
import peercrawler


class telemetry_req:
    def __init__(self, ctx):
        self.header = message_header(ctx['net_id'], [18, 18, 18], message_type(message_type_enum.telemetry_req), 0)

    def serialise(self):
        return self.header.serialise_header()


class telemetry_ack:
    def __init__(self, hdr, signature, node_id, block_count, cemented_count,
                 unchecked_count, account_count, bandwidth_cap, uptime,
                 peer_count, protocol_ver, genesis_hash, major_ver,
                 minor_ver, patch_ver, pre_release_ver, maker_ver,
                 timestamp, active_difficulty):
        self.hdr = hdr
        self.sig = signature
        self.node_id = node_id
        self.block_count = block_count
        self.cemented_count = cemented_count
        self.unchecked_count = unchecked_count
        self.account_count = account_count
        self.bandwidth_cap = bandwidth_cap
        self.uptime = uptime
        self.peer_count = peer_count
        self.protocol_ver = protocol_ver
        self.genesis_hash = genesis_hash
        self.major_ver = major_ver
        self.minor_ver = minor_ver
        self.patch_ver = patch_ver
        self.pre_release_ver = pre_release_ver
        self.maker_ver = maker_ver
        self.timestamp = timestamp
        self.active_difficulty = active_difficulty

    def __str__(self):
        string =  "Signature: %s\n" % hexlify(self.sig)
        string += "Node ID: %s\n" % hexlify(self.node_id)
        string += "         %s\n" % acctools.to_account_addr(self.node_id, 'node_')
        string += "Block Count: %d\n" % self.block_count
        string += "Cemented Count: %d\n" % self.cemented_count
        string += "Unchecked Count: %d\n" % self.unchecked_count
        string += "Account Count: %d\n" % self.account_count
        string += "Bandwidth Cap: %d\n" % self.bandwidth_cap
        string += "Uptime: %d s\n" % self.uptime
        string += "Peer Count: %d\n" % self.peer_count
        string += "Protocol Version: %d\n" % self.protocol_ver
        string += "Genesis Hash: %s\n" % hexlify(self.genesis_hash)
        string += "Major Version: %d\n" % self.major_ver
        string += "Minor Version: %d\n" % self.minor_ver
        string += "Patch Version: %d\n" % self.patch_ver
        string += "Pre-release Version: %d\n" % self.pre_release_ver
        string += "Maker Version: %d\n" % self.maker_ver
        string += "Timestamp: %d ms\n" % self.timestamp
        string += "Active Difficulty: %s (%s)" % (self.active_difficulty, hex(self.active_difficulty))
        return string

    def get_sw_version(self):
        return "%s.%s.%s.%s" % (self.major_ver, self.minor_ver, self.patch_ver, self.pre_release_ver)

    @classmethod
    def parse(self, hdr, data):
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
        return telemetry_ack(hdr, sig, node_id, block_count, cemented_count, unchecked_count,
                             account_count, bandwidth_cap, uptime, peer_count, protocol_ver,
                             genesis_hash, major_ver, minor_ver, patch_ver, pre_release_ver, maker_ver,
                             timestamp, active_difficulty)


def parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')


    group1 = parser.add_mutually_exclusive_group(required=False)
    group1.add_argument('-a', '--allpeers', action="store_true", default=False,
                        help='contact all known peers for telemetry')
    group1.add_argument('-p', '--peer',
                        help='peer to contact for frontiers (if not set, one is randomly selected using DNS)')

    return parser.parse_args()


def do_telemetry_req(ctx, peeraddr, peerport):
    with get_connected_socket_endpoint(peeraddr, peerport) as s:
        node_handshake_id.perform_handshake_exchange(ctx, s)

        req = telemetry_req(ctx)
        s.send(req.serialise())

        hdr, data = get_next_hdr_payload(s)
        while hdr.msg_type != message_type(13):
            hdr, data = get_next_hdr_payload(s)
        print(hdr)

        resp = telemetry_ack.parse(hdr, data)
        print(resp)


def main():
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx

    peer_tuples = []

    if args.peer:
        peer_tuples.append(parse_endpoint(args.peer, default_port=ctx['peerport']))
    elif args.allpeers:
        _, peers = peercrawler.get_peers_from_service(ctx)
        for peer in peers:
            peer_tuples.append((str(peer.ip), peer.port))
    else:
        peer = peercrawler.get_random_peer(ctx, lambda p: p.score >= 1000)
        peer_tuples.append((str(peer.ip), peer.port))

    for peeraddr, peerport in peer_tuples:
        print('connecting to %s:%s' % (peeraddr, peerport))
        try:
            do_telemetry_req(ctx, peeraddr, peerport)
        except (OSError, PyNanoCoinException) as e:
            print('Exception %s: %s' % (type(e), e))
            if (not args.allpeers):
                raise


if __name__ == "__main__":
    main()
