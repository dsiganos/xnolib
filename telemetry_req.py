#!/bin/env python3

import argparse
from pynanocoin import *
from msg_handshake import *
from peercrawler import get_initial_connected_socket, get_peers_from_service


class telemetry_req:
    def __init__(self, ctx):
        self.header = message_header(ctx['net_id'], [18, 18, 18], message_type(message_type_enum.telemetry_req), 0)

    def serialise(self):
        return self.header.serialise_header()


class telemetry_ack:
    def __init__(self, signature, node_id, block_count, cemented_count,
                 unchecked_count, account_count, bandwidth_cap, uptime,
                 peer_count, protocol_ver, genesis_hash, major_ver,
                 minor_ver, patch_ver, pre_release_ver, maker_ver,
                 timestamp, active_difficulty):
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

    @classmethod
    def parse(self, data):
        if len(data) != 202:
            raise BadTelemetryReply('message len not 202, data=%s', data)
        sig = data[0:64]
        node_id = data[64:96]
        block_count = int.from_bytes(data[96:104], "big")
        cemented_count = int.from_bytes(data[104:112], "big")
        unchecked_count = int.from_bytes(data[112:120], "big")
        account_count = int.from_bytes(data[120:128], "big")
        bandwidth_cap = int.from_bytes(data[128:136], "big")
        uptime = int.from_bytes(data[136:144], "big")
        peer_count = int.from_bytes(data[144:148], "big")
        protocol_ver = data[148]
        genesis_hash = data[149:181]
        major_ver = data[181]
        minor_ver = data[182]
        patch_ver = data[183]
        pre_release_ver = data[184]
        maker_ver = data[185]
        timestamp = int.from_bytes(data[186:194], "big")
        active_difficulty = int.from_bytes(data[194:202], "big")
        return telemetry_ack(sig, node_id, block_count, cemented_count, unchecked_count,
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

    parser.add_argument('-p', '--peer',
                        help='peer to contact for frontiers (if not set, one is randomly selected using DNS)')
    return parser.parse_args()


def main():
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx

    # Peer provided in argparse args
    if args.peer is not None:
        peeraddr, peerport = parse_endpoint(args.peer)

        if peerport is None:
            peerport = ctx['peerport']

        s = get_connected_socket_endpoint(peeraddr, peerport)

    # Peer selected from peer service
    else:

        hdr, peers = get_peers_from_service(ctx)
        peers = list(filter(lambda p: p.score == 1000, peers))

        for peer in peers:
            try:
                s = get_connected_socket_endpoint(str(peer.ip), peer.port)
                break
            except (socket.error, OSError) as err:
                continue

    assert s

    with s:

        perform_handshake_exchange(ctx, s)

        req = telemetry_req(ctx)
        s.send(req.serialise())

        hdr, data = get_next_hdr_payload(s)
        while hdr.msg_type != message_type(13):
            hdr, data = get_next_hdr_payload(s)
        print(hdr)

        resp = telemetry_ack.parse(data)
        print(resp)


if __name__ == "__main__":
    main()
