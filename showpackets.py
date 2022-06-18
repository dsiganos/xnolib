#!/bin/env python3
import time
import socket
import random
import argparse

from pynanocoin import *
from msg_handshake import *
from peercrawler import *
from confirm_req import *
from confirm_ack import confirm_ack
from msg_publish import *
from frontier_request import *
from bulk_pull_account import *
from telemetry_req import *
import acctools


def parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')

    parser.add_argument('--peer',
                        help='peer to contact')

    parser.add_argument('-k', '--keepalive', action='store_true', default=False,
                        help='indicates the script to show keepalives')
    parser.add_argument('-c', '--confirm_req', action='store_true', default=False,
                        help='indicated the script to show confirm requests')
    parser.add_argument('-C', '--confirm_ack', action='store_true', default=False,
                        help='indicates the script to show confirm acks')
    parser.add_argument('-p', '--publish', action='store_true', default=False,
                        help='indicates to show msg_publish packets')
    parser.add_argument('-P', '--bulk_pull', action='store_true', default=False,
                        help='indicates to show bulk_pull packets')
    parser.add_argument('-B', '--bulk_push', action='store_true', default=False,
                        help='indicates to show bulk_push packets')
    parser.add_argument('-f', '--frontier_req', action='store_true', default=False,
                        help='indicates to show frontier_req packets')
    parser.add_argument('-H', '--handshake', action='store_true', default=False,
                        help='indicates to show node_id_handshake packets')
    parser.add_argument('-a', '--bulk_pull_acc', action='store_true', default=False,
                        help='indicates to show bulk_pull_account packets')
    parser.add_argument('--tr', dest='telemetry_req', action='store_true', default=False,
                        help='indicates to show telemetry_req packets')
    parser.add_argument('--ta', dest='telemetry_ack', action='store_true', default=False,
                        help='indicates to show telemetry_ack packets')
    parser.add_argument('--all', action='store_true', default=False,
                        help='indicates to show all packets')

    return parser.parse_args()


functions = {
    message_type_enum.keepalive: message_keepalive.parse_payload,
    message_type_enum.publish: msg_publish.parse,
    message_type_enum.confirm_req: confirm_req.confirm_req.parse,
    message_type_enum.confirm_ack: confirm_ack.parse,
    message_type_enum.bulk_pull: message_bulk_pull.parse,
    message_type_enum.bulk_push: bulk_push.parse,
    message_type_enum.frontier_req: frontier_request.parse,
    message_type_enum.node_id_handshake: node_handshake_id.parse,
    message_type_enum.bulk_pull_account: bulk_pull_account.parse,
    message_type_enum.telemetry_req: lambda hdr, payload: hdr,
    message_type_enum.telemetry_ack: telemetry_ack.parse,
    message_type_enum.not_a_block: lambda hdr, payload: hdr
}


def set_functions(args) -> None:
    if args.all:
        return
    if not args.keepalive:
        functions[message_type_enum.keepalive] = None
    if not args.publish:
        functions[message_type_enum.publish] = None
    if not args.confirm_req:
        functions[message_type_enum.confirm_req] = None
    if not args.confirm_ack:
        functions[message_type_enum.confirm_ack] = None
    if not args.bulk_pull:
        functions[message_type_enum.bulk_pull] = None
    if not args.bulk_push:
        functions[message_type_enum.bulk_push] = None
    if not args.frontier_req:
        functions[message_type_enum.frontier_req] = None
    if not args.handshake:
        functions[message_type_enum.node_id_handshake] = None
    if not args.bulk_pull_acc:
        functions[message_type_enum.bulk_pull_account] = None
    if not args.telemetry_req:
        functions[message_type_enum.telemetry_req] = None
    if not args.telemetry_ack:
        functions[message_type_enum.telemetry_ack] = None


def make_telemetry_ack(ctx: dict, signing_key: ed25519_blake2b.keys.SigningKey,
                                  verifying_key: ed25519_blake2b.keys.VerifyingKey) -> telemetry_ack:
    tel_ack_hdr = message_header(ctx['net_id'], [18, 18, 18], message_type(message_type_enum.telemetry_ack), 202)
    telem_ack = telemetry_ack(
        hdr=tel_ack_hdr,
        signature=None,
        node_id=verifying_key.to_bytes(),
        block_count=10,
        cemented_count=5,
        unchecked_count=7,
        account_count=500,
        bandwidth_cap=10485760,
        peer_count=22,
        protocol_ver=18,
        uptime=3,
        genesis_hash=ctx['genesis_block']['hash'],
        major_ver=77,
        minor_ver=77,
        patch_ver=77,
        pre_release_ver=77,
        maker_ver=77,
        timestamp=4,
        active_difficulty=0xfffffff800000000
    )
    telem_ack.sign(signing_key)
    return telem_ack


def main() -> None:
    args = parse_args()
    set_functions(args)

    ctx = livectx
    if args.beta: ctx = betactx
    elif args.test: ctx = testctx

    if args.peer:
        peeraddr, peerport = parse_endpoint(args.peer, default_port=ctx['peerport'])
    else:
        peer = get_random_peer(ctx, lambda p: p.score >= 1000 and p.is_voting)
        peeraddr, peerport = str(peer.ip), peer.port

    print('Connecting to [%s]:%s' % (peeraddr, peerport))
    with get_connected_socket_endpoint(peeraddr, peerport) as s:
        s.settimeout(10)
        signing_key, verifying_key = node_handshake_id.keypair()
        peer_id = node_handshake_id.perform_handshake_exchange(ctx, s, signing_key, verifying_key)
        print('Local Node ID: %s' % acctools.to_account_addr(verifying_key.to_bytes(), prefix='node_'))
        print('Peer  Node ID: %s' % acctools.to_account_addr(peer_id, prefix='node_'))

        # send a keepalive, this is not necessary, just doing it as an example
        hdr = message_header(ctx['net_id'], [18, 18, 18], message_type(message_type_enum.keepalive), 0)
        keepalive = message_keepalive(hdr)
        req = keepalive.serialise()
        s.send(req)

        # do a telemetry request
        s.send(telemetry_req(ctx).serialise())

        # now we are waiting for keepalives, so set a long timeout (60 minutes)
        s.settimeout(60 * 60)

        # create a telemetry response message to send, this helps to keep the connection open long term
        # if the peer does not receive telemetry responses, it eventually closes the socket
        telem_ack = make_telemetry_ack(ctx, signing_key, verifying_key)

        while True:
            hdr, payload = get_next_hdr_payload(s)

            if functions[hdr.msg_type.type] is not None:
                print(functions[hdr.msg_type.type](hdr, payload))

            if hdr.msg_type.type == message_type_enum.telemetry_req:
                s.send(telem_ack.serialize())


if __name__ == "__main__":
    main()
