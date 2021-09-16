#!/bin/env python3
import time
import socket
import random
import argparse

from pynanocoin import *
from msg_handshake import *
from peercrawler import *
from confirm_req import *
from msg_publish import *
from frontier_request import *
from bulk_pull_account import *
from telemetry_req import *


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

def set_functions(args):
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


def main():
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
        perform_handshake_exchange(ctx, s)

        # send a keepalive, this is not necessary, just doing it as an example
        hdr = message_header(ctx['net_id'], [18, 18, 18], message_type(message_type_enum.keepalive), 0)
        keepalive = message_keepalive(hdr)
        req = keepalive.serialise()
        s.send(req)

        # now we are waiting for keepalives, so set a long timeout (60 minutes)
        s.settimeout(60 * 60)

        while True:
            hdr, payload = get_next_hdr_payload(s)

            if functions[hdr.msg_type.type] is not None:
                print(functions[hdr.msg_type.type](hdr, payload))


if __name__ == "__main__":
    main()
