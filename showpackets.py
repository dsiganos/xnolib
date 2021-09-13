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


def publish_func(ctx, hdr, payload):
    publish = msg_publish.parse(hdr, payload)
    return publish


def confirm_req_func(ctx, hdr, payload):
    if hdr.block_type() == block_type_enum.not_a_block:
        req = confirm_req_hash.parse(hdr, payload)
    else:
        req = confirm_req_block.parse(hdr, payload)
    return req


def confirm_ack_func(ctx, hdr, payload):
    if hdr.block_type() == block_type_enum.not_a_block:
        ack = confirm_ack_hash.parse(hdr, payload)
    else:
        ack = confirm_ack_block.parse(hdr, payload)
    return ack


def bulk_pull_func(ctx, hdr, payload):
    bp = message_bulk_pull.parse(hdr, payload)
    return bp


def bulk_push_func(ctx, hdr, payload):
    bp = bulk_push.parse(hdr, payload)
    return bp


def frontier_req_func(ctx, hdr, payload):
    fr = frontier_request.parse(ctx, payload, hdr=hdr)
    return fr


def node_handshake_id(ctx, hdr, payload):
    if hdr.is_query() and hdr.is_response():
        handshake = handshake_response_query.parse_query_response(hdr, payload)
    elif hdr.is_query():
        handshake = handshake_query.parse_query(hdr, payload)
    elif hdr.is_response():
        handshake = handshake_response.parse_response(hdr, payload)
    return handshake


def bulk_pull_account_func(ctx, hdr, payload):
    bpa = bulk_pull_account.parse(hdr, payload)
    return bpa


def telemetry_req_func(ctx, hdr, payload):
    return hdr


def telemetry_ack_func(ctx, hdr, payload):
    ta = telemetry_ack.parse(payload)
    return ta

functions = {
    message_type_enum.keepalive: message_keepalive.parse_payload,
    message_type_enum.publish: publish_func,
    message_type_enum.confirm_req: confirm_req_func,
    message_type_enum.confirm_ack: confirm_ack_func,
    message_type_enum.bulk_pull: bulk_pull_func,
    message_type_enum.bulk_push: bulk_push_func,
    message_type_enum.frontier_req: frontier_req_func,
    message_type_enum.node_id_handshake: node_handshake_id,
    message_type_enum.bulk_pull_account: bulk_pull_account_func,
    message_type_enum.telemetry_req: telemetry_req_func,
    message_type_enum.telemetry_ack: telemetry_ack_func,
    message_type_enum.not_a_block: lambda ctx, args, hdr, payload: print(hdr)
}

show = {
    message_type_enum.keepalive: False,
    message_type_enum.publish: False,
    message_type_enum.confirm_req: False,
    message_type_enum.confirm_ack: False,
    message_type_enum.bulk_pull: False,
    message_type_enum.bulk_push: False,
    message_type_enum.frontier_req: False,
    message_type_enum.node_id_handshake: False,
    message_type_enum.bulk_pull_account: False,
    message_type_enum.telemetry_req: False,
    message_type_enum.telemetry_ack: False
}


def set_up_show(args, show):
    if args.all:
        for x in show:
            show[x] = True
    if args.keepalive:
        show[message_type_enum.keepalive] = True
    if args.publish:
        show[message_type_enum.publish] = True
    if args.confirm_req:
        show[message_type_enum.confirm_req] = True
    if args.confirm_ack:
        show[message_type_enum.confirm_ack] = True
    if args.bulk_pull:
        show[message_type_enum.bulk_pull] = True
    if args.bulk_push:
        show[message_type_enum.bulk_push] = True
    if args.frontier_req:
        show[message_type_enum.frontier_req] = True
    if args.handshake:
        show[message_type_enum.node_id_handshake] = True
    if args.bulk_pull_acc:
        show[message_type_enum.bulk_pull_account] = True
    if args.telemetry_req:
        show[message_type_enum.telemetry_req] = True
    if args.telemetry_ack:
        show[message_type_enum.telemetry_ack] = True


def main():
    args = parse_args()
    set_up_show(args, show)

    ctx = livectx
    if args.beta: ctx = betactx
    elif args.test: ctx = testctx

    if args.peer:
        peeraddr, peerport = parse_endpoint(args.peer, default_port=ctx['peerport'])
    else:
        peer = get_random_peer(ctx, lambda p: p.score >= 1000)
        peeraddr, peerport = str(peer.ip), peer.port

    print('Conneting to [%s]:%s' % (peeraddr, peerport))
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
            # TODO: this if statement should not be necessary, we just need a mapping
            # from message type to handler function and this big if can disapper
            if show[hdr.msg_type.type]:
                print(functions[hdr.msg_type.type](ctx, hdr, payload))


if __name__ == "__main__":
    main()
