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

    parser.add_argument('-k', '--keepalive', action='store_true', default=False,
                        help='indicates the script to show keepalives')
    parser.add_argument('-c', '--confirm_req', action='store_true', default=False,
                        help='indicated the script to show confirm requests')
    parser.add_argument('-C', '--confirm_ack', action='store_true', default=False,
                        help='indicates the script to show confirm acks')
    parser.add_argument('-p', '--publish', action='store_true', default=False,
                        help='indicates to show msg_publish packets')
    parser.add_argument('-b' '--bulk_pull', action='store_true', default=False,
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

    return parser.parse_args()


def main():
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    elif args.test: ctx = testctx

    s, _ = get_initial_connected_socket(ctx)
    assert s
    with s:
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
            if hdr.msg_type == message_type(message_type_enum.keepalive):
                if args.keepalive:
                    keepalive = message_keepalive.parse_payload(hdr, payload)
                    print(keepalive)

            elif hdr.msg_type == message_type(message_type_enum.publish):
                if args.publish:
                    publish = msg_publish.parse(hdr, payload)
                    print(publish)

            elif hdr.msg_type == message_type(message_type_enum.confirm_req):
                if args.confirm_req:
                    if hdr.block_type() == block_type_enum.not_a_block:
                        req = confirm_req_hash.parse(hdr, payload)
                    else:
                        req = confirm_req_block.parse(hdr, payload)
                    print(req)

            elif hdr.msg_type == message_type(message_type_enum.confirm_ack):
                if args.confirm_ack:
                    if hdr.block_type() == block_type_enum.not_a_block:
                        ack = confirm_ack_hash.parse(hdr, payload)
                    else:
                        ack = confirm_ack_block.parse(hdr, payload)
                    print(ack)

            elif hdr.msg_type == message_type(message_type_enum.bulk_pull):
                if args.bulk_pull:
                    bp = message_bulk_pull.parse(hdr, payload)
                    print(bp)

            elif hdr.msg_type == message_type(message_type_enum.bulk_push):
                if args.bulk_push:
                    bp = bulk_push.parse(hdr, payload)
                    print(bp)

            elif hdr.msg_type == message_type(message_type_enum.frontier_req):
                if args.frontier_req:
                    fr = frontier_request.parse(ctx, payload, hdr=hdr)
                    print(fr)

            # TODO: Parsing for handshake messages needs to be done
            elif hdr.msg_type == message_type(message_type_enum.node_id_handshake):
                if args.handshake:
                    print(hdr)

            elif hdr.msg_type == message_type(message_type_enum.bulk_pull_account):
                if args.bulk_pull_acc:
                    bpa = bulk_pull_account.parse(hdr, payload)
                    print(bpa)

            elif hdr.msg_type == message_type(message_type_enum.telemetry_req):
                if args.telemetry_req:
                    print(hdr)
            elif hdr.msg_type == message_type(message_type_enum.telemetry_ack):
                print(hdr)
                ta = telemetry_ack.parse(payload)
                print(ta)

            else:
                print(hdr)


if __name__ == "__main__":
    main()