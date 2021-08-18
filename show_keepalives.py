#!/bin/env python3
import time
import socket
import random
import argparse

from pynanocoin import *


def parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')

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
                keepalive = message_keepalive.parse_payload(hdr, payload)
                print(keepalive)
            else:
                print(hdr)


if __name__ == "__main__":
    main()