#!/bin/env python3
#
# Example usage:
#
# echo '{
#         "type": "state",
#         "account": "nano_3pi8p16b19qfcgdsycshyzm71jzpdscnb8g44fnp5h67fe1xc8iztphutest",
#         "previous": "F3FCADE2F8BF6D4D71E4FCC699C78A93CDE660637F779F2295F28B5AA7A6E849",
#         "representative": "nano_3pi8p16b19qfcgdsycshyzm71jzpdscnb8g44fnp5h67fe1xc8iztphutest",
#         "balance": "99",
#         "link": "DA06B008901EED53979F2B2FF7E65047F65E554499C2136961BC856B01D51A1F",
#         "link_as_account": "nano_3pi8p16b19qfcgdsycshyzm71jzpdscnb8g44fnp5h67fe1xc8iztphutest",
#         "signature": "B3C49A72C5923B8312805FF184CFE18790B77A185E3683EBB0C0652DDB436B2611C3134D71B3D028A51BF021BDFD82DB39EE040A3FB04509A72CE0CA5EF81400",
#         "work": "f1e9abd3c54a5075"
# }' | ./msg_publish.py -t --peer 144.76.30.190

import argparse
import sys

from pynanocoin import *
from peercrawler import get_random_peer
from msg_handshake import node_handshake_id
import block


class msg_publish:
    def __init__(self, hdr: message_header, block):
        assert(isinstance(hdr, message_header))
        self.hdr = hdr
        self.block = block

    def serialise(self) -> bytes:
        data = self.hdr.serialise_header()
        data += self.block.serialise(False)
        return data

    @classmethod
    def parse(cls, hdr: message_header, data: bytes):
        block = None
        blocktype = hdr.block_type()
        if blocktype == 2:
            block = block_send.parse(data)
        elif blocktype == 3:
            block = block_receive.parse(data)
        elif blocktype == 4:
            block = block_open.parse(data)
        elif blocktype == 5:
            block = block_change.parse(data)
        elif blocktype == 6:
            block = block_state.parse(data)
        else:
            assert False
        return msg_publish(hdr, block)

    def __str__(self):
        return str(self.hdr) + "\n" + str(self.block)

def parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')

    parser.add_argument('--peer',
                        help='peer to contact')

    return parser.parse_args()


def read_json_block_from_stdin():
    json_block = sys.stdin.read()
    blk = block.Block.parse_from_json_string(json_block)
    return blk


def main() -> None:
    args = parse_args()

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
        signing_key, verifying_key = node_handshake_id.keypair()
        node_handshake_id.perform_handshake_exchange(ctx, s, signing_key, verifying_key)
        blk = read_json_block_from_stdin()
        # only state blocks for now
        assert(isinstance(blk, block_state))
        msgtype = message_type_enum.publish
        hdr = message_header(ctx['net_id'], [18, 18, 18], message_type(msgtype), 0)
        hdr.set_block_type(block_type_enum.state)
        msg = msg_publish(hdr, blk)
        print(msg)
        s.send(msg.serialise())


if __name__ == '__main__':
    main()
