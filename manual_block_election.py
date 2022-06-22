import argparse
import binascii

import _logger
import common
from block import block_open
from confirm_req import get_confirm_hash_resp
from peercrawler import get_peers_from_service
from pynanocoin import livectx, get_connected_socket_endpoint, betactx, testctx
from msg_handshake import node_handshake_id
from exceptions import PyNanoCoinException
from representative_mapping import representative_mapping
from common import hexlify

logger = _logger.get_logger()


def parse_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')
    parser.add_argument('-H', '--hash', type=str,
                        default='991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948:E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA',
                        help='the hash pair (in the form hash:root)')
    return parser.parse_args()


def main():
    # eg hash: 991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948
    # eg root: E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA
    args = parse_args()
    ctx = livectx

    if args.beta:
        ctx = betactx
    elif args.test:
        ctx = testctx

    peers = filter(lambda p: p.is_voting, get_peers_from_service(ctx))
    block_hash = args.hash.split(':')

    if len(block_hash) == 1:
        pair = common.hash_pair(binascii.unhexlify(block_hash[0]), b'\x00' * 32)
    else:
        pair = common.hash_pair(binascii.unhexlify(block_hash[0]), binascii.unhexlify(block_hash[1]))

    votes = []
    peers_voted = []
    voting_weights = []
    rep_map = representative_mapping()
    rep_map.load_from_file("representative-mappings.json")

    for p in peers:
        voting_weight = 0
        rep = rep_map.find(hexlify(p.peer_id), str(p.ip))
        if len(rep) >= 1:
            voting_weight = rep[0]['weight']
        print(hexlify(p.peer_id), str(p.ip), len(rep))
        try:
            with get_connected_socket_endpoint(str(p.ip), p.port) as s:
                signing_key, verifying_key = node_handshake_id.keypair()
                node_handshake_id.perform_handshake_exchange(ctx, s, signing_key, verifying_key)
                resp = get_confirm_hash_resp(ctx, [pair], s)
                if resp is not None:
                    votes.append(resp)
                    peers_voted.append(p)
                    voting_weights.append(int(voting_weight))
                else:
                    continue
        except (OSError, PyNanoCoinException):
            print("Node was unreachable")

    for v in votes:
        print(v)

    print(sum(voting_weights))


if __name__ == "__main__":
    main()