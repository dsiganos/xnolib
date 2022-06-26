import argparse
import binascii

import requests

import _logger
import common
from confirm_req import get_confirm_hash_resp
from peercrawler import get_peers_from_service
from pynanocoin import livectx, get_connected_socket_endpoint, betactx, testctx, parse_endpoint
from msg_handshake import node_handshake_id
from exceptions import PyNanoCoinException
from representative_mapping import representative_mapping
from common import hexlify
from representatives import get_representatives, Representative

logger = _logger.get_logger()


def parse_reps(resp):
    reps = []
    for i in resp.keys():
        rep = Representative()
        rep.account = i
        rep.endpoint = resp[i]['endpoint']
        rep.set_weight(resp[i]['weight'])
        rep.node_id = resp[i]['node_id']
        rep.protover = resp[i]['protover']
        rep.voting = resp[i]['voting']
        reps.append(rep)
    return reps


def parse_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')
    parser.add_argument('-H', '--hash', type=str,
                        default=None,
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

    if args.hash is not None:
        block_hash = args.hash.split(':')
        if len(block_hash) == 1:
            pair = common.hash_pair(binascii.unhexlify(block_hash[0]), b'\x00' * 32)
        else:
            pair = common.hash_pair(binascii.unhexlify(block_hash[0]), binascii.unhexlify(block_hash[1]))
    else:
        genesis_block = ctx['genesis_block']
        pair = common.hash_pair(genesis_block.hash(), genesis_block.root())

    votes = []
    reps_voted = []
    voting_weights = []
    session = requests.Session()
    print("contacting: %s" % ctx['repservurl'])
    resp = session.get(ctx['repservurl'], timeout=5).json()
    reps = list(filter(lambda r: r.voting and r.endpoint is not None, parse_reps(resp)))

    for r in reps:
        voting_weight = r.weight
        print(r.account, str(r.endpoint), voting_weight)
        ip, port = parse_endpoint(r.endpoint)
        try:
            with get_connected_socket_endpoint(ip, port) as s:
                signing_key, verifying_key = node_handshake_id.keypair()
                node_handshake_id.perform_handshake_exchange(ctx, s, signing_key, verifying_key)
                resp = get_confirm_hash_resp(ctx, [pair], s)
                if resp is not None:
                    votes.append(resp)
                    reps_voted.append(r)
                    voting_weights.append(int(voting_weight))
                else:
                    continue
        except (OSError, PyNanoCoinException):
            print("Node was unreachable")

    for v in votes:
        print(v)

    print("Total votes: %d (%f)" % (sum(voting_weights), sum(voting_weights) / (10**30)))


if __name__ == "__main__":
    main()
