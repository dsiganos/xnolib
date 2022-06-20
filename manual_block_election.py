import argparse

from block import block_open
from confirm_req import get_confirm_block_resp
from peercrawler import get_peers_from_service
from pynanocoin import livectx, get_connected_socket_endpoint, betactx, testctx
from msg_handshake import node_handshake_id
from exceptions import PyNanoCoinException


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

    if args.beta:
        ctx = betactx
    elif args.test:
        ctx = testctx

    peers = filter(lambda p: p.is_voting, get_peers_from_service(ctx))
    genesis_block = block_open(ctx['genesis_block']['source'], ctx['genesis_block']['representative'],
                               ctx['genesis_block']['account'], ctx['genesis_block']['signature'],
                               ctx['genesis_block']['work'])

    votes = []

    for p in peers:
        try:
            with get_connected_socket_endpoint(str(p.ip), p.port) as s:
                signing_key, verifying_key = node_handshake_id.keypair()
                node_handshake_id.perform_handshake_exchange(ctx, s, signing_key, verifying_key)
                resp = get_confirm_block_resp(ctx, genesis_block, s)
                print("completed")
                if resp is not None:
                    votes.append(resp)
                else:
                    continue
        except (OSError, PyNanoCoinException):
            print("Node was unreachable")


if __name__ == "__main__":
    main()