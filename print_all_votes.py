#!/bin/env python3

import acctools
from pynanocoin import *
from confirm_req import *
from frontier_request import *
from pull_n_accounts import store_frontiers_handler


def frontier_iter_with_retries(ctx: dict, peeraddr: str, peerport: int, start_acc: bytes = b'\x00' * 32) \
        -> frontier_entry or None:
    while True:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.settimeout(10)

            failed_count = 0
            last_acc = start_acc

            try:
                s.connect((peeraddr, peerport))
                front_hdr = frontier_request.generate_header(ctx, confirmed=True)
                print('Sending frontier request starting from account %s' % hexlify(last_acc))
                req = frontier_request(front_hdr, maxacc=num, start_account=last_acc)
                s.send(req.serialise())

                while True:
                    frontier = read_frontier_response(s)
                    last_acc = frontier.account
                    if frontier.is_end_marker():
                        failed_count = 0
                        return
                    yield frontier

                break

            except (OSError, PyNanoCoinException) as err:
                print(err)
                if failed_count >= 20:
                    raise FrontierIteratorFail("exiting due to 20 errors in a row")
                failed_count += 1


# reads a sequence of blocks from stdin, each block is prefixed by its hash
# Example input:
# 00000003E4DC06FA2F314E10E59E23C30241CD42D9FF6B4AEE0F4EB52F71D9B1
# {
#     "type": "state",
#     "account": "nano_31fr1qtbrfnujcspx5xq61uxgjf9j6rzckdj1kdn61y3h53nxr7911dzetk3",
#     "previous": "C2BC9E7EA387E73E9EF7AF805386B3188EC71567BA3F58031E8CA04BF0B56317",
#     "representative": "nano_3testing333before333adoption333333333333333333333333y71t3kt9",
#     "balance": "999999999999998367700000",
#     "link": "DD573D46AD23730FF0557F59247C92CEE695D5DA347D2AA592DC08716B580DA8",
#     "link_as_account": "nano_3qcq9o5ctaum3zr7czts6jyb7mq8kqcxnf5x7cks7q1ag7ooi5farai51dpi",
#     "signature": "073C1A87469F79A55A94EC94F587D463DB617BB235EC00796EEACCFAD6C19E4D7524B0D236E46A2766E68FD813E29F0CB1B76656B94A3ED646CE2AE30F904905",
#     "work": "27f60f8a95403ae1"
# }
def blocks_stdin_iterator() -> str or None:
    reading_json = False
    for line in sys.stdin:
        line = line.rstrip()
        if reading_json:
            json_str += line
            if line == '}':
                reading_json = False
                yield json_str
        else:
            # line contains the hash
            reading_json = True;
            json_str = ''
    return

def parse_args():
    parser = argparse.ArgumentParser()

    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument('-b', '--beta', action='store_true', default=False,
                        help='use beta network')
    group2.add_argument('-t', '--test', action='store_true', default=False,
                        help='use test network')

    parser.add_argument('-p', '--peer',
                        help='peer to contact for frontiers (if not set, one is randomly selected using DNS)')

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx

    if args.peer is not None:
        peeraddr, peerport = parse_endpoint(args.peer, default_port=ctx['peerport'])
        print('Connecting to [%s]:%s' % (peeraddr, peerport))
    else:
        peer = get_random_peer(ctx, lambda p: p.score >= 1000 and p.ip.is_ipv4() and p.is_voting)
        print('Using peer %s' % peer)
        peeraddr = str(peer.ip)
        peerport = peer.port

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        s.settimeout(3)
        s.connect((peeraddr, peerport))
        s.settimeout(20)

        signing_key, verifying_key = node_handshake_id.keypair()
        node_handshake_id.perform_handshake_exchange(ctx, s, signing_key, verifying_key)
        print('handshake done')

        # read hashes from stdin one by one
        count = 0
        for block_json_str in blocks_stdin_iterator():
            print(block_json_str)
            block = Block.parse_from_json_string(block_json_str)
            count += 1
            resp = get_confirm_block_resp(ctx, block, s)
            print('%s: %s' % (count, resp))

    print('all blocks printed')


if __name__ == "__main__":
    main()
