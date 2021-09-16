#!/bin/env python3

from pynanocoin import *
from confirm_req import *
from peercrawler import get_initial_connected_socket
from frontier_request import *
from pull_n_accounts import store_frontiers_handler


ctx = testctx

hdr, peers = get_peers_from_service(ctx)

peers = list(filter(lambda p: p.score == 1000, peers))
peers = list(filter(lambda p: p.is_voting, peers))
peer = random.choice(peers)

print('Using peer %s' % peer)

with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    s.settimeout(10)
    s.connect((str(peer.ip), peer.port))

    front_hdr = frontier_request.generate_header(ctx)
    req = frontier_request(front_hdr)

    s.send(req.serialise())

    frontiers = []

    read_all_frontiers(s, store_frontiers_handler(frontiers))
    print('%d frontiers read' % len(frontiers))

    blocks = []

    for f in frontiers:
        blocks += get_account_blocks(ctx, s, f.account)
        print('.', end='', flush=True)
    print('\nblocks received')

with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    s.settimeout(10)
    s.connect((str(peer.ip), peer.port))

    node_handshake_id.perform_handshake_exchange(ctx, s)
    print('handshake done')

    count = 0
    for b in blocks:
        count += 1
        resp = get_confirm_block_resp(ctx, b, s)
        print('%s: %s' % (count, resp))
print('all blocks printed')
