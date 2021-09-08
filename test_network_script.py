from pynanocoin import *
from confirm_req import *
from peercrawler import get_initial_connected_socket
from frontier_request import *
from pull_n_accounts import store_frontiers_handler


ctx = testctx

hdr, peers = get_peers_from_service(ctx)

peers = list(filter(lambda p: p.score == 1000, peers))
peers = list(filter(lambda p: p.is_voting, peers))


with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.settimeout(10)
    peer = random.choice(peers)
    s.connect((str(peer.ip), peer.port))

    req = frontier_request(ctx)

    s.send(req.serialise())

    frontiers = []

    read_all_frontiers(s, store_frontiers_handler(frontiers))

    blocks = []

    for f in frontiers:
        current_blocks = get_account_blocks(ctx, s, f.account)
        for b in current_blocks:
            blocks.append(b)

    for b in blocks:
        resp = get_confirm_block_resp(ctx, b, s)
        print(resp)

    pass

