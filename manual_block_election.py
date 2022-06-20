from block import block_open
from confirm_req import get_confirm_block_resp
from peercrawler import get_peers_from_service
from pynanocoin import livectx, get_connected_socket_endpoint, live_genesis_block
from msg_handshake import node_handshake_id

ctx = livectx
peers = filter(lambda p: p.is_voting, get_peers_from_service(ctx))
genesis_block = block_open(live_genesis_block['source'], live_genesis_block['representative'],
                           live_genesis_block['account'], live_genesis_block['signature'], live_genesis_block['work'])

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
    except OSError:
        print("Node was unreachable")





