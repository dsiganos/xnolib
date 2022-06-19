#!/bin/env python3
import socket
import time
import sys
import tempfile
import peercrawler
import frontier_request
from pynanocoin import *
from exceptions import *
from peer import Peer


def frontier_req(ctx: dict, s: socket.socket, peer: Peer, acc_id: bytes) -> None:
    hdr = frontier_request.frontier_request.generate_header(ctx, True)
    frontier = frontier_request.frontier_request(hdr, start_account=acc_id, maxacc=1)
    s.send(frontier.serialise())
    frontier = frontier_request.read_frontier_response(s)
    endmark = frontier_request.read_frontier_response(s)
    assert endmark.is_end_marker()
    peer.aux['confirmed_frontier'] = frontier.frontier_hash

    hdr = frontier_request.frontier_request.generate_header(ctx, False)
    frontier = frontier_request.frontier_request(hdr, start_account=acc_id, maxacc=1)
    s.send(frontier.serialise())
    frontier = frontier_request.read_frontier_response(s)
    endmark = frontier_request.read_frontier_response(s)
    assert endmark.is_end_marker()
    peer.aux['unconfirmed_frontier'] = frontier.frontier_hash

    print('Frontier [%s]:%s (%s, %s)' %
        (peer.ip, peer.port, hexlify(peer.aux['confirmed_frontier']), hexlify(peer.aux['unconfirmed_frontier'])))


def pull_blocks(ctx: dict, blockman: block_manager, peer: Peer, acc: bytes) -> int:
    print('pull blocks for account %s from peer %s' % (hexlify(acc), peer))
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(3)
        s.connect((str(peer.ip), peer.port))

        frontier_req(ctx, s, peer, acc)

        # send a block pull request
        hdr = message_header(ctx['net_id'], [18, 18, 18], message_type(6), 0)
        bulk_pull = message_bulk_pull(hdr, hexlify(acc))
        s.send(bulk_pull.serialise())

        # pull blocks from peer
        blocks_pulled = 0
        while True:
            block = Block.read_block_from_socket(s)
            if block is None:
                break
            peerinfo = (peer.ip, peer.port, hexlify(peer.aux['confirmed_frontier']), hexlify(peer.aux['unconfirmed_frontier']))
            block.ancillary['peers'].add('[%s]:%s c:%s unc:%s' % peerinfo)
            print(block)
            blockman.process(block)
            blocks_pulled += 1

    return blocks_pulled

        #a, b = blockman.accounts[0].check_forks()
        #if a is not None or b is not None:
        #    print("Found forks in peer: %s" % str(peer))
        #    print("The following blocks have the same previous link:")
        #    print(a)
        #    print(b)


def once(ctx: dict, workdir: str, forkacc: bytes) -> None:
    workdir = '%s/%s' % (workdir, hexlify(forkacc))
    print(workdir)

    peers = peercrawler.get_peers_from_service(ctx)
    print('Starting a round of pulling blocks with %s peers' % len(peers))

    # initialise a git project in the temporary work directory
    gitrepo = git.Repo.init(workdir)

    blockman = block_manager(ctx, workdir, gitrepo)

    pulls = 0
    for peer in peers:
        try:
            blocks_pulled = pull_blocks(ctx, blockman, peer, forkacc)
            print('%s: %s' % (peer, blocks_pulled))
            pulls += 1
        except (PyNanoCoinException, OSError) as e:
            peer.score = 0
            print('FAILED to pull blocks from %s' % peer)
            print(e)

    for acc in blockman.accounts:
        print(acc)
    print(blockman)
    print(workdir)
    print('Pulled blocks from %s out of %s peers' % (pulls, len(peers)))


ctx = livectx

# nano_3m65ub5mpcrunbuzeits57ynnfn8fm66nzc5p9u7aoskakdwgquoiszd4zz1
fork1 = binascii.unhexlify('cc83da473b2b1ba277f64359197d4a36866cc84a7d43b1f65457324497c75f75')

# nano_1zdhwgoxjrqqd86j5rbxs94wtdmj6683zheitn3whai65yzojuqxyfxzmzj8
fork2 = binascii.unhexlify('7d6fe3abd8e2f7598911e13dc9c5cd2e71210c1fbd90d503c7a2041fbf58eefd')

# nano_35u3s789f3to4956beqm6t3tnt99oiqxtu4juxezrtsnua1k7nxhnwexrt8d
fork3 = binascii.unhexlify('8F61C94C76875511C644B2F32683AA68E7AC2FDD6C51DF59FC6B34DA0122D3AF')

# nano_31kphxzkf3unoahwqy33xq16d16y4aucjpph568apsbdu7rosqr9kkmo99wh
fork4 = binascii.unhexlify('82567f7f268774aa1fcbf821edc045809e1236a8dacf190c8b652bd9715cdf07')

# nano_1gwu55iga8pf3bpef3shfqgmdgqj3xsqpptuqqnknb4zu4f8cxcyk7ezd36p
fork5 = binascii.unhexlify('3b9b18e0e41acd0a6cc6872f6ddd35baf10f737b5b5bbde92a245fd89a65755e')

# nano_3dzw98zso4gk9b19jho1ao5ie18bzhxrrdpzbf1eoiyeagudk35w176ybx48
fork6 = binascii.unhexlify('affc39bf9a89d23a4078bea045470600c9fbfb8c2edf4b40cac3cc43b6b9047c')

# nano_1jkexaqe9yxcd4wr1sy5p4hndpbz9dquouwrcd5oauuqymc1k6soacpww3ry
fork7 = binascii.unhexlify('464cea2ec3fbaa58b98067c3b09f45d93f3aefbaef9852c7546f77f4d4091335')

# nano_35gp6d11p4uw4cyu9xgoths3xu1dpophfixaxy56jtr971rwz9ngtf715add
fork8 = binascii.unhexlify('8dd622c00b0b7c12bdb3f5d5d3f21eec0bb56cf6c3a8ef8648eb072831cf9e8e')

# nano_1krrw3w3xfzeiex7463nmmmst9ycgabmg5k9bsuxokt3pdm4fu8abj478t9y
fork9 = binascii.unhexlify('4b18e0781eb7ec833a5110349ce79d1fca7213370e474e77dacb41b2e626ecc8')

# nano_34pdjoy6c7e8foj3srbppszqa9j3kun79yb8mxfjsfmr978g83cmjmgpff59
fork10 = binascii.unhexlify('8acb8d7c4515866d621ce136b67f741e2196e853f9269f5b1cb678394ce30553')

# nano_3h4kaw6hg6oc5ze4ak5btpgq5adeyfu7tzc7jfdpifxt4ftpsg7pm6pjwtug
fork11 = binascii.unhexlify('bc524708f712aa1fd8244869d59d71a16cf3765d7d458b576837ba13756cb8b6')

# nano_1z9myhyffmfikpjk6qh5sbx7n8hifcm95it8q3898cmdktmpxgko16sy3pfo
fork12 = binascii.unhexlify('7cf3f3fcd6cdb095a3225de3ca7a5a19f06aa671c346b84c732a6b96a76eba55')

# nano_3h5n3hpud9hho74ybcibqpuwdkbbzzbhb8z6osbbq8rayik5eciw1o83cgh8
fork13 = binascii.unhexlify('bc740bedb59defa945e4aa09bdb7c5c929ffd2f49be4ae529b9b08f424362a1c')

# nano_3swpttz8t86zywz7xa83wb9ygsq89y71i7eyg9ackeix1nubzng9uj7aw9ha
fork14 = binascii.unhexlify('e796d6be6d189ff73e5ea0c1e24fe766e63f8a08159e71d0a9321d05369fd1c7')


forks = [
    fork1,
    fork2,
    fork3,
    fork4,
    fork5,
    fork6,
    fork7,
    fork8,
    fork9,
    fork10,
    fork11,
    fork12,
    fork13,
    fork14,
]

topworkdir = 'fork_analyser.data'
os.makedirs(topworkdir, exist_ok=True)
workdir = tempfile.mkdtemp(dir=topworkdir)
print(workdir)

for fork in forks:
    once(ctx, workdir, fork)
