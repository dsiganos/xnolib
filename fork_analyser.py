#!/bin/env python3
import socket
import time
import sys
import tempfile
import peercrawler
import frontier_request
from pynanocoin import *
from exceptions import *


def frontier_req(ctx, s, peer, acc_id):
    frontier = frontier_request.frontier_request(ctx, acc_id, maxacc=1, confirmed=True)
    s.send(frontier.serialise())
    frontier = frontier_request.read_frontier_response(s)
    endmark = frontier_request.read_frontier_response(s)
    assert endmark.is_end_marker()
    peer.aux['confirmed_frontier'] = frontier.frontier_hash

    frontier = frontier_request.frontier_request(ctx, acc_id, maxacc=1, confirmed=False)
    s.send(frontier.serialise())
    frontier = frontier_request.read_frontier_response(s)
    endmark = frontier_request.read_frontier_response(s)
    assert endmark.is_end_marker()
    peer.aux['unconfirmed_frontier'] = frontier.frontier_hash

    print('Frontier [%s]:%s (%s, %s)' %
        (peer.ip, peer.port, hexlify(peer.aux['confirmed_frontier']), hexlify(peer.aux['unconfirmed_frontier'])))


def pull_blocks(ctx, blockman, peer, hsh):
    print('pull blocks for account %s' % hexlify(hsh))
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(3)
        s.connect((str(peer.ip), peer.port))

        frontier_req(ctx, s, peer, hsh)

        # send a block pull request
        hdr = message_header(ctx['net_id'], [18, 18, 18], message_type(6), 0)
        bulk_pull = message_bulk_pull(hdr, hexlify(hsh))
        s.send(bulk_pull.serialise())

        # pull blocks from peer
        while True:
            block = read_block_from_socket(s)
            if block is None:
                break
            peerinfo = (peer.ip, peer.port, hexlify(peer.aux['confirmed_frontier']), hexlify(peer.aux['unconfirmed_frontier']))
            block.ancillary['peers'].add('[%s]:%s c:%s unc:%s' % peerinfo)
            print(block)
            blockman.process(block)

        #a, b = blockman.accounts[0].check_forks()
        #if a is not None or b is not None:
        #    print("Found forks in peer: %s" % str(peer))
        #    print("The following blocks have the same previous link:")
        #    print(a)
        #    print(b)

ctx=livectx
peers = peercrawler.get_all_peers()
if peers is None:
    peercrawler_thread = peercrawler.spawn_peer_crawler_thread(ctx=ctx, forever=True, delay=30, verbosity=1)
    peerman = peercrawler_thread.peerman
    time.sleep(1)
else:
    peerman = None

fork1 = binascii.unhexlify('7D6FE3ABD8E2F7598911E13DC9C5CD2E71210C1FBD90D503C7A2041FBF58EEFD')
fork2 = binascii.unhexlify('CC83DA473B2B1BA277F64359197D4A36866CC84A7D43B1F65457324497C75F75')

# nano_35u3s789f3to4956beqm6t3tnt99oiqxtu4juxezrtsnua1k7nxhnwexrt8d
fork3 = binascii.unhexlify('8F61C94C76875511C644B2F32683AA68E7AC2FDD6C51DF59FC6B34DA0122D3AF')

# nano_31kphxzkf3unoahwqy33xq16d16y4aucjpph568apsbdu7rosqr9kkmo99wh
fork4 = binascii.unhexlify('82567f7f268774aa1fcbf821edc045809e1236a8dacf190c8b652bd9715cdf07')

# nano_1gwu55iga8pf3bpef3shfqgmdgqj3xsqpptuqqnknb4zu4f8cxcyk7ezd36p
fork5 = binascii.unhexlify('3b9b18e0e41acd0a6cc6872f6ddd35baf10f737b5b5bbde92a245fd89a65755e')

acc_ids = [
    livectx["genesis_pub"],
    '42DD308BA91AA225B9DD0EF15A68A8DD49E2940C6277A4BFAC363E1C8BF14279',
#    '3309D2BDB2DCE1C5744F357E39DC8AC85980F00499F8F43B0A1287D0658C7173',
    fork1,
    fork2,
]

workdirname = 'fork_analyser.data'
os.makedirs(workdirname, exist_ok=True)
workdir = tempfile.mkdtemp(dir=workdirname)
print(workdir)

# initialise a git project in the temporary work directory
gitrepo = git.Repo.init(workdir)

blockman = block_manager(workdir, gitrepo)
stop = False
while True:
    if peerman is None:
        peers = peercrawler.get_all_peers()
    else:
        peerman.get_peers_copy()
    print()
    print('Starting a round of pulling blocks with %s peers' % len(peers))
    pulls = 0
    for peer in peers:
        try:
            pull_blocks(ctx, blockman, peer, fork3)
            pulls += 1
#            if pulls >= 1:
#                stop = True
#                break
        except OSError as e:
            peer.score = 0
            print(e)
        except PyNanoCoinException as e:
            peer.score = 0
            print(e)

    #print(blockman.accounts[0].str_blocks())
    #for acc in blockman.accounts:
    #    print(acc)
    #print(blockman)
    #time.sleep(3)

#print(blockman.unprocessed_blocks[0])
for acc in blockman.accounts:
    print(acc)
print(blockman)
print(workdir)
