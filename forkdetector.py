#!/bin/env python3
import socket
import time

import peercrawler
from nanolib import *


def pull_blocks(blockman, peer):
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(1)
        s.connect((str(peer.ip), peer.port))

        # send a block pull request
        hdr = message_header(network_id(67), [18, 18, 18], message_type(6), 0)
        bulk_pull = message_bulk_pull(hdr, livectx["genesis_pub"])
        s.send(bulk_pull.serialise())

        # pull blocks from peer
        while True:
            block = read_block_from_socket(s)
            if block is None:
                break
            blockman.process(block)

        #a, b = blockman.accounts[0].check_forks()
        #if a is not None or b is not None:
        #    print("Found forks in peer: %s" % str(peer))
        #    print("The following blocks have the same previous link:")
        #    print(a)
        #    print(b)


peercrawler_thread = peercrawler.spawn_peer_crawler_thread(ctx=livectx, forever=True, delay=30)
peerman = peercrawler_thread.peerman

blockman = blocks_manager()

while True:
    peers = peerman.get_peers_copy()
    print()
    print('Starting a round of pulling blocks with %s peers' % len(peers))
    for peer in peers:
        try:
            pull_blocks(blockman, peer)
        except socket.error as error:
            peer.score = 0
            print('socker error %s' % error)

    print(blockman)
    print(blockman.accounts[0])
    print(blockman.accounts[0].str_blocks())
    time.sleep(3)
