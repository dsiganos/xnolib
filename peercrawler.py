#!/bin/env python3
import ipaddress
import random
import socket
import copy
import time
import argparse

from nanolib import *


class peer_manager:
    def __init__(self, peers=[]):
        self.peers = set()
        self.add_peers(peers)

    def add_peers(self, peers):
        for p in peers:
            #print('adding peer %s' % p)
            self.peers.add(p)

    def get_peers_from_peer(self, peer):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.settimeout(3)

            # try to connect to peer
            try:
                s.connect((str(peer.ip), peer.port))
            except socket.error as error:
                peer.score = 0
                #print('Failed to connect to peer %s, error: %s' % (peer, error))
                return

            # connected to peer, do handshake followed by listening for the first keepalive
            # once we get the first keepalive, we have what we need and we move on
            try:
                perform_handshake_exchange(s)
                starttime = time.time()
                while time.time() - starttime <= 10:
                    hdr, payload = get_next_hdr_payload(s)
                    if hdr.msg_type == message_type(message_type_enum.keepalive):
                        keepalive = message_keepalive.parse_payload(hdr, payload)
                        self.add_peers(keepalive.peers)
                        peer.score = 1000
                        return

                # timeout whilst waiting for keepalive, score it with 2
                peer.score = 2
            except:
                # peer was connectable but some other error happpened, score it with 1
                peer.score = 1

    def crawl_once(self):
        assert len(self.peers) > 0
        print('Starting a peer crawl')

        # it is important to take a copy of the peers so that it is not changing as we walk it
        for p in copy.copy(self.peers):
            print('Get peers from %41s:%5s (score:%4s)' % ('[%s]' % p.ip, p.port, p.score))
            self.get_peers_from_peer(p)

    def __str__(self):
        s = '---------- Start of Manager peers (%s peers) ----------\n' % len(self.peers)
        for p in self.peers:
            s += '%41s:%5s (score:%4s)\n' % ('[%s]' % p.ip, p.port, p.score)
        s += '---------- End of Manager peers (%s peers) ----------' % len(self.peers)
        return s


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--forever', action='store_true', default=True,
                        help='loop forever looking for new peers')
    parser.add_argument('-d', '--delay', type=int, default=300,
                        help='delay between crawls in seconds')
    return parser.parse_args()


def main():
    ctx = livectx
    args = parse_args()

    ipv4_addresses = get_all_dns_addresses(ctx['peeraddr'])
    peers = [peer(ipaddress.IPv6Address('::ffff:' + a), ctx['peerport']) for a in ipv4_addresses]

    peerman = peer_manager(peers)
    print(peerman)

    peerman.crawl_once()
    print(peerman)

    while args.forever:
        time.sleep(args.delay)
        peerman.crawl_once()
        print(peerman)

if __name__ == "__main__":
    main()
