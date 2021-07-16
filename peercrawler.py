#!/bin/env python3
import ipaddress
import random
import socket
import copy
import time
import argparse
import threading

from nanolib import *


class peer_manager:
    def __init__(self, peers=[]):
        self.mutex = threading.Lock()
        self.peers = set()
        self.add_peers(peers)

    def add_peers(self, newpeers):
        with self.mutex:
            for p in newpeers:
                #print('adding peer %s' % p)
                self.peers.add(p)

    def get_peers_copy(self):
        with self.mutex:
            return copy.copy(self.peers)

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
        print('Starting a peer crawl')

        # it is important to take a copy of the peers so that it is not changing as we walk it
        peers_copy = self.get_peers_copy()
        assert len(peers_copy) > 0

        for p in peers_copy:
            print('Query %41s:%5s (score:%4s)' % ('[%s]' % p.ip, p.port, p.score))
            self.get_peers_from_peer(p)

    def crawl(self, ctx, forever, delay):
        ipv4_addresses = get_all_dns_addresses(ctx['peeraddr'])
        initial_peers = [peer(ipaddress.IPv6Address('::ffff:' + a), ctx['peerport']) for a in ipv4_addresses]

        self.add_peers(initial_peers)
        print(self)

        self.crawl_once()
        print(self)

        while forever:
            time.sleep(delay)
            self.crawl_once()
            print(self)

    def __str__(self):
        with self.mutex:
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


class peer_crawler_thread(threading.Thread):
    def __init__(self, ctx, forever, delay):
        threading.Thread.__init__(self, daemon=False)
        self.ctx = ctx
        self.forever = forever
        self.delay = delay
        self.peerman = peer_manager()

    def run(self):
        print('Starting peer crawler in a thread')
        self.peerman.crawl(self.ctx, self.forever, self.delay)
        print('Peer crawler thread ended')


def spawn_peer_crawler_thread(ctx, forever, delay):
    t = peer_crawler_thread(ctx, forever, delay)
    t.start()
    return t


def main():
    ctx = livectx
    args = parse_args()

    peerman = peer_manager()
    peerman.crawl(ctx, args.forever, args.delay)


if __name__ == "__main__":
    main()
