#!/bin/env python3
import ipaddress
import random
import socket
import copy
import time
import argparse
import threading
import jsonpickle

from pynanocoin import *


class peer_manager:
    def __init__(self, peers=[], verbosity=0):
        self.mutex = threading.Lock()
        self.peers = set()
        self.verbosity = verbosity
        self.add_peers(peers)

    def add_peers(self, newpeers):
        with self.mutex:
            for p in newpeers:
                if self.verbosity >= 2:
                    print('adding peer %s' % p)
                self.peers.add(p)

    def get_peers_copy(self):
        with self.mutex:
            return copy.copy(self.peers)

    def get_peers_from_peer(self, peer, ctx):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.settimeout(3)

            # try to connect to peer
            try:
                s.connect((str(peer.ip), peer.port))
            except socket.error as error:
                peer.score = 0
                if self.verbosity >= 2:
                    print('Failed to connect to peer %s, error: %s' % (peer, error))
                return

            # connected to peer, do handshake followed by listening for the first keepalive
            # once we get the first keepalive, we have what we need and we move on
            try:
                peer_id = perform_handshake_exchange(ctx, s)
                peer.peer_id = peer_id
                if self.verbosity >= 1:
                    print('  %s' % hexlify(peer_id))
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
            except OSError as e:
                # peer was connectable but some other error happpened, score it with 1
                peer.score = 1
                print('Exception %s: %s' % (type(e), e))
            except PyNanoCoinException as e:
                # peer was connectable but some other error happpened, score it with 1
                peer.score = 1
                print('Exception %s: %s' % (type(e), e))

    def crawl_once(self, ctx):
        if self.verbosity >= 1:
            print('Starting a peer crawl')

        # it is important to take a copy of the peers so that it is not changing as we walk it
        peers_copy = self.get_peers_copy()
        assert len(peers_copy) > 0

        for p in peers_copy:
            if self.verbosity >= 1:
                print('Query %41s:%5s (score:%4s)' % ('[%s]' % p.ip, p.port, p.score))
            self.get_peers_from_peer(p, ctx)

    def crawl(self, ctx, forever, delay):
        addresses = get_all_dns_addresses(ctx['peeraddr'])
        initial_peers = [peer(ip_addr(ipaddress.IPv6Address(a)), ctx['peerport']) for a in addresses]

        self.add_peers(initial_peers)
        if self.verbosity >= 1:
            print(self)

        self.crawl_once(ctx)
        if self.verbosity >= 1:
            print(self)

        while forever:
            time.sleep(delay)
            self.crawl_once(ctx)
            if self.verbosity >= 1:
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
    parser.add_argument('-b', '--beta', action='store_true', default=False,
                        help='use beta network')
    parser.add_argument('-v', '--verbosity', type=int,
                        help='verbosity level')
    parser.add_argument('-f', '--forever', action='store_true', default=True,
                        help='loop forever looking for new peers')
    parser.add_argument('-d', '--delay', type=int, default=300,
                        help='delay between crawls in seconds')
    parser.add_argument('-s', '--service', action='store_true', default=False,
                        help='run peer crawler as a service')
    parser.add_argument('-p', '--port', type=int, default=12345,
                        help='tcp port number to listen on in service mode')
    return parser.parse_args()


class peer_crawler_thread(threading.Thread):
    def __init__(self, ctx, forever, delay, verbosity=0):
        threading.Thread.__init__(self, daemon=True)
        self.ctx = ctx
        self.forever = forever
        self.delay = delay
        self.peerman = peer_manager(verbosity=verbosity)

    def run(self):
        print('Starting peer crawler in a thread')
        self.peerman.crawl(self.ctx, self.forever, self.delay)
        print('Peer crawler thread ended')


def spawn_peer_crawler_thread(ctx, forever, delay, verbosity):
    t = peer_crawler_thread(ctx, forever, delay, verbosity)
    t.start()
    return t


def run_peer_service_forever(peerman, addr='::1', port=12345):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    s.listen()

    while True:
        conn, addr = s.accept()
        conn.settimeout(5)
        json_list = jsonpickle.encode(peerman.get_peers_copy())
        conn.send(json_list.encode())
        conn.close()


def get_all_peers(addr='::1'):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.settimeout(5)
    try:
        s.connect((addr, 12345))
    except ConnectionRefusedError:
        return None
    json_peers = readall(s)
    peers = jsonpickle.decode(json_peers)
    s.close()
    return peers


def main():
    args = parse_args()
    ctx = betactx if args.beta else livectx

    if args.service:
        verbosity = args.verbosity if (args.verbosity is not None) else 0
        crawler_thread = spawn_peer_crawler_thread(ctx, True, args.delay, verbosity)
        run_peer_service_forever(crawler_thread.peerman, port=args.port)
    else:
        verbosity = args.verbosity if (args.verbosity is not None) else 1
        peerman = peer_manager(verbosity=verbosity)
        peerman.crawl(ctx, args.forever, args.delay)


if __name__ == "__main__":
    main()
