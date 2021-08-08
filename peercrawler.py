#!/bin/env python3
import ipaddress
import random
import socket
import copy
import time
import sys
import argparse
import threading
import jsonpickle
from functools import reduce

from pynanocoin import *


class peer_manager:
    def __init__(self, ctx, peers=[], verbosity=0):
        self.ctx = ctx
        self.mutex = threading.Lock()
        self.peers = set()
        self.verbosity = verbosity
        self.add_peers(peers)

    def add_peers(self, newpeers):
        with self.mutex:
            for p in newpeers:
                if self.verbosity >= 3:
                    print('adding peer %s' % p)
                self.peers.add(p)

    def get_peers_copy(self):
        with self.mutex:
            return copy.copy(self.peers)

    def count_good_peers(self):
        counter = 0
        for p in self.get_peers_copy():
            if p.score >= 1000:
                counter += 1
        return counter

    def count_peers(self):
        return len(self.get_peers_copy())

    def get_peers_from_peer(self, peer):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.settimeout(3)

            # try to connect to peer
            try:
                s.connect((str(peer.ip), peer.port))
            except socket.error as error:
                peer.score = 0
                if self.verbosity >= 3:
                    print('Failed to connect to peer %s, error: %s' % (peer, error))
                return

            # connected to peer, do handshake followed by listening for the first keepalive
            # once we get the first keepalive, we have what we need and we move on
            try:
                peer_id = perform_handshake_exchange(self.ctx, s)
                peer.peer_id = peer_id
                if self.verbosity >= 2:
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

    def crawl_once(self):
        if self.verbosity >= 1:
            print('Starting a peer crawl')

        # it is important to take a copy of the peers so that it is not changing as we walk it
        peers_copy = self.get_peers_copy()
        assert len(peers_copy) > 0

        for p in peers_copy:
            if self.verbosity >= 2:
                print('Query %41s:%5s (score:%4s)' % ('[%s]' % p.ip, p.port, p.score))
            self.get_peers_from_peer(p)

    def crawl(self, forever, delay):
        addresses = get_all_dns_addresses(self.ctx['peeraddr'])
        initial_peers = [Peer(ip_addr(ipaddress.IPv6Address(a)), self.ctx['peerport']) for a in addresses]

        self.add_peers(initial_peers)
        if self.verbosity >= 1:
            print(self)

        self.crawl_once()
        if self.verbosity >= 1:
            print(self)

        count = 1
        while forever:
            # for a faster startup, do not delay the first 5 times
            if count > 5:
                time.sleep(delay)
            self.crawl_once()
            if self.verbosity >= 1:
                print(self)
            count += 1

    def __str__(self):
        with self.mutex:
            good = reduce(lambda c, p: c + int(p.score >= 1000), self.peers, 0)
            s = '---------- Start of Manager peers (%s peers, %s good) ----------\n' % (len(self.peers), good)
            for p in self.peers:
                s += '%41s:%5s (score:%4s)\n' % ('[%s]' % p.ip, p.port, p.score)
            s += '---------- End of Manager peers (%s peers, %s good) ----------' % (len(self.peers), good)
        return s


def parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')

    parser.add_argument('-c', '--connect',
                        help='connect to peercrawler service given by arg and get list of peers')

    parser.add_argument('-v', '--verbosity', type=int,
                        help='verbosity level')
    parser.add_argument('-f', '--forever', action='store_true', default=True,
                        help='loop forever looking for new peers')
    parser.add_argument('-d', '--delay', type=int, default=300,
                        help='delay between crawls in seconds')
    parser.add_argument('-s', '--service', action='store_true', default=False,
                        help='run peer crawler as a service')
    parser.add_argument('-p', '--port', type=int, default=7070,
                        help='tcp port number to listen on in service mode')
    return parser.parse_args()


class peer_service_header:
    def __init__(self, net_id, good_peers, total_peers, software_ver = "1.1", protocol_ver = 1):
        self.magic = b'PEER'
        assert(isinstance(net_id, network_id))
        assert(isinstance(software_ver, str))
        self.net_id = net_id
        self.good_peers = good_peers
        self.total_peers = total_peers
        self.software_ver = software_ver
        self.protocol_ver = protocol_ver

    def serialise(self):
        data = self.magic
        data += self.net_id.id.to_bytes(1, "big")
        data += string_to_bytes(self.software_ver, 100)
        data += self.protocol_ver.to_bytes(1, "big")
        data += self.good_peers.to_bytes(8, "big")
        data += self.total_peers.to_bytes(8, "big")
        return data

    @classmethod
    def parse(cls, data):
        assert(len(data) == 122)
        assert(data[0:4] == b'PEER')
        return peer_service_header(network_id(data[4]), int.from_bytes(data[107:114], "big"),
                                   int.from_bytes(data[114:], "big"), software_ver=data[5:105].decode("utf-8"),
                                   protocol_ver=data[106])


class peer_crawler_thread(threading.Thread):
    def __init__(self, ctx, forever, delay, verbosity=0):
        threading.Thread.__init__(self, daemon=True)
        self.ctx = ctx
        self.forever = forever
        self.delay = delay
        self.peerman = peer_manager(ctx, verbosity=verbosity)

    def run(self):
        print('Starting peer crawler in a thread')
        self.peerman.crawl(self.forever, self.delay)
        print('Peer crawler thread ended')


def spawn_peer_crawler_thread(ctx, forever, delay, verbosity):
    t = peer_crawler_thread(ctx, forever, delay, verbosity)
    t.start()
    return t


def run_peer_service_forever(peerman, addr='', port=7070):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    s.listen()

    while True:
        conn, addr = s.accept()
        conn.settimeout(5)
        hdr = peer_service_header(peerman.ctx["net_id"], peerman.count_good_peers(), peerman.count_peers())
        data = hdr.serialise()
        json_list = jsonpickle.encode(peerman.get_peers_copy())
        data += json_list.encode()
        conn.send(data)
        conn.close()


def get_peers_from_service(ctx, addr = '::1'):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.settimeout(5)
    try:
        s.connect((addr, 7070))
        response = readall(s)
        hdr = peer_service_header.parse(response[0:122])
        if hdr.net_id != ctx['net_id']:
            raise PeerServiceUnavailable("Peer service for the given network is unavailable")
    except (ConnectionRefusedError, TypeError) as e:
        print("Error getting peers: %s" % str(e))
        raise PeerServiceUnavailable("Peer service is unavailable")

    json_peers = response[122:]
    peers = jsonpickle.decode(json_peers)
    s.close()
    return hdr, peers


def string_to_bytes(string, length):
    data = string.encode("utf-8")
    assert (len(data) <= length)
    size_offset = length - len(data)
    if size_offset != 0:
        data += b'\x00' * size_offset
    return data


def do_connect(ctx, server):
    print('server =', server)
    _, peers = get_peers_from_service(ctx, addr=server)
    peerman = peer_manager(ctx, peers, 2)
    print(peerman)


def main():
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx

    if args.connect:
        do_connect(ctx, args.connect)
        sys.exit(0)

    if args.service:
        verbosity = args.verbosity if (args.verbosity is not None) else 0
        crawler_thread = spawn_peer_crawler_thread(ctx, True, args.delay, verbosity)
        run_peer_service_forever(crawler_thread.peerman, port=args.port)
    else:
        verbosity = args.verbosity if (args.verbosity is not None) else 1
        peerman = peer_manager(ctx, verbosity=verbosity)
        peerman.crawl(args.forever, args.delay)


if __name__ == "__main__":
    main()
