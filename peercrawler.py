#!/bin/env python3

from __future__ import annotations

import copy
import logging
import sys
import argparse
import threading
from ipaddress import IPv6Address
import jsonpickle
from functools import reduce
from typing import Iterable, Optional

from pydot import Dot, Node, Edge

import confirm_req
import telemetry_req
from msg_handshake import *
from logger import setup_logging


def get_telemetry(ctx, s):
    req = telemetry_req.telemetry_req(ctx)
    s.sendall(req.serialise())
    hdr, data = get_next_hdr_payload(s)
    while hdr.msg_type != message_type(message_type_enum.telemetry_ack):
        hdr, data = get_next_hdr_payload(s)
    return telemetry_req.telemetry_ack.parse(hdr, data)


class peer_manager:
    def __init__(self, ctx, peers=[], verbosity=0, inactivity_threshold_seconds=0, logger: logging.Logger = None):
        self.ctx = ctx
        self.verbosity = verbosity

        self.mutex = threading.Lock()
        self.peers: set[Peer] = set()
        self.add_peers(peers)

        if logger:
            self.logger = logger
        else:
            self.logger = setup_logging("peercrawler")

        if inactivity_threshold_seconds > 0:
            thread = threading.Thread(target=self.run_periodic_cleanup, args=(inactivity_threshold_seconds,), daemon=True)
            thread.start()

    def add_peers(self, new_peers: Iterable[Peer]):
        with self.mutex:
            for peer in new_peers:
                if peer.ip.ipv6.is_unspecified:
                    continue

                if self.verbosity >= 3:
                    print('adding peer %s' % peer)

                if peer in self.peers:
                    find_peer(peer, self.peers).last_seen = int(time.time())
                else:
                    self.peers.add(peer)

    def run_periodic_cleanup(self, inactivity_threshold_seconds):
        while True:
            with self.mutex:
                cleanup_inactive_peers(self.peers, inactivity_threshold_seconds, self.verbosity)

            time.sleep(inactivity_threshold_seconds)

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

    def listen_incoming(self, port: int):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(("::", port))
            s.listen()

            while True:
                connection, address = s.accept()
                threading.Thread(target=self.handle_incoming, args=(connection, address), daemon=True).start()

    def handle_incoming(self, connection: socket.socket, address):
        self.logger.debug(f"Receiving connection from {address}")

        header, payload = get_next_hdr_payload(connection)
        if header.msg_type == message_type(message_type_enum.node_id_handshake):
            if header.is_response():
                raise CommsError()

            query = handshake_query.parse_query(header, payload)
            signing_key, verifying_key = node_handshake_id.keypair()
            handshake_exchange_server(self.ctx, connection, query, signing_key, verifying_key)
            self.logger.debug(f"Successful handshake from from {address}")
        else:
            self.logger.debug(f"First message from {address} was {header.msg_type}, connection is now closing")
            connection.close()
            return

        start_time = time.time()
        while True:
            if time.time() - start_time > 60:
                self.logger.debug(f"The time limit for receiving a keepalive has been exceeded for {address}, connection is now closing")
                connection.close()
                return

            header, payload = get_next_hdr_payload(connection)
            if header.msg_type == message_type(message_type_enum.keepalive):
                keepalive = message_keepalive.parse_payload(header, payload)
                self.add_peers(keepalive.peers)

                self.logger.debug(f"Received peers from {address}, connection is now closing")
                connection.close()
                return

    def send_keepalive_packet(self, connection: socket):
        local_peer = Peer(ip_addr(IPv6Address("::ffff:78.46.80.199")), 7777)  # this should be changed manually
        packet = message_keepalive.make_packet([local_peer], self.ctx["net_id"], 18)
        connection.send(packet)

    def get_peers_from_peer(self, peer, no_telemetry=False, no_confirm_req=False) -> list[Peer]:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.settimeout(3)

            # try to connect to peer
            try:
                s.connect((str(peer.ip), peer.port))
                s.settimeout(10)
            except OSError as error:
                peer.score = 0
                if self.verbosity >= 3:
                    print('Failed to connect to peer %s, error: %s' % (peer, error))
                return []

            # connected to peer, do handshake followed by listening for the first keepalive
            # and the reply to the confirm request
            # once we get the first keepalive and the confirm ack mtaching the req sent
            # then we have what we need and we move on
            try:
                signing_key, verifying_key = node_handshake_id.keypair()
                peer_id = node_handshake_id.perform_handshake_exchange(self.ctx, s, signing_key, verifying_key)
                peer.peer_id = peer_id

                self.send_keepalive_packet(s)

                if self.verbosity >= 2:
                    print('  ID:%s' % hexlify(peer_id))

                starttime = time.time()
                while time.time() - starttime <= 10:
                    hdr, payload = get_next_hdr_payload(s)
                    if hdr.msg_type == message_type(message_type_enum.keepalive):
                        keepalive = message_keepalive.parse_payload(hdr, payload)
                        peer.score = 1000
                        if not no_telemetry:
                            peer.telemetry = get_telemetry(self.ctx, s)
                        if not no_confirm_req:
                            peer.is_voting = send_confirm_req_genesis(self.ctx, peer, s)

                        return keepalive.peers

                # timeout whilst waiting for keepalive, score it with 2
                peer.score = 2
            except (PyNanoCoinException, OSError) as e:
                # peer was connectable but some other error happpened, score it with 1
                peer.score = 1
                print('Exception %s: %s' % (type(e), e))

            return []

    def crawl_once(self):
        if self.verbosity >= 1:
            print('Starting a peer crawl')

        # it is important to take a copy of the peers so that it is not changing as we walk it
        peers_copy = self.get_peers_copy()
        assert len(peers_copy) > 0

        for p in peers_copy:
            if self.verbosity >= 2:
                print('Query %41s:%5s (score:%4s)' % ('[%s]' % p.ip, p.port, p.score))

            new_peers = self.get_peers_from_peer(p)
            self.add_peers(new_peers)

    def crawl(self, forever, delay):
        initial_peers = get_all_dns_addresses_as_peers(self.ctx['peeraddr'], self.ctx['peerport'], -1)

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
                voting_str = ' (voting)' if p.is_voting else ''
                sw_ver = ''
                cemented_count = ''
                if p.telemetry:
                    sw_ver = ' v' + p.telemetry.get_sw_version()
                    cemented_count = ' cc=%s' % p.telemetry.cemented_count
                s += '%41s:%5s (score:%4s)%s%s%s\n' % \
                     ('[%s]' % p.ip, p.port, p.score, sw_ver, cemented_count, voting_str)
                # if p.score >= 1000:
                #    s += 'ID: %s, voting:%s\n' % (acctools.to_account_addr(p.peer_id, prefix='node_'), p.is_voting)
            s += '---------- End of Manager peers (%s peers, %s good) ----------' % (len(self.peers), good)
        return s


def parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')

    parser.add_argument('-c', '--connect', nargs='?', const='::ffff:78.46.80.199',
                        help='connect to peercrawler service given by arg and get list of peers')

    parser.add_argument('-v', '--verbosity', type=int,
                        help='verbosity level')
    parser.add_argument('-f', '--forever', action='store_true', default=False,
                        help='loop forever looking for new peers')
    parser.add_argument('-d', '--delay', type=int, default=300,
                        help='delay between crawls in seconds')
    parser.add_argument('-s', '--service', action='store_true', default=False,
                        help='run peer crawler as a service')
    parser.add_argument('-l', '--listen', action='store_true', default=False,
                        help='listen to incoming connections')
    parser.add_argument('-p', '--port', type=int, default=7070,
                        help='tcp port number to listen on in service mode')
    return parser.parse_args()


class peer_service_header:
    size = 124

    def __init__(self, net_id, good_peers, total_peers, software_ver="devel", protocol_ver=3):
        self.magic = b'PEER'
        assert (isinstance(net_id, network_id))
        assert (isinstance(software_ver, str))
        self.net_id = net_id
        self.good_peers = good_peers
        self.total_peers = total_peers
        self.software_ver = software_ver
        self.protocol_ver = protocol_ver

    def serialise(self):
        data = self.magic
        data += self.net_id.id.to_bytes(1, "big")
        data += self.protocol_ver.to_bytes(3, "big")
        data += self.good_peers.to_bytes(8, "big")
        data += self.total_peers.to_bytes(8, "big")
        data += string_to_bytes(self.software_ver, 100)
        return data

    @classmethod
    def parse(cls, data):
        assert (len(data) == peer_service_header.size)
        assert (data[0:4] == b'PEER')
        return peer_service_header(
            net_id=network_id(data[4]),
            protocol_ver=int.from_bytes(data[5:8], "big"),
            good_peers=int.from_bytes(data[8:16], "big"),
            total_peers=int.from_bytes(data[16:24], "big"),
            software_ver=data[24:].decode("utf-8")
        )

    def __str__(self):
        s = ''
        s += 'NetID:      %s\n' % self.net_id
        s += 'GoodPeers:  %s\n' % self.good_peers
        s += 'TotalPeers: %s\n' % self.total_peers
        s += 'ProtoVers:  %s\n' % self.protocol_ver
        s += 'SwVers:     %s' % self.software_ver
        return s


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


class network_connections():
    def __init__(self, peerman: peer_manager, inactivity_threshold_seconds=0, verbosity=0):
        self.peerman = peerman
        self.inactivity_threshold_seconds = inactivity_threshold_seconds
        self.verbosity = verbosity

        self.__connections: dict[Peer, set[Peer]] = {}

    def register_connections(self, peer: Peer, new_peers: Iterable[Peer]):
        for new_peer in new_peers:
            if new_peer.ip.ipv6.is_unspecified:
                continue

            if new_peer not in self.__connections:
                self.__connections[new_peer] = set()

            peer_connections = self.__connections[peer]
            if new_peer in peer_connections:
                find_peer(new_peer, peer_connections).last_seen = int(time.time())
            else:
                peer_connections.add(new_peer)

    def get_connections(self) -> dict[Peer, set[Peer]]:
        return copy.deepcopy(self.__connections)

    def run(self, initial_peer: Peer, interval_seconds=0):
        self.__connections[initial_peer] = set()

        while True:
            peers_list = [peer for peer in self.__connections]
            for peer in peers_list:
                new_peers = self.peerman.get_peers_from_peer(peer)
                self.register_connections(peer, new_peers)
                print(f"Received peers from {peer.ip}, active peer count for this peer is now {self.__connections[peer].__len__()}\nNow tracking {len(self.__connections)} peers in total")

            if self.inactivity_threshold_seconds > 0:
                for _, peers in self.__connections.items():
                    cleanup_inactive_peers(peers, self.inactivity_threshold_seconds, self.verbosity)

            time.sleep(interval_seconds)

    def get_connections_flat(self) -> set[tuple[Peer, Peer]]:
        connections = set()

        for peer_origin, peers in self.__connections.items():
            for peer_destination in peers:
                connections.add((peer_origin, peer_destination))

        return connections


def spawn_peer_crawler_thread(ctx, forever, delay, verbosity):
    t = peer_crawler_thread(ctx, forever, delay, verbosity)
    t.start()
    return t


def run_peer_service_forever(peerman, addr='', port=7070):
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((addr, port))
        s.listen()

        while True:
            conn, addr = s.accept()
            with conn:
                conn.settimeout(10)
                hdr = peer_service_header(peerman.ctx["net_id"], peerman.count_good_peers(), peerman.count_peers())
                data = hdr.serialise()
                json_list = jsonpickle.encode(peerman.get_peers_copy())
                data += json_list.encode()
                conn.sendall(data)


def get_peers_from_service(ctx, addr='::ffff:78.46.80.199'):
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(10)
        try:
            s.connect((addr, ctx['peercrawlerport']))
            response = readall(s)
            hdr = peer_service_header.parse(response[0:peer_service_header.size])
            assert (hdr.protocol_ver == 3)
            if hdr.net_id != ctx['net_id']:
                raise PeerServiceUnavailable("Peer service for the given network is unavailable")
        except (PyNanoCoinException, OSError, TypeError) as e:
            print("Error getting peers: %s" % str(e))
            raise PeerServiceUnavailable("Peer service is unavailable")

        json_peers = response[peer_service_header.size:]
        peers = jsonpickle.decode(json_peers)
    return hdr, peers


def get_initial_connected_socket(ctx, peers=None):
    if peers is None or len(peers) == 0:
        _, peers = get_peers_from_service(ctx)
        peers = list(peers)
        random.shuffle(peers)
    for peer in peers:
        peeraddr = str(peer.ip)
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(3)
        try:
            s.connect((peeraddr, peer.port))
            print('Connected to [%s]:%s' % (s.getpeername()[0], s.getpeername()[1]))
            return s, peeraddr
        except socket.error as e:
            print('Failed to connect to %s' % peer)
            print(e)

    print('Failed to connect to any of the peering servers')
    return None, None


def get_random_peer(ctx, filter_func=None):
    ''' This fucntion connects to the peer service and get all the known peers
        applies the filter function, if given
        and return a random peer from the filtered set
    '''
    hdr, peers = get_peers_from_service(ctx)
    if filter_func is not None:
        peers = list(filter(filter_func, peers))
    return random.choice(peers)


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


def send_confirm_req_genesis(ctx, peer, s):
    assert (isinstance(peer, Peer))
    block = block_open(ctx["genesis_block"]["source"], ctx["genesis_block"]["representative"],
                       ctx["genesis_block"]["account"], ctx["genesis_block"]["signature"],
                       ctx["genesis_block"]["work"])

    try:
        outcome = confirm_req.confirm_block(ctx, block, s)
    except (PyNanoCoinException, OSError):
        outcome = False

    return outcome


# NOTE: this is a free standing function because it is used by both peer and conection managers
def cleanup_inactive_peers(peers: set[Peer], inactivity_threshold_seconds: int, verbosity: int):
    for peer in peers.copy():
        if int(time.time()) - peer.last_seen > inactivity_threshold_seconds:
            if verbosity >= 2:
                print('removing inactive peer %s' % peer)
            peers.remove(peer)


def find_peer(item: Peer, collection: set[Peer]) -> Optional[Peer]:
    for i in collection:
        if i == item:
            return i

    return None


# noinspection PyUnresolvedReferences
def get_dot_string(connections: dict[Peer, set[Peer]], only_voting: bool = False) -> str:
    def get_label(p: Peer) -> str:
        if p.ip.ipv6.ipv4_mapped is None:
            ip = f"[{p.ip.ipv6}]"
        else:
            ip = f"[{p.ip.ipv6.ipv4_mapped}]"

        if p.port == 7075:
            port = ""
        else:
            port = f":{p.port}"

        return ip + port

    graph = Dot("network_connections", graph_type="digraph")
    for node, peers in connections.items():
        for peer in peers:
            if only_voting and not (node.is_voting and peer.is_voting):
                continue

            graph.add_edge(Edge(get_label(node), get_label(peer)))

    return graph.to_string()


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

        if args.listen:
            threading.Thread(target=peerman.listen_incoming, args=(args.port,), daemon=True).start()

        peerman.crawl(args.forever, args.delay)


if __name__ == "__main__":
    main()
