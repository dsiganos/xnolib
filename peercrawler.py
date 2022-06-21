#!/bin/env python3

from __future__ import annotations

import copy
import logging
import sys
import argparse
import threading
from _thread import interrupt_main
from ipaddress import IPv6Address
import jsonpickle
from functools import reduce
from typing import Collection, Iterable, Optional, Callable
from concurrent.futures import ThreadPoolExecutor

import requests
from pydot import Dot, Node, Edge

import _logger
import confirm_req
import telemetry_req
from msg_handshake import *
from peer_set import peer_set
from confirm_ack import confirm_ack
from peer import Peer


logger = _logger.get_logger()


def get_telemetry(ctx, s):
    req = telemetry_req.telemetry_req(ctx)
    s.sendall(req.serialise())
    hdr, data = get_next_hdr_payload(s)
    while hdr.msg_type != message_type(message_type_enum.telemetry_ack):
        hdr, data = get_next_hdr_payload(s)
    return telemetry_req.telemetry_ack.parse(hdr, data)


class peer_manager:
    def __init__(self, ctx,
                 verbosity=0,
                 peers: Iterable[Peer] = None, inactivity_threshold_seconds=0,
                 listen=True, listening_port=7777):
        self.ctx = ctx
        self.verbosity = verbosity
        self.mutex = threading.Lock()
        self.listening_port = listening_port

        self.__connections_graph: dict[Peer, peer_set] = {}

        if peers:
            for peer in peers:
                self.add_peers(peer, [])

        if listen:
            threading.Thread(target=self.listen_incoming, daemon=True).start()

        if inactivity_threshold_seconds > 0:
            thread = threading.Thread(target=self.run_periodic_cleanup, args=(inactivity_threshold_seconds,), daemon=True)
            thread.start()

    def add_peers(self, from_peer: Peer, new_peers: Iterable[Peer]):
        def find_existing_peer(peer: Peer):
            for p in self.__connections_graph:
                if p == peer:
                    return p

        with self.mutex:
            if from_peer not in self.__connections_graph:
                self.__connections_graph[from_peer] = peer_set()

            for new_peer in new_peers:
                if new_peer.ip.ipv6.is_unspecified:
                    continue

                # if there's already a peer object in the graph representing the same peer as new_peer,
                # the existing one should be used
                if new_peer in self.__connections_graph:
                    new_peer = find_existing_peer(new_peer)
                else:
                    self.__connections_graph[new_peer] = peer_set()
                    logger.debug(f"Discovered new peer {new_peer}")

                self.__connections_graph[from_peer].add(new_peer)

    def run_periodic_cleanup(self, inactivity_threshold_seconds):
        while True:
            with self.mutex:
                for peer_collection in self.__connections_graph.values():
                    peer_collection.cleanup_inactive(inactivity_threshold_seconds)

            time.sleep(inactivity_threshold_seconds)

    def get_peers_as_list(self) -> Collection[Peer]:
        with self.mutex:
            return self.__connections_graph.keys()

    def get_connections_graph(self) -> dict[Peer, set[Peer]]:
        with self.mutex:
            return self.__connections_graph.copy()

    def count_good_peers(self):
        counter = 0
        for p in self.get_peers_as_list():
            if p.score >= 1000:
                counter += 1
        return counter

    def count_peers(self):
        return len(self.get_peers_as_list())

    def listen_incoming(self):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            try:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("::", self.listening_port))
                s.listen()

                semaphore = threading.BoundedSemaphore(8)

                while True:
                    semaphore.acquire()
                    connection, address = s.accept()
                    threading.Thread(target=self.__handle_incoming_semaphore, args=(semaphore, connection, address), daemon=True).start()
            except:
                logger.exception("Error occurred in listener thread")
                interrupt_main()

    def __handle_incoming_semaphore(self, semaphore: threading.BoundedSemaphore, connection: socket.socket, address):
        try:
            result = self.handle_incoming(connection, address, self.ctx)
            if result:
                self.add_peers(result[0], result[1])
        finally:
            semaphore.release()
            connection.close()

    @staticmethod
    def handle_incoming(connection: socket.socket, address, ctx: dict) -> Optional[tuple[Peer, list[Peer], bool]]:
        logger.log(_logger.VERBOSE, f"Receiving connection from {address}")

        incoming_peer = Peer(ip_addr.from_string(address[0]), address[1], incoming=True)
        incoming_peer_peers = None
        is_voting = False

        header, payload = get_next_hdr_payload(connection)
        if header.msg_type == message_type(message_type_enum.node_id_handshake):
            if header.is_response():
                logger.info(f"The first node ID handshake package received from {address} has the response flag set, connection is now closing")
                return

            query = handshake_query.parse_query(header, payload)
            signing_key, verifying_key = node_handshake_id.keypair()
            handshake_exchange_server(ctx, connection, query, signing_key, verifying_key)
            logger.debug(f"Successful handshake from from {address}")

            telemetry_request = telemetry_req.telemetry_req(ctx)
            connection.sendall(telemetry_request.serialise())

            block = block_open(ctx["genesis_block"]["source"], ctx["genesis_block"]["representative"],
                               ctx["genesis_block"]["account"], ctx["genesis_block"]["signature"],
                               ctx["genesis_block"]["work"])
            confirm_request = confirm_req.confirm_req_block(message_header(ctx['net_id'], [18, 18, 18], message_type(4), 0), block)
            connection.sendall(confirm_request.serialise())

        else:
            logger.debug(f"First message from {address} was {header.msg_type}, connection is now closing")
            return

        start_time = time.time()
        while incoming_peer.telemetry is None or incoming_peer_peers is None or is_voting is False:
            if time.time() - start_time > 15:
                logger.info(f"The time limit for receiving a keepalive and telemetry has been exceeded for {address}, connection is now closing")
                return

            header, payload = get_next_hdr_payload(connection)
            if header.msg_type == message_type(message_type_enum.telemetry_ack):
                incoming_peer.telemetry = telemetry_req.telemetry_ack.parse(header, payload)
                logger.debug(f"Received telemetry from {address}")

            elif header.msg_type == message_type(message_type_enum.keepalive):
                keepalive = message_keepalive.parse_payload(header, payload)
                logger.debug(f"Received peers from {address}")
                incoming_peer_peers = keepalive.peers

            elif header.msg_type == message_type(message_type_enum.confirm_ack):
                confirm_response = confirm_ack.parse(header, payload)
                if confirm_request.is_response(confirm_response):
                    is_voting = True
                    logger.debug(f"Received confirm_ack message from {address}")

        return incoming_peer, incoming_peer_peers, is_voting

    def send_keepalive_packet(self, connection: socket):
        local_peer = Peer(ip_addr(IPv6Address("::ffff:78.46.80.199")), self.listening_port)  # this should be changed manually
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
                logger.log(_logger.VERBOSE, f"Failed to connect to peer {peer}", exc_info=True)
                return []

            # connected to peer, do handshake followed by listening for the first keepalive
            # and the reply to the confirm request
            # once we get the first keepalive and the confirm ack mtaching the req sent
            # then we have what we need and we move on
            try:
                signing_key, verifying_key = node_handshake_id.keypair()
                peer_id = node_handshake_id.perform_handshake_exchange(self.ctx, s, signing_key, verifying_key)
                peer.peer_id = peer_id
                logger.debug(f"ID: {hexlify(peer_id)}")

                self.send_keepalive_packet(s)

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

    def crawl_once(self, max_workers=4):
        logger.info("Starting a peer crawl")

        # it is important to take a copy of the peers so that it is not changing as we walk it
        peers_copy = self.get_peers_as_list()
        assert len(peers_copy) > 0

        def crawl_peer(peer: Peer):
            # catch unexpected exceptions here otherwise they get lost/ignored due to ThreadPoolExecutor
            try:
                logger.debug("Query %39s:%5s (score:%4s)" % ('[%s]' % p.ip, p.port, p.score))
                self.add_peers(peer, self.get_peers_from_peer(peer))
            except Exception as e:
                logger.error(f"Unexpected exception while crawling peer [{peer.ip}]:{peer.port}", exc_info=True, stack_info=True)

        with ThreadPoolExecutor(max_workers=max_workers) as t:
            for p in peers_copy:
                t.submit(crawl_peer, peer=p)

    def crawl(self, forever, delay, max_workers=4):
        initial_peers = get_all_dns_addresses_as_peers(self.ctx['peeraddr'], self.ctx['peerport'], -1)
        for peer in initial_peers:
            self.add_peers(peer, [])

        self.crawl_once(max_workers)
        logger.info(self)

        count = 1
        while forever:
            if count > 5:  # for a faster startup, do not delay the first 5 times
                time.sleep(delay)

            self.crawl_once(max_workers)
            logger.info(self)
            count += 1

    # noinspection PyUnresolvedReferences
    def get_dot_string(self, should_draw_edge: Callable[[Peer, Peer], bool] = None) -> str:
        def get_label(p: Peer) -> str:
            if p.ip.ipv6.ipv4_mapped is None:
                address = f"{p.ip.ipv6}"
            else:
                address = f"{p.ip.ipv6.ipv4_mapped}"

            if p.port != self.ctx["peerport"]:
                address = f"[{address}]:{p.port}"

            return address

        graph = Dot("network_connections", graph_type="digraph")
        for node, peers in self.get_connections_graph().items():
            for peer in peers:
                if should_draw_edge is not None and not should_draw_edge(node, peer):
                    continue

                graph.add_edge(Edge(get_label(node), get_label(peer)))

        return graph.to_string()

    def peer_to_string(self, p: Peer) -> str:
        s = '%39s:%5s score=%-4s' % (p.ip, p.port, p.score)

        if p.telemetry:
            s += ' v%-10s' % p.telemetry.get_sw_version()
            s += ' cc=%11s' % format(p.telemetry.cemented_count, ',')

        s += ' (voting)\n' if p.is_voting else '\n'
        return s

    def __str__(self):
        peers = self.get_peers_as_list()
        good = reduce(lambda c, p: c + int(p.score >= 1000), peers, 0)
        s = '---------- Start of Manager peers (%s peers, %s good) ----------\n' % (len(peers), good)
        for p in peers:
            s += self.peer_to_string(p)
        s += '---------- End of Manager peers (%s peers, %s good) ----------' % (len(peers), good)

        return s


def parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')

    # empty string singifies existance of switch but lack of argument
    parser.add_argument('-c', '--connect', nargs='?', const='',
                        help='connect to peercrawler service given by arg and get list of peers')

    parser.add_argument('-v', '--verbosity', type=int, default=0,
                        help='verbosity level')
    parser.add_argument('-f', '--forever', action='store_true', default=False,
                        help='loop forever looking for new peers')
    parser.add_argument('-d', '--delay', type=int, default=300,
                        help='delay between crawls in seconds')
    parser.add_argument('-s', '--service', action='store_true', default=False,
                        help='run peer crawler as a service')
    parser.add_argument('-l', '--nolisten', action='store_true', default=False,
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
                json_list = jsonpickle.encode(peerman.get_peers_as_list())
                data += json_list.encode()
                conn.sendall(data)


def get_peers_from_service(ctx: dict, url = None):
    if url is None:
        url = ctx['peerserviceurl']
    session = requests.Session()
    resp = session.get(url, timeout=5)
    json_resp = resp.json()
    return [ Peer.from_json(r) for r in json_resp ]


def get_initial_connected_socket(ctx, peers=None):
    if peers is None or len(peers) == 0:
        peers = get_peers_from_service(ctx)
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
    peers = get_peers_from_service(ctx)
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
    peers = get_peers_from_service(ctx, url=server)
    peerman = peer_manager(ctx, peers=peers, verbosity=2, listen=False)
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


def main():
    args = parse_args()
    _logger.setup_logger(logger, _logger.get_logging_level_from_int(args.verbosity))

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx

    if args.connect is not None:
        do_connect(ctx, None if args.connect == '' else args.connect)
        sys.exit(0)

    if args.service:
        verbosity = args.verbosity if (args.verbosity is not None) else 0
        crawler_thread = spawn_peer_crawler_thread(ctx, True, args.delay, verbosity)
        run_peer_service_forever(crawler_thread.peerman, port=args.port)
    else:
        verbosity = args.verbosity if (args.verbosity is not None) else 1
        peerman = peer_manager(ctx, listen=(not args.nolisten), verbosity=verbosity)
        peerman.crawl(args.forever, args.delay)


if __name__ == "__main__":
    main()
