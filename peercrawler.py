#!/usr/bin/env python3

from __future__ import annotations

import sys
import argparse
import threading
from _thread import interrupt_main
import jsonpickle
from functools import reduce
from typing import Collection, Iterable, Optional, Callable
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

import requests
from pydot import Dot, Node, Edge

import common
import _logger
import jsonencoder
import telemetry_req
from args import add_network_switcher_args
from msg_handshake import *
import confirm_req
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
                 verbosity=0, initial_graph: dict[Peer, peer_set] = None,
                 peers: Iterable[Peer] = None, inactivity_threshold_seconds=0,
                 listening_address: Optional[str] = None, listening_port=7777):
        self.ctx = ctx
        self.verbosity = verbosity
        self.mutex = threading.Lock()
        self.listening_address: Optional[ip_addr] = ip_addr.from_string(listening_address) if listening_address is not None else None
        self.listening_port = listening_port

        self.__connections_graph: dict[Peer, peer_set]
        if initial_graph is None:
            self.__connections_graph = {}
        else:
            self.__connections_graph = initial_graph.copy()

        if peers:
            for peer in peers:
                self.add_peers(peer, [])

        if self.listening_address:
            threading.Thread(target=self.listen_incoming, daemon=True).start()

        if inactivity_threshold_seconds > 0:
            thread = threading.Thread(target=self.__run_periodic_cleanup, args=(inactivity_threshold_seconds,), daemon=True)
            thread.start()

    def add_peers(self, from_peer: Peer, new_peers: Iterable[Peer]):
        def find_existing_peer(peer: Peer) -> Optional[Peer]:
            """Looks through the connection graph keys for the same peer."""
            for p in self.__connections_graph:
                if p.compare(peer):
                    return p

        with self.mutex:
            existing_peer = find_existing_peer(from_peer)
            if existing_peer:
                existing_peer.merge(from_peer)
                from_peer = existing_peer
            else:
                self.__connections_graph[from_peer] = peer_set()  # add this peer as a key to the graph
                logger.debug(f"Discovered new peer {from_peer}")

            for new_peer in new_peers:
                if new_peer.ip.ipv6.is_unspecified:
                    continue

                # if there's already a peer object in the graph representing the same peer as new_peer,
                # the existing one should be used
                existing_peer = find_existing_peer(new_peer)
                if existing_peer:  # if this peer was already known, simply register the connection
                    existing_peer.merge(new_peer)
                    self.__connections_graph[from_peer].add(existing_peer)
                else:
                    self.__connections_graph[new_peer] = peer_set()
                    self.__connections_graph[from_peer].add(new_peer)
                    logger.debug(f"Discovered new peer {new_peer}")

    def __run_periodic_cleanup(self, inactivity_threshold_seconds):
        while True:
            time.sleep(inactivity_threshold_seconds)
            logger.info("Running inactive peer cleanup")
            with self.mutex:
                t = time.time()
                for peer in self.__connections_graph.copy().keys():
                    if t - peer.last_seen > inactivity_threshold_seconds:
                        self.__remove_peer(peer)
                        logger.debug(f"Removing peer {peer} due to inactivity")

    def __remove_peer(self, peer: Peer) -> None:
        """
        Removes the node representing this peer from the graph and all the edges connected to it.
        The peer argument should be the exact same instance present in the graph, and not a "similar" instance.
        """
        for peer_collection in self.__connections_graph.values():  # remove all the edges connected to that node
            peer_collection.remove(peer)

        del self.__connections_graph[peer]  # remove the node and its edges

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
            except Exception:
                logger.exception("Error occurred in listener thread")
                interrupt_main()

    def __handle_incoming_semaphore(self, semaphore: threading.BoundedSemaphore, connection: socket.socket, address):
        try:
            result = self.handle_incoming(connection, address, self.ctx)
            if result:
                self.add_peers(result[0], result[1])
        except (CommsError, SocketClosedByPeer):
            logger.log(_logger.VERBOSE, f"Error in connection to peer {address}")
        finally:
            semaphore.release()
            connection.close()

    @staticmethod
    def handle_incoming(connection: socket.socket, address, ctx: dict) -> Optional[tuple[Peer, list[Peer], bool]]:
        logger.log(_logger.VERBOSE, f"Receiving connection from {address}")

        incoming_peer = Peer(ip=ip_addr.from_string(address[0]), incoming=True)
        incoming_peer_peers = None
        is_voting = False

        try:
            header, payload = get_next_hdr_payload(connection)
        except UnknownPacketType as exception:
            logger.debug(f"Received unknown packet type from {address}: {exception.message_type}")
            return

        if header.msg_type == message_type(message_type_enum.node_id_handshake):
            if header.is_response():
                logger.debug(f"First node ID handshake package received from {address} has the response flag set, "
                             f"connection closing")
                return

            query = handshake_query.parse_query(header, payload)
            signing_key, verifying_key = node_handshake_id.keypair()
            incoming_peer.peer_id = handshake_exchange_server(ctx, connection, query, signing_key, verifying_key).account
            logger.debug(f"Successfully handshaked with incoming connection from {address}")

            telemetry_request = telemetry_req.telemetry_req(ctx)
            connection.sendall(telemetry_request.serialise())

            hdr = message_header(ctx["net_id"], [18, 18, 18], message_type(message_type_enum.confirm_req), 0)
            pairs = [common.hash_pair(ctx["genesis_block"].hash(), ctx["genesis_block"].root())]
            confirm_request = confirm_req.confirm_req_hash(hdr, pairs)

            connection.sendall(confirm_request.serialise())

        else:
            logger.debug(f"First message from {address} was {header.msg_type}, connection is now closing")
            return

        start_time = time.time()
        while incoming_peer.telemetry is None or incoming_peer_peers is None or is_voting is False:
            if time.time() - start_time > 15:
                logger.debug(f"Time limit for receiving a keepalive and telemetry was exceeded for {address}, connection closing")
                return

            header, payload = get_next_hdr_payload(connection)
            if header.msg_type == message_type(message_type_enum.telemetry_ack):
                incoming_peer.telemetry = telemetry_req.telemetry_ack.parse(header, payload)
                logger.log(_logger.VERBOSE, f"Received telemetry from {address}")

            elif header.msg_type == message_type(message_type_enum.keepalive):
                keepalive = message_keepalive.parse_payload(header, payload)
                logger.log(_logger.VERBOSE, f"Received peers from {address}")
                incoming_peer_peers = keepalive.peers

            elif header.msg_type == message_type(message_type_enum.confirm_ack):
                confirm_response = confirm_ack.parse(header, payload)
                if confirm_request.is_response(confirm_response):
                    is_voting = True
                    logger.log(_logger.VERBOSE, f"Received confirm_ack message from {address}")

        return incoming_peer, incoming_peer_peers, is_voting

    def send_keepalive_packet(self, connection: socket):
        assert self.listening_address is not None

        local_peer = Peer(self.listening_address, self.listening_port)  # this should be changed manually
        packet = message_keepalive.make_packet([local_peer], self.ctx["net_id"], 18)
        connection.sendall(packet)

    def get_peers_from_peer(self, peer, no_telemetry=False, no_confirm_req=False) -> list[Peer]:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.settimeout(3)

            # try to connect to peer
            try:
                s.connect((str(peer.ip), peer.port))
                s.settimeout(10)
            except OSError:
                peer.score = 0
                logger.debug(f"Failed to connect to peer {peer}", exc_info=True)
                return []

            # connected to peer, do handshake followed by listening for the first keepalive
            # and the reply to the confirm request
            # once we get the first keepalive and the confirm ack mtaching the req sent
            # then we have what we need and we move on
            try:
                signing_key, verifying_key = node_handshake_id.keypair()
                peer_id = node_handshake_id.perform_handshake_exchange(self.ctx, s, signing_key, verifying_key)
                peer.peer_id = peer_id
                logger.log(_logger.VERBOSE, f"Connected and handshaked to peer with ID {hexlify(peer_id)}")

                if self.listening_address:
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
                logger.debug(f"Querying peer {peer}")
                peers = self.get_peers_from_peer(peer)
                self.add_peers(peer, peers)
            except Exception:
                logger.error(f"Unexpected exception while crawling peer {peer}", exc_info=True, stack_info=True)

        with ThreadPoolExecutor(max_workers=max_workers) as t:
            for p in peers_copy:
                if p.incoming is False:  # connections shouldn't be made to peers marked as incoming, as their real port isn't known
                    t.submit(crawl_peer, peer=p)

    def crawl(self, forever, delay, max_workers=4):
        initial_peers = get_all_dns_addresses_as_peers(self.ctx['peeraddr'], self.ctx['peerport'], -1)
        for peer in initial_peers:
            self.add_peers(peer, [])

        count = 0
        while forever:
            if count > 4:  # for a faster startup, do not delay the first 5 times
                time.sleep(delay)

            self.crawl_once(max_workers)
            logger.log(_logger.VERBOSE, self)
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
            if p.score >= 1000:
                s += self.peer_to_string(p)
        s += '---------- End of Manager peers (%s peers, %s good) ----------' % (len(peers), good)

        return s

    def serialize_dict(self) -> dict[str, dict]:
        graph_copy = self.get_connections_graph()
        nodes = {}
        for peer, connections in graph_copy.items():
            peer_data = vars(deepcopy(peer))
            peer_data["connections"] = [str(id(c)) for c in connections]
            nodes[str(id(peer))] = peer_data

        return nodes

    def serialize(self) -> str:
        nodes = self.serialize_dict()
        json_connections = json.dumps(nodes, cls=jsonencoder.NanoJSONEncoder)
        return json_connections

    @staticmethod
    def deserialize_dict(data: dict) -> dict[Peer, peer_set]:
        # parse all peers
        peer_id_mapping: dict[str, Peer] = {}
        for key, value in data.items():
            peer = Peer.from_json(value)
            peer_id_mapping[key] = peer

        # build the graph
        result: dict[Peer, peer_set] = {}
        for key, value in data.items():
            peer = peer_id_mapping[key]
            peers = peer_set()
            result[peer] = peers

            for connection in value["connections"]:
                peers.add(peer_id_mapping[connection])

        return result

    @classmethod
    def deserialize(cls, data: str) -> dict[Peer, peer_set]:
        json_data = json.loads(data)
        graph = cls.deserialize_dict(json_data)
        return graph


def parse_args():
    parser = argparse.ArgumentParser()
    add_network_switcher_args(parser)

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
    parser.add_argument('-l', '--listen', type=str, default=None,
                        help='the public IP address of this machine; this address will be advertised in outgoing keepalive packets and the incoming connection listener will be enabled'
                             'if this argument isn\'t set no keepalive packets will be sent out and incoming connections will be ignored')
    parser.add_argument('-p', '--port', type=int, default=7070,
                        help='tcp port number to listen on in service mode')
    parser.add_argument('--serialize', action='store_true', default=False,
                        help='serialize the graph of peer connection to peer_connection_graph.json periodically')
    parser.add_argument('--deserialize', type=str, default=None,
                        help='deserialize the graph of peer connection from the provided file and use it to initialize the peercrawler')

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
    return [Peer.from_json(r) for r in json_resp.values()]


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
    peerman = peer_manager(ctx, peers=peers, verbosity=2)
    print(peerman)


def send_confirm_req_genesis(ctx, peer, s):
    assert (isinstance(peer, Peer))
    block = ctx["genesis_block"]

    try:
        outcome = confirm_req.confirm_block(ctx, block, s)
    except (PyNanoCoinException, OSError):
        outcome = False

    return outcome


def deserialize_graph_from_file(path: str) -> Optional[dict[Peer, peer_set]]:
    try:
        with open(path, "r") as file:
            contents = file.read()
            return peer_manager.deserialize(contents)
    except FileNotFoundError:
        return None


def serialize_thread(peerman: peer_manager):
    while True:
        time.sleep(60)

        serialized_graph = peerman.serialize()
        with open("peer_connection_graph.json", "w") as file:
            file.write(serialized_graph)


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

        initial_graph = None
        if args.deserialize:
            initial_graph = deserialize_graph_from_file(args.deserialize)

        peerman = peer_manager(ctx, initial_graph=initial_graph, listening_address=args.listen, verbosity=verbosity)

        if args.serialize:
            threading.Thread(target=serialize_thread, args=(peerman,), daemon=True).start()

        peerman.crawl(args.forever, args.delay)


if __name__ == "__main__":
    main()
