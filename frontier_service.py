#!/bin/env python3

from __future__ import annotations

import argparse
import itertools
import sys
import time
import lmdb
import threading
import frontier_request
import peercrawler
from abc import ABC, abstractmethod
from typing import Collection, Iterable, Iterator, Set

from mysql.connector.pooling import MySQLConnectionPool

import representatives
from _logger import get_logger, get_logging_level_from_int, VERBOSE, setup_logger
from args import add_network_switcher_args
from sql_utils import *
from pynanocoin import *
from peer import Peer
from peer_set import peer_set


logger = get_logger()


class frontier_service:
    def __init__(self, ctx, interface, verbosity=0, initial_peers: Iterable[Peer] = None):
        assert isinstance(interface, frontier_database)
        self.ctx = ctx
        self.database_interface: frontier_database = interface
        self.verbosity = verbosity
        self.peers: Set[Peer] = peer_set()
        self.blacklist = blacklist_manager(Peer, 1800)

        if initial_peers:
            self.merge_peers(initial_peers)

    def start_service(self, addr='::', port=7080) -> None:
        self.run()

        # TODO broken
        # def incoming_connection_handler(sock: socket.socket):
        #     try:
        #         self.comm_thread(sock)
        #     finally:
        #         semaphore.release()
        #
        # # start the frontier request thread
        # threading.Thread(target=self.run, daemon=True).start()
        #
        # with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        #     s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        #     s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #     s.bind((addr, port))
        #
        #     s.listen()
        #
        #     semaphore = threading.BoundedSemaphore(8)
        #     while True:
        #         semaphore.acquire()
        #
        #         conn, addr = s.accept()
        #         logger.debug(f"Receiving connection from {addr}")
        #
        #         conn.settimeout(60)
        #         threading.Thread(target=incoming_connection_handler, args=(conn,), daemon=True).start()

    # def comm_thread(self, s: socket.socket) -> None:
    #     with s:
    #         data = s.recv(33)
    #         c_packet = client_packet.parse(data)
    #         if c_packet.is_all_zero():
    #             frontiers = self.database_interface.get_all()
    #             s_packet = server_packet(frontiers)
    #             s.sendall(s_packet.serialise())
    #             return
    #
    #         else:
    #             frontier = self.database_interface.get_frontier(c_packet.account)
    #             s_packet = server_packet([frontier])
    #             s.sendall(s_packet.serialise())

    def fetch_peers(self) -> None:
        peers = representatives.get_representatives_from_service(self.ctx["repservurl"], prs_only=True)
        logger.debug(f"Fetched {len(peers)} from the peer service")
        self.merge_peers(peers)

    def run(self) -> None:
        while True:
            self.fetch_peers()
            self.single_pass()

    def single_pass(self) -> None:
        for p in self.peers:
            try:
                logger.info(f"Fetching frontiers from peer {p}")
                self.manage_peer_frontiers(p)
            except (ConnectionRefusedError, socket.timeout, PyNanoCoinException, FrontierServiceSlowPeer) as exception:
                p.deduct_score(200)
                logger.info(f"Error while connecting to peer {p}", exc_info=exception)

    def manage_peer_frontiers(self, p) -> None:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.settimeout(15)

            s.connect((str(p.ip), p.port))

            # maxacc argument can be removed in final version
            hdr = frontier_request.frontier_request.generate_header(self.ctx)
            req = frontier_request.frontier_request(hdr)
            s.sendall(req.serialise())

            front_iter = frontier_read_iter(s)
            self.add_fronts_from_iter(front_iter, p)

    def add_fronts_from_iter(self, front_iter, peer) -> None:
        while True:
            try:
                front = next(front_iter)
                self.database_interface.add_frontier(front, peer)
            except StopIteration:
                return

    # def get_all_records(self):
    #     records = []
    #
    #     self.cursor.execute("SELECT * FROM frontiers")
    #     for rec in self.cursor.fetchall():
    #         records.append(frontiers_record.from_tuple(rec))
    #
    #     return records

    def count_frontiers(self) -> int:
        return self.database_interface.count_frontiers()

    def merge_peers(self, peers: Iterable[Peer]) -> None:
        for p in peers:
            if not self.blacklist.is_blacklisted(p) and p not in self.peers:
                self.peers.add(p)


class client_packet:
    def __init__(self, account):
        self.account = account
        self.magic = ord('K')

    @classmethod
    def parse(cls, data):
        assert len(data) == 33
        assert data[0] == ord('K')
        account = data[1:]
        return client_packet(account)

    def is_all_zero(self) -> bool:
        return self.account == b'\x00' * 32

    def serialise(self) -> bytes:
        data = b''
        data += ord('K').to_bytes(1, 'big')
        data += self.account
        return data


class server_packet_header:
    def __init__(self, no_of_frontiers):
        self.no_of_frontiers = no_of_frontiers

    def serialise(self) -> bytes:
        data = b''
        data += ord('K').to_bytes(1, 'big')
        data += self.no_of_frontiers.to_bytes(8, 'big')
        return data

    @classmethod
    def parse(cls, data):
        assert data[0] == ord('K')
        no_of_frontiers = int.from_bytes(data[1:9], 'big')
        return server_packet_header(no_of_frontiers)

    def __str__(self):
        return str(self.no_of_frontiers)


class server_packet:
    def __init__(self, frontiers):
        # TODO: make this a header followed by frontier_response (nano protocol)
        assert isinstance(frontiers, list)
        self.frontiers = frontiers
        self.header = server_packet_header(len(frontiers))

    def serialise(self) -> bytes:
        data = b''
        data += self.header.serialise()
        for f in self.frontiers:
            data += f.serialise()
        data += b'\x00' * 64
        return data

    @classmethod
    def parse(cls, hdr, data):
        assert len(data) == 64 * hdr.no_of_frontiers + 64
        frontiers = []
        start_index = 0
        end_index = 64

        for i in range(0, hdr.no_of_frontiers):
            front = frontier_request.frontier_entry(data[start_index:end_index - 32], data[end_index - 32:end_index])
            frontiers.append(front)
            start_index += 64
            end_index += 64

        return server_packet(frontiers)

    def __str__(self):
        string = 'No of frontiers: %s\n' % str(self.header)
        for f in self.frontiers:
            string += str(f) + '\n\n'
        return string


class frontier_database(ABC):
    @abstractmethod
    def add_frontier(self, frontier: frontier_request.frontier_entry, peer: Peer) -> None:
        raise NotImplementedError()

    @abstractmethod
    def remove_frontier(self, frontier: frontier_request.frontier_entry, peer: Peer) -> None:
        raise NotImplementedError()

    @abstractmethod
    def get_frontier(self, account_hash: bytes) -> Optional[frontier_database_entry]:
        raise NotImplementedError()

    @abstractmethod
    def get_frontier_from_peer(self, account_hash: bytes, peer: Peer) -> Optional[frontier_database_entry]:
        raise NotImplementedError()

    @abstractmethod
    def get_all_frontiers_for_account(self, account_hash: bytes) -> Set[frontier_database_entry]:
        raise NotImplementedError()

    @abstractmethod
    def get_all(self) -> Iterator[frontier_request.frontier_entry]:
        raise NotImplementedError()

    @abstractmethod
    def count_frontiers(self) -> int:
        raise NotImplementedError()

    @abstractmethod
    def find_accounts_with_different_hashes(self) -> Set[bytes]:
        """Finds all the accounts which have more than one known frontier hash. Might take a long time to process."""
        raise NotImplementedError()


class my_sql_db(frontier_database):
    BATCH_SIZE = 1024

    def __init__(self, database_connection_pool: MySQLConnectionPool):
        self.peers_stored = []

        self.__connection_pool = database_connection_pool
        self.__cache = []
        self.__cache_lock = threading.Lock()

    def add_frontier(self, frontier: frontier_request.frontier_entry, peer: Peer) -> None:
        if peer not in self.peers_stored:
            self.add_peer_to_db(peer)
            self.peers_stored.append(peer)

        query = "('%s', '%s', '%s')" % (hexlify(peer.serialise()), hexlify(frontier.account), hexlify(frontier.frontier_hash))
        with self.__cache_lock:
            self.__cache.append(query)

            if len(self.__cache) > self.BATCH_SIZE:
                self.__add_batch()

    def __add_batch(self):
        query = f"INSERT INTO Frontiers(peer_id, account_hash, frontier_hash) VALUES {', '.join(self.__cache)} ON DUPLICATE KEY UPDATE frontier_hash = VALUES(frontier_hash)"
        self.__cache.clear()

        with self.__connection_pool.get_connection() as database:
            database.cursor().execute(query)
            database.commit()

    def get_frontier(self, account_hash: bytes) -> Optional[frontier_database_entry]:
        with self.__connection_pool.get_connection() as database:
            cursor = database.cursor()
            cursor.execute("""
            SELECT f.frontier_hash, f.account_hash, p.ip_address, p.port
            FROM Frontiers AS f INNER JOIN Peers AS p ON f.peer_id = p.peer_id AND f.account_hash = %(account_hash)s
            """, {"account_hash": hexlify(account_hash)})
            entry = cursor.fetchone()

        if entry is None:
            return None

        peer = Peer(ip=ip_addr.from_string(entry[2]), port=entry[3])
        return frontier_database_entry(peer=peer, frontier_hash=bytes.fromhex(entry[0]), account_hash=bytes.fromhex(entry[1]))

    def get_frontier_from_peer(self, account_hash: bytes, peer: Peer) -> Optional[frontier_database_entry]:
        with self.__connection_pool.get_connection() as database:
            cursor = database.cursor()
            cursor.execute("""
            SELECT f.frontier_hash, f.account_hash, p.ip_address, p.port
            FROM Frontiers AS f INNER JOIN Peers AS p ON f.peer_id = p.peer_id
            WHERE f.account_hash = %(account_hash)s AND f.peer_id = %(peer_id)s
            """, {"account_hash": hexlify(account_hash), "peer_id": hexlify(peer.serialise())})
            entry = cursor.fetchone()

        if entry is None:
            return None

        peer = Peer(ip=ip_addr.from_string(entry[2]), port=entry[3])
        return frontier_database_entry(peer=peer, frontier_hash=bytes.fromhex(entry[0]), account_hash=bytes.fromhex(entry[1]))

    def get_all_frontiers_for_account(self, account_hash: bytes) -> Set[frontier_database_entry]:
        with self.__connection_pool.get_connection() as database:
            cursor = database.cursor()
            cursor.execute("""
                    SELECT f.frontier_hash, f.account_hash, p.ip_address, p.port
                    FROM Frontiers AS f INNER JOIN Peers AS p ON f.peer_id = p.peer_id AND f.account_hash = %(account_hash)s
                    """, {"account_hash": hexlify(account_hash)})
            entries = cursor.fetchall()

        result = set()
        for entry in entries:
            peer = Peer(ip=ip_addr.from_string(entry[2]), port=entry[3])
            database_entry = frontier_database_entry(peer=peer, frontier_hash=bytes.fromhex(entry[0]), account_hash=bytes.fromhex(entry[1]))
            result.add(database_entry)

        return result

    def remove_frontier(self, frontier: frontier_request.frontier_entry, peer: Peer) -> None:
        with self.__connection_pool.get_connection() as database:
            database.cursor().execute("DELETE FROM Frontiers WHERE account_hash = %(account_hash)s AND peer_id = %(peer_id)s",
                                      {"account_hash": hexlify(frontier.account), "peer_id": hexlify(peer.serialise())})
            database.commit()

    def count_frontiers(self) -> int:
        query = "SELECT COUNT(*) from Frontiers"

        with self.__connection_pool.get_connection() as database:
            cursor = database.cursor()
            cursor.execute(query)
            return cursor.fetchone()[0]

    def add_peer_to_db(self, peer) -> None:
        query = "INSERT INTO Peers(peer_id, ip_address, port, score) "
        query += "VALUES('%s', '%s', %d, %d) " % (hexlify(peer.serialise()), str(peer.ip), peer.port, peer.score)
        query += "ON DUPLICATE KEY UPDATE port = port"

        logger.info(f"Adding new peer to database: {peer}")

        with self.__connection_pool.get_connection() as database:
            database.cursor().execute(query)
            database.commit()

    def get_all(self) -> Iterator[frontier_request.frontier_entry]:
        with self.__connection_pool.get_connection() as database:
            cursor = database.cursor(buffered=False)
            cursor.execute("""SELECT account_hash, frontier_hash FROM Frontiers GROUP BY account_hash""")
            while True:
                cache = cursor.fetchmany(size=64)
                cache = [frontier_request.frontier_entry(account=bytes.fromhex(f[0]), frontier_hash=bytes.fromhex(f[1])) for f in cache]
                for c in cache:
                    yield c

    def find_accounts_with_different_hashes(self) -> Set[bytes]:
        with self.__connection_pool.get_connection() as database:
            cursor = database.cursor()
            accounts = query_accounts_different_hashes(cursor).fetchall()

        accounts_flattened = itertools.chain.from_iterable(accounts)
        return set([bytes.fromhex(account) for account in accounts_flattened])


class store_in_ram_interface(frontier_database):
    def __init__(self):
        self.__frontiers: Set[frontier_database_entry] = set()
        self.__mutex = threading.Lock()

    def add_frontier(self, frontier: frontier_request.frontier_entry, peer: Peer) -> None:
        with self.__mutex:
            existing_frontier_entry = self.__find_specific(peer, frontier.account)
            if existing_frontier_entry is not None:
                existing_frontier_entry.frontier_hash = frontier.frontier_hash
                logger.log(VERBOSE, "Updated %s accounts frontier to %s" % (hexlify(frontier.account), hexlify(frontier.frontier_hash)))
            else:
                entry = frontier_database_entry(peer=peer, frontier_hash=frontier.frontier_hash, account_hash=frontier.account)
                self.__frontiers.add(entry)
                logger.log(VERBOSE, "Added %s accounts frontier %s " % (hexlify(frontier.account), hexlify(frontier.frontier_hash)))

    def remove_frontier(self, frontier: frontier_request.frontier_entry, peer: Peer) -> None:
        with self.__mutex:
            existing_frontier_entry = self.__find_specific(peer, frontier.account)
            if existing_frontier_entry is not None:
                self.__frontiers.remove(existing_frontier_entry)
                logger.log(VERBOSE, "Removed the following frontier from list %s" % str(existing_frontier_entry))

    def get_frontier(self, account_hash: bytes) -> Optional[frontier_database_entry]:
        with self.__mutex:
            for f in self.__frontiers:
                if f.account_hash == account_hash:
                    return f

    def get_frontier_from_peer(self, account_hash: bytes, peer: Peer) -> Optional[frontier_database_entry]:
        with self.__mutex:
            for f in self.__frontiers:
                if f.account_hash == account_hash and f.peer == peer:
                    return f

    def get_all_frontiers_for_account(self, account_hash: bytes) -> Set[frontier_database_entry]:
        result = set()
        with self.__mutex:
            for f in self.__frontiers:
                if f.account_hash == account_hash:
                    result.add(f)

        return result

    def count_frontiers(self) -> int:
        with self.__mutex:
            return len(self.__frontiers)

    def get_all(self) -> Iterator[frontier_request.frontier_entry]:
        # make shallow copy of the frontiers set, to avoid it changing size during iteration (temporary)
        with self.__mutex:
            frontiers = self.__frontiers.copy()

        sent_accounts: Set[bytes] = set()
        for f in frontiers:
            account = f.account_hash
            if account not in sent_accounts:
                sent_accounts.add(account)
                yield frontier_request.frontier_entry(account=account, frontier_hash=f.frontier_hash)

    def find_accounts_with_different_hashes(self) -> Set[bytes]:
        # make shallow copy of the frontiers set, to avoid it changing size during iteration (temporary)
        with self.__mutex:
            frontiers = self.__frontiers.copy()

        accounts: Set[bytes] = set()
        for f1 in frontiers:
            account_hash = f1.account_hash
            frontier_hash = f1.frontier_hash

            if account_hash in accounts:
                continue

            for f2 in frontiers:
                if f1 is not f2 and f2.account_hash == account_hash and f2.frontier_hash != frontier_hash:
                    accounts.add(account_hash)
                    break

        return accounts

    def __find_specific(self, peer: Peer, account_hash: bytes) -> frontier_database_entry:
        for f in self.__frontiers:
            if f.peer == peer and f.account_hash == account_hash:
                return f


class store_in_lmdb(frontier_database):
    def __init__(self, file_name: str = "frontiers_db"):
        self.lmdb_env = self.get_lmdb_env(file_name)

    def add_frontier(self, frontier: frontier_request.frontier_entry, peer: Peer):
        with self.lmdb_env.begin(write=True) as tx:
            tx.put(frontier.account, frontier.frontier_hash)
            logger.info("Added values %s, %s to lmdb" % (hexlify(frontier.account), hexlify(frontier.frontier_hash)))

    @staticmethod
    def get_lmdb_env(name):
        os.makedirs('frontier_lmdb_databases', exist_ok=True)
        return lmdb.open('frontier_lmdb_databases/' + name, subdir=False, max_dbs=10000, map_size=(10 * 1000 * 1000 * 1000))

    def get_frontier(self, account_hash: bytes) -> Optional[frontier_database_entry]:
        with self.lmdb_env.begin(write=False) as tx:
            front_hash = tx.get(account_hash)
            return frontier_request.frontier_entry(account_hash, front_hash)

    def get_frontier_from_peer(self, account_hash: bytes, peer: Peer) -> Optional[frontier_database_entry]:
        raise NotImplementedError()

    def get_all(self):
        with self.lmdb_env.begin(write=False) as tx:
            frontiers = []
            for key, value in tx.cursor():
                front = frontier_request.frontier_entry(key, value)
                frontiers.append(front)
        return frontiers

    def get_all_frontiers_for_account(self, account_hash: bytes) -> Set[frontier_database_entry]:
        raise NotImplementedError()

    def remove_frontier(self, frontier: frontier_request.frontier_entry, peer: Peer) -> None:
        raise NotImplementedError()

    def count_frontiers(self) -> int:
        raise NotImplementedError()

    def find_accounts_with_different_hashes(self) -> Set[bytes]:
        raise NotImplementedError()


class frontier_database_entry:
    def __init__(self, peer: Peer, frontier_hash: bytes, account_hash: bytes):
        self.peer: Peer = peer
        self.frontier_hash: bytes = frontier_hash
        self.account_hash: bytes = account_hash

    def __str__(self):
        return f"frontier_hash:{hexlify(self.frontier_hash)} account_hash:{hexlify(self.account_hash)} peer:{self.peer}"


class blacklist_entry:
    def __init__(self, item, time_added):
        self.item = item
        self.time = time_added

    def has_expired(self, expiry_time):
        if time.time() - self.time > expiry_time:
            return True
        return False


class blacklist_manager:
    def __init__(self, object_type, expiry_time = None):
        self.blacklist = []
        self.object_type = object_type
        self.expiry_time = expiry_time

    def add_item(self, item):
        if not isinstance(item, self.object_type):
            raise BlacklistItemTypeError("This black list holds items of item type : %s, type %s given" %
                                         (str(self.object_type), str(type(item))))
        elif self.get_entry(item) is None:
            self.blacklist.append(blacklist_entry(item, time.time()))

    def is_blacklisted(self, item):
        entry = self.get_entry(item)
        if entry is None:
            return False
        elif self.expiry_time is not None:
            if entry.has_expired(self.expiry_time):
                self.remove_entry(entry)
                return False
            else:
                return True
        else:
            return True

    def remove_entry(self, entry):
        self.blacklist.remove(entry)

    def remove_item(self, item):
        entry = self.get_entry(item)
        if entry is not None:
            self.remove_entry(entry)

    def set_expiry_time(self, expiry_time):
        assert(isinstance(expiry_time, int))
        self.expiry_time = expiry_time

    def get_entry(self, item):
        for b in self.blacklist:
            if item == b.item:
                return b
        return None


class frontiers_record:
    def __init__(self, peer_hash, frontier_hash, account):
        self.peer_hash = peer_hash
        self.frontier_hash = frontier_hash
        self.account = account

    # This method exists because cursor.fetchall() returns the data in the form of tuples
    @classmethod
    def from_tuple(cls, data):
        assert(isinstance(data, tuple))
        return frontiers_record(data[0], data[1], data[2])

    def __str__(self):
        string = "Peer: %s\n" % self.peer_hash
        string += "Frontier Hash: %s\n" % self.frontier_hash
        string += "Account: %s\n" % self.account
        return string


class peer_frontiers:
    def __init__(self, p, frontiers):
        assert(isinstance(p, Peer))
        assert(isinstance(frontiers, list))
        self.p = p
        self.frontiers = frontiers


def parse_args():
    parser = argparse.ArgumentParser()
    add_network_switcher_args(parser)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--sql', action='store_true', default=False,
                       help='Use this argument to use the SQL interface')
    group.add_argument('--ram', action='store_true', default=False,
                       help='Use this argument to store frontiers in RAM')
    group.add_argument('--lmdb', action='store_true', default=False,
                       help='Use this argument to store frontiers in LMDB database')

    parser.add_argument('-f', '--forever', action="store_true", default=False,
                        help='"forever" argument for the peercrawler thread')
    parser.add_argument('-v', '--verbosity', type=int, default=0,
                        help='verbosity for the peercrawler')

    parser.add_argument('--rmdb', action='store_true', default=False,
                        help='drops the MySQL database and exits')
    parser.add_argument('--db', type=str, default=None,
                        help='the name of the database that will be either created or connected to')
    parser.add_argument('-u', '--username', type=str, default='root',
                        help='the username for the connection')
    parser.add_argument('-p', '--password', type=str, default='password123',
                        help='password for the database connection')
    parser.add_argument('-H', '--host', type=str, default='localhost',
                        help='the ip of the sql server')

    parser.add_argument('--peer', action="append", default=[],
                        help='also connect to this peer, address should be provided in the following format: [2001:db8::1]:80')

    parser.add_argument('-D', '--differences', action='store_true', default=False,
                        help='If you want the service to get differences or not')
    parser.add_argument('-s', '--service', action='store_true', default=False,
                        help='runs the service, can be forever depending on the -f argument')
    parser.add_argument('--dumpdb', action='store_true', default=False,
                        help='option to dump all the data in the database')

    return parser.parse_args()


def frontier_read_iter(s):

    while True:
        front = frontier_request.read_frontier_response(s)
        if front.is_end_marker():
            return
        yield front


def find_average_time(times):
    n = 0.0
    for t in times:
        n += t
    return n / len(times)


def get_all_frontiers_packet_from_service(addr = '::1', port = 7080):
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(3)
        s.connect((addr, port))

        c_packet1 = client_packet(b'\x00' * 32)

        s.sendall((c_packet1.serialise()))

        hdr_data = read_socket(s, 9)
        s_hdr = server_packet_header.parse(hdr_data)

        front_data = read_socket(s, 64 * s_hdr.no_of_frontiers + 64)
        s_packet = server_packet.parse(s_hdr, front_data)
        return s_packet


def get_accounts_frontier_packet_from_service(account, addr = '::1', port = 7080):
    assert len(account) == 32
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(3)
        s.connect((addr, port))

        c_packet = client_packet(account)

        s.sendall(c_packet.serialise())

        hdr_data = read_socket(s, 9)
        s_hdr = server_packet_header.parse(hdr_data)

        front_data = read_socket(s, 128)
        s_packet = server_packet.parse(s_hdr, front_data)

        return s_packet


def main():
    # Defaults:
    # - MySQL IP: 127.0.0.1
    # - MySQL Port: 3306
    # - MySQL Pass: password123

    # TODO: Remove the -c, replace with code which will create a new db if one doesn't exist
    # TODO: Add dumpdb option

    args = parse_args()
    setup_logger(logger, get_logging_level_from_int(args.verbosity))

    if args.beta:
        ctx = betactx
        db_name = "beta_net_frontiers"
    elif args.test:
        ctx = testctx
        db_name = "test_net_frontiers"
    else:
        ctx = livectx
        db_name = "live_net_frontiers"

    if args.db is None:
        args.db = db_name

    # if args.rmdb:  # drop database and exit program
    #     db = setup_db_connection(host=args.host, user=args.username, password=args.password)
    #     db.cursor().execute(f"DROP DATABASE {args.db}")
    #     sys.exit(0)

    if args.ram:
        database_interface = store_in_ram_interface()
    elif args.lmdb:
        database_interface = store_in_lmdb(file_name=args.db)
    else:
        connection_pool = MySQLConnectionPool(pool_name="mypool", pool_size=8, host=args.host, user=args.username, passwd=args.password, auth_plugin='mysql_native_password')

        with connection_pool.get_connection() as database:
            cursor = database.cursor()

            if args.rmdb:
                cursor.execute(f"DROP DATABASE {args.db}")
                sys.exit(0)

            create_new_database(cursor, args.db)
            create_db_structure_frontier_service(cursor)
            database.commit()

        connection_pool.set_config(database=args.db)
        database_interface = my_sql_db(connection_pool)

    initial_peers = set()
    for peer in args.peer:
        ip, port = extract_ip_and_port_from_ipv6_address(peer)
        initial_peers.add(Peer(ip=ip_addr.from_string(ip), port=port))

    service = frontier_service(ctx, database_interface, args.verbosity, initial_peers=initial_peers)

    if args.service:
        if args.forever:
            service.start_service()
        else:
            service.fetch_peers()
            service.single_pass()
    elif args.differences:
        records = database_interface.find_accounts_with_different_hashes()
        for record in records:
            print(hexlify(record))


if __name__ == "__main__":
    main()
