#!/bin/env python3

import argparse
import sys
import time
from sql_utils import *
import frontier_request
import peercrawler
import mysql.connector
from pynanocoin import *


class frontier_service:
    def __init__(self, ctx, db, cursor, verbosity = 0):
        self.ctx = ctx
        self.db = db
        self.cursor = cursor
        self.verbosity = verbosity
        self.peers = []
        self.blacklist = blacklist_manager(Peer, 1800)

    def start_service(self):
        while True:
            self.single_pass()

    def single_pass(self):
        hdr, peers = peercrawler.get_peers_from_service(self.ctx)
        assert peers
        self.merge_peers(peers)

        for p in self.peers:
            if p.score <= 0:
                self.remove_peer_data(p)
                self.peers.remove(p)
                self.blacklist.add_item(p)
                continue

            try:
                self.manage_peer_frontiers(p)
                self.db.commit()

            except (ConnectionRefusedError, socket.timeout, PyNanoCoinException,
                    FrontierServiceSlowPeer) as ex:
                p.deduct_score(200)
                if self.verbosity >= 1:
                    print(ex)
                continue

    def manage_peer_frontiers(self, p):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(15)

        s.connect((str(p.ip), p.port))

        # maxacc argument can be removed in final version
        req = frontier_request.frontier_request(self.ctx, maxacc=1000)
        s.send(req.serialise())
        frontier_request.read_all_frontiers(s, mysql_handler(p, self.cursor, self.verbosity))

    def remove_peer_data(self, p):
        self.cursor.execute("DELETE FROM Frontiers WHERE peer_id = '%s'" % hexlify(p.serialise()))
        self.cursor.execute("DELETE FROM Peers WHERE peer_id = '%s'" % hexlify(p.serialise()))

    # Function which will query all accounts with different frontier hashes
    def find_accounts_different_hashes(self):
        fetched_records = []

        query_accounts_different_hashes(self.cursor)

        for record in self.cursor.fetchall():
            fetched_records.append(record[0])

        return fetched_records

    def get_all_records(self):
        records = []

        self.cursor.execute("SELECT * FROM frontiers")
        for rec in self.cursor.fetchall():
            records.append(frontiers_record.from_tuple(rec))

        return records

    def count_frontiers(self):
        self.cursor.execute("SELECT COUNT(*) FROM frontiers")
        result = self.cursor.fetchall()
        return result[0]

    def merge_peers(self, peers):
        for p in peers:
            if self.blacklist.is_blacklisted(p):
                continue
            elif p not in self.peers:
                self.peers.append(p)


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

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')

    parser.add_argument('-f', '--forever', action="store_true", default=False,
                        help='"forever" argument for the peercrawler thread')
    parser.add_argument('-v', '--verbosity', type=int, default=1,
                        help='verbosity for the peercrawler')

    parser.add_argument('--rmdb', action='store_true', default=False,
                        help='determines whether the frontier service tables should be reset')
    parser.add_argument('--db', type=str, default=None,
                        help='the name of the database that will be either created or connected to')
    parser.add_argument('-u', '--username', type=str, default='root',
                        help='the username for the connection')
    parser.add_argument('-p', '--password', type=str, default='password123',
                        help='password for the database connection')
    parser.add_argument('-H', '--host', type=str, default='localhost',
                        help='the ip of the sql server')

    parser.add_argument('-D', '--differences', action='store_true', default=False,
                        help='If you want the service to get differences or not')
    parser.add_argument('-s', '--service', action='store_true', default=False,
                        help='runs the service, can be forever depending on the -f argument')
    parser.add_argument('--dumpdb', action='store_true', default=False,
                        help='option to dump all the data in the database')

    return parser.parse_args()


# MySQL closure
def mysql_handler(p, cursor, verbosity):
    assert(isinstance(p, Peer))
    times = []
    query1 = "INSERT INTO Peers(peer_id, ip_address, port, score) "
    query1 += "VALUES('%s', '%s', %d, %d) " % (hexlify(p.serialise()), str(p.ip), p.port, p.score)
    query1 += "ON DUPLICATE KEY UPDATE port = port"
    if verbosity > 0:
        print(query1)
    cursor.execute(query1)

    def add_data(counter, frontier, readtime):
        times.append(readtime)
        if counter > 4:
            if find_average_time(times) > 0.05:
                raise FrontierServiceSlowPeer("peer: %s is too slow" % str(p))
        query2 = "INSERT INTO Frontiers(peer_id, account_hash, frontier_hash) "
        query2 += "VALUES ('%s', '%s', '%s') " % (hexlify(p.serialise()), hexlify(frontier.account),
                                                  hexlify(frontier.frontier_hash))
        query2 += "ON DUPLICATE KEY UPDATE frontier_hash = '%s'" % hexlify(frontier.frontier_hash)

        if verbosity > 1:
            print(query2)
        cursor.execute(query2)
    return add_data


def find_average_time(times):
    n = 0.0
    for t in times:
        n += t
    return n / len(times)


def main():
    # Defaults:
    # - MySQL IP: 127.0.0.1
    # - MySQL Port: 3306
    # - MySQL Pass: password123

    # TODO: Automatically choose database name using ctx
    # TODO: Remove the -c, replace with code which will create a new db if one doesn't exist
    # TODO: Add dumpdb option

    args = parse_args()

    ctx = livectx
    db_name = "live_net_frontiers"
    if args.beta:
        ctx = betactx
        db_name = "beta_net_frontiers"
    elif args.test:
        ctx = testctx
        db_name = "test_net_frontiers"

    if args.db is None:
        args.db = db_name

    if args.rmdb:
        db = setup_db_connection(host=args.host, user=args.username, passwd=args.password)
        db.cursor().execute("DROP DATABASE %s" % args.db)
        sys.exit(0)

    else:
        try:
            db = setup_db_connection(host=args.host, user=args.username, passwd=args.password, db=args.db)
            cursor = db.cursor()
        except mysql.connector.errors.ProgrammingError as err:
            db = setup_db_connection(host=args.host, user=args.username, passwd=args.password)
            create_new_database(db.cursor(), name=args.db)
            create_db_structure_frontier_service(db.cursor())
            db.close()
            db = setup_db_connection(host=args.host, user=args.username, passwd=args.password, db=args.db)
            cursor = db.cursor()

    frontserv = frontier_service(ctx, db, cursor, args.verbosity)

    # This will run forever
    if args.service:
        hdr, _ = peercrawler.get_peers_from_service(ctx)
        if args.forever:
            frontserv.start_service()

        else:
            frontserv.single_pass()

    # This is a piece of code which can find accounts with different frontier hashes
    if args.differences:
        records = frontserv.find_accounts_different_hashes()
        for rec in records:
            print(rec)

    if args.dumpdb:
        records = frontserv.get_all_records()
        for rec in records:
            print(rec)


if __name__ == "__main__":
    main()
