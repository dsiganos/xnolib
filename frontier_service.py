import argparse
import time
from sql_utils import *
import frontier_request
import peercrawler
import mysql.connector
from pynanocoin import *


class frontier_service:
    def __init__(self, ctx, db, cursor, peer_service_active = False, peerman = None, verbosity = 0):
        assert(peerman is None if peer_service_active else not None)
        assert(isinstance(peerman, peercrawler.peer_manager) or peerman is None)
        self.ctx = ctx
        self.db = db
        self.cursor = cursor
        self.peer_service_active = peer_service_active
        self.peerman = peerman
        self.verbosity = verbosity
        self.peers = []
        self.visited_peers = []

    def start_service(self):
        while True:
            self.single_pass()

    def single_pass(self):
        if self.peer_service_active:
            _, self.peers = peercrawler.get_all_peers()
        else:
            self.peers = self.peerman.get_peers_copy()

        for p in self.peers:
            if p.score <= 0:
                continue
            if p not in self.visited_peers:
                self.manage_peer_frontiers(p)
                self.visited_peers.append(p)

    def manage_peer_frontiers(self, p):
        # Attempts to connect to a peer recursively (if it fails)
        if p.score <= 0:
            self.remove_peer_data(p)
            self.peers.remove(p)

        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(15)

        # Testing a peers connection
        try:
            s.connect((str(p.ip), p.port))
        except Exception as ex:
            p.deduct_score(200)
            print(ex)

            # Will try to connect to the peer again, until the score is 0 (recursively)
            return self.manage_peer_frontiers(p)

        # maxacc argument can be removed in final version
        req = frontier_request.frontier_request(self.ctx, maxacc=1000)
        s.send(req.serialise())

        try:
            frontier_request.read_all_frontiers(s, mysql_handler(p, self.cursor, self.verbosity))
            self.db.commit()

        except PyNanoCoinException:
            return

    def remove_peer_data(self, p):
        self.cursor.execute("DELETE FROM frontiers WHERE peer_id = '%s'" % p.serialise())
        self.cursor.execute("DELETE FROM peers WHERE peer_id = '%s'" % p.serialise())

    # Function which will query all accounts with different frontier hashes
    def find_accounts_different_hashes(self):
        fetched_records = []

        query_accounts_different_hashes(self.cursor)

        for record in self.cursor.fetchall():
            f_rec = frontiers_record.from_tuple(record)
            fetched_records.append(f_rec)

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


class frontiers_record:
    def __init__(self, peer_hash, frontier_hash, account):
        self.peer_hash = peer_hash
        self.frontier_hash = frontier_hash
        self.account = account

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
        assert(isinstance(p, peer))
        assert(isinstance(frontiers, list))
        self.p = p
        self.frontiers = frontiers


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--db',
                        help='save frontiers in the database named by the argument')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')
    parser.add_argument('-f', '--forever', action="store_true", default=True,
                        help='"forever" argument for the peercrawler thread')
    parser.add_argument('-d', '--delay', type=int, default=0,
                        help='delay between crawls in seconds')
    parser.add_argument('-v', '--verbosity', type=int, default=1,
                        help='verbosity for the peercrawler')
    parser.add_argument('-c', '--create', action='store_true', default=False,
                        help='determines a new database should be created')
    parser.add_argument('-db', '--database', type=str, default="peer_frontiers",
                        help='the name of the database that will be either created or connected to')
    parser.add_argument('-u', '--username', type=str, default='root',
                        help='the username for the connection')
    parser.add_argument('-p', '--password', type=str, default='password123',
                        help='password for the database connection')
    parser.add_argument('-H', '--host', type=str, default='localhost',
                        help='the ip of the sql server')
    return parser.parse_args()


# MySQL closure
def mysql_handler(p, cursor, verbosity):
    assert(isinstance(p, peer))
    query1 = "INSERT INTO Peers(peer_id, ip_address, port, score) "
    query1 += "VALUES('%s', '%s', %d, %d) " % (hexlify(p.serialise()), str(p.ip), p.port, p.score)
    query1 += "ON DUPLICATE KEY UPDATE port = port"
    if verbosity > 0:
        print(query1)
    cursor.execute(query1)

    def add_data(counter, frontier):
        query2 = "INSERT INTO Frontiers(peer_id, account_hash, frontier_hash) "
        query2 += "VALUES ('%s', '%s', '%s') " % (hexlify(p.serialise()), hexlify(frontier.account),
                                                 hexlify(frontier.frontier_hash))
        query2 += "ON DUPLICATE KEY UPDATE frontier_hash = '%s'" % hexlify(frontier.frontier_hash)

        if verbosity > 1:
            print(query2)
        cursor.execute(query2)
    return add_data


def main():
    # Defaults:
    # - MySQL IP: 127.0.0.1
    # - MySQL Port: 3306
    # - MySQL Pass: password123

    args = parse_args()

    if args.create:
        db = setup_db_connection(host=args.host, user=args.username, passwd=args.password)
        create_new_database(db.cursor(), name=args.database)
        create_db_structure_frontier_service(db.cursor())
        db.close()
        db = setup_db_connection(host=args.host, user=args.username, passwd=args.password, db=args.database)
        cursor = db.cursor()

    else:
        db = setup_db_connection(host=args.host, user=args.username, passwd=args.password, db=args.database)
        cursor = db.cursor()

    ctx = livectx
    if args.beta: ctx = betactx
    if args.test: ctx = testctx

    hdr, peers = peercrawler.get_all_peers()

    if hdr is not None and hdr.net_id != ctx["net_id"]:
        peers = None

    peer_service_active = False
    if peers is None:
        thread = peercrawler.spawn_peer_crawler_thread(ctx, forever=args.forever,
                                                       delay=args.delay, verbosity=args.verbosity)
        peerman = thread.peerman
        time.sleep(1)
    else:
        peer_service_active = True
        peerman = None

    frontserv = frontier_service(ctx, db, cursor, peer_service_active, peerman, args.verbosity)

    # This will run forever
    frontserv.single_pass()

    # This is a piece of code which can find accounts with different frontier hashes

    # records = frontserv.find_accounts_different_hashes()
    # for rec in records:
    #     print(rec)


if __name__ == "__main__":
    main()
