import argparse
import time
from sql_utils import *
import frontier_request
import peercrawler
import mysql.connector
from pynanocoin import *


class frontier_service:
    def __init__(self, ctx, db, cursor, peer_service_active = False, peerman = None):
        assert(peerman is None if peer_service_active else not None)
        assert(isinstance(peerman, peercrawler.peer_manager) or peerman is None)
        self.ctx = ctx
        self.db = db
        self.cursor = cursor
        self.peer_service_active = peer_service_active
        self.peerman = peerman
        self.peers = []
        self.peers_frontiers = []

    def start_service(self):
        if self.peer_service_active:
            self.peers = peercrawler.get_all_peers()
        else:
            self.peers = self.peerman.get_peers_copy()

        for p in self.peers:
            peer_frontier = self.get_peer_frontiers(p)
            # if peer_frontier is None:
            #     continue
            # self.peers_frontiers.append(peer_frontiers)


    def get_peer_frontiers(self, p):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        try:
            s.connect((str(p.ip), p.port))
        except Exception as ex:
            print(ex)
            return None
        req = frontier_request.frontier_request(self.ctx, maxacc=1000)
        s.send(req.serialise())

        frontier_request.read_all_frontiers(s, mysql_hander(p, self.cursor))
        self.db.commit()
        return None



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
    parser.add_argument('-b', '--beta', action='store_true', default=False,
                        help='use beta network')
    parser.add_argument('-f', '--forever', action="store_true", default=True,
                        help='"forever" argument for the peercrawler thread')
    parser.add_argument('-d', '--delay', type=int, default=0,
                        help='delay between crawls in seconds')
    parser.add_argument('-v', '--verbosity', type=int, default=0,
                        help='verbosity for the peercrawler')
    parser.add_argument('-c', '--create', action='store_true', default=True,
                        help='determines a new database should be created')
    parser.add_argument('-db', '--database', type=str, default="initial_test",
                        help='the name of the database that will be either created of connected to')
    parser.add_argument('-u', '--username', type=str, default='root',
                        help='the username for the connection')
    parser.add_argument('-p', '--password', type=str, default='password123',
                        help='password for the database connection')
    parser.add_argument('-H', '--host', type=str, default='localhost',
                        help='the ip of the sql server')
    return parser.parse_args()


def mysql_hander(p, cursor):
    assert(isinstance(p, peer))
    print("INSERT INTO Peers(peer_id, ip_address, port, score) " +
          "VALUES('%s', '%s', '%d', '%d')" % (hexlify(p.serialise()), str(p.ip), p.port, p.score))
    cursor.execute("INSERT INTO Peers(peer_id, ip_address, port, score) " +
                   "VALUES('%s', '%s', '%d', '%d')" % (hexlify(p.serialise()), str(p.ip), p.port, p.score))

    def add_data(counter, frontier):
        print("INSERT INTO Frontiers(peer_id, frontier_hash, account) " +
              "VALUES ('%s', '%s', '%s')" % (hexlify(p.serialise()), hexlify(frontier.frontier_hash),
                                       hexlify(frontier.account)))
        cursor.execute("INSERT INTO Frontiers(peer_id, frontier_hash, account) " +
                       "VALUES ('%s', '%s', '%s')" % (hexlify(p.serialise()), hexlify(frontier.frontier_hash),
                                                hexlify(frontier.account)))
    return add_data


def main():
    # MySQL IP: 127.0.0.1
    # MySQL Port: 3306
    # MySQL Pass: password123

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

    ctx = betactx if args.beta else livectx
    peers = peercrawler.get_all_peers()
    peer_service_active = False
    if peers is None:
        thread = peercrawler.spawn_peer_crawler_thread(ctx, forever=args.forever,
                                                       delay=args.delay, verbosity=args.verbosity)
        peerman = thread.peerman
        time.sleep(1)
    else:
        peer_service_active = True
        peerman = None

    frontserv = frontier_service(ctx, db, cursor, peer_service_active, peerman)
    frontserv.start_service()


if __name__ == "__main__":
    main()
