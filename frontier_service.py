import argparse
import time

import frontier_request
import peercrawler
from pynanocoin import *


class frontier_service:
    def __init__(self, ctx, peer_service_active = False, peerman = None):
        assert(peerman is None if peer_service_active else not None)
        assert(isinstance(peerman, peercrawler.peer_manager) or peerman is None)
        self.ctx = ctx
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

        frontier_request.read_all_frontiers(s, frontier_request.print_handler)
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
    return parser.parse_args()


def setup_db_connection():
    pass


def main():
    # MySQL IP: 127.0.0.1
    # MySQL Port: 3306


    args = parse_args()
    ctx = betactx if args.beta else livectx
    s = get_initial_connected_socket(ctx)
    peers = peercrawler.get_all_peers()
    peer_service_active = False
    if peers is None:
        thread = peercrawler.spawn_peer_crawler_thread()
        peerman = thread.peerman
        time.sleep(1)
    else:
        peer_service_active = True
        peerman = None

    frontserv = frontier_service(ctx, peer_service_active, peerman)
    frontserv.start_service()


if __name__ == "__main__":
    main()
