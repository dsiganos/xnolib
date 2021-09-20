#!/bin/env python3

import argparse
import sys
import copy
import time
import threading
from sql_utils import *
from frontier_request import *
from pull_n_accounts import store_frontiers_handler
import peercrawler
import mysql.connector
from pynanocoin import *


class frontier_service:
    def __init__(self, ctx, mutex, verbosity = 0):
        self.ctx = ctx
        self.mutex = mutex
        self.verbosity = verbosity
        self.frontiers = []

    def start_service(self):
        while True:
            self.single_pass()

    def single_pass(self):
        _, peers = peercrawler.get_peers_from_service(self.ctx)
        peers = list(filter(lambda p: p.score >= 1000 and p.ip.is_ipv4(), peers))

        if self.verbosity > 0:
            print("Got and filtered peers")
            print("Getting frontiers from each peer")

        for p in peers:
            frontiers = []
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                s.settimeout(3)
                s.connect((str(p.ip), p.port))
                hdr = frontier_request.generate_header(self.ctx)
                req = frontier_request(hdr)

                s.send(req.serialise())
                read_all_frontiers(s, store_frontiers_handler(frontiers))
                self.manage_new_frontiers(frontiers)

    def manage_new_frontiers(self, frontiers):
        for f in frontiers:
            existing_front = self.get_accounts_frontier(f.account)
            if existing_front is not None:
                existing_front.frontier_hash = f.frontier_hash
                if self.verbosity > 1:
                    print("Updating account %s with frontier %s" % (hexlify(f.account), hexlify(f.frontier_hash)))
            else:
                self.frontiers.append(f)

                if self.verbosity > 1:
                    print("Added new frontier for account: %s" % hexlify(f.account))

    def get_accounts_frontier(self, account):
        for f in self.frontiers:
            if f.account == account:
                return f
        return None

    def get_frontiers(self):
        return copy.copy(self.frontiers)


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

    parser.add_argument('-D', '--differences', action='store_true', default=False,
                        help='If you want the service to get differences or not')
    parser.add_argument('-s', '--service', action='store_true', default=True,
                        help='runs the service, can be forever depending on the -f argument')

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

    ctx = testctx

    mutex = threading.Lock()
    frontserv = frontier_service(ctx, mutex, args.verbosity)

    # This will run forever
    if args.service:
        hdr, _ = peercrawler.get_peers_from_service(ctx)
        if args.forever:
            frontserv.start_service()

        else:
            frontserv.single_pass()
            pass


if __name__ == "__main__":
    main()
