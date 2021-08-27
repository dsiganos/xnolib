import argparse

from frontier_request import *
from pynanocoin import *
from peercrawler import *
from pull_n_accounts import store_frontiers_handler
import time
import threading
import random


class enum_error_type:
    NoError = 0
    SocketError = 1
    AccountError = 2


class thread_manager:
    def __init__(self, ctx, peers, representatives):
        self.ctx = ctx
        self.peers = peers
        self.representatives = representatives
        self.peers_in_use = []
        self.threads = []
        self.mutex = threading.Lock()

    def update_manager(self):
        for data in self.threads:
            peer = data[0]
            result = data[1]
            account = data[2]
            thread = data[3]
            if not thread.is_alive():
                self.threads.remove(data)
                self.peers_in_use.remove(peer)
                if result == enum_error_type.NoError:
                    continue
                elif result == enum_error_type.AccountError:
                    # this may change depending on what we decide to do with accounts that yield no blocks
                    continue
                elif result == enum_error_type.SocketError:
                    self.get_account_reps(account)

    def get_account_reps(self, account):
        while len(self.threads) == 30:
            self.update_manager()
        peer = random.choice(self.peers)
        while peer in self.peers_in_use:
            self.update_manager()
            peer = random.choice(self.peers)
        result = None

        thread = threading.Thread(target=get_representative_thread,
                                  args=(self.ctx, account, self.representatives, self.mutex, peer, result,),
                                  daemon=True)
        self.threads.append((peer, result, account, thread))
        thread.start()
        self.peers_in_use.append(peer)

    def all_threads_finished(self):
        self.update_manager()
        return True if len(self.threads) == 0 else False


def find_most_recent_block_type(blocks, block_type):
    for i in range(0, len(blocks)):
        if isinstance(blocks[i], block_type):
            return blocks[i]

    return None

def parse_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')

    return parser.parse_args()


def remove_finished_threads(threads):
    for t in threads:
        if not t.is_alive():
            threads.remove(t)


def get_representative_thread(ctx, acc, representatives, mutex, peer, result):
    counter = 1
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    with s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

        try:
            s.connect((str(peer.ip), peer.port))
            s.settimeout(3)
            blocks = get_account_blocks(ctx, s, acc, no_of_blocks=counter)
            block = blocks[0]

        # Sometimes there are no blocks read from the socket
        except IndexError as e:
            result = enum_error_type.AccountError
            return

        # Socket sometimes times out or doesn't connect
        except (socket.error, OSError) as e:
            result = enum_error_type.SocketError
            return

        finished = False

        # Keep pulling blocks from account if the block is not a block state, change, or open
        while not finished:

            if type(block) in [block_open, block_state, block_change]:
                with mutex:
                    representatives.add(block.representative)
                    result = enum_error_type.NoError
                finished = True
                continue

            counter += 1
            block = get_account_blocks(ctx, s, acc, no_of_blocks=counter)[counter - 1]


def main():
    args = parse_args()

    ctx = livectx
    if args.test: ctx = testctx
    elif args.beta: ctx = betactx

    _, peers = get_peers_from_service(ctx)
    peers = list(peers)
    req = frontier_request(ctx, maxacc=1000)
    frontiers = []
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    with s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

        while True:
            try:
                peer = random.choice(peers)
                s.connect((str(peer.ip), peer.port))
                break
            except socket.error:
                continue

        s.settimeout(180)
        s.send(req.serialise())
        starttime1 = time.time()
        read_all_frontiers(s, store_frontiers_handler(frontiers))
        representatives = set()

        starttime2 = time.time()
        threadman = thread_manager(ctx, peers, representatives)

        # Go through each account
        for front in frontiers:
            acc = front.account
            threadman.get_account_reps(acc)

    while not threadman.all_threads_finished():
        pass

    endtime = time.time()
    timetaken1 = endtime - starttime1
    timetaken2 = endtime - starttime2
    for rep in representatives:
        print(hexlify(rep))

    print("time taken with reading frontiers: %f" % timetaken1)
    print("Time taken just to gather reps from accounts: %f" % timetaken2)


if __name__ == '__main__':
    main()
