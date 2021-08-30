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

        # Temp veriable, remove after
        self.times = []

        self.representatives = representatives
        self.peers_in_use = []
        self.threads = []
        self.mutex = threading.Lock()

    def update_manager(self):
        for data in self.threads:
            peer = data[0]
            result = data[1][0]
            account = data[2]
            thread = data[3]
            if not thread.is_alive():
                self.threads.remove(data)
                self.peers_in_use.remove(peer)
                self.times.append(data[1][1])
                if result == enum_error_type.NoError:
                    continue
                elif result == enum_error_type.AccountError:
                    # this may change depending on what we decide to do with accounts that yield no blocks
                    continue
                elif result == enum_error_type.SocketError:
                    self.get_account_reps(account)
                else:
                    print("Thread didn't set a result")

    def get_account_reps(self, account):
        # Temp variable, remove
        while len(self.threads) == 30:
            self.update_manager()
        peer = random.choice(self.peers)
        while peer in self.peers_in_use:
            self.update_manager()
            peer = random.choice(self.peers)
        results = [None, None]

        thread = threading.Thread(target=get_representative_thread,
                                  args=(self.ctx, account, self.representatives, self.mutex, peer, results,),
                                  daemon=True)
        self.threads.append((peer, results, account, thread))
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


def find_rep_in_blocks(blocks):
    for b in blocks:
        if type(b) in [block_open, block_state, block_change]:
            return b.representative


def get_representative_thread(ctx, acc, representatives, mutex, peer, results):
    starttime = time.time()
    counter = 1
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    with s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

        try:
            s.connect((str(peer.ip), peer.port))
            s.settimeout(3)
            blocks = get_account_blocks(ctx, s, acc, no_of_blocks=counter)

            # Keep pulling blocks from account if the block is not a block state, change, or open
            while True:
                rep = find_rep_in_blocks(blocks)
                if rep is not None:
                    results[0] = enum_error_type.NoError
                    results[1] = time.time() - starttime
                    with mutex:
                        representatives.add(rep)
                    return

                counter += 1000
                blocks = get_account_blocks(ctx, s, acc, no_of_blocks=counter)

        # Sometimes there are no blocks read from the socket
        except IndexError as e:
            print(e)
            results[0] = enum_error_type.AccountError
            results[1] = time.time() - starttime
            return

        # Socket sometimes times out or doesn't connect
        except (socket.error, OSError) as e:
            print(e)
            results[0] = enum_error_type.SocketError
            results[1] = time.time() - starttime
            return


def main():
    args = parse_args()

    ctx = livectx
    if args.test: ctx = testctx
    elif args.beta: ctx = betactx

    _, peers = get_peers_from_service(ctx)
    peers = list(filter(lambda p: p.score == 1000, peers))
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
