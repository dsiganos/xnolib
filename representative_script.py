import argparse
from statistics import mean

from frontier_request import *
from pynanocoin import *
from peercrawler import *
from pull_n_accounts import store_frontiers_handler
import time
import threading
import random


class thread_manager:
    def __init__(self, ctx, peers, thread_count):
        self.ctx = ctx
        self.peers = peers
        self.next_peer_index = 0
        self.thread_count = thread_count
        self.sem = threading.Semaphore(thread_count)
        assert len(peers) > 0

        self.successful_times = []
        self.unsuccessful_times = []

        self.representatives = set()
        self.threads = []
        self.blocks_downloaded = []
        self.connection_times = []
        self.mutex = threading.Lock()

    def get_next_peer(self):
        with self.mutex:
            if self.next_peer_index >= len(self.peers):
                self.next_peer_index = 0
            peer = self.peers[self.next_peer_index]
            self.next_peer_index += 1
            return peer

    def thread_func(self, peer, account):
        try:
            self.get_representative_for_account(account, peer, self.mutex)
        finally:
            self.sem.release()
            print('Thread completed peer=%s account=%s' % (peer, hexlify(account)))

    def get_account_rep(self, account):
        self.sem.acquire()
        peer = self.get_next_peer()
        thread = threading.Thread(target=self.thread_func,
                                  args=(peer, account),
                                  daemon=True)
        thread.start()
        self.threads.append(thread)

    def join(self):
        for t in self.threads:
            t.join()
        print('All threads are finished')

    def get_representative_for_account(self, acc, peer, mutex):
        starttime = time.time()
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            try:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                s.settimeout(3)
                conn_starttime = time.time()
                s.connect((str(peer.ip), peer.port))
                conn_time = time.time() - conn_starttime

                # we ask for one block first in the hope it has everything we need (state block) 
                s.settimeout(10)
                starttime2 = time.time()
                blocks = get_account_blocks(self.ctx, s, acc, no_of_blocks=1)
                timetaken2 = time.time() - starttime2

                # Keep pulling blocks from account if the block is not a block state, change, or open
                while True:
                    if len(blocks) == 0:
                        raise NoBlocksPulled("No blocks pulled from account: %s" % acctools.to_account_addr(acc))

                    rep_block = find_rep_in_blocks(blocks)
                    if rep_block is not None:
                        with mutex:
                            if rep_block.balance > 0:
                                print('Found rep: %s' % hexlify(rep_block.representative))
                                self.representatives.add(rep_block.representative)
                                self.successful_times.append(time.time() - starttime)
                            else:
                                print('Balance is zero')
                                self.unsuccessful_times.append(time.time() - starttime)
                            self.connection_times.append(conn_time)
                            self.blocks_downloaded.append(len(blocks))

                        return

                    starttime3 = time.time()
                    blocks = get_account_blocks(self.ctx, s, acc, no_of_blocks=1000)
                    timetaken3 = time.time() - starttime3

            # Socket sometimes times out, doesn't connect or there are no blocks read from the socket
            except (socket.error, OSError, SocketClosedByPeer, NoBlocksPulled) as e:
                print(str(e) + "(" + threading.currentThread().getName() + ")")
                with mutex:
                    self.unsuccessful_times.append(time.time() - starttime)


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

    parser.add_argument('-c', '--thread_count', type=int, default=150,
                        help='determines the number of threads that can run in parallel')
    parser.add_argument('-a', '--account_count', type=int, default=10000,
                        help='determines the number of accounts that will be pulled')
    return parser.parse_args()


def find_rep_in_blocks(blocks):
    for b in blocks:
        if type(b) in [block_open, block_state, block_change]:
            return b
    return None


def main():
    args = parse_args()

    ctx = livectx
    if args.test: ctx = testctx
    elif args.beta: ctx = betactx

    _, peers = get_peers_from_service(ctx)
    peers = list(filter(lambda p: p.score == 1000, peers))

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(3)

        while True:
            try:
                peer = random.choice(peers)
                s.connect((str(peer.ip), peer.port))
                break
            except socket.error:
                continue

        starttime1 = time.time()
        req = frontier_request(ctx, maxacc=args.account_count)
        s.send(req.serialise())
        frontiers = []
        read_all_frontiers(s, store_frontiers_handler(frontiers))
        print('%s frontiers received' % len(frontiers))

        starttime2 = time.time()
        threadman = thread_manager(ctx, peers, args.thread_count)

        # Go through each account
        for front in frontiers[9000:]:
            acc = front.account
            threadman.get_account_rep(acc)
        print('all threads started')

    # wait for all threads to finish
    threadman.join()

    endtime = time.time()
    timetaken1 = endtime - starttime1
    timetaken2 = endtime - starttime2

    average_blocks_downloaded = mean(threadman.blocks_downloaded)
    average_connection_time = mean(threadman.connection_times)
    one_block_downloads = 0

    for i in threadman.blocks_downloaded:
        if i == 1:
            one_block_downloads += 1

    for rep in threadman.representatives:
        print(hexlify(rep))

    print("time taken with reading frontiers: %f" % timetaken1)
    print("Time taken just to gather reps from accounts: %f" % timetaken2)
    print("Average connection time: %f" % average_connection_time)
    print("Average blocks downloaded: %d" % average_blocks_downloaded)
    print("Number of one-block downloads: %d" % one_block_downloads)
    print("Number of successful threads: %d" % len(threadman.successful_times))
    print("Number of reps: %d" % len(threadman.representatives))


if __name__ == '__main__':
    main()
