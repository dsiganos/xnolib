#!/bin/env python3

import argparse
from statistics import mean

from frontier_request import *
from pynanocoin import *
from peercrawler import *
from pull_n_accounts import store_frontiers_handler
import time
import threading
import random
import tracemalloc
from exceptions import *
from peer import Peer


class thread_manager:
    def __init__(self, ctx: dict, peers: list[Peer], num_of_threads: int):
        self.ctx = ctx
        self.peers = peers
        self.next_peer_index = 0
        self.num_of_threads = num_of_threads
        self.sem = threading.Semaphore(num_of_threads)
        self.representatives = set()
        self.threads = []
        self.mutex = threading.Lock()
        assert len(peers) > 0

        # Analysis data
        self.thread_count = 0

        self.successful_count = 0
        self.unsuccessful_count = 0
        self.total_unsuccessful_times = 0
        self.total_successful_times = 0
        self.max_successful_time = -1.0
        self.min_successful_time = 100000.0
        self.max_unsuccessful_time = -1.0
        self.min_unsuccessful_time = 100000.0

        self.total_blocks_downloaded = 0
        self.max_blocks_downloaded = 0
        self.min_blocks_downloaded = 0
        self.download_blocks_count = 0
        self.one_block_downloads = 0
        self.no_balance_block_count = 0

        self.total_connection_times = 0.0
        self.min_connection_time = 100000.0
        self.max_connection_time = -1.0

    def update(self) -> None:
        for t in self.threads:
            if not t.is_alive():
                t.join()
                self.threads.remove(t)

    def get_next_peer(self) -> Peer:
        with self.mutex:
            if self.next_peer_index >= len(self.peers):
                self.next_peer_index = 0
            peer = self.peers[self.next_peer_index]
            self.next_peer_index += 1
            return peer

    def average_blocks_downloaded(self) -> float:
        if self.thread_count == 0:
            return -1
        return self.total_blocks_downloaded / self.thread_count

    def average_connection_time(self) -> float:
        if self.thread_count == 0:
            return -1.0
        return self.total_connection_times / self.thread_count

    def average_successful_time(self) -> float:
        if self.successful_count == 0:
            return -1.0
        return self.total_successful_times / self.successful_count

    def average_unsuccessful_time(self) -> float:
        if self.unsuccessful_count == 0:
            return -1.0
        return self.total_unsuccessful_times / self.unsuccessful_count

    def analyse_successful_time(self, t: int) -> None:
        if t < self.min_successful_time:
            self.min_successful_time = t
        elif t > self.max_successful_time:
            self.max_successful_time = t

    def analyse_unsuccessful_time(self, t: int) -> None:
        if t < self.min_unsuccessful_time:
            self.min_unsuccessful_time = t
        elif t > self.max_unsuccessful_time:
            self.max_unsuccessful_time = t

    def analyse_blocks_downloaded(self, n: int) -> None:
        if n > self.max_blocks_downloaded:
            self.max_blocks_downloaded = n
        elif n < self.min_blocks_downloaded:
            self.min_blocks_downloaded = n

    def analyse_connection_time(self, t: int) -> None:
        if t > self.max_connection_time:
            self.max_connection_time = t
        if t < self.min_connection_time:
            self.min_connection_time = t

    def str_stats(self) -> str:
        string = 'Total threads ran: %d \n\n' % self.thread_count
        string += 'Socket Connection Data:\n'
        string += '    Average connection time: %f\n' % self.average_connection_time()
        string += '    Max connection time: %f s\n' % self.max_connection_time
        string += '    Min connection time: %f s\n' % self.min_connection_time
        string += 'Successful Thread Data:\n'
        string += '    Number of successful threads: %d\n' % self.successful_count
        string += '    Average successful thread runtime: %f s\n' % self.average_successful_time()
        string += '    Max successful thread runtime: %f s\n' % self.max_successful_time
        string += '    Min successful thread runtime: %f s\n' % self.min_successful_time
        string += 'Unsuccessful Thread Data: \n'
        string += '    Number of unsuccessful threads: %d\n' % self.unsuccessful_count
        string += '    Average unsuccessful thread runtime: %f s\n' % self.average_unsuccessful_time()
        string += '    Max unsuccessful thread runtime: %f s\n' % self.max_unsuccessful_time
        string += '    Min unsuccessful thread runtime: %f s\n' % self.min_unsuccessful_time
        string += 'Block Download Data:\n'
        string += '    Total blocks downloaded: %d\n' % self.total_blocks_downloaded
        string += '    Average blocks downloaded: %d\n' % self.average_blocks_downloaded()
        string += '    Max blocks downloaded: %d\n' % self.max_blocks_downloaded
        string += '    Min blocks downloaded: %d\n' % self.min_blocks_downloaded
        string += '    One block downloads: %d\n' % self.one_block_downloads
        string += '    Blocks with no balance found: %d\n\n' % self.no_balance_block_count
        string += 'Number of reps: %d\n' % len(self.representatives)
        return string

    def str_reps(self) -> str:
        string = ''
        for rep in self.representatives:
            string += str(rep) + '\n'
        return string

    def thread_func(self, peer: Peer, account: bytes) -> None:
        try:
            self.get_representative_for_account(account, peer, self.mutex)
        finally:
            self.sem.release()
            print('Thread completed peer=%s account=%s' % (peer, hexlify(account)))

    def get_account_rep(self, account: bytes) -> None:
        self.sem.acquire()
        peer = self.get_next_peer()
        thread = threading.Thread(target=self.thread_func,
                                  args=(peer, account),
                                  daemon=True)
        thread.start()
        self.thread_count += 1
        self.threads.append(thread)

    def join(self) -> None:
        for t in self.threads:
            t.join()
            self.threads.remove(t)
        print('All threads are finished')

    def get_rep_in_representatives(self, representative: bytes) -> bytes or None:
        for rep in self.representatives:
            if rep.representative == representative:
                return rep
        return None

    # Remember to use mutex when using this function
    def process_block_no_balance(self, block, endtime: int) -> None:
        print("Block has no balance")

        self.no_balance_block_count += 1
        self.unsuccessful_count += 1
        self.total_unsuccessful_times += endtime
        self.analyse_unsuccessful_time(endtime)

    # Remember to use mutex when using this function
    def process_good_block(self, rep_block, endtime: int) -> None:
        print('Found rep: %s' % hexlify(rep_block.representative))

        rep = self.get_rep_in_representatives(rep_block.representative)

        if rep is None:
            rep = Rep(rep_block.representative)
            self.representatives.add(rep)

        rep.add_voting_power(rep_block.get_balance())

        self.successful_count += 1
        self.total_successful_times += endtime
        self.analyse_successful_time(endtime)

    def process_zero_balance_block(self, endtime: int) -> None:
        print('Balance is zero')
        self.unsuccessful_count += 1
        self.total_unsuccessful_times += endtime
        self.analyse_unsuccessful_time(endtime)

    def get_representative_for_account(self, acc: bytes, peer: Peer, mutex: threading.Lock) -> None:
        starttime = time.time()
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            try:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                s.settimeout(3)
                conn_starttime = time.time()
                s.connect((str(peer.ip), peer.port))
                conn_time = time.time() - conn_starttime
                with mutex:
                    self.total_connection_times += conn_time
                    self.analyse_connection_time(conn_time)

                # we ask for one block first in the hope it has everything we need (state block) 
                s.settimeout(10)
                blocks = get_account_blocks(self.ctx, s, acc, no_of_blocks=1)
                blocks_downloaded = 0

                # Keep pulling blocks from account if the block is not a block state, change, or open
                while True:
                    with mutex:
                        if len(blocks) == 0:
                            raise NoBlocksPulled("No blocks pulled from account: %s" % acctools.to_account_addr(acc))

                        rep_block = find_rep_in_blocks(blocks)
                        if rep_block is not None:

                            if rep_block.get_balance() is None:
                                endtime = time.time() - starttime
                                self.process_block_no_balance(rep_block, endtime)

                            elif rep_block.get_balance() > 0:
                                endtime = time.time() - starttime
                                self.process_good_block(rep_block, endtime)
                            else:
                                endtime = time.time() - starttime
                                self.process_zero_balance_block(endtime)

                            blocks_downloaded += len(blocks)

                            self.total_blocks_downloaded += blocks_downloaded
                            self.analyse_blocks_downloaded(blocks_downloaded)

                            if blocks_downloaded == 1:
                                self.one_block_downloads += 1

                            return

                        blocks = get_account_blocks(self.ctx, s, acc, no_of_blocks=1000)

            # Socket sometimes times out, doesn't connect or there are no blocks read from the socket
            except (socket.error, OSError, SocketClosedByPeer, NoBlocksPulled) as e:
                print(str(e) + "(" + threading.currentThread().getName() + ")")
                endtime = time.time() - starttime
                with mutex:
                    self.total_unsuccessful_times += endtime
                    self.unsuccessful_count += 1
                    self.analyse_unsuccessful_time(endtime)


class Rep:
    def __init__(self, representative: bytes):
        self.representative = representative
        self.voting_power = 0

    def add_voting_power(self, n: int) -> None:
        self.voting_power += n

    def __eq__(self, other):
        if not isinstance(other, Rep):
            return False
        elif self.representative != other.representative:
            return False
        elif self.voting_power != other.voting_power:
            return False
        return True

    def __hash__(self):
        return hash((self.representative, self.voting_power))

    def __str__(self):
        string = "Rep: %s\n" % hexlify(self.representative)
        string += "Voting Power: %d \n" % self.voting_power
        return string


class memory_tracker:
    def __init__(self):

        self._running = True
        self.peak = -1
        self.thread = None

    def track(self) -> None:
        assert tracemalloc.is_tracing()

        while self._running:

            current, peak = tracemalloc.get_traced_memory()

            if peak > self.peak:
                print("[Memory_Tracker] current: %d B, peak: %d B" % (current, peak))
                self.peak = peak

            time.sleep(60)

    def start(self) -> None:
        thread = threading.Thread(target=self.track,
                                  daemon=True)
        thread.start()
        self.thread = thread

    def stop(self) -> None:
        self._running = False
        self.thread.join()


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

    parser.add_argument('-c', '--thread_count', type=int, default=None,
                        help='determines the number of threads that can run in parallel')
    parser.add_argument('-a', '--account_count', type=int, default=0xffffffff,
                        help='determines the number of accounts that will be pulled')
    parser.add_argument('--ipv4', action='store_true', default=False,
                        help='determies whether only ipv4 addresses should be used')
    parser.add_argument('--mem_track', action='store_true', default=False,
                        help='tells the script to track memory usage detecting upward trend')

    return parser.parse_args()


def find_rep_in_blocks(blocks: list):
    for b in blocks:
        if type(b) in [block_open, block_state, block_change]:
            return b
    return None


def frontier_iter(ctx: dict, peers: list[Peer], num: int, start_acc: bytes = b'\x00' * 32) -> frontier_entry or None:
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.settimeout(3)

        failed_count = 0

        accounts_read = 0
        last_acc = start_acc
        while True:
            try:
                peer = random.choice(peers)
                s.connect((str(peer.ip), peer.port))
                front_hdr = frontier_request.generate_header(ctx)
                req = frontier_request(front_hdr, maxacc=num, start_account=start_acc)
                s.send(req.serialise())

                for i in range(0, num):
                    accounts_read += 1
                    front = read_frontier_response(s)
                    last_acc = front.account
                    if front.is_end_marker():
                        return
                    yield front

                break

            except (socket.error, OSError) as err:
                if failed_count >= 20:
                    raise FrontierIteratorFail("20 socket errors in a row")

                failed_count += 1
                continue

            except PyNanoCoinException:
                num = num - accounts_read
                start_acc = last_acc
                continue


def main() -> None:
    args = parse_args()

    if args.mem_track:
        tracemalloc.start()
        mem_tracker = memory_tracker()
        mem_tracker.start()

    ctx = livectx
    if args.test: ctx = testctx
    elif args.beta: ctx = betactx

    peers = get_peers_from_service(ctx)
    peers = list(filter(lambda p: p.score == 1000, peers))

    if args.ipv4:
        peers = list(filter(lambda p: p.ip.is_ipv4(), peers))

    if args.thread_count is None:
        thread_count = len(peers)

    else:
        thread_count = args.thread_count

    starttime = time.time()
    threadman = thread_manager(ctx, peers, thread_count)

    front_iter = frontier_iter(ctx, peers, args.account_count)

    # Go through each account
    for front in front_iter:
        threadman.get_account_rep(front.account)
        threadman.update()

    print('all threads started')

    # wait for all threads to finish
    threadman.join()

    if args.mem_track:
        mem_tracker.stop()

    timetaken = time.time() - starttime

    print(threadman.str_reps())
    print(threadman.str_stats())
    print("Total run time: %f" % timetaken)


if __name__ == '__main__':
    main()
