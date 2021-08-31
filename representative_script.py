import argparse
from statistics import mean

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
        self.successful_times = []
        self.unsuccessful_times = []

        self.representatives = representatives
        self.peers_in_use = []
        self.threads = []
        self.blocks_downloaded = []
        self.connection_times = []
        self.successful_thread_count = 0
        self.mutex = threading.Lock()

    def update_manager(self):
        for data in self.threads:
            peer = data[0]
            results = data[1]
            account = data[2]
            thread = data[3]

            if not thread.is_alive():
                self.threads.remove(data)
                self.peers_in_use.remove(peer)
                if results['blocks_downloaded'] is not None:
                    self.blocks_downloaded.append(results['blocks_downloaded'])
                if results['connection_time'] is not None:
                    self.connection_times.append(results['connection_time'])

                if results['error'] == enum_error_type.NoError:
                    self.successful_thread_count += 1
                    self.successful_times.append(results['completion_time'])
                    continue

                elif results['error'] == enum_error_type.AccountError:
                    self.unsuccessful_times.append(results['completion_time'])
                    # this may change depending on what we decide to do with accounts that yield no blocks
                    continue

                elif results['error'] == enum_error_type.SocketError:
                    self.unsuccessful_times.append(results['completion_time'])
                    continue

                else:
                    print("Thread (%s) didn't set a results" % thread.getName())


    def get_account_reps(self, account):
        # Temp variable, remove
        while len(self.threads) == 177:
            self.update_manager()
        peer = random.choice(self.peers)
        while peer in self.peers_in_use:
            self.update_manager()
            peer = random.choice(self.peers)
        results = {
            'error': None,
            'completion_time': None,
            'blocks_downloaded': None,
            'connection_time': None
        }

        thread = threading.Thread(target=get_representative_thread,
                                  args=(self.ctx, account, self.representatives, self.mutex, peer, results,),
                                  daemon=True)
        thread.start()
        self.threads.append((peer, results, account, thread))
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
            return b.representative, b
    return None, None


def get_representative_thread(ctx, acc, representatives, mutex, peer, results):
    socket_timeout_count = 0
    blocks_downloaded = 0
    starttime = time.time()
    counter = 1
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    with s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

        try:
            conn_starttime = time.time()
            s.connect((str(peer.ip), peer.port))
            conn_time = time.time() - conn_starttime
            results['connection_time'] = conn_time

            s.settimeout(20)

            starttime2 = time.time()
            blocks = get_account_blocks(ctx, s, acc, no_of_blocks=counter)
            timetaken2 = time.time() - starttime2

            # Keep pulling blocks from account if the block is not a block state, change, or open
            while True:
                if len(blocks) == 0:
                    raise NoBlocksPulled("No blocks pulled from account: %s" % acctools.to_account_addr(acc))
                blocks_downloaded += len(blocks)
                rep, block = find_rep_in_blocks(blocks)

                if rep is not None and block is not None:
                    if block.balance == 0:
                        results['error'] = enum_error_type.AccountError
                        results['completion_time'] = time.time() - starttime
                        results['blocks_downloaded'] = blocks_downloaded
                        return

                    results['error'] = enum_error_type.NoError
                    results['completion_time'] = time.time() - starttime
                    results['blocks_downloaded'] = blocks_downloaded
                    with mutex:
                        representatives.add(rep)
                    return

                counter += 1000
                starttime3 = time.time()
                blocks = get_account_blocks(ctx, s, acc, no_of_blocks=counter)
                timetaken3 = time.time() - starttime3
                pass

        # Socket sometimes times out, doesn't connect or there are no blocks read from the socket
        except (socket.error, OSError, SocketClosedByPeer, NoBlocksPulled) as e:
            print(str(e) + "(" + threading.currentThread().getName() + ")")
            results['error'] = enum_error_type.SocketError
            results['completion_time'] = time.time() - starttime
            return


def main():
    args = parse_args()

    ctx = livectx
    if args.test: ctx = testctx
    elif args.beta: ctx = betactx

    _, peers = get_peers_from_service(ctx)
    peers = list(filter(lambda p: p.score == 1000, peers))
    req = frontier_request(ctx, maxacc=10000)
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

    average_blocks_downloaded = mean(threadman.blocks_downloaded)
    average_connection_time = mean(threadman.connection_times)
    one_block_downloads = 0

    for i in threadman.blocks_downloaded:
        if i == 1:
            one_block_downloads += 1

    for rep in representatives:
        print(hexlify(rep))

    print("time taken with reading frontiers: %f" % timetaken1)
    print("Time taken just to gather reps from accounts: %f" % timetaken2)
    print("Average connection time: %f" % average_connection_time)
    print("Average blocks downloaded: %d" % average_blocks_downloaded)
    print("Number of one-block downloads: %d" % one_block_downloads)
    print("Number of successful threads: %d" % threadman.successful_thread_count)


if __name__ == '__main__':
    main()
