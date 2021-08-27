import argparse

from frontier_request import *
from pynanocoin import *
from peercrawler import *
from pull_n_accounts import store_frontiers_handler
import time
import threading
import random


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


def get_representative_thread(ctx, acc, representatives, mutex, peers):
    counter = 1
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    with s:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        while True:
            try:
                peer = random.choice(peers)
                s.connect((str(peer.ip), peer.port))
                blocks = get_account_blocks(ctx, s, acc, no_of_blocks=counter)
                block = blocks[0]
                break

            # Sometimes there are no blocks read from the socket
            except IndexError as e:
                return

            # Socket sometimes times out or doesn't connect
            except (socket.timeout, OSError) as e:
                continue

        finished = False

        # Keep pulling blocks from account if the block is not a block state, change, or open
        while not finished:

            if type(block) in [block_open, block_state, block_change]:
                with mutex:
                    representatives.add(block.representative)
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
        threads = []
        # Go through each account
        for front in frontiers:

            acc = front.account
            mutex = threading.Lock()
            thread = threading.Thread(target=get_representative_thread,
                                      args=(ctx, acc, representatives, mutex, peers,),
                                      daemon=True)
            while len(threads) == 100:
                remove_finished_threads(threads)
            thread.start()
            threads.append(thread)

    for t in threads:
        t.join()
    endtime = time.time()
    timetaken1 = endtime - starttime1
    timetaken2 = endtime - starttime2
    for rep in representatives:
        print(hexlify(rep))

    print("time taken with reading frontiers: %f" % timetaken1)
    print("Time taken just to gather reps from accounts: %f" % timetaken2)


if __name__ == '__main__':
    main()
