#!/bin/env python3
import random
import socket

from pynanocoin import *
from frontier_request import *
from peercrawler import *


def store_frontiers_handler(frontiers: list[frontier_entry]):
    assert isinstance(frontiers, list)

    def add_frontier(counter: int, frontier: frontier_entry, readtime: int):
        frontiers.append(frontier)

    return add_frontier


def valid_account(acc: bytes) -> bool:
    # if acc == b"\x05\x9fh\xaa\xb2\x9d\xe0\xd3\xa2tCb\\~\xa9\xcd\xdbe\x17\xa8\xb7o\xe3w'\xefjMv\x83*\xd5":
    #     return False
    if acc == b'\x00' * 32:
        return False
    return True


def main() -> None:
    ctx = testctx
    s, _ = get_initial_connected_socket(ctx)
    assert s
    frontiers = []
    with s:
        front_hdr = frontier_request.generate_header(ctx)
        s.send(frontier_request(front_hdr).serialise())
        read_all_frontiers(s, store_frontiers_handler(frontiers))

        manager = block_manager(ctx, None, None)
        manager.trust_open_blocks = True

        count = 0
        for f in frontiers:
            try:
                starttime = time.time()
                blocks = get_account_blocks(ctx, s, f.account)
                endtime = time.time()
                timetaken = endtime - starttime
                print("Time: %f" % timetaken)
                if len(blocks) == 0:
                    print("No blocks?")
                if len(blocks) > 1000:
                    print()
                count += len(blocks)
                for b in blocks:
                    starttime = time.time()
                    manager.process(b)
                    endtime = time.time()
                    timetaken = endtime - starttime
                    print()
            except ConnectionAbortedError:
                s, _ = get_initial_connected_socket(ctx)
                blocks = get_account_blocks(ctx, s, f.account)
                if len(blocks) == 0:
                    print("No blocks?")
                count += len(blocks)
                for b in blocks:
                    manager.process(b)



    # next_account = binascii.unhexlify(ctx["genesis_pub"])
    #
    # acc_iter = manager.next_acc_iter()
    # count = 0
    # while next_account is not None:
    #     if count == 10:
    #         break
    #     blocks = get_account_blocks(ctx, s, next_account)
    #     if len(blocks) == 0:
    #         next_account = next(acc_iter)
    #         continue
    #     while len(blocks) != 0:
    #         block = blocks.pop()
    #         manager.process(block)
    #     next_account = next(acc_iter)
    #     print(next_account)
    #     while not valid_account(next_account):
    #         next_account = next(acc_iter)
    #         print(next_account)
    #
    #     print("Valid account!")
    #     count += 1

    print(count)
    print(manager)

    for acc in manager.accounts:
        print(acc)
        block = acc.first
        while block is not None:
            print(block)
            block = acc.find_next(block)

    print('DONE')


if __name__ == "__main__":
    main()