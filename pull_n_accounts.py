import random
import socket

from nanolib import *


def valid_account(acc):
    # if acc == b"\x05\x9fh\xaa\xb2\x9d\xe0\xd3\xa2tCb\\~\xa9\xcd\xdbe\x17\xa8\xb7o\xe3w'\xefjMv\x83*\xd5":
    #     return False
    if acc == b'\x00' * 32:
        return False
    return True

ctx = livectx
s = get_initial_connected_socket(ctx)
assert s

manager = block_manager()

next_account = binascii.unhexlify(ctx["genesis_pub"])

acc_iter = manager.next_acc_iter()
count = 0
while next_account is not None:
    if count == 10:
        break
    blocks = get_account_blocks(s, next_account)
    while len(blocks) != 0:
        block = blocks.pop()
        manager.process(block)
    next_account = next(acc_iter)
    print(next_account)
    while not valid_account(next_account):
        next_account = next(acc_iter)
        print(next_account)

    print("Valid account!")
    count += 1

print(manager)
