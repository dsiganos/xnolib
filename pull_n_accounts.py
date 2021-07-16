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
s = get_initial_connected_socket()

manager = blocks_manager()

next_account = binascii.unhexlify(ctx["genesis_pub"])

acc_iter = manager.next_acc_iter()
count = 0
while next_account is not None:
    if count == 10:
        break
    header = message_header(network_id(67), [18, 18, 18], message_type(6), 0)
    bulk_pull = message_bulk_pull(header, binascii.hexlify(next_account).decode("utf-8"))
    s.send(bulk_pull.serialise())
    blocks = read_all_blocks_from_socket(s)
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

test = b'\tk\xce\x88\x9e\xbd\xf7\xef\xeb\x11\x13D\xd9\xc3\xba\xba-n\x82?<\xb01l\x8a\xf6i\x1c\xc8\r79'