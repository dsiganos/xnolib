import random
import socket

from nanolib import *


def valid_account(acc):
    if acc == b"\x05\x9fh\xaa\xb2\x9d\xe0\xd3\xa2tCb\\~\xa9\xcd\xdbe\x17\xa8\xb7o\xe3w'\xefjMv\x83*\xd5":
        return False
    elif acc == b'\x00' * 32:
        return False
    return True

ctx = livectx
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
peeraddr = '::ffff:' + peeraddr
s.settimeout(3)
s.connect((peeraddr, ctx['peerport']))

manager = blocks_manager()

# header = message_header(network_id(67), [18, 18, 18], message_type(6), 0)
# bulk_pull = message_bulk_pull(header, ctx["genesis_pub"])
# s.send(bulk_pull.serialise())
# blocks = read_blocks_from_socket(s)
# while len(blocks) != 0:
#     manager.process(blocks.pop())

next_account = binascii.unhexlify(ctx["genesis_pub"])

acc_iter = manager.next_acc_iter()
count = 1
while next_account is not None:
    if count == 10:
        break
    header = message_header(network_id(67), [18, 18, 18], message_type(6), 0)
    bulk_pull = message_bulk_pull(header, binascii.hexlify(next_account).decode("utf-8"))
    s.send(bulk_pull.serialise())
    blocks = read_blocks_from_socket(s)
    while len(blocks) != 0:
        block = blocks.pop()
        manager.process(block)
    next_account = next(acc_iter)
    while not valid_account(next_account):
        next_account = next(acc_iter)
        print(next_account)

    print("Valid account!")
    count += 1


print(manager)
