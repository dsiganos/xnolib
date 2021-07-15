import random
import socket

from nanolib import *

ctx = livectx
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
peeraddr = '::ffff:' + peeraddr
s.settimeout(3)
s.connect((peeraddr, ctx['peerport']))

manager = blocks_manager()

next_account = binascii.unhexlify(livectx["genesis_pub"])
print(next_account)
count = 1
while next_account is not None:
    if count == 10:
        break
    header = message_header(network_id(67), [18, 18, 18], message_type(6), 0)
    bulk_pull = message_bulk_pull(header, binascii.hexlify(next_account).decode("utf-8"))
    s.send(bulk_pull.serialise())
    print("Sent request")
    blocks = read_blocks_from_socket(s)
    print(len(blocks))
    while len(blocks) != 0:
        block = blocks.pop()
        manager.process(block)

    next_account = manager.get_next_account()
    print(next_account)
    count += 1