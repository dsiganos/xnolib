#!/bin/env python3
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
print('Connected to [%s]:%s' % (s.getpeername()[0], s.getpeername()[1]))

header = message_header(network_id(67), [18, 18, 18], message_type(6), 0)
bulk_pull = message_bulk_pull(header, ctx['genesis_pub'])
# bulk_pull = message_bulk_pull(header, '42DD308BA91AA225B9DD0EF15A68A8DD49E2940C6277A4BFAC363E1C8BF14279')
req = bulk_pull.serialise()
s.send(req)
# req = bulk_pull2.serialise()

blocks = read_all_blocks_from_socket(s)

manager = blocks_manager()
while len(blocks) != 0:
    block = blocks.pop()
    manager.process(block)

print(manager)
print(manager.accounts[0])
print(manager.accounts[0].str_blocks())
