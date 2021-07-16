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

blocks = get_account_blocks(s, ctx["genesis_pub"])

manager = blocks_manager()
while len(blocks) != 0:
    block = blocks.pop()
    manager.process(block)

print(manager)