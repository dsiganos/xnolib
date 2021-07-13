import random
import socket

from nanolib import *

ctx = livectx
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
s.connect((peeraddr, ctx['peerport']))
print('Connected to %s:%s' % s.getpeername())
s.settimeout(2)

bulk_pull = message_bulk_pull(ctx['genesis_pub'], network_id(67))
# bulk_pull2 = message_bulk_pull('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5', network_id(67))
req = bulk_pull.serialise()
s.send(req)
# req = bulk_pull2.serialise()
# s.send(req)

blocks = read_blocks_from_socket(s)

manager = blocks_manager()
while len(blocks) != 0:
    manager.process(blocks.pop())

print(manager.accounts[0].str_blocks())
