import socket

from nanolib import *

peer_list = []
addresses = get_all_dns_addresses("peering.nano.org")
for addr in addresses:
    addr = '::ffff:' + addr
    peer_list.append(peer_address(ipaddress.IPv6Address(addr), 7075))

for p in peer_list:
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.connect((str(p.ip), p.port))
    manager = blocks_manager()
    bulk_pull = message_bulk_pull(livectx["genesis_pub"])
    s.send(bulk_pull.serialise())
    blocks = read_blocks_from_socket(s)
    while len(blocks) != 0:
        manager.process(blocks.pop())
    manager.accounts[0].blocks[1].previous = manager.accounts[0].blocks[2].previous
    a, b = manager.accounts[0].find_forks()
    if a is not None or b is not None:
        print("Found forks in peer: %s" % str(p))
        print("The following blocks have the same previous link:")
        print(a)
        print(b)
    s.close()
