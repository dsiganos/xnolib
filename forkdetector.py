import random
import socket
import time
from threading import Thread, Lock

from nanolib import *
from peercrawler import peer_manager, get_next_peers

class FoundFork(Exception): pass



def peer_crawl(manager):
    ctx = livectx
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
    s.connect((peeraddr, ctx['peerport']))
    s.settimeout(3600)
    perform_handshake_exchange(s)
    recvd_peers = get_next_peers(s)
    manager.parse_and_add_peers(recvd_peers, peer_address(ipaddress.IPv4Address(peeraddr), ctx["peerport"]))
    manager.crawl()

def bulk_pull(p_manager):
    assert(isinstance(p_manager, peer_manager))
    ctx = livectx
    for n in p_manager.nodes:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((str(n.node.get_ipv4()), n.node.port))
        s.settimeout(5)
        bulk_pull = message_bulk_pull(ctx["genesis_pub"])
        s.send(bulk_pull.serialise())
        blocks = read_blocks_from_socket(s)
        b_manager = blocks_manager()
        while len(blocks != 0):
            b_manager.process(blocks.pop())
        print("nothing")
        a, b = b_manager.accounts[0].check_forks()
        if a is not None and b is not None:
            raise FoundFork()


mutex = Lock()
p_manager = peer_manager()
t = Thread(target=peer_crawl, args=(p_manager, ))
t.start()

time.sleep(5)
t2 = Thread(target=bulk_pull, args=(p_manager, ))
t2.start()
