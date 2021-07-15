import socket
import random

from nanolib import *


ctx = livectx
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
peeraddr = '::ffff:' + peeraddr
s.settimeout(3)
s.connect((peeraddr, ctx['peerport']))

perform_handshake_exchange(s)
