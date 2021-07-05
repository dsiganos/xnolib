import binascii
import random
import socket

from main import message_header, network_id, message_type, livectx, read_socket, get_all_dns_addresses


class frontier_request:
    def __init__(self, start_account='00'*32):
        self.header = message_header(network_id(67), [18, 18, 18], message_type(8), '0000')
        self.start_account = binascii.unhexlify(start_account)
        self.max_age = binascii.unhexlify('FFFFFFFF')
        self.max_acc = binascii.unhexlify("FFFFFFFF")

    def serialise(self):
        data = self.header.serialise_header()
        data += self.start_account
        data += self.max_age
        data += self.max_acc
        return data


ctx = livectx
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
s.connect((peeraddr, ctx['peerport']))
print('Connected to %s:%s' % s.getpeername())
s.settimeout(2)
frontier = frontier_request()
s.send(frontier.serialise())
read_socket(s, 64)
s.recv(1)