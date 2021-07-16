import binascii
import random
import socket
from nanolib import message_header, network_id, message_type, livectx, read_socket, get_all_dns_addresses, \
    get_account_id, get_initial_connected_socket


class frontier_request:
    def __init__(self, start_account='00'*32):
        self.header = message_header(network_id(67), [18, 18, 18], message_type(8), 0)
        self.start_account = binascii.unhexlify(start_account)
        self.max_age = binascii.unhexlify('FFFFFFFF')
        self.max_acc = binascii.unhexlify("FFFFFFFF")

    def serialise(self):
        data = self.header.serialise_header()
        data += self.start_account
        data += self.max_age
        data += self.max_acc
        return data

class frontier_entry:
    def __init__(self, account, frontier_hash):
        self.account = account
        self.frontier_hash = frontier_hash

    def __str__(self):
        string = "%s\n" % get_account_id(self.account)
        string += "%s\n" % binascii.hexlify(self.frontier_hash).decode("utf-8").upper()
        return string



def read_frontier_response(s):
    frontiers = []
    counter = 0
    while True:
        data = read_socket(s, 64)
        if int.from_bytes(data, "big") == 0:
            print("counter: {}".format(counter))
            return frontiers
        frontier = frontier_entry(data[0:32], data[32:])
        frontiers.append(frontier)
        print(frontier)
        counter += 1
        print("counter: {}".format(counter))

ctx = livectx
s = get_initial_connected_socket()

frontier = frontier_request()
s.send(frontier.serialise())
frontiers = read_frontier_response(s)
