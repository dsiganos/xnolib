#!/bin/env python3
import argparse

from pynanocoin import *
from peercrawler import *


class bulk_pull_account:
    def __init__(self, hdr, account, flag, min_amount=0):
        assert (flag in [0, 1, 2])
        assert(hdr.msg_type == message_type(11))
        assert(isinstance(account, bytes))
        self.header = hdr
        self.account = account
        self.flag = flag
        self.min_amount = min_amount

    def serialise(self):
        data = self.header.serialise_header()
        data += self.account
        data += self.min_amount.to_bytes(16, "big")
        data += self.flag.to_bytes(1, "big")
        return data

    @classmethod
    def parse(cls, hdr, data):
        account = data[0:32]
        min_amount = int.from_bytes(data[32:48], 'big')
        flag = data[48]
        return bulk_pull_account(hdr, account, flag, min_amount=min_amount)

    def __eq__(self, other):
        if not isinstance(other, bulk_pull_account):
            return False
        elif not self.account == other.account:
            return False
        elif not self.flag == other.flag:
            return False
        elif not self.min_amount == other.min_amount:
            return False
        elif not self.header == other.header:
            return False
        return True

    def __str__(self):
        string = str(self.header) + '\n'
        string += 'Account: %s \n' % hexlify(self.account)
        string += 'Flag: %d \n' % self.flag
        string += 'Min Amount: %d\n' % self.min_amount
        return string


class bulk_pull_account_entry:
    def __init__(self, source=None, hash=None, amount=-1):
        self.hash = hash
        self.amount = amount
        self.source = source

    def __str__(self):
        string =  "Hash: %s\n" % hexlify(self.hash)
        string += "Amount: %d\n" % self.amount
        string += "Source: %s\n" % hexlify(self.source)
        return string


class bulk_pull_account_response:
    def __init__(self, frontier_hash, balance, account_entries=[]):
        assert(isinstance(balance, int))
        self.frontier_hash = frontier_hash
        self.balance = balance
        self.account_entries = account_entries

    def add_entry(self, entry):
        assert(isinstance(entry, bulk_pull_account_entry))
        self.account_entries.append(entry)

    def __str__(self):
        balance = self.balance / (10**30)
        string =  "Frontier Hash: %s\n" % hexlify(self.frontier_hash)
        string += "Balance: %f\n" % balance
        string += "%d Entries: \n" % len(self.account_entries)
        for e in self.account_entries:
            string += "\n"
            string += str(e)
            string += "\n"
        return string

def read_account_entries(s, flag):
    assert(flag in [0, 1, 2])
    if flag == 0:
        return read_account_entries_hash_amount(s)
    elif flag == 1:
        return read_account_entries_addr_only(s)
    elif flag == 2:
        return read_account_entries_hash_amount_addr(s)


# Reads entries if flags is not an instance of pending_address_only or pending_include_address (flag == 0)
def read_account_entries_hash_amount(s):
    hash = read_socket(s, 32)
    amount = int.from_bytes(read_socket(s, 16), "big")
    entries = []
    while int.from_bytes(hash, "big") != 0:
        entry = bulk_pull_account_entry(hash=hash, amount=amount)
        entries.append(entry)
        hash = read_socket(s, 32)
        amount = int.from_bytes(read_socket(s, 16), "big")
    return entries


# Reads entries if flags instance: pending_address_only (flag == 1)
def read_account_entries_addr_only(s):
    source = read_socket(s, 32)
    entries = []
    while int.from_bytes(source, "big") != 0:
        entry = bulk_pull_account_entry(source=source)
        entries.append(entry)
        source = read_socket(s, 32)
    return entries


# Reads the entries if flags instance: pending_include_address (flag == 2)
def read_account_entries_hash_amount_addr(s):
    hash = read_socket(s, 32)
    amount = int.from_bytes(read_socket(s, 16), "big")
    source = read_socket(s, 32)
    entries = []
    while int.from_bytes(hash, "big") != 0:
        entry = bulk_pull_account_entry(hash=hash, amount=amount, source=source)
        entries.append(entry)
        hash = read_socket(s, 32)
        amount = int.from_bytes(read_socket(s, 16), "big")
        source = read_socket(s, 32)
    return entries


def parse_args():
    parser = argparse.ArgumentParser()

    group1 = parser.add_mutually_exclusive_group()
    group1.add_argument('-b', '--beta', action='store_true', default=False,
                        help='use beta network')
    group1.add_argument('-t', '--test', action='store_true', default=False,
                        help='use test network')

    parser.add_argument('--peer',
                        help='peer to contact')

    parser.add_argument('-a', '--account', type=str,
                        help='Account from which we pull')

    parser.add_argument('-f', '--flag', type=int, default=0,
                        help='Flag for the bulk_pull_account:\n  0: hash and amount\n  1: address only\n  '+
                             '2: hash, amount and address')

    return parser.parse_args()

def main():
    args = parse_args()

    ctx = livectx
    if args.beta: ctx = betactx
    elif args.test: ctx = testctx

    if args.peer:
        peeraddr, peerport = parse_endpoint(args.peer, default_port=ctx['peerport'])
    else:
        peer = get_random_peer(ctx, lambda p: p.score >= 1000)
        peeraddr, peerport = str(peer.ip), peer.port

    print('Connecting to [%s]:%s' % (peeraddr, peerport))
    with get_connected_socket_endpoint(peeraddr, peerport) as s:
        if args.account is None:
            account = binascii.unhexlify(ctx['genesis_pub'])
        else:
            account = binascii.unhexlify(args.account)
        hdr = message_header(network_id(67), [18, 18, 18], message_type(11), 0)

        # Change the flag to see the different results (in range 0-2)
        flag = args.flag

        msg = bulk_pull_account(hdr, account, flag)
        s.send(msg.serialise())

        # All entries start with a frontier_balance_entry
        front_hash = read_socket(s, 32)
        balance = int.from_bytes(read_socket(s, 16), "big")

        print("flag: %d" % flag)
        resp = bulk_pull_account_response(front_hash, balance)
        entries = read_account_entries(s, flag)
        for e in entries:
            resp.add_entry(e)
        print(resp)

    # data = s.recv(1000)
    # print(data)
    # print(len(data))


if __name__ == "__main__":
    main()
