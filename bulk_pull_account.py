#!/bin/env python3

from pynanocoin import *


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


def main():
    s, _ = get_initial_connected_socket(livectx)
    try:
        account = binascii.unhexlify('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5')
        hdr = message_header(network_id(67), [18, 18, 18], message_type(11), 0)

        # Change the flag to see the different results (in range 0-2)
        flag = 1

        msg = bulk_pull_account(hdr, account, flag)
        s.send(msg.serialise())

        # All entries start with a frontier_balance_entry
        front_hash = read_socket(s, 32)
        balance = int.from_bytes(read_socket(s, 16), "big")

        print("frontier hash: %s     balance: %d     flag: %d" % (hexlify(front_hash), balance, flag))
        resp = bulk_pull_account_response(front_hash, balance)
        entries = read_account_entries(s, flag)
        for e in entries:
            resp.add_entry(e)
        print(resp)

    finally:
        s.close()

    # data = s.recv(1000)
    # print(data)
    # print(len(data))


if __name__ == "__main__":
    main()
