import time

from nanolib import *


class confirm_req_hash:
    def __init__(self, first, second, header=message_header(network_id(67), [18, 18, 18], message_type(12), 0)):
        self.header = header
        self.first = first
        self.second = second

    @classmethod
    def parse(self, data):
        assert(len(data) == 72)
        header = message_header.parse_header(data[:8])
        first = data[8:40]
        second = data[40:]
        return confirm_req_hash(first, second, header=header)

    def serialise(self):
        data = self.first
        data += self.second
        return data

    def __str__(self):
        string = "First: %s\n" % hexlify(self.first)
        string += "Second: %s\n" % hexlify(self.first)
        return string


class confirm_req_block:
    def __init__(self, hdr, block):
        assert(isinstance(hdr, message_header))
        self.hdr = hdr
        self.block = block

    def serialise(self):
        data = self.hdr.serialise_header()
        data += block.serialise(True)
        return data

class vote_common:
    def __init__(self, account, sig, seq):
        assert(isinstance(seq, int))
        self.account = account
        self.sig = sig
        self.seq = seq

    @classmethod
    def parse(cls, data):
        assert (len(data) == 104)
        account = data[0:32]
        sig = data[32:96]
        seq = int.from_bytes(data[96:], "little")
        return vote_common(account, sig, seq)

    def __str__(self):
        string = "Account: %s\n" % hexlify(self.account)
        string += "Signature: %s\n" % hexlify(self.sig)
        stirng += "Sequence: %s\n" % self.seq
        return string


class confirm_ack_hash:
    def __init__(self, hdr, common, hashes):
        assert(isinstance(hdr, message_header))
        assert(isinstance(common, vote_common))
        self.hdr = hdr
        self.common = common
        self.hashes = hashes

    @classmethod
    def parse(cls, hdr, data):
        assert(isinstance(hdr, message_header))
        common = vote_common.parse(data[0:104])

        item_count = hdr.count_get()
        hashes_data = data[104:]
        assert((len(hashes_data)/32) == item_count)

        hashes = []
        for i in range(0, item_count):
            _hash = hashes_data[:32]
            hashes_data = hashes_data[32:]
            hashes.append(_hash)

        return confirm_ack_hash(hdr, common, hashes)

    def __str__(self):
        string = ""
        string += str(self.hdr)
        string += str(self.common)
        string += "Hashes: \n"
        for h in self.hashes:
            string += "   " + h + "\n"
        return string


class confirm_ack_block:
    def __init__(self, hdr, block):
        assert(isinstance(hdr, message_header))
        self.hdr = hdr
        self.block = block

    @classmethod
    def parse(cls, hdr, data):
        assert(isinstance(hdr, message_header))
        block_type = hdr.block_type()
        assert(block_type in range(2, 7))
        assert(len(data) == block_length_by_type(block_type))
        block = None
        if block_type == 2:
            block = block_send.parse(data)
        elif block_type == 3:
            block = block_receive.parse(data)
        elif block_type == 4:
            block = block_open.parse(data)
        elif block_type == 5:
            block = block_change.parse(data)
        elif block_type == 6:
            block = block_state.parse(data)
        return confirm_ack_block(hdr, block)

    def __str__(self):
        string = ""
        string += str(hdr)
        string += str(block)


def get_next_confirm_ack(s):
    hdr, data = get_next_hdr_payload(s)
    while hdr.msg_type != message_type(5):
        hdr, data = get_next_hdr_payload(s)
    return hdr, data


header = message_header(network_id(67), [18, 18, 18], message_type(4), 0)
block = block_open(genesis_block_open["source"], genesis_block_open["representative"],
                   genesis_block_open["account"], genesis_block_open["signature"],
                   genesis_block_open["work"])
header.set_block_type(4)
msg = confirm_req_block(header, block)

ctx = livectx
s = get_initial_connected_socket(ctx)
assert s
s.settimeout(20)
perform_handshake_exchange(s)
s.send(msg.serialise())

confirm_acks = []

starttime = time.time()
while time.time() - starttime <= 10:
    hdr, data = get_next_confirm_ack(s)
    if hdr.block_type() == 1:
        ack = confirm_ack_hash.parse(hdr, data)
        confirm_acks.append(ack)
    else:
        ack = confirm_ack_block.parse(hdr, data)
        confirm_acks.append(ack)

for a in confirm_acks:
    print(a)

print(hdr)
print("header block type: %d" % hdr.block_type())




#TODO: Look if one confirm_ack is exactly the same every time you run the program, that should be the response





# TODO: Examine this data, why is it like this? (Look at extensions)


