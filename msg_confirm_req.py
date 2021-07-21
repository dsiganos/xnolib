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


header = message_header(network_id(67), [18, 18, 18], message_type(4), 0)
block = block_open(genesis_block_open["source"], genesis_block_open["representative"],
                   genesis_block_open["account"], genesis_block_open["signature"],
                   genesis_block_open["work"])

msg = header.serialise_header()
msg += block.serialise(True)
print(len(msg))

ctx = livectx
s = get_initial_connected_socket(ctx)
assert s



data = s.recv(1000)
data += s.recv(1000)
data += s.recv(1000)
print(len(data))
print(data)
print(data[5])

msg_header = message_header.parse_header(data[0:8])
print(msg_header)
print(data[9])

# TODO: Examine this data, why is it like this? (Look at extensions)


