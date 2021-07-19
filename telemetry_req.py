from nanolib import *

class telemetry_req:
    def __init__(self):
        self.header = message_header(network_id(67), [18, 18, 18], message_type(12), 0)

    def serialise(self):
        return self.header.serialise_header()




ctx = livectx
s = get_initial_connected_socket(s)
assert s

perform_handshake_exchange(s)
header = message_header(network_id(67), [18, 18, 18], message_type(12), 0)
s.send(header.serialise_header())
data = s.recv(1000)
data += s.recv(1000)
data += s.recv(1000)
print(len(data))
print(data)
print(data[8])

recv_header = message_header.parse_header(data[0:8])
print(recv_header)
interesting = b'RC\x12\x12\x12\x02\x00\x00'
interesting2 = b'RC\x12\x12\x12\x04\x00\x11\x89\x98z\xbe4\xb9\x94\xc4\x1b8_\xc3\xc8\'l\x0b\xf1[\xf1m\x04\xcf\xb3r\xaah\x93J\xa8C\x1dRU\xfe\x07\x11\xce\x1ck\xbc\x8eC=\x86=\x07V\x0e\xbb\x1b\xd7\x1e\xc4U\x9d\xdc=\xf3\x95\xa2r\xc6\xd1\xbb'
header2 = message_header.parse_header(interesting)
print(len(interesting2))
print(header2)

# The data deffinitely consists of a msg_confirm_req and a keepalive
# The first msg_confirm_req contains a hash_pair
