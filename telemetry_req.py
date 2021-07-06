from nanolib import *

class telemetry_req:
    def __init__(self):
        self.header = message_header(network_id(67), [18, 18, 18], message_type(12), 0)

    def serialise(self):
        return self.header.serialise_header()


ctx = livectx
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
s.connect((peeraddr, ctx['peerport']))
s.settimeout(2)

msg_handshake = message_handshake_query()
s.send(msg_handshake.serialise())

data = read_socket(s, 136)
recvd_response = message_handshake_response.parse_msg_handshake_response(data)


response = message_handshake_response.create_handshake_response(recvd_response.cookie)
s.send(response.serialise())

header = message_header(network_id(67), [18, 18, 18], message_type(12), 0)
s.send(header.serialise_header())
print(s.recv(1000))