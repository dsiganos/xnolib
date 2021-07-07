from nanolib import *


ctx = livectx
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
s.connect((peeraddr, ctx['peerport']))
s.settimeout(2)

msg_handshake = handshake_query()
s.send(msg_handshake.serialise())
print(msg_handshake)

data = read_socket(s, 136)
recvd_response = handshake_response_query.parse_query_response(data)
print(recvd_response)


response = handshake_response.create_response(recvd_response.cookie)
print(response)
s.send(response.serialise())

# print(eddsa.verify(recvd_response.account, recvd_response.sig, msg_handshake.cookie))
