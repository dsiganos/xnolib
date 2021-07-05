from nanolib import *

handshake_exchange_data = {
    "response_vk": binascii.unhexlify('9d17bf0a2571377c4a1d10eb1330266a5d8c6898bb7dfc487242e419ac9852e0'),
    "response_sig": binascii.unhexlify('eb52b3182359562259f4634287e9b4857c86339e18d8cfdb7b45237662993d1448673bf3075771744ecb62e14774f267ed26f6e4c1913eb571bb8b2e3b8fd909'),
    "cookie": binascii.unhexlify('05851093f35a90be9f1c8a48539d70b48d1a2f2787a1158904d15c38f86188e2')
}

print(eddsa.verify(handshake_exchange_data["response_vk"], handshake_exchange_data["response_sig"],
                   handshake_exchange_data["cookie"]))


ctx = livectx
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
s.connect((peeraddr, ctx['peerport']))


msg_handshake = message_handshake_query()
print (msg_handshake.serialise()[6])
s.send(msg_handshake.serialise())
data = read_socket(s, 136)
print(data[6])
recvd_response = message_handshake_response.parse_msg_handshake_response(data)

response = message_handshake_response.create_handshake_response(recvd_response.cookie)
s.send(response.serialise())
data = read_socket(s, 104)
print(data[6])
recvd_response2 = message_handshake_response.parse_msg_handshake_response(data)

keepalive = message_keepalive(ctx['net_id'])
req = keepalive.serialise()
s.send(req)
print(s.recv(1000))