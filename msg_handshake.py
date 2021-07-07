from nanolib import *


ctx = livectx
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
s.connect((peeraddr, ctx['peerport']))
s.settimeout(2)

perform_handshake_exchange(s)

# print(eddsa.verify(recvd_response.account, recvd_response.sig, msg_handshake.cookie))
