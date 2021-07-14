from nanolib import *

header = message_header(network_id(67), [18, 18, 18], message_type(4), 0)
block = block_open(genesis_block_open["source"], genesis_block_open["representative"],
                   genesis_block_open["account"], genesis_block_open["signature"],
                   genesis_block_open["work"])

msg = header.serialise_header()
msg += block.serialise(True)
print(len(msg))

ctx = livectx
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
peeraddr = '::ffff:' + peeraddr
s.connect((peeraddr, ctx['peerport']))
s.settimeout(2)
perform_handshake_exchange(s)
s.send(msg)

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


