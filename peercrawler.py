from nanolib import *

block_type_lengths = {
    2 : 152,
    3 : 136,
    4 : 168,
    5 : 136,
    6 : 216
}


class peer_manager:
    def __init__(self):
        self.peers = []

    def parse_and_add_peers(self, data):
        assert(len(data) % 18 == 0)
        n = int(len(data) / 18)
        start_index = 0
        end_index = 18
        for i in range(0, n):
            # if not self.valid_peer_data(data[start_index:end_index]):
            #     start_index = end_index
            #     end_index += 18
            #     continue
            ip = ipv6addresss.parse_address(data[start_index:end_index - 2])
            port = int.from_bytes(data[end_index - 2:end_index], "little")
            p = peer_address(ip, port)
            if p not in self.peers:
                self.peers.append(p)
            start_index = end_index
            end_index += 18

    def valid_peer_data(self, data):
        if int.from_bytes(data[0:16], "big") == 0:
            return False
        elif int.from_bytes(data[16:], "little") == 0:
            return False
        return True


def calculate_item_count(extensions):
    return(extensions & 0xf000) >> 12


def report_warning():
    print("Warning: Bad Peer")
    # TODO: Add the peer and the address the socket was connected to


def clear_next_packet(s, header):
    if header.msg_type == message_type(4):
        i_count = calculate_item_count(header.ext)
        for i in range(0, i_count):
            data = read_socket(s, 1)
            if data[0] not in range(2, 7):
                read_socket(s, 71)
            else:
                read_socket(s, block_type_lengths.get(data[0]))

    elif header.msg_type == message_type(5):
        i_count = calculate_item_count(header.ext)
        read_socket(s, 104)
        for i in range(0, i_count):
            data = read_socket(s, 1)
            if data[0] not in range(2, 7):
                read_socket(s, 31)
            else:
                read_socket(s, block_type_lengths.get(data[0]))

def get_next_peers(s):
    header = message_header.parse_header(read_socket(s, 8))
    if header.msg_type != message_type(2):
        clear_next_packet(s, header)
    return read_socket(s, 144)









ctx = livectx
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
s.connect((peeraddr, ctx['peerport']))
s.settimeout(3)

perform_handshake_exchange(s)
s.send(message_keepalive().serialise())

manager = peer_manager()
manager.parse_and_add_peers(get_next_peers(s))
for p in manager.peers:
    print(str(p))
