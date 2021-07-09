from nanolib import *

block_type_lengths = {
    2: 152,
    3: 136,
    4: 168,
    5: 136,
    6: 216
}

BLOCK_TYPE_MASK = 0x0f00
COUNT_MASK = 0xf000


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

    def str_peers(self):
        string = ""
        for p in self.peers:
            string += str(p) + "\n"
        return string

def calculate_item_count(extensions):
    return(extensions & 0xf000) >> 12

def calculate_block_type(extensions):
    return (extensions & 0x0f00) >> 8

def confirm_ack_size(ext):
    size = 104
    i_count = calculate_item_count(ext)
    block_type = calculate_block_type(ext)
    if block_type == message_type_enum.not_a_block:
        size += i_count * 32
    else:
        assert(i_count == 1)
        size += block_type_lengths.get(block_type)
    return size

def confirm_req_size(ext):
    i_count = calculate_item_count(ext)
    block_type = calculate_block_type(ext)
    if block_type == message_type_enum.not_a_block:
        size = 64 * i_count
    else:
        assert(i_count == 1)
        size = block_type_lengths.get(block_type)
    return size

def report_warning():
    print("Warning: Bad Peer")
    # TODO: Add the peer and the address the socket was connected to


def clear_next_packet(s, header):
    if header.msg_type == message_type(4):
        size = confirm_req_size(header.ext)
        print(size)
        read_socket(s, size)


    elif header.msg_type == message_type(5):
        read_socket(s, confirm_ack_size(header.ext))


def get_next_peers(s):
    data = read_socket(s, 8)
    print(data)
    if data is None:
        return None
    header = message_header.parse_header(data)
    if header.msg_type != message_type(2):
        clear_next_packet(s, header)
    return read_socket(s, 144)




# test = b'RC\x12\x12\x12\x05\x001\xbdbg\xd6\xec\xd8\x03\x83\'\xd2\xbc\xc0\x85\x0b\xdf\x8fV\xec\x04\x14\x91"\x07\xe8\x1b\xcf\x90\xdf\xac\x8aJ\xaa\x15#\x98T\x8d6\xbf\\ \x03G\x87\x14L\x0e"\'\xd2H\x17\xb9\xd8k\x9a\xefKe\xdb\xe1\xd2.\n?h.\xf1\xbc[\x8d\xf1a\xdd\xdc\x14\\\xdf\x9a\\\xff\x9f\xbc EL\xa8\xc2\xda\x9f=Iep\xa6\x06\xff\xff\xff\xff\xff\xff\xff\xff^LeT\x05d\x86\x0f\xb2;8\x9aL%c|\xa5\x98b\xc1\x8c\xda\xc2Z\xe5\xd2yu\x85\xceY\t{\x91\xdax\x96\x9d\xc7\x01\xf9\xd8m\\\xfab:\xb8\xa1%V\xbd\x11\xe5RyE\xa2\xac{k"\x800>UK%\x9d8\x9aR\x90\xe6\x1c\x11D\x9b\xe1\xacd\x05"h>I?\xc7q\xbeZs\xcb0\xfa\x06'
# header = message_header.parse_header(test[0:8])
# print(calculate_item_count(header.ext))

# test = b'\x1c\x07\x15\xe7\xee\xbd/\x85'
# print(len(test))

# test = b"\xbd\xe7\x1e\x90S%\xde\xfd\x18\xdd\x01M\x94\xa7\x04\xdb\x0b\xd0\xfc\xf9?c\x02\xa9,V\xc9\xdd\xfe\xed'\xa8\xd1\xc8\xf4.\xf6\xdbt\x90qe|\xf5\x8d\xa7w\xc9;<\xd0[\x86\x94\xc9\xd2;\xbc\xc9\x06=\xce\nc"
# print(len(test))

# test = b'RC\x12\x12\x12\x04\x00\x11\x15O\x9f\xa2\x1eL\xe2\xe9e\xaa\xf8\xb2.\x18\xe6\xd7%~\x9c\x1d\x96\n\x9b\xa5\xb6\xc2\xcda\x98I\xd5\x94S\x86\xa0$x\x14Z\xf3\xdb\x15\xe2\xa2\x0eM\xebG#V\xec\xf4G\x9b\xe6\xa7E\xe3\x80\x00\x8f4\x1b\x15'
# print(len(test))
# --------------------------------------------- End of Analysis Code ---------------------------------------------





ctx = livectx
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
s.connect((peeraddr, ctx['peerport']))
s.settimeout(5)

perform_handshake_exchange(s)
s.send(message_keepalive().serialise())
manager = peer_manager()
recvd_peers = get_next_peers(s)
while recvd_peers is not None:
    manager.parse_and_add_peers(recvd_peers)
    print(manager.str_peers())
    recvd_peers = get_next_peers(s)


# for p in manager.peers:
#     print(str(p))
