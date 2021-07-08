from nanolib import *

block_type_lengths = {
    2: 152,
    3: 136,
    4: 168,
    5: 136,
    6: 216
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

    def str_peers(self):
        string = ""
        for p in self.peers:
            string += str(p) + "\n"
        return string

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
            print(data[0])
            if data[0] not in range(2, 7):
                read_socket(s, 71)
            else:
                read_socket(s, block_type_lengths.get(data[0]))

    elif header.msg_type == message_type(5):
        i_count = calculate_item_count(header.ext)
        read_socket(s, 104)
        data = read_socket(s, 1)
        if data[0] not in range(2, 7):
            print("Clearing: {}".format(read_socket(s, 31)))
            for i in range(1, i_count):
                print("Clearing 2: {}".format(read_socket(s, 32)))

        else:
            assert(i_count == 1)
            read_socket(s, block_type_lengths.get(data[0]))


def get_next_peers(s):
    data = read_socket(s, 8)
    print(data)
    if data is None:
        return None
    try:
        header = message_header.parse_header(data)
    except ParseErrorBadMagicNumber:
        print(s.recv(200))
        print("stop here")
        return None
    if header.msg_type != message_type(2):
        clear_next_packet(s, header)
    return read_socket(s, 144)




# test = b'RC\x12\x12\x12\x05\x001\xbdbg\xd6\xec\xd8\x03\x83\'\xd2\xbc\xc0\x85\x0b\xdf\x8fV\xec\x04\x14\x91"\x07\xe8\x1b\xcf\x90\xdf\xac\x8aJ\xaa\x15#\x98T\x8d6\xbf\\ \x03G\x87\x14L\x0e"\'\xd2H\x17\xb9\xd8k\x9a\xefKe\xdb\xe1\xd2.\n?h.\xf1\xbc[\x8d\xf1a\xdd\xdc\x14\\\xdf\x9a\\\xff\x9f\xbc EL\xa8\xc2\xda\x9f=Iep\xa6\x06\xff\xff\xff\xff\xff\xff\xff\xff^LeT\x05d\x86\x0f\xb2;8\x9aL%c|\xa5\x98b\xc1\x8c\xda\xc2Z\xe5\xd2yu\x85\xceY\t{\x91\xdax\x96\x9d\xc7\x01\xf9\xd8m\\\xfab:\xb8\xa1%V\xbd\x11\xe5RyE\xa2\xac{k"\x800>UK%\x9d8\x9aR\x90\xe6\x1c\x11D\x9b\xe1\xacd\x05"h>I?\xc7q\xbeZs\xcb0\xfa\x06'
# header = message_header.parse_header(test[0:8])
# print(calculate_item_count(header.ext))

# test = b'\x1c\x07\x15\xe7\xee\xbd/\x85'
# print(len(test))

# test = b'H\xab)L\xec\xbdE\x87\xf3\x15\x04I\xa6h@\x86\xaa\xb7\xdf\xd6\xfbb\x88{\x8c/^\xa0Bk\x98\xbb'
# print(len(test))

# --------------------------------------------- End of Analysis Code ---------------------------------------------

ctx = livectx
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
s.connect((peeraddr, ctx['peerport']))
s.settimeout(3)

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
