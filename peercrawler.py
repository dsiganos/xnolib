from nanolib import *

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

def clear_until_keepalive(data):


ctx = livectx
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
s.connect((peeraddr, ctx['peerport']))
s.settimeout(3)

# test_data = b'RC\x12\x12\x12\x05\x001\xbdbg\xd6\xec\xd8\x03\x83\'\xd2\xbc\xc0\x85\x0b\xdf\x8fV\xec\x04\x14\x91"\x07\xe8\x1b\xcf\x90\xdf\xac\x8aJ\xaa\x15#\x98T\x8d6\xbf\\ \x03G\x87\x14L\x0e"\'\xd2H\x17\xb9\xd8k\x9a\xefKe\xdb\xe1\xd2.\n?h.\xf1\xbc[\x8d\xf1a\xdd\xdc\x14\\\xdf\x9a\\\xff\x9f\xbc EL\xa8\xc2\xda\x9f=Iep\xa6\x06\xff\xff\xff\xff\xff\xff\xff\xff^LeT\x05d\x86\x0f\xb2;8\x9aL%c|\xa5\x98b\xc1\x8c\xda\xc2Z\xe5\xd2yu\x85\xceY\t{\x91\xdax\x96\x9d\xc7\x01\xf9\xd8m\\\xfab:\xb8\xa1%V\xbd\x11\xe5RyE\xa2\xac{k"\x800>UK%\x9d8\x9aR\x90\xe6\x1c\x11D\x9b\xe1\xacd\x05"h>I?\xc7q\xbeZs\xcb0\xfa\x06'
# print(len(test_data))
# test_data2 = b'RC\x12\x12\x12\x05\x00\x11#\x99\xa0\x83\xc6\x00\xaa\x05r\xf5\xe3bG\xd9x\xfc\xfc\x84\x04\x05\xf8\xd4\xb6\xd31a\xc0\x06jU\xf411\xf8!\x10\xc5>\x84\x9f\x18\xc6\xca\x04\xad1\x94*7<c\x0cK\x9b9P\xdbn\xff\x19\xbbI\xe2\x11\x12\xb5\'\xea\xdc"\xe0\x97\xf0\xda\xb6\xbb\xeb\x9a\xa7\xc3$XVZ\xaf\x98(\xdb\x8b\xd33\x13Z\'y\x0f\xff\xff\xff\xff\xff\xff\xff\xff7K\x8b\xb9\xf8\xe0\xbb\xedRi\x14\xf3lt\x19\xdaS\xe8\xce\xa4\xee\xcf\x8c\x98\x9c\x87\xb7\x1e\x05\x8a\x0c\x96'
# print(len(test_data2))
# test_data = b'RC\x12\x12\x12\x04\x00\x11)\x9aH\xf1\x8e\x9bUa\xa3\xf2\xcd\x91\x05\xd6K[\x9d\x96tH\x16\x87\xac|\x96t\x02y\xd3\xa3\x84d\xd3\xc0\xfd\x8f\x14\x12\x0bG>_{a\xf5\x8c\xa4\x13\x11\x14\x9b\xc4\xf2\xd0\xd5\xf9\x9f^UG\x85)\xcf\xf3'
# print(len(test_data))
perform_handshake_exchange(s)
s.send(message_keepalive().serialise())
data = read_socket(s, 8)
header = message_header.parse_header(data)
print(calculate_item_count(header.ext))

# read_socket(s, 72)
# data = read_socket(s, 152)
# print(message_header.parse_header(data[0:8]))
# manager = peer_manager()
# manager.parse_and_add_peers(data[8:])
# for p in manager.peers:
#     print(str(p))
# print("stop")
