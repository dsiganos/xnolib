from pynanocoin import *

class msg_publish:
    def __init__(self, hdr, block):
        assert(isinstance(hdr, message_header))
        self.hdr = hdr
        self.block = block

    def serialise(self):
        data = self.hdr.serialise_header()
        data += self.block.serialise(True)
        return data


header = message_header(network_id(66), [18, 18, 18], message_type(3), 0)

example_block_send = {
    "prev" : binascii.unhexlify('4A039AD482C917C266A3D4A2C97849CE69173B6BC775AFC779B9EA5CE446426F'),
    "dest" : binascii.unhexlify('42DD308BA91AA225B9DD0EF15A68A8DD49E2940C6277A4BFAC363E1C8BF14279'),
    "bal" : 100,
    "sig" : binascii.unhexlify('30A5850305AA61185008D4A732AA8527682D239D85457368B6A581F517D5F8C0078DB99B5741B79CC29880387292B64F668C964BE1B50790D3EC7D948396D007'),
    "work" : binascii.unhexlify('EDFD7157025EA461')
}
block = block_send(example_block_send["prev"], example_block_send["dest"], example_block_send["bal"],
                   example_block_send["sig"], example_block_send["work"])
msg = msg_publish(header, block)

s, _ = get_initial_connected_socket(betactx)
with s:
    s.send(msg.serialise())
    print(s.recv(1000))
