from deserialisng import message_header, message_type

class message:
    def __init__(self, network_id, type):
        self.network_id = network_id
        self.message_type = type
        self.serialise_header()

    def serialise_header(self):
        header = b""
        header += ord('R').to_bytes(1, "big")
        header += ord(self.network_id).to_bytes(1, "big")
        for i in range(0, 3):
            header += (34).to_bytes(1, "big")
        header += self.message_type.to_bytes(1, "big")
        header += (00).to_bytes(1, "big")
        header += (00).to_bytes(1, "big")
        return header

    def serialise_peers(self):
        pass

m = message('A', 2)
h = message_header(m.serialise_header())
print(h)

