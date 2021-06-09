import binascii


class parsing_hexdump:
    network_id = -1
    version_max = -1
    version_using = -1
    version_min = -1
    message_type = -1
    extensions = []

    def __init__(self, hexdump):
        self.hexdump = hexdump
        self.parse_header()

    def parse_header(self):
        parsing_hexdump.network_id = self.hexdump[1]
        parsing_hexdump.version_max = self.hexdump[2]
        parsing_hexdump.version_using = self.hexdump[3]
        parsing_hexdump.version_min = self.hexdump[4]
        parsing_hexdump.message_type = self.hexdump[5]
        parsing_hexdump.extensions.append(self.hexdump[6])
        parsing_hexdump.extensions.append(self.hexdump[7])


    def display_header(self):
        print("Network ID: {}".format(parsing_hexdump.network_id))
        print("Version Max: {}".format(parsing_hexdump.version_max))
        print("Version Using: {}".format(parsing_hexdump.version_using))
        print("Version Min: {}".format(parsing_hexdump.version_min))
        print("Message Type: {}".format(parsing_hexdump.message_type))
        print("Extensions: {} {}".format(parsing_hexdump.extensions[0], parsing_hexdump.extensions[1]))


input_stream = "524212121202000000000000000000000000ffff9df5d11ef0d200000000000000000000ffff18fb4f64f0d200000000000000000000ffff405a48c2f0d200000000000000000000ffff95382eecf0d200000000000000000000ffff2e044970f0d200000000000000000000ffff68cdcd53f0d200000000000000000000ffffb3a2bdeff0d200000000000000000000ffff74ca6b61f0d2"
h = parsing_hexdump(binascii.unhexlify(input_stream))
h.display_header()
