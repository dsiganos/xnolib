
class parsing_hexdump:
    network_id = ""
    version_max = ""
    version_using = ""
    version_min = ""
    message_type = ""
    extensions = []

    def __init__(self, hexdump):
        self.original_hexdump = hexdump
        self.working_hexdump = hexdump
        self.parse_header()

    def parse_header(self):
        for i in range(0, 8):
            attribute = self.working_hexdump[:2]
            self.working_hexdump = self.working_hexdump[2:]
            if (i == 1):
                parsing_hexdump.network_id = attribute
            elif (i == 2):
                parsing_hexdump.version_max = attribute
            elif(i == 3) :
                parsing_hexdump.version_using = attribute
            elif(i == 4):
                parsing_hexdump.version_min = attribute
            elif (i == 5):
                parsing_hexdump.message_type = attribute
            elif(i == 6 or i == 7):
                parsing_hexdump.extensions.append(attribute)


    def display_header(self):
        print("Network ID: {}".format(parsing_hexdump.network_id))
        print("Version Max: {}".format(parsing_hexdump.version_max))
        print("Version Using: {}".format(parsing_hexdump.version_using))
        print("Version Min: {}".format(parsing_hexdump.version_min))
        print("Message Type: {}".format(parsing_hexdump.message_type))
        print("Extensions: {} {}".format(parsing_hexdump.extensions[0], parsing_hexdump.extensions[1]))


h = parsing_hexdump("524212121202000000000000000000000000ffff9df5d11ef0d200000000000000000000ffff18fb4f64f0d200000000000000000000ffff405a48c2f0d200000000000000000000ffff95382eecf0d200000000000000000000ffff2e044970f0d200000000000000000000ffff68cdcd53f0d200000000000000000000ffffb3a2bdeff0d200000000000000000000ffff74ca6b61f0d2")
h.display_header()
