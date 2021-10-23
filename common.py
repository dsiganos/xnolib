import binascii

def writefile(filename, content):
    with open(filename, "w") as f:
        f.write(content)


def hexlify(data):
    if data is None: return 'None'
    return binascii.hexlify(data).decode("utf-8").upper()
