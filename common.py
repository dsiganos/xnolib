import binascii
import re
from typing import Tuple


def writefile(filename, content) -> None:
    with open(filename, "w") as f:
        f.write(content)


def hexlify(data) -> str:
    if data is None: return 'None'
    return binascii.hexlify(data).decode("utf-8").upper()


def extract_ip_and_port_from_ipv6_address(address: str) -> Tuple[str, int]:
    """Extract the IP and port from an IPv6 address such as \"[::ffff:1.2.3.4]:7075\"."""
    ip_address = re.search(r"(?<=\[)(.*?)(?=\])", address).group(0)
    port = int(address.split(":")[-1])

    return ip_address, port


class hash_pair:
    def __init__(self, hsh, root):
        assert len(hsh) == 32 and len(root) == 32
        self.hsh = hsh
        self.root = root

    def __str__(self):
        string =  "  Hash: %s\n" % hexlify(self.hsh)
        string += "  Root: %s\n" % hexlify(self.root)
        return string

    def serialise(self) -> bytes:
        return self.hsh + self.root

    @classmethod
    def parse(self, data):
        assert len(data) == 64
        return hash_pair(data[0:32], data[32:64])
