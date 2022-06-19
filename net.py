import ipaddress
import socket

from common import *
from exceptions import *


def read_socket(sock: socket.socket, byte_count: int) -> bytes or None:
    try:
        data = bytearray()
        while len(data) < byte_count:
            data += sock.recv(1)
            if len(data) == 0:
                raise SocketClosedByPeer('read_socket: data=%s' % data)

        return bytes(data)

    except OSError as msg:
        print('read_socket] Error reading %d bytes, data=%s, msg=%s' % (byte_count, hexlify(data), msg))
        return None


def parse_ipv6(data: bytes) -> ipaddress.IPv6Address:
    if len(data) != 16:
        raise ParseErrorBadIPv6()
    return ipaddress.IPv6Address(data)
