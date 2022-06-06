import ipaddress
import socket

from common import *
from exceptions import *


def read_socket(socket: socket.socket, numbytes: int):
    try:
        data = bytearray()
        while len(data) < byte_count:
            data += sock.recv(1)
            if len(data) == 0:
                raise SocketClosedByPeer('read_socket: data=%s' % data)

        return bytes(data)

    except OSError as msg:
        print('read_socket] Error whilst reading %d bytes' % byte_count)
        print('  %s bytes in buffer: %s "%s"' % (len(data), hexlify(data), data))
        print(msg)
        return None


def parse_ipv6(data: bytes):
    if len(data) != 16:
        raise ParseErrorBadIPv6()
    return ipaddress.IPv6Address(data)
