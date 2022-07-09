import ipaddress
import socket
from typing import Optional

from _logger import get_logger, VERBOSE
from exceptions import ParseErrorBadIPv6, SocketClosedByPeer


logger = get_logger()


def read_socket(sock: socket.socket, byte_count: int) -> Optional[bytes]:  # ideally this should either raise or return None, not both
    data = bytearray()
    while len(data) < byte_count:
        try:
            data.extend(sock.recv(byte_count - len(data)))
        except OSError:
            logger.log(VERBOSE, f"Error while reading {byte_count} bytes", exc_info=True)
            return None

        if len(data) == 0:
            raise SocketClosedByPeer('read_socket: data=%s' % data)

    return bytes(data)


def parse_ipv6(data: bytes) -> ipaddress.IPv6Address:
    if len(data) != 16:
        raise ParseErrorBadIPv6()
    return ipaddress.IPv6Address(data)
