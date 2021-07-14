#!/bin/env python3
import time
import socket
import random

from nanolib import *


def get_next_hdr_payload():
    # read and parse header
    data = read_socket(s, 8)
    if data is None:
        raise CommsError()
    header = message_header.parse_header(data)

    # we can determine the size of the payload from the header
    size = header.payload_length_bytes()

    # read and parse payload
    data = read_socket(s, size)
    return header, data


ctx = livectx
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
s.settimeout(3)
s.connect((peeraddr, ctx['peerport']))

perform_handshake_exchange(s)

# send a keepalive, this is not necessary, just doing it as an example
hdr = message_header(ctx['net_id'], [18, 18, 18], message_type(message_type_enum.keepalive), 0)
keepalive = message_keepalive(hdr)
req = keepalive.serialise()
s.send(req)

# now we are waiting for keepalives, so set a long timeout (60 minutes)
s.settimeout(60 * 60)

while True:
    hdr, payload = get_next_hdr_payload()
    if hdr.msg_type == message_type(message_type_enum.keepalive):
        keepalive = message_keepalive.parse_payload(hdr, payload)
        print(keepalive)
    else:
        print(hdr)
