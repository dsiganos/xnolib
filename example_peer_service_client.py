import socket
import sys

import jsonpickle


def get_socket_response(s):
    data = b''
    while True:
        try:
            data += s.recv(1)
        except socket.timeout:
            if len(data) > 0:
                return data
            else:
                print("failure")
                return None


s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.connect(('::ffff:127.0.0.1', 12345))

s.settimeout(10)
count = 0

# The program will pull peers from the peer_service a number of times (depending on loop condition)
# You need to rerun the peer_service after this program finishes to attempt again

while count != 3:
    s.send((1).to_bytes(1, "big"))
    resp = get_socket_response(s)
    print(resp)
    if resp is None:
        sys.exit(0)
    my_list = jsonpickle.decode(resp)
    for p in my_list:
        print(p)
    print("Count is %d" % count)
    count += 1