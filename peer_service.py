import socket
import jsonpickle

from peercrawler import spawn_peer_crawler_thread
from pynanocoin import livectx


def listen_to_conn(conn):
    while True:
        try:
            data = conn.recv(1)
            return data
        except socket.timeout:
            continue


def get_json_peers(peerman):
    return jsonpickle.encode(peerman.peers)

# Run this code before running the example_peer_service_client.py


crawler_thread = spawn_peer_crawler_thread(livectx, True, 0)
peerman = crawler_thread.peerman

s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.bind(('::ffff:127.0.0.1', 12345))
s.listen()
conn, addr = s.accept()
conn.settimeout(5)

while True:
    req = listen_to_conn(conn)
    if int.from_bytes(req, "big") == 1:
        json_list = get_json_peers(peerman)
        conn.send(json_list.encode())
