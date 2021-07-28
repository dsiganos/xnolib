import socket
import jsonpickle

from peercrawler import spawn_peer_crawler_thread
from pynanocoin import livectx


crawler_thread = spawn_peer_crawler_thread(livectx, True, 0)
peerman = crawler_thread.peerman

s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.bind(('::ffff:127.0.0.1', 12345))
s.listen()

while True:
    conn, addr = s.accept()
    conn.settimeout(5)
    json_list = jsonpickle.encode(peerman.get_peers_copy())
    conn.send(json_list.encode())
    conn.close()
