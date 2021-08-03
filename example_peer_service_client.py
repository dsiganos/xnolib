import socket
import sys
import jsonpickle

from peercrawler import get_peers_from_service

peers = get_peers_from_service()
for p in peers:
    print(p)
