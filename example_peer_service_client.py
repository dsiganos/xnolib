import socket
import sys
import jsonpickle

from peercrawler import get_all_peers

peers = get_all_peers()
for p in peers:
    print(p)
