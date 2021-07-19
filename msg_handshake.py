import socket
import random

from nanolib import *


ctx = livectx
s = get_initial_connected_socket(ctx)
assert s

perform_handshake_exchange(s)
