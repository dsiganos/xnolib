import socket
import random

from pynanocoin import *


ctx = livectx
s, _ = get_initial_connected_socket(ctx)
assert s

perform_handshake_exchange(ctx, s)
