import socket
import random

from nanolib import *


ctx = livectx
s = get_initial_connected_socket()

perform_handshake_exchange(s)
