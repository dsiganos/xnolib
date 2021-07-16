#!/bin/env python3
import random
import socket

from nanolib import *

ctx = livectx
s = get_initial_connected_socket()

blocks = get_account_blocks(s, ctx["genesis_pub"])

manager = blocks_manager()
while len(blocks) != 0:
    block = blocks.pop()
    manager.process(block)

print(manager)
print(manager.accounts[0])
print(manager.accounts[0].str_blocks())

