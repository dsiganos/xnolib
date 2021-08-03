#!/bin/env python3
import random
import socket

from pynanocoin import *

ctx = livectx
s, _ = get_initial_connected_socket(ctx)
assert s

blocks = get_account_blocks(s, ctx["genesis_pub"])

manager = block_manager(None, None)
while len(blocks) != 0:
    block = blocks.pop()
    manager.process(block)

print(manager)
print(manager.accounts[0])
print(manager.accounts[0].str_blocks())

