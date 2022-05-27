import pow
from block import *
from peercrawler import *
from pynanocoin import livectx


def validate_pow(block, post_v2=True):
    if not post_v2:
        difficulty = pow.epoch1_threshold
    else:
        difficulty = get_blocks_difficulty(block)

    # Here, if I change int.from_bytes(block.work, "little") to "big" it works
    digest = pow.generate_pow_hash(int.from_bytes(block.work, "little"), int.from_bytes(block.root(), "big"))
    return digest >= difficulty


def get_blocks_difficulty(block):
    difficulty_level = None
    if isinstance(block, block_state):

        # Need to determine a block states type before validating POW
        if block.ancillary["type"] == block_type_enum.not_a_block:
            raise Exception("State blocks type needs to be determined")
        elif block.ancillary["type"] == block_type_enum.send or block.ancillary["type"] == block_type_enum.change:
            return pow.epoch2_threshold_high
        elif block.ancillary["type"] == block_type_enum.open or block.ancillary["type"] == block_type_enum.receive:
            return pow.epoch2_threshold_low
        else:
            assert False
    else:
        if isinstance(block, block_send) or isinstance(block, block_change):
            return pow.epoch2_threshold_high
        elif isinstance(block, block_receive) or isinstance(block, block_open):
            return pow.epoch2_threshold_low


ctx = livectx
s, _ = get_initial_connected_socket(ctx)
blocks = get_account_blocks(ctx, s, ctx['genesis_pub'])
block = blocks[0]
block.set_type(block_type_enum.open)
print(block)
print("")
print("POW Little: %d" % int.from_bytes(block.work, "little"))
print("POW Big: %d" % int.from_bytes(block.work, "big"))
print("Valid POW: %s" % validate_pow(block))

