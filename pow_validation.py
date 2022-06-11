from block import *
import pow


def validate_pow(block, post_v2: bool = True) -> bool:
    if not post_v2:
        difficulty = pow.epoch1_threshold
    else:
        difficulty = get_blocks_difficulty(block)
    digest = pow.generate_pow_hash(block.work, int.from_bytes(block.root(), "big"))
    return digest >= difficulty


def get_blocks_difficulty(block) -> int:
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
