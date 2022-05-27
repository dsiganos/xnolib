import pow
from block import *
from peercrawler import *


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



livectx = {
    'net_id': network_id(ord('C')),
    'peeraddr': "peering.nano.org",
    'peerport': 7075,
    'peercrawlerport': 7070,
    'genesis_pub': 'E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA',
    'another_pub': '059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5',
    'random_block': '6E5404423E7DDD30A0287312EC79DFF5B2841EADCD5082B9A035BCD5DB4301B6',
    'epoch_v2_signing_account': 'dd24a9200d4bf8247981e4ac63dbde38fd2319386970a26d02ecc98c79975db1',
    'genesis_block': live_genesis_block
}


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

