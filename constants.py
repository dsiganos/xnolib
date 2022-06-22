import binascii

import common

max_nano_supply = 133248298 * (10**30)
genesis_hash_pair_str = common.hash_pair(
            binascii.unhexlify('991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948'),
            binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA'))