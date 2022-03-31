#!/bin/env python3

import hashlib
import os

epoch1_threshold = 0xffffffc000000000
epoch2_threshold_high = 0xfffffff800000000
epoch2_threshold_low  = 0xfffffe0000000000


# return a random 8-byte nonce as an integer
def random_nonce():
    nonce_bytes = os.urandom(8)
    return int.from_bytes(nonce_bytes, "little")


# take a nonce (8 byte unsigned int) and a root (32 byte unsigned int) and produce
# blake2b(nonce + root), which is a hash of the nonce and the root
# the output hash is an 8 byte unsigned integer
def generate_pow_hash(nonce, root):
    alg = hashlib.blake2b(digest_size=8)
    alg.update(nonce.to_bytes(8, byteorder='little'))
    alg.update(root.to_bytes(32, byteorder='big'))
    return int.from_bytes(alg.digest(), byteorder='little')


def find_pow_for_root_and_difficulty(root, target_difficulty):
    nonce = random_nonce()
    difficulty = generate_pow_hash(nonce, root)
    while difficulty < target_difficulty:
        nonce = random_nonce()
        difficulty = generate_pow_hash(nonce, root)
    return nonce


#
# check genesis block
#

genesis_root     = 0xE89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA
genesis_pow      = 0x62F05417DD3FB691
digest = generate_pow_hash(genesis_pow, genesis_root)
print(hex(digest))
print(hex(epoch1_threshold))
print(digest >= epoch1_threshold)


#
# check first epoch block of genesis account
#

root = 0xECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113
pow1 = 0x0F78168D5B30191D
digest = generate_pow_hash(pow1, root)
print(hex(digest))
print(hex(epoch1_threshold))
print(digest >= epoch1_threshold)


#
# check second epoch block of genesis account
#

root = 0x6875C0DBFE5C44D8F8CFF431BC69ED5587C68F89F0663F2BC1FBBFCB46DC5989
pow2 = 0x494DBB4E8BD688AA
digest = generate_pow_hash(pow2, root)
print(hex(digest))
print(hex(epoch2_threshold_low))
print(digest >= epoch2_threshold_low)
