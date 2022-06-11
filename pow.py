import hashlib
import os


epoch1_threshold = 0xffffffc000000000
epoch2_threshold_high = 0xfffffff800000000
epoch2_threshold_low  = 0xfffffe0000000000


# return a random 8-byte nonce as an integer
def random_nonce() -> int:
    nonce_bytes = os.urandom(8)
    return int.from_bytes(nonce_bytes, "little")


# take a nonce (8 byte unsigned int) and a root (32 byte unsigned int) and produce
# blake2b(nonce + root), which is a hash of the nonce and the root
# the output hash is an 8 byte unsigned integer
def generate_pow_hash(nonce: int, root: int) -> int:
    alg = hashlib.blake2b(digest_size=8)
    alg.update(nonce.to_bytes(8, byteorder='little'))
    alg.update(root.to_bytes(32, byteorder='big'))
    return int.from_bytes(alg.digest(), byteorder='little')


def find_pow_for_root_and_difficulty(root: int, target_difficulty: int) -> int:
    nonce = random_nonce()
    difficulty = generate_pow_hash(nonce, root)
    while difficulty < target_difficulty:
        nonce = random_nonce()
        difficulty = generate_pow_hash(nonce, root)
    return nonce
