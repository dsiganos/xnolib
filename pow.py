#!/usr/bin/env python3

import hashlib
import os
import argparse


epoch1_threshold = 0xffffffc000000000
epoch2_threshold_high = 0xfffffff800000000
epoch2_threshold_low  = 0xfffffe0000000000


# return a random 8-byte nonce as an integer
def random_nonce() -> int:
    nonce_bytes = os.urandom(8)
    return int.from_bytes(nonce_bytes, 'little')


# Return the calculated difficulty for a root and nonce
# take a nonce (8 byte unsigned int) and a root (32 byte unsigned int) and produce
# blake2b(nonce + root), which is a hash of the nonce and the root
# the output hash is an 8 byte unsigned integer (calculated difficulty)
def generate_pow_hash(nonce: int, root: int) -> int:
    alg = hashlib.blake2b(digest_size=8)
    alg.update(nonce.to_bytes(8, byteorder='little'))
    alg.update(root.to_bytes(32, byteorder='big'))
    return int.from_bytes(alg.digest(), byteorder='little')


# returns a nonce that satisfies the difficulty contraint
def generate_pow_for_root_and_difficulty(root: int, target_difficulty: int) -> int:
    nonce = random_nonce()
    difficulty = generate_pow_hash(nonce, root)
    while difficulty < target_difficulty:
        nonce = random_nonce()
        difficulty = generate_pow_hash(nonce, root)
    return nonce


def verify_pow_for_root_and_difficulty(root: int, target_difficulty: int, work : int) -> int:
    digest = generate_pow_hash(work, root)
    return digest >= target_difficulty


def calculate_multiplier(base_diff: int, diff) -> int:
    return (2**64 - args.difficulty) / (2**64 - calculated_diff)


def parse_int(val):
    return int(val, 16) if val.startswith('0x') else int(val)


def parse_args():
    parser = argparse.ArgumentParser(description='Accept arguments for verify or generate mode.')
    subparsers = parser.add_subparsers(dest='mode', help='Mode selection')

    verify_parser = subparsers.add_parser('verify', help='Verify mode')
    verify_parser.add_argument('root', type=parse_int, help='Root value (decimal or hexadecimal)')
    verify_parser.add_argument('difficulty', type=parse_int, help='Target difficulty value (decimal or hexadecimal)')
    verify_parser.add_argument('work', type=parse_int, help='Work value (decimal or hexadecimal)')

    generate_parser = subparsers.add_parser('generate', help='Generate mode')
    generate_parser.add_argument('root', type=parse_int, help='Root value (decimal or hexadecimal)')
    generate_parser.add_argument('difficulty', type=parse_int, help='Target difficulty value (decimal or hexadecimal)')

    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = parse_args()

    if args.mode == 'verify':
        print('Work:', args.work)
        print('Root:', args.root)
        print('Difficulty:', args.difficulty)

        calculated_diff = generate_pow_hash(args.work, args.root)
        print(f'Calculated difficulty : 0x{calculated_diff:08X}')
        print(f'Target difficulty     : 0x{args.difficulty:08X}')
        mult = calculate_multiplier(args.difficulty, calculated_diff)
        print(f'Multiplier            : {mult}')
        print('Verify: %s' % (calculated_diff >= args.difficulty))

    if args.mode == 'generate':
        print(f'Root: {args.root:032X}')
        print(f'Target Difficulty  : 0x{args.difficulty:08X}')
        nonce = generate_pow_for_root_and_difficulty(args.root, args.difficulty)
        calculated_diff = generate_pow_hash(nonce, args.root)
        print(f'       Difficulty  : 0x{calculated_diff:08X}')
        print(f'Generated POW nonce: 0x{nonce:08X}')
        mult = calculate_multiplier(args.difficulty, calculated_diff)
        print(f'Multiplier         : {mult}')
        assert verify_pow_for_root_and_difficulty(args.root, args.difficulty, nonce)
