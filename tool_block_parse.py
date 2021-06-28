import sys
from pyblake2 import blake2b
import ed25519_blake2
from bitstring import BitArray


if len(sys.argv) > 1:
    block = bytes.fromhex(sys.argv[1])
else:
    block = bytes.fromhex('e89208dd038fbb269987689621d52292ae9c35941a7484756ecced92a65093baeccb8cb65cd3106eda8ce9aa893fead497a91bca903890cbd7a5c59f06ab9113e89208dd038fbb269987689621d52292ae9c35941a7484756ecced92a65093ba000000041c06df91d202b70a4000001165706f636820763120626c6f636b00000000000000000000000000000000000057bfe93f4675fc16df0ccfc7ee4f78cc68047b5c14e2e2eed243f17348d8bab3cca04f8cbc2d291b4ddec5f7a74c1be1e872df78d560c46365eb15270a1d12010f78168d5b30191d')

def account_xrb(account):
	# Given a string containing a hex address, encode to public address format with checksum
	account_map = "13456789abcdefghijkmnopqrstuwxyz"					# each index = binary value, account_lookup['00001'] == '3'
	account_lookup = {}
	for i in range(0,32):												# populate lookup index for binary string to base-32 string character
		account_lookup[BitArray(uint=i,length=5).bin] = account_map[i]

	account = BitArray(hex=account)										# hex string > binary

	# get checksum
	h = blake2b(digest_size=5)
	h.update(account.bytes)
	checksum = BitArray(hex=h.hexdigest())

	# encode checksum
	checksum.byteswap()													# swap bytes for compatibility with original implementation
	encode_check = ''
	for x in range(0,int(len(checksum.bin)/5)):
			encode_check += account_lookup[checksum.bin[x*5:x*5+5]]		# each 5-bit sequence = a base-32 character from account_map

	# encode account
	encode_account = ''
	while len(account.bin) < 260:										# pad our binary value so it is 260 bits long before conversion (first value can only be 00000 '1' or 00001 '3')
		account = '0b0' + account
	for x in range(0,int(len(account.bin)/5)):
			encode_account += account_lookup[account.bin[x*5:x*5+5]]	# each 5-bit sequence = a base-32 character from account_map

	return 'xrb_'+encode_account+encode_check							# build final address string

def verify(message,signature,public_key):
    try:
        ed25519_blake2.checkvalid(signature, message, public_key)
    except ed25519_blake2.SignatureMismatch:
        return False
    return True

def pow_threshold(check):
	if check > b'\xFF\xFF\xFF\xC0\x00\x00\x00\x00': return True
	else: return False

def pow_validate(pow, hash):
	pow_data = bytearray.fromhex(pow)
	hash_data = bytearray.fromhex(hash)
	h = blake2b(digest_size=8)
	pow_data.reverse()
	h.update(pow_data)
	h.update(hash_data)
	final = bytearray(h.digest())
	final.reverse()
	return pow_threshold(final)

# just state block for now
if len(block) == 216:
	print('State Block')
	bh = blake2b(digest_size=32)
	bh.update((b'\x00'*31)+b'\x06')
	bh.update(block[0:144])
	hash = bh.hexdigest().upper()
	print('Hash:     {}'.format(hash))
	print('Account:  {}'.format(account_xrb(block[0:32].hex())))
	print('Previous: {}'.format(block[32:64].hex().upper()))
	print('Rep:      {}'.format(account_xrb(block[64:96].hex())))
	print('Balance:  {}'.format(int(block[96:112].hex(),16)))
	print('Link:     {}'.format(block[112:144].hex().upper()))
	print('Sig:      {} Valid: {}'.format(block[144:208].hex().upper(),verify(bytes.fromhex(hash),\
                                                                                  block[144:208],\
                                                                                  block[0:32])))
	print('Work:     {} Valid: {}'.format(block[208:216].hex().upper(),pow_validate(block[208:216].hex(),block[32:64].hex())))
	print('Work Inv: {} Valid: {}'.format(block[208:216][::-1].hex().upper(),pow_validate(block[208:216][::-1].hex(),block[32:64].hex())))



