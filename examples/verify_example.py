from ed25519_blake2b import VerifyingKey
import binascii

pubkeyhex = 'AC7B5798039E8AE7259C6A5018014C967F59DE47C19F4CCDC93CD3F819F8B4D5'
pubkey = VerifyingKey(binascii.unhexlify(pubkeyhex))

msghex = '5050505050505050505050505050505050505050505050505050505050505050'
msg = binascii.unhexlify(msghex)

sighex  = '4E033958AC33D0D45294F18CF81BCD22A1172CD06EB09563431004CBCC887B39'
sighex += 'AEA896F780005CA3684D313ADA34DCE1D53585ACC246C483A2DD2A9CD8D2F309'
sig = binascii.unhexlify(sighex)

try:
    pubkey.verify(sig, msg)
    print("SUCCESS!")
except:
    print("Invalid signature!")
