import binascii
import base64
import hashlib

accounts = {
    'nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3' : 'Genesis',
    'nano_13ezf4od79h1tgj9aiu4djzcmmguendtjfuhwfukhuucboua8cpoihmh8byo' : 'Landing',
    'nano_35jjmmmh81kydepzeuf9oec8hzkay7msr6yxagzxpcht7thwa5bus5tomgz9' : 'Faucet',
    'nano_1111111111111111111111111111111111111111111111111111hifc8npp' : 'Burn',
    'nano_1betagoxpxwykx4kw86dnhosc8t3s7ix8eeentwkcg1hbpez1outjrcyg4n1' : 'BetaGenesis',
    'nano_1jg8zygjg3pp5w644emqcbmjqpnzmubfni3kfe1s8pooeuxsw49fdq1mco9j' : 'TestGenesis',
    'nano_1ipx847tk8o46pwxt5qjdbncjqcbwcc1rrmqnkztrfjy5k7z4imsrata9est' : 'DevFund',

    'nano_1awsn43we17c1oshdru4azeqjz9wii41dy8npubm4rg11so7dx3jtqgoeahy' : 'NF6',

    'nano_31xitw55kb3ko8yaz3439hqaqpibxa9shx76suaa3no786do3hjuz8dy6izw' : 'Nano.lol',
    'nano_3jwrszth46rk1mu7rmb4rhm54us8yg1gw3ipodftqtikf5yqdyr7471nsg1k' : 'Binance Hot Wallet',
    'nano_17oc98sqccfqqfah8jggkziu8i6ar8biq7syxqcd6e1sagje11gts88gfj95' : 'Binance US Hot Wallet',
    'nano_3x4ui45q1cw8hydmfdn4ec5ijsdqi4ryp14g4ayh71jcdkwmddrq7ca9xzn9' : 'Binance Cold Wallet',
    'nano_14cuejfpr58epnpxenirusimsrbwxbecin7a3izq1injptecc31qsjwquoe6' : 'Binance Cold Wallet #2',
    'nano_3cpz7oh9qr5b7obbcb5867omqf8esix4sdd5w6mh8kkknamjgbnwrimxsaaf' : 'Kraken Hot Wallet',
    'nano_3hua6a116y4jmbeaf63zi6mn8gf5s4n3eyxa3q4m5ibabi6pmegfubky3wpi' : 'KuCoin Hot Wallet',
    'nano_1c3nz77f3t5bz346je4bwtcfxgfnp6habs9to4utfeuhjfpxdhkd593kn5gn' : 'KuCoin Cold Wallet',
    'nano_1oxho99gkeczaweapwfkoqq465c1apr4fq5qmnmrwb3u5cjebq5rctqqikhf' : 'Huobi Hot Wallet',
    'nano_1kiw5p5kfsypbf5cjhrmbkq5xjrufhjawaz1i691yw4tfsn14ssjx64orfdb' : 'Huobi Cold Wallet',
    'nano_3jyt9ye4yerydg91twwgxo7edke84a7cbjtomq4bg7uh5anqwiture4h1saa' : 'Huobi Hot Wallet #2',
    'nano_1e3t7fh57qozn1fkcdzatypygbcoxs9r3ku9tsqx69fn5za4fqfjrihf5w7c' : 'Mercatox Cold Wallet',
    'nano_1b9wguhh39at8qtm93oghd6r4f4ubk7zmqc9oi5ape6yyz4s1gamuwn3jjit' : '465 Digital Investments - Node 1',
    'nano_1niabkx3gbxit5j5yyqcpas71dkffggbr6zpd3heui8rpoocm5xqbdwq44oh' : 'KuCoin',
    'nano_3robocazheuxet5ju1gtif4cefkhfbupkykc97hfanof859ie9ajpdfhy3ez' : 'RoboCash DBA FynCom',
    'nano_1aoxwfsmu6wazes9jq4xu695jx5txa3qrrfsrg4w4uk35bhmxkn378fwebng' : '1.NANONODE.FR',
    'nano_3rw4un6ys57hrb39sy1qx8qy5wukst1iiponztrz9qiz6qqa55kxzx4491or' : 'NanoVault',
    'nano_3uip1jmeo4irjuua9xiyosq6fkgogwd6bf5uqopb1m6mfq6g3n8cna6h3tuk' : 'BitGrail Trustee'
}


# this function expects account to be a 32 byte bytearray
def to_account_addr(account: bytes, prefix: str = 'nano_') -> str:
    assert (len(account) == 32)

    RFC_3548 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    ENCODING = b"13456789abcdefghijkmnopqrstuwxyz"

    h = hashlib.blake2b(digest_size=5)
    h.update(account)
    checksum = h.digest()

    # prefix account to make it even length for base32, add checksum in reverse byte order
    account2 = b'\x00\x00\x00' + account + checksum[::-1]

    # use the optimized base32 lib to speed this up
    encode_account = base64.b32encode(account2)

    # simply translate the result from RFC3548 to Nano's encoding, snip off the leading useless bytes
    encode_account = encode_account.translate(bytes.maketrans(RFC_3548, ENCODING))[4:]

    # add prefix, label and return
    return prefix + encode_account.decode()


def account_key(account: str) -> bytes:
    """Get the public key for account
    :param str account: account name e.g. nano_31fr1qtbrfnujcspx5xq61uxgjf9j6rzckdj1kdn61y3h53nxr7911dzetk3
    :return: 32 byte public key
    :rtype: bytes
    :raise AssertionError: for invalid account
    """
    account_prefix = "nano_"
    _B32 = b"13456789abcdefghijkmnopqrstuwxyz"
    assert (
        len(account) == len(account_prefix) + 60
        and account[: len(account_prefix)] == account_prefix
    )

    account = b"1111" + account[-60:].encode()
    account = account.translate(bytes.maketrans(_B32, base64._b32alphabet))
    key = base64.b32decode(account)

    checksum = key[:-6:-1]
    key = key[3:-5]

    assert hashlib.blake2b(key, digest_size=5).digest() == checksum

    return key


def to_friendly_name(acc: bytes) -> str:
    if len(acc) == 32:
        addr = to_account_addr(acc)
    elif len(acc) == 64:
        addr = to_account_addr(binascii.unhexlify(acc))
    else:
        addr = acc
    return accounts.get(addr, '')
