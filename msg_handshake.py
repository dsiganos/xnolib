from __future__ import annotations

from pynanocoin import *


class node_handshake_id:
    @classmethod
    def parse(cls, hdr: message_header, payload: bytes):
        if hdr.is_query() and hdr.is_response():
            handshake = handshake_response_query.parse_query_response(hdr, payload)
        elif hdr.is_query():
            handshake = handshake_query.parse_query(hdr, payload)
        elif hdr.is_response():
            handshake = handshake_response.parse_response(hdr, payload)
        return handshake

    @classmethod
    def keypair(cls) -> tuple[ed25519_blake2b.SigningKey, ed25519_blake2b.VerifyingKey]:
        return ed25519_blake2b.create_keypair()

    @classmethod
    def perform_handshake_exchange(cls, ctx: dict, s: socket.socket,
                                   signing_key: ed25519_blake2b.SigningKey,
                                   verifying_key: ed25519_blake2b.VerifyingKey) -> bytes:
        hdr = message_header(ctx['net_id'], [20, 20, 18], message_type(10), 5)
        msg_handshake = handshake_query(ctx, hdr)
        print(msg_handshake)
        s.sendall(msg_handshake.serialise())
        try:
            data = read_socket(s, 8)
            hdr = message_header.parse_header(data)
            print(hdr)
            if hdr.is_v2:
                data = read_socket(s, 128+32+32)
            else:
                data = read_socket(s, 128)
            print('parsing')
            recvd_response = handshake_response_query.parse_query_response(hdr, data)

            response = handshake_response.create_response(ctx, recvd_response.cookie, signing_key, verifying_key)
            print('sending response')
            s.sendall(response.serialise())

            vk = ed25519_blake2b.keys.VerifyingKey(recvd_response.account)
            vk.verify(recvd_response.sig, msg_handshake.cookie)
        except TypeError:
            raise HandshakeExchangeFail()

        return recvd_response.account


class handshake_query(node_handshake_id):
    def __init__(self,
                 ctx: dict,
                 hdr: message_header,
                 cookie: bytes = os.urandom(32),
                 v2: bool = True):
        assert isinstance(hdr, message_header)
        assert hdr.is_query()
        self.header = hdr
        self.cookie = cookie
        self.v2 = v2
        self.salt = os.urandom(32)
        self.genesis = ctx['genesis_block'].hash()

    def serialise(self) -> bytes:
        data = self.header.serialise_header()
        if self.v2:
            data += self.salt
            data += self.genesis
        data += self.cookie
        return data

    @classmethod
    def parse_query(cls, ctx: dict, hdr: message_header, data: bytes):
        assert(len(data) == 32)
        cookie = data
        return handshake_query(ctx, hdr, cookie)

    def __str__(self):
        string = "Header: [%s]\n" % str(self.header)
        string += "Cookie: %s\n" % hexlify(self.cookie)
        string += "Is query: %s\n" % self.header.is_query()
        string += "Is response: %s\n" % self.header.is_response()
        string += "Is v2: %s\n" % self.header.is_v2()
        if self.v2:
            string += "Salt: %s\n" % hexlify(self.salt)
            string += "Genesis: %s\n" % hexlify(self.genesis)
        return string

    def __eq__(self, other):
        if not isinstance(other, handshake_query):
            return False
        elif not self.header == other.header:
            return False
        elif not self.cookie == other.cookie:
            return False
        return True


class handshake_response(node_handshake_id):
    def __init__(self, hdr: message_header, account: bytes, signature: bytes):
        assert isinstance(hdr, message_header)
        assert hdr.is_response()

        self.header = hdr
        self.account = account
        self.sig = signature

    def serialise(self) -> bytes:
        data = self.header.serialise_header()
        data += self.account
        data += self.sig
        return data

    @classmethod
    def create_response(cls, ctx, cookie, signing_key: ed25519_blake2b.SigningKey,
                        verifying_key: ed25519_blake2b.VerifyingKey):
        sig = signing_key.sign(cookie)
        hdr = message_header(ctx['net_id'], [20, 20, 18], message_type(10), 4+2)
        return handshake_response(hdr, verifying_key.to_bytes(), sig)

    @classmethod
    def parse_response(cls, hdr: message_header, data: bytes):
        assert len(data) == 96
        assert isinstance(hdr, message_header)

        account = data[0:32]
        sig = data[32:]

        assert(len(sig) == 64)

        return handshake_response(hdr, account, sig)

    def __str__(self):
        string = "Header: [%s]\n" % str(self.header)
        string += "Account: %s\n" % hexlify(self.account)
        string += "Signature: %s\n" % hexlify(self.sig)
        string += "Is query: False\n"
        string += "Is response: True\n"
        return string

    def __eq__(self, other):
        if not isinstance(other, handshake_response):
            return False
        elif not self.header == other.header:
            return False
        elif not self.account == other.account:
            return False
        elif not self.sig == other.sig:
            return False
        return True


class handshake_response_query(node_handshake_id):
    def __init__(self,
                 hdr: message_header,
                 cookie: bytes,
                 account: bytes,
                 salt: bytes,
                 genesis: bytes,
                 signature: bytes):
        assert isinstance(hdr, message_header)
        assert hdr.is_query()
        assert hdr.is_response()

        self.header = hdr
        self.cookie = cookie
        self.account = account
        self.salt = salt
        self.genesis = genesis
        self.sig = signature

    def serialise(self) -> bytes:
        data = self.header.serialise_header()
        data += self.cookie
        data += self.account
        data += self.salt
        data += self.genesis
        data += self.sig
        return data

    @classmethod
    def parse_query_response(cls, hdr: message_header, data: bytes):
        assert isinstance(hdr, message_header)
        assert(len(data) == 128 or len(data) == 128+32+32)

        if hdr.is_v2:
            cookie = data[0:32]
            account = data[32:64]
            salt = data[64:96]
            genesis = data[96:128]
            sig = data[128:]
        else:
            cookie = data[0:32]
            account = data[32:64]
            sig = data[64:]

        assert len(sig) == 64

        print(hexlify(account))
        print(hexlify(genesis))
        return handshake_response_query(hdr, cookie, account, salt, genesis, sig)

    @classmethod
    def create_response(cls, ctx, cookie, signing_key: ed25519_blake2b.SigningKey,
                        verifying_key: ed25519_blake2b.VerifyingKey):
        my_cookie = os.urandom(32)
        sig = signing_key.sign(cookie)
        hdr = message_header(ctx['net_id'], [18, 18, 18], message_type(10), 3)
        return handshake_response_query(hdr, my_cookie, verifying_key.to_bytes(), sig)

    def __str__(self):
        string = "Header: [%s]\n" % str(self.header)
        string += "Cookie: %s\n" % hexlify(self.cookie)
        string += "Account: %s\n" % hexlify(self.account)
        string += "Signature: %s\n" % hexlify(self.sig)
        string += "Is query: True\n"
        string += "Is response: True\n"
        return string

    def __eq__(self, other):
        if not isinstance(other, handshake_response_query):
            return False
        elif not self.header == other.header:
            return False
        elif not self.cookie == other.cookie:
            return False
        elif not self.account == other.account:
            return False
        elif not self.sig == other.sig:
            return False
        return True


def handshake_exchange_server(ctx: dict, sock: socket.socket, query: handshake_query,
                              signing_key: ed25519_blake2b.SigningKey,
                              verifying_key: ed25519_blake2b.VerifyingKey) -> handshake_response:
    response = handshake_response_query.create_response(ctx, query.cookie, signing_key, verifying_key)
    sock.send(response.serialise())

    data = read_socket(sock, 104)
    hdr = message_header.parse_header(data[0:8])
    recvd_response = handshake_response.parse_response(hdr, data[8:])

    vk = ed25519_blake2b.keys.VerifyingKey(recvd_response.account)
    vk.verify(recvd_response.sig, response.cookie)

    return recvd_response
