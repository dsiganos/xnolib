from pynanocoin import *


class handshake_query:
    def __init__(self, ctx, cookie=os.urandom(32)):
        self.header = message_header(ctx["net_id"], [18, 18, 18], message_type(10), 1)
        self.cookie = cookie

    def serialise(self):
        data = self.header.serialise_header()
        data += self.cookie
        return data

    @classmethod
    def parse_query(cls, ctx, data):
        assert(len(data) == 40)
        cookie = data[8:]
        assert(len(cookie) == 32)
        return handshake_query(ctx, cookie)

    def __str__(self):
        string = "Header: [%s]\n" % str(self.header)
        string += "Cookie: %s\n" % hexlify(self.cookie)
        string += "Is query: True\n"
        string += "Is response: False\n"
        return string


class handshake_response:
    def __init__(self, ctx, account, signature):
        self.header = message_header(ctx["net_id"], [18, 18, 18], message_type(10), 2)
        self.account = account
        self.sig = signature

    def serialise(self):
        data = self.header.serialise_header()
        data += self.account
        data += self.sig
        return data

    @classmethod
    def create_response(cls, ctx, cookie):
        signing_key, verifying_key = ed25519_blake2b.create_keypair()
        sig = signing_key.sign(cookie)
        return handshake_response(ctx, verifying_key.to_bytes(), sig)

    @classmethod
    def parse_response(cls, ctx, data):
        assert(len(data) == 104)
        account = data[8:40]
        sig = data[40:]
        assert(len(sig) == 64)
        return handshake_response(ctx, account, sig)

    def __str__(self):
        string = "Header: [%s]\n" % str(self.header)
        string += "Account: %s\n" % hexlify(self.account)
        string += "Signature: %s\n" % hexlify(self.sig)
        string += "Is query: False\n"
        string += "Is response: True\n"
        return string


class handshake_response_query:
    def __init__(self, ctx, cookie, account, signature):
        self.header = message_header(ctx["net_id"], [18, 18, 18], message_type(10), 3)
        self.cookie = cookie
        self.account = account
        self.sig = signature

    def serialise(self):
        data = self.header.serialise_header()
        data += self.cookie
        data += self.account
        data += self.sig
        return data

    @classmethod
    def parse_query_response(cls, ctx, data):
        assert(len(data) == 136)
        cookie = data[8:40]
        account = data[40:72]
        sig = data[72:]
        return handshake_response_query(ctx, cookie, account, sig)

    @classmethod
    def create_response(self, ctx, cookie):
        signing_key, verifying_key = ed25519_blake2b.create_keypair()
        my_cookie = os.urandom(32)
        sig = signing_key.sign(cookie)
        return handshake_response_query(ctx, my_cookie, verifying_key.to_bytes(), sig)



    def __str__(self):
        string = "Header: [%s]\n" % str(self.header)
        string += "Cookie: %s\n" % hexlify(self.cookie)
        string += "Account: %s\n" % hexlify(self.account)
        string += "Signature: %s\n" % hexlify(self.sig)
        string += "Is query: True\n"
        string += "Is response: True\n"
        return string


def perform_handshake_exchange(ctx, s):
    msg_handshake = handshake_query(ctx)
    s.send(msg_handshake.serialise())
    try:
        data = read_socket(s, 136)
        recvd_response = handshake_response_query.parse_query_response(ctx, data)

        response = handshake_response.create_response(ctx, recvd_response.cookie)
        s.send(response.serialise())

        vk = ed25519_blake2b.keys.VerifyingKey(recvd_response.account)
        vk.verify(recvd_response.sig, msg_handshake.cookie)
    except TypeError:
        raise HandshakeExchangeFail()

    return recvd_response.account


def handshake_exchange_server(ctx, s, query):
    assert(isinstance(s, socket.socket) and isinstance(query, handshake_query))
    response = handshake_response_query.create_response(ctx, query.cookie)
    s.send(response.serialise())

    data = read_socket(s, 104)
    recvd_response = handshake_response.parse_response(ctx, data)

    vk = ed25519_blake2b.keys.VerifyingKey(recvd_response.account)
    vk.verify(recvd_response.sig, response.cookie)


def main():
    ctx = livectx
    s, _ = get_initial_connected_socket(ctx)
    assert s
    with s:
        perform_handshake_exchange(ctx, s)


if __name__ == "__main__":
    main()
