
# all exceptions in this project inherit this class
class PyNanoCoinException(Exception):
    pass


class ParseErrorBadMagicNumber(PyNanoCoinException):
    pass


class ParseErrorBadNetworkId(PyNanoCoinException):
    pass


class ParseErrorBadMessageType(PyNanoCoinException):
    pass


class ParseErrorBadIPv6(PyNanoCoinException):
    pass


class ParseErrorBadMessageBody(PyNanoCoinException):
    pass


class ParseErrorBadBlockSend(PyNanoCoinException):
    pass


class ParseErrorBadBlockReceive(PyNanoCoinException):
    pass


class ParseErrorBadBlockOpen(PyNanoCoinException):
    pass


class ParseErrorBadBlockChange(PyNanoCoinException):
    pass


class ParseErrorBadBlockChange(PyNanoCoinException):
    pass


class ParseErrorBadBlockState(PyNanoCoinException):
    pass


class ParseErrorBadBulkPullResponse(PyNanoCoinException):
    pass


class BadBlockHash(PyNanoCoinException):
    pass


class SocketClosedByPeer(PyNanoCoinException):
    pass


class InvalidBlockHash(PyNanoCoinException):
    pass


class HandshakeExchangeFail(PyNanoCoinException):
    pass


class CommsError(PyNanoCoinException):
    pass


class BadTelemetryReply(PyNanoCoinException):
    pass


class PeerServiceUnavailable(PyNanoCoinException):
    pass


class FrontierServiceSlowPeer(PyNanoCoinException):
    pass


class BlacklistItemTypeError(PyNanoCoinException):
    pass


class VerificationErrorNoAccount(PyNanoCoinException):
    pass


class NoBlocksPulled(PyNanoCoinException):
    pass
