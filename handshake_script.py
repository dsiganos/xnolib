from msg_handshake import perform_handshake_exchange
from peercrawler import get_initial_connected_socket
from pynanocoin import livectx


def main():
    ctx = livectx
    s, _ = get_initial_connected_socket(ctx)
    assert s
    with s:
        perform_handshake_exchange(ctx, s)


if __name__ == "__main__":
    main()