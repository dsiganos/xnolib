from msg_handshake import node_handshake_id
from peercrawler import get_initial_connected_socket
from pynanocoin import livectx


def main():
    ctx = livectx
    s, _ = get_initial_connected_socket(ctx)
    assert s
    with s:
        node_handshake_id.perform_handshake_exchange(ctx, s)


if __name__ == "__main__":
    main()
