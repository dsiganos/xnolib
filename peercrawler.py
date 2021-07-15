#!/bin/env python3
import ipaddress
import random
import socket
import copy

from nanolib import *


class peer_manager:
    def __init__(self):
        self.nodes = []
        self.count = 1

    def parse_and_add_peers(self, data, addr):
        node = self.find_node(addr)
        if node is None:
            node = node_peers(addr, score=1000)
            self.nodes.append(node)
        assert(len(data) % 18 == 0)
        n = int(len(data) / 18)
        start_index = 0
        end_index = 18
        for i in range(0, n):
            ip = parse_ipv6(data[start_index:end_index - 2])
            port = int.from_bytes(data[end_index - 2:end_index], "little")
            p = peer(ip, port)
            node.add_peer(p)
            start_index = end_index
            end_index += 18

    def valid_peer_data(self, data):
        if int.from_bytes(data[0:16], "big") == 0:
            return False
        elif int.from_bytes(data[16:], "little") == 0:
            return False
        return True

    def add_node(self, ip, score):
        node = node_peers(ip, score=score)
        self.nodes.append(node)

    def crawl(self):
        for n in self.nodes:
            for p in copy.copy(n.get_peers()):
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                s.settimeout(30)
                try:
                    s.connect((str(p.ip), p.port))
                    perform_handshake_exchange(s)
                    peers = get_next_peers(s)
                    self.parse_and_add_peers(peers, p)
                except (ConnectionRefusedError, socket.gaierror, TimeoutError):
                    self.add_node(p, 0)
                    s.close()
                    continue
                except (TypeError, HandshakeExchangeFail):
                    self.add_node(p, 1)
                s.close()


    def find_node(self, addr):
        for n in self.nodes:
            if addr == n.node:
                return n
        return None

    def __str__(self):
        string = "---------- Manager ----------\n"
        string += "Number of Nodes: %d\n" % len(self.nodes)
        return string

    def str_nodes(self):
        string = ""
        for n in self.nodes:
            string += str(n) + "\n"
        string += "Count: %d\n" % self.count
        self.count += 1
        return string


class node_peers:
    def __init__(self, node, score=1000):
        assert(isinstance(node, peer))
        self.peers = set()
        self.bad_peers = set()
        self.node = node
        self.score = score

    def add_peer(self, peer):
        if not peer.is_valid():
            self.bad_peers.add(peer)
            self.report_warning(peer)
        else:
            self.peers.add(peer)

    def set_score(self, num):
        self.score = num

    def report_warning(self, peer):
        print("Bad peer: %s in node: %s" % (str(peer), self.node))

    def get_peers(self):
        return self.peers

    def __str__(self):
        string = "----------- Node: %s ----------\n" % self.node
        string += "---- Peers ----\n"
        for p in self.peers:
            string += "  " + str(p) + "\n"
        string += "---- Bad Peers ----\n"
        for p in self.bad_peers:
            string += "  " + str(p) + "\n"
        return string


def confirm_ack_size(ext):
    size = 104
    i_count = extensions_to_count(ext)
    block_type = extensions_to_block_type(ext)
    if block_type == message_type_enum.not_a_block:
        size += i_count * 32
    else:
        assert(i_count == 1)
        size += block_length_by_type.get(block_type)
    return size

def confirm_req_size(ext):
    i_count = extensions_to_count(ext)
    block_type = extensions_to_block_type(ext)
    if block_type == message_type_enum.not_a_block:
        size = 64 * i_count
    else:
        assert(i_count == 1)
        size = block_length_by_type.get(block_type)
    return size


def clear_next_packet(s, header):
    assert(header.msg_type != message_type(9))
    assert(header.msg_type != message_type(13))
    assert(header.msg_type != message_type(7))

    if header.msg_type == message_type(3):
        block_type = calculate_block_type(header.ext)
        assert(block_type in range(2, 7))
        read_socket(s, block_length_by_type.get(block_type))

    elif header.msg_type == message_type(4):
        size = confirm_req_size(header.ext)
        read_socket(s, size)

    elif header.msg_type == message_type(5):
        read_socket(s, confirm_ack_size(header.ext))

    elif header.msg_type == message_type(6):
        read_socket(s, 64)
        if extensions_to_extented_params(header.ext) != 0:
            read_socket(s, 8)

    # elif header.msg_type == message_type(7):
    #     print("******** Detected a bulk push ********")

    elif header.msg_type == message_type(10):
        read_socket(s, 32)

    elif header.msg_type == message_type(11):
        read_socket(s, 49)

    elif header.msg_type != message_type(13):
        read_socket(s, 202)


def get_next_peers(s):
    data = read_socket(s, 8)
    print(data)
    if data is None:
        return None
    header = message_header.parse_header(data)
    while header.msg_type != message_type(2):
        clear_next_packet(s, header)
        data = read_socket(s, 8)
        header = message_header.parse_header(data)
        print(data)
    return read_socket(s, 144)


def main():
    ctx = livectx
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    peeraddr = random.choice(get_all_dns_addresses(ctx['peeraddr']))
    peeraddr = '::ffff:' + peeraddr
    s.connect((peeraddr, ctx['peerport']))
    s.settimeout(3600)

    perform_handshake_exchange(s)

    manager = peer_manager()
    recvd_peers = get_next_peers(s)
    manager.parse_and_add_peers(recvd_peers, peer(ipaddress.IPv6Address(peeraddr), ctx["peerport"]))
    manager.crawl()


if __name__ == "__main__":
    main()
