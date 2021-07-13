import unittest
import binascii
from main import message_header, peers, network_id, message_type, peer_address, ipv6addresss
from ipaddress import IPv6Address


class TestComms(unittest.TestCase):
    def setUp(self):
        data = "524122222202000000000000000000000000ffff9df5d11ef0d200000000000000000000ffff18fb4f64f0d200000000000000000000ffff405a48c2f0d200000000000000000000ffff95382eecf0d200000000000000000000ffff2e044970f0d200000000000000000000ffff68cdcd53f0d200000000000000000000ffffb3a2bdeff0d200000000000000000000ffff74ca6b61f0d2"
        self.data = binascii.unhexlify(data)
        ip1 = peer(ipv6addresss(IPv6Address("::ffff:9df5:d11e")), 54000)
        ip2 = peer(ipv6addresss(IPv6Address("::ffff:18fb:4f64")), 54000)
        ip3 = peer(ipv6addresss(IPv6Address("::ffff:405a:48c2")), 54000)
        ip4 = peer(ipv6addresss(IPv6Address("::ffff:9538:2eec")), 54000)
        ip5 = peer(ipv6addresss(IPv6Address("::ffff:2e04:4970")), 54000)
        ip6 = peer(ipv6addresss(IPv6Address("::ffff:68cd:cd53")), 54000)
        ip7 = peer(ipv6addresss(IPv6Address("::ffff:b3a2:bdef")), 54000)
        ip8 = peer(ipv6addresss(IPv6Address("::ffff:74ca:6b61")), 54000)
        self.peer_list = [ip1, ip2, ip3, ip4, ip5, ip6, ip7, ip8]
        self.p = peers(self.peer_list)


    def test_header_deserialisation(self):
        h = message_header.parse_header(self.data)
        self.assertEqual(chr(h.net_id.id), 'A')
        self.assertEqual(h.ver_max, 34)
        self.assertEqual(h.ver_using, 34)
        self.assertEqual(h.ver_min, 34)
        self.assertEqual(h.msg_type.type, 2)
        self.assertEqual(h.ext, [0, 0])

    def test_header_serialisation(self):
        h = message_header(network_id(65), [34, 34, 34], message_type(2), [0, 0])
        self.assertEqual(h.serialise_header(), self.data[:8])

    def test_peer_deserialisation(self):
        p = peers.parse_peers(self.data[8:])
        self.assertEqual(8, len(p.peers))

    def test_peer_serialisation(self):
        self.assertEqual(len(self.p.serialise()), len(self.data[8:]))
        self.assertEqual(self.data[8:], self.p.serialise())

    def test_full_serialisation(self):
        h = message_header(network_id(65), [34, 34, 34], message_type(2), [0, 0])
        output = h.serialise_header()
        output += self.p.serialise()
        self.assertEqual(self.data, output)

    def test_equality_headers(self):
        h = message_header(network_id(65), [34, 34, 34], message_type(2), [0, 0])
        h1 = message_header(network_id(65), [34, 34, 34], message_type(2), [0, 0])
        self.assertTrue(h1 == h)

    def test_equality_peers(self):
        p1 = peers(self.peer_list)
        self.assertTrue(self.p == p1)

    def test_full_loop1(self):
        h = message_header.parse_header(self.data)
        p = peers.parse_peers(self.data[8:])
        output = h.serialise_header()
        output += p.serialise()
        self.assertEqual(self.data, output)

    def test_full_loop2(self):
        h = message_header(network_id(65), [34, 34, 34], message_type(2), [0, 0])
        data = h.serialise_header()
        data += self.p.serialise()
        h2 = message_header.parse_header(data[:8])
        p2 = peers.parse_peers(data[8:])
        self.assertTrue(self.p == p2)
        self.assertTrue(h == h2)

if __name__ == '__main__':
    unittest.main()
