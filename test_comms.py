import unittest
import binascii
from nanolib import *
from ipaddress import IPv6Address


class TestComms(unittest.TestCase):
    def setUp(self):
        data = "524122222202000000000000000000000000ffff9df5d11ef0d200000000000000000000ffff18fb4f64f0d200000000000000000000ffff405a48c2f0d200000000000000000000ffff95382eecf0d200000000000000000000ffff2e044970f0d200000000000000000000ffff68cdcd53f0d200000000000000000000ffffb3a2bdeff0d200000000000000000000ffff74ca6b61f0d2"
        self.data = binascii.unhexlify(data)
        ip1 = peer(IPv6Address("::ffff:9df5:d11e"), 54000)
        ip2 = peer(IPv6Address("::ffff:18fb:4f64"), 54000)
        ip3 = peer(IPv6Address("::ffff:405a:48c2"), 54000)
        ip4 = peer(IPv6Address("::ffff:9538:2eec"), 54000)
        ip5 = peer(IPv6Address("::ffff:2e04:4970"), 54000)
        ip6 = peer(IPv6Address("::ffff:68cd:cd53"), 54000)
        ip7 = peer(IPv6Address("::ffff:b3a2:bdef"), 54000)
        ip8 = peer(IPv6Address("::ffff:74ca:6b61"), 54000)
        self.peer_list = [ip1, ip2, ip3, ip4, ip5, ip6, ip7, ip8]

    def test_header_deserialisation(self):
        h = message_header.parse_header(self.data)
        self.assertEqual(chr(h.net_id.id), 'A')
        self.assertEqual(h.ver_max, 34)
        self.assertEqual(h.ver_using, 34)
        self.assertEqual(h.ver_min, 34)
        self.assertEqual(h.msg_type.type, 2)
        self.assertEqual(h.ext, [0, 0])

    def test_header_serialisation(self):
        h = message_header(network_id(65), [34, 34, 34], message_type(2), 0)
        self.assertEqual(h.serialise_header(), self.data[:8])

    def test_header_deserialisation(self):
        h = message_header(network_id(65), [34, 34, 34], message_type(2), 0)
        h2 = message_header.parse_header(self.data[0:8])
        self.assertEqual(h2, h)

    def test_peer_deserialisation(self):
        p = peer(IPv6Address("::ffff:9df5:d11e"), 54000)
        p1 = peer.parse_peer(self.data[8:26])
        self.assertEqual(p, p1)

    def test_peer_serialisation(self):
        p = peer(IPv6Address("::ffff:9df5:d11e"), 54000)
        self.assertEqual(self.data[8:26], p.serialise())

    def test_full_keepalive_serialisation(self):
        h = message_header(network_id(65), [34, 34, 34], message_type(2), 0)
        keepalive = message_keepalive(h, self.peer_list)
        self.assertEqual(self.data, keepalive.serialise())

    def test_equality_headers(self):
        h = message_header(network_id(65), [34, 34, 34], message_type(2), 0)
        h1 = message_header(network_id(65), [34, 34, 34], message_type(2), 0)
        self.assertTrue(h1 == h)

    def test_equality_peer(self):
        p = peer(IPv6Address("::ffff:9df5:d11e"), 54000)
        p2 = peer(IPv6Address("::ffff:9df5:d11e"), 54000)
        self.assertTrue(p == p2)

    def test_keepalive_full_loop1(self):
        h = message_header.parse_header(self.data[0:8])
        keepalive = message_keepalive.parse_payload(h, self.data[8:])
        self.assertEqual(self.data, keepalive.serialise())

    def test_keepalive_full_loop2(self):
        h = message_header(network_id(65), [34, 34, 34], message_type(2), 0)
        keepalive = message_keepalive(h, self.peer_list)
        data = keepalive.serialise()
        h = message_header.parse_header(data[0:8])
        keepalive2 = message_keepalive.parse_payload(h, data[8:])
        self.assertTrue(keepalive == keepalive2)

    def test_msg_bulk_pull_serialisation(self):
        header = message_header(network_id(67), [18, 18, 18], message_type(6), 0)
        bulk_pull = message_bulk_pull(header, livectx["genesis_pub"])
        expected = b'RC\x12\x12\x12\x06\x00\x00\xe8\x92\x08\xdd\x03\x8f\xbb&\x99\x87h\x96!\xd5"\x92\xae\x9c5\x94\x1at\x84un\xcc\xed\x92\xa6P\x93\xba\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    def test_block_send_serialisation(self):
        prev = binascii.unhexlify('4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05')
        dest = binascii.unhexlify('0000000000000000000000000000000000000000000000000000000000000000')
        bal = 325586539664609129644855132177
        sign = binascii.unhexlify('047115CB577AC78F5C66AD79BBF47540DE97A441456004190F22025FE4255285F57010D962601AE64C266C98FA22973DD95AC62309634940B727AC69F0C86D03')
        work = binascii.unhexlify('7202DF8A7C380578')
        expected = prev + dest + bal.to_bytes(16, "big") + sign + work[::-1]
        b = block_send(prev, dest, bal, sign, work)
        self.assertEqual(expected, b.serialise(False))

    def test_block_send_hash(self):
        prev = binascii.unhexlify('4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05')
        dest = binascii.unhexlify('0000000000000000000000000000000000000000000000000000000000000000')
        bal = 325586539664609129644855132177
        sign = binascii.unhexlify('047115CB577AC78F5C66AD79BBF47540DE97A441456004190F22025FE4255285F57010D962601AE64C266C98FA22973DD95AC62309634940B727AC69F0C86D03')
        work = binascii.unhexlify('7202DF8A7C380578')
        b = block_send(prev, dest, bal, sign, work)
        expected = 'ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113'
        self.assertEqual(expected, hexlify(b.hash()))

    def test_block_receive_serialisation(self):
        prev = binascii.unhexlify('ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113')
        source = binascii.unhexlify('4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05')
        sig = binascii.unhexlify('57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201')
        work = binascii.unhexlify('7202DF8A7C380578')
        expected = prev + source + sig + work[::-1]
        b = block_receive(prev, source, sig, work)
        self.assertEqual(expected, b.serialise(False))

    def test_block_receive_hash(self):
        prev = binascii.unhexlify('ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113')
        source = binascii.unhexlify('4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05')
        sig = binascii.unhexlify('57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201')
        work = binascii.unhexlify('7202DF8A7C380578')
        b = block_receive(prev, source, sig, work)
        expected = '617703C3D7343138CADFCAE391CA863E46BB5661AA74C93635A104141600D46D'
        self.assertEqual(expected, hexlify(b.hash()))

    def test_block_open_serialisation(self):
        source = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        rep = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        acc = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        sig = binascii.unhexlify('9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02')
        work = binascii.unhexlify('62F05417DD3FB691')
        expected = source + rep + acc + sig + work[::-1]
        b = block_open(source, rep, acc, sig, work)
        self.assertEqual(expected, b.serialise(False))

    def test_block_open_hash(self):
        source = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        rep = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        acc = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        sig = binascii.unhexlify('9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02')
        work = binascii.unhexlify('62F05417DD3FB691')
        b = block_open(source, rep, acc, sig, work)
        expected = '991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948'
        self.assertEqual(expected, hexlify(b.hash()))

    def test_block_change_serialisation(self):
        prev = binascii.unhexlify('4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05')
        rep = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        sig = binascii.unhexlify('57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201')
        work = binascii.unhexlify('0F78168D5B30191D')
        expected = prev + rep + sig + work[::-1]
        b = block_change(prev, rep, sig, work)
        self.assertEqual(expected, b.serialise(False))

    def test_block_change_hash(self):
        prev = binascii.unhexlify('4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05')
        rep = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        sig = binascii.unhexlify('57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201')
        work = binascii.unhexlify('0F78168D5B30191D')
        b = block_change(prev, rep, sig, work)
        expected = '01A8479535B4C10238F9B637ABB33B3271575F0918F748B4B6B01020073206AF'
        self.assertEqual(expected, hexlify(b.hash()))

    def test_block_state_serialisation(self):
        acc = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        prev = binascii.unhexlify('ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113')
        rep = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        bal = 325586539664609129644855132177
        link = binascii.unhexlify('65706F636820763120626C6F636B000000000000000000000000000000000000')
        sig = binascii.unhexlify('57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201')
        work = binascii.unhexlify('0F78168D5B30191D')
        expected = acc + prev + rep + bal.to_bytes(16, "big") + link + sig + work
        b = block_state(acc, prev, rep, bal, link, sig, work)
        self.assertEqual(expected, b.serialise(False))

    def test_block_state_hash(self):
        acc = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        prev = binascii.unhexlify('ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113')
        rep = binascii.unhexlify('E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA')
        bal = 325586539664609129644855132177
        link = binascii.unhexlify('65706F636820763120626C6F636B000000000000000000000000000000000000')
        sig = binascii.unhexlify(
            '57BFE93F4675FC16DF0CCFC7EE4F78CC68047B5C14E2E2EED243F17348D8BAB3CCA04F8CBC2D291B4DDEC5F7A74C1BE1E872DF78D560C46365EB15270A1D1201')
        work = binascii.unhexlify('0F78168D5B30191D')
        b = block_state(acc, prev, rep, bal, link, sig, work)
        expected = '6875C0DBFE5C44D8F8CFF431BC69ED5587C68F89F0663F2BC1FBBFCB46DC5989'
        self.assertEqual(expected, hexlify(b.hash()))

    def test_blocks_manager_traversals(self):
        block1 = {
            "prev" : binascii.unhexlify('991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948'),
            "dest" : binascii.unhexlify('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5'),
            "bal" : 337010421085160209006996005437231978653,
            "sig" : binascii.unhexlify('5B11B17DB9C8FE0CC58CAC6A6EECEF9CB122DA8A81C6D3DB1B5EE3AB065AA8F8CB1D6765C8EB91B58530C5FF5987AD95E6D34BB57F44257E20795EE412E61600'),
            "work" : binascii.unhexlify('3C82CC724905EE95')
        }

        block2 = {
            "prev": binascii.unhexlify('A170D51B94E00371ACE76E35AC81DC9405D5D04D4CEBC399AEACE07AE05DD293'),
            "dest": binascii.unhexlify('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5'),
            "bal": 333738475249381954550617403442695745851,
            "sig": binascii.unhexlify('D6CAB5845050A058806D18C38E022322664A7E169498206420619F2ED031E7ED6FC80D5F33701B54B34B4DF2B65F02ECD8B5E26E44EC11B17570E1EE008EEC0E'),
            "work": binascii.unhexlify('96B201F33F0394AE')
        }

        block3 = {
            "prev": binascii.unhexlify('28129ABCAB003AB246BA22702E0C218794DFFF72AD35FD56880D8E605C0798F6'),
            "dest": binascii.unhexlify('059F68AAB29DE0D3A27443625C7EA9CDDB6517A8B76FE37727EF6A4D76832AD5'),
            "bal": 330466529413603700094238801448159513049,
            "sig": binascii.unhexlify('7F5ABE59D6C25EEEFE28174A6646D6E228FFDE3ACBA1293EDFFA057CE739AF9DAC89A4D1783BD30E2B4F0154815A959A57424C5EA35EA3ADF0CD2AF981BF7103'),
            "work": binascii.unhexlify('6B8567274385A390')
        }
        b1 = block_send(block1["prev"], block1["dest"], block1["bal"], block1["sig"], block1["work"])
        b2 = block_send(block2["prev"], block2["dest"], block2["bal"], block2["sig"], block2["work"])
        b3 = block_send(block3["prev"], block3["dest"], block3["bal"], block3["sig"], block3["work"])
        manager = block_manager(None, None)
        manager.process(b1)
        manager.process(b2)
        manager.process(b3)
        self.assertEqual(manager.accounts[0].blocks[b1.hash()], b1)
        self.assertEqual(manager.accounts[0].blocks[b2.hash()], b2)
        self.assertEqual(manager.accounts[0].blocks[b3.hash()], b3)


if __name__ == '__main__':
    unittest.main()
