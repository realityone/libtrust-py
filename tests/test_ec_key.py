import StringIO
import unittest

from libtrust import ec_key
from libtrust import hash as hash_
from tests import fixtures_path


class ECKeyTest(unittest.TestCase):
    def setUp(self):
        with open(fixtures_path('ec-private.pem'), 'r') as f:
            self.private_key = ec_key.ECPrivateKey.from_pem(f.read())
        with open(fixtures_path('ec-public.pem'), 'r') as f:
            self.public_key = ec_key.ECPublicKey.from_pem(f.read())

    def test_key_id(self):
        pub_key_key_id = self.public_key.key_id()
        priv_key_id = self.private_key.key_id()
        self.assertEqual('UEV2:PPF2:4DMU:WZYF:WOWU:677P:B7XU:SGFA:BMUG:NCTC:R7CL:XFKZ', pub_key_key_id)
        self.assertEqual(pub_key_key_id, priv_key_id)

    def test_marshal_json(self):
        pub_key_json = self.public_key.marshal_json()
        priv_key_json = self.private_key.marshal_json()
        pub_key_json_origin = r"""{"crv":"P-256","kid":"UEV2:PPF2:4DMU:WZYF:WOWU:677P:B7XU:SGFA:BMUG:NCTC:R7CL:XFKZ","kty":"EC","x":"4pBqYlc5IU5pJh5AOvijtEccStyJu0dSAiz4OlDGGFk","y":"OT70pUofsKlHEsqdWUUj-ZF-z5bqH-9oOTJ4mqBayyo"}"""
        priv_key_json_origin = r"""{"crv":"P-256","d":"bIovQ3DJpFKLJsjjguT088jR-hm4BHKYpC1zomg_2RY","kid":"UEV2:PPF2:4DMU:WZYF:WOWU:677P:B7XU:SGFA:BMUG:NCTC:R7CL:XFKZ","kty":"EC","x":"4pBqYlc5IU5pJh5AOvijtEccStyJu0dSAiz4OlDGGFk","y":"OT70pUofsKlHEsqdWUUj-ZF-z5bqH-9oOTJ4mqBayyo"}"""
        self.assertEqual(pub_key_json_origin, pub_key_json)
        self.assertEqual(priv_key_json_origin, priv_key_json)

    def test_sign(self):
        message = StringIO.StringIO('Hello, World!')
        sig_algs = (hash_.ES256,)
        origin_sig = (
            [73, 162, 45, 237, 124, 0, 197, 116, 200, 184, 246, 95, 170, 84, 143, 186, 94, 103, 228, 237, 193, 211, 99, 10, 145,
             68, 20, 35, 96, 230, 86, 232, 17, 9, 62, 186, 41, 216, 179, 32, 226, 123, 79, 47, 12, 149, 158, 104, 122, 78, 106,
             43, 18, 126, 110, 0, 233, 68, 245, 240, 72, 169, 7, 21],
        )

        for i, sa in enumerate(sig_algs):
            message.seek(0)
            sig, alg = self.private_key.sign(message, sa.hash_id)

            message.seek(0)
            self.assertTrue(self.public_key.verify(message, alg, sig))

            message.seek(0)
            self.assertTrue(self.public_key.verify(message, alg, ''.join([chr(i) for i in origin_sig[i]])))
