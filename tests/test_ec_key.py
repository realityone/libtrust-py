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

    def test_to_pem(self):
        self.private_key.pem_block()
        self.public_key.pem_block()

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
        sig_algs = (hash_.ES256, hash_.ES384, hash_.ES521)
        origin_sig = (
            [88, 34, 78, 248, 120, 105, 162, 172, 14, 179, 252, 201, 193, 230, 124, 105, 227, 145, 236, 104, 31, 153, 215, 117,
             193, 126, 229, 98, 143, 88, 81, 216, 19, 67, 86, 127, 212, 195, 149, 200, 63, 117, 65, 155, 70, 6, 219, 234, 151,
             120, 229, 214, 193, 210, 165, 158, 135, 160, 244, 210, 41, 49, 132, 71],
            [65, 50, 99, 81, 100, 105, 169, 194, 75, 54, 38, 34, 69, 117, 22, 1, 105, 176, 138, 47, 254, 233, 225, 132, 39, 40,
             160, 2, 9, 208, 78, 11, 76, 20, 163, 57, 222, 176, 108, 93, 155, 163, 102, 185, 211, 138, 83, 92, 67, 92, 133, 51,
             119, 58, 20, 212, 51, 37, 20, 175, 202, 134, 85, 14],
            [112, 133, 177, 239, 79, 252, 240, 252, 28, 96, 174, 40, 109, 34, 109, 141, 183, 16, 246, 249, 102, 213, 128, 132,
             206, 148, 124, 150, 254, 248, 164, 62, 109, 95, 178, 120, 53, 52, 216, 135, 213, 193, 97, 109, 255, 0, 220, 219, 41,
             224, 112, 236, 14, 131, 170, 191, 223, 234, 36, 90, 152, 133, 138, 247]
        )

        for i, sa in enumerate(sig_algs):
            message.seek(0)
            sig, alg = self.private_key.sign(message, sa.hash_id)

            message.seek(0)
            self.assertTrue(self.public_key.verify(message, alg, sig))

            message.seek(0)
            self.assertTrue(self.public_key.verify(message, alg, ''.join([chr(i) for i in origin_sig[i]])))
