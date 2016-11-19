from __future__ import unicode_literals

import unittest

from libtrust import ec_key
from libtrust import jsonsign
from libtrust import rsa_key
from tests import fixtures_path


class JSONSignTest(unittest.TestCase):
    def setUp(self):
        self.content = {
            'hello': '123'
        }
        with open(fixtures_path('private.pem'), 'r') as f:
            self.rsa_private_key = rsa_key.RSAPrivateKey.from_pem(f.read())
        with open(fixtures_path('ec-private.pem'), 'r') as f:
            self.ec_private_key = ec_key.ECPrivateKey.from_pem(f.read())

    def create_js(self):
        return jsonsign.JSONSignature.from_map(self.content)

    def test_from_map(self):
        self.assertEqual('ewogICAiaGVsbG8iOiAiMTIzIgp9', self.create_js().payload)
        self.assertEqual('eyJmb3JtYXRMZW5ndGgiOjE5LCJmb3JtYXRUYWlsIjoiQ24wIiwidGltZSI6IjIwMTYtMTEtMDZUMDk6MDQ6MzJaIn0',
                         self.create_js().protected_header(timestamp=1478423072))

    def test_sign(self):
        rsa_js = self.create_js()
        rsa_sig_bytes, rsa_algorithm = rsa_js.sign(self.rsa_private_key, timestamp=1478423072)
        self.assertEqual(
            [176, 211, 90, 236, 109, 15, 137, 15, 6, 6, 165, 219, 181, 42, 9, 152, 25, 15, 64, 216, 150, 82, 197, 105, 13, 178,
             181, 37, 234, 181, 203, 70, 117, 87, 106, 85, 176, 255, 112, 95, 193, 198, 89, 87, 84, 99, 233, 180, 216, 81, 236,
             34, 194, 124, 188, 248, 160, 51, 56, 248, 104, 211, 150, 217, 14, 21, 227, 169, 107, 161, 74, 9, 95, 182, 140, 20,
             18, 194, 4, 121, 16, 116, 230, 179, 224, 64, 38, 241, 114, 48, 162, 192, 151, 69, 11, 146, 47, 44, 199, 208, 175,
             147, 139, 239, 57, 247, 155, 178, 248, 8, 27, 119, 51, 193, 204, 12, 111, 14, 123, 182, 74, 43, 158, 8, 57, 126, 186,
             159, 23, 56, 131, 179, 155, 150, 43, 234, 169, 189, 236, 216, 6, 5, 35, 244, 139, 237, 20, 88, 51, 216, 121, 239,
             171, 189, 186, 246, 46, 136, 52, 237, 240, 137, 171, 223, 110, 123, 248, 196, 78, 225, 71, 140, 32, 96, 25, 170, 135,
             230, 56, 57, 104, 160, 51, 57, 162, 52, 173, 79, 255, 251, 155, 241, 147, 187, 204, 173, 136, 205, 173, 170, 221, 21,
             173, 150, 128, 195, 91, 53, 171, 207, 189, 226, 20, 142, 246, 77, 99, 65, 38, 231, 28, 105, 180, 21, 94, 45, 204,
             110, 169, 145, 193, 56, 179, 209, 112, 204, 211, 52, 37, 172, 203, 85, 30, 233, 52, 25, 191, 33, 19, 74, 31, 156,
             161, 153, 48, 100, 245, 26, 204, 218, 100, 203, 194, 168, 149, 74, 73, 4, 161, 240, 212, 125, 11, 119, 14, 96, 109,
             91, 132, 47, 223, 101, 153, 225, 92, 197, 151, 162, 24, 24, 193, 31, 110, 38, 149, 111, 165, 204, 119, 171, 106, 118,
             200, 219, 202, 212, 247, 34, 133, 125, 187, 58, 137, 29, 87, 81, 207, 237, 57, 139, 221, 85, 28, 68, 136, 178, 211,
             46, 224, 123, 129, 174, 193, 72, 201, 240, 118, 43, 204, 202, 85, 24, 100, 253, 85, 247, 109, 215, 87, 120, 90, 106,
             221, 196, 53, 29, 120, 10, 142, 211, 222, 125, 171, 126, 198, 129, 82, 164, 92, 155, 183, 129, 36, 42, 169, 68, 176,
             8, 179, 220, 80, 69, 231, 229, 254, 109, 55, 19, 43, 83, 118, 97, 98, 250, 97, 164, 184, 191, 168, 158, 205, 205,
             251, 237, 51, 130, 114, 177, 154, 242, 145, 162, 204, 235, 109, 76, 154, 242, 180, 152, 250, 48, 170, 226, 205, 35,
             235, 194, 152, 186, 9, 170, 228, 24, 128, 43, 103, 195, 20, 105, 174, 255, 177, 128, 167, 39, 140, 198, 221, 51, 82,
             22, 119, 214, 222, 151, 216, 128, 76, 222, 217, 197, 176, 66, 173, 151, 72, 198, 49, 21, 246, 106, 131, 157, 164,
             199, 166, 103, 204, 85, 78, 194, 10, 38, 248, 95, 181, 233, 237, 199, 166, 254, 222, 77, 216, 221, 17, 45, 120, 8,
             174, 23, 193, 150, 133, 169, 128, 107, 208, 145, 121, 130],
            [ord(c) for c in rsa_sig_bytes]
        )
        self.assertEqual(
            rsa_algorithm, 'RS256'
        )
        self.assertEqual([self.rsa_private_key.public_key()], rsa_js.verify())

        ec_js = self.create_js()
        ec_sig_bytes, ec_algorithm = ec_js.sign(self.ec_private_key, timestamp=1478423072)
        self.assertEqual(
            ec_algorithm, 'ES256'
        )
        self.assertEqual([self.ec_private_key.public_key()], ec_js.verify())

    def test_ec_key_verify(self):
        from libtrust import util
        from libtrust.jsonsign import JsHeader
        from libtrust.jsonsign import JsSignature
        sig_bytes = str('').join(
            [
                chr(c) for c in
                [
                    53, 176, 9, 188, 171, 104, 49, 228, 136, 38, 67, 255, 195, 21, 235, 107, 150, 22, 152, 124, 80,
                    89, 129, 125,
                    160, 26, 54, 23, 67, 221, 200, 125, 230, 77, 166, 151, 195, 132, 181, 179, 15, 116, 43, 17,
                    159, 236, 145,
                    217, 20, 64, 47, 45, 101, 174, 255, 235, 54, 248, 139, 227, 169, 241, 60, 138
                ]
                ]
        )
        protected = 'eyJmb3JtYXRMZW5ndGgiOjE5LCJmb3JtYXRUYWlsIjoiQ24wIiwidGltZSI6IjIwMTYtMTEtMDZUMDk6MDQ6MzJaIn0'

        ec_js = self.create_js()
        ec_js.signatures.append(
            JsSignature(
                JsHeader(
                    self.ec_private_key.public_key(),
                    'ES256'
                ),
                util.jose_base64_url_encode(sig_bytes),
                protected
            )
        )

        ec_js.verify()
