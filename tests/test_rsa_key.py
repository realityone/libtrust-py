import unittest

from tests import fixtures_path
from libtrust import rsa_key


class RSAKeyTest(unittest.TestCase):
    def setUp(self):
        with open(fixtures_path('private.pem'), 'r') as f:
            self.private_key = rsa_key.RSAPrivateKey.from_pem(f.read())
        with open(fixtures_path('public.pem'), 'r') as f:
            self.public_key = rsa_key.RSAPublicKey.from_pem(f.read())

    def test_key_id(self):
        pubkey_key_id = self.public_key.key_id()
        priv_key_id = self.private_key.key_id()
        self.assertEqual(
            pubkey_key_id,
            'IIYO:OWAZ:MBMG:2SIK:IK2I:OP5Z:H6QR:KN6Y:QUGO:BUWN:TYW3:JXVW')
        self.assertEqual(pubkey_key_id, priv_key_id)
