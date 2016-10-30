import unittest

from libtrust import ec_key
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
