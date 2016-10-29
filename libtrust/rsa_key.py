import copy
import hashlib

import util
from Crypto.PublicKey import RSA
from libtrust import key

__all__ = ['RSAPublicKey', 'RSAPrivateKey']

PublicKey = key.PublicKey
PrivateKey = key.PrivateKey


class RSAKey(object):
    def key_type(self):
        return 'RSA'

    def pem_block(self):
        return self._key.exportKey(format='PEM')

    def key_id(self):
        der_bytes = self.crypto_public_key().exportKey(format='DER')
        hash_bytes = hashlib.sha256(der_bytes).digest()
        return util.key_id_encode(hash_bytes[:30])

    def crypto_public_key(self):
        return self._key.publickey()


class RSAPublicKey(RSAKey, PublicKey):
    def __init__(self, public_key):
        self._key = public_key

    @classmethod
    def from_pem(cls, key_data):
        public_key = RSA.import_key(key_data)
        return cls(public_key)


class RSAPrivateKey(RSAKey, PrivateKey):
    def __init__(self, private_key):
        self._key = private_key

    @classmethod
    def from_pem(cls, key_data, passphrase=None):
        private_key = RSA.import_key(key_data, passphrase=passphrase)
        return cls(private_key)

    def public_key(self):
        return RSAPublicKey(self.crypto_public_key())

    def crypto_private_key(self):
        return copy.copy(self._key)
