import copy
import hashlib

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from libtrust import hash as hash_
from libtrust import key
from libtrust import util

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

    def marshal_json(self):
        return util.dump_json(self.to_map())


class RSAPublicKey(RSAKey, PublicKey):
    def __init__(self, public_key):
        self._key = public_key

    @classmethod
    def from_pem(cls, key_data):
        public_key = RSA.import_key(key_data)
        return cls(public_key)

    def to_map(self):
        return {
            'kty': self.key_type(),
            'kid': self.key_id(),
            'n': util.jose_base64_url_encode(util.number_to_byte(self._key.n)),
            'e': util.jose_base64_url_encode(util.serialize_rsa_public_exponent_param(self._key.e))
        }

    def verify(self, buffer, alg, signature):
        sig_alg = hash_.rsa_signature_algorithm_by_name(alg)
        hasher = sig_alg.hasher()
        while True:
            d = buffer.read(1024)
            if not d:
                break
            hasher.update(d)

        try:
            pkcs1_15.new(self.crypto_public_key()).verify(hasher, signature)
        except ValueError as e:
            raise e

        return True


class RSAPrivateKey(RSAKey, PrivateKey):
    def __init__(self, private_key):
        self._key = private_key

    @property
    def dp(self):
        return int(self._key.d % (self._key.p - 1))

    @property
    def dq(self):
        return self._key.d % (self._key.q - 1)

    @property
    def qinv(self):
        return util.inverse_number(self._key.q, self._key.p)

    @classmethod
    def from_pem(cls, key_data, passphrase=None):
        private_key = RSA.import_key(key_data, passphrase=passphrase)
        return cls(private_key)

    def public_key(self):
        return RSAPublicKey(self.crypto_public_key())

    def crypto_private_key(self):
        return copy.copy(self._key)

    def to_map(self):
        public_key_map = self.public_key().to_map()
        private_key_map = {
            'd': util.jose_base64_url_encode(util.number_to_byte(self._key.d)),
            'p': util.jose_base64_url_encode(util.number_to_byte(self._key.p)),
            'q': util.jose_base64_url_encode(util.number_to_byte(self._key.q)),
            'dp': util.jose_base64_url_encode(util.number_to_byte(self.dp)),
            'dq': util.jose_base64_url_encode(util.number_to_byte(self.dq)),
            'qi': util.jose_base64_url_encode(util.number_to_byte(self.qinv)),
        }
        private_key_map.update(public_key_map)
        return private_key_map

    def sign(self, buffer, hash_id):
        sig_alg = hash_.rsa_pkcs1v15_signature_algorithm_for_hash_id(hash_id)
        hasher = sig_alg.hasher()
        while True:
            d = buffer.read(1024)
            if not d:
                break
            hasher.update(d)

        return pkcs1_15.new(self._key).sign(hasher), sig_alg.header_param()
