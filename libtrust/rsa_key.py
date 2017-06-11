from __future__ import unicode_literals

import copy

from cryptography import utils as cry_utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

from . import hash as hash_
from . import key
from . import util

__all__ = ['RSAPublicKey', 'RSAPrivateKey']

PublicKey = key.PublicKey
PrivateKey = key.PrivateKey


class RSAKey(object):
    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, value):
        self._key = value
        self.numbers = self._numbers()

    def _numbers(self):
        raise NotImplementedError()

    def key_type(self):
        return 'RSA'

    def key_id(self):
        der_bytes = self.crypto_public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        hasher = hashes.Hash(hashes.SHA256(), default_backend())
        hasher.update(der_bytes)
        hash_bytes = hasher.finalize()
        return util.key_id_encode(hash_bytes[:30])

    def __eq__(self, other):
        return self.crypto_public_key().public_numbers() == other.crypto_public_key().public_numbers()


class RSAPublicKey(RSAKey, PublicKey):
    def __init__(self, public_key):
        self.key = public_key

    def _numbers(self):
        return self.key.public_numbers()

    @classmethod
    def from_pem(cls, key_data):
        public_key = serialization.load_pem_public_key(key_data, default_backend())
        return cls(public_key)

    def pem_block(self):
        return self._key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def crypto_public_key(self):
        return copy.copy(self._key)

    def to_map(self):
        return {
            'kty': self.key_type(),
            'kid': self.key_id(),
            'n': util.jose_base64_url_encode(cry_utils.int_to_bytes(self.numbers.n)).decode('utf-8'),
            'e': util.jose_base64_url_encode(util.serialize_rsa_public_exponent_param(self.numbers.e)).decode('utf-8')
        }

    def verify(self, buffer, alg, signature):
        sig_alg = hash_.rsa_signature_algorithm_by_name(alg)
        verifier = self.key.verifier(
            signature,
            padding.PKCS1v15(),
            sig_alg.hasher()
        )
        while True:
            d = buffer.read(1024).encode()
            if not d:
                break
            verifier.update(d)

        try:
            verifier.verify()
        except Exception as e:
            raise e

        return True


class RSAPrivateKey(RSAKey, PrivateKey):
    def __init__(self, private_key):
        self.key = private_key

    def _numbers(self):
        return self.key.private_numbers()

    @classmethod
    def from_pem(cls, key_data, passphrase=None):
        private_key = serialization.load_pem_private_key(
            key_data,
            passphrase,
            default_backend()
        )
        return cls(private_key)

    def pem_block(self):
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )

    def public_key(self):
        return RSAPublicKey(self.crypto_public_key())

    def crypto_private_key(self):
        return copy.copy(self._key)

    def crypto_public_key(self):
        return self._key.public_key()

    def to_map(self):
        public_key_map = self.public_key().to_map()
        private_key_map = {
            'd': util.jose_base64_url_encode(cry_utils.int_to_bytes(self.numbers.d)).decode('utf-8'),
            'p': util.jose_base64_url_encode(cry_utils.int_to_bytes(self.numbers.p)).decode('utf-8'),
            'q': util.jose_base64_url_encode(cry_utils.int_to_bytes(self.numbers.q)).decode('utf-8'),
            'dp': util.jose_base64_url_encode(cry_utils.int_to_bytes(self.numbers.dmp1)).decode('utf-8'),
            'dq': util.jose_base64_url_encode(cry_utils.int_to_bytes(self.numbers.dmq1)).decode('utf-8'),
            'qi': util.jose_base64_url_encode(cry_utils.int_to_bytes(self.numbers.iqmp)).decode('utf-8'),
        }
        private_key_map.update(public_key_map)
        return private_key_map

    def sign(self, buffer, hash_id):
        sig_alg = hash_.rsa_pkcs1v15_signature_algorithm_for_hash_id(hash_id)
        signer = self.key.signer(
            padding.PKCS1v15(),
            sig_alg.hasher()
        )
        while True:
            d = buffer.read(1024).encode('utf-8')
            if not d:
                break
            signer.update(d)

        return signer.finalize(), sig_alg.header_param()


def rsa_public_key_from_map(jwk):
    nb64url = jwk['n'].encode('utf-8')
    eb64url = jwk['e'].encode('utf-8')

    n = util.parse_rsa_modules_params(nb64url)
    e = util.parse_rsa_public_exponent_param(eb64url)
    public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
    return RSAPublicKey(public_key)
