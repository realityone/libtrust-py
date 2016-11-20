from __future__ import unicode_literals

import copy

import enum
from cryptography import utils as cry_utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asy_utils
from . import hash as hash_
from . import key
from . import util

__all__ = ['ECPublicKey', 'ECPrivateKey']

PublicKey = key.PublicKey
PrivateKey = key.PrivateKey


class Curves(enum.Enum):
    P256 = 'P-256'
    P384 = 'P-384'
    P521 = 'P-521'

    @classmethod
    def from_common_name(cls, common_name):
        return {
            ec.SECP256R1.name: cls.P256,
            ec.SECP384R1.name: cls.P384,
            ec.SECP521R1.name: cls.P521
        }[common_name]

    def crypto_curve(self):
        return {
            self.P256: ec.SECP256R1,
            self.P384: ec.SECP384R1,
            self.P521: ec.SECP521R1
        }[self]

    def signature_algorithm(self):
        return {
            self.P256: hash_.ES256,
            self.P384: hash_.ES384,
            self.P521: hash_.ES521
        }[self]

    def bit_size(self):
        return {
            self.P256: 256,
            self.P384: 384,
            self.P521: 521
        }[self]


class ECKey(object):
    def key_type(self):
        return 'EC'

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, value):
        self._key = value
        self.numbers = self._numbers()

    def _numbers(self):
        raise NotImplementedError()

    def key_id(self):
        der_bytes = self.crypto_public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        hasher = hashes.Hash(hashes.SHA256(), default_backend())
        hasher.update(der_bytes)
        hash_bytes = hasher.finalize()
        return util.key_id_encode(hash_bytes[:30])

    @property
    def curve_name(self):
        return self.curve.value

    @property
    def curve(self):
        return Curves.from_common_name(self.key.curve.name)

    @property
    def signature_algorithm(self):
        return self.curve.signature_algorithm()

    def __eq__(self, other):
        return self.crypto_public_key().public_numbers() == other.crypto_public_key().public_numbers()


class ECPublicKey(ECKey, PublicKey):
    def __init__(self, key):
        self.key = key

    def _numbers(self):
        return self.key.public_numbers()

    @classmethod
    def from_pem(cls, key_data):
        public_key = serialization.load_pem_public_key(
            key_data,
            default_backend()
        )
        return cls(public_key)

    def pem_block(self):
        return self.key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def crypto_public_key(self):
        return copy.copy(self.key)

    def to_map(self):
        jwk = {
            'kty': self.key_type(),
            'kid': self.key_id(),
            'crv': self.curve_name,
        }
        x_bytes = cry_utils.int_to_bytes(self.numbers.x)
        y_bytes = cry_utils.int_to_bytes(self.numbers.y)
        octet_length = (self.curve.bit_size() + 7) >> 3

        x_bytes = str('\x00') * (octet_length - len(x_bytes)) + x_bytes
        y_bytes = str('\x00') * (octet_length - len(y_bytes)) + y_bytes

        jwk['x'] = util.jose_base64_url_encode(x_bytes)
        jwk['y'] = util.jose_base64_url_encode(y_bytes)
        return jwk

    def verify(self, buffer, alg, signature):
        sig_length = len(signature)
        r_bytes, s_bytes = signature[:sig_length / 2], signature[sig_length / 2:]
        r, s = cry_utils.int_from_bytes(r_bytes, 'big'), cry_utils.int_from_bytes(s_bytes, 'big')

        signature = asy_utils.encode_dss_signature(r, s)
        sig_alg = self.signature_algorithm
        verifier = self.key.verifier(
            signature,
            ec.ECDSA(sig_alg.hasher())
        )
        while True:
            d = buffer.read(1024)
            if not d:
                break
            verifier.update(d)

        try:
            verifier.verify()
        except Exception as e:
            raise e

        return True


class ECPrivateKey(ECKey, PrivateKey):
    def __init__(self, key):
        self.key = key

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
        return ECPublicKey(self.crypto_public_key())

    def crypto_private_key(self):
        return copy.copy(self.key)

    def crypto_public_key(self):
        return self.key.public_key()

    def to_map(self):
        public_key_map = self.public_key().to_map()
        d_bytes = cry_utils.int_to_bytes(self.numbers.private_value)
        octet_length = (len(cry_utils.int_to_bytes(self.numbers.private_value - 1)) + 7) >> 3

        d_bytes = str('\x00') * (octet_length - len(d_bytes)) + d_bytes
        private_key_map = {
            'd': util.jose_base64_url_encode(d_bytes)
        }

        private_key_map.update(public_key_map)
        return private_key_map

    def sign(self, buffer, hash_id):
        sig_alg = self.signature_algorithm
        signer = self.key.signer(
            ec.ECDSA(sig_alg.hasher())
        )
        while True:
            d = buffer.read(1024)
            if not d:
                break
            signer.update(d)

        r, s = asy_utils.decode_dss_signature(signer.finalize())
        r_bytes = cry_utils.int_to_bytes(r)
        s_bytes = cry_utils.int_to_bytes(s)
        octet_length = (self.public_key().curve.bit_size() + 7) >> 3

        r_bytes = str('\x00') * (octet_length - len(r_bytes)) + r_bytes
        s_bytes = str('\x00') * (octet_length - len(s_bytes)) + s_bytes
        signature = r_bytes + s_bytes
        return signature, self.signature_algorithm.header_param()


def ec_public_key_from_map(jwk):
    crv_name = jwk['crv']
    curve = Curves(crv_name)

    crypto_curve = curve.crypto_curve()

    xb64url = jwk['x']
    yb64url = jwk['y']
    x = util.parse_ec_coordinate(xb64url, curve)
    y = util.parse_ec_coordinate(yb64url, curve)
    public_key = ec.EllipticCurvePublicNumbers(x, y, crypto_curve()).public_key(default_backend())
    return ECPublicKey(public_key)
