import enum

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from libtrust import hash as hash_
from libtrust import key
from libtrust import util

PublicKey = key.PublicKey
PrivateKey = key.PrivateKey


class Curves(enum.Enum):
    P256 = 'P-256'

    def curve(self):
        return {
            self.P256: ECC._curve
        }[self]

    def signature_algorithm(self):
        return {
            self.P256: hash_.ES256
        }[self]

    def bit_size(self):
        return {
            self.P256: 256
        }[self]


class ECKey(object):
    def key_type(self):
        return 'EC'

    def pem_block(self):
        return self._key.export_key(format='PEM')

    def crypto_public_key(self):
        return self._key.public_key()

    def marshal_json(self):
        return util.dump_json(self.to_map())

    def key_id(self):
        der_bytes = self.crypto_public_key().export_key(format='DER')
        hash_bytes = SHA256.new(der_bytes).digest()
        return util.key_id_encode(hash_bytes[:30])

    @property
    def curve_name(self):
        return self.curve.value

    @property
    def curve(self):
        return Curves(self.crypto_public_key().curve)

    @property
    def signature_algorithm(self):
        return self.curve.signature_algorithm()


class ECPublicKey(ECKey, PublicKey):
    def __init__(self, key):
        self._key = key

    @classmethod
    def from_pem(cls, key_data):
        public_key = ECC.import_key(key_data)
        return cls(public_key)

    def to_map(self):
        jwk = {
            'kty': self.key_type(),
            'kid': self.key_id(),
            'crv': self.curve_name,
        }
        x_bytes = util.number_to_byte(self._key.pointQ.x)
        y_bytes = util.number_to_byte(self._key.pointQ.y)
        octet_length = (self.curve.bit_size() + 7) >> 3

        x_bytes = '\x00' * (octet_length - len(x_bytes)) + x_bytes
        y_bytes = '\x00' * (octet_length - len(y_bytes)) + y_bytes

        jwk['x'] = util.jose_base64_url_encode(x_bytes)
        jwk['y'] = util.jose_base64_url_encode(y_bytes)
        return jwk


class ECPrivateKey(ECKey, PrivateKey):
    def __init__(self, key):
        self._key = key

    @classmethod
    def from_pem(cls, key_data, passphrase=None):
        # ignore EC PARAMETERS block
        fixed_key_data = key_data[key_data.index('-----BEGIN EC PRIVATE KEY-----'):]
        private_key = ECC.import_key(fixed_key_data, passphrase=passphrase)
        return cls(private_key)

    def public_key(self):
        return ECPublicKey(self.crypto_public_key())

    def to_map(self):
        public_key_map = self.public_key().to_map()
        d_bytes = util.number_to_byte(int(self._key.d))
        octet_length = (len(util.number_to_byte(int(self._key.d) - 1)) + 7) >> 3

        d_bytes = '\x00' * (octet_length - len(d_bytes)) + d_bytes

        private_key_map = {
            'd': util.jose_base64_url_encode(d_bytes)
        }
        private_key_map.update(public_key_map)
        return private_key_map
