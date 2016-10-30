from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from libtrust import hash as hash_
from libtrust import key
from libtrust import util

PublicKey = key.PublicKey
PrivateKey = key.PrivateKey


class ECKey(object):
    curve_to_signature_algorithm = {
        'P-256': hash_.ES256,
    }

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
        return self.crypto_public_key().curve

    @property
    def signature_algorithm(self):
        return self.curve_to_signature_algorithm[self.curve_name]


class ECPublicKey(ECKey, PublicKey):
    def __init__(self, key):
        self._key = key

    @classmethod
    def from_pem(cls, key_data):
        public_key = ECC.import_key(key_data)
        return cls(public_key)


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
