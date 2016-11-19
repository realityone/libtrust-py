from __future__ import unicode_literals

import collections
import json

from libtrust import util

__all__ = ['unmarshal_public_key_jwk']


class PublicKey(object):
    def key_type(self):
        raise NotImplementedError()

    def key_id(self):
        raise NotImplementedError()

    def crypto_public_key(self):
        raise NotImplementedError()

    def pem_block(self):
        raise NotImplementedError()

    def to_map(self):
        raise NotImplementedError()

    def verify(self, buffer, alg, signature):
        raise NotImplementedError()

    def marshal_json(self):
        return util.dump_json(self.to_map())

    def json(self):
        return collections.OrderedDict(sorted(self.to_map().items(), key=lambda item: item[0]))


class PrivateKey(PublicKey):
    def public_key(self):
        raise NotImplementedError()

    def crypto_private_key(self):
        raise NotImplementedError()

    def sign(self, buffer, hash_id):
        raise NotImplementedError()


def unmarshal_public_key_jwk(data):
    from libtrust import ec_key
    from libtrust import rsa_key

    jwk = json.loads(data)

    kty = jwk['kty']
    return {
        'EC': ec_key.ec_public_key_from_map(jwk),
        'RSA': rsa_key.rsa_public_key_from_map(jwk)
    }[kty]
