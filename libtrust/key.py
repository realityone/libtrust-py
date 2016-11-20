from __future__ import unicode_literals

import collections

from . import util

__all__ = ['parse_public_key_jwk']


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


def parse_public_key_jwk(jwk):
    from libtrust import ec_key
    from libtrust import rsa_key

    kty = jwk['kty']
    return {
        'EC': ec_key.ec_public_key_from_map,
        'RSA': rsa_key.rsa_public_key_from_map
    }[kty](jwk)
