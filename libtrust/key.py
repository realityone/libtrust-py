from __future__ import unicode_literals

import json


class PublicKey(object):
    def key_type(self):
        raise NotImplementedError()

    def key_id(self):
        raise NotImplementedError()

    def crypto_public_key(self):
        raise NotImplementedError()

    def pem_block(self):
        raise NotImplementedError()

    def marshal_json(self):
        raise NotImplementedError()

    def verify(self, buffer, alg, signature):
        raise NotImplementedError()


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
