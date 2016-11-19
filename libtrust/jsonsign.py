from __future__ import unicode_literals

import StringIO
import collections

from libtrust import hash as hash_
from libtrust import util

namedtuple = collections.namedtuple


class JSONSignError(Exception):
    pass


class JsHeader(dict):
    def __init__(self, jwk, algorithm, chain=None):
        super(JsHeader, self).__init__()
        chain = chain or []
        self['jwk'] = jwk
        self['algorithm'] = algorithm
        self['chain'] = chain


class JsSignature(dict):
    def __init__(self, header, signature, protected):
        super(JsSignature, self).__init__()
        self['header'] = header
        self['signature'] = signature
        self['protected'] = protected


class SignKey(dict):
    def __init__(self, private_key, chain):
        super(SignKey, self).__init__()
        self['private_key'] = private_key
        self['chain'] = chain


class JSONSignature(object):
    def __init__(self, payload, indent, format_length, format_tail, signatures=None):
        self.payload = payload
        self.indent = indent
        self.format_length = format_length
        self.format_tail = format_tail
        self.signatures = signatures or []

    @classmethod
    def from_map(cls, content):
        indent = 3
        payload = util.dump_json(content, indent=3, separators=(',', ': '))
        payload_b64url = util.jose_base64_url_encode(payload)
        format_length = len(payload) - 2
        return cls(payload_b64url, ' ' * indent, format_length, payload[format_length:])

    def protected_header(self, timestamp=None):
        protected = {
            'formatLength': self.format_length,
            'formatTail': util.jose_base64_url_encode(self.format_tail),
            'time': util.utc_rfc3339(timestamp=timestamp)
        }
        return util.jose_base64_url_encode(util.dump_json(protected))

    def sign_bytes(self, protected):
        return '{}.{}'.format(protected, self.payload).encode('utf-8')

    def sign(self, private_key, timestamp=None):
        protected = self.protected_header(timestamp=timestamp)
        sign_bytes = StringIO.StringIO(self.sign_bytes(protected))

        sig_bytes, algorithm = private_key.sign(sign_bytes, hash_.HashID.SHA256)
        self.signatures.append(
            JsSignature(
                JsHeader(
                    private_key.public_key(),
                    algorithm
                ),
                util.jose_base64_url_encode(sig_bytes),
                protected
            )
        )
        return sig_bytes, algorithm

    def verify(self):
        keys = []
        for sign in self.signatures:
            sign_bytes = self.sign_bytes(sign['protected'])
            if sign['header']['chain']:
                raise NotImplementedError()
            elif sign['header']['jwk']:
                public_key = sign['header']['jwk']
            else:
                raise JSONSignError("missing public key")

            sig_bytes = util.jose_base64_url_decode(sign['signature'])

            try:
                public_key.verify(StringIO.StringIO(sign_bytes), sign['header']['algorithm'], sig_bytes)
            except Exception as e:
                raise e

            keys.append(public_key)

        return keys
