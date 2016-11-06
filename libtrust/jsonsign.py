from __future__ import unicode_literals

import StringIO
import collections

from libtrust import hash as hash_
from libtrust import util

namedtuple = collections.namedtuple


class JsHeader(namedtuple('_JsHeader', ['public_key', 'algorithm', 'chain'])):
    @staticmethod
    def __new__(cls, public_key, algorithm, chain=None):
        chain = chain or []
        return super(JsHeader, cls).__new__(cls, public_key, algorithm, chain)


class JsSignature(namedtuple('_JsSignature', ['header', 'signature', 'protected'])):
    pass


class SignKey(namedtuple('_SignKey', ['private_key', 'chain'])):
    pass


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
