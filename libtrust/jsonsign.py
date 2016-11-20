from __future__ import unicode_literals

import StringIO
import collections
import json

from . import hash as hash_
from . import util

namedtuple = collections.namedtuple


def detect_json_indent(json_content):
    indent = ''
    if len(json_content) > 2 and json_content[0] == '{' and json_content[1] == '\n':
        quote_index = json_content[1:].find('"')
        if quote_index > 0:
            indent = json_content[2:quote_index + 1]
        return indent


class JSONSignError(Exception):
    pass


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if hasattr(o, 'json'):
            return o.json()
        return super(JSONEncoder, self).default(o)


class JsHeader(object):
    def __init__(self, jwk, algorithm, chain=None):
        super(JsHeader, self).__init__()
        chain = chain or []
        self.jwk = jwk
        self.algorithm = algorithm
        self.chain = chain

    def json(self):
        data = collections.OrderedDict((
            ('jwk', self.jwk),
            ('alg', self.algorithm),
        ))
        if self.chain:
            data['chain'] = self.chain
        return data

    @classmethod
    def from_map(cls, header_map):
        from libtrust.key import parse_public_key_jwk

        jwk = parse_public_key_jwk(header_map['jwk'])
        algorithm = header_map['alg']
        chain = header_map.get('chain')
        return cls(jwk, algorithm, chain=chain)


class JsSignature(object):
    def __init__(self, header, signature, protected):
        super(JsSignature, self).__init__()
        self.header = header
        self.signature = signature
        self.protected = protected

    def json(self):
        return collections.OrderedDict((
            ('header', self.header),
            ('signature', self.signature),
            ('protected', self.protected)
        ))

    @classmethod
    def from_map(cls, js_signature_map):
        header = JsHeader.from_map(js_signature_map['header'])
        signature = js_signature_map['signature']
        protected = js_signature_map['protected']
        return cls(header, signature, protected)


class SignKey(object):
    def __init__(self, private_key, chain):
        super(SignKey, self).__init__()
        self.private_key = private_key
        self.chain = chain

    def json(self):
        return collections.OrderedDict((
            ('private_key', self.private_key),
            ('chain', self.chain)
        ))


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
        payload = util.dump_json(content, indent=indent, separators=(',', ': '))
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
            sign_bytes = self.sign_bytes(sign.protected)
            if sign.header.chain:
                raise NotImplementedError()
            elif sign.header.jwk:
                public_key = sign.header.jwk
            else:
                raise JSONSignError("missing public key")

            sig_bytes = util.jose_base64_url_decode(sign.signature)

            try:
                public_key.verify(StringIO.StringIO(sign_bytes), sign.header.algorithm, sig_bytes)
            except Exception as e:
                raise e

            keys.append(public_key)

        return keys

    def jws(self):
        if not self.signatures:
            raise JSONSignError("missing signature")

        self.signatures.sort()
        json_map = collections.OrderedDict((
            ('payload', self.payload),
            ('signatures', self.signatures)
        ))
        return util.dump_json(json_map, sort_keys=False, indent=self.indent.count(' '), separators=(',', ': '), cls=JSONEncoder)

    @classmethod
    def new_json_signature(cls, content, *signatures):
        indent = detect_json_indent(content)
        payload = util.jose_base64_url_encode(content)

        not_space = lambda c: c not in ('\t', '\n', '\v', '\f', '\r', ' ', '\x85', '\xa0')
        last_index_func = lambda d, f: len(d) - next((i for i, c in enumerate(d[::-1]) if f(c)), -1) - 1

        close_index = last_index_func(content, not_space)
        if content[close_index] != '}':
            raise JSONSignError("invalid json content")

        last_rune_index = last_index_func(content[:close_index], not_space)
        if content[last_rune_index] == ',':
            raise JSONSignError("invalid json content")

        format_length = last_rune_index + 1
        format_tail = content[format_length:]

        signatures = [JsSignature.from_map(sign) for sign in signatures]

        js = cls(payload, indent, format_length, format_tail, signatures=signatures)
        return js

    @classmethod
    def parse_jws(cls, content):
        parsed = json.loads(content)
        for f in ('payload', 'signatures'):
            if f not in parsed:
                raise JSONSignError("field `{}` missed".format(f))

        if not parsed['signatures']:
            raise JSONSignError("missing signatures")

        payload = util.jose_base64_url_decode(parsed['payload'])
        js = cls.new_json_signature(payload, *parsed.get('signatures', []))
        return js
