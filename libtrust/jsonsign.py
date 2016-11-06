from __future__ import unicode_literals

from libtrust import util


class JsHeader(object):
    def __init__(self, public_key, algorithm, chain):
        self.public_key = public_key
        self.algorithm = algorithm
        self.chain = chain


class JsSignature(object):
    def __init__(self, header, signature, protected):
        self.header = header
        self.signature = signature
        self.protected = protected


class SignKey(object):
    def __init__(self, private_key, chain):
        self.private_key = private_key
        self.chain = chain


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
        payload = util.jose_base64_url_encode(
            util.dump_json(content, indent=3, separators=(',', ': '))
        )
        format_length = len(payload) - 2
        return cls(payload, ' ' * indent, format_length, payload[format_length:])
