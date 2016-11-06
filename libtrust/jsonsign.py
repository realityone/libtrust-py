from __future__ import unicode_literals


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
    def __init__(self, payload, signatures, indent, format_length, format_tail):
        self.payload = payload
        self.signatures = signatures
        self.indent = indent
        self.format_length = format_length
        self.format_tail = format_tail
