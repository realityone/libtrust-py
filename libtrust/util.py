import base64
import json

from Crypto.Math.Numbers import Integer


def key_id_encode(hash_bytes):
    s = base64.b32encode(hash_bytes).rstrip('=')
    result = []
    i = 0
    for i in xrange(len(s) / 4 - 1):
        start = i * 4
        end = start + 4
        result.append(s[start:end])
    result.append(s[(i + 1) * 4:])
    return ':'.join(result)


def jose_base64_url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip('=')


def number_to_byte(number):
    return Integer(number).to_bytes()


def serialize_rsa_public_exponent_param(e):
    return Integer(e).to_bytes().lstrip('\x00')


def dump_json(data, **kwargs):
    kwargs.setdefault('sort_keys', True)
    kwargs.setdefault('separators', (',', ':'))
    return json.dumps(data, **kwargs)


def inverse_number(x, m):
    return int(Integer(x).inverse(m))
