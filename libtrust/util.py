import base64
import json

from cryptography import utils as cry_utils


def key_id_encode(hash_bytes):
    s = base64.b32encode(hash_bytes).rstrip('=')
    block_size = 4
    result = ':'.join((s[i:i + block_size] for i in range(0, len(s), block_size)))
    remain = len(s) % block_size
    if remain:
        result += s[-remain:]
    return result


def jose_base64_url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip('=')


def serialize_rsa_public_exponent_param(e):
    return cry_utils.int_to_bytes(e).lstrip('\x00')


def dump_json(data, **kwargs):
    kwargs.setdefault('sort_keys', True)
    kwargs.setdefault('separators', (',', ':'))
    return json.dumps(data, **kwargs)
