from __future__ import unicode_literals

import base64
import datetime
import json
import time

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


def jose_base64_url_decode(data):
    data = data.replace('\n', '')
    data = data.replace(' ', '')
    # illegal when data % 4 == 1
    data += {
        0: '',
        2: '==',
        3: '='
    }[len(data) % 4]
    return base64.urlsafe_b64decode(data.encode('utf-8'))


def serialize_rsa_public_exponent_param(e):
    return cry_utils.int_to_bytes(e).lstrip('\x00')


def dump_json(data, **kwargs):
    kwargs.setdefault('sort_keys', True)
    kwargs.setdefault('separators', (',', ':'))
    return json.dumps(data, **kwargs)


def parse_rsa_modules_params(nb64url):
    n_bytes = jose_base64_url_decode(nb64url)
    return cry_utils.int_from_bytes(n_bytes, 'big')


def parse_rsa_public_exponent_param(eb64url):
    e_bytes = jose_base64_url_decode(eb64url)
    e_bytes = '\x00' * (4 - len(e_bytes)) + e_bytes
    return cry_utils.int_from_bytes(e_bytes, 'big')


def parse_ec_coordinate(cb64url, curve):
    curve_byte_len = (curve.bit_size() + 7) >> 3
    c_bytes = jose_base64_url_decode(cb64url)

    if len(c_bytes) != curve_byte_len:
        raise Exception("invalid number of octets: got %d, should be %d", len(c_bytes), curve_byte_len)
    return cry_utils.int_from_bytes(c_bytes, 'big')


def utc_rfc3339(timestamp=None):
    timestamp = timestamp or time.time()
    date = datetime.datetime.utcfromtimestamp(timestamp)
    return date.strftime('%Y-%m-%dT%H:%M:%SZ')
