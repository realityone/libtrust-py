import base64


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
