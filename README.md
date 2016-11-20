# libtrust-py

Integrate [docker/libtrust](https://github.com/docker/libtrust) with python.

However libtrust has been deprecated, sign/verify manifest with docker distribution in python still cause great suffering.

## Usage

### Install

You can install from PyPi.

```shell
$ pip install libtrust-py
```

Or install from GitHub for latest version.

```shell
$ pip install https://github.com/realityone/libtrust-py/archive/master.zip
```

### Sign & Verify

```python
from libtrust import rsa_key
from libtrust import jsonsign

pem_data = """-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
"""

# Sign Content
# Content may be is the manifest
content = {
    'hello': '123456'
}
js = jsonsign.JSONSignature.from_map(content)
rsa_private_key = rsa_key.RSAPrivateKey.from_pem(pem_data)
js.sign(rsa_private_key, timestamp=1478423072)

# Get jws
jws = js.jws()

# Parse from jws
js2 = jsonsign.JSONSignature.parse_jws(jws)
jws2 = js2.jws()

print jws, jws2, jws == jws2

# Verify jws
print js.verify() == js2.verify()
```

## Reference

- [docker/libtrust](https://github.com/docker/libtrust)