import enum
from Crypto.Hash import MD5
from Crypto.Hash import SHA1
from Crypto.Hash import SHA224
from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Hash import SHA512


class HashID(enum.Enum):
    MD5 = 2
    SHA1 = 3
    SHA224 = 4
    SHA256 = 5
    SHA384 = 6
    SHA512 = 7

    @property
    def hash_func(self):
        return {
            self.MD5: MD5,
            self.SHA1: SHA1,
            self.SHA224: SHA224,
            self.SHA256: SHA256,
            self.SHA384: SHA384,
            self.SHA512: SHA512,
        }[self]

    @classmethod
    def iterkeys(cls):
        for k in cls._value2member_map_.keys():
            yield k


class SignatureAlgorithm(object):
    def __init__(self, alg_header_param, hash_id):
        self.alg_header_param = alg_header_param
        self.hash_id = hash_id

    def header_param(self):
        return self.alg_header_param

    def hasher(self):
        return self.hash_id.hash_func.new()


RS256 = SignatureAlgorithm('RS256', HashID.SHA256)
RS384 = SignatureAlgorithm('RS384', HashID.SHA384)
RS512 = SignatureAlgorithm('RS512', HashID.SHA512)
ES256 = SignatureAlgorithm('ES256', HashID.SHA256)
ES384 = SignatureAlgorithm('ES384', HashID.SHA384)
ES512 = SignatureAlgorithm('ES512', HashID.SHA512)


def rsa_signature_algorithm_by_name(alg):
    signature_algorithms = {
        'RS256': RS256,
        'RS384': RS384,
        'RS512': RS512
    }
    if alg not in signature_algorithms:
        raise NotImplementedError("RSA Digital Signature Algorithm {} not supported".format(alg))
    return signature_algorithms[alg]


def rsa_pkcs1v15_signature_algorithm_for_hash_id(hash_id):
    signature_algorithms = {
        HashID.SHA512: RS512,
        HashID.SHA384: RS384,
    }
    return signature_algorithms.get(hash_id, RS256)
