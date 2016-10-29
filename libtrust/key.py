class PublicKey(object):
    def key_type(self):
        raise NotImplementedError()

    def key_id(self):
        raise NotImplementedError()

    def crypto_public_key(self):
        raise NotImplementedError()

    def pem_block(self):
        raise NotImplementedError()

    def marshal_json(self):
        raise NotImplementedError()


class PrivateKey(PublicKey):
    def public_key(self):
        raise NotImplementedError()

    def crypto_private_key(self):
        raise NotImplementedError()
