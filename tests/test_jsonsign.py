from __future__ import unicode_literals

import unittest

from libtrust import jsonsign


class JSONSignTest(unittest.TestCase):
    def test_from_map(self):
        content = {
            'hello': '123'
        }
        js = jsonsign.JSONSignature.from_map(content)
        self.assertEqual('ewogICAiaGVsbG8iOiAiMTIzIgp9', js.payload)
        self.assertEqual('eyJmb3JtYXRMZW5ndGgiOjE5LCJmb3JtYXRUYWlsIjoiQ24wIiwidGltZSI6IjIwMTYtMTEtMDZUMDk6MDQ6MzJaIn0',
                         js.protected_header(timestamp=1478423072))
