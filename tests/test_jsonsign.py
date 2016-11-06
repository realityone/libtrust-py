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
