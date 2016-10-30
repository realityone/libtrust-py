import StringIO
import unittest

from libtrust import hash as hash_
from libtrust import rsa_key
from tests import fixtures_path


class RSAKeyTest(unittest.TestCase):
    def setUp(self):
        with open(fixtures_path('private.pem'), 'r') as f:
            self.private_key = rsa_key.RSAPrivateKey.from_pem(f.read())
        with open(fixtures_path('public.pem'), 'r') as f:
            self.public_key = rsa_key.RSAPublicKey.from_pem(f.read())

    def test_key_id(self):
        pub_key_key_id = self.public_key.key_id()
        priv_key_id = self.private_key.key_id()
        self.assertEqual('IIYO:OWAZ:MBMG:2SIK:IK2I:OP5Z:H6QR:KN6Y:QUGO:BUWN:TYW3:JXVW', pub_key_key_id)
        self.assertEqual(pub_key_key_id, priv_key_id)

    def test_marshal_json(self):
        pub_key_json = self.public_key.marshal_json()
        priv_key_json = self.private_key.marshal_json()
        pub_key_json_origin = r"""{"e":"AQAB","kid":"IIYO:OWAZ:MBMG:2SIK:IK2I:OP5Z:H6QR:KN6Y:QUGO:BUWN:TYW3:JXVW","kty":"RSA","n":"wq1mCmgn460MC6MnCqranQNTgmKuKPl7bNH7Qc6hBDGHlnIjU6q_h2KXF37TC5Y9tsKvQ4b8jd0Sf0dXFHml8qunSvNnqsSvoD8tSPUKqXS6jrlbGSQXhya7BL1RPGccD5K1xrV73QlI6uFPd3APRQYij5EOB8IOWEQujJk_8Mjc0EC9zvk5TUJb59hkOUPZ3CkvSBNLNS8wpQI98FRnIzHjuaNicqve8054oxmDKifHWy0nnF135cXW8zkH3Zto1q89zD2g-zcVxLcRP84Uhe0nSQyg7vEYl4Wl74Eo6_89qL2yE0mEiQN245ACA5B8WFV_t3j_OD3ydOCaAOg28vQtzcZ1gh2Ev4RxeR7bKq58g-R0-MMwl7nnW29mbCkcgdVVR4YPmglP7Vb6w7_NbqFhnxx4E3A05AeevHdMdYCrtgQwogvIhdOHLcVQxJgwy1d2Lg_mv9rovhCJ7d3XaNEYym6CplCHPMtfnU1LCVkA6b44pFaOVjsAQ8FviFtGXQAToRtwoszSarzslHKYdPoSGFOsgNJgW67iViOYqGPD97rgJA0VPm0POMNHGw_R6o-08KhDF_OI1EDckmjXhUggY_WCqWDxD77Ezd_wr9Zlbv_uSIEL9ifvBLq06lLcXMLrQbJrwMbDrngMZMAcUkTzThmtxNs4uwu45R-zfKc"}"""
        priv_key_json_origin = r"""{"d":"tu9aQ808LqYd-5GEznFenMzTXGJ-ZeKKKOfowx34EIi6cJUwvR5mfEIY2OtERk8YDvVC3KGsEWL8Tr4rBgKJ_k9vFO9FKyNIJb04QKaDLlmSNSvYfvd7ZHTwqLN98tSxebDTP7aqfjqLWqv-kK2sq5_oOiCEnqWr9SWc2GHpw8n8NXWg5y0qu37v_h1JkMZBorDQzVnUAlYlz-kbawrlIB1xcLAngroe92N12U3QA3z9yJ_V6Qmr8S7HniapTYUMLzDdUV9YNri8q-2bN-nfPzprACnt0JqeEUR1eWpVme5vcnFPNPCQqm-m-JAKVG8haaBuM2pv6dnMTCgCj3emqWLVfBoc3qmi1KJT_dG54GRepIyN82jFDByKqQGMMO5_Chf2DlRYQYBrkPI5hIZLvbU-a1K5Uf1wauNpGgiGCEjxiXsYGUPyCjAgMmNwnNjfOO7U5KQQMV1PbEj1iPU0xw_Q7adqKd4UeD_rwaTo00KcH6K7_1pFZP3UrkcQ5de9nI_jULIF7YCPqZxs5_dpK8HGwF5VroYIjyVm5AVh9xaE3sugxf8nsdopLybIwcR7nk2RCibW7ClbsJd7eTrYiuPBI50Lb3I-CLczo6VgvlnnqhVDs_kYDZA9c4j11ayAW7l4zc47cPjK6M-ggvL4zqc2n7Ba0Z2Med07hiNrHwE","dp":"MUMOUuBHrByzXNNEsKXFTOOFvOt_eVSorlL2KTcQQjHTSoxv7jY1yqfx41qNNRn6rlcjwGf3_GLuN5bq8zHX37vDD2O5uQDbDmGZc4W0X4E7ZDAY7UTMi_DONzf7Pu-8pN7mBneeLSuUoL-lduNLzC0b-0kOLHG7WCGA5Y9wJT8_fz9h25Yf8BmCe3peuDMwT5E-RHlnk4epQFno_bVz7ZVawE9EpE7FY3l34JOSKrh0hIIz_w1QmFt1fabSfrueM3igaibrc5DyeRmAT0xtLQUUbuzXvycmU-S6VqOwQET6LEVsCaZKGwzRqXXwSTIsyAdNHTg1Oyqdu1jsxt3u8Q","dq":"fKcxyUxSlDYOBky14bORjN3fEujFMgZd4cdIWIyaCzgWMPZIMAJKRfTguH76Msg2rZQ5sIuUetXfBdF7o7k7Zndl_inNuirRclb3Ggty7wfVddk-qIfbGwX_rsqD_H4hnFj2ARBSZO6MAua99ZWERqHpi50vqwBG-iftm9MDEbyp3qUixqHH765bXcOnm2abHOwD_F_Oj1QXECdh76OteZ_13Gz7e9dz9xn2QeEs4_Sg84LUCTDcfy42uGRMx2kKHzUEGh120tqLY5X0sRG8wgUgA4e-By-yAXODjCbApfxFCz1ObCVwJqXmCk66nTp1n1X2du11ht4SWouOooM83Q","e":"AQAB","kid":"IIYO:OWAZ:MBMG:2SIK:IK2I:OP5Z:H6QR:KN6Y:QUGO:BUWN:TYW3:JXVW","kty":"RSA","n":"wq1mCmgn460MC6MnCqranQNTgmKuKPl7bNH7Qc6hBDGHlnIjU6q_h2KXF37TC5Y9tsKvQ4b8jd0Sf0dXFHml8qunSvNnqsSvoD8tSPUKqXS6jrlbGSQXhya7BL1RPGccD5K1xrV73QlI6uFPd3APRQYij5EOB8IOWEQujJk_8Mjc0EC9zvk5TUJb59hkOUPZ3CkvSBNLNS8wpQI98FRnIzHjuaNicqve8054oxmDKifHWy0nnF135cXW8zkH3Zto1q89zD2g-zcVxLcRP84Uhe0nSQyg7vEYl4Wl74Eo6_89qL2yE0mEiQN245ACA5B8WFV_t3j_OD3ydOCaAOg28vQtzcZ1gh2Ev4RxeR7bKq58g-R0-MMwl7nnW29mbCkcgdVVR4YPmglP7Vb6w7_NbqFhnxx4E3A05AeevHdMdYCrtgQwogvIhdOHLcVQxJgwy1d2Lg_mv9rovhCJ7d3XaNEYym6CplCHPMtfnU1LCVkA6b44pFaOVjsAQ8FviFtGXQAToRtwoszSarzslHKYdPoSGFOsgNJgW67iViOYqGPD97rgJA0VPm0POMNHGw_R6o-08KhDF_OI1EDckmjXhUggY_WCqWDxD77Ezd_wr9Zlbv_uSIEL9ifvBLq06lLcXMLrQbJrwMbDrngMZMAcUkTzThmtxNs4uwu45R-zfKc","p":"6ql31IHaMnhXtM0Bv13awqXzujVMfdzVEpBA1NEGdiiEaroLlfpX6tHmrlJnYEJjEk5pwXldTcu5fOBgphEZ985VR8O7nOhxtsYNt0RJe_34SSeUeZNK2kCSB-4uy8TSICUepzL1e59sj7pzHXNz6fxbG-SjGk8dUphgS1QsmJGsFw1hcjYs_yvGfAPpRb0Y8qs4yM3yeKLKq-qW3IFjiAsrrw7w2IEXmUQgyXhdv9DySSPr7WrDL2AV5yV6WouloDABPhlV-ZtCsIvN_5Eu9GTN8kEZ3TiOg7j2IFcP0MKanPbQT4ivYXIAfS7Pt2cVlpwGfCxBtaRk425rGZ3viQ","q":"1GEn69ysWOsGN-U_R9ifaK7RsrfssRsjr7FE_KpWfXqBaUaKLYL6DUc3J4RIr9IP4MQw9gMl6TOXI16G-d6jXtsKODIFHGvkWTxs_iPkOWnBPTTHgklCIdev9MfVxctN-dB_UI6ayEZ_mooWoUQYaZEEwxHRY1Xn0VpWJMSCGfQf3FJEoI3u5HnWaz_HjrCDbJ7u0ZyXJdUn_-IXjZFDsTz_lwaq_dmVsW2KcOVASKHIBGQXdAGwN6fe7XO3MJvLt9oB4mGgCKJgON8IJx9OF0CplF66QmduIAIptnYzwYbeTtcU1y0IAApOj0dj3jmnOzBXnYdbZ7L3mu7glnlOrw","qi":"Qh5chO-_2sdaREPCXOGXMMmw2Ajci-rKAE9HFWaWXSRaduf_P_tPaBV4V4wnFsw6MYaZECgK1wW-u2FpYWdCWF1AyeSIx7egATmfwdpHDPF9ebjSneem9KNhrPPc0MXmYR--cPAVhgtvTq4IV-x32kDUWJQN6VTgvwWmFjL7lrxiq30_TyYopi2pqinnFRGuMj8gWDRi_YmOwrii49t6mmteYS48R8H59DqazVqXIMMc2nIUt9LZs5QGzpoYkyBsMdCIFmJV5mHFeCxVD6S5-3rvD_fCSiCRT94YQbYdHkKQnn3JpUmnpIwraBxNJErjRs-PRTAzMSAts-im_bCAXQ"}"""
        self.assertEqual(pub_key_json_origin, pub_key_json)
        self.assertEqual(priv_key_json_origin, priv_key_json)

    def test_sign(self):
        message = StringIO.StringIO('Hello, World!')
        sig_algs = (hash_.RS256, hash_.RS384, hash_.RS512)
        origin_sig = (
            [47, 53, 27, 154, 98, 40, 87, 246, 73, 49, 80, 241, 186, 20, 180, 75, 78, 152, 83, 140, 12, 163, 134, 214, 100, 92,
             80, 104, 65, 36, 88, 234, 166, 131, 135, 85, 242, 96, 111, 191, 36, 177, 18, 245, 217, 173, 194, 139, 87, 220, 104,
             213, 79, 205, 31, 137, 79, 137, 147, 45, 127, 139, 137, 234, 161, 175, 64, 21, 215, 232, 237, 138, 115, 212, 216,
             219, 100, 104, 189, 113, 59, 169, 99, 43, 227, 122, 155, 51, 250, 244, 53, 247, 99, 249, 174, 72, 175, 131, 122, 166,
             198, 148, 48, 54, 71, 15, 210, 18, 156, 57, 34, 107, 74, 76, 224, 62, 227, 228, 208, 139, 153, 252, 142, 37, 73, 54,
             163, 165, 230, 12, 37, 54, 188, 147, 82, 239, 96, 56, 71, 10, 199, 180, 44, 213, 111, 101, 163, 246, 162, 239, 105,
             2, 46, 121, 142, 153, 6, 90, 161, 254, 244, 52, 168, 82, 215, 181, 9, 237, 84, 116, 131, 38, 145, 126, 148, 44, 170,
             119, 2, 9, 26, 184, 7, 86, 93, 22, 129, 63, 211, 196, 92, 219, 164, 168, 76, 76, 78, 1, 244, 172, 142, 134, 162, 75,
             253, 236, 138, 193, 182, 16, 224, 2, 109, 2, 62, 40, 173, 30, 205, 99, 97, 189, 245, 136, 84, 196, 172, 52, 151, 208,
             101, 228, 184, 90, 208, 73, 202, 81, 6, 22, 134, 141, 124, 186, 110, 227, 68, 145, 253, 244, 2, 154, 242, 33, 147,
             115, 206, 138, 102, 88, 223, 184, 2, 193, 56, 170, 9, 5, 116, 22, 205, 36, 152, 51, 196, 35, 19, 54, 2, 23, 93, 120,
             215, 107, 137, 79, 79, 186, 151, 186, 252, 146, 100, 47, 217, 232, 197, 218, 164, 16, 208, 37, 123, 126, 158, 103,
             221, 111, 92, 24, 172, 223, 219, 136, 196, 20, 91, 163, 152, 195, 97, 155, 237, 11, 143, 98, 74, 30, 182, 186, 255,
             24, 212, 138, 252, 41, 121, 169, 166, 125, 108, 116, 15, 71, 175, 241, 238, 22, 163, 149, 184, 244, 99, 193, 77, 242,
             201, 20, 133, 41, 32, 26, 112, 48, 250, 148, 117, 80, 69, 179, 119, 202, 250, 204, 151, 196, 94, 25, 191, 40, 173,
             60, 116, 234, 159, 37, 59, 43, 223, 253, 98, 31, 103, 243, 140, 150, 132, 252, 244, 88, 69, 158, 56, 86, 57, 58, 189,
             80, 164, 213, 93, 169, 112, 231, 153, 150, 37, 185, 153, 94, 2, 104, 146, 146, 141, 80, 104, 129, 37, 74, 184, 8,
             179, 228, 59, 79, 156, 19, 47, 193, 13, 238, 187, 220, 133, 176, 150, 13, 140, 162, 84, 217, 248, 66, 101, 206, 203,
             8, 218, 106, 97, 102, 194, 106, 56, 86, 40, 64, 183, 16, 94, 127, 232, 119, 69, 56, 44, 182, 215, 34, 124, 167, 42,
             125, 8, 172, 19, 144, 143, 166, 145, 24, 18, 167, 9, 231, 227, 83, 29, 149, 174, 184, 195, 106, 38, 97, 197, 175,
             206, 155, 172, 157],
            [78, 220, 151, 16, 42, 6, 220, 1, 70, 30, 1, 181, 74, 193, 140, 54, 28, 26, 140, 60, 153, 128, 54, 68, 202, 42, 218,
             127, 230, 140, 60, 120, 92, 229, 32, 15, 178, 123, 253, 132, 100, 54, 96, 6, 30, 148, 5, 168, 106, 48, 88, 244, 134,
             192, 189, 225, 67, 96, 8, 210, 8, 12, 135, 250, 172, 255, 113, 1, 2, 126, 25, 173, 76, 96, 193, 165, 217, 109, 229,
             15, 96, 200, 68, 42, 167, 164, 224, 84, 210, 4, 180, 56, 104, 245, 119, 24, 16, 31, 235, 1, 150, 181, 25, 11, 201,
             29, 48, 206, 223, 54, 191, 246, 29, 127, 86, 137, 136, 84, 140, 172, 51, 240, 95, 156, 41, 245, 86, 215, 92, 50, 237,
             74, 211, 31, 85, 41, 14, 142, 128, 213, 229, 29, 224, 163, 252, 102, 9, 148, 216, 128, 190, 143, 150, 208, 12, 231,
             81, 105, 167, 161, 192, 65, 98, 28, 248, 215, 193, 167, 48, 196, 80, 156, 114, 134, 216, 231, 95, 232, 47, 117, 40,
             110, 39, 247, 53, 61, 201, 216, 47, 149, 153, 39, 246, 86, 255, 79, 134, 55, 254, 187, 111, 235, 87, 44, 55, 85, 108,
             144, 36, 137, 201, 43, 145, 216, 30, 221, 18, 101, 128, 105, 162, 50, 20, 92, 42, 121, 142, 232, 159, 20, 37, 136,
             64, 160, 21, 216, 201, 49, 146, 43, 22, 92, 169, 162, 189, 7, 218, 50, 235, 246, 238, 212, 102, 153, 38, 218, 194, 4,
             103, 168, 53, 50, 148, 94, 120, 216, 134, 122, 45, 40, 170, 27, 154, 248, 162, 18, 147, 182, 138, 209, 1, 50, 114,
             182, 215, 132, 104, 186, 58, 97, 0, 163, 249, 105, 170, 254, 76, 26, 161, 247, 51, 195, 4, 151, 230, 32, 253, 120,
             48, 155, 74, 168, 158, 222, 142, 17, 253, 62, 68, 46, 69, 145, 204, 188, 41, 194, 184, 210, 211, 146, 228, 116, 143,
             239, 131, 203, 63, 89, 234, 129, 29, 122, 48, 131, 8, 103, 36, 110, 9, 126, 30, 85, 211, 153, 170, 125, 79, 29, 244,
             213, 121, 12, 144, 142, 182, 165, 179, 198, 245, 86, 173, 0, 96, 189, 195, 129, 39, 37, 60, 13, 98, 112, 222, 134,
             153, 12, 10, 194, 223, 166, 232, 122, 0, 162, 80, 35, 164, 253, 34, 19, 237, 177, 229, 141, 227, 166, 108, 183, 49,
             246, 204, 17, 45, 218, 30, 73, 162, 189, 167, 204, 142, 68, 3, 194, 213, 38, 79, 194, 55, 195, 29, 192, 99, 135, 72,
             24, 215, 8, 155, 97, 88, 9, 185, 187, 236, 217, 34, 156, 28, 111, 221, 209, 110, 163, 20, 90, 163, 251, 15, 40, 19,
             226, 233, 115, 243, 36, 96, 180, 122, 90, 191, 203, 34, 32, 106, 34, 239, 24, 17, 89, 36, 221, 190, 246, 225, 141,
             212, 200, 15, 11, 192, 11, 105, 83, 138, 98, 64, 177, 1, 71, 67, 105, 239, 164, 161, 123, 92, 21, 67, 51, 177, 161],
            [47, 17, 171, 73, 252, 150, 144, 127, 249, 242, 4, 175, 7, 192, 226, 130, 145, 236, 156, 65, 61, 231, 21, 197, 174,
             141, 59, 93, 13, 51, 155, 30, 3, 153, 0, 68, 220, 36, 252, 141, 0, 208, 226, 92, 71, 16, 159, 46, 3, 61, 144, 110,
             103, 38, 85, 131, 45, 31, 219, 8, 27, 117, 72, 101, 124, 60, 44, 105, 194, 104, 183, 214, 101, 180, 235, 72, 144,
             230, 109, 103, 55, 215, 67, 189, 183, 9, 48, 206, 49, 211, 39, 118, 80, 192, 141, 48, 226, 250, 118, 255, 236, 163,
             20, 207, 213, 158, 5, 12, 200, 163, 201, 51, 253, 34, 91, 75, 41, 30, 67, 48, 161, 75, 44, 70, 45, 31, 76, 179, 171,
             136, 202, 20, 200, 227, 2, 18, 98, 197, 93, 13, 121, 181, 59, 92, 16, 204, 27, 123, 29, 43, 37, 246, 236, 43, 40,
             173, 216, 255, 181, 85, 117, 193, 200, 208, 208, 171, 95, 103, 175, 188, 120, 159, 201, 142, 160, 4, 200, 14, 219,
             128, 142, 70, 147, 229, 175, 39, 46, 142, 66, 98, 164, 103, 239, 197, 108, 28, 202, 27, 210, 63, 118, 127, 178, 137,
             77, 209, 208, 34, 84, 56, 197, 181, 80, 243, 186, 132, 96, 20, 251, 28, 151, 179, 6, 140, 184, 204, 121, 89, 227, 51,
             225, 175, 160, 188, 157, 253, 72, 184, 241, 225, 210, 231, 82, 35, 139, 228, 177, 51, 178, 49, 101, 181, 196, 141,
             98, 55, 192, 210, 193, 224, 35, 113, 233, 219, 93, 185, 205, 173, 86, 128, 51, 149, 206, 161, 104, 67, 191, 146, 46,
             219, 213, 67, 144, 254, 101, 63, 171, 65, 215, 203, 10, 19, 112, 4, 104, 11, 162, 132, 247, 157, 141, 103, 231, 133,
             98, 127, 116, 97, 250, 170, 130, 79, 214, 239, 242, 169, 33, 114, 218, 76, 184, 46, 12, 64, 104, 236, 61, 238, 159,
             163, 36, 33, 170, 168, 77, 25, 103, 238, 63, 84, 203, 11, 214, 148, 61, 181, 205, 72, 87, 229, 46, 207, 119, 173,
             215, 187, 153, 193, 227, 212, 8, 182, 28, 153, 25, 33, 234, 78, 57, 20, 242, 28, 131, 234, 232, 26, 155, 215, 41, 89,
             209, 7, 103, 241, 47, 226, 155, 12, 135, 152, 93, 92, 243, 38, 150, 45, 114, 252, 120, 126, 25, 131, 173, 89, 84,
             208, 117, 186, 252, 168, 134, 128, 205, 203, 176, 29, 203, 142, 218, 61, 67, 126, 182, 66, 157, 248, 246, 246, 189,
             233, 127, 67, 249, 158, 218, 83, 239, 52, 211, 201, 162, 101, 113, 1, 220, 113, 251, 102, 213, 22, 241, 63, 201, 193,
             62, 98, 156, 119, 144, 98, 22, 40, 255, 158, 224, 236, 248, 170, 206, 186, 231, 11, 205, 167, 107, 33, 4, 151, 95,
             212, 39, 128, 6, 140, 99, 131, 114, 219, 65, 198, 12, 46, 169, 236, 123, 64, 105, 76, 59, 233, 250, 249, 82, 201,
             174, 137, 79, 123, 111, 191, 241, 39]
        )

        for i, sa in enumerate(sig_algs):
            message.seek(0)
            sig, alg = self.private_key.sign(message, sa.hash_id)

            message.seek(0)
            self.assertTrue(self.public_key.verify(message, alg, sig))

            self.assertEqual(origin_sig[i], [ord(c) for c in sig])
