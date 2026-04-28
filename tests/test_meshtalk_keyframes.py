import os
import unittest


class TestKeyFrames(unittest.TestCase):
    def test_parse_key_frame_hello(self):
        import meshTalk
        from meshtalk.mt2_frames import build_hello_frame

        nonce = b"ABCD"
        payload = build_hello_frame(nonce)
        kind, pub, got_nonce = meshTalk.parse_key_frame(payload)
        self.assertEqual(kind, "hello")
        self.assertIsNone(pub)
        self.assertEqual(got_nonce, nonce)

    def test_parse_key_frame_kr1_kr2(self):
        import meshTalk
        from meshtalk.mt2_frames import build_kr1_frame, build_kr2_frame

        pub = bytes(range(32))
        nonce = b"WXYZ"
        kr1 = build_kr1_frame(pub, nonce)
        kr2 = build_kr2_frame(pub, nonce)
        kind1, pub1, n1 = meshTalk.parse_key_frame(kr1)
        kind2, pub2, n2 = meshTalk.parse_key_frame(kr2)
        self.assertEqual(kind1, "req")
        self.assertEqual(kind2, "resp")
        self.assertEqual(pub1, pub)
        self.assertEqual(pub2, pub)
        self.assertEqual(n1, nonce)
        self.assertEqual(n2, nonce)

    def test_parse_key_frame_reject_wrong_magic_or_ver(self):
        import meshTalk
        from meshtalk.mt2_frames import MT2_MAGIC, MT2_F_KR1

        # Wrong magic
        self.assertIsNone(meshTalk.parse_key_frame(b"XX" + b"\x00" * 10))
        # Wrong version
        pub = b"\x11" * 32
        nonce = b"1234"
        bad = MT2_MAGIC + bytes([MT2_F_KR1, 99, 0]) + pub + nonce
        self.assertIsNone(meshTalk.parse_key_frame(bad))


if __name__ == "__main__":
    unittest.main()
