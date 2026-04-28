import unittest


class TestMT2Frames(unittest.TestCase):
    def test_build_and_parse_hello(self):
        from meshtalk.mt2_frames import build_hello_frame, parse_mt2_frame

        frame = build_hello_frame(b"abcd")
        kind, pub, nonce4 = parse_mt2_frame(frame)
        self.assertEqual(kind, "hello")
        self.assertIsNone(pub)
        self.assertEqual(nonce4, b"abcd")

    def test_build_and_parse_kr1_kr2(self):
        from meshtalk.mt2_frames import build_kr1_frame, build_kr2_frame, parse_mt2_frame

        pub = bytes(range(32))
        n = b"\x01\x02\x03\x04"
        kr1 = build_kr1_frame(pub, n)
        kr2 = build_kr2_frame(pub, n)
        self.assertEqual(parse_mt2_frame(kr1), ("req", pub, n))
        self.assertEqual(parse_mt2_frame(kr2), ("resp", pub, n))

    def test_parse_mt2_frame_rejects_bad(self):
        from meshtalk.mt2_frames import parse_mt2_frame

        self.assertIsNone(parse_mt2_frame(b""))
        self.assertIsNone(parse_mt2_frame(b"XX\x00\x00\x00"))
        self.assertIsNone(parse_mt2_frame(b"MT\x10\x02\x00abcd"))  # wrong ver
        self.assertIsNone(parse_mt2_frame(b"MT\x10\x01"))  # truncated hello
        self.assertIsNone(parse_mt2_frame(b"MT\x10\x01\x00abcdX"))  # overlong hello
        # KR1/KR2 are fixed-size frames in v2 and must reject trailing bytes.
        self.assertIsNone(parse_mt2_frame(b"MT\x01\x01\x00" + (b"A" * 32) + b"abcdX"))
        self.assertIsNone(parse_mt2_frame(b"MT\x02\x01\x00" + (b"A" * 32) + b"abcdX"))


if __name__ == "__main__":
    unittest.main()
