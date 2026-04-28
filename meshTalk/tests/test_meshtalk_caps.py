import unittest


class TestCapsFrameParsing(unittest.TestCase):
    def test_parse_caps_frame_ok_filters_and_truncates(self):
        # Import inside tests to avoid importing PySide during test collection in some envs.
        from meshTalk import parse_caps_frame

        pt = (
            b"CP1|wire=2|msg=1,2|mc=1|aad=aesgcm|unknown=x|"
            b"aad=" + (b"a" * 200)
        )
        caps = parse_caps_frame(pt)
        self.assertIsInstance(caps, dict)
        # Only allow-listed keys are kept.
        self.assertEqual(set(caps.keys()), {"wire", "msg", "mc", "aad"})
        # Values are preserved (stringified), but long values are truncated to keep logs safe.
        self.assertEqual(caps["wire"], "2")
        self.assertEqual(caps["msg"], "1,2")
        self.assertEqual(caps["mc"], "1")
        self.assertTrue(caps["aad"].startswith("a"))
        self.assertLessEqual(len(caps["aad"]), 64)

    def test_parse_caps_frame_non_cp1_returns_none(self):
        from meshTalk import parse_caps_frame

        self.assertIsNone(parse_caps_frame(b"KR1|..."))
        self.assertIsNone(parse_caps_frame(b""))
        self.assertIsNone(parse_caps_frame(b"CP2|wire=2"))

    def test_parse_caps_frame_bad_pairs_ignored(self):
        from meshTalk import parse_caps_frame

        caps = parse_caps_frame(b"CP1|wire=2|noval|mc=1|=x|aad=")
        # "noval" and "=x" are ignored, empty "aad=" becomes empty string.
        self.assertEqual(caps, {"wire": "2", "mc": "1", "aad": ""})


if __name__ == "__main__":
    unittest.main()

