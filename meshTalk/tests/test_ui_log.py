import unittest

from meshtalk.ui_log import classify_log_level, should_skip_verbose_log, should_suppress_duplicate_log


class UiLogTests(unittest.TestCase):
    def test_classify_log_level(self) -> None:
        self.assertEqual(classify_log_level("TRACE: start", "info"), "trace")
        self.assertEqual(classify_log_level("KEYOK: confirmed", "info"), "keyok")
        self.assertEqual(classify_log_level("CAPS: rx", "info"), "caps")
        self.assertEqual(classify_log_level("error: bad", "info"), "error")
        self.assertEqual(classify_log_level("WARN: hmm", "info"), "warn")

    def test_should_skip_verbose_log(self) -> None:
        self.assertTrue(should_skip_verbose_log("norm: x", False))
        self.assertFalse(should_skip_verbose_log("send: x", False))
        self.assertFalse(should_skip_verbose_log("norm: x", True))

    def test_should_suppress_duplicate_log(self) -> None:
        last = {"body": "same", "ts": 10.0}
        self.assertTrue(should_suppress_duplicate_log("same", "info", 10.3, last))
        self.assertFalse(should_suppress_duplicate_log("same", "warn", 10.3, last))
        self.assertFalse(should_suppress_duplicate_log("other", "info", 10.3, last))


if __name__ == "__main__":
    unittest.main()
