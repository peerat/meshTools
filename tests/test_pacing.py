import unittest

from meshtalk.pacing import AdaptivePacer


class TestAdaptivePacer(unittest.TestCase):
    def test_no_change_does_not_update_last_adjust_ts(self):
        p = AdaptivePacer(
            rate_seconds=5,
            parallel_sends=4,
            enabled=True,
            min_rate_seconds=5,
            max_rate_seconds=120,
            min_parallel=1,
            max_parallel=4,
            adjust_interval_seconds=15.0,
            stats_window_seconds=90.0,
        )
        # Clean link metrics trigger a "scale up" branch, but we're already at max score.
        p.observe_ack(rtt_s=1.0, attempts=1, now=1000.0)
        p.observe_ack(rtt_s=1.0, attempts=1, now=1001.0)
        p.observe_ack(rtt_s=1.0, attempts=1, now=1002.0)
        self.assertEqual(p._last_adjust_ts, 0.0)
        out = p.suggest(pending_count=10, now=1003.0)
        self.assertIsNone(out)
        self.assertEqual(p._last_adjust_ts, 0.0)


if __name__ == "__main__":
    unittest.main()
