import unittest

from meshtalk.metrics import MetricsStore, METRICS_GRAPH_WINDOW_SECONDS


class TestMetricsStore(unittest.TestCase):
    def test_inc_and_set_in_same_second(self):
        ms = MetricsStore(retention_seconds=3600)
        t = 1000.3
        ms.inc("a", 1, now=t)
        ms.inc("a", 2, now=t)
        ms.set("b", 7, now=t)
        rows = ms.snapshot_rows(window_s=60, now=t)
        self.assertEqual(len(rows), 60)
        last_sec, last_row = rows[-1]
        self.assertEqual(last_sec, 1000)
        self.assertEqual(last_row["a"], 3.0)
        self.assertEqual(last_row["b"], 7.0)

    def test_snapshot_is_continuous(self):
        ms = MetricsStore(retention_seconds=3600)
        # Put values into two sparse seconds.
        ms.inc("x", 1, now=2000.0)
        ms.inc("x", 1, now=2005.0)
        # Store enforces a minimum window of 60s (matches UI graph baseline).
        rows = ms.snapshot_rows(window_s=10, now=2005.0)
        secs = [s for (s, _r) in rows]
        self.assertEqual(secs, list(range(1946, 2006)))
        # Missing seconds should be empty dicts.
        empty_secs = [s for (s, r) in rows if s not in (2000, 2005) and r == {}]
        self.assertTrue(len(empty_secs) >= 1)

    def test_retention_trims_old_data(self):
        ms = MetricsStore(retention_seconds=3)
        ms.inc("x", 1, now=10.0)
        ms.inc("x", 1, now=20.0)
        # Snapshot window reaches back, but old rows should be trimmed from store.
        rows = ms.snapshot_rows(window_s=5, now=20.0)
        # Still continuous by construction, but minimum window is 60s.
        self.assertEqual([s for (s, _r) in rows], list(range(-39, 21)))


if __name__ == "__main__":
    unittest.main()
