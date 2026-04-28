import unittest

from meshtalk.ui_settings import (
    build_activity_runtime_settings,
    compute_activity_preset,
    normalize_contacts_visibility,
    parse_float_text,
    parse_int_text,
)


class UiSettingsTests(unittest.TestCase):
    def test_compute_activity_preset_returns_bounded_values(self):
        preset = compute_activity_preset("fast", 100)
        self.assertGreaterEqual(preset["activity_probe_interval_min_seconds"], 60.0)
        self.assertGreaterEqual(
            preset["activity_probe_interval_max_seconds"],
            preset["activity_probe_interval_min_seconds"],
        )
        self.assertIn("activity_fast_budget_per_second", preset)

    def test_parse_helpers_fallback(self):
        self.assertEqual(parse_int_text(" 12 ", 7), 12)
        self.assertEqual(parse_int_text("", 7), 7)
        self.assertEqual(parse_int_text("bad", 7), 7)
        self.assertAlmostEqual(parse_float_text("1,5", 0.0), 1.5)
        self.assertAlmostEqual(parse_float_text("", 2.5), 2.5)

    def test_normalize_contacts_visibility(self):
        self.assertEqual(normalize_contacts_visibility("ONLINE"), "online")
        self.assertEqual(normalize_contacts_visibility("weird"), "all")
        self.assertEqual(normalize_contacts_visibility(None, default="app"), "app")

    def test_build_activity_runtime_settings(self):
        out = build_activity_runtime_settings(
            retry_text="15",
            max_days_text="2",
            max_bytes_text="200",
            batch_count_text="3",
            intra_gap_text="5",
            backoff_cap_text="120",
            jitter_text="25",
            show_advanced=True,
            parallel_default=1,
            intra_gap_default=0,
            backoff_default=60,
            jitter_ratio_default=0.1,
        )
        self.assertEqual(out["retry_seconds"], 15)
        self.assertEqual(out["max_seconds"], 2 * 86400)
        self.assertEqual(out["parallel_sends"], 3)
        self.assertEqual(out["activity_intra_batch_gap_ms"], 5)
        self.assertAlmostEqual(out["activity_retry_jitter_ratio"], 0.25)


if __name__ == "__main__":
    unittest.main()
