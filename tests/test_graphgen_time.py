import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import graphGen


class ParseTracesTimeTests(unittest.TestCase):
    def test_naive_trace_timestamps_use_local_timezone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            trace_path = Path(tmp_dir) / "2026-03-21 !11111111.txt"
            trace_path.write_text(
                "2026-03-21 12:34:56 !11111111 --> !22222222 (-70dB)\n",
                encoding="utf-8",
            )

            local_tz = timezone(timedelta(hours=3))
            with mock.patch.object(graphGen, "LOCAL_TZ", local_tz):
                edge_count, _edge_rssi, _transit_count, time_series, time_meta, _stats_list, _debug, selected_files = graphGen.parse_traces_with_stats(
                    [trace_path],
                    include_unknown=False,
                    dt_window=None,
                )

        expected_epoch = int(datetime(2026, 3, 21, 12, 34, 56, tzinfo=local_tz).timestamp())
        expected_bin = expected_epoch - (expected_epoch % 300)

        self.assertEqual(edge_count[("!11111111", "!22222222")], 1)
        self.assertEqual(time_series[0]["t"], expected_bin)
        self.assertEqual(time_meta["timeRangeStart"], expected_bin)
        self.assertEqual(time_meta["timeRangeEnd"], expected_bin)
        self.assertEqual(selected_files, [trace_path])


if __name__ == "__main__":
    unittest.main()
