import sqlite3
import tempfile
import unittest
from pathlib import Path

import meshLogger


class TracerouteSchemaTests(unittest.TestCase):
    def test_insert_traceroute_stores_epoch_column(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "meshLogger.db"
            meshLogger.insert_traceroute(
                str(db_path),
                "2026-03-19T10:11:12+00:00",
                "!11111111",
                "!22222222",
                "out",
                "!11111111 --> !22222222",
                "!11111111 > !22222222",
            )

            conn = sqlite3.connect(str(db_path))
            try:
                row = conn.execute(
                    "SELECT ts_utc, ts_epoch, self_id, target_id FROM traceroutes"
                ).fetchone()
            finally:
                conn.close()

            self.assertIsNotNone(row)
            self.assertEqual(row[0], "2026-03-19T10:11:12+00:00")
            self.assertIsInstance(row[1], int)
            self.assertEqual(row[2], "!11111111")
            self.assertEqual(row[3], "!22222222")


if __name__ == "__main__":
    unittest.main()
