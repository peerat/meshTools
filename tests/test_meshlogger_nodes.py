import tempfile
import unittest
from pathlib import Path

import meshLogger


class MeshLoggerNodeTests(unittest.TestCase):
    def test_partial_upsert_preserves_metadata_and_zero_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "meshLogger.db"
            meshLogger.init_db(str(db_path))
            conn = meshLogger.connect_sqlite(str(db_path))
            try:
                meshLogger.upsert_node(
                    conn,
                    {
                        "user": {
                            "id": "!11111111",
                            "longName": "Alpha",
                            "shortName": "A",
                            "role": "ROUTER",
                            "hwModel": "T-ECHO",
                        },
                        "deviceMetrics": {
                            "channelUtilization": 42.5,
                            "airUtilTx": 7.5,
                        },
                        "hopsAway": 2,
                        "lastHeard": 1710843072,
                    },
                    "2026-03-19T10:11:12+00:00",
                )
                meshLogger.upsert_node(
                    conn,
                    {
                        "user": {"id": "!11111111"},
                        "channelUtil": 0,
                        "txAirUtil": 0,
                        "hopsAway": 0,
                    },
                    "2026-03-19T10:21:12+00:00",
                    sample_type="listen",
                )

                row = conn.execute(
                    "SELECT long_name, short_name, role, hardware, channel_util, tx_air_util, hops, last_heard_utc FROM nodes WHERE id = ?",
                    ("!11111111",),
                ).fetchone()
                snapshot = meshLogger._load_nodes_snapshot(conn)
            finally:
                conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], "Alpha")
        self.assertEqual(row[1], "A")
        self.assertEqual(row[2], "ROUTER")
        self.assertEqual(row[3], "T-ECHO")
        self.assertEqual(row[4], 0.0)
        self.assertEqual(row[5], 0.0)
        self.assertEqual(row[6], 0)
        self.assertEqual(row[7], meshLogger.epoch_to_iso_utc(1710843072))

        self.assertEqual(snapshot["!11111111"]["channel_util"], 0.0)
        self.assertEqual(snapshot["!11111111"]["tx_air_util"], 0.0)
        self.assertEqual(snapshot["!11111111"]["hops"], 0)


if __name__ == "__main__":
    unittest.main()
