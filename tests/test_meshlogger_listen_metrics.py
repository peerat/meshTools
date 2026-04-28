import tempfile
import unittest
from pathlib import Path

import meshLogger


class MeshLoggerListenMetricsTests(unittest.TestCase):
    def test_legacy_listen_packet_with_bytes_payload_is_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "meshLogger.db"
            line = (
                "asDict: {'fromId': '!22222222', 'toId': '!11111111', 'rxTime': 1710000000, "
                "'rxSnr': 4.0, 'rxRssi': -110, 'payload': b'\\\\x01\\\\x02', "
                "'decoded': {'portnum': 'TELEMETRY_APP'}}"
            )

            meshLogger._handle_listen_line(str(db_path), line)

            conn = meshLogger.connect_sqlite(str(db_path))
            try:
                event_row = conn.execute(
                    """
                    SELECT event_type, node_id, raw_json
                    FROM listen_events
                    """
                ).fetchone()
                packet_row = conn.execute(
                    """
                    SELECT node_id, rx_snr, rx_rssi, noise_floor
                    FROM packet_rx_samples
                    """
                ).fetchone()
            finally:
                conn.close()

        self.assertEqual(event_row[0], "telemetry")
        self.assertEqual(event_row[1], "!22222222")
        self.assertIn('"encoding": "hex"', event_row[2])
        self.assertEqual(packet_row, ("!22222222", 4.0, -110.0, -114.0))

    def test_structured_packet_event_stores_rx_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "meshLogger.db"
            meshLogger._handle_listen_structured_event(
                str(db_path),
                {
                    "kind": "packet",
                    "ts_utc": "2026-03-22T02:00:00+00:00",
                    "packet": {
                        "fromId": "!22222222",
                        "toId": "!11111111",
                        "rxTime": 1_710_000_000,
                        "rxSnr": 6.5,
                        "rxRssi": -112,
                        "hopLimit": 3,
                        "decoded": {
                            "portnum": "TELEMETRY_APP",
                            "telemetry": {
                                "deviceMetrics": {
                                    "channelUtilization": 42.5,
                                    "airUtilTx": 7.5,
                                }
                            },
                        },
                    },
                },
            )

            conn = meshLogger.connect_sqlite(str(db_path))
            try:
                packet_row = conn.execute(
                    """
                    SELECT node_id, rx_snr, rx_rssi, noise_floor, portnum
                    FROM packet_rx_samples
                    """
                ).fetchone()
                node_row = conn.execute(
                    """
                    SELECT id, channel_util, tx_air_util
                    FROM nodes
                    WHERE id = ?
                    """,
                    ("!22222222",),
                ).fetchone()
                event_row = conn.execute(
                    """
                    SELECT event_type, node_id
                    FROM listen_events
                    """
                ).fetchone()
            finally:
                conn.close()

        self.assertEqual(packet_row, ("!22222222", 6.5, -112.0, -118.5, "TELEMETRY_APP"))
        self.assertEqual(node_row, ("!22222222", 42.5, 7.5))
        self.assertEqual(event_row, ("telemetry", "!22222222"))

    def test_structured_node_event_updates_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "meshLogger.db"
            meshLogger._handle_listen_structured_event(
                str(db_path),
                {
                    "kind": "node",
                    "ts_utc": "2026-03-22T02:05:00+00:00",
                    "node": {
                        "num": 123,
                        "user": {
                            "id": "!33333333",
                            "longName": "Bravo",
                            "shortName": "B",
                            "role": "CLIENT",
                            "hwModel": "T-ECHO",
                        },
                    },
                },
            )

            conn = meshLogger.connect_sqlite(str(db_path))
            try:
                node_row = conn.execute(
                    """
                    SELECT id, long_name, short_name, role, hardware
                    FROM nodes
                    WHERE id = ?
                    """,
                    ("!33333333",),
                ).fetchone()
                event_row = conn.execute(
                    """
                    SELECT event_type, node_id
                    FROM listen_events
                    """
                ).fetchone()
            finally:
                conn.close()

        self.assertEqual(node_row, ("!33333333", "Bravo", "B", "CLIENT", "T-ECHO"))
        self.assertEqual(event_row, ("nodeinfo", "!33333333"))


if __name__ == "__main__":
    unittest.main()
