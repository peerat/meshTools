#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import graphGen
import meshLogger


class MeshLoggerGraphGenTests(unittest.TestCase):
    def test_meshlogger_update_db_returns_existing_snapshot_on_empty_fetch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "meshLogger.db"
            meshLogger.init_db(str(db_path))
            conn = sqlite3.connect(str(db_path))
            try:
                meshLogger.upsert_node(
                    conn,
                    {"user": {"id": "!12345678", "longName": "Node A", "shortName": "A"}},
                    "2026-02-08T00:00:00+00:00",
                    sample_type="nodes",
                )
                conn.commit()
            finally:
                conn.close()

            with mock.patch("meshLogger.fetch_nodes_json", return_value=None), mock.patch("meshLogger.fetch_info_raw", return_value=None):
                updated, prev_snap, cur_snap = meshLogger.update_db_from_nodes("auto", 5, str(db_path))

            self.assertEqual(updated, 0)
            self.assertEqual(prev_snap, cur_snap)
            self.assertIn("!12345678", cur_snap)

    def test_meshlogger_update_db_falls_back_to_info_nodes_dict(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "meshLogger.db"
            meshLogger.init_db(str(db_path))
            nodes_from_info = {
                "!87654321": {
                    "user": {"id": "!87654321", "longName": "Node B", "shortName": "B"},
                    "hopsAway": 1,
                }
            }
            with mock.patch("meshLogger.fetch_nodes_json", return_value=None), mock.patch(
                "meshLogger.fetch_info_raw",
                return_value='{"nodesById":{"!87654321":{"user":{"id":"!87654321","longName":"Node B","shortName":"B"}}}}',
            ), mock.patch("meshLogger.parse_nodes_block", return_value=nodes_from_info):
                updated, _prev_snap, cur_snap = meshLogger.update_db_from_nodes("auto", 5, str(db_path))

            self.assertEqual(updated, 1)
            self.assertIn("!87654321", cur_snap)
            self.assertEqual(cur_snap["!87654321"].get("long_name"), "Node B")

    def test_graphgen_db_selected_rows_in_datetime_window(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "meshLogger.db"
            conn = sqlite3.connect(str(db_path))
            try:
                cur = conn.cursor()
                cur.execute(
                    """
                    CREATE TABLE traceroutes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts_utc TEXT,
                        self_id TEXT,
                        target_id TEXT,
                        direction TEXT,
                        route_raw TEXT
                    )
                    """
                )
                cur.executemany(
                    "INSERT INTO traceroutes (ts_utc, self_id, target_id, direction, route_raw) VALUES (?, ?, ?, ?, ?)",
                    [
                        ("2026-02-08 10:00:00", "!aaaa1111", "!bbbb2222", "out", "!aaaa1111 --> !bbbb2222 (-10dB)"),
                        ("2026-02-08 11:00:00", "!aaaa1111", "!cccc3333", "out", "!aaaa1111 --> !cccc3333 (-11dB)"),
                        ("2026-02-09 11:00:00", "!aaaa1111", "!dddd4444", "out", "!aaaa1111 --> !dddd4444 (-12dB)"),
                    ],
                )
                conn.commit()
            finally:
                conn.close()

            dt_window = graphGen.parse_datetime_window("2026-02-08 10:30 - 2026-02-08 23:59")
            _edge_count, _edge_rssi, _transit_count, _time_series, _time_meta, stats_list, debug, _selected_files = (
                graphGen.parse_traceroutes_with_stats_from_db(
                    db_path=db_path,
                    include_unknown=False,
                    dt_window=dt_window,
                )
            )

            self.assertEqual(int(debug.get("selected_rows", -1)), 1)
            self.assertEqual(int(stats_list[0].lines_in_window), 1)

    def test_graphgen_db_selected_rows_with_iso_ts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "meshLogger.db"
            conn = sqlite3.connect(str(db_path))
            try:
                cur = conn.cursor()
                cur.execute(
                    """
                    CREATE TABLE traceroutes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts_utc TEXT,
                        self_id TEXT,
                        target_id TEXT,
                        direction TEXT,
                        route_raw TEXT
                    )
                    """
                )
                cur.executemany(
                    "INSERT INTO traceroutes (ts_utc, self_id, target_id, direction, route_raw) VALUES (?, ?, ?, ?, ?)",
                    [
                        ("2026-02-08T10:00:00+00:00", "!aaaa1111", "!bbbb2222", "out", "!aaaa1111 --> !bbbb2222 (-10dB)"),
                        ("2026-02-08T11:00:00+00:00", "!aaaa1111", "!cccc3333", "out", "!aaaa1111 --> !cccc3333 (-11dB)"),
                        ("2026-02-09T11:00:00+00:00", "!aaaa1111", "!dddd4444", "out", "!aaaa1111 --> !dddd4444 (-12dB)"),
                    ],
                )
                conn.commit()
            finally:
                conn.close()

            dt_window = graphGen.parse_datetime_window("2026-02-08 10:30 - 2026-02-08 23:59")
            _edge_count, _edge_rssi, _transit_count, _time_series, _time_meta, stats_list, debug, _selected_files = (
                graphGen.parse_traceroutes_with_stats_from_db(
                    db_path=db_path,
                    include_unknown=False,
                    dt_window=dt_window,
                )
            )

            self.assertEqual(int(debug.get("selected_rows", -1)), 1)
            self.assertEqual(int(stats_list[0].lines_in_window), 1)


if __name__ == "__main__":
    unittest.main()
