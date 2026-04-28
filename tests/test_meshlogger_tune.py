import re
import tempfile
import unittest
from pathlib import Path

import meshLogger


class MeshLoggerTuneTests(unittest.TestCase):
    def test_load_tune_direct_nodes_keeps_only_recent_direct_rows(self) -> None:
        now_epoch = 1_710_000_000

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "meshLogger.db"
            meshLogger.init_db(str(db_path))
            conn = meshLogger.connect_sqlite(str(db_path))
            try:
                conn.execute(
                    """
                    INSERT INTO nodes (
                        id, long_name, short_name, updated_utc
                    ) VALUES (?, ?, ?, ?)
                    """,
                    ("!22222222", "Alpha", "A", "2026-03-22T00:00:00+00:00"),
                )
                conn.execute(
                    """
                    INSERT INTO nodes (
                        id, long_name, short_name, updated_utc
                    ) VALUES (?, ?, ?, ?)
                    """,
                    ("!33333333", "Bravo", "B", "2026-03-22T00:00:00+00:00"),
                )
                conn.executemany(
                    """
                    INSERT INTO traceroutes (
                        ts_utc, ts_epoch, self_id, target_id, direction, route_raw, route_pretty, hops
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            "2026-03-22T00:00:00+00:00",
                            now_epoch - 120,
                            "!11111111",
                            "!22222222",
                            "out",
                            "!11111111 --> !22222222 (-12.5dB)",
                            "self > Alpha (-12.5dB)",
                            1,
                        ),
                        (
                            "2026-03-22T00:00:20+00:00",
                            now_epoch - 100,
                            "!11111111",
                            "!22222222",
                            "back",
                            "!22222222 --> !11111111 (3.5dB)",
                            "Alpha > self (3.5dB)",
                            1,
                        ),
                        (
                            "2026-03-22T00:00:30+00:00",
                            now_epoch - 90,
                            "!11111111",
                            "!22222222",
                            "out",
                            "!11111111 --> !22222222 (-9.0dB)",
                            "self > Alpha (-9.0dB)",
                            1,
                        ),
                    (
                        "2026-03-22T00:01:00+00:00",
                        now_epoch - 60,
                        "!11111111",
                        "!33333333",
                        "out",
                        "!11111111 --> !33333333 (-6.0dB) --> !44444444 (-11.0dB)",
                        "self > Bravo > relay",
                        2,
                    ),
                    (
                        "2026-03-22T00:01:10+00:00",
                        now_epoch - 50,
                        "!11111111",
                        "!55555555",
                        "back",
                        "!55555555 --> !33333333 (-4.5dB) --> !11111111 (8.0dB)",
                        "target > Bravo > self",
                        2,
                    ),
                    (
                        "2026-03-21T22:00:00+00:00",
                        now_epoch - 7200,
                        "!11111111",
                            "!55555555",
                            "out",
                            "!11111111 --> !55555555 (-4.0dB)",
                            "self > old",
                            1,
                        ),
                        (
                            "2026-03-22T00:00:40+00:00",
                            now_epoch - 80,
                            "!aaaaaaaa",
                            "!22222222",
                            "out",
                            "!aaaaaaaa --> !22222222 (-7.0dB)",
                            "other > Alpha",
                            1,
                        ),
                    ],
                )
                conn.execute(
                    """
                    INSERT INTO packet_rx_samples (
                        ts_utc, ts_epoch, node_id, from_id, to_id, portnum,
                        rx_snr, rx_rssi, noise_floor, hop_limit, hop_start, rx_time, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "2026-03-22T00:00:25+00:00",
                        now_epoch - 95,
                        "!22222222",
                        "!22222222",
                        "!11111111",
                        "TELEMETRY_APP",
                        6.5,
                        -112.0,
                        -118.5,
                        3,
                        3,
                        now_epoch - 95,
                        "{}",
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO packet_rx_samples (
                        ts_utc, ts_epoch, node_id, from_id, to_id, portnum,
                        rx_snr, rx_rssi, noise_floor, hop_limit, hop_start, rx_time, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "2026-03-22T00:00:15+00:00",
                        now_epoch - 105,
                        "!22222222",
                        "!22222222",
                        "!11111111",
                        "TELEMETRY_APP",
                        5.5,
                        -114.0,
                        -119.5,
                        3,
                        3,
                        now_epoch - 105,
                        "{}",
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            rows = meshLogger.load_tune_direct_nodes(
                str(db_path),
                "!11111111",
                window_seconds=3600,
                now_epoch=now_epoch,
            )

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["node_id"], "!22222222")
        self.assertEqual(rows[0]["name"], "Alpha[A]")
        self.assertEqual(rows[0]["hears_me"], -9.0)
        self.assertEqual(rows[0]["hears_me_prev"], -12.5)
        self.assertEqual(rows[0]["hears_me_noise"], "-")
        self.assertEqual(rows[0]["i_hear_him"], 6.5)
        self.assertEqual(rows[0]["i_hear_him_prev"], 3.5)
        self.assertEqual(rows[0]["i_hear_him_noise"], -118.5)
        self.assertEqual(rows[0]["i_hear_him_noise_prev"], -119.5)
        self.assertEqual(rows[0]["tx_sample_count"], 2)
        self.assertEqual(rows[0]["rx_sample_count"], 3)
        self.assertEqual(rows[0]["tx_sample_count"], len(rows[0]["hears_me_history"]))
        self.assertEqual(rows[0]["rx_sample_count"], len(rows[0]["i_hear_him_history"]))
        self.assertEqual(rows[0]["tx_variability"]["state"], "wild")
        self.assertEqual(rows[0]["rx_variability"]["state"], "wild")
        self.assertEqual(rows[0]["nf_variability"]["state"], "stable")
        self.assertEqual(rows[0]["tx_variability"]["history"], ".#")
        self.assertEqual(rows[0]["last_seen_epoch"], now_epoch - 90)
        self.assertEqual(rows[1]["node_id"], "!33333333")
        self.assertEqual(rows[1]["name"], "Bravo[B]")
        self.assertEqual(rows[1]["hears_me"], -6.0)
        self.assertEqual(rows[1]["i_hear_him"], 8.0)
        self.assertEqual(rows[1]["i_hear_him_noise"], "-")
        self.assertEqual(rows[1]["tx_sample_count"], 1)
        self.assertEqual(rows[1]["rx_sample_count"], 1)
        self.assertEqual(rows[1]["tx_variability"]["state"], "new")
        self.assertEqual(rows[1]["rx_variability"]["state"], "new")
        self.assertEqual(rows[1]["last_seen_epoch"], now_epoch - 50)

    def test_load_tune_direct_nodes_keeps_recent_rows_but_filters_metrics_before_tune_start(self) -> None:
        now_epoch = 1_710_000_000

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "meshLogger.db"
            meshLogger.init_db(str(db_path))
            conn = meshLogger.connect_sqlite(str(db_path))
            try:
                conn.execute(
                    """
                    INSERT INTO nodes (
                        id, long_name, short_name, updated_utc
                    ) VALUES (?, ?, ?, ?)
                    """,
                    ("!22222222", "Alpha", "A", "2026-03-22T00:00:00+00:00"),
                )
                conn.execute(
                    """
                    INSERT INTO nodes (
                        id, long_name, short_name, updated_utc
                    ) VALUES (?, ?, ?, ?)
                    """,
                    ("!33333333", "Bravo", "B", "2026-03-22T00:00:00+00:00"),
                )
                conn.executemany(
                    """
                    INSERT INTO traceroutes (
                        ts_utc, ts_epoch, self_id, target_id, direction, route_raw, route_pretty, hops
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            "2026-03-22T00:00:00+00:00",
                            now_epoch - 120,
                            "!11111111",
                            "!22222222",
                            "out",
                            "!11111111 --> !22222222 (-12.5dB)",
                            "self > Alpha (-12.5dB)",
                            1,
                        ),
                        (
                            "2026-03-22T00:00:20+00:00",
                            now_epoch - 100,
                            "!11111111",
                            "!22222222",
                            "back",
                            "!22222222 --> !11111111 (3.5dB)",
                            "Alpha > self (3.5dB)",
                            1,
                        ),
                        (
                            "2026-03-22T00:01:00+00:00",
                            now_epoch - 60,
                            "!11111111",
                            "!33333333",
                            "out",
                            "!11111111 --> !33333333 (-6.0dB)",
                            "self > Bravo (-6.0dB)",
                            1,
                        ),
                        (
                            "2026-03-22T00:01:10+00:00",
                            now_epoch - 50,
                            "!11111111",
                            "!33333333",
                            "back",
                            "!33333333 --> !11111111 (8.0dB)",
                            "Bravo > self (8.0dB)",
                            1,
                        ),
                    ],
                )
                conn.commit()
            finally:
                conn.close()

            rows = meshLogger.load_tune_direct_nodes(
                str(db_path),
                "!11111111",
                window_seconds=3600,
                now_epoch=now_epoch,
                session_start_epoch=now_epoch - 70,
            )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["node_id"], "!33333333")
        self.assertEqual(rows[0]["hears_me"], -6.0)
        self.assertEqual(rows[0]["i_hear_him"], 8.0)
        self.assertEqual(rows[0]["tx_sample_count"], 1)
        self.assertEqual(rows[0]["rx_sample_count"], 1)

    def test_load_tune_direct_nodes_without_window_uses_whole_tune_session(self) -> None:
        now_epoch = 1_710_000_000

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "meshLogger.db"
            meshLogger.init_db(str(db_path))
            conn = meshLogger.connect_sqlite(str(db_path))
            try:
                conn.execute(
                    """
                    INSERT INTO nodes (
                        id, long_name, short_name, updated_utc
                    ) VALUES (?, ?, ?, ?)
                    """,
                    ("!22222222", "Alpha", "A", "2026-03-22T00:00:00+00:00"),
                )
                conn.executemany(
                    """
                    INSERT INTO traceroutes (
                        ts_utc, ts_epoch, self_id, target_id, direction, route_raw, route_pretty, hops
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            "2026-03-21T22:53:20+00:00",
                            now_epoch - 4000,
                            "!11111111",
                            "!22222222",
                            "out",
                            "!11111111 --> !22222222 (-12.5dB)",
                            "self > Alpha (-12.5dB)",
                            1,
                        ),
                        (
                            "2026-03-21T22:54:20+00:00",
                            now_epoch - 3940,
                            "!11111111",
                            "!22222222",
                            "back",
                            "!22222222 --> !11111111 (3.5dB)",
                            "Alpha > self (3.5dB)",
                            1,
                        ),
                        (
                            "2026-03-22T00:58:20+00:00",
                            now_epoch - 100,
                            "!11111111",
                            "!22222222",
                            "out",
                            "!11111111 --> !22222222 (-9.0dB)",
                            "self > Alpha (-9.0dB)",
                            1,
                        ),
                        (
                            "2026-03-22T00:59:20+00:00",
                            now_epoch - 40,
                            "!11111111",
                            "!22222222",
                            "back",
                            "!22222222 --> !11111111 (4.0dB)",
                            "Alpha > self (4.0dB)",
                            1,
                        ),
                    ],
                )
                conn.commit()
            finally:
                conn.close()

            rows = meshLogger.load_tune_direct_nodes(
                str(db_path),
                "!11111111",
                window_seconds=None,
                now_epoch=now_epoch,
                session_start_epoch=now_epoch - 7200,
            )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["tx_sample_count"], 2)
        self.assertEqual(rows[0]["rx_sample_count"], 2)
        self.assertEqual(rows[0]["hears_me_history"], [-9.0, -12.5])
        self.assertEqual(rows[0]["i_hear_him_history"], [4.0, 3.5])
        self.assertEqual(rows[0]["hears_me_log_history"], [-9.0, -12.5])
        self.assertEqual(rows[0]["i_hear_him_log_history"], [4.0, 3.5])

    def test_load_tune_direct_nodes_drops_rows_older_than_visibility_window(self) -> None:
        now_epoch = 1_710_000_000

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "meshLogger.db"
            meshLogger.init_db(str(db_path))
            conn = meshLogger.connect_sqlite(str(db_path))
            try:
                conn.execute(
                    """
                    INSERT INTO nodes (
                        id, long_name, short_name, updated_utc
                    ) VALUES (?, ?, ?, ?)
                    """,
                    ("!22222222", "Alpha", "A", "2026-03-22T00:00:00+00:00"),
                )
                conn.execute(
                    """
                    INSERT INTO traceroutes (
                        ts_utc, ts_epoch, self_id, target_id, direction, route_raw, route_pretty, hops
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "2026-03-22T00:00:00+00:00",
                        now_epoch - 3700,
                        "!11111111",
                        "!22222222",
                        "out",
                        "!11111111 --> !22222222 (-12.5dB)",
                        "self > Alpha (-12.5dB)",
                        1,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            rows = meshLogger.load_tune_direct_nodes(
                str(db_path),
                "!11111111",
                window_seconds=3600,
                now_epoch=now_epoch,
                session_start_epoch=now_epoch - 7200,
            )

        self.assertEqual(rows, [])

    def test_load_tune_direct_nodes_skips_rows_without_numeric_tx_or_rx_metrics(self) -> None:
        now_epoch = 1_710_000_000

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "meshLogger.db"
            meshLogger.init_db(str(db_path))
            conn = meshLogger.connect_sqlite(str(db_path))
            try:
                conn.execute(
                    """
                    INSERT INTO traceroutes (
                        ts_utc, ts_epoch, self_id, target_id, direction, route_raw, route_pretty, hops
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "2026-03-22T00:00:00+00:00",
                        now_epoch - 60,
                        "!11111111",
                        "!22222222",
                        "out",
                        "!11111111 --> !22222222",
                        "self > direct",
                        1,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO traceroutes (
                        ts_utc, ts_epoch, self_id, target_id, direction, route_raw, route_pretty, hops
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "2026-03-22T00:00:05+00:00",
                        now_epoch - 55,
                        "!11111111",
                        "!22222222",
                        "back",
                        "!22222222 --> !11111111",
                        "direct > self",
                        1,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            rows = meshLogger.load_tune_direct_nodes(
                str(db_path),
                "!11111111",
                window_seconds=3600,
                now_epoch=now_epoch,
                session_start_epoch=now_epoch - 7200,
            )

        self.assertEqual(rows, [])

    def test_build_tune_screen_renders_table_rows(self) -> None:
        session_start_epoch = 1_709_999_400
        now_epoch = 1_710_000_000
        rows = [
            {
                "node_id": "!22222222",
                "name": "Alpha[A]",
                "tx_sample_count": 7,
                "rx_sample_count": 3,
                "last_seen_epoch": 1_710_000_000,
                "hears_me": -9.0,
                "hears_me_prev": -12.5,
                "hears_me_noise": "-",
                "i_hear_him": 6.5,
                "i_hear_him_prev": 5.5,
                "i_hear_him_history": [6.5, 5.5],
                "i_hear_him_noise": -118.5,
                "i_hear_him_noise_prev": -119.5,
                "i_hear_him_noise_history": [-118.5, -119.5],
                "hears_me_history": [-9.0, -12.5],
            }
        ]
        prev_snapshot = {
            "!22222222": {
                "tx_current": -12.5,
                "tx_spread": 0.0,
                "tx_min": -12.5,
                "tx_avg": -12.5,
                "tx_max": -12.5,
                "rx_current": 5.5,
                "rx_spread": 0.0,
                "rx_min": 5.5,
                "rx_avg": 5.5,
                "rx_max": 5.5,
                "nf_current": -119.5,
                "nf_spread": 0.0,
                "nf_min": -119.5,
                "nf_avg": -119.5,
                "nf_max": -119.5,
            }
        }
        screen = meshLogger.build_tune_screen(
            rows,
            self_id="!11111111",
            refreshed_at="2026-03-22 01:23:45",
            refresh_seconds=30,
            window_seconds=3600,
            poll_hours=24,
            status="Tracing: 1 active node(s)",
            session_start_epoch=session_start_epoch,
            now_epoch=now_epoch,
            highlight_previous=prev_snapshot,
            terminal_size=(260, 30),
            trace_requests=9,
            trace_success=6,
            measurement_total=10,
        )
        plain = meshLogger.clean_ansi(screen)

        self.assertIn("\x1b[38;5;", screen)
        self.assertIn("\x1b[48;2;", screen)
        self.assertIn(
            "meshLogger, self node: !11111111, окно 60м, опрашиваются ноды видимые последние 24 часа.",
            plain,
        )
        self.assertIn(f"старт:\t\t{meshLogger._format_tune_full_epoch(session_start_epoch)}", plain)
        self.assertIn(f"обновлено:\t{meshLogger._format_tune_full_datetime('2026-03-22 01:23:45')}", plain)
        self.assertIn(
            f"прошло\t\t{meshLogger._format_tune_elapsed(now_epoch - session_start_epoch)} | окно 60м | обновление 30с",
            plain,
        )
        self.assertIn("Last", plain)
        self.assertIn("Tx SNR", plain)
        self.assertIn("Tx dSNR", plain)
        self.assertIn("TxCnt", plain)
        self.assertIn("Tx Min", plain)
        self.assertIn("Tx Avg", plain)
        self.assertIn("Tx Max", plain)
        self.assertIn("RxCnt", plain)
        self.assertIn("Rx SNR", plain)
        self.assertIn("Rx dSNR", plain)
        self.assertIn("Rx Min", plain)
        self.assertIn("Rx Avg", plain)
        self.assertIn("Rx Max", plain)
        self.assertIn("Tx Log", plain)
        self.assertIn("Rx Log", plain)
        self.assertIn(
            "прямых узлов: 1 | запросов traceroute 9 | принятых ответов 6, 67%",
            plain,
        )
        self.assertIn("порт:\t\tauto", plain)
        self.assertIn("Last:\tвремя последнего полученного значения.", plain)
        self.assertIn("TxCnt:\tсчетчик значений уровня приема dBm (как слышат нас).", plain)
        self.assertIn("Tx SNR/dSNR/Min/Avg/Max:\tтекущее, разница max-min, минимум, среднее и максимум Tx SNR в выбранном tune-окне.", plain)
        self.assertIn("RxCnt:\tсчетчик значений уровня приема dBm (как слышим мы).", plain)
        self.assertIn("Rx SNR/dSNR/Min/Avg/Max:\tтекущее, разница max-min, минимум, среднее и максимум Rx SNR в выбранном tune-окне.", plain)
        self.assertIn("Tx Log:\tпоследние 20 значений Tx SNR в выбранном tune-окне, справа новое.", plain)
        self.assertIn("Rx Log:\tпоследние 20 значений Rx SNR в выбранном tune-окне, справа новое.", plain)
        self.assertIn("SNR цвет: -20..+10 от красного к зеленому.", plain)
        self.assertIn("Alpha[A]", plain)
        self.assertIn("7", plain)
        self.assertIn("3", plain)
        self.assertIn(meshLogger._format_tune_last_epoch(1_710_000_000), plain)
        self.assertIn("-9.00", plain)
        self.assertIn("3.50", plain)
        self.assertIn("-10.75", plain)
        self.assertIn("6.50", plain)
        self.assertIn("1.00", plain)
        self.assertIn("6.00", plain)

        screen_without_change = meshLogger.build_tune_screen(
            rows,
            self_id="!11111111",
            refreshed_at="2026-03-22 01:23:45",
            refresh_seconds=30,
            window_seconds=3600,
            status="Tracing: 1 active node(s)",
            session_start_epoch=session_start_epoch,
            now_epoch=now_epoch,
            highlight_previous=meshLogger._build_tune_metric_snapshot(rows),
            terminal_size=(260, 30),
        )
        self.assertRegex(screen, r"\x1b\[48;2;[0-9;]+m(?:\x1b\[38;2;[0-9;]+m)?-9\.00")
        self.assertIsNone(re.search(r"\x1b\[48;2;[0-9;]+m(?:\x1b\[38;2;[0-9;]+m)?-9\.00", screen_without_change))

    def test_build_tune_screen_shows_waiting_state_before_first_measurement(self) -> None:
        screen = meshLogger.build_tune_screen(
            [],
            self_id="!11111111",
            refreshed_at="2026-03-22 01:23:45",
            refresh_seconds=30,
            window_seconds=None,
            poll_hours=24,
            status="Цикл опроса: 1, опрашивается 1 из 56 - Alpha[A]",
            session_start_epoch=1_709_999_700,
            now_epoch=1_710_000_000,
            trace_requests=1,
            trace_success=0,
            measurement_total=0,
            terminal_size=(160, 30),
        )
        plain = meshLogger.clean_ansi(screen)

        self.assertIn("Ожидание первых данных...", plain)
        self.assertIn("Сейчас происходит:", plain)
        self.assertIn("обновляется список активных нод;", plain)
        self.assertIn("выполняются traceroute по очереди;", plain)
        self.assertIn("пока еще не получены ответы traceroute.", plain)
        self.assertIn("Таблица появится автоматически после первого прямого Tx/Rx-измерения.", plain)
        self.assertNotIn("TxCnt", plain)
        self.assertNotIn("Last", plain)

    def test_build_tune_screen_does_not_highlight_first_seen_metric_value(self) -> None:
        rows = [
            {
                "node_id": "!22222222",
                "name": "Solo[S]",
                "last_seen_epoch": 1_710_000_000,
                "tx_sample_count": 1,
                "rx_sample_count": 1,
                "hears_me": 3.75,
                "hears_me_prev": None,
                "hears_me_history": [3.75],
                "i_hear_him": -13.0,
                "i_hear_him_prev": None,
                "i_hear_him_history": [-13.0],
                "i_hear_him_noise": -88.5,
                "i_hear_him_noise_prev": None,
                "i_hear_him_noise_history": [-88.5],
            }
        ]

        screen = meshLogger.build_tune_screen(
            rows,
            self_id="!11111111",
            refreshed_at="2026-03-22 01:23:45",
            refresh_seconds=30,
            session_start_epoch=1_709_999_700,
            now_epoch=1_710_000_000,
            highlight_previous={},
            measurement_total=2,
            terminal_size=(260, 30),
        )

        self.assertIsNone(re.search(r"\x1b\[48;2;[0-9;]+m3\.75", screen))
        self.assertIsNone(re.search(r"\x1b\[48;2;[0-9;]+m-13\.00", screen))
        self.assertIn("\x1b[48;2;", screen)

    def test_build_tune_screen_shows_table_when_rows_exist_even_if_live_measurement_counter_is_zero(self) -> None:
        rows = [
            {
                "node_id": "!22222222",
                "name": "Solo[S]",
                "last_seen_epoch": 1_710_000_000,
                "tx_sample_count": 1,
                "rx_sample_count": 1,
                "hears_me": 3.75,
                "hears_me_prev": None,
                "hears_me_history": [3.75],
                "i_hear_him": -13.0,
                "i_hear_him_prev": None,
                "i_hear_him_history": [-13.0],
                "i_hear_him_noise": -88.5,
                "i_hear_him_noise_prev": None,
                "i_hear_him_noise_history": [-88.5],
            }
        ]

        screen = meshLogger.build_tune_screen(
            rows,
            self_id="!11111111",
            refreshed_at="2026-03-22 01:23:45",
            refresh_seconds=30,
            session_start_epoch=1_709_999_700,
            now_epoch=1_710_000_000,
            measurement_total=0,
            terminal_size=(260, 30),
        )
        plain = meshLogger.clean_ansi(screen)

        self.assertIn("TxCnt", plain)
        self.assertIn("Solo[S]", plain)
        self.assertNotIn("Ожидание первых данных...", plain)

    def test_build_tune_screen_shows_table_when_rows_exist_even_if_row_counts_are_zero(self) -> None:
        rows = [
            {
                "node_id": "!22222222",
                "name": "Direct[D]",
                "last_seen_epoch": 1_710_000_000,
                "tx_sample_count": 0,
                "rx_sample_count": 0,
                "hears_me": "-",
                "hears_me_prev": None,
                "hears_me_history": [],
                "i_hear_him": "-",
                "i_hear_him_prev": None,
                "i_hear_him_history": [],
                "i_hear_him_noise": "-",
                "i_hear_him_noise_prev": None,
                "i_hear_him_noise_history": [],
            }
        ]

        screen = meshLogger.build_tune_screen(
            rows,
            self_id="!11111111",
            refreshed_at="2026-03-22 01:23:45",
            refresh_seconds=30,
            session_start_epoch=1_709_999_700,
            now_epoch=1_710_000_000,
            measurement_total=0,
            terminal_size=(260, 30),
        )
        plain = meshLogger.clean_ansi(screen)

        self.assertIn("TxCnt", plain)
        self.assertIn("Direct[D]", plain)
        self.assertNotIn("Ожидание первых данных...", plain)

    def test_build_tune_screen_hides_min_avg_max_for_single_measurement(self) -> None:
        now_epoch = 1_710_000_000
        rows = [
            {
                "node_id": "!22222222",
                "name": "Solo[S]",
                "last_seen_epoch": now_epoch,
                "tx_sample_count": 1,
                "rx_sample_count": 1,
                "hears_me": 3.75,
                "hears_me_prev": None,
                "hears_me_history": [3.75],
                "i_hear_him": -13.0,
                "i_hear_him_prev": None,
                "i_hear_him_history": [-13.0],
                "i_hear_him_noise": -88.5,
                "i_hear_him_noise_prev": None,
                "i_hear_him_noise_history": [-88.5],
            }
        ]

        screen = meshLogger.build_tune_screen(
            rows,
            self_id="!11111111",
            refreshed_at="2026-03-22 01:23:45",
            refresh_seconds=30,
            session_start_epoch=now_epoch - 300,
            now_epoch=now_epoch,
            measurement_total=2,
            terminal_size=(260, 30),
        )
        plain = meshLogger.clean_ansi(screen)
        row_line = next(line for line in plain.splitlines() if "Solo[S]" in line)
        columns = re.split(r"\s{2,}", row_line.strip())

        self.assertEqual(
            columns[:16],
            [
                "1",
                meshLogger._format_tune_last_epoch(now_epoch),
                "!22222222",
                "Solo[S]",
                "1",
                "3.75",
                "-",
                "-",
                "-",
                "-",
                "1",
                "-13.00",
                "-",
                "-",
                "-",
                "-",
            ],
        )
        self.assertIn("Tx Log", plain)
        self.assertIn("Rx Log", plain)
        self.assertNotIn("NF Min", plain)
        self.assertNotIn("dNF", plain)

    def test_apply_tune_session_rows_accumulates_only_new_session_samples(self) -> None:
        session_state = {}

        first_rows = meshLogger._apply_tune_session_rows(
            [
                {
                    "node_id": "!22222222",
                    "hears_me": -9.0,
                    "hears_me_epoch": 100,
                    "i_hear_him": 6.0,
                    "i_hear_him_epoch": 100,
                    "i_hear_him_noise": -118.0,
                    "i_hear_him_noise_epoch": 100,
                }
            ],
            session_state,
        )
        second_rows = meshLogger._apply_tune_session_rows(
            [
                {
                    "node_id": "!22222222",
                    "hears_me": -7.0,
                    "hears_me_epoch": 110,
                    "i_hear_him": 5.0,
                    "i_hear_him_epoch": 110,
                    "i_hear_him_noise": -116.0,
                    "i_hear_him_noise_epoch": 110,
                }
            ],
            session_state,
        )

        self.assertEqual(first_rows[0]["session_tx"]["current"], -9.0)
        self.assertEqual(first_rows[0]["session_tx"]["delta"], "-")
        self.assertEqual(second_rows[0]["session_tx"]["current"], -7.0)
        self.assertEqual(second_rows[0]["session_tx"]["previous"], -9.0)
        self.assertEqual(second_rows[0]["session_tx"]["delta"], "+2.00")
        self.assertEqual(second_rows[0]["session_tx"]["min"], -9.0)
        self.assertEqual(second_rows[0]["session_tx"]["avg"], -8.0)
        self.assertEqual(second_rows[0]["session_tx"]["max"], -7.0)
        self.assertEqual(second_rows[0]["session_rx"]["avg"], 5.5)
        self.assertEqual(second_rows[0]["session_nf"]["avg"], -117.0)

    def test_packet_rx_uses_traceroute_previous_when_packet_previous_is_missing(self) -> None:
        now_epoch = 1_710_000_000

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "meshLogger.db"
            meshLogger.init_db(str(db_path))
            conn = meshLogger.connect_sqlite(str(db_path))
            try:
                conn.execute(
                    """
                    INSERT INTO nodes (
                        id, long_name, short_name, updated_utc
                    ) VALUES (?, ?, ?, ?)
                    """,
                    ("!22222222", "Alpha", "A", "2026-03-22T00:00:00+00:00"),
                )
                conn.executemany(
                    """
                    INSERT INTO traceroutes (
                        ts_utc, ts_epoch, self_id, target_id, direction, route_raw, route_pretty, hops
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            "2026-03-22T00:00:10+00:00",
                            now_epoch - 110,
                            "!11111111",
                            "!22222222",
                            "out",
                            "!11111111 --> !22222222 (-9.0dB)",
                            "self > Alpha (-9.0dB)",
                            1,
                        ),
                        (
                            "2026-03-22T00:00:20+00:00",
                            now_epoch - 100,
                            "!11111111",
                            "!22222222",
                            "back",
                            "!22222222 --> !11111111 (3.5dB)",
                            "Alpha > self (3.5dB)",
                            1,
                        ),
                        (
                            "2026-03-22T00:00:40+00:00",
                            now_epoch - 80,
                            "!11111111",
                            "!22222222",
                            "back",
                            "!22222222 --> !11111111 (4.0dB)",
                            "Alpha > self (4.0dB)",
                            1,
                        ),
                    ],
                )
                conn.execute(
                    """
                    INSERT INTO packet_rx_samples (
                        ts_utc, ts_epoch, node_id, from_id, to_id, portnum,
                        rx_snr, rx_rssi, noise_floor, hop_limit, hop_start, rx_time, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "2026-03-22T00:00:50+00:00",
                        now_epoch - 70,
                        "!22222222",
                        "!22222222",
                        "!11111111",
                        "TELEMETRY_APP",
                        5.5,
                        -112.0,
                        -117.5,
                        3,
                        3,
                        now_epoch - 70,
                        "{}",
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            rows = meshLogger.load_tune_direct_nodes(
                str(db_path),
                "!11111111",
                window_seconds=3600,
                now_epoch=now_epoch,
            )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["i_hear_him"], 5.5)
        self.assertEqual(rows[0]["i_hear_him_prev"], 4.0)
        self.assertEqual(rows[0]["i_hear_him_noise"], -117.5)
        self.assertEqual(rows[0]["rx_variability"]["history_count"], 3)

    def test_extract_direct_neighbor_sample_from_route_keeps_id_but_ignores_unknown_metric(self) -> None:
        node_id, snr_value = meshLogger._extract_direct_neighbor_sample_from_route(
            "!11111111",
            "!11111111 --> !22222222 (?dB)",
            direction="out",
        )
        self.assertEqual(node_id, "!22222222")
        self.assertIsNone(snr_value)


if __name__ == "__main__":
    unittest.main()
