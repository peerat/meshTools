#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


DEFAULT_BUSY_TIMEOUT_MS = 30000
LOCAL_TZ = datetime.now().astimezone().tzinfo or timezone.utc


def connect_sqlite(db_path: str | Path, *, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=max(1.0, busy_timeout_ms / 1000.0))
    conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def parse_ts_to_epoch(value: Any, *, naive_tz: timezone | Any = timezone.utc) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return float(value)
        except Exception:
            return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            s_norm = s.replace("Z", "+00:00")
            dt_obj = datetime.fromisoformat(s_norm)
            if dt_obj.tzinfo is None:
                dt_obj = dt_obj.replace(tzinfo=naive_tz)
            return dt_obj.timestamp()
        except Exception:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
                try:
                    dt_obj = datetime.strptime(s, fmt).replace(tzinfo=naive_tz)
                    return dt_obj.timestamp()
                except Exception:
                    continue
    return None


def parse_local_naive_ts_to_epoch(value: Any) -> Optional[int]:
    epoch = parse_ts_to_epoch(value, naive_tz=LOCAL_TZ)
    if epoch is None:
        return None
    return int(epoch)


def ensure_column(conn: sqlite3.Connection, table: str, name: str, ctype: str) -> None:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    existing = {row[1] for row in cur.fetchall()}
    if name not in existing:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ctype}")
        conn.commit()


def ensure_traceroutes_ts_epoch(conn: sqlite3.Connection) -> None:
    ensure_column(conn, "traceroutes", "ts_epoch", "INTEGER")

    cur = conn.cursor()
    cur.execute("SELECT id, ts_utc FROM traceroutes WHERE ts_epoch IS NULL")
    rows = cur.fetchall()
    if not rows:
        return

    updates = []
    for row_id, ts_utc in rows:
        updates.append((parse_local_naive_ts_to_epoch(ts_utc), row_id))

    cur.executemany("UPDATE traceroutes SET ts_epoch = ? WHERE id = ?", updates)
    conn.commit()
