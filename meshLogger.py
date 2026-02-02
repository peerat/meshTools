#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime as _dt
import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import time
import unicodedata
import threading
import ast
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

VERSION = "1.9.0"

# ----------------------------
# Global stop + current child process (fast Ctrl+C shutdown)
# RU: Глобальная остановка + текущий дочерний процесс (для мгновенного Ctrl+C)
# ----------------------------

STOP = False
CURRENT_PROC: Optional[subprocess.Popen] = None
LISTEN_PROC: Optional[subprocess.Popen] = None
LISTEN_SUSPENDED = False


def _sigint_handler(_signum, _frame):
    global STOP, CURRENT_PROC
    STOP = True
    if CURRENT_PROC is not None:
        _terminate_process(CURRENT_PROC)
    if LISTEN_PROC is not None:
        _terminate_process(LISTEN_PROC)


# ----------------------------
# Utilities: time / output
# RU: Утилиты: время / вывод
# ----------------------------

def ts_now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def date_today() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d")


def out(msg: str) -> None:
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def clean_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", s)


def detect_device_not_found(text: str) -> bool:
    s = (text or "").lower()
    if not s:
        return False
    if "file not found error" in s:
        return True
    if "serial device" in s and "not found" in s:
        return True
    if "no such file or directory" in s and ("/dev/" in s or "tty" in s):
        return True
    if "device at" in s and "was not found" in s:
        return True
    return False


def detect_device_busy(text: str) -> bool:
    s = (text or "").lower()
    if not s:
        return False
    if "resource temporarily unavailable" in s:
        return True
    if "couldn't be opened" in s and "port" in s:
        return True
    if "could not exclusively lock port" in s:
        return True
    if "might be in use by another process" in s:
        return True
    return False


def iso_utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def epoch_to_iso_utc(value: Optional[float]) -> Optional[str]:
    if value is None:
        return None
    try:
        return _dt.datetime.fromtimestamp(float(value), tz=_dt.timezone.utc).isoformat(timespec="seconds")
    except Exception:
        return None


def format_ts_display(value: Optional[str]) -> str:
    """
    Format ISO ts to 'YYYY-MM-DD HH:MM:SS' (drop 'T' and timezone).
    RU: Форматирует ISO в 'YYYY-MM-DD HH:MM:SS' (без 'T' и зоны).
    """
    if not value:
        return ""
    s = str(value).strip()
    if not s:
        return ""
    # Replace T with space and drop timezone suffix.
    if "T" in s:
        s = s.replace("T", " ")
    if "+" in s:
        s = s.split("+", 1)[0].strip()
    if s.endswith("Z"):
        s = s[:-1].strip()
    return s


def fmt_line(ts: str, pct: str, cyc: str, hop: str, msg: str) -> str:
    # TS<space>PCT<TAB>[cycle][i/n]<space>HOP<TAB>MESSAGE
    # RU: TS<пробел>PCT<TAB>[cycle][i/n]<пробел>HOP<TAB>MESSAGE
    return f"{ts} {pct}\t{cyc} {hop}\t{msg}"


def _display_width(s: str) -> int:
    width = 0
    for ch in s:
        if ch == "\t":
            width += 4
            continue
        if unicodedata.combining(ch):
            continue
        eaw = unicodedata.east_asian_width(ch)
        width += 2 if eaw in ("W", "F") else 1
    return width


def _ljust_display(s: str, width: int) -> str:
    pad = width - _display_width(s)
    if pad <= 0:
        return s
    return s + (" " * pad)


def format_table(headers: List[str], rows: List[List[object]]) -> List[str]:
    widths = [_display_width(h) for h in headers]
    for row in rows:
        for i, v in enumerate(row):
            widths[i] = max(widths[i], _display_width(str(v) if v is not None else "-"))
    line1 = "  " + "  ".join(_ljust_display(h, widths[i]) for i, h in enumerate(headers))
    line2 = "  " + "  ".join(_ljust_display("-" * widths[i], widths[i]) for i in range(len(headers)))
    out_lines = [line1, line2]
    for row in rows:
        out_lines.append(
            "  " + "  ".join(_ljust_display(str(v) if v is not None else "-", widths[i]) for i, v in enumerate(row))
        )
    return out_lines


# ----------------------------
# Node ID normalization
# RU: Нормализация id узла
# ----------------------------

_NODE_HEX8 = re.compile(r"^[0-9a-fA-F]{8}$")
_NODE_BANG_HEX8 = re.compile(r"^![0-9a-fA-F]{8}$")
_BANG_ID_FINDER = re.compile(r"![0-9a-fA-F]{8}")


def normalize_node_id(s: str) -> Optional[str]:
    """
    Accepts:
      - !aca96d48
      - aca96d48   (to avoid bash history expansion on '!')
    Returns canonical lower-case "!xxxxxxxx" or None.
    RU:
    Принимает:
      - !aca96d48
      - aca96d48   (чтобы избежать расширения истории bash по '!')
    Возвращает канонический нижний регистр "!xxxxxxxx" или None.
    """
    s = (s or "").strip()
    if not s:
        return None
    if _NODE_BANG_HEX8.match(s):
        return s.lower()
    if _NODE_HEX8.match(s):
        return "!" + s.lower()
    return None


# ----------------------------
# SQLite storage
# RU: SQLite-хранилище
# ----------------------------

def init_db(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                long_name TEXT,
                short_name TEXT,
                role TEXT,
                hardware TEXT,
                first_seen_utc TEXT,
                last_seen_utc TEXT,
                last_heard_utc TEXT,
                updated_utc TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS node_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT,
                ts_utc TEXT,
                sample_type TEXT,
                snr REAL,
                hops INTEGER,
                last_heard_utc TEXT,
                channel_util REAL,
                tx_air_util REAL,
                battery_level REAL,
                voltage REAL,
                uptime_seconds INTEGER,
                position_lat REAL,
                position_lon REAL,
                position_alt REAL,
                position_time_utc TEXT,
                location_source TEXT,
                temperature_c REAL,
                humidity_pct REAL,
                pressure_hpa REAL,
                gas_resistance REAL,
                light_lux REAL,
                sample_json TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_node_samples_node_ts
            ON node_samples (node_id, ts_utc)
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS info_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc TEXT,
                info_json TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS listen_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc TEXT,
                event_type TEXT,
                node_id TEXT,
                raw_json TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS traceroutes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc TEXT,
                self_id TEXT,
                target_id TEXT,
                direction TEXT,
                route_raw TEXT,
                route_pretty TEXT,
                hops INTEGER
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS node_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc TEXT,
                node_id TEXT,
                field TEXT,
                from_value TEXT,
                to_value TEXT
            )
            """
        )
        conn.commit()

        # lightweight migration for existing DBs (add missing columns)
        def _ensure_columns(table: str, cols: Dict[str, str]) -> None:
            cur.execute(f"PRAGMA table_info({table})")
            existing = {row[1] for row in cur.fetchall()}
            for name, ctype in cols.items():
                if name not in existing:
                    cur.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ctype}")

        _ensure_columns(
            "node_samples",
            {
                "sample_type": "TEXT",
                "snr": "REAL",
                "hops": "INTEGER",
                "last_heard_utc": "TEXT",
                "channel_util": "REAL",
                "tx_air_util": "REAL",
                "battery_level": "REAL",
                "voltage": "REAL",
                "uptime_seconds": "INTEGER",
                "position_lat": "REAL",
                "position_lon": "REAL",
                "position_alt": "REAL",
                "position_time_utc": "TEXT",
                "location_source": "TEXT",
                "temperature_c": "REAL",
                "humidity_pct": "REAL",
                "pressure_hpa": "REAL",
                "gas_resistance": "REAL",
                "light_lux": "REAL",
                "sample_json": "TEXT",
            },
        )
        _ensure_columns(
            "nodes",
            {
                "long_name": "TEXT",
                "short_name": "TEXT",
                "role": "TEXT",
                "hardware": "TEXT",
                "first_seen_utc": "TEXT",
                "last_seen_utc": "TEXT",
                "last_heard_utc": "TEXT",
                "updated_utc": "TEXT",
            },
        )
        conn.commit()
    finally:
        conn.close()


def _get_meta(conn: sqlite3.Connection, key: str) -> Optional[str]:
    cur = conn.cursor()
    cur.execute("SELECT value FROM meta WHERE key = ?", (key,))
    row = cur.fetchone()
    return row[0] if row else None


def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def upsert_node(conn: sqlite3.Connection, node: Dict[str, object], ts_utc: str, sample_type: str = "nodes") -> None:
    user = node.get("user") if isinstance(node.get("user"), dict) else {}
    node_id = user.get("id") or node.get("id")
    if not isinstance(node_id, str) or not node_id.startswith("!"):
        return

    long_name = user.get("longName") or user.get("long_name") or ""
    short_name = user.get("shortName") or user.get("short_name") or ""
    role = user.get("role") or node.get("role") or ""
    hardware = user.get("hwModel") or user.get("hw_model") or node.get("hardware") or ""
    snr = node.get("snr")
    hops = node.get("hopsAway") if node.get("hopsAway") is not None else node.get("hops_away")
    last_heard = node.get("lastHeard") if node.get("lastHeard") is not None else node.get("last_heard")
    last_heard_utc = epoch_to_iso_utc(last_heard) if isinstance(last_heard, (int, float)) else None

    channel_util = None
    tx_air_util = None
    dev_metrics = node.get("deviceMetrics") if isinstance(node.get("deviceMetrics"), dict) else None
    if dev_metrics:
        channel_util = dev_metrics.get("channelUtilization")
        tx_air_util = dev_metrics.get("airUtilTx")
    if channel_util is None:
        channel_util = node.get("channelUtil") or node.get("channel_util") or node.get("channelUtilization")
    if tx_air_util is None:
        tx_air_util = node.get("txAirUtil") or node.get("tx_air_util") or node.get("txAirUtilization")

    battery_level = None
    voltage = None
    uptime_seconds = None
    if dev_metrics:
        battery_level = dev_metrics.get("batteryLevel")
        voltage = dev_metrics.get("voltage")
        uptime_seconds = dev_metrics.get("uptimeSeconds")

    position = node.get("position") if isinstance(node.get("position"), dict) else None
    position_lat = position.get("latitude") if position else None
    position_lon = position.get("longitude") if position else None
    position_alt = position.get("altitude") if position else None
    position_time = position.get("time") if position else None
    position_time_utc = epoch_to_iso_utc(position_time) if isinstance(position_time, (int, float)) else None
    location_source = position.get("locationSource") if position else None

    temperature_c = None
    humidity_pct = None
    pressure_hpa = None
    gas_resistance = None
    light_lux = None
    env = node.get("environmentalMetrics") if isinstance(node.get("environmentalMetrics"), dict) else None
    if env:
        temperature_c = env.get("temperature")
        humidity_pct = env.get("relativeHumidity")
        pressure_hpa = env.get("barometricPressure")
        gas_resistance = env.get("gasResistance")
        light_lux = env.get("lux")

    cur = conn.cursor()
    cur.execute("SELECT first_seen_utc FROM nodes WHERE id = ?", (node_id,))
    row = cur.fetchone()
    first_seen = row[0] if row else None
    if not first_seen:
        first_seen = ts_utc

    cur.execute(
        """
        INSERT INTO nodes (
            id, long_name, short_name, role, hardware,
            first_seen_utc, last_seen_utc, last_heard_utc, updated_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            long_name=excluded.long_name,
            short_name=excluded.short_name,
            role=excluded.role,
            hardware=excluded.hardware,
            last_seen_utc=excluded.last_seen_utc,
            last_heard_utc=excluded.last_heard_utc,
            updated_utc=excluded.updated_utc
        """,
        (
            node_id,
            long_name,
            short_name,
            role,
            hardware,
            first_seen,
            ts_utc,
            last_heard_utc,
            ts_utc,
        ),
    )
    cur.execute(
        """
        INSERT INTO node_samples (
            node_id, ts_utc, sample_type,
            snr, hops, last_heard_utc,
            channel_util, tx_air_util,
            battery_level, voltage, uptime_seconds,
            position_lat, position_lon, position_alt, position_time_utc, location_source,
            temperature_c, humidity_pct, pressure_hpa, gas_resistance, light_lux,
            sample_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            node_id,
            ts_utc,
            sample_type,
            snr,
            hops,
            last_heard_utc,
            channel_util,
            tx_air_util,
            battery_level,
            voltage,
            uptime_seconds,
            position_lat,
            position_lon,
            position_alt,
            position_time_utc,
            location_source,
            temperature_c,
            humidity_pct,
            pressure_hpa,
            gas_resistance,
            light_lux,
            json.dumps(node, ensure_ascii=False),
        ),
    )


def _load_nodes_snapshot(conn: sqlite3.Connection) -> Dict[str, Dict[str, object]]:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, long_name, short_name, role, hardware, first_seen_utc, last_seen_utc, last_heard_utc
        FROM nodes
        """
    )
    snap: Dict[str, Dict[str, object]] = {}
    for row in cur.fetchall():
        (nid, ln, sn, role, hw, fs, ls, lh) = row
        snap[nid] = {
            "long_name": ln,
            "short_name": sn,
            "role": role,
            "hardware": hw,
            "first_seen_utc": fs,
            "last_seen_utc": ls,
            "last_heard_utc": lh,
        }
    return snap


def _load_nodes_snapshot_from_db(db_path: str) -> Dict[str, Dict[str, object]]:
    if not os.path.isfile(db_path):
        return {}
    try:
        conn = sqlite3.connect(db_path)
    except Exception:
        return {}
    try:
        return _load_nodes_snapshot(conn)
    finally:
        conn.close()


def _diff_nodes(prev: Dict[str, Dict[str, object]], cur: Dict[str, Dict[str, object]]) -> Tuple[List[str], List[Tuple[str, Dict[str, Dict[str, object]]]]]:
    new_nodes = [nid for nid in cur.keys() if nid not in prev]
    changes: List[Tuple[str, Dict[str, Dict[str, object]]]] = []
    tracked_fields = [
        "long_name",
        "short_name",
        "role",
        "hardware",
        "last_seen_utc",
        "last_heard_utc",
        "channel_util",
        "tx_air_util",
        "hops",
    ]
    for nid in cur.keys():
        if nid not in prev:
            continue
        change_map: Dict[str, Dict[str, object]] = {}
        for f in tracked_fields:
            a = prev[nid].get(f)
            b = cur[nid].get(f)
            if a != b:
                change_map[f] = {"from": a, "to": b}
        if change_map:
            changes.append((nid, change_map))
    return new_nodes, changes


def _record_changes(conn: sqlite3.Connection, ts_utc: str, changes: List[Tuple[str, Dict[str, Dict[str, object]]]]) -> None:
    if not changes:
        return
    cur = conn.cursor()
    rows = []
    for node_id, change_map in changes:
        for field, vals in change_map.items():
            rows.append(
                (
                    ts_utc,
                    node_id,
                    field,
                    str(vals.get("from")) if vals.get("from") is not None else None,
                    str(vals.get("to")) if vals.get("to") is not None else None,
                )
            )
    cur.executemany(
        "INSERT INTO node_changes (ts_utc, node_id, field, from_value, to_value) VALUES (?, ?, ?, ?, ?)",
        rows,
    )


def _print_db_report(prev: Dict[str, Dict[str, object]], cur: Dict[str, Dict[str, object]]) -> None:
    new_nodes, changes = _diff_nodes(prev, cur)
    out(line_bar("[DB REPORT] / [ОТЧЁТ БД]"))
    out(f"  Total: {len(cur)} | New: {len(new_nodes)} | Changed: {len(changes)}")
    if new_nodes:
        out("")
        out("[NEW NODES] / [НОВЫЕ УЗЛЫ]")
        rows: List[List[object]] = []
        for i, nid in enumerate(sorted(new_nodes), 1):
            rec = cur[nid]
            rows.append([
                i,
                nid,
                rec.get("long_name") or "",
                rec.get("short_name") or "",
                format_ts_display(rec.get("first_seen_utc")),
                format_ts_display(rec.get("last_seen_utc")),
            ])
        for line in format_table(["#", "ID", "Long", "Short", "First Seen", "Last Seen"], rows):
            out(line)

    if changes:
        out("")
        out("[CHANGES] / [ИЗМЕНЕНИЯ]")
        for nid, ch in changes:
            out(f"  * {nid}")
            rows = []
            for k, v in ch.items():
                rows.append([k, v.get("from"), v.get("to")])
            for line in format_table(["Field", "From", "To"], rows):
                out(line)

    if cur:
        out(line_bar("[NODES] / [УЗЛЫ]"))
        rows = []
        items = sorted(cur.items(), key=lambda x: (x[1].get("first_seen_utc") or "", x[0]))
        for i, (nid, rec) in enumerate(items, 1):
            rows.append([
                i,
                nid,
                rec.get("long_name") or "",
                rec.get("short_name") or "",
                rec.get("first_seen_utc") or "",
                rec.get("last_seen_utc") or "",
            ])
        for line in format_table(["#", "ID", "Long", "Short", "First Seen", "Last Seen"], rows):
            out(line)


def _print_db_nodes_only(cur: Dict[str, Dict[str, object]]) -> None:
    if not cur:
        return
    out(line_bar("[NODES] / [УЗЛЫ]"))
    rows = []
    items = sorted(cur.items(), key=lambda x: (x[1].get("first_seen_utc") or "", x[0]))
    for i, (nid, rec) in enumerate(items, 1):
        rows.append([
            i,
            nid,
            rec.get("long_name") or "",
            rec.get("short_name") or "",
            format_ts_display(rec.get("first_seen_utc")),
            format_ts_display(rec.get("last_seen_utc")),
        ])
    for line in format_table(["#", "ID", "Long", "Short", "First Seen", "Last Seen"], rows):
        out(line)


def _print_nodes_from_info(nodes: Dict[str, dict], db_snap: Optional[Dict[str, Dict[str, object]]] = None) -> None:
    if not nodes:
        return
    out(line_bar("[NODES FROM INFO] / [УЗЛЫ ИЗ INFO]"))
    rows: List[List[object]] = []
    for i, (nid, nd) in enumerate(sorted(nodes.items(), key=lambda x: x[0]), 1):
        db_rec = db_snap.get(nid, {}) if isinstance(db_snap, dict) else {}
        u = nd.get("user") if isinstance(nd.get("user"), dict) else {}
        ln = (u.get("longName") or "").strip()
        sn = (u.get("shortName") or "").strip()
        lh = nd.get("lastHeard")
        lh_iso = epoch_to_iso_utc(lh) if isinstance(lh, (int, float)) else ""
        fs = db_rec.get("first_seen_utc") or ""
        ls = db_rec.get("last_seen_utc") or (lh_iso or "")
        rows.append([i, nid, ln, sn, format_ts_display(fs), format_ts_display(ls)])
    for line in format_table(["#", "ID", "Long", "Short", "First Seen", "Last Seen"], rows):
        out(line)


def line_bar(title: Optional[str] = None) -> str:
    if not title:
        return "=" * 70
    txt = f" {title} "
    if len(txt) >= 70:
        return txt
    side = (70 - len(txt)) // 2
    return ("=" * side) + txt + ("=" * (70 - len(txt) - side))


def migrate_nodeDb_txt_once(db_path: str, txt_path: str) -> bool:
    """
    Migrate nodeDb.txt -> SQLite only once.
    RU: Однократная миграция nodeDb.txt -> SQLite.
    """
    if not os.path.isfile(txt_path):
        return False
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    try:
        if _get_meta(conn, "migrated_nodeDb_txt") == "1":
            return False
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM nodes")
        if cur.fetchone()[0] > 0:
            _set_meta(conn, "migrated_nodeDb_txt", "1")
            conn.commit()
            return False

        with open(txt_path, "r", encoding="utf-8", errors="ignore") as f:
            try:
                data = json.load(f)
            except Exception:
                return False

        nodes = data.get("nodes") if isinstance(data, dict) else None
        if not isinstance(nodes, dict):
            return False

        ts_utc = iso_utc_now()
        for nid, rec in nodes.items():
            if not (isinstance(nid, str) and nid.startswith("!") and isinstance(rec, dict)):
                continue
            cur_info = rec.get("current") if isinstance(rec.get("current"), dict) else {}
            user = cur_info.get("user") if isinstance(cur_info.get("user"), dict) else {}
            raw = cur_info.get("raw_nodes_row") if isinstance(cur_info.get("raw_nodes_row"), dict) else {}

            node = {
                "user": {
                    "id": nid,
                    "longName": user.get("longName") or raw.get("User") or "",
                    "shortName": user.get("shortName") or raw.get("AKA") or "",
                    "hwModel": user.get("hwModel") or raw.get("Hardware") or "",
                    "role": user.get("role") or raw.get("Role") or "",
                },
                "snr": raw.get("snr_db") or raw.get("snr"),
                "lastHeard": cur_info.get("last_heard"),
                "hopsAway": cur_info.get("hops"),
                "deviceMetrics": {
                    "channelUtilization": cur_info.get("channel_util_pct"),
                    "airUtilTx": cur_info.get("tx_air_util_pct"),
                    "batteryLevel": cur_info.get("battery", {}).get("percent") if isinstance(cur_info.get("battery"), dict) else None,
                    "voltage": cur_info.get("battery", {}).get("voltage") if isinstance(cur_info.get("battery"), dict) else None,
                },
            }
            upsert_node(conn, node, ts_utc, sample_type="migrate")

        _set_meta(conn, "migrated_nodeDb_txt", "1")
        conn.commit()
        return True
    finally:
        conn.close()


# ----------------------------
# CLI launch
# RU: Запуск CLI
# ----------------------------

def _popen_new_process_group(cmd: List[str]) -> subprocess.Popen:
    if os.name == "nt":
        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=os.setsid,
    )


def _terminate_process(p: subprocess.Popen) -> None:
    if p.poll() is not None:
        return
    if os.name == "nt":
        try:
            p.send_signal(signal.CTRL_BREAK_EVENT)
            time.sleep(0.2)
        except Exception:
            pass
        try:
            if p.poll() is None:
                p.kill()
        except Exception:
            pass
        if p.poll() is None:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(p.pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass
    else:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass


_LISTEN_LOCK = threading.Lock()


def stop_listen() -> None:
    global LISTEN_PROC
    if LISTEN_PROC is not None:
        _terminate_process(LISTEN_PROC)
        LISTEN_PROC = None


def set_listen_suspended(v: bool) -> None:
    global LISTEN_SUSPENDED
    LISTEN_SUSPENDED = v


def run_cmd(cmd: List[str], timeout: int, tick: float = 0.2) -> Tuple[int, str, str]:
    """
    Run command with:
      - its own process group (for instant Ctrl+C kill)
      - periodic tick timeouts for frequent STOP checks
    RU:
    Запускает команду с:
      - отдельной группой процесса (чтобы мгновенно убить по Ctrl+C)
      - периодическими тик‑таймаутами для частой проверки STOP
    """
    global CURRENT_PROC, STOP

    p = None
    try:
        with _LISTEN_LOCK:
            set_listen_suspended(True)
            stop_listen()
        time.sleep(0.2)
        p = _popen_new_process_group(cmd)
        CURRENT_PROC = p
        start = time.time()

        stdout_chunks: List[str] = []
        stderr_chunks: List[str] = []

        while True:
            if STOP:
                _terminate_process(p)
                raise KeyboardInterrupt

            elapsed = time.time() - start
            if elapsed >= timeout:
                _terminate_process(p)
                return 124, "".join(stdout_chunks), "[TIMEOUT]"

            try:
                so, se = p.communicate(timeout=tick)
                stdout_chunks.append(so or "")
                stderr_chunks.append(se or "")
                rc = p.returncode if p.returncode is not None else 0
                return rc, "".join(stdout_chunks), "".join(stderr_chunks)
            except subprocess.TimeoutExpired:
                continue

    finally:
        CURRENT_PROC = None
        with _LISTEN_LOCK:
            set_listen_suspended(False)


# ----------------------------
# Meshtastic --info parsing
# RU: Парсинг Meshtastic --info
# ----------------------------

def extract_balanced_braces(text: str, start_idx: int) -> Optional[str]:
    i = text.find("{", start_idx)
    if i < 0:
        return None
    depth = 0
    for j in range(i, len(text)):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    return None


def parse_nodes_block(mesh_info_text: str) -> Dict[str, dict]:
    t = clean_ansi(mesh_info_text)
    t_lines = [line for line in t.splitlines() if line.strip() and line.strip() != "Connected to radio"]
    t_clean = "\n".join(t_lines).strip()
    if t_clean:
        try:
            import json
            parsed = json.loads(t_clean)
            if isinstance(parsed, dict):
                nodes = _extract_nodes_from_info_json(parsed)
                if nodes is not None:
                    return nodes
        except Exception:
            pass

        block = extract_balanced_braces(t_clean, 0)
        if block:
            try:
                import json
                parsed = json.loads(block)
                if isinstance(parsed, dict):
                    nodes = _extract_nodes_from_info_json(parsed)
                    if nodes is not None:
                        return nodes
            except Exception:
                pass
        nodes_block = _extract_nodes_block_from_text(t_clean)
        if nodes_block is not None:
            return nodes_block

    m = re.search(r"Nodes\s+in\s+mesh\s*:\s*", t)
    if not m:
        raise RuntimeError("cannot parse nodes (missing Nodes in mesh block)")
    block = extract_balanced_braces(t, m.end())
    if not block:
        raise RuntimeError("cannot parse nodes (missing Nodes in mesh block)")

    import json
    try:
        nodes = json.loads(block)
        if isinstance(nodes, dict):
            return nodes
        raise RuntimeError("nodes block is not a dict")
    except Exception:
        import ast
        nodes = ast.literal_eval(block)
        if isinstance(nodes, dict):
            return nodes
        raise RuntimeError("nodes block is not a dict")


def fetch_nodes_json(port: str, timeout: int) -> Optional[List[Dict[str, object]]]:
    for extra_args in (["--format", "json"], ["--json"], []):
        cmd = ["meshtastic", "--port", port, "--nodes"] + extra_args
        rc, so, se = run_cmd(cmd, timeout=max(60, timeout + 15))
        out_text = clean_ansi((so or "") + ("\n" + se if se else ""))
        if detect_device_not_found(out_text):
            raise RuntimeError(
                f"device not found on port {port} (meshtastic). Check cable/port/drivers (Windows: COM3). "
                f"RU: устройство не найдено на порту {port}. Проверьте кабель/порт/драйверы (Windows: COM3)."
            )
        if detect_device_busy(out_text):
            raise RuntimeError(
                f"device busy on port {port} (in use). Close other apps and try again. "
                f"RU: порт {port} занят (используется). Закройте другие приложения."
            )
        if rc != 0:
            continue
        cleaned = "\n".join(
            [line for line in out_text.splitlines() if line.strip() and line.strip() != "Connected to radio"]
        ).strip()
        if not cleaned:
            continue
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            continue
    return None


def fetch_info_raw(port: str, timeout: int) -> Optional[str]:
    for extra_args in (["--format", "json"], ["--json"], []):
        cmd = ["meshtastic", "--port", port, "--info"] + extra_args
        rc, so, se = run_cmd(cmd, timeout=max(60, timeout + 15))
        out_text = clean_ansi((so or "") + ("\n" + se if se else ""))
        if detect_device_not_found(out_text):
            raise RuntimeError(
                f"device not found on port {port} (meshtastic). Check cable/port/drivers (Windows: COM3). "
                f"RU: устройство не найдено на порту {port}. Проверьте кабель/порт/драйверы (Windows: COM3)."
            )
        if detect_device_busy(out_text):
            raise RuntimeError(
                f"device busy on port {port} (in use). Close other apps and try again. "
                f"RU: порт {port} занят (используется). Закройте другие приложения."
            )
        if rc == 0 and out_text.strip():
            return out_text
    return None


def update_db_from_nodes(port: str, timeout: int, db_path: str) -> Tuple[int, Dict[str, Dict[str, object]], Dict[str, Dict[str, object]]]:
    nodes_list = fetch_nodes_json(port, timeout)
    if not nodes_list:
        return 0, {}, {}
    init_db(db_path)
    ts_utc = iso_utc_now()
    conn = sqlite3.connect(db_path)
    try:
        prev = _load_nodes_snapshot(conn)
        for node in nodes_list:
            if isinstance(node, dict):
                upsert_node(conn, node, ts_utc, sample_type="nodes")
        info_raw = fetch_info_raw(port, timeout)
        if info_raw:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO info_samples (ts_utc, info_json) VALUES (?, ?)",
                (ts_utc, info_raw),
            )
        conn.commit()
        cur_snap = _load_nodes_snapshot(conn)
        new_nodes, changes = _diff_nodes(prev, cur_snap)
        _record_changes(conn, ts_utc, changes)
        conn.commit()
    finally:
        conn.close()

    return len(nodes_list), prev, cur_snap


def insert_traceroute(db_path: str, ts_utc: str, self_id: str, target_id: str, direction: str, route_raw: str, route_pretty: str) -> None:
    init_db(db_path)
    hops = count_edges(route_raw)
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO traceroutes (ts_utc, self_id, target_id, direction, route_raw, route_pretty, hops) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts_utc, self_id, target_id, direction, route_raw, route_pretty, hops),
        )
        conn.commit()
    finally:
        conn.close()


def _extract_dict_from_line(line: str) -> Optional[Dict[str, object]]:
    i = line.find("{")
    j = line.rfind("}")
    if i < 0 or j < 0 or j <= i:
        return None
    try:
        return ast.literal_eval(line[i : j + 1])
    except Exception:
        return None


def _extract_node_id_from_event(d: Dict[str, object]) -> Optional[str]:
    if isinstance(d.get("fromId"), str) and d.get("fromId").startswith("!"):
        return d.get("fromId")
    user = d.get("user") if isinstance(d.get("user"), dict) else None
    if user and isinstance(user.get("id"), str) and user.get("id").startswith("!"):
        return user.get("id")
    return None


def _insert_listen_event(db_path: str, ts_utc: str, event_type: str, node_id: Optional[str], data: Dict[str, object]) -> None:
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO listen_events (ts_utc, event_type, node_id, raw_json) VALUES (?, ?, ?, ?)",
            (ts_utc, event_type, node_id, json.dumps(data, ensure_ascii=False)),
        )
        conn.commit()
    finally:
        conn.close()


def _handle_listen_line(db_path: str, line: str) -> None:
    if "Received nodeinfo:" in line:
        d = _extract_dict_from_line(line)
        if isinstance(d, dict):
            node_id = _extract_node_id_from_event(d)
            ts_utc = iso_utc_now()
            _insert_listen_event(db_path, ts_utc, "nodeinfo", node_id, d)
            if node_id:
                conn = sqlite3.connect(db_path)
                try:
                    upsert_node(conn, d, ts_utc, sample_type="listen_nodeinfo")
                    conn.commit()
                finally:
                    conn.close()
        return

    if "asDict:" in line or "d:{" in line:
        d = _extract_dict_from_line(line)
        if isinstance(d, dict):
            node_id = _extract_node_id_from_event(d)
            ts_utc = iso_utc_now()
            event_type = "listen_event"
            decoded = d.get("decoded") if isinstance(d.get("decoded"), dict) else None
            if decoded and decoded.get("portnum") == "POSITION_APP":
                event_type = "position"
            elif decoded and decoded.get("portnum") == "TELEMETRY_APP":
                event_type = "telemetry"
            _insert_listen_event(db_path, ts_utc, event_type, node_id, d)
            if node_id and decoded and isinstance(decoded.get("telemetry"), dict):
                telem = decoded.get("telemetry") if isinstance(decoded.get("telemetry"), dict) else {}
                node = {
                    "user": {"id": node_id},
                    "deviceMetrics": telem.get("deviceMetrics"),
                    "environmentalMetrics": telem.get("environmentalMetrics"),
                }
                conn = sqlite3.connect(db_path)
                try:
                    upsert_node(conn, node, ts_utc, sample_type="listen_telemetry")
                    conn.commit()
                finally:
                    conn.close()
            if node_id and decoded and isinstance(decoded.get("position"), dict):
                node = {"user": {"id": node_id}, "position": decoded.get("position")}
                conn = sqlite3.connect(db_path)
                try:
                    upsert_node(conn, node, ts_utc, sample_type="listen_position")
                    conn.commit()
                finally:
                    conn.close()
        return


def start_listen_thread(port: str, timeout: int, db_path: str) -> threading.Thread:
    def _worker() -> None:
        cmd = ["meshtastic", "--port", port, "--listen"]
        while True:
            if STOP:
                return
            if LISTEN_SUSPENDED:
                time.sleep(0.2)
                continue
            with _LISTEN_LOCK:
                try:
                    global LISTEN_PROC
                    LISTEN_PROC = subprocess.Popen(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
                    )
                except Exception:
                    LISTEN_PROC = None
                    time.sleep(5)
                    continue
                p = LISTEN_PROC
            if not p or not p.stdout:
                time.sleep(5)
                continue
            for raw in p.stdout:
                if STOP:
                    return
                line = raw.strip()
                if not line:
                    continue
                if detect_device_not_found(line):
                    out(
                        f"{ts_now()} ERROR: device not found on port {port} (meshtastic). Windows: COM3. "
                        f"RU: устройство не найдено на порту {port} (Windows: COM3)."
                    )
                    time.sleep(5)
                    break
                if detect_device_busy(line):
                    out(
                        f"{ts_now()} ERROR: device busy on port {port} (in use). "
                        f"RU: порт {port} занят (используется)."
                    )
                    time.sleep(5)
                    break
                _handle_listen_line(db_path, line)
            time.sleep(2)

    th = threading.Thread(target=_worker, daemon=True)
    th.start()
    return th


def _extract_nodes_from_info_json(parsed: dict) -> Optional[Dict[str, dict]]:
    candidate_keys = ("nodes", "Nodes", "nodesById")
    for key in candidate_keys:
        nodes = parsed.get(key)
        if isinstance(nodes, dict):
            return nodes
    for key in ("mesh", "meshInfo", "info"):
        nested = parsed.get(key)
        if isinstance(nested, dict):
            for nested_key in candidate_keys:
                nodes = nested.get(nested_key)
                if isinstance(nodes, dict):
                    return nodes
    return None


def _extract_nodes_block_from_text(text: str) -> Optional[Dict[str, dict]]:
    m = re.search(r'"nodes"\s*:\s*{', text)
    if not m:
        return None
    block = extract_balanced_braces(text, m.start())
    if not block:
        return None
    try:
        import json
        parsed = json.loads(block)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    return None


def parse_my_node_num(mesh_info_text: str) -> Optional[int]:
    t = clean_ansi(mesh_info_text)
    m = re.search(r'"myNodeNum"\s*:\s*(\d+)', t)
    return int(m.group(1)) if m else None


def parse_owner_line(mesh_info_text: str) -> Tuple[Optional[str], Optional[str]]:
    t = clean_ansi(mesh_info_text)
    m = re.search(r"^Owner:\s*(.+?)\s*\((.+?)\)\s*$", t, flags=re.MULTILINE)
    if not m:
        return None, None
    return m.group(1).strip(), m.group(2).strip()


def detect_self_id(mesh_info_text: str, nodes: Dict[str, dict]) -> str:
    my_num = parse_my_node_num(mesh_info_text)
    if my_num is not None:
        for node_id, nd in nodes.items():
            try:
                if int(nd.get("num", -1)) == my_num:
                    return node_id.lower()
            except Exception:
                continue

    owner_long, owner_short = parse_owner_line(mesh_info_text)
    if owner_long or owner_short:
        for node_id, nd in nodes.items():
            u = nd.get("user") or {}
            ln = (u.get("longName") or "").strip()
            sn = (u.get("shortName") or "").strip()
            if owner_long and ln == owner_long:
                return node_id.lower()
            if owner_short and sn == owner_short:
                return node_id.lower()

    raise RuntimeError("cannot detect self node (need My info/myNodeNum or Owner line + nodes list)")


# ----------------------------
# Node model / filtering
# RU: Модель узла / отбор
# ----------------------------

@dataclass
class NodeRec:
    node_id: str
    long: str
    short: str
    last_heard: Optional[int]
    hops_away: Optional[int]


def node_names(nodes: Dict[str, dict], node_id: str) -> Tuple[str, str]:
    nd = nodes.get(node_id) or {}
    u = nd.get("user") or {}
    ln = (u.get("longName") or node_id).strip()
    sn = (u.get("shortName") or "").strip()
    return ln, sn


def load_active_nodes(nodes: Dict[str, dict], hours: int, self_id: str) -> List[NodeRec]:
    now = int(time.time())
    cutoff = now - int(hours * 3600)

    out_list: List[NodeRec] = []
    for node_id, nd in nodes.items():
        nid = node_id.lower()
        if nid == self_id:
            continue

        last_heard = nd.get("lastHeard", None)
        hops_away = nd.get("hopsAway", None)
        if not isinstance(hops_away, int):
            hops_away = None

        if isinstance(last_heard, int) and last_heard >= cutoff:
            ln, sn = node_names(nodes, nid)
            out_list.append(NodeRec(node_id=nid, long=ln, short=sn, last_heard=last_heard, hops_away=hops_away))

    out_list.sort(key=lambda x: (x.long.lower(), x.node_id.lower()))
    return out_list


def read_id_list(path: str) -> set:
    """
    Reads ANY text file, extracts all !xxxxxxxx (hex8) occurrences.
    Everything else is ignored. Duplicates are removed.
    RU:
    Читает ЛЮБОЙ текстовый файл, извлекает все вхождения !xxxxxxxx (hex8) по всему файлу.
    Всё остальное игнорируется. Дубликаты удаляются.
    """
    want = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            for m in _BANG_ID_FINDER.finditer(line):
                want.add(m.group(0).lower())
    return want


def filter_ids(all_nodes: List[NodeRec], want_ids: Optional[set]) -> List[NodeRec]:
    if not want_ids:
        return all_nodes
    return [n for n in all_nodes if n.node_id in want_ids]


def filter_hops(all_nodes: List[NodeRec], minhops: Optional[int], maxhops: Optional[int]) -> List[NodeRec]:
    if minhops is None and maxhops is None:
        return all_nodes

    out_list: List[NodeRec] = []
    for n in all_nodes:
        if n.hops_away is None:
            continue
        if minhops is not None and n.hops_away < minhops:
            continue
        if maxhops is not None and n.hops_away > maxhops:
            continue
        out_list.append(n)
    return out_list


# ----------------------------
# traceroute parsing -> human readable routes
# RU: Парсинг traceroute -> маршруты с человекочитаемыми именами
# ----------------------------

def parse_routes_from_meshtastic_output(raw: str) -> Tuple[Optional[str], Optional[str]]:
    t = clean_ansi(raw)

    towards = None
    back = None

    m1 = re.search(r"Route traced towards destination:\s*\n(.+)", t)
    if m1:
        towards = m1.group(1).strip()

    m2 = re.search(r"Route traced back to us:\s*\n(.+)", t)
    if m2:
        back = m2.group(1).strip()

    if towards and "\n" in towards:
        towards = towards.splitlines()[0].strip()
    if back and "\n" in back:
        back = back.splitlines()[0].strip()

    return towards, back


def route_ids_to_names(route_line: str, nodes: Dict[str, dict]) -> str:
    parts = [p.strip() for p in route_line.split("-->")]
    out_parts = []
    for p in parts:
        m = re.match(r"^(![0-9a-fA-F]{8})(\s*\(.*\))?$", p)
        if m:
            nid = m.group(1).lower()
            suffix = m.group(2) or ""
            ln, sn = node_names(nodes, nid)
            out_parts.append(f"{ln}[{sn}]{suffix}")
        else:
            out_parts.append(p)
    return " > ".join(out_parts)


def count_edges(route_line: str) -> int:
    parts = [p.strip() for p in route_line.split("-->") if p.strip()]
    return max(1, len(parts) - 1)


# ----------------------------
# Logging
# RU: Логирование
# ----------------------------

def log_filename_for_day(self_id: str) -> str:
    # CHANGED: write logs to meshLogger/ subfolder (relative to script cwd).
    # RU: ИЗМЕНЕНО: пишем логи в подпапку meshLogger/ (относительно cwd скрипта)
    return f"meshLogger/{date_today()} {self_id}.txt"


def append_log_line(path: str, line: str) -> None:
    # CHANGED: ensure meshLogger exists.
    # RU: ИЗМЕНЕНО: гарантируем существование meshLogger
    import os
    os.makedirs("meshLogger", exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line.rstrip("\n") + "\n")


# ----------------------------
# Help text (detailed)
# RU: Текст справки (подробно)
# ----------------------------

HELP_TEXT = """\
usage: meshLogger.py [options]

Meshtastic route logger.
RU: Логгер маршрутов Meshtastic.
Periodically performs "meshtastic --traceroute" to selected mesh nodes and stores routes in SQLite.
RU: Периодически выполняет "meshtastic --traceroute" к выбранным узлам и сохраняет маршруты в SQLite.

Terminal output:
RU: Вывод в терминал:
  3 lines per node:
  RU: 3 строки на узел:
    1) request line
    RU: 1) строка запроса
    2) if ok: route towards ("> ..."), else: "<name>[<short>] is no response..."
    RU: 2) если ок: маршрут туда ("> ..."), иначе: "<name>[<short>] is no response..."
    3) if ok: route back ("< ...")
    RU: 3) если ок: маршрут обратно ("< ...")

Node IDs and Bash:
RU: ID узлов и Bash:
  Bash treats '!' as history expansion ("event not found").
  RU: Bash воспринимает '!' как историю команд ("event not found").
  This logger accepts node IDs BOTH ways:
  RU: Этот логгер принимает ID узла ОБОИМИ способами:
    - with bang:  !aca96d48
    RU: - с восклицательным знаком: !aca96d48
    - without:    aca96d48   (recommended; no quoting needed)
    RU: - без знака:          aca96d48   (рекомендуется; без кавычек)

options:
  -h, --help
        Show this help message and exit
        RU: Показать помощь и выйти

  --port PORT
        Serial port for Meshtastic device.
        Default: /dev/ttyUSB0
        RU: Серийный порт устройства Meshtastic.
        RU: По умолчанию: /dev/ttyUSB0 (Windows: COM3 и т.п.)

  --hours HOURS
        Consider nodes active if they were heard within the last HOURS (by lastHeard).
        Used to build polling list from "meshtastic --info".
        Default: 24
        RU: Узел активен, если был слышен за последние HOURS (по lastHeard).
        RU: Используется для списка опроса из "meshtastic --info".
        RU: По умолчанию: 24

  --timeout SECONDS
        Timeout for single "meshtastic --traceroute" command.
        If exceeded, the request is treated as "no response".
        Default: 30
        RU: Таймаут одного "meshtastic --traceroute".
        RU: Если превышен — считаем, что ответа нет.
        RU: По умолчанию: 30

  --pause SECONDS
        Pause between traceroute requests (after both success and fail).
        Default: 30
        RU: Пауза между запросами traceroute (после успеха и неудачи).
        RU: По умолчанию: 30

  --db FILE
        SQLite DB file for node snapshots.
        Default: meshLogger.db
        RU: SQLite-файл базы для снимков узлов.
        RU: По умолчанию: meshLogger.db

  --db-schema
        Print DB schema and exit.
        RU: Показать схему БД и выйти.

  --minhops N
        Poll only nodes with hopsAway >= N (from "meshtastic --info").
        Nodes without hopsAway are excluded when hop filtering is used.
        Default: not set
        RU: Опрос только узлов с hopsAway >= N (из "meshtastic --info").
        RU: Узлы без hopsAway исключаются при фильтрации.
        RU: По умолчанию: не задано

  --maxhops N
        Poll only nodes with hopsAway <= N (from "meshtastic --info").
        Default: not set
        RU: Опрос только узлов с hopsAway <= N (из "meshtastic --info").
        RU: По умолчанию: не задано

  --once
        Do exactly one full pass over the selected nodes and exit.
        Default: off (continuous loop)
        RU: Сделать один полный проход и выйти.
        RU: По умолчанию: выключено (бесконечный цикл)

  --node NODEID
        Poll only one specific node.
        NODEID can be "!xxxxxxxx" or "xxxxxxxx".
        Example:
          --node aca96d48
        RU: Опросить только один узел.
        RU: NODEID может быть "!xxxxxxxx" или "xxxxxxxx".
        RU: Пример:
          --node aca96d48

  --id-list FILE
        Poll only node IDs found inside FILE.
        The file may contain ANY text; we extract all patterns like "!xxxxxxxx".
        This filter is applied on top of --hours selection.
        Example:
          --id-list nodes.txt
        RU: Опросить только ID, найденные в FILE.
        RU: Файл может содержать ЛЮБОЙ текст; извлекаются шаблоны "!xxxxxxxx".
        RU: Фильтр применяется поверх --hours.
        RU: Пример:
          --id-list nodes.txt

  --quiet
        Less terminal output (do not print the initial numbered node list).
        RU: Меньше вывода (не печатать стартовый список узлов).

  --version
        Print program version and exit
        RU: Показать версию и выйти
"""


# ----------------------------
# Banner
# RU: Баннер
# ----------------------------

def print_banner(
    *,
    port: str,
    hours: int,
    timeout_s: int,
    pause_s: int,
    mode: str,
    filter_str: str,
    quiet: bool,
    self_id: str,
    self_long: str,
    self_short: str,
    total_nodes: int,
    active_nodes: int,
    db_file: str,
    defaults: dict,
) -> None:
    out(line_bar("CURRENT CONFIGURATION / ТЕКУЩИЕ НАСТРОЙКИ"))
    out(f"Script version:        {VERSION}")
    out(f"Device port:           {port} (default: {defaults['port']})")
    out(f"Activity window:       {hours} (default: {defaults['hours']})")
    out(f"Traceroute timeout:    {timeout_s} (default: {defaults['timeout']})")
    out(f"Pause after response:  {pause_s} (default: {defaults['pause']})")
    out(f"DB file:               {db_file} (default: {defaults['db']})")
    out(f"Mode:                  {mode}")
    out(f"Filter:                {filter_str}")
    out(f"Quiet mode:            {'Yes' if quiet else 'No'}")
    out("")
    out(f"Self node:             {self_id} {self_long}[{self_short}]")
    out(f"Total nodes in mesh:   {total_nodes}")
    out(f"Active nodes to poll:  {active_nodes}")
    out(f"Traceroutes stored in: {db_file}")


# ----------------------------
# Main loop
# RU: Основной код
# ----------------------------

def main() -> int:
    global STOP
    signal.signal(signal.SIGINT, _sigint_handler)

    DEFAULTS = {
        "port": "/dev/ttyUSB0",
        "hours": 24,
        "timeout": 30,
        "pause": 30,
        "db": "meshLogger.db",
    }

    ap = argparse.ArgumentParser(
        prog="meshLogger.py",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    ap.add_argument("-h", "--help", action="store_true", help="show this help message and exit. RU: показать помощь и выйти.")
    ap.add_argument("--port", default=DEFAULTS["port"], help=f"serial port (default: {DEFAULTS['port']}, Windows: COM3). RU: серийный порт (по умолчанию: {DEFAULTS['port']}, Windows: COM3).")
    ap.add_argument("--hours", type=int, default=DEFAULTS["hours"], help=f"active window by lastHeard hours (default: {DEFAULTS['hours']}). RU: окно активности по lastHeard (по умолчанию: {DEFAULTS['hours']}).")
    ap.add_argument("--timeout", type=int, default=DEFAULTS["timeout"], help=f"timeout for traceroute (default: {DEFAULTS['timeout']}). RU: таймаут traceroute (по умолчанию: {DEFAULTS['timeout']}).")
    ap.add_argument("--pause", type=int, default=DEFAULTS["pause"], help=f"pause between requests (default: {DEFAULTS['pause']}). RU: пауза между запросами (по умолчанию: {DEFAULTS['pause']}).")
    ap.add_argument("--db", default=DEFAULTS["db"], help=f"SQLite DB file (default: {DEFAULTS['db']}). RU: SQLite-файл базы (по умолчанию: {DEFAULTS['db']}).")
    ap.add_argument("--db-schema", action="store_true", help="print DB schema and exit. RU: вывести схему БД и выйти.")

    ap.add_argument("--minhops", type=int, default=None, help="min hopsAway filter (default: not set). RU: минимум hopsAway (по умолчанию: не задан).")
    ap.add_argument("--maxhops", type=int, default=None, help="max hopsAway filter (default: not set). RU: максимум hopsAway (по умолчанию: не задан).")

    ap.add_argument("--once", action="store_true", help="one pass then exit (default: continuous loop). RU: один проход и выход (по умолчанию: бесконечный цикл).")
    ap.add_argument("--node", default=None, help="poll only one node (accepts !xxxxxxxx or xxxxxxxx). RU: опрашивать только один узел (!xxxxxxxx или xxxxxxxx).")
    ap.add_argument("--id-list", dest="id_list", default=None, help="file to extract !xxxxxxxx ids from (any text allowed). RU: файл для извлечения !xxxxxxxx (любой текст).")

    ap.add_argument("--quiet", action="store_true", help="less terminal output. RU: меньше вывода в терминал.")
    ap.add_argument("--version", action="store_true", help="print version and exit. RU: вывести версию и выйти.")

    args = ap.parse_args()

    if args.help:
        out(HELP_TEXT.rstrip("\n"))
        return 0
    if args.db_schema:
        init_db(args.db)
        conn = sqlite3.connect(args.db)
        try:
            cur = conn.cursor()
            cur.execute("SELECT sql FROM sqlite_master WHERE type IN ('table','index') AND sql IS NOT NULL ORDER BY type, name")
            out("DB schema:")
            out("RU: Схема БД:")
            for (sql,) in cur.fetchall():
                out(sql + ";")
        finally:
            conn.close()
        return 0

    migrated = migrate_nodeDb_txt_once(args.db, "nodeDb.txt")
    if migrated:
        out(f"{ts_now()} migration: nodeDb.txt -> {args.db} done. RU: миграция nodeDb.txt -> {args.db} выполнена.")

    start_listen_thread(args.port, args.timeout, args.db)

    if args.version:
        out(f"meshLogger.py v{VERSION}")
        return 0

    if args.minhops is not None and args.minhops < 0:
        out(f"{ts_now()} ERROR: --minhops must be >= 0")
        return 2
    if args.maxhops is not None and args.maxhops < 0:
        out(f"{ts_now()} ERROR: --maxhops must be >= 0")
        return 2
    if args.minhops is not None and args.maxhops is not None and args.minhops > args.maxhops:
        out(f"{ts_now()} ERROR: --minhops cannot be greater than --maxhops")
        return 2

    loop_forever = not args.once

    want_ids: Optional[set] = None
    filter_parts = [f"All nodes active within {args.hours} hours"]

    if args.node:
        nid = normalize_node_id(args.node)
        if not nid:
            out(f"{ts_now()} ERROR: invalid --node (use !xxxxxxxx or xxxxxxxx)")
            return 2
        want_ids = {nid}
        filter_parts = [f"Only node {nid}"]

    if args.id_list:
        try:
            ids = read_id_list(args.id_list)
        except Exception as ex:
            out(f"{ts_now()} ERROR: cannot read --id-list: {ex}")
            return 2
        if not ids:
            out(f"{ts_now()} ERROR: --id-list contains no !xxxxxxxx patterns")
            return 2
        want_ids = ids if want_ids is None else (want_ids & ids)
        filter_parts.append(f"IDs extracted from {args.id_list} ({len(want_ids)} ids)")

    if args.minhops is not None:
        filter_parts.append(f"minhops={args.minhops}")
    if args.maxhops is not None:
        filter_parts.append(f"maxhops={args.maxhops}")

    filter_str = ", ".join(filter_parts)

    out(f"meshLogger.py v{VERSION}")

    cycle = 0
    total_sent = 0
    total_ok = 0

    last_info_refresh = 0.0
    last_db_refresh = 0.0
    nodes: Dict[str, dict] = {}
    db_snapshot: Dict[str, Dict[str, object]] = {}
    self_id = ""
    self_long = ""
    self_short = ""
    banner_printed = False

    def pct_str() -> str:
        if total_sent <= 0:
            return "0%"
        pct = int(round((total_ok * 100.0) / total_sent))
        return f"{pct}%"

    def refresh_info(force: bool = False) -> List[NodeRec]:
        nonlocal last_info_refresh, last_db_refresh, nodes, self_id, self_long, self_short, banner_printed, db_snapshot

        now = time.time()
        if STOP:
            raise KeyboardInterrupt

        if (not force) and (now - last_info_refresh) < 3600 and nodes and self_id:
            active0 = load_active_nodes(nodes, args.hours, self_id)
            active0 = filter_ids(active0, want_ids)
            active0 = filter_hops(active0, args.minhops, args.maxhops)
            return active0

        if force or (now - last_db_refresh) >= 3600:
            try:
                out(line_bar("DB UPDATE / ОБНОВЛЕНИЕ БД"))
                out(f"{ts_now()} DB: sending --nodes/--info request... RU: БД: отправляю запрос --nodes/--info...")
                updated, prev_snap, cur_snap = update_db_from_nodes(args.port, args.timeout, args.db)
                out(f"{ts_now()} DB: response received. RU: БД: ответ получен.")
                out(f"{ts_now()} DB: comparing with current state... RU: БД: сопоставляю с текущим состоянием...")
                _print_db_report(prev_snap, cur_snap)
                if cur_snap:
                    _print_db_nodes_only(cur_snap)
                out(f"{ts_now()} DB: updated {updated} nodes. RU: БД: обновлено {updated} узлов.")
                last_db_refresh = now
                db_snapshot = cur_snap
            except Exception as ex:
                out(f"{ts_now()} ERROR: db update failed: {ex}")
        if not db_snapshot:
            db_snapshot = _load_nodes_snapshot_from_db(args.db)

        mesh_info_text = ""
        parse_error: Optional[Exception] = None
        attempt_log: List[str] = []
        for extra_args in (["--format", "json"], ["--json"], []):
            cmd = ["meshtastic", "--port", args.port, "--info"] + extra_args
            rc, so, se = run_cmd(
                cmd,
                timeout=max(60, args.timeout + 15),
            )
            mesh_info_text = clean_ansi((so or "") + ("\n" + se if se else ""))
            if detect_device_not_found(mesh_info_text):
                raise RuntimeError(
                    f"device not found on port {args.port} (meshtastic). Check cable/port/drivers (Windows: COM3). "
                    f"RU: устройство не найдено на порту {args.port}. Проверьте кабель/порт/драйверы (Windows: COM3)."
                )
            if detect_device_busy(mesh_info_text):
                raise RuntimeError(
                    f"device busy on port {args.port} (in use). Close other apps and try again. "
                    f"RU: порт {args.port} занят (используется). Закройте другие приложения."
                )
            try:
                nodes = parse_nodes_block(mesh_info_text)
                parse_error = None
                break
            except Exception as ex:
                parse_error = ex
                nodes = {}
                preview = "\n".join(mesh_info_text.splitlines()[:8])
                stderr_preview = "\n".join((se or "").splitlines()[:6])
                attempt_log.append(
                    "cmd=" + " ".join(cmd)
                    + f" rc={rc} stderr={stderr_preview!r} preview={preview!r}"
                )
                continue

        if parse_error is not None:
            details = " | ".join(attempt_log) if attempt_log else "no output captured"
            raise RuntimeError(f"{parse_error} (parse attempts: {details})")

        self_id = detect_self_id(mesh_info_text, nodes)
        self_long, self_short = node_names(nodes, self_id)

        active = load_active_nodes(nodes, args.hours, self_id)
        active = filter_ids(active, want_ids)
        active = filter_hops(active, args.minhops, args.maxhops)

        # THESE TWO LINES MUST STAY
        # RU: ЭТИ ДВЕ СТРОКИ ДОЛЖНЫ ОСТАТЬСЯ
        out(f"{ts_now()} meshtastic --info updated from {self_id} {self_long}[{self_short}]")
        out(
            f"{ts_now()} a total of {len(nodes)} nodes were found, of which {len(active)} were active within the last {args.hours} hours. "
            f"Oh, they're going to get it now!"
        )

        _print_nodes_from_info(nodes, db_snapshot)

        if not banner_printed:
            mode = "Continuous loop" if loop_forever else "One pass"
            print_banner(
                port=args.port,
                hours=args.hours,
                timeout_s=args.timeout,
                pause_s=args.pause,
                mode=mode,
                filter_str=filter_str,
                quiet=args.quiet,
                self_id=self_id,
                self_long=self_long,
                self_short=self_short,
                total_nodes=len(nodes),
                active_nodes=len(active),
                db_file=args.db,
                defaults=DEFAULTS,
            )
            banner_printed = True

        last_info_refresh = now

        if not args.quiet:
            out(line_bar("[NODE SELECTION] / [ОТБОР УЗЛОВ]"))
            for i, n in enumerate(active, 1):
                hops = "?" if n.hops_away is None else str(n.hops_away)
                # N.\t!id\t<HO>h\tLong[Short]
                # RU: N.\t!id\t<HO>h\tДлинное[Короткое]
                out(f"{i}.\t{n.node_id}\t{hops}h\t{n.long}[{n.short}]")

        return active

    try:
        active = refresh_info(force=True)
    except KeyboardInterrupt:
        out("Interrupted by user (Ctrl+C). Exiting cleanly...")
        return 0
    except Exception as ex:
        out(f"{ts_now()} ERROR: {ex}")
        return 2

    while True:
        if STOP:
            out("Interrupted by user (Ctrl+C). Exiting cleanly...")
            return 0

        try:
            active = refresh_info(force=False)
        except KeyboardInterrupt:
            out("Interrupted by user (Ctrl+C). Exiting cleanly...")
            return 0
        except Exception as ex:
            out(f"{ts_now()} ERROR: {ex}")
            for _ in range(20):
                if STOP:
                    out("Interrupted by user (Ctrl+C). Exiting cleanly...")
                    return 0
                time.sleep(0.1)
            continue

        if len(active) == 0:
            out(f"{ts_now()} No nodes to poll (check --hours/filters or hopsAway availability)")
            if not loop_forever:
                return 0
            for _ in range(600):
                if STOP:
                    out("Interrupted by user (Ctrl+C). Exiting cleanly...")
                    return 0
                time.sleep(0.1)
            continue

        cycle += 1
        total_nodes = len(active)

        if not args.quiet:
            out(line_bar("TRACEROUTE / ТРАССИРОВКА"))

        for idx, n in enumerate(active, 1):
            if STOP:
                out("Interrupted by user (Ctrl+C). Exiting cleanly...")
                return 0

            total_sent += 1
            pct_req = pct_str()
            cyc = f"[{cycle}][{idx}/{total_nodes}]"

            req_ts_epoch = time.time()
            req_ts_str = ts_now()

            out(fmt_line(req_ts_str, pct_req, cyc, "-", f"request traceroute to {n.node_id} {n.long}[{n.short}]"))

            try:
                rc, so, se = run_cmd(
                    ["meshtastic", "--port", args.port, "--traceroute", n.node_id],
                    timeout=args.timeout,
                )
            except KeyboardInterrupt:
                out("Interrupted by user (Ctrl+C). Exiting cleanly...")
                return 0

            raw = clean_ansi((so or "") + ("\n" + se if se else ""))
            if detect_device_not_found(raw):
                out(
                    f"{ts_now()} ERROR: device not found on port {args.port} (meshtastic). "
                    f"Windows: COM3. RU: устройство не найдено на порту {args.port} (Windows: COM3)."
                )
                return 2
            towards, back = parse_routes_from_meshtastic_output(raw)

            if not towards:
                out(fmt_line(ts_now(), pct_req, cyc, "-", f"{n.long}[{n.short}] is no response..."))
                for _ in range(int(max(0, args.pause) * 10)):
                    if STOP:
                        out("Interrupted by user (Ctrl+C). Exiting cleanly...")
                        return 0
                    time.sleep(0.1)
                continue

            ans_ts_epoch = time.time()
            ans_ts_str = ts_now()

            edges_out = count_edges(towards)
            edges_back = count_edges(back) if back else 0
            denom = max(1, edges_out + edges_back)
            avg_hop_s = int(round((ans_ts_epoch - req_ts_epoch) / float(denom)))
            hop_field = f"{avg_hop_s}s/h"

            total_ok += 1
            pct_ans = pct_str()

            pretty_out = route_ids_to_names(towards, nodes)
            out(fmt_line(ans_ts_str, pct_ans, cyc, hop_field, f"> {pretty_out}"))

            if back:
                pretty_back = route_ids_to_names(back, nodes)
                out(fmt_line(ans_ts_str, pct_ans, cyc, hop_field, f"< {pretty_back}"))

            insert_traceroute(args.db, req_ts_str, self_id, n.node_id, "out", towards, pretty_out)
            if back:
                insert_traceroute(args.db, ans_ts_str, self_id, n.node_id, "back", back, pretty_back)

            for _ in range(int(max(0, args.pause) * 10)):
                if STOP:
                    out("Interrupted by user (Ctrl+C). Exiting cleanly...")
                    return 0
                time.sleep(0.1)

        if not loop_forever:
            return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        out("Interrupted by user (Ctrl+C). Exiting cleanly...")
        sys.exit(0)
