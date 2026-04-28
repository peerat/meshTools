#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

import argparse
import datetime as _dt
import json
import importlib.util
import locale
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import traceback
import unicodedata
import threading
import ast
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from sqlite_utils import connect_sqlite, ensure_traceroutes_ts_epoch, parse_local_naive_ts_to_epoch

VERSION = "1.9.0"

# ----------------------------
# Global stop + current child process (fast Ctrl+C shutdown)
# RU: Глобальная остановка + текущий дочерний процесс (для мгновенного Ctrl+C)
# ----------------------------

STOP = False
CURRENT_PROC: Optional[subprocess.Popen] = None
LISTEN_PROC: Optional[subprocess.Popen] = None
LISTEN_SUSPENDED = False
TUNE_MODE = False
ACTIVE_PORT_HINT: Optional[str] = None
_CONSOLE_ANSI_ENABLED: Optional[bool] = None
_WINDOWS_CTRL_HANDLER = None
_TUNE_DB_RE = re.compile(r"\((-?\d+(?:\.\d+)?|\?)dB\)")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_ROUTE_STEP_RE = re.compile(r"^\s*((?:!?[0-9a-fA-F]{8}|0x[0-9a-fA-F]{8}|Unknown))\s*(?:\(([-+]?\d+(?:\.\d+)?|\?)dB\))?\s*$")


def _sigint_handler(_signum, _frame):
    global STOP, CURRENT_PROC
    STOP = True
    if CURRENT_PROC is not None:
        _terminate_process(CURRENT_PROC)
    if LISTEN_PROC is not None:
        _terminate_process(LISTEN_PROC)


def _install_console_handlers() -> None:
    global _WINDOWS_CTRL_HANDLER
    if os.name != "nt" or _WINDOWS_CTRL_HANDLER is not None:
        return

    try:
        import ctypes

        CTRL_C_EVENT = 0
        CTRL_BREAK_EVENT = 1
        CTRL_CLOSE_EVENT = 2
        CTRL_LOGOFF_EVENT = 5
        CTRL_SHUTDOWN_EVENT = 6
        handled_events = {
            CTRL_C_EVENT,
            CTRL_BREAK_EVENT,
            CTRL_CLOSE_EVENT,
            CTRL_LOGOFF_EVENT,
            CTRL_SHUTDOWN_EVENT,
        }

        @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)
        def _ctrl_handler(ctrl_type):  # type: ignore[misc]
            if int(ctrl_type) in handled_events:
                _sigint_handler(None, None)
                return True
            return False

        if ctypes.windll.kernel32.SetConsoleCtrlHandler(_ctrl_handler, True):
            _WINDOWS_CTRL_HANDLER = _ctrl_handler
    except Exception:
        _WINDOWS_CTRL_HANDLER = None


# ----------------------------
# Utilities: time / output
# RU: Утилиты: время / вывод
# ----------------------------

def ts_now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def date_today() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d")


def out(msg: str, *, force: bool = False) -> None:
    if TUNE_MODE and not force:
        return
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def _console_ansi_enabled() -> bool:
    global _CONSOLE_ANSI_ENABLED
    if _CONSOLE_ANSI_ENABLED is not None:
        return _CONSOLE_ANSI_ENABLED

    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        _CONSOLE_ANSI_ENABLED = False
        return _CONSOLE_ANSI_ENABLED

    if os.name != "nt":
        _CONSOLE_ANSI_ENABLED = True
        return _CONSOLE_ANSI_ENABLED

    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        if handle in (0, -1):
            _CONSOLE_ANSI_ENABLED = False
            return _CONSOLE_ANSI_ENABLED

        mode = ctypes.c_uint()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            _CONSOLE_ANSI_ENABLED = False
            return _CONSOLE_ANSI_ENABLED

        enable_vt = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if mode.value & enable_vt:
            _CONSOLE_ANSI_ENABLED = True
            return _CONSOLE_ANSI_ENABLED

        _CONSOLE_ANSI_ENABLED = bool(kernel32.SetConsoleMode(handle, mode.value | enable_vt))
        return _CONSOLE_ANSI_ENABLED
    except Exception:
        _CONSOLE_ANSI_ENABLED = False
        return _CONSOLE_ANSI_ENABLED


def _clear_console_plain() -> bool:
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False

    if os.name != "nt":
        return False

    try:
        import ctypes

        class _COORD(ctypes.Structure):
            _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

        class _SMALL_RECT(ctypes.Structure):
            _fields_ = [("Left", ctypes.c_short), ("Top", ctypes.c_short), ("Right", ctypes.c_short), ("Bottom", ctypes.c_short)]

        class _CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
            _fields_ = [
                ("dwSize", _COORD),
                ("dwCursorPosition", _COORD),
                ("wAttributes", ctypes.c_ushort),
                ("srWindow", _SMALL_RECT),
                ("dwMaximumWindowSize", _COORD),
            ]

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        if handle in (0, -1):
            return False

        csbi = _CONSOLE_SCREEN_BUFFER_INFO()
        if kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(csbi)) == 0:
            return False

        cells = int(csbi.dwSize.X) * int(csbi.dwSize.Y)
        origin = _COORD(0, 0)
        written = ctypes.c_ulong()
        kernel32.FillConsoleOutputCharacterW(handle, ctypes.c_wchar(" "), cells, origin, ctypes.byref(written))
        kernel32.FillConsoleOutputAttribute(handle, csbi.wAttributes, cells, origin, ctypes.byref(written))
        kernel32.SetConsoleCursorPosition(handle, origin)
        return True
    except Exception:
        return False


def _decode_subprocess_output(data: object) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    if not isinstance(data, (bytes, bytearray)):
        return str(data)

    raw = bytes(data)
    tried: List[str] = []
    for enc in ("utf-8", locale.getpreferredencoding(False), "cp1251", "cp866"):
        if not enc:
            continue
        enc_norm = enc.lower()
        if enc_norm in tried:
            continue
        tried.append(enc_norm)
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


def _sanitize(value: object) -> object:
    if isinstance(value, dict):
        out: Dict[object, object] = {}
        for key, item in value.items():
            if key == "raw":
                continue
            out[key] = _sanitize(item)
        return out
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize(item) for item in value]
    if isinstance(value, bytes):
        return {"encoding": "hex", "data": value.hex()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def clean_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


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
    if "could not open port" in s:
        return True
    if "could not exclusively lock port" in s:
        return True
    if "might be in use by another process" in s:
        return True
    if "permissionerror(13" in s:
        return True
    if "access is denied" in s:
        return True
    if "отказано в доступе" in s:
        return True
    return False


def detect_multiple_ports(text: str) -> bool:
    s = (text or "").lower()
    if not s:
        return False
    if "multiple serial ports were detected" in s:
        return True
    if "one serial port must be specified with the '--port'" in s:
        return True
    return False


def _port_sort_key(port_name: str) -> Tuple[int, int, str]:
    text = str(port_name or "").strip()
    m = re.fullmatch(r"COM(\d+)", text, flags=re.IGNORECASE)
    if m:
        return (0, int(m.group(1)), text.upper())
    return (1, 0, text.lower())


def _list_serial_ports() -> List[str]:
    try:
        from serial.tools import list_ports
    except Exception:
        return []

    ports: List[str] = []
    seen = set()
    try:
        comports = list_ports.comports()
    except Exception:
        return []

    for item in comports:
        device = str(getattr(item, "device", "") or "").strip()
        if not device:
            continue
        key = device.lower()
        if key in seen:
            continue
        seen.add(key)
        ports.append(device)

    if os.name == "nt":
        ports.sort(key=_port_sort_key)
    else:
        ports.sort()
    return ports


def _remember_working_port(port: Optional[str]) -> None:
    global ACTIVE_PORT_HINT
    value = str(port or "").strip()
    if value:
        ACTIVE_PORT_HINT = value


def _candidate_ports(port: Optional[str]) -> List[Optional[str]]:
    explicit = str(port or "").strip()
    if explicit:
        return [explicit]

    hint = str(ACTIVE_PORT_HINT or "").strip()
    ordered: List[Optional[str]] = [hint] if hint else [None]
    seen = {str(item).lower() for item in ordered if item}

    for device in _list_serial_ports():
        key = device.lower()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(device)

    return ordered


def _port_cli_args(port: Optional[str]) -> List[str]:
    value = str(port or ACTIVE_PORT_HINT or "").strip()
    if not value:
        return []
    return ["--port", value]


def _port_display(port: Optional[str]) -> str:
    value = str(port or "").strip()
    return value if value else "auto"


def _device_lookup_error(port: Optional[str]) -> str:
    value = str(port or "").strip()
    if value:
        return (
            f"device not found on port {value} (meshtastic). Check cable/port/drivers (Windows: COM3). "
            f"RU: устройство не найдено на порту {value}. Проверьте кабель/порт/драйверы (Windows: COM3)."
        )
    return (
        "device not found using automatic port detection (meshtastic). "
        "Try --port COM3 on Windows or --port /dev/ttyUSB0 on Linux. "
        "RU: устройство не найдено при автоматическом поиске порта. "
        "Попробуйте --port COM3 в Windows или --port /dev/ttyUSB0 в Linux."
    )


def _device_busy_error(port: Optional[str]) -> str:
    value = str(port or "").strip()
    if value:
        return (
            f"device busy on port {value} (in use). Close other apps and try again. "
            f"RU: порт {value} занят (используется). Закройте другие приложения."
        )
    return (
        "auto-detected device is busy (in use). Close other apps and try again, or pass --port explicitly. "
        "RU: автоматически найденное устройство занято. Закройте другие приложения или укажите --port явно."
    )


def _multiple_ports_error() -> str:
    return (
        "multiple serial ports were detected by Meshtastic. Pass --port explicitly, for example --port COM3. "
        "RU: найдено несколько serial-портов Meshtastic. Укажите --port явно, например --port COM3."
    )


def _meshtastic_cli_missing_error() -> str:
    return (
        "meshtastic CLI was not found in PATH. Install Meshtastic CLI or add it to PATH. "
        "RU: meshtastic CLI не найден в PATH. Установите Meshtastic CLI или добавьте его в PATH."
    )


def _meshtastic_module_missing_error() -> str:
    return (
        "meshtastic Python module/CLI runner is not available. Install Meshtastic for the Python launcher or add meshtastic CLI to PATH. "
        "RU: модуль/CLI Meshtastic недоступен. Установите Meshtastic для Python launcher или добавьте meshtastic CLI в PATH."
    )


def _meshtastic_cmd_bases() -> List[List[str]]:
    bases: List[List[str]] = []
    seen: set[Tuple[str, ...]] = set()
    frozen_windows = os.name == "nt" and getattr(sys, "frozen", False)

    def _add(base: List[str]) -> None:
        key = tuple(base)
        if key in seen:
            return
        seen.add(key)
        bases.append(base)

    env_python = os.environ.get("MESHTASTIC_PYTHON")
    if env_python and os.path.isfile(env_python):
        _add([env_python, "-m", "meshtastic"])

    if not getattr(sys, "frozen", False):
        try:
            if importlib.util.find_spec("meshtastic") is not None:
                _add([sys.executable, "-m", "meshtastic"])
        except Exception:
            pass

    if os.name == "nt" and not frozen_windows:
        py_launcher = shutil.which("py")
        if py_launcher:
            _add([py_launcher, "-3", "-m", "meshtastic"])

    _add(["meshtastic"])
    return bases


def _meshtastic_text_suggests_missing_module(text: str) -> bool:
    s = (text or "").lower()
    if not s:
        return False
    hints = [
        "no module named meshtastic",
        "meshtastic.__main__",
        "can't find module",
        "could not import",
    ]
    return any(hint in s for hint in hints)


def _run_meshtastic_cli(args: List[str], *, timeout: int) -> Tuple[int, str, str]:
    last_runtime_error: Optional[RuntimeError] = None
    last_result: Optional[Tuple[int, str, str]] = None

    for base in _meshtastic_cmd_bases():
        cmd = base + list(args)
        try:
            rc, so, se = run_cmd(cmd, timeout=timeout)
        except RuntimeError as ex:
            msg = str(ex)
            if (
                "meshtastic cli was not found in path" in msg.lower()
                or "meshtastic python module/cli runner is not available" in msg.lower()
            ):
                last_runtime_error = ex
                continue
            raise

        combined = clean_ansi((so or "") + ("\n" + se if se else ""))
        if rc != 0 and _meshtastic_text_suggests_missing_module(combined):
            last_result = (rc, so, se)
            continue
        return rc, so, se

    if last_runtime_error is not None:
        raise last_runtime_error
    if last_result is not None:
        return last_result
    raise RuntimeError(_meshtastic_module_missing_error())


def _is_retryable_connection_error(text: object) -> bool:
    s = str(text or "").lower()
    if not s:
        return False
    hints = [
        "device not found",
        "automatic port detection",
        "auto-detected device is busy",
        "device busy on port",
        "multiple serial ports were detected",
        "one serial port must be specified",
        "meshtastic cli was not found in path",
        "cannot load nodes from meshtastic",
        "cannot detect self node",
        "cannot parse nodes",
    ]
    return any(hint in s for hint in hints)


def _wait_retry_delay(seconds: float = 5.0) -> bool:
    ticks = max(1, int(seconds * 10))
    for _ in range(ticks):
        if STOP:
            return False
        time.sleep(0.1)
    return True


def _retry_status_message(error_text: object, port: Optional[str]) -> str:
    s = str(error_text or "").lower()
    port_label = _port_display(port)
    if "meshtastic cli was not found in path" in s:
        return "Waiting: meshtastic CLI is not available"
    if "multiple serial ports" in s or "one serial port must be specified" in s:
        return "Waiting: multiple serial ports detected, pass --port"
    if "busy" in s:
        return f"Waiting for device on {port_label}: port busy"
    if "cannot load nodes from meshtastic" in s or "cannot parse nodes" in s:
        return "Waiting: Meshtastic node list is not ready"
    if "cannot detect self node" in s:
        return "Waiting: local node info is not ready"
    return f"Waiting for device on {port_label}..."


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
    s = clean_ansi(s)
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


def _trim_display(s: str, width: int) -> str:
    if width <= 0:
        return ""

    out_chars: List[str] = []
    used = 0
    idx = 0
    limit_hit = False
    while idx < len(s):
        if s[idx] == "\x1b":
            match = _ANSI_RE.match(s, idx)
            if match:
                out_chars.append(match.group(0))
                idx = match.end()
                continue
        ch = s[idx]
        ch_width = _display_width(ch)
        if used + ch_width > width:
            limit_hit = True
            break
        out_chars.append(ch)
        used += ch_width
        idx += 1
    trimmed = "".join(out_chars)
    if limit_hit and "\x1b[" in trimmed and not trimmed.endswith("\x1b[0m"):
        trimmed += "\x1b[0m"
    return trimmed


def _fit_lines_to_terminal(lines: List[str], *, columns: int, rows: int) -> List[str]:
    if columns <= 0:
        columns = 80
    if rows <= 0:
        rows = len(lines) or 1

    trimmed = [_trim_display(line, columns) for line in lines]
    if len(trimmed) <= rows:
        return trimmed

    omitted = len(trimmed) - rows + 1
    summary = _trim_display(f"... omitted {omitted} line(s)", columns)
    if rows == 1:
        return [summary]
    return trimmed[: rows - 1] + [summary]


def _fit_tune_screen_sections(
    header_lines: List[str],
    table_lines: List[str],
    footer_lines: List[str],
    *,
    columns: int,
    rows: int,
) -> List[str]:
    if columns <= 0:
        columns = 80
    if rows <= 0:
        rows = len(header_lines) + len(table_lines) + len(footer_lines) or 1

    header = [_trim_display(line, columns) for line in header_lines]
    table = [_trim_display(line, columns) for line in table_lines]
    footer = [_trim_display(line, columns) for line in footer_lines]
    total = len(header) + len(table) + len(footer)
    if total <= rows:
        return header + table + footer

    fixed = len(header) + len(footer)
    if fixed + 1 <= rows:
        table_room = rows - fixed
        if len(table) <= table_room:
            return header + table + footer
        if table_room <= 1:
            summary = _trim_display(f"... omitted {len(table)} table line(s)", columns)
            return header + [summary] + footer
        kept = table[: table_room - 1]
        omitted = len(table) - len(kept)
        summary = _trim_display(f"... omitted {omitted} table line(s)", columns)
        return header + kept + [summary] + footer

    # Terminal is too short for the full footer. Keep the header, the tail of the
    # footer, and use the middle section for a compact summary plus table preview.
    available_after_header = max(1, rows - len(header))
    footer_keep = max(0, available_after_header - 1)
    footer_tail = footer[-footer_keep:] if footer_keep else []
    middle_room = max(1, rows - len(header) - len(footer_tail))
    if middle_room == 1:
        summary = _trim_display(
            f"... omitted {len(table)} table line(s) and {len(footer) - len(footer_tail)} hint line(s)",
            columns,
        )
        return header + [summary] + footer_tail

    preview = table[: middle_room - 1]
    omitted_table = max(0, len(table) - len(preview))
    omitted_footer = max(0, len(footer) - len(footer_tail))
    summary = _trim_display(
        f"... omitted {omitted_table} table line(s) and {omitted_footer} hint line(s)",
        columns,
    )
    return header + preview + [summary] + footer_tail


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


def _normalize_route_node_id(s: str) -> Optional[str]:
    text = (s or "").strip()
    if not text or text == "Unknown":
        return None
    if re.fullmatch(r"0x[0-9a-fA-F]{8}", text):
        return "!" + text[2:].lower()
    return normalize_node_id(text)


# ----------------------------
def _first_not_none(*values: object) -> object:
    for value in values:
        if value is not None:
            return value
    return None


def _merge_text_value(new_value: object, existing_value: object) -> str:
    if isinstance(new_value, str):
        stripped = new_value.strip()
        if stripped:
            return stripped
    if isinstance(existing_value, str):
        stripped_existing = existing_value.strip()
        if stripped_existing:
            return stripped_existing
    return ""


# SQLite storage
# RU: SQLite-хранилище
# ----------------------------

def init_db(db_path: str) -> None:
    conn = connect_sqlite(db_path)
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
                channel_util REAL,
                tx_air_util REAL,
                hops INTEGER,
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
                ts_epoch INTEGER,
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
            CREATE TABLE IF NOT EXISTS packet_rx_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc TEXT,
                ts_epoch INTEGER,
                node_id TEXT,
                from_id TEXT,
                to_id TEXT,
                portnum TEXT,
                rx_snr REAL,
                rx_rssi REAL,
                noise_floor REAL,
                hop_limit INTEGER,
                hop_start INTEGER,
                rx_time INTEGER,
                raw_json TEXT
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
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_info_samples_ts
            ON info_samples (ts_utc)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_listen_events_ts
            ON listen_events (ts_utc)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_listen_events_node_ts
            ON listen_events (node_id, ts_utc)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_node_changes_node_ts
            ON node_changes (node_id, ts_utc)
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
                "channel_util": "REAL",
                "tx_air_util": "REAL",
                "hops": "INTEGER",
                "first_seen_utc": "TEXT",
                "last_seen_utc": "TEXT",
                "last_heard_utc": "TEXT",
                "updated_utc": "TEXT",
            },
        )
        _ensure_columns(
            "traceroutes",
            {
                "ts_epoch": "INTEGER",
            },
        )
        ensure_traceroutes_ts_epoch(conn)
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_traceroutes_ts_epoch
            ON traceroutes (ts_epoch)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_traceroutes_self_ts_epoch
            ON traceroutes (self_id, ts_epoch)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_traceroutes_target_ts_epoch
            ON traceroutes (target_id, ts_epoch)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_packet_rx_samples_ts_epoch
            ON packet_rx_samples (ts_epoch)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_packet_rx_samples_node_ts_epoch
            ON packet_rx_samples (node_id, ts_epoch)
            """
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
    node_id = _first_not_none(user.get("id"), node.get("id"))
    if not isinstance(node_id, str) or not node_id.startswith("!"):
        return

    long_name = _first_not_none(user.get("longName"), user.get("long_name"))
    short_name = _first_not_none(user.get("shortName"), user.get("short_name"))
    role = _first_not_none(user.get("role"), node.get("role"))
    hardware = _first_not_none(user.get("hwModel"), user.get("hw_model"), node.get("hardware"))
    snr = node.get("snr")
    hops = node.get("hopsAway") if node.get("hopsAway") is not None else node.get("hops_away")
    last_heard = _first_not_none(node.get("lastHeard"), node.get("last_heard"))
    last_heard_utc = epoch_to_iso_utc(last_heard) if isinstance(last_heard, (int, float)) else None

    channel_util = None
    tx_air_util = None
    dev_metrics = node.get("deviceMetrics") if isinstance(node.get("deviceMetrics"), dict) else None
    if dev_metrics:
        channel_util = dev_metrics.get("channelUtilization")
        tx_air_util = dev_metrics.get("airUtilTx")
    if channel_util is None:
        channel_util = _first_not_none(
            node.get("channelUtil"),
            node.get("channel_util"),
            node.get("channelUtilization"),
        )
    if tx_air_util is None:
        tx_air_util = _first_not_none(
            node.get("txAirUtil"),
            node.get("tx_air_util"),
            node.get("txAirUtilization"),
        )

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
    cur.execute(
        """
        SELECT
            first_seen_utc,
            long_name,
            short_name,
            role,
            hardware,
            channel_util,
            tx_air_util,
            hops,
            last_heard_utc
        FROM nodes
        WHERE id = ?
        """,
        (node_id,),
    )
    row = cur.fetchone()
    first_seen = row[0] if row else None
    existing_long_name = row[1] if row else None
    existing_short_name = row[2] if row else None
    existing_role = row[3] if row else None
    existing_hardware = row[4] if row else None
    existing_channel_util = row[5] if row else None
    existing_tx_air_util = row[6] if row else None
    existing_hops = row[7] if row else None
    existing_last_heard_utc = row[8] if row else None
    if not first_seen:
        first_seen = ts_utc

    long_name = _merge_text_value(long_name, existing_long_name)
    short_name = _merge_text_value(short_name, existing_short_name)
    role = _merge_text_value(role, existing_role)
    hardware = _merge_text_value(hardware, existing_hardware)
    channel_util = _first_not_none(channel_util, existing_channel_util)
    tx_air_util = _first_not_none(tx_air_util, existing_tx_air_util)
    hops = _first_not_none(hops, existing_hops)
    last_heard_utc = _first_not_none(last_heard_utc, existing_last_heard_utc)

    cur.execute(
        """
        INSERT INTO nodes (
            id, long_name, short_name, role, hardware,
            channel_util, tx_air_util, hops,
            first_seen_utc, last_seen_utc, last_heard_utc, updated_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            long_name=excluded.long_name,
            short_name=excluded.short_name,
            role=excluded.role,
            hardware=excluded.hardware,
            channel_util=excluded.channel_util,
            tx_air_util=excluded.tx_air_util,
            hops=excluded.hops,
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
            channel_util,
            tx_air_util,
            hops,
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
        SELECT
            id, long_name, short_name, role, hardware,
            channel_util, tx_air_util, hops,
            first_seen_utc, last_seen_utc, last_heard_utc
        FROM nodes
        """
    )
    snap: Dict[str, Dict[str, object]] = {}
    for row in cur.fetchall():
        (nid, ln, sn, role, hw, ch_util, tx_air_util, hops, fs, ls, lh) = row
        snap[nid] = {
            "long_name": ln,
            "short_name": sn,
            "role": role,
            "hardware": hw,
            "channel_util": ch_util,
            "tx_air_util": tx_air_util,
            "hops": hops,
            "first_seen_utc": fs,
            "last_seen_utc": ls,
            "last_heard_utc": lh,
        }
    return snap


def _load_nodes_snapshot_from_db(db_path: str) -> Dict[str, Dict[str, object]]:
    if not os.path.isfile(db_path):
        return {}
    try:
        conn = connect_sqlite(db_path)
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
    conn = connect_sqlite(db_path)
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
            text=False,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
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
    try:
        p.wait(timeout=1.5)
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
        time.sleep(0.5 if os.name == "nt" else 0.2)
        try:
            p = _popen_new_process_group(cmd)
        except FileNotFoundError as ex:
            missing_cmd = cmd[0] if cmd else "command"
            if str(missing_cmd).lower() == "meshtastic":
                raise RuntimeError(_meshtastic_cli_missing_error()) from ex
            raise
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
                try:
                    so, se = p.communicate(timeout=1.0)
                except Exception:
                    so, se = "", ""
                stdout_chunks.append(_decode_subprocess_output(so))
                stderr_chunks.append(_decode_subprocess_output(se))
                stderr_chunks.append("[TIMEOUT]")
                return 124, "".join(stdout_chunks), "".join(stderr_chunks)

            try:
                so, se = p.communicate(timeout=tick)
                stdout_chunks.append(_decode_subprocess_output(so))
                stderr_chunks.append(_decode_subprocess_output(se))
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


def extract_balanced_brackets(text: str, start_idx: int) -> Optional[str]:
    i = text.find("[", start_idx)
    if i < 0:
        return None
    depth = 0
    for j in range(i, len(text)):
        c = text[j]
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    return None


def _nodes_dict_to_list(nodes: Dict[str, object]) -> List[Dict[str, object]]:
    out_list: List[Dict[str, object]] = []
    for node_id, node_obj in nodes.items():
        if not (isinstance(node_id, str) and node_id.startswith("!")):
            continue
        if isinstance(node_obj, dict):
            normalized = dict(node_obj)
            user = normalized.get("user") if isinstance(normalized.get("user"), dict) else {}
            if not user.get("id"):
                user["id"] = node_id
            normalized["user"] = user
            if not normalized.get("id"):
                normalized["id"] = node_id
            out_list.append(normalized)
    return out_list


def _nodes_list_to_dict(nodes_list: List[Dict[str, object]]) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for node in nodes_list:
        if not isinstance(node, dict):
            continue
        user = node.get("user") if isinstance(node.get("user"), dict) else {}
        node_id_raw = _first_not_none(user.get("id"), node.get("id"))
        node_id = normalize_node_id(str(node_id_raw)) if isinstance(node_id_raw, str) else None
        if not node_id:
            continue
        normalized = dict(node)
        normalized_user = dict(user)
        normalized_user["id"] = node_id
        normalized["user"] = normalized_user
        normalized["id"] = node_id
        out[node_id] = normalized
    return out


def _normalize_nodes_payload(parsed: object) -> Optional[List[Dict[str, object]]]:
    if isinstance(parsed, list):
        out_list: List[Dict[str, object]] = []
        for row in parsed:
            if isinstance(row, dict):
                out_list.append(row)
        return out_list if out_list else None

    if not isinstance(parsed, dict):
        return None

    nodes_candidates = ("nodes", "Nodes", "nodesById")
    for key in nodes_candidates:
        value = parsed.get(key)
        if isinstance(value, list):
            out_list = [row for row in value if isinstance(row, dict)]
            return out_list if out_list else None
        if isinstance(value, dict):
            out_list = _nodes_dict_to_list(value)
            return out_list if out_list else None

    for key in ("mesh", "meshInfo", "info"):
        nested = parsed.get(key)
        if isinstance(nested, dict):
            out_list = _normalize_nodes_payload(nested)
            if out_list:
                return out_list

    # Last-resort shape: mapping "!xxxxxxxx" -> node dict
    if any(isinstance(k, str) and k.startswith("!") for k in parsed.keys()):
        out_list = _nodes_dict_to_list(parsed)
        return out_list if out_list else None

    return None


def _parse_nodes_json_text(out_text: str) -> Optional[List[Dict[str, object]]]:
    cleaned = "\n".join(
        [line for line in out_text.splitlines() if line.strip() and line.strip() != "Connected to radio"]
    ).strip()
    if not cleaned:
        return None

    parse_candidates: List[str] = [cleaned]
    bracket_block = extract_balanced_brackets(cleaned, 0)
    if bracket_block and bracket_block not in parse_candidates:
        parse_candidates.append(bracket_block)
    braces_block = extract_balanced_braces(cleaned, 0)
    if braces_block and braces_block not in parse_candidates:
        parse_candidates.append(braces_block)

    for candidate in parse_candidates:
        try:
            parsed = json.loads(candidate)
        except Exception:
            continue
        nodes_list = _normalize_nodes_payload(parsed)
        if nodes_list:
            return nodes_list
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


def fetch_nodes_json(port: Optional[str], timeout: int) -> Optional[List[Dict[str, object]]]:
    explicit = str(port or "").strip()
    last_port_error: Optional[str] = None

    for candidate_port in _candidate_ports(port):
        for extra_args in (["--format", "json"], ["--json"], []):
            cmd_args = _port_cli_args(candidate_port) + ["--nodes"] + extra_args
            rc, so, se = _run_meshtastic_cli(cmd_args, timeout=max(60, timeout + 15))
            out_text = clean_ansi((so or "") + ("\n" + se if se else ""))
            if detect_device_not_found(out_text):
                last_port_error = _device_lookup_error(candidate_port)
                if explicit:
                    raise RuntimeError(last_port_error)
                break
            if detect_multiple_ports(out_text):
                last_port_error = _multiple_ports_error()
                if explicit:
                    raise RuntimeError(last_port_error)
                break
            if detect_device_busy(out_text):
                last_port_error = _device_busy_error(candidate_port)
                if explicit:
                    raise RuntimeError(last_port_error)
                break
            if rc != 0:
                continue
            parsed_nodes = _parse_nodes_json_text(out_text)
            if parsed_nodes:
                _remember_working_port(candidate_port)
                return parsed_nodes

    if explicit and last_port_error:
        raise RuntimeError(last_port_error)
    return None


def fetch_info_raw(port: Optional[str], timeout: int) -> Optional[str]:
    explicit = str(port or "").strip()
    last_port_error: Optional[str] = None

    for candidate_port in _candidate_ports(port):
        for extra_args in (["--format", "json"], ["--json"], []):
            cmd_args = _port_cli_args(candidate_port) + ["--info"] + extra_args
            rc, so, se = _run_meshtastic_cli(cmd_args, timeout=max(60, timeout + 15))
            out_text = clean_ansi((so or "") + ("\n" + se if se else ""))
            if detect_device_not_found(out_text):
                last_port_error = _device_lookup_error(candidate_port)
                if explicit:
                    raise RuntimeError(last_port_error)
                break
            if detect_multiple_ports(out_text):
                last_port_error = _multiple_ports_error()
                if explicit:
                    raise RuntimeError(last_port_error)
                break
            if detect_device_busy(out_text):
                last_port_error = _device_busy_error(candidate_port)
                if explicit:
                    raise RuntimeError(last_port_error)
                break
            if rc == 0 and out_text.strip():
                _remember_working_port(candidate_port)
                return out_text

    if explicit and last_port_error:
        raise RuntimeError(last_port_error)
    return None


def update_db_from_nodes(port: Optional[str], timeout: int, db_path: str) -> Tuple[int, Dict[str, Dict[str, object]], Dict[str, Dict[str, object]]]:
    nodes_list = fetch_nodes_json(port, timeout)
    info_raw: Optional[str] = None
    if not nodes_list:
        info_raw = fetch_info_raw(port, timeout)
        if info_raw:
            try:
                nodes_dict = parse_nodes_block(info_raw)
                nodes_list = _nodes_dict_to_list(nodes_dict)
            except Exception:
                nodes_list = None
    if not nodes_list:
        init_db(db_path)
        conn = connect_sqlite(db_path)
        try:
            snap = _load_nodes_snapshot(conn)
        finally:
            conn.close()
        return 0, snap, snap
    init_db(db_path)
    ts_utc = iso_utc_now()
    conn = connect_sqlite(db_path)
    try:
        prev = _load_nodes_snapshot(conn)
        for node in nodes_list:
            if isinstance(node, dict):
                upsert_node(conn, node, ts_utc, sample_type="nodes")
        if info_raw is None:
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
    ts_epoch = parse_local_naive_ts_to_epoch(ts_utc)
    conn = connect_sqlite(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO traceroutes (ts_utc, ts_epoch, self_id, target_id, direction, route_raw, route_pretty, hops) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ts_utc, ts_epoch, self_id, target_id, direction, route_raw, route_pretty, hops),
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
    conn = connect_sqlite(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO listen_events (ts_utc, event_type, node_id, raw_json) VALUES (?, ?, ?, ?)",
            (ts_utc, event_type, node_id, json.dumps(data, ensure_ascii=False)),
        )
        conn.commit()
    finally:
        conn.close()


def _as_float(value: object) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return float(text)
        except Exception:
            return None
    return None


def _as_int(value: object) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(float(text))
        except Exception:
            return None
    return None


def _format_db_value(value: object, unit: str) -> str:
    numeric = _as_float(value)
    if numeric is None:
        return "-"
    text = f"{numeric:.2f}".rstrip("0").rstrip(".")
    return f"{text}{unit}"


def _format_metric_number(value: object) -> str:
    numeric = _as_float(value)
    if numeric is None:
        return "-"
    return f"{numeric:.2f}"


def _format_count_number(value: object) -> str:
    numeric = _as_int(value)
    if numeric is None:
        return "0"
    return str(numeric)


def _metric_ratio(value: float, low: float, high: float, *, invert: bool = False) -> float:
    if high == low:
        ratio = 0.5
    else:
        ratio = (value - low) / float(high - low)
    ratio = max(0.0, min(1.0, ratio))
    if invert:
        ratio = 1.0 - ratio
    return ratio


def _ratio_to_ansi_color(ratio: float) -> str:
    red, green, blue = _ratio_to_rgb_components(ratio)
    return f"\x1b[38;2;{red};{green};{blue}m"


def _ansi_fg_rgb(text: str, red: int, green: int, blue: int) -> str:
    return f"\x1b[38;2;{red};{green};{blue}m{text}\x1b[0m"


def _ansi_metric_footer_text(text: str, *, kind: str, metric_type: str, sample_value: float) -> str:
    if metric_type == "spread":
        ratio = _metric_ratio(sample_value, 0.0, 30.0 if kind == "snr" else 12.0, invert=True)
    else:
        if kind == "snr":
            ratio = _metric_ratio(sample_value, -20.0, 10.0)
        else:
            ratio = _metric_ratio(sample_value, -130.0, -90.0, invert=True)
    return f"{_ratio_to_ansi_color(ratio)}{text}\x1b[0m"


def _colorize_footer_scale_line(
    label: str,
    low_text: str,
    high_text: str,
    *,
    kind: str,
    metric_type: str,
    low_value: float,
    high_value: float,
    direction_text: str,
    note: str = "",
) -> str:
    label_text = _ansi_fg_rgb(label, 220, 220, 220)
    low_colored = _ansi_metric_footer_text(low_text, kind=kind, metric_type=metric_type, sample_value=low_value)
    high_colored = _ansi_metric_footer_text(high_text, kind=kind, metric_type=metric_type, sample_value=high_value)
    red_word = _ansi_fg_rgb("красного", 255, 80, 80)
    green_word = _ansi_fg_rgb("зеленому", 80, 255, 80)
    direction_colored = direction_text.replace("красного", red_word).replace("зеленому", green_word)
    note_colored = ""
    if note:
        note_text = note.strip()
        note_suffix = note_text[:-1] if note_text.endswith(".") else note_text
        note_colored = ", " + _ansi_fg_rgb(note_suffix, 150, 255, 150)
    return f"{label_text}: {low_colored}..{high_colored} {direction_colored}{note_colored}."


def _ratio_to_rgb_components(ratio: float) -> Tuple[int, int, int]:
    ratio = max(0.0, min(1.0, ratio))
    if ratio <= 0.5:
        red = 255
        green = int(round(510 * ratio))
    else:
        red = int(round(255 * (1.0 - ((ratio - 0.5) * 2.0))))
        green = 255
    return red, green, 0


def _colorize_tune_age_text(text: object, *, age_seconds: object, window_seconds: int = 3600) -> str:
    rendered = str(text if text is not None else "-")
    age = _as_float(age_seconds)
    if age is None or age < 0:
        return rendered
    fade_window_seconds = 3600.0
    if age >= fade_window_seconds:
        return f"\x1b[38;5;239m\x1b[2m{rendered}\x1b[0m"
    ratio = max(0.0, min(1.0, age / fade_window_seconds))
    gray = int(round(255 - (11.0 * ratio)))
    return f"\x1b[38;5;{gray}m{rendered}\x1b[0m"


def _format_metric_delta(value: object, previous: object) -> Optional[str]:
    numeric = _as_float(value)
    prev_numeric = _as_float(previous)
    if numeric is None or prev_numeric is None:
        return None

    delta = numeric - prev_numeric
    if abs(delta) < 0.005:
        delta = 0.0

    return f"{delta:+.2f}"


def _colorize_metric_value(value: object, *, kind: str) -> str:
    numeric = _as_float(value)
    if numeric is None:
        return "-"

    if kind == "snr":
        ratio = _metric_ratio(numeric, -20.0, 10.0)
    else:
        ratio = _metric_ratio(numeric, -130.0, -90.0, invert=True)

    text = _format_metric_number(numeric)
    return f"{_ratio_to_ansi_color(ratio)}{text}\x1b[0m"


def _metric_value_foreground(value: object, *, kind: str) -> Tuple[Optional[str], str]:
    numeric = _as_float(value)
    if numeric is None:
        return None, "-"

    if kind == "snr":
        ratio = _metric_ratio(numeric, -20.0, 10.0)
    else:
        ratio = _metric_ratio(numeric, -130.0, -90.0, invert=True)
    return _ratio_to_ansi_color(ratio), _format_metric_number(numeric)


def _metric_spread_foreground(value: object, *, kind: str) -> Tuple[Optional[str], str]:
    numeric = _as_float(value)
    if numeric is None:
        return None, "-"

    if kind == "snr":
        ratio = _metric_ratio(numeric, 0.0, 30.0, invert=True)
    else:
        ratio = _metric_ratio(numeric, 0.0, 12.0, invert=True)
    return _ratio_to_ansi_color(ratio), _format_metric_number(numeric)


def _metric_change_background(
    current: object,
    previous: object,
    *,
    kind: str,
    metric_type: str,
    emphasis: str = "strong",
) -> str:
    current_numeric = _as_float(current)
    previous_numeric = _as_float(previous)
    if current_numeric is None:
        return ""
    if previous_numeric is None:
        return ""

    delta = current_numeric - previous_numeric
    if abs(delta) < 0.005:
        return ""

    if metric_type == "spread":
        better = delta < 0
        scale = 8.0 if kind == "snr" else 12.0
    else:
        if kind == "snr":
            better = delta > 0
            scale = 6.0
        else:
            better = delta < 0
            scale = 10.0

    ratio = _metric_ratio(abs(delta), 0.0, scale)
    if better:
        red = int(round(16 * (1.0 - ratio)))
        green = int(round(40 + (160 * ratio)))
        blue = int(round(16 * (1.0 - ratio)))
    else:
        red = int(round(40 + (160 * ratio)))
        green = int(round(16 * (1.0 - ratio)))
        blue = int(round(16 * (1.0 - ratio)))

    if emphasis == "soft":
        base = 18
        softness = 0.40
        red = int(round(base + ((red - base) * softness)))
        green = int(round(base + ((green - base) * softness)))
        blue = int(round(base + ((blue - base) * softness)))
    return f"\x1b[48;2;{red};{green};{blue}m"


def _metric_residual_background(value: object, *, kind: str, metric_type: str, active: bool) -> str:
    if not active:
        return ""
    numeric = _as_float(value)
    if numeric is None:
        return ""

    if metric_type == "spread":
        if kind == "snr":
            ratio = _metric_ratio(numeric, 0.0, 30.0, invert=True)
        else:
            ratio = _metric_ratio(numeric, 0.0, 12.0, invert=True)
    else:
        if kind == "snr":
            ratio = _metric_ratio(numeric, -20.0, 10.0)
        else:
            ratio = _metric_ratio(numeric, -130.0, -90.0, invert=True)

    red, green, _ = _ratio_to_rgb_components(ratio)
    base = 16
    strength = 0.18
    red = int(round(base + (red * strength)))
    green = int(round(base + (green * strength)))
    blue = 8
    return f"\x1b[48;2;{red};{green};{blue}m"


def _metric_layered_background(
    current: object,
    previous: object,
    older: object,
    *,
    kind: str,
    metric_type: str,
    residual_active: bool = False,
) -> str:
    return _metric_change_background(current, previous, kind=kind, metric_type=metric_type, emphasis="strong")


def _colorize_metric_value_change(
    value: object,
    previous: object,
    older: object = None,
    *,
    kind: str,
    residual_active: bool = False,
) -> str:
    foreground, text = _metric_value_foreground(value, kind=kind)
    if foreground is None:
        return text
    background = _metric_layered_background(
        value,
        previous,
        older,
        kind=kind,
        metric_type="value",
        residual_active=residual_active,
    )
    return f"{background}{foreground}{text}\x1b[0m"


def _colorize_metric_spread_change(
    value: object,
    previous: object,
    older: object = None,
    *,
    kind: str,
    residual_active: bool = False,
) -> str:
    foreground, text = _metric_spread_foreground(value, kind=kind)
    if foreground is None:
        return text
    background = _metric_layered_background(
        value,
        previous,
        older,
        kind=kind,
        metric_type="spread",
        residual_active=residual_active,
    )
    return f"{background}{foreground}{text}\x1b[0m"


def _colorize_metric_delta(value: object, previous: object, *, kind: str) -> str:
    text = _format_metric_delta(value, previous)
    if text is None:
        return "-"

    magnitude = abs(_as_float(value) - _as_float(previous))
    if kind == "snr":
        ratio = _metric_ratio(magnitude, 0.0, 6.0, invert=True)
    else:
        ratio = _metric_ratio(magnitude, 0.0, 10.0, invert=True)

    return f"{_ratio_to_ansi_color(ratio)}{text}\x1b[0m"


def _metric_history_spread(values: object) -> Optional[float]:
    history = [_as_float(v) for v in (values if isinstance(values, list) else [])]
    numeric_values = [value for value in history if value is not None]
    if not numeric_values:
        return None
    if len(numeric_values) == 1:
        return 0.0
    return abs(max(numeric_values) - min(numeric_values))


def _colorize_metric_spread(value: object, *, kind: str) -> str:
    numeric = _as_float(value)
    if numeric is None:
        return "-"

    if kind == "snr":
        ratio = _metric_ratio(numeric, 0.0, 30.0, invert=True)
    else:
        ratio = _metric_ratio(numeric, 0.0, 12.0, invert=True)

    return f"{_ratio_to_ansi_color(ratio)}{_format_metric_number(numeric)}\x1b[0m"


def _metric_history_stats(values: object, *, fallback_current: object = None, fallback_previous: object = None) -> Dict[str, object]:
    history = [_as_float(v) for v in (values if isinstance(values, list) else [])]
    numeric_values = [value for value in history if value is not None]

    if not numeric_values:
        current = _as_float(fallback_current)
        previous = _as_float(fallback_previous)
        if current is None:
            return {
                "current": "-",
                "spread": "-",
                "min": "-",
                "avg": "-",
                "max": "-",
                "count": 0,
            }
        values2 = [current]
        if previous is not None:
            values2.append(previous)
        return {
            "current": current,
            "spread": _metric_history_spread(values2),
            "min": min(values2),
            "avg": sum(values2) / float(len(values2)),
            "max": max(values2),
            "count": len(values2),
        }

    return {
        "current": numeric_values[0],
        "spread": _metric_history_spread(numeric_values),
        "min": min(numeric_values),
        "avg": sum(numeric_values) / float(len(numeric_values)),
        "max": max(numeric_values),
        "count": len(numeric_values),
    }


def _metric_previous_stats(values: object, *, fallback_previous: object = None) -> Dict[str, object]:
    history = [_as_float(v) for v in (values if isinstance(values, list) else [])]
    numeric_values = [value for value in history if value is not None]

    if len(numeric_values) > 1:
        previous_values = numeric_values[1:]
    else:
        previous_value = _as_float(fallback_previous)
        previous_values = [previous_value] if previous_value is not None else []

    if not previous_values:
        return {
            "current": "-",
            "spread": "-",
            "min": "-",
            "avg": "-",
            "max": "-",
            "count": 0,
        }

    return {
        "current": previous_values[0],
        "spread": _metric_history_spread(previous_values),
        "min": min(previous_values),
        "avg": sum(previous_values) / float(len(previous_values)),
        "max": max(previous_values),
        "count": len(previous_values),
    }


def _collect_tune_row_windows(row: Dict[str, object]) -> Dict[str, Dict[str, object]]:
    return {
        "tx": _metric_history_stats(
            row.get("hears_me_history"),
            fallback_current=row.get("hears_me"),
            fallback_previous=row.get("hears_me_prev"),
        ),
        "rx": _metric_history_stats(
            row.get("i_hear_him_history"),
            fallback_current=row.get("i_hear_him"),
            fallback_previous=row.get("i_hear_him_prev"),
        ),
        "nf": _metric_history_stats(
            row.get("i_hear_him_noise_history"),
            fallback_current=row.get("i_hear_him_noise"),
            fallback_previous=row.get("i_hear_him_noise_prev"),
        ),
    }


def _tune_window_summary_value(window: Dict[str, object], key: str) -> object:
    if key not in ("spread", "min", "avg", "max"):
        return window.get(key)
    count = int(_as_int(window.get("count")) or 0)
    if count <= 1:
        return "-"
    return window.get(key)


def _build_tune_metric_snapshot(rows: List[Dict[str, object]]) -> Dict[str, Dict[str, object]]:
    snapshot: Dict[str, Dict[str, object]] = {}
    for row in rows:
        node_id = str(row.get("node_id") or "")
        if not node_id:
            continue
        windows = _collect_tune_row_windows(row)
        snapshot[node_id] = {
            "tx_current": windows["tx"].get("current"),
            "tx_spread": _tune_window_summary_value(windows["tx"], "spread"),
            "tx_min": _tune_window_summary_value(windows["tx"], "min"),
            "tx_avg": _tune_window_summary_value(windows["tx"], "avg"),
            "tx_max": _tune_window_summary_value(windows["tx"], "max"),
            "rx_current": windows["rx"].get("current"),
            "rx_spread": _tune_window_summary_value(windows["rx"], "spread"),
            "rx_min": _tune_window_summary_value(windows["rx"], "min"),
            "rx_avg": _tune_window_summary_value(windows["rx"], "avg"),
            "rx_max": _tune_window_summary_value(windows["rx"], "max"),
            "nf_current": windows["nf"].get("current"),
            "nf_spread": _tune_window_summary_value(windows["nf"], "spread"),
            "nf_min": _tune_window_summary_value(windows["nf"], "min"),
            "nf_avg": _tune_window_summary_value(windows["nf"], "avg"),
            "nf_max": _tune_window_summary_value(windows["nf"], "max"),
        }
    return snapshot


def _row_window_sample_count(row: Dict[str, object]) -> int:
    counts = [
        int(_metric_history_stats(row.get("hears_me_history"), fallback_current=row.get("hears_me")).get("count", 0) or 0),
        int(_metric_history_stats(row.get("i_hear_him_history"), fallback_current=row.get("i_hear_him")).get("count", 0) or 0),
        int(_metric_history_stats(row.get("i_hear_him_noise_history"), fallback_current=row.get("i_hear_him_noise")).get("count", 0) or 0),
    ]
    return max(counts) if counts else 0


def _append_metric_history(rec: Dict[str, object], key: str, value: object, *, limit: Optional[int] = None) -> None:
    numeric = _as_float(value)
    if numeric is None:
        return

    history = rec.setdefault(key, [])
    if not isinstance(history, list):
        history = []
        rec[key] = history
    if limit is None or len(history) < max(1, int(limit)):
        history.append(numeric)


def _append_metric_sample(
    rec: Dict[str, object],
    key: str,
    ts_epoch: object,
    value: object,
    *,
    limit: Optional[int] = None,
) -> None:
    numeric = _as_float(value)
    event_epoch = _as_int(ts_epoch)
    if numeric is None or event_epoch is None or event_epoch <= 0:
        return

    samples = rec.setdefault(key, [])
    if not isinstance(samples, list):
        samples = []
        rec[key] = samples
    if limit is None or len(samples) < max(1, int(limit)):
        samples.append((int(event_epoch), numeric))


def _merge_metric_samples(*series: object, limit: Optional[int] = None) -> List[Tuple[int, float]]:
    merged: List[Tuple[int, float]] = []
    for bucket in series:
        if not isinstance(bucket, list):
            continue
        for item in bucket:
            if not isinstance(item, (list, tuple)) or len(item) < 2:
                continue
            event_epoch = _as_int(item[0])
            numeric = _as_float(item[1])
            if event_epoch is None or event_epoch <= 0 or numeric is None:
                continue
            merged.append((int(event_epoch), numeric))
    merged.sort(key=lambda item: item[0], reverse=True)
    if limit is not None:
        return merged[: max(1, int(limit))]
    return merged


def _sample_history(values: List[float], *, max_points: int = 6) -> List[float]:
    if len(values) <= max_points:
        return list(values)
    if max_points <= 1:
        return [values[-1]]

    sampled: List[float] = []
    count = len(values)
    for idx in range(max_points):
        src_index = int(round((idx * (count - 1)) / float(max_points - 1)))
        sampled.append(values[src_index])
    return sampled


def _build_metric_history_text(values: List[float], *, max_points: int = 6) -> str:
    if not values:
        return "-"

    sequence = list(reversed(_sample_history(values, max_points=max_points)))
    chars = ".:-=+*#"
    low = min(sequence)
    high = max(sequence)
    if abs(high - low) < 0.005:
        return "=" * len(sequence)

    out_chars: List[str] = []
    for value in sequence:
        ratio = (value - low) / float(high - low)
        index = int(round(ratio * (len(chars) - 1)))
        out_chars.append(chars[max(0, min(len(chars) - 1, index))])
    return "".join(out_chars)


def _metric_log_segment(value: object, *, kind: str) -> str:
    numeric = _as_float(value)
    if numeric is None:
        return " "
    if kind == "snr":
        ratio = _metric_ratio(numeric, -20.0, 10.0)
    else:
        ratio = _metric_ratio(numeric, -130.0, -90.0, invert=True)
    red, green, _ = _ratio_to_rgb_components(ratio)
    base = 12
    strength = 0.75
    red = int(round(base + (red * strength)))
    green = int(round(base + (green * strength)))
    blue = 8
    return f"\x1b[48;2;{red};{green};{blue}m \x1b[0m"


def _build_metric_color_log(values: object, *, kind: str, width: int = 10) -> str:
    if width <= 0:
        return ""
    history = [_as_float(v) for v in (values if isinstance(values, list) else [])]
    numeric_values = [value for value in history if value is not None]
    if not numeric_values:
        return "-"

    newest_first = list(numeric_values[:width])
    oldest_to_newest = list(reversed(newest_first))
    if len(oldest_to_newest) < width:
        oldest_to_newest = ([None] * (width - len(oldest_to_newest))) + oldest_to_newest
    else:
        oldest_to_newest = oldest_to_newest[-width:]

    return "".join(_metric_log_segment(value, kind=kind) for value in oldest_to_newest)


def _compute_variability_stats(values: object, *, kind: str) -> Dict[str, object]:
    numbers = [_as_float(v) for v in (values if isinstance(values, list) else [])]
    history = [v for v in numbers if v is not None]
    if not history:
        return {
            "jitter": None,
            "range": None,
            "score": None,
            "state": "-",
            "history": "-",
            "history_count": 0,
        }

    if len(history) == 1:
        return {
            "jitter": 0.0,
            "range": 0.0,
            "score": 100,
            "state": "new",
            "history": _build_metric_history_text(history),
            "history_count": 1,
        }

    diffs = [abs(history[idx] - history[idx + 1]) for idx in range(len(history) - 1)]
    jitter = sum(diffs) / float(len(diffs))
    metric_range = max(history) - min(history)

    if kind == "snr":
        jitter_ratio = _metric_ratio(jitter, 0.0, 4.0)
        range_ratio = _metric_ratio(metric_range, 0.0, 10.0)
    else:
        jitter_ratio = _metric_ratio(jitter, 0.0, 5.0)
        range_ratio = _metric_ratio(metric_range, 0.0, 12.0)

    penalty = (0.65 * jitter_ratio) + (0.35 * range_ratio)
    score = int(round(100.0 * (1.0 - penalty)))
    score = max(0, min(100, score))

    if score >= 80:
        state = "stable"
    elif score >= 55:
        state = "mid"
    else:
        state = "wild"

    return {
        "jitter": jitter,
        "range": metric_range,
        "score": score,
        "state": state,
        "history": _build_metric_history_text(history),
        "history_count": len(history),
    }


def _variability_ratio_from_score(score: object) -> Optional[float]:
    numeric = _as_float(score)
    if numeric is None:
        return None
    return max(0.0, min(1.0, numeric / 100.0))


def _colorize_variability_value(value: object, *, kind: str, metric: str) -> str:
    if metric == "score":
        numeric = _as_float(value)
        if numeric is None:
            return "-"
        ratio = _variability_ratio_from_score(numeric)
        text = str(int(round(numeric)))
        return f"{_ratio_to_ansi_color(ratio)}{text}\x1b[0m"

    numeric = _as_float(value)
    if numeric is None:
        return "-"
    if kind == "snr":
        ratio = _metric_ratio(numeric, 0.0, 4.0 if metric == "jitter" else 10.0, invert=True)
    else:
        ratio = _metric_ratio(numeric, 0.0, 5.0 if metric == "jitter" else 12.0, invert=True)
    return f"{_ratio_to_ansi_color(ratio)}{_format_metric_number(numeric)}\x1b[0m"


def _colorize_variability_state(state: object, score: object) -> str:
    text = str(state or "-")
    if text == "-":
        return "-"
    ratio = _variability_ratio_from_score(100 if text == "new" else score)
    if ratio is None:
        return text
    return f"{_ratio_to_ansi_color(ratio)}{text}\x1b[0m"


def _colorize_variability_history(history: object, score: object) -> str:
    text = str(history or "-")
    if text == "-":
        return "-"
    ratio = _variability_ratio_from_score(score)
    if ratio is None:
        ratio = 1.0 if text == "=" else 0.5
    return f"{_ratio_to_ansi_color(ratio)}{text}\x1b[0m"


def _make_tune_session_metric_state() -> Dict[str, object]:
    return {
        "last_key": None,
        "current": None,
        "previous": None,
        "min": None,
        "max": None,
        "sum": 0.0,
        "count": 0,
    }


def _make_tune_session_node_state() -> Dict[str, object]:
    return {
        "tx": _make_tune_session_metric_state(),
        "rx": _make_tune_session_metric_state(),
        "nf": _make_tune_session_metric_state(),
    }


def _update_tune_session_metric(metric_state: Dict[str, object], value: object, sample_key: object) -> None:
    numeric = _as_float(value)
    if numeric is None or sample_key in (None, "", 0):
        return
    if metric_state.get("last_key") == sample_key:
        return

    metric_state["last_key"] = sample_key
    metric_state["previous"] = metric_state.get("current")
    metric_state["current"] = numeric
    metric_state["count"] = int(metric_state.get("count", 0) or 0) + 1
    metric_state["sum"] = float(metric_state.get("sum", 0.0) or 0.0) + numeric

    current_min = _as_float(metric_state.get("min"))
    current_max = _as_float(metric_state.get("max"))
    metric_state["min"] = numeric if current_min is None else min(current_min, numeric)
    metric_state["max"] = numeric if current_max is None else max(current_max, numeric)


def _snapshot_tune_session_metric(metric_state: Optional[Dict[str, object]]) -> Dict[str, object]:
    if not isinstance(metric_state, dict):
        return {
            "current": "-",
            "previous": "-",
            "delta": "-",
            "min": "-",
            "avg": "-",
            "max": "-",
            "count": 0,
        }

    current = _as_float(metric_state.get("current"))
    previous = _as_float(metric_state.get("previous"))
    total = float(metric_state.get("sum", 0.0) or 0.0)
    count = int(metric_state.get("count", 0) or 0)
    avg = (total / float(count)) if count > 0 else None

    return {
        "current": current if current is not None else "-",
        "previous": previous if previous is not None else "-",
        "delta": _format_metric_delta(current, previous) if current is not None and previous is not None else "-",
        "min": metric_state.get("min") if _as_float(metric_state.get("min")) is not None else "-",
        "avg": avg if avg is not None else "-",
        "max": metric_state.get("max") if _as_float(metric_state.get("max")) is not None else "-",
        "count": count,
    }


def _session_metric_from_row(row: Dict[str, object], *, value_key: str, previous_key: str) -> Dict[str, object]:
    current = _as_float(row.get(value_key))
    previous = _as_float(row.get(previous_key))
    if current is None:
        return {
            "current": "-",
            "previous": "-",
            "delta": "-",
            "min": "-",
            "avg": "-",
            "max": "-",
            "count": 0,
        }

    values = [current]
    if previous is not None:
        values.append(previous)

    return {
        "current": current,
        "previous": previous if previous is not None else "-",
        "delta": _format_metric_delta(current, previous) if previous is not None else "-",
        "min": min(values),
        "avg": (sum(values) / float(len(values))) if values else "-",
        "max": max(values),
        "count": len(values),
    }


def _apply_tune_session_rows(rows: List[Dict[str, object]], session_state: Dict[str, object]) -> List[Dict[str, object]]:
    enriched_rows: List[Dict[str, object]] = []
    for row in rows:
        node_id = str(row.get("node_id") or "")
        if not node_id:
            enriched_rows.append(dict(row))
            continue

        node_state = session_state.setdefault(node_id, _make_tune_session_node_state())

        tx_epoch = _as_int(row.get("hears_me_epoch"))
        rx_epoch = _as_int(row.get("i_hear_him_epoch"))
        nf_epoch = _as_int(row.get("i_hear_him_noise_epoch"))

        _update_tune_session_metric(node_state["tx"], row.get("hears_me"), (tx_epoch, _as_float(row.get("hears_me"))))
        _update_tune_session_metric(node_state["rx"], row.get("i_hear_him"), (rx_epoch, _as_float(row.get("i_hear_him"))))
        _update_tune_session_metric(
            node_state["nf"],
            row.get("i_hear_him_noise"),
            (nf_epoch, _as_float(row.get("i_hear_him_noise"))),
        )

        enriched = dict(row)
        enriched["session_tx"] = _snapshot_tune_session_metric(node_state["tx"])
        enriched["session_rx"] = _snapshot_tune_session_metric(node_state["rx"])
        enriched["session_nf"] = _snapshot_tune_session_metric(node_state["nf"])
        enriched_rows.append(enriched)

    return enriched_rows


def _classify_packet_event_type(packet: Dict[str, object]) -> str:
    decoded = packet.get("decoded") if isinstance(packet.get("decoded"), dict) else None
    if not decoded:
        return "listen_event"
    if isinstance(decoded.get("position"), dict) or decoded.get("portnum") == "POSITION_APP":
        return "position"
    if isinstance(decoded.get("telemetry"), dict) or decoded.get("portnum") == "TELEMETRY_APP":
        return "telemetry"
    if isinstance(decoded.get("user"), dict) or decoded.get("portnum") == "NODEINFO_APP":
        return "user"
    return "listen_event"


def _extract_packet_rx_sample(packet: Dict[str, object], ts_utc: str, fallback_node_id: Optional[str] = None) -> Optional[Dict[str, object]]:
    node_id = normalize_node_id(str(packet.get("fromId"))) if isinstance(packet.get("fromId"), str) else None
    if not node_id:
        node_id = fallback_node_id
    if not node_id:
        return None

    rx_snr = _as_float(_first_not_none(packet.get("rxSnr"), packet.get("rx_snr")))
    rx_rssi = _as_float(_first_not_none(packet.get("rxRssi"), packet.get("rx_rssi")))
    if rx_snr is None and rx_rssi is None:
        return None

    noise_floor = None
    if rx_snr is not None and rx_rssi is not None:
        noise_floor = rx_rssi - rx_snr

    ts_epoch = _as_int(_first_not_none(packet.get("rxTime"), packet.get("rx_time")))
    if ts_epoch is None:
        ts_epoch = int(time.time())

    return {
        "ts_utc": ts_utc,
        "ts_epoch": ts_epoch,
        "node_id": node_id,
        "from_id": node_id,
        "to_id": normalize_node_id(str(packet.get("toId"))) if isinstance(packet.get("toId"), str) else None,
        "portnum": str(packet.get("decoded", {}).get("portnum")) if isinstance(packet.get("decoded"), dict) and packet.get("decoded", {}).get("portnum") is not None else None,
        "rx_snr": rx_snr,
        "rx_rssi": rx_rssi,
        "noise_floor": noise_floor,
        "hop_limit": _as_int(_first_not_none(packet.get("hopLimit"), packet.get("hop_limit"))),
        "hop_start": _as_int(_first_not_none(packet.get("hopStart"), packet.get("hop_start"))),
        "rx_time": _as_int(_first_not_none(packet.get("rxTime"), packet.get("rx_time"))),
        "raw_json": json.dumps(_sanitize(packet), ensure_ascii=False),
    }


def _insert_packet_rx_sample(conn: sqlite3.Connection, sample: Dict[str, object]) -> None:
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO packet_rx_samples (
            ts_utc, ts_epoch, node_id, from_id, to_id, portnum,
            rx_snr, rx_rssi, noise_floor,
            hop_limit, hop_start, rx_time, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sample.get("ts_utc"),
            sample.get("ts_epoch"),
            sample.get("node_id"),
            sample.get("from_id"),
            sample.get("to_id"),
            sample.get("portnum"),
            sample.get("rx_snr"),
            sample.get("rx_rssi"),
            sample.get("noise_floor"),
            sample.get("hop_limit"),
            sample.get("hop_start"),
            sample.get("rx_time"),
            sample.get("raw_json"),
        ),
    )


def _handle_packet_payload(conn: sqlite3.Connection, ts_utc: str, node_id: Optional[str], packet: Dict[str, object]) -> None:
    decoded = packet.get("decoded") if isinstance(packet.get("decoded"), dict) else None
    if not node_id or not decoded:
        return

    user = decoded.get("user") if isinstance(decoded.get("user"), dict) else None
    if user:
        upsert_node(
            conn,
            {
                "user": {
                    "id": node_id,
                    "longName": user.get("longName"),
                    "shortName": user.get("shortName"),
                    "role": user.get("role"),
                    "hwModel": user.get("hwModel"),
                },
                "snr": _first_not_none(packet.get("rxSnr"), packet.get("rx_snr")),
                "lastHeard": _first_not_none(packet.get("rxTime"), packet.get("rx_time")),
            },
            ts_utc,
            sample_type="listen_user",
        )

    if isinstance(decoded.get("telemetry"), dict):
        telem = decoded.get("telemetry") if isinstance(decoded.get("telemetry"), dict) else {}
        upsert_node(
            conn,
            {
                "user": {"id": node_id},
                "deviceMetrics": telem.get("deviceMetrics"),
                "environmentalMetrics": telem.get("environmentalMetrics"),
            },
            ts_utc,
            sample_type="listen_telemetry",
        )

    if isinstance(decoded.get("position"), dict):
        upsert_node(
            conn,
            {"user": {"id": node_id}, "position": decoded.get("position")},
            ts_utc,
            sample_type="listen_position",
        )


def _extract_structured_event_from_line(line: str) -> Optional[Dict[str, object]]:
    text = (line or "").strip()
    if not text.startswith("{"):
        return None
    try:
        data = json.loads(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if data.get("kind") not in ("packet", "node"):
        return None
    return data


def _handle_listen_structured_event(db_path: str, event: Dict[str, object]) -> None:
    kind = str(event.get("kind") or "")
    ts_utc = str(event.get("ts_utc") or iso_utc_now())

    if kind == "node":
        node = event.get("node") if isinstance(event.get("node"), dict) else None
        if not node:
            return
        node_id = _extract_node_id_from_event(node)
        _insert_listen_event(db_path, ts_utc, "nodeinfo", node_id, node)
        if node_id:
            init_db(db_path)
            conn = connect_sqlite(db_path)
            try:
                upsert_node(conn, node, ts_utc, sample_type="listen_nodeinfo")
                conn.commit()
            finally:
                conn.close()
        return

    if kind != "packet":
        return

    packet = event.get("packet") if isinstance(event.get("packet"), dict) else None
    if not packet:
        return

    packet_sanitized = _sanitize(packet)
    node_id = _extract_node_id_from_event(packet)
    event_type = _classify_packet_event_type(packet)
    init_db(db_path)
    conn = connect_sqlite(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO listen_events (ts_utc, event_type, node_id, raw_json) VALUES (?, ?, ?, ?)",
            (ts_utc, event_type, node_id, json.dumps(packet_sanitized, ensure_ascii=False)),
        )
        sample = _extract_packet_rx_sample(packet, ts_utc, fallback_node_id=node_id)
        if sample:
            _insert_packet_rx_sample(conn, sample)
        _handle_packet_payload(conn, ts_utc, node_id, packet)
        conn.commit()
    finally:
        conn.close()


def _handle_listen_line(db_path: str, line: str) -> None:
    structured = _extract_structured_event_from_line(line)
    if structured is not None:
        _handle_listen_structured_event(db_path, structured)
        return

    if "Received nodeinfo:" in line:
        d = _extract_dict_from_line(line)
        if isinstance(d, dict):
            node_id = _extract_node_id_from_event(d)
            ts_utc = iso_utc_now()
            _insert_listen_event(db_path, ts_utc, "nodeinfo", node_id, _sanitize(d))
            if node_id:
                conn = connect_sqlite(db_path)
                try:
                    upsert_node(conn, d, ts_utc, sample_type="listen_nodeinfo")
                    conn.commit()
                finally:
                    conn.close()
        return

    if "asDict:" in line or "d:{" in line:
        d = _extract_dict_from_line(line)
        if isinstance(d, dict):
            d_sanitized = _sanitize(d)
            node_id = _extract_node_id_from_event(d)
            ts_utc = iso_utc_now()
            event_type = _classify_packet_event_type(d)
            init_db(db_path)
            conn = connect_sqlite(db_path)
            try:
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO listen_events (ts_utc, event_type, node_id, raw_json) VALUES (?, ?, ?, ?)",
                    (ts_utc, event_type, node_id, json.dumps(d_sanitized, ensure_ascii=False)),
                )
                sample = _extract_packet_rx_sample(d, ts_utc, fallback_node_id=node_id)
                if sample:
                    _insert_packet_rx_sample(conn, sample)
                _handle_packet_payload(conn, ts_utc, node_id, d)
                conn.commit()
            finally:
                conn.close()
        return


def _meshtastic_helper_script_path() -> str:
    if getattr(sys, "frozen", False):
        frozen_dirs: List[str] = []
        meipass = getattr(sys, "_MEIPASS", None)
        if isinstance(meipass, str) and meipass:
            frozen_dirs.append(meipass)
        frozen_dirs.append(os.path.dirname(os.path.abspath(sys.executable)))

        for base_dir in frozen_dirs:
            for name in ("meshtastic_listen_helper.exe", "meshtastic_listen_helper"):
                candidate = os.path.join(base_dir, name)
                if os.path.isfile(candidate):
                    return candidate
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "meshtastic_listen_helper.py")


def _resolve_meshtastic_python() -> Optional[str]:
    env_python = os.environ.get("MESHTASTIC_PYTHON")
    if env_python and os.path.isfile(env_python):
        return env_python

    meshtastic_bin = shutil.which("meshtastic")
    if not meshtastic_bin or not os.path.isfile(meshtastic_bin):
        return None

    try:
        with open(meshtastic_bin, "r", encoding="utf-8", errors="ignore") as fh:
            first_line = fh.readline().strip()
    except Exception:
        first_line = ""

    if first_line.startswith("#!"):
        candidate = first_line[2:].strip()
        if candidate.startswith("/usr/bin/env "):
            candidate = candidate.split(None, 1)[1].strip()
        if os.path.isabs(candidate) and os.path.isfile(candidate):
            return candidate
        resolved = shutil.which(candidate)
        if resolved:
            return resolved

    return None


def _build_listen_command(port: Optional[str], timeout: int) -> List[str]:
    helper_path = _meshtastic_helper_script_path()
    port_args = _port_cli_args(port)
    if os.name == "nt" and getattr(sys, "frozen", False):
        return _meshtastic_cmd_bases()[0] + port_args + ["--listen"]
    if os.path.isfile(helper_path) and os.path.splitext(helper_path)[1].lower() == ".exe":
        return [helper_path] + port_args + ["--timeout", str(max(30, int(timeout)))]
    helper_python = _resolve_meshtastic_python()
    if helper_python and os.path.isfile(helper_path):
        return [helper_python, helper_path] + port_args + ["--timeout", str(max(30, int(timeout)))]
    return _meshtastic_cmd_bases()[0] + port_args + ["--listen"]


def start_listen_thread(port: Optional[str], timeout: int, db_path: str) -> threading.Thread:
    def _worker() -> None:
        while True:
            if STOP:
                return
            if LISTEN_SUSPENDED:
                time.sleep(0.2)
                continue
            cmd = _build_listen_command(port, timeout)
            with _LISTEN_LOCK:
                try:
                    global LISTEN_PROC
                    popen_kwargs = {
                        "stdout": subprocess.PIPE,
                        "stderr": subprocess.STDOUT,
                        "text": False,
                        "bufsize": 0,
                    }
                    if os.name == "nt":
                        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
                    else:
                        popen_kwargs["preexec_fn"] = os.setsid
                    LISTEN_PROC = subprocess.Popen(cmd, **popen_kwargs)
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
                line = _decode_subprocess_output(raw).strip()
                if not line:
                    continue
                if detect_device_not_found(line):
                    out(
                        f"{ts_now()} ERROR: {_device_lookup_error(port)}"
                    )
                    time.sleep(5)
                    break
                if detect_multiple_ports(line):
                    out(f"{ts_now()} ERROR: {_multiple_ports_error()}")
                    time.sleep(5)
                    break
                if detect_device_busy(line):
                    out(
                        f"{ts_now()} ERROR: {_device_busy_error(port)}"
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


def _poll_sort_key_far_first(node: NodeRec) -> Tuple[int, int, str, str]:
    hops = node.hops_away if isinstance(node.hops_away, int) else -1
    last_heard = node.last_heard if isinstance(node.last_heard, int) else 0
    return (-hops, -last_heard, node.long.lower(), node.node_id.lower())


def _poll_sort_key_direct_round_robin(
    node: NodeRec,
    sample_counts: Dict[str, int],
    poll_order: Dict[str, int],
) -> Tuple[int, int, str, str]:
    return (
        int(sample_counts.get(node.node_id, 0) or 0),
        int(poll_order.get(node.node_id, 0) or 0),
        node.long.lower(),
        node.node_id.lower(),
    )


def _poll_members_signature(active: List[NodeRec]) -> Tuple[str, ...]:
    return tuple(sorted(node.node_id for node in active if node.node_id))


def _load_recent_transit_node_ids(
    db_path: str,
    self_id: str,
    *,
    window_seconds: Optional[int],
    session_start_epoch: Optional[int] = None,
    now_epoch: Optional[int] = None,
) -> set:
    if not self_id:
        return set()

    cutoff = _resolve_tune_window_cutoff(
        window_seconds=window_seconds,
        session_start_epoch=session_start_epoch,
        now_epoch=now_epoch,
    )
    init_db(db_path)
    conn = connect_sqlite(db_path)
    try:
        ensure_traceroutes_ts_epoch(conn)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT route_raw
            FROM traceroutes
            WHERE
                self_id = ?
                AND ts_epoch IS NOT NULL
                AND ts_epoch >= ?
            ORDER BY ts_epoch DESC, id DESC
            """,
            (self_id, cutoff),
        )

        transit_ids = set()
        for (route_raw,) in cur.fetchall():
            steps = _parse_route_steps(route_raw)
            if len(steps) < 3:
                continue
            for node_id, _ in steps[1:-1]:
                if node_id and node_id != self_id:
                    transit_ids.add(node_id)
        return transit_ids
    finally:
        conn.close()


def _load_recent_direct_node_ids(
    db_path: str,
    self_id: str,
    *,
    window_seconds: Optional[int] = None,
    session_start_epoch: Optional[int] = None,
    now_epoch: Optional[int] = None,
) -> set:
    rows = load_tune_direct_nodes(
        db_path,
        self_id,
        window_seconds=window_seconds,
        now_epoch=now_epoch,
        session_start_epoch=session_start_epoch,
    )
    return {str(row.get("node_id")) for row in rows if row.get("node_id")}


def _schedule_active_nodes(
    active: List[NodeRec],
    *,
    tune_mode: bool,
    direct_ids: set,
    transit_ids: set,
    sample_counts: Optional[Dict[str, int]] = None,
    poll_order: Optional[Dict[str, int]] = None,
) -> List[NodeRec]:
    if not active:
        return []

    sample_counts = sample_counts or {}
    poll_order = poll_order or {}
    active_ids = {node.node_id for node in active}
    direct_ids = {node_id for node_id in direct_ids if node_id in active_ids}
    transit_ids = {node_id for node_id in transit_ids if node_id in active_ids}

    if tune_mode:
        direct_nodes = [node for node in active if node.node_id in direct_ids]
        other_nodes = [node for node in active if node.node_id not in direct_ids and node.node_id not in transit_ids]
        direct_nodes.sort(key=lambda node: _poll_sort_key_direct_round_robin(node, sample_counts, poll_order))
        other_nodes.sort(key=_poll_sort_key_far_first)
        scheduled = direct_nodes + other_nodes
        return scheduled if scheduled else sorted(active, key=_poll_sort_key_far_first)

    scheduled = [node for node in active if node.node_id not in transit_ids]
    if not scheduled:
        scheduled = list(active)
    scheduled.sort(key=_poll_sort_key_far_first)
    return scheduled


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
    def _strip_trace_prefixes(line: str) -> str:
        text = clean_ansi(line or "").strip()
        while True:
            stripped = re.sub(r"^\[[^\]]+\]\s*", "", text).strip()
            if stripped == text:
                break
            text = stripped
        for marker in (
            "Route traced towards destination:",
            "Route traced back to us:",
            "Route traced:",
            "Trace route result:",
        ):
            pos = text.find(marker)
            if pos >= 0:
                return text[pos:].strip()
        return text

    def _looks_like_route_line(line: str) -> bool:
        text = (line or "").strip()
        if not text:
            return False
        return any(sep in text for sep in ("-->", "<--", " > "))

    def _canonicalize_route_line(line: Optional[str]) -> Optional[str]:
        text = _strip_trace_prefixes(str(line or ""))
        if not text:
            return None
        if ":" in text and text.split(":", 1)[0] in (
            "Route traced towards destination",
            "Route traced back to us",
            "Route traced",
            "Trace route result",
        ):
            text = text.split(":", 1)[1].strip()
        if not text:
            return None

        if "<--" in text and "-->" not in text:
            parts = [part.strip() for part in text.split("<--") if part.strip()]
            if not parts:
                return None
            leading_metric = None
            metric_match = re.match(r"^\(([-+]?\d+(?:\.\d+)?|\?)dB\)\s*(.+)$", parts[0])
            if metric_match:
                leading_metric = metric_match.group(1)
                parts[0] = metric_match.group(2).strip()
            parts = list(reversed(parts))
            if leading_metric and parts and not re.search(r"\(([-+]?\d+(?:\.\d+)?|\?)dB\)\s*$", parts[-1]):
                parts[-1] = f"{parts[-1]} ({leading_metric}dB)"
            text = " --> ".join(parts)

        text = re.sub(r"\s>\s", " --> ", text)
        text = re.sub(r"\b0x([0-9a-fA-F]{8})\b", lambda m: "!" + m.group(1).lower(), text)
        return text.strip() or None

    def _next_route_line(lines: List[str], start_idx: int) -> Tuple[Optional[str], int]:
        for idx in range(start_idx, len(lines)):
            candidate = _strip_trace_prefixes(lines[idx])
            if not candidate:
                continue
            if candidate.startswith(("Route traced", "Trace route result")):
                continue
            if _looks_like_route_line(candidate):
                return _canonicalize_route_line(candidate), idx
        return None, start_idx

    lines = [_strip_trace_prefixes(line) for line in clean_ansi(raw).splitlines() if line.strip()]
    towards: Optional[str] = None
    back: Optional[str] = None

    for idx, line in enumerate(lines):
        if "Route traced towards destination:" in line:
            route_line, _ = _next_route_line(lines, idx + 1)
            if route_line:
                towards = route_line
            continue

        if "Route traced back to us:" in line:
            route_line, _ = _next_route_line(lines, idx + 1)
            if route_line:
                back = route_line
            continue

        if "Route traced:" in line:
            first_line, first_idx = _next_route_line(lines, idx + 1)
            second_line, _ = _next_route_line(lines, first_idx + 1 if first_line else idx + 1)
            if first_line and not towards:
                towards = first_line
            if second_line and not back:
                back = second_line
            continue

        if "Trace route result:" in line:
            first_inline = _canonicalize_route_line(line)
            second_line, _ = _next_route_line(lines, idx + 1)
            if first_inline and not towards:
                towards = first_inline
            if second_line and not back:
                back = second_line

    return towards, back


def route_ids_to_names(route_line: str, nodes: Dict[str, dict]) -> str:
    parts = [p.strip() for p in route_line.split("-->")]
    out_parts = []
    for p in parts:
        m = re.match(r"^((?:!?[0-9a-fA-F]{8}|0x[0-9a-fA-F]{8}))(\s*\(.*\))?$", p)
        if m:
            nid = _normalize_route_node_id(m.group(1))
            suffix = m.group(2) or ""
            if nid:
                ln, sn = node_names(nodes, nid)
                out_parts.append(f"{ln}[{sn}]{suffix}")
            else:
                out_parts.append(p)
        else:
            out_parts.append(p)
    return " > ".join(out_parts)


def count_edges(route_line: str) -> int:
    normalized = route_line.replace(" > ", " --> ")
    parts = [p.strip() for p in normalized.split("-->") if p.strip()]
    return max(1, len(parts) - 1)


def _extract_last_rssi_display(route_line: Optional[str]) -> str:
    if not route_line:
        return "-"
    matches = _TUNE_DB_RE.findall(route_line)
    if not matches:
        return "-"
    last = matches[-1]
    return "?dB" if last == "?" else f"{last}dB"


def _summarize_traceroute_output(raw: str, *, max_len: int = 160) -> str:
    lines = []
    for line in clean_ansi(raw or "").splitlines():
        text = line.strip()
        if not text or text == "[TIMEOUT]":
            continue
        lines.append(text)
        if len(lines) >= 2:
            break
    summary = " | ".join(lines)
    if len(summary) > max_len:
        return summary[: max_len - 3].rstrip() + "..."
    return summary


def _format_tune_name(node_id: str, long_name: Optional[str], short_name: Optional[str]) -> str:
    ln = (long_name or "").strip() or node_id
    sn = (short_name or "").strip() or node_id[-4:]
    return f"{ln}[{sn}]"


def _format_tune_last_epoch(value: object) -> str:
    epoch = _as_int(value)
    if epoch is None or epoch <= 0:
        return "-"
    try:
        return _dt.datetime.fromtimestamp(epoch).strftime("%H:%M")
    except Exception:
        return "-"


def _format_tune_full_epoch(value: object) -> str:
    epoch = _as_int(value)
    if epoch is None or epoch <= 0:
        return "-"
    try:
        return _dt.datetime.fromtimestamp(epoch).strftime("%H:%M %d.%m.%Y")
    except Exception:
        return "-"


def _format_tune_full_datetime(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return "-"
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = _dt.datetime.strptime(text, fmt)
            return parsed.strftime("%H:%M %d.%m.%Y")
        except Exception:
            continue
    return text


def _format_tune_elapsed(value: object) -> str:
    seconds = _as_int(value)
    if seconds is None or seconds < 0:
        return "-"
    total_minutes = int(seconds) // 60
    hours, minutes = divmod(total_minutes, 60)
    days, hours = divmod(hours, 24)
    if days > 0:
        return f"{days}d {hours:02d}:{minutes:02d}"
    return f"{hours:02d}:{minutes:02d}"


def _resolve_tune_window_cutoff(
    *,
    window_seconds: Optional[int],
    session_start_epoch: Optional[int] = None,
    now_epoch: Optional[int] = None,
) -> int:
    now_value = int(now_epoch if now_epoch is not None else time.time())
    session_start = _as_int(session_start_epoch)
    normalized_window = _as_int(window_seconds)
    if normalized_window is None or normalized_window <= 0:
        if session_start is not None and session_start > 0:
            return int(session_start)
        return 0

    cutoff = now_value - int(normalized_window)
    if session_start is not None and session_start > 0:
        cutoff = max(cutoff, int(session_start))
    return max(0, int(cutoff))


def _format_tune_window_label(window_seconds: Optional[int]) -> str:
    normalized_window = _as_int(window_seconds)
    if normalized_window is None or normalized_window <= 0:
        return "весь сеанс"
    minutes = max(1, int(round(normalized_window / 60.0)))
    return f"{minutes}м"


def _format_ru_hours(value: object) -> str:
    hours = max(0, int(_as_int(value) or 0))
    mod10 = hours % 10
    mod100 = hours % 100
    if mod10 == 1 and mod100 != 11:
        suffix = "час"
    elif mod10 in (2, 3, 4) and mod100 not in (12, 13, 14):
        suffix = "часа"
    else:
        suffix = "часов"
    return f"{hours} {suffix}"


def _parse_route_steps(route_line: Optional[str]) -> List[Tuple[Optional[str], Optional[float]]]:
    if not route_line:
        return []

    steps: List[Tuple[Optional[str], Optional[float]]] = []
    for raw_part in route_line.split("-->"):
        part = raw_part.strip()
        if not part:
            continue

        node_id: Optional[str] = None
        snr_value: Optional[float] = None

        match = _ROUTE_STEP_RE.match(part)
        if match:
            token = match.group(1)
            if token != "Unknown":
                node_id = _normalize_route_node_id(token)
            if match.group(2):
                rssi_value = match.group(2)
                if rssi_value != "?":
                    snr_value = _as_float(rssi_value)
        else:
            token = part.split(" ", 1)[0]
            node_id = _normalize_route_node_id(token)
            rssi_match = _TUNE_DB_RE.search(part)
            if rssi_match:
                rssi_value = rssi_match.group(1)
                if rssi_value != "?":
                    snr_value = _as_float(rssi_value)

        steps.append((node_id, snr_value))

    return steps


def _capture_latest_previous_metric(
    rec: Dict[str, object],
    value_key: str,
    previous_key: str,
    value: object,
) -> None:
    numeric = _as_float(value)
    if numeric is None:
        return

    if _as_float(rec.get(value_key)) is None:
        rec[value_key] = numeric
        return

    if _as_float(rec.get(previous_key)) is None:
        rec[previous_key] = numeric


def _extract_direct_neighbor_sample_from_route(
    self_id: str,
    route_line: Optional[str],
    *,
    direction: str,
) -> Tuple[Optional[str], Optional[float]]:
    steps = _parse_route_steps(route_line)
    if len(steps) < 2:
        return None, None
    if direction == "out":
        node_id = steps[1][0]
        snr_value = steps[1][1]
    else:
        node_id = steps[-2][0]
        snr_value = steps[-1][1]
    if node_id and node_id != self_id:
        return node_id, snr_value
    return None, None


def _extract_direct_neighbor_id_from_route(self_id: str, route_line: Optional[str], *, direction: str) -> Optional[str]:
    node_id, _ = _extract_direct_neighbor_sample_from_route(self_id, route_line, direction=direction)
    return node_id


def _load_recent_packet_rx_by_node(
    conn: sqlite3.Connection,
    node_ids: List[str],
    *,
    metric_cutoff_epoch: int,
    count_cutoff_epoch: Optional[int] = None,
    log_cutoff_epoch: Optional[int] = None,
) -> Dict[str, Dict[str, object]]:
    if not node_ids:
        return {}

    count_cutoff = _as_int(count_cutoff_epoch)
    if count_cutoff is None or count_cutoff <= 0:
        count_cutoff = int(metric_cutoff_epoch)
    log_cutoff = _as_int(log_cutoff_epoch)
    if log_cutoff is None or log_cutoff <= 0:
        log_cutoff = int(metric_cutoff_epoch)
    query_cutoff = min(int(metric_cutoff_epoch), int(count_cutoff), int(log_cutoff))
    placeholders = ", ".join("?" for _ in node_ids)
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT
            node_id,
            rx_snr,
            noise_floor,
            ts_epoch
        FROM packet_rx_samples
        WHERE
            node_id IN ({placeholders})
            AND ts_epoch IS NOT NULL
            AND ts_epoch >= ?
        ORDER BY ts_epoch DESC, id DESC
        """,
        tuple(node_ids) + (query_cutoff,),
    )

    latest: Dict[str, Dict[str, object]] = {}
    for node_id, rx_snr, noise_floor, ts_epoch in cur.fetchall():
        event_epoch = int(ts_epoch) if isinstance(ts_epoch, (int, float)) else 0
        rec = latest.setdefault(
            node_id,
            {
                "rx_snr": "-",
                "rx_snr_prev": None,
                "rx_snr_history": [],
                "rx_snr_samples": [],
                "rx_snr_log_samples": [],
                "noise_floor": "-",
                "noise_floor_prev": None,
                "noise_floor_history": [],
                "noise_floor_samples": [],
                "noise_floor_log_samples": [],
                "ts_epoch": ts_epoch,
                "sample_count": 0,
            },
        )
        if event_epoch >= int(count_cutoff) and (_as_float(rx_snr) is not None or _as_float(noise_floor) is not None):
            rec["sample_count"] = int(rec.get("sample_count", 0) or 0) + 1
        if event_epoch >= int(log_cutoff):
            _append_metric_sample(rec, "rx_snr_log_samples", event_epoch, rx_snr)
            _append_metric_sample(rec, "noise_floor_log_samples", event_epoch, noise_floor)
        if event_epoch < int(metric_cutoff_epoch):
            continue
        _capture_latest_previous_metric(rec, "rx_snr", "rx_snr_prev", rx_snr)
        _capture_latest_previous_metric(rec, "noise_floor", "noise_floor_prev", noise_floor)
        _append_metric_history(rec, "rx_snr_history", rx_snr)
        _append_metric_sample(rec, "rx_snr_samples", event_epoch, rx_snr)
        _append_metric_history(rec, "noise_floor_history", noise_floor)
        _append_metric_sample(rec, "noise_floor_samples", event_epoch, noise_floor)
        if event_epoch > 0:
            rec["ts_epoch"] = max(int(rec.get("ts_epoch", 0) or 0), event_epoch)
    return latest


def load_tune_direct_nodes(
    db_path: str,
    self_id: str,
    *,
    window_seconds: Optional[int] = None,
    now_epoch: Optional[int] = None,
    session_start_epoch: Optional[int] = None,
) -> List[Dict[str, object]]:
    if not self_id:
        return []

    effective_cutoff = _resolve_tune_window_cutoff(
        window_seconds=window_seconds,
        session_start_epoch=session_start_epoch,
        now_epoch=now_epoch,
    )
    visibility_cutoff = effective_cutoff
    metric_cutoff = effective_cutoff
    count_cutoff = effective_cutoff
    log_cutoff = effective_cutoff
    fetch_cutoff = effective_cutoff
    init_db(db_path)
    conn = connect_sqlite(db_path)
    try:
        ensure_traceroutes_ts_epoch(conn)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
                t.direction,
                t.route_raw,
                t.ts_epoch
            FROM traceroutes AS t
            WHERE
                t.self_id = ?
                AND t.direction IN ('out', 'back')
                AND t.ts_epoch IS NOT NULL
                AND t.ts_epoch >= ?
            ORDER BY t.ts_epoch DESC, t.id DESC
            """,
            (self_id, fetch_cutoff),
        )
        fetched = cur.fetchall()

        by_node: Dict[str, Dict[str, object]] = {}
        for direction, route_raw, ts_epoch in fetched:
            neighbor_id, snr_value = _extract_direct_neighbor_sample_from_route(self_id, route_raw, direction=direction)
            if not neighbor_id or neighbor_id == self_id:
                continue

            rec = by_node.setdefault(
                neighbor_id,
                {
                    "node_id": neighbor_id,
                    "name": _format_tune_name(neighbor_id, None, None),
                    "hears_me": "-",
                    "hears_me_prev": None,
                    "hears_me_epoch": None,
                    "hears_me_history": [],
                    "hears_me_log_history": [],
                    "hears_me_noise": "-",
                    "hears_me_noise_prev": None,
                    "i_hear_him": "-",
                    "i_hear_him_prev": None,
                    "i_hear_him_epoch": None,
                    "i_hear_him_history": [],
                    "i_hear_him_trace_history": [],
                    "i_hear_him_trace_samples": [],
                    "i_hear_him_log_history": [],
                    "i_hear_him_trace_log_samples": [],
                    "i_hear_him_noise": "-",
                    "i_hear_him_noise_prev": None,
                    "i_hear_him_noise_epoch": None,
                    "i_hear_him_noise_history": [],
                    "tx_sample_count": 0,
                    "rx_trace_sample_count": 0,
                    "rx_sample_count": 0,
                    "last_seen_epoch": int(ts_epoch) if isinstance(ts_epoch, (int, float)) else 0,
                },
            )

            event_epoch = int(ts_epoch) if isinstance(ts_epoch, (int, float)) else 0
            if isinstance(ts_epoch, (int, float)):
                rec["last_seen_epoch"] = max(int(rec.get("last_seen_epoch", 0)), event_epoch)

            if direction == "out":
                if event_epoch >= count_cutoff and _as_float(snr_value) is not None:
                    rec["tx_sample_count"] = int(rec.get("tx_sample_count", 0) or 0) + 1
                if event_epoch >= log_cutoff:
                    _append_metric_history(rec, "hears_me_log_history", snr_value)
                if event_epoch >= metric_cutoff:
                    set_current = _as_float(rec.get("hears_me")) is None
                    _capture_latest_previous_metric(rec, "hears_me", "hears_me_prev", snr_value)
                    if set_current and _as_float(rec.get("hears_me")) is not None and isinstance(ts_epoch, (int, float)):
                        rec["hears_me_epoch"] = int(ts_epoch)
                    _append_metric_history(rec, "hears_me_history", snr_value)
            if direction == "back":
                if event_epoch >= count_cutoff and _as_float(snr_value) is not None:
                    rec["rx_trace_sample_count"] = int(rec.get("rx_trace_sample_count", 0) or 0) + 1
                if event_epoch >= log_cutoff:
                    _append_metric_sample(rec, "i_hear_him_trace_log_samples", event_epoch, snr_value)
                if event_epoch >= metric_cutoff:
                    set_current = _as_float(rec.get("i_hear_him")) is None
                    _capture_latest_previous_metric(rec, "i_hear_him", "i_hear_him_prev", snr_value)
                    if set_current and _as_float(rec.get("i_hear_him")) is not None and isinstance(ts_epoch, (int, float)):
                        rec["i_hear_him_epoch"] = int(ts_epoch)
                    _append_metric_history(rec, "i_hear_him_trace_history", snr_value)
                    _append_metric_sample(rec, "i_hear_him_trace_samples", event_epoch, snr_value)

        if by_node:
            placeholders = ", ".join("?" for _ in by_node)
            cur.execute(
                f"SELECT id, long_name, short_name FROM nodes WHERE id IN ({placeholders})",
                tuple(by_node.keys()),
            )
            for node_id, long_name, short_name in cur.fetchall():
                rec = by_node.get(node_id)
                if rec is None:
                    continue
                rec["name"] = _format_tune_name(node_id, long_name, short_name)

            latest_rx = _load_recent_packet_rx_by_node(
                conn,
                list(by_node.keys()),
                metric_cutoff_epoch=metric_cutoff,
                count_cutoff_epoch=count_cutoff,
                log_cutoff_epoch=log_cutoff,
            )
            for node_id, metric in latest_rx.items():
                rec = by_node.get(node_id)
                if rec is None:
                    continue
                if _as_float(metric.get("noise_floor")) is not None:
                    previous_noise = rec.get("i_hear_him_noise")
                    previous_noise_prev = rec.get("i_hear_him_noise_prev")
                    rec["i_hear_him_noise"] = metric["noise_floor"]
                    if isinstance(metric.get("ts_epoch"), (int, float)):
                        rec["i_hear_him_noise_epoch"] = int(metric["ts_epoch"])
                    if _as_float(metric.get("noise_floor_prev")) is not None:
                        rec["i_hear_him_noise_prev"] = metric.get("noise_floor_prev")
                    elif _as_float(previous_noise) is not None:
                        rec["i_hear_him_noise_prev"] = previous_noise
                    else:
                        rec["i_hear_him_noise_prev"] = previous_noise_prev
                    rec["i_hear_him_noise_history"] = list(metric.get("noise_floor_history") or [])
                if isinstance(metric.get("ts_epoch"), (int, float)):
                    rec["last_seen_epoch"] = max(int(rec.get("last_seen_epoch", 0)), int(metric["ts_epoch"]))
            for rec in by_node.values():
                metric = latest_rx.get(str(rec.get("node_id") or ""), {}) or {}
                rec["tx_sample_count"] = len([value for value in (rec.get("hears_me_history") or []) if _as_float(value) is not None])
                merged_rx_samples = _merge_metric_samples(
                    metric.get("rx_snr_samples"),
                    rec.get("i_hear_him_trace_samples"),
                )
                merged_rx_log_samples = _merge_metric_samples(
                    metric.get("rx_snr_log_samples"),
                    rec.get("i_hear_him_trace_log_samples"),
                )
                rec["rx_sample_count"] = len(merged_rx_samples)
                rec["i_hear_him_history"] = [value for _, value in merged_rx_samples]
                rec["i_hear_him_log_history"] = [value for _, value in merged_rx_log_samples]
                if merged_rx_samples:
                    rec["i_hear_him"] = merged_rx_samples[0][1]
                    rec["i_hear_him_epoch"] = merged_rx_samples[0][0]
                    rec["i_hear_him_prev"] = merged_rx_samples[1][1] if len(merged_rx_samples) > 1 else None
                else:
                    rec["i_hear_him"] = "-"
                    rec["i_hear_him_prev"] = None
                rec["tx_variability"] = _compute_variability_stats(rec.get("hears_me_history"), kind="snr")
                rec["rx_variability"] = _compute_variability_stats(rec.get("i_hear_him_history"), kind="snr")
                rec["nf_variability"] = _compute_variability_stats(rec.get("i_hear_him_noise_history"), kind="nf")
    finally:
        conn.close()

    rows = []
    for row in by_node.values():
        last_seen_epoch = _as_int(row.get("last_seen_epoch"))
        if last_seen_epoch is None or int(last_seen_epoch or 0) < visibility_cutoff:
            continue
        has_numeric_direct_metric = (
            _as_float(row.get("hears_me")) is not None
            or _as_float(row.get("i_hear_him")) is not None
            or int(_as_int(row.get("tx_sample_count")) or 0) > 0
            or int(_as_int(row.get("rx_sample_count")) or 0) > 0
        )
        if not has_numeric_direct_metric:
            continue
        rows.append(row)
    rows.sort(
        key=lambda row: (
            str(row.get("name", "")).lower(),
            str(row.get("node_id", "")).lower(),
        )
    )
    return rows


def build_tune_screen(
    rows: List[Dict[str, object]],
    *,
    self_id: str,
    refreshed_at: Optional[str] = None,
    refresh_seconds: int = 30,
    window_seconds: Optional[int] = None,
    poll_hours: int = 24,
    status: Optional[str] = None,
    session_start_epoch: Optional[int] = None,
    now_epoch: Optional[int] = None,
    highlight_previous: Optional[Dict[str, Dict[str, object]]] = None,
    terminal_size: Optional[object] = None,
    trace_requests: object = 0,
    trace_success: object = 0,
    measurement_total: object = 0,
    active_port: Optional[str] = None,
    last_trace_error: Optional[str] = None,
) -> str:
    size = terminal_size or shutil.get_terminal_size((120, 30))
    if hasattr(size, "columns") and hasattr(size, "lines"):
        columns = int(size.columns)
        rows_count = int(size.lines)
    else:
        columns = int(size[0])
        rows_count = int(size[1])
    refreshed = refreshed_at or ts_now()
    display_now_epoch = int(now_epoch if now_epoch is not None else time.time())
    start_epoch = _as_int(session_start_epoch)
    elapsed_display = _format_tune_elapsed(display_now_epoch - start_epoch) if start_epoch is not None and start_epoch > 0 else "-"
    window_label = _format_tune_window_label(window_seconds)
    start_display = _format_tune_full_epoch(start_epoch)
    refreshed_display = _format_tune_full_datetime(refreshed)
    age_window_seconds = _as_int(window_seconds)
    if age_window_seconds is None or age_window_seconds <= 0:
        if start_epoch is not None and start_epoch > 0:
            age_window_seconds = max(1, display_now_epoch - start_epoch)
        else:
            age_window_seconds = 3600
    trace_request_count = max(0, int(_as_int(trace_requests) or 0))
    trace_success_count = max(0, int(_as_int(trace_success) or 0))
    measurement_count = max(0, int(_as_int(measurement_total) or 0))
    response_pct = int(round((trace_success_count * 100.0) / float(trace_request_count))) if trace_request_count > 0 else 0
    active_port_display = _port_display(active_port)
    header_lines = [
        (
            f"meshLogger, self node: {self_id or '(определяется...)'}, "
            f"окно {window_label}, опрашиваются ноды видимые последние {_format_ru_hours(poll_hours)}."
        ),
        f"старт:\t\t{start_display}",
        f"обновлено:\t{refreshed_display}",
        f"прошло\t\t{elapsed_display} | окно {window_label} | обновление {refresh_seconds}с",
        f"прямых узлов: {len(rows)} | запросов traceroute {trace_request_count} | принятых ответов {trace_success_count}, {response_pct}%",
        f"порт:\t\t{active_port_display}",
    ]
    if last_trace_error:
        header_lines.append(f"последняя ошибка traceroute:\t{last_trace_error}")
    if status:
        header_lines.append(status)
    header_lines.append("")

    if not rows:
        waiting_lines = [
            "Ожидание первых данных...",
            "",
            "Сейчас происходит:",
            "обновляется список активных нод;",
            "выполняются traceroute по очереди;",
        ]
        if trace_success_count > 0:
            waiting_lines.append("ответы уже получены, ожидаются первые прямые Tx/Rx-измерения.")
        else:
            waiting_lines.append("пока еще не получены ответы traceroute.")
        footer_lines = [
            "",
            "Таблица появится автоматически после первого прямого Tx/Rx-измерения.",
            "",
            "Ctrl+C для выхода",
        ]
        fitted = _fit_tune_screen_sections(header_lines, waiting_lines, footer_lines, columns=columns, rows=rows_count)
        return "\n".join(fitted)

    table_rows: List[List[object]] = []
    for idx, row in enumerate(rows, 1):
        last_seen_epoch = _as_int(row.get("last_seen_epoch"))
        age_seconds = max(0, display_now_epoch - last_seen_epoch) if last_seen_epoch is not None and last_seen_epoch > 0 else None
        node_id = str(row.get("node_id") or "")
        prev_snapshot = highlight_previous.get(node_id, {}) if isinstance(highlight_previous, dict) else {}
        windows = _collect_tune_row_windows(row)
        tx_window = windows["tx"]
        rx_window = windows["rx"]
        tx_has_history = int(_as_int(tx_window.get("count")) or 0) > 1
        rx_has_history = int(_as_int(rx_window.get("count")) or 0) > 1

        table_rows.append(
            [
                _colorize_tune_age_text(idx, age_seconds=age_seconds, window_seconds=age_window_seconds),
                _colorize_tune_age_text(_format_tune_last_epoch(row.get("last_seen_epoch")), age_seconds=age_seconds, window_seconds=age_window_seconds),
                _colorize_tune_age_text(node_id or "-", age_seconds=age_seconds, window_seconds=age_window_seconds),
                _colorize_tune_age_text(row.get("name", "-"), age_seconds=age_seconds, window_seconds=age_window_seconds),
                _format_count_number(row.get("tx_sample_count", 0)),
                _colorize_metric_value_change(tx_window.get("current"), prev_snapshot.get("tx_current"), kind="snr", residual_active=tx_has_history),
                _colorize_metric_spread_change(_tune_window_summary_value(tx_window, "spread"), prev_snapshot.get("tx_spread"), kind="snr", residual_active=tx_has_history),
                _colorize_metric_value_change(_tune_window_summary_value(tx_window, "min"), prev_snapshot.get("tx_min"), kind="snr", residual_active=tx_has_history),
                _colorize_metric_value_change(_tune_window_summary_value(tx_window, "avg"), prev_snapshot.get("tx_avg"), kind="snr", residual_active=tx_has_history),
                _colorize_metric_value_change(_tune_window_summary_value(tx_window, "max"), prev_snapshot.get("tx_max"), kind="snr", residual_active=tx_has_history),
                _format_count_number(row.get("rx_sample_count", 0)),
                _colorize_metric_value_change(rx_window.get("current"), prev_snapshot.get("rx_current"), kind="snr", residual_active=rx_has_history),
                _colorize_metric_spread_change(_tune_window_summary_value(rx_window, "spread"), prev_snapshot.get("rx_spread"), kind="snr", residual_active=rx_has_history),
                _colorize_metric_value_change(_tune_window_summary_value(rx_window, "min"), prev_snapshot.get("rx_min"), kind="snr", residual_active=rx_has_history),
                _colorize_metric_value_change(_tune_window_summary_value(rx_window, "avg"), prev_snapshot.get("rx_avg"), kind="snr", residual_active=rx_has_history),
                _colorize_metric_value_change(_tune_window_summary_value(rx_window, "max"), prev_snapshot.get("rx_max"), kind="snr", residual_active=rx_has_history),
                _build_metric_color_log(row.get("hears_me_log_history", row.get("hears_me_history")), kind="snr", width=20),
                _build_metric_color_log(row.get("i_hear_him_log_history", row.get("i_hear_him_history")), kind="snr", width=20),
            ]
        )
    if not table_rows:
        table_rows.append(
            [
                "-",
                "-",
                "-",
                "No direct nodes in the selected tune window",
                "-",
                "-",
                "-",
                "0",
                "-",
                "-",
                "-",
                "-",
                "-",
                "0",
                "-",
                "-",
                "-",
                "-",
            ]
        )

    table_lines = format_table(
        [
            "#",
            "Last",
            "ID",
            "longName[shortName]",
            "TxCnt",
            "Tx SNR",
            "Tx dSNR",
            "Tx Min",
            "Tx Avg",
            "Tx Max",
            "RxCnt",
            "Rx SNR",
            "Rx dSNR",
            "Rx Min",
            "Rx Avg",
            "Rx Max",
            "Tx Log",
            "Rx Log",
        ],
        table_rows,
    )
    footer_lines = [
        "",
        "Last:\tвремя последнего полученного значения.",
        "TxCnt:\tсчетчик значений уровня приема dBm (как слышат нас).",
        "Tx SNR/dSNR/Min/Avg/Max:\tтекущее, разница max-min, минимум, среднее и максимум Tx SNR в выбранном tune-окне.",
        "RxCnt:\tсчетчик значений уровня приема dBm (как слышим мы).",
        "Rx SNR/dSNR/Min/Avg/Max:\tтекущее, разница max-min, минимум, среднее и максимум Rx SNR в выбранном tune-окне.",
        "Tx Log:\tпоследние 20 значений Tx SNR в выбранном tune-окне, справа новое.",
        "Rx Log:\tпоследние 20 значений Rx SNR в выбранном tune-окне, справа новое.",
        _colorize_footer_scale_line(
            "SNR цвет",
            "-20",
            "+10",
            kind="snr",
            metric_type="value",
            low_value=-20.0,
            high_value=10.0,
            direction_text="от красного к зеленому",
        ),
        _colorize_footer_scale_line(
            "dSNR цвет",
            "0",
            "30",
            kind="snr",
            metric_type="spread",
            low_value=0.0,
            high_value=30.0,
            direction_text="от зеленого к красному",
        ),
        "",
        "Ctrl+C для выхода",
    ]

    fitted = _fit_tune_screen_sections(header_lines, table_lines, footer_lines, columns=columns, rows=rows_count)
    return "\n".join(fitted)


def render_tune_screen(screen: str) -> None:
    if _console_ansi_enabled():
        sys.stdout.write("\x1b[?25l\x1b[H\x1b[2J")
        sys.stdout.write(screen)
    else:
        if not _clear_console_plain():
            sys.stdout.write("\n" * 80)
        sys.stdout.write(clean_ansi(screen))
    if not screen.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()


def leave_tune_screen() -> None:
    if _console_ansi_enabled():
        sys.stdout.write("\x1b[?25h")
        sys.stdout.flush()


def start_tune_thread(state: Dict[str, object]) -> threading.Thread:
    def _worker() -> None:
        cached_rows: List[Dict[str, object]] = []
        cached_metric_snapshot: Dict[str, Dict[str, object]] = {}
        cached_highlight_previous: Dict[str, Dict[str, object]] = {}
        cached_self_id = ""
        cached_refresh_seconds = 30
        cached_window_seconds: Optional[int] = None
        cached_session_start_epoch = 0
        cached_trace_success = -1
        cached_measurement_total = -1
        cached_refreshed_at = ts_now()
        cached_error: Optional[str] = None
        last_db_load_at = 0.0
        last_screen = ""

        while True:
            if STOP:
                return

            self_id = str(state.get("self_id") or "")
            status = str(state.get("status") or "")
            refresh_seconds = int(state.get("refresh_seconds", 30) or 30)
            window_seconds = _as_int(state.get("window_seconds"))
            session_start_epoch = int(state.get("session_start_epoch", 0) or 0)
            trace_success = int(_as_int(state.get("trace_success")) or 0)
            measurement_total = int(_as_int(state.get("measurement_total")) or 0)
            now = time.time()

            should_reload = (
                (now - last_db_load_at) >= max(1, refresh_seconds)
                or self_id != cached_self_id
                or refresh_seconds != cached_refresh_seconds
                or window_seconds != cached_window_seconds
                or session_start_epoch != cached_session_start_epoch
                or trace_success != cached_trace_success
                or measurement_total != cached_measurement_total
            )

            if should_reload:
                try:
                    previous_self_id = cached_self_id
                    previous_window_seconds = cached_window_seconds
                    previous_session_start_epoch = cached_session_start_epoch
                    previous_snapshot = cached_metric_snapshot
                    cached_rows = load_tune_direct_nodes(
                        str(state["db_path"]),
                        self_id,
                        window_seconds=window_seconds,
                        session_start_epoch=session_start_epoch,
                    )
                    current_snapshot = _build_tune_metric_snapshot(cached_rows)
                    if (
                        self_id != previous_self_id
                        or window_seconds != previous_window_seconds
                        or session_start_epoch != previous_session_start_epoch
                    ):
                        cached_highlight_previous = {}
                    elif current_snapshot != previous_snapshot:
                        cached_highlight_previous = previous_snapshot
                    cached_metric_snapshot = current_snapshot
                    cached_refreshed_at = ts_now()
                    cached_error = None
                except Exception as ex:
                    cached_rows = []
                    cached_metric_snapshot = {}
                    cached_highlight_previous = {}
                    cached_refreshed_at = ts_now()
                    cached_error = f"DB error: {ex}"

                cached_self_id = self_id
                cached_refresh_seconds = refresh_seconds
                cached_window_seconds = window_seconds
                cached_session_start_epoch = session_start_epoch
                cached_trace_success = trace_success
                cached_measurement_total = measurement_total
                last_db_load_at = now

            screen = build_tune_screen(
                cached_rows,
                self_id=self_id,
                refreshed_at=cached_refreshed_at,
                refresh_seconds=refresh_seconds,
                window_seconds=window_seconds,
                poll_hours=int(_as_int(state.get("poll_hours")) or 24),
                status=(cached_error or status or None),
                session_start_epoch=session_start_epoch,
                now_epoch=int(now),
                highlight_previous=cached_highlight_previous,
                trace_requests=state.get("trace_requests", 0),
                trace_success=state.get("trace_success", 0),
                measurement_total=state.get("measurement_total", 0),
                active_port=str(state.get("active_port") or ""),
                last_trace_error=str(state.get("last_trace_error") or ""),
            )

            if screen != last_screen:
                render_tune_screen(screen)
                last_screen = screen

            time.sleep(0.2)

    th = threading.Thread(target=_worker, daemon=True)
    th.start()
    return th


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
        Default: auto-detect
        RU: Серийный порт устройства Meshtastic.
        RU: По умолчанию: автоопределение (Windows: COM3 и т.п. можно указать явно)

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

  --tune
        Static dashboard mode. Suppresses the normal traceroute log and redraws
        a fixed table every 30 seconds using only direct traceroutes from SQLite.
        Rows and metrics use the selected tune window. If no tune window is set,
        the whole current tune session is used.
        RU: Режим статичной панели. Отключает обычный лог трассировок и
        перерисовывает фиксированную таблицу каждые 30 секунд только по прямым
        трассам из SQLite. Узлы и метрики считаются по выбранному tune-окну.
        Если окно не задано, используется весь текущий tune-сеанс.

  --tune-window-minutes MIN
        Optional tune window in minutes.
        If omitted, tune uses the whole current session from its start.
        RU: Необязательное tune-окно в минутах.
        RU: Если не задано, tune использует весь текущий сеанс с его старта.

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
    port: Optional[str],
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
    out(f"Device port:           {_port_display(port)} (default: {defaults['port']})")
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
    global STOP, TUNE_MODE
    signal.signal(signal.SIGINT, _sigint_handler)
    _install_console_handlers()

    DEFAULTS = {
        "port": "auto",
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
    ap.add_argument("--port", default=None, help=f"serial port (default: {DEFAULTS['port']}, Windows: COM3). RU: серийный порт (по умолчанию: {DEFAULTS['port']}, Windows: COM3).")
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
    ap.add_argument("--tune", action="store_true", help="static direct-neighbor dashboard from SQLite. RU: статичная таблица прямых соседей из SQLite.")
    ap.add_argument("--tune-window-minutes", dest="tune_window_minutes", type=int, default=None, help="optional tune window in minutes; if omitted, tune uses the whole session. RU: необязательное tune-окно в минутах; если не задано, используется весь сеанс.")
    ap.add_argument("--version", action="store_true", help="print version and exit. RU: вывести версию и выйти.")

    args = ap.parse_args()

    if args.help:
        out(HELP_TEXT.rstrip("\n"))
        return 0
    if args.version:
        out(f"meshLogger.py v{VERSION}")
        return 0
    if args.db_schema:
        init_db(args.db)
        conn = connect_sqlite(args.db)
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

    if args.minhops is not None and args.minhops < 0:
        out(f"{ts_now()} ERROR: --minhops must be >= 0")
        return 2
    if args.maxhops is not None and args.maxhops < 0:
        out(f"{ts_now()} ERROR: --maxhops must be >= 0")
        return 2
    if args.minhops is not None and args.maxhops is not None and args.minhops > args.maxhops:
        out(f"{ts_now()} ERROR: --minhops cannot be greater than --maxhops")
        return 2
    if args.tune_window_minutes is not None and args.tune_window_minutes <= 0:
        out(f"{ts_now()} ERROR: --tune-window-minutes must be > 0")
        return 2

    TUNE_MODE = bool(args.tune)
    tune_state: Optional[Dict[str, object]] = None

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

    try:
        if args.tune:
            tune_state = {
                "db_path": args.db,
                "self_id": "",
                "refresh_seconds": 30,
                "window_seconds": (int(args.tune_window_minutes) * 60) if args.tune_window_minutes is not None else None,
                "poll_hours": int(args.hours),
                "session_start_epoch": int(time.time()),
                "status": "Initializing...",
                "tx_sample_counts": {},
                "rx_sample_counts": {},
                "trace_requests": 0,
                "trace_success": 0,
                "measurement_total": 0,
                "active_port": str(args.port or "").strip(),
                "last_trace_error": "",
            }
            start_tune_thread(tune_state)

        migrated = migrate_nodeDb_txt_once(args.db, "nodeDb.txt")
        if migrated:
            out(f"{ts_now()} migration: nodeDb.txt -> {args.db} done. RU: миграция nodeDb.txt -> {args.db} выполнена.")

        start_listen_thread(args.port, args.timeout, args.db)

        out(f"meshLogger.py v{VERSION}")

        cycle = 0
        cycle_members_signature: Tuple[str, ...] = ()
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
        tune_tx_sample_counts: Dict[str, int] = {}
        tune_rx_sample_counts: Dict[str, int] = {}
        poll_order: Dict[str, int] = {}
        poll_order_seq = 0

        def pct_str() -> str:
            if total_sent <= 0:
                return "0%"
            pct = int(round((total_ok * 100.0) / total_sent))
            return f"{pct}%"

        def refresh_info(force: bool = False) -> List[NodeRec]:
            nonlocal last_info_refresh, last_db_refresh, nodes, self_id, self_long, self_short, banner_printed, db_snapshot, tune_tx_sample_counts, tune_rx_sample_counts, poll_order, poll_order_seq

            if tune_state is not None:
                tune_state["status"] = "Обновление списка нод..."
                tune_state["active_port"] = str(ACTIVE_PORT_HINT or args.port or "").strip()

            now = time.time()
            if STOP:
                raise KeyboardInterrupt

            if (not force) and (now - last_info_refresh) < 3600 and nodes and self_id:
                tune_session_start_epoch = int(tune_state.get("session_start_epoch", 0) or 0) if tune_state is not None else 0
                tune_window_seconds = _as_int(tune_state.get("window_seconds")) if tune_state is not None else None
                active0 = load_active_nodes(nodes, args.hours, self_id)
                active0 = filter_ids(active0, want_ids)
                active0 = filter_hops(active0, args.minhops, args.maxhops)
                direct_rows0 = (
                    load_tune_direct_nodes(
                        args.db,
                        self_id,
                        window_seconds=tune_window_seconds,
                        session_start_epoch=tune_session_start_epoch,
                    )
                    if args.tune
                    else []
                )
                direct_ids0 = {str(row.get("node_id")) for row in direct_rows0 if row.get("node_id")}
                transit_ids0 = _load_recent_transit_node_ids(
                    args.db,
                    self_id,
                    window_seconds=tune_window_seconds if args.tune else args.hours * 3600,
                    session_start_epoch=tune_session_start_epoch if args.tune else None,
                )
                active0 = _schedule_active_nodes(
                    active0,
                    tune_mode=bool(args.tune),
                    direct_ids=direct_ids0,
                    transit_ids=transit_ids0,
                    sample_counts=tune_tx_sample_counts,
                    poll_order=poll_order,
                )
                if tune_state is not None:
                    tune_state["status"] = f"Опрашиваются активные ноды: {len(active0)}"
                    tune_state["active_port"] = str(ACTIVE_PORT_HINT or args.port or "").strip()
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
                    if tune_state is not None:
                        tune_state["status"] = f"DB update failed: {ex}"
                    out(f"{ts_now()} ERROR: db update failed: {ex}")
            if not db_snapshot:
                db_snapshot = _load_nodes_snapshot_from_db(args.db)

            mesh_info_text = fetch_info_raw(args.port, args.timeout) or ""

            nodes = {}
            parse_errors: List[str] = []
            if mesh_info_text:
                try:
                    nodes = parse_nodes_block(mesh_info_text)
                except Exception as ex:
                    parse_errors.append(str(ex))

            if not nodes:
                nodes_list = fetch_nodes_json(args.port, args.timeout)
                if nodes_list:
                    nodes = _nodes_list_to_dict(nodes_list)

            if not nodes:
                details = "; ".join(parse_errors) if parse_errors else "no parsable nodes returned"
                raise RuntimeError(f"cannot load nodes from Meshtastic ({details})")

            try:
                self_id = detect_self_id(mesh_info_text, nodes)
            except Exception as ex:
                prev_self_id = str(self_id or "").strip().lower()
                if prev_self_id and prev_self_id in nodes:
                    self_id = prev_self_id
                else:
                    raise RuntimeError(str(ex)) from ex
            self_long, self_short = node_names(nodes, self_id)
            if tune_state is not None and str(tune_state.get("self_id") or "") != self_id:
                prev_tune_self_id = str(tune_state.get("self_id") or "")
                tune_tx_sample_counts = {}
                tune_rx_sample_counts = {}
                poll_order = {}
                poll_order_seq = 0
                if prev_tune_self_id:
                    tune_state["session_start_epoch"] = int(time.time())
                    tune_state["trace_requests"] = 0
                    tune_state["trace_success"] = 0
                tune_state["tx_sample_counts"] = tune_tx_sample_counts
                tune_state["rx_sample_counts"] = tune_rx_sample_counts
                tune_state["measurement_total"] = 0
            if tune_state is not None:
                tune_state["self_id"] = self_id
                tune_state["active_port"] = str(ACTIVE_PORT_HINT or args.port or "").strip()

            active = load_active_nodes(nodes, args.hours, self_id)
            active = filter_ids(active, want_ids)
            active = filter_hops(active, args.minhops, args.maxhops)
            tune_session_start_epoch = int(tune_state.get("session_start_epoch", 0) or 0) if tune_state is not None else 0
            tune_window_seconds = _as_int(tune_state.get("window_seconds")) if tune_state is not None else None
            direct_rows = (
                load_tune_direct_nodes(
                    args.db,
                    self_id,
                    window_seconds=tune_window_seconds,
                    session_start_epoch=tune_session_start_epoch,
                )
                if args.tune
                else []
            )
            direct_ids = {str(row.get("node_id")) for row in direct_rows if row.get("node_id")}
            transit_ids = _load_recent_transit_node_ids(
                args.db,
                self_id,
                window_seconds=tune_window_seconds if args.tune else args.hours * 3600,
                session_start_epoch=tune_session_start_epoch if args.tune else None,
            )
            active = _schedule_active_nodes(
                active,
                tune_mode=bool(args.tune),
                direct_ids=direct_ids,
                transit_ids=transit_ids,
                sample_counts=tune_tx_sample_counts,
                poll_order=poll_order,
            )

            # THESE TWO LINES MUST STAY
            # RU: ЭТИ ДВЕ СТРОКИ ДОЛЖНЫ ОСТАТЬСЯ
            out(f"{ts_now()} meshtastic --info updated from {self_id} {self_long}[{self_short}]")
            out(
                f"{ts_now()} a total of {len(nodes)} nodes were found, of which {len(active)} were active within the last {args.hours} hours. "
                f"Oh, they're going to get it now!"
            )

            _print_nodes_from_info(nodes, db_snapshot)

            if not banner_printed:
                mode = "Tune dashboard" if args.tune else ("Continuous loop" if loop_forever else "One pass")
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

            if tune_state is not None:
                tune_state["status"] = f"Опрашиваются активные ноды: {len(active)}"
                tune_state["active_port"] = str(ACTIVE_PORT_HINT or args.port or "").strip()

            if not args.quiet:
                out(line_bar("[NODE SELECTION] / [ОТБОР УЗЛОВ]"))
                for i, n in enumerate(active, 1):
                    hops = "?" if n.hops_away is None else str(n.hops_away)
                    # N.\t!id\t<HO>h\tLong[Short]
                    # RU: N.\t!id\t<HO>h\tДлинное[Короткое]
                    out(f"{i}.\t{n.node_id}\t{hops}h\t{n.long}[{n.short}]")

            return active

        while True:
            try:
                active = refresh_info(force=True)
                break
            except KeyboardInterrupt:
                out("Interrupted by user (Ctrl+C). Exiting cleanly...", force=True)
                return 0
            except Exception as ex:
                retryable = _is_retryable_connection_error(ex)
                status_text = f"Error: {ex}" if not retryable else _retry_status_message(ex, args.port)
                if tune_state is not None:
                    tune_state["status"] = status_text
                    render_tune_screen(
                        build_tune_screen(
                            [],
                            self_id=str(tune_state.get("self_id") or ""),
                            refreshed_at=ts_now(),
                            refresh_seconds=int(tune_state.get("refresh_seconds", 30)),
                            window_seconds=_as_int(tune_state.get("window_seconds")),
                            poll_hours=int(_as_int(tune_state.get("poll_hours")) or args.hours),
                            status=str(tune_state["status"]),
                            session_start_epoch=int(tune_state.get("session_start_epoch", 0) or 0),
                            active_port=str(tune_state.get("active_port") or ""),
                            last_trace_error=str(tune_state.get("last_trace_error") or ""),
                        )
                    )
                if not args.tune or not retryable:
                    out(f"{ts_now()} ERROR: {ex}", force=True)
                if not retryable:
                    if args.tune:
                        leave_tune_screen()
                        out(f"FATAL tune startup error: {ex}", force=True)
                    return 2
                if not _wait_retry_delay(5.0):
                    out("Interrupted by user (Ctrl+C). Exiting cleanly...", force=True)
                    return 0

        while True:
            if STOP:
                out("Interrupted by user (Ctrl+C). Exiting cleanly...", force=True)
                return 0

            try:
                active = refresh_info(force=False)
            except KeyboardInterrupt:
                out("Interrupted by user (Ctrl+C). Exiting cleanly...", force=True)
                return 0
            except Exception as ex:
                retryable = _is_retryable_connection_error(ex)
                if tune_state is not None:
                    tune_state["status"] = _retry_status_message(ex, args.port) if retryable else f"Error: {ex}"
                out(f"{ts_now()} ERROR: {ex}")
                for _ in range(20):
                    if STOP:
                        out("Interrupted by user (Ctrl+C). Exiting cleanly...", force=True)
                        return 0
                    time.sleep(0.1)
                continue

            if len(active) == 0:
                if tune_state is not None:
                    tune_state["status"] = "Нет нод для опроса"
                out(f"{ts_now()} No nodes to poll (check --hours/filters or hopsAway availability)")
                if not loop_forever:
                    return 0
                for _ in range(600):
                    if STOP:
                        out("Interrupted by user (Ctrl+C). Exiting cleanly...", force=True)
                        return 0
                    time.sleep(0.1)
                continue

            current_members_signature = _poll_members_signature(active)
            if current_members_signature != cycle_members_signature:
                cycle = 0
                cycle_members_signature = current_members_signature

            cycle += 1
            total_nodes = len(active)

            if tune_state is not None:
                tune_state["status"] = f"Цикл опроса: {cycle}, всего нод в очереди {total_nodes}"

            if not args.quiet:
                out(line_bar("TRACEROUTE / ТРАССИРОВКА"))

            cycle_retry_error: Optional[str] = None
            for idx, n in enumerate(active, 1):
                if STOP:
                    out("Interrupted by user (Ctrl+C). Exiting cleanly...", force=True)
                    return 0

                if tune_state is not None:
                    tune_state["status"] = f"Цикл опроса: {cycle}, опрашивается {idx} из {total_nodes} - {n.long}[{n.short}]"
                    tune_state["active_port"] = str(ACTIVE_PORT_HINT or args.port or "").strip()

                poll_order_seq += 1
                poll_order[n.node_id] = poll_order_seq
                total_sent += 1
                if tune_state is not None:
                    tune_state["trace_requests"] = total_sent
                    tune_state["trace_success"] = total_ok
                pct_req = pct_str()
                cyc = f"[{cycle}][{idx}/{total_nodes}]"

                req_ts_epoch = time.time()
                req_log_ts = ts_now()
                req_ts_utc = iso_utc_now()

                out(fmt_line(req_log_ts, pct_req, cyc, "-", f"request traceroute to {n.node_id} {n.long}[{n.short}]"))

                try:
                    rc, so, se = _run_meshtastic_cli(
                        _port_cli_args(args.port) + ["--traceroute", n.node_id],
                        timeout=args.timeout,
                    )
                except KeyboardInterrupt:
                    out("Interrupted by user (Ctrl+C). Exiting cleanly...", force=True)
                    return 0

                raw = clean_ansi((so or "") + ("\n" + se if se else ""))
                if detect_device_not_found(raw):
                    cycle_retry_error = _device_lookup_error(args.port)
                    if tune_state is not None:
                        tune_state["status"] = _retry_status_message(cycle_retry_error, args.port)
                        tune_state["last_trace_error"] = cycle_retry_error
                    out(f"{ts_now()} ERROR: {cycle_retry_error}")
                    break
                if detect_multiple_ports(raw):
                    cycle_retry_error = _multiple_ports_error()
                    if tune_state is not None:
                        tune_state["status"] = _retry_status_message(cycle_retry_error, args.port)
                        tune_state["last_trace_error"] = cycle_retry_error
                    out(f"{ts_now()} ERROR: {cycle_retry_error}")
                    break
                if detect_device_busy(raw):
                    cycle_retry_error = _device_busy_error(args.port)
                    if tune_state is not None:
                        tune_state["status"] = _retry_status_message(cycle_retry_error, args.port)
                        tune_state["last_trace_error"] = cycle_retry_error
                    out(f"{ts_now()} ERROR: {cycle_retry_error}")
                    break
                towards, back = parse_routes_from_meshtastic_output(raw)

                if (rc == 124 or "[TIMEOUT]" in raw) and not towards:
                    timeout_error = f"таймаут traceroute {int(args.timeout)}с для {n.long}[{n.short}]"
                    if tune_state is not None:
                        tune_state["last_trace_error"] = timeout_error
                    out(fmt_line(ts_now(), pct_req, cyc, "-", f"{n.long}[{n.short}] traceroute timeout after {int(args.timeout)}s"))
                    for _ in range(int(max(0, args.pause) * 10)):
                        if STOP:
                            out("Interrupted by user (Ctrl+C). Exiting cleanly...", force=True)
                            return 0
                        time.sleep(0.1)
                    continue

                if not towards:
                    if tune_state is not None:
                        if "Route traced" in raw or "Trace route result" in raw:
                            tune_state["last_trace_error"] = f"ответ от {n.long}[{n.short}] получен, но формат маршрута не распознан"
                        else:
                            raw_summary = _summarize_traceroute_output(raw)
                            if raw_summary:
                                tune_state["last_trace_error"] = f"{n.long}[{n.short}]: {raw_summary}"
                            else:
                                tune_state["last_trace_error"] = f"нет ответа от {n.long}[{n.short}]"
                    out(fmt_line(ts_now(), pct_req, cyc, "-", f"{n.long}[{n.short}] is no response..."))
                    for _ in range(int(max(0, args.pause) * 10)):
                        if STOP:
                            out("Interrupted by user (Ctrl+C). Exiting cleanly...", force=True)
                            return 0
                        time.sleep(0.1)
                    continue

                ans_ts_epoch = time.time()
                ans_log_ts = ts_now()
                ans_ts_utc = iso_utc_now()

                edges_out = count_edges(towards)
                edges_back = count_edges(back) if back else 0
                denom = max(1, edges_out + edges_back)
                avg_hop_s = int(round((ans_ts_epoch - req_ts_epoch) / float(denom)))
                hop_field = f"{avg_hop_s}s/h"

                total_ok += 1
                if tune_state is not None:
                    tune_state["trace_success"] = total_ok
                    tune_state["last_trace_error"] = ""
                pct_ans = pct_str()

                pretty_out = route_ids_to_names(towards, nodes)
                out(fmt_line(ans_log_ts, pct_ans, cyc, hop_field, f"> {pretty_out}"))

                if back:
                    pretty_back = route_ids_to_names(back, nodes)
                    out(fmt_line(ans_log_ts, pct_ans, cyc, hop_field, f"< {pretty_back}"))

                insert_traceroute(args.db, req_ts_utc, self_id, n.node_id, "out", towards, pretty_out)
                if back:
                    insert_traceroute(args.db, ans_ts_utc, self_id, n.node_id, "back", back, pretty_back)
                if args.tune:
                    tx_direct_node_id, tx_direct_snr = _extract_direct_neighbor_sample_from_route(self_id, towards, direction="out")
                    rx_direct_node_id, rx_direct_snr = _extract_direct_neighbor_sample_from_route(self_id, back, direction="back")
                    if tx_direct_node_id and _as_float(tx_direct_snr) is not None:
                        tune_tx_sample_counts[tx_direct_node_id] = int(tune_tx_sample_counts.get(tx_direct_node_id, 0) or 0) + 1
                    if rx_direct_node_id and _as_float(rx_direct_snr) is not None:
                        tune_rx_sample_counts[rx_direct_node_id] = int(tune_rx_sample_counts.get(rx_direct_node_id, 0) or 0) + 1
                    if tune_state is not None:
                        tune_state["tx_sample_counts"] = tune_tx_sample_counts
                        tune_state["rx_sample_counts"] = tune_rx_sample_counts
                        tune_state["measurement_total"] = sum(tune_tx_sample_counts.values()) + sum(tune_rx_sample_counts.values())
                for _ in range(int(max(0, args.pause) * 10)):
                    if STOP:
                        out("Interrupted by user (Ctrl+C). Exiting cleanly...", force=True)
                        return 0
                    time.sleep(0.1)

            if cycle_retry_error is not None:
                if not _wait_retry_delay(5.0):
                    out("Interrupted by user (Ctrl+C). Exiting cleanly...", force=True)
                    return 0
                continue

            if not loop_forever:
                return 0
    finally:
        if args.tune:
            leave_tune_screen()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        out("Interrupted by user (Ctrl+C). Exiting cleanly...", force=True)
        sys.exit(0)
    except Exception as ex:
        if TUNE_MODE:
            leave_tune_screen()
        out(f"FATAL unhandled error: {ex}", force=True)
        tb = traceback.format_exc().rstrip()
        if tb:
            out(tb, force=True)
        sys.exit(2)
