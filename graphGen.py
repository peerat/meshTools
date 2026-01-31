#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
graphGen.py — генератор графов Meshtastic:
  - Graphviz DOT/SVG
  - D3.js HTML/JSON (интерактив и normalized stacked area chart)

Версия: 0.8.1
Дата: 2026-01-31

ИСТОРИЯ ИЗМЕНЕНИЙ:
0.8.1 (2026-01-31)
  - Добавлен D3.js HTML/JSON вывод, включая normalized stacked area chart по важности узлов.
  - Переключатель --no-d3 для отключения D3.
  - Graphviz метки переведены на обычный label (не HTML) + charset UTF-8 + шрифт DejaVu Sans.

0.7.9 (2026-01-25)
  - Фильтр окна --datetime теперь берёт временные метки СТРОГО с начала КАЖДОЙ СТРОКИ ТРАССЫ
    внутри файла (НЕ из имени файла и НЕ из mtime/ctime).
  - Толщина рёбер теперь нормализуется ОТНОСИТЕЛЬНО текущей выборки:
      максимум подтверждений => 100% => maxwidthline
      остальные => пропорционально между minwidthline..maxwidthline
    Добавлено: --minwidthline / --maxwidthline (по умолчанию 1..30).
  - PNG отключён, рендерится только SVG.
  - Постобработка SVG: width="8000pt" height="4500pt".

0.7.5 (2026-01-19)
  - Узел Unknown по умолчанию исключён (считаем, что его нет):
      * удаляются все рёбра, смежные с Unknown (!ffffffff)
      * НЕ выполняется "мост" A->B через Unknown
      * Unknown исключён из статистики маршрутизации/транзита
    Флаг --include-unknown возвращает старое поведение.
  - В терминале выводится, сколько рёбер отброшено из-за Unknown.
  - Имя выходных файлов по шаблону: "YYYY-MM-DD HH:MM:SS !<measurer_id>"
  - Автоопределение measurer id по именам файлов; DOT+SVG по умолчанию

ВАЖНЫЕ ПУТИ:
  - папка трасс:     <root>/meshLogger
  - папка вывода:    <root>/graphGen
  - поиск nodeDb:    1) root, 2) папка скрипта, 3) домашняя папка

Ожидаемый шаблон имени файлов трасс в <root>/meshLogger:
  'YYYY-MM-DD !xxxxxxxx*.txt'
"""

__version__ = "0.8.1"

import argparse
import colorsys
import hashlib
import json
import math
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


UNKNOWN_ID = "!ffffffff"

ROLE_COLORS = {
    "CLIENT": "#8cff8c",
    "CLIENT_MUTE": "#ffd966",
    "MUTE": "#ffd966",
    "ROUTER": "#ff6b6b",
    "REPEATER": "#ff6b6b",
    "TRACKER": "#ffb347",
    "SENSOR": "#6ec6ff",
    "GATEWAY": "#c77dff",
    "UNKNOWN": "#e0e0e0",
}

# hop parsing in trace lines
# RU: разбор hop в строках трассировки
NODE_RE = re.compile(r"(![0-9a-fA-F]{8}|Unknown)")
DB_RE = re.compile(r"\((-?\d+(?:\.\d+)?|\?)dB\)")

# measurer-id extraction from filename
# RU: извлечение measurer-id из имени файла
TRACE_NAME_ID_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\s+(![0-9a-fA-F]{8})", re.I)

# timestamp at the start of each trace line (filter ONLY by it)
# RU: временная метка в начале каждой строки трассы (фильтруем ТОЛЬКО по ней)
# Accepted / RU: Принимаем:
#   2026-01-24 16:30:12 ...
#   2026-01-24 16:30 ...
LINE_TS_RE = re.compile(r"^\s*(\d{4}-\d{2}-\d{2})(?:[ T]+(\d{2}:\d{2})(?::(\d{2}))?)?")


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    x = float(n)
    for u in units:
        if x < 1024.0:
            return f"{x:.1f}{u}"
        x /= 1024.0
    return f"{x:.1f}PB"


def sha1_file(path: Path, max_bytes: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha1()
    with path.open("rb") as f:
        h.update(f.read(max_bytes))
    st = path.stat()
    h.update(str(st.st_size).encode())
    h.update(str(int(st.st_mtime)).encode())
    return h.hexdigest()


def which_dot() -> Optional[str]:
    return shutil.which("dot")


def extract_first_json_object(text: str) -> Optional[str]:
    start = text.find("{")
    if start < 0:
        return None
    s = text[start:]
    depth = 0
    end = None
    for i, ch in enumerate(s):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    return s[:end] if end else None


def load_json_fuzzy(path: Path) -> Optional[Any]:
    raw = path.read_text(errors="ignore")
    obj = extract_first_json_object(raw)
    if obj is None:
        return None

    candidates = [
        obj,
        obj.replace('\\"', '"').replace("\\n", "\n").replace("\\t", "\t"),
    ]
    try:
        candidates.append(bytes(obj, "utf-8").decode("unicode_escape"))
    except Exception:
        pass

    for cand in candidates:
        try:
            c = extract_first_json_object(cand) or cand
            return json.loads(c)
        except Exception:
            continue
    return None


def find_latest_file(patterns: List[str], root: Path) -> Optional[Path]:
    cand: List[Path] = []
    for pat in patterns:
        cand += list(root.glob(pat))
    cand = [p for p in cand if p.is_file()]
    if not cand:
        return None
    cand.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return cand[0]


def fixed_paths(root: Path) -> Tuple[Path, Path, List[Path]]:
    """
    root = cwd (где запускаете) ИЛИ папка скрипта (в вашем случае ~/meshTools)
    Используем фиксированный расклад:
      трассы:  <root>/meshLogger
      вывод:   <root>/graphGen
      nodeDb:  порядок поиска: root, папка скрипта, домашняя папка
    """
    cwd = Path.cwd().resolve()
    script_dir = Path(__file__).resolve().parent
    home = Path.home().resolve()

    # In your scenario, run from ~/meshTools and script is there.
    # RU: В вашем сценарии запуск из ~/meshTools и скрипт там же.
    # Use root as cwd to keep current behavior.
    # RU: Берём root как cwd, чтобы сохранить текущее поведение.
    trace_root = root / "meshLogger"
    out_dir = root / "graphGen"
    node_search = [root, script_dir, home]
    return trace_root, out_dir, node_search


def find_trace_files(trace_root: Path) -> List[Path]:
    """
    Единственный ожидаемый шаблон:
      'YYYY-MM-DD !xxxxxxxx*.txt'
    Внутри фиксированной папки: <root>/meshLogger
    """
    files = set()
    for p in trace_root.glob("20??-??-?? !*.txt"):
        if p.is_file():
            files.add(p)
    for p in trace_root.glob("20??-??-?? !*.TXT"):
        if p.is_file():
            files.add(p)
    return sorted(files)


def detect_measurer_id_from_filenames(trace_files: List[Path]) -> Tuple[str, Counter]:
    c = Counter()
    for p in trace_files:
        m = TRACE_NAME_ID_RE.match(p.name)
        if m:
            c[m.group(1).lower()] += 1
    if not c:
        return UNKNOWN_ID, c
    maxv = max(c.values())
    best = sorted([k for k, v in c.items() if v == maxv])[0]
    return best, c


def norm_node(n: str) -> str:
    return UNKNOWN_ID if n == "Unknown" else n


def role_fill(role: str) -> str:
    r = (role or "").upper()
    if not r:
        return ROLE_COLORS["UNKNOWN"]
    if "MUTE" in r:
        return ROLE_COLORS["MUTE"]
    if "CLIENT" in r:
        return ROLE_COLORS["CLIENT"]
    if "ROUTER" in r or "REPEATER" in r:
        return ROLE_COLORS["ROUTER"]
    if "TRACKER" in r:
        return ROLE_COLORS["TRACKER"]
    if "SENSOR" in r:
        return ROLE_COLORS["SENSOR"]
    if "GATEWAY" in r:
        return ROLE_COLORS["GATEWAY"]
    return ROLE_COLORS["UNKNOWN"]


def esc_html(s: str) -> str:
    return (
        (s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def esc_dot_label(s: str) -> str:
    return (s or "").replace("\\", "\\\\").replace('"', '\\"')


def grad_rssi(value_db: Optional[float], vmin: float, vmax: float) -> str:
    if value_db is None:
        return "#9a9a9a"
    if vmin == vmax:
        t = 0.5
    else:
        t = (value_db - vmin) / (vmax - vmin)
        t = max(0.0, min(1.0, t))
    r, g, b = colorsys.hsv_to_rgb((120.0 * t) / 360.0, 0.9, 0.95)
    return "#{:02x}{:02x}{:02x}".format(int(r * 255), int(g * 255), int(b * 255))


def fontsize_from_neighbors(n: int, vmax: int) -> float:
    if vmax <= 0:
        return 12.0
    t = math.log1p(n) / math.log1p(vmax)
    return round(10.0 + 20.0 * t, 1)


def margin_from_neighbors(n: int, vmax: int) -> str:
    if vmax <= 0:
        return "0.35,0.32"
    t = math.log1p(n) / math.log1p(vmax)
    mx = 0.25 + 0.60 * t
    my = 0.22 + 0.58 * t
    return f"{mx:.2f},{my:.2f}"


def fmt_role(role: str) -> str:
    r = (role or "").upper()
    return r if r else "-"


def build_auto_out(measurer_id: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"{ts} {measurer_id}"


def parse_line_ts(line: str) -> Optional[datetime]:
    """
    Парсинг временной метки СТРОГО с начала строки.
    Допустимые форматы:
      YYYY-MM-DD
      YYYY-MM-DD HH:MM
      YYYY-MM-DD HH:MM:SS
    Если только дата — время 00:00:00.
    """
    m = LINE_TS_RE.match(line)
    if not m:
        return None
    d = m.group(1)
    hm = m.group(2)
    ss = m.group(3)
    if hm is None:
        try:
            return datetime.strptime(d, "%Y-%m-%d")
        except Exception:
            return None
    if ss is None:
        try:
            return datetime.strptime(f"{d} {hm}", "%Y-%m-%d %H:%M")
        except Exception:
            return None
    try:
        return datetime.strptime(f"{d} {hm}:{ss}", "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def parse_datetime_point(s: str) -> Tuple[datetime, bool]:
    """
    Парсинг одного конца интервала.
    Возвращает (dt, has_time).
    has_time=True, если строка содержит HH:MM (и опционально :SS).
    """
    s = (s or "").strip()
    # try full formats
    # RU: пробуем полные форматы
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt, True
        except Exception:
            pass
    # date only
    # RU: только дата
    try:
        dt = datetime.strptime(s, "%Y-%m-%d")
        return dt, False
    except Exception:
        raise ValueError("bad --datetime format")


def parse_datetime_window(expr: str) -> Tuple[datetime, datetime]:
    """
    --datetime поддерживает:
      'YYYY-MM-DD'
      'YYYY-MM-DD - YYYY-MM-DD'
      'YYYY-MM-DD HH:MM - YYYY-MM-DD HH:MM'
      'YYYY-MM-DD HH:MM:SS - YYYY-MM-DD HH:MM:SS'
    Разбиваем ТОЛЬКО по ' - ' (пробел-дефис-пробел), чтобы не ломать даты.
    """
    expr = (expr or "").strip()
    if not expr:
        raise ValueError("bad --datetime format")

    if " - " in expr:
        a_str, b_str = expr.split(" - ", 1)
        a_dt, a_has_time = parse_datetime_point(a_str)
        b_dt, b_has_time = parse_datetime_point(b_str)

        # If end is date-only, use end of day.
        # RU: Если конец — только дата, берём конец дня
        if not b_has_time:
            b_dt = b_dt + timedelta(days=1) - timedelta(seconds=1)

        # If start is date-only, it's start of day.
        # RU: Если начало — только дата, это уже начало дня
        if not a_has_time:
            a_dt = a_dt.replace(hour=0, minute=0, second=0)

        if b_dt < a_dt:
            raise ValueError("bad --datetime format")
        return a_dt, b_dt

    # single point:
    # RU: одиночная точка:
    a_dt, a_has_time = parse_datetime_point(expr)
    if a_has_time:
        # exact minute/second => [dt .. dt] (single moment)
        # RU: точная минута/секунда => считаем [dt .. dt] (один момент)
        return a_dt, a_dt
    # date only => full day
    # RU: только дата => весь день
    b_dt = a_dt + timedelta(days=1) - timedelta(seconds=1)
    return a_dt, b_dt


def parse_ts_to_epoch(value: Any) -> Optional[float]:
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
                dt_obj = dt_obj.replace(tzinfo=timezone.utc)
            return dt_obj.timestamp()
        except Exception:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
                try:
                    dt_obj = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                    return dt_obj.timestamp()
                except Exception:
                    continue
    return None


@dataclass
class TraceFileStats:
    path: str
    size_bytes: int
    mtime_iso: str
    sha1sig: str
    lines_total: int
    hops_total: int
    edges_added: int
    edges_unique: int
    rssi_samples: int
    nodes_unique: int
    unknown_mentions: int
    lines_in_window: int


def build_node_meta(node_search: List[Path]) -> Tuple[Dict[str, Dict[str, Any]], Optional[Path], Dict[str, Any]]:
    """
    Надёжный парсер nodeDb:
    - Сначала пробуем формат экспорта Meshtastic JSON: nodes -> {id: {current:{user:{longName, shortName, role}, ...}}}
    - Если нет, поддерживаем nodeDb, где current.raw_nodes_row содержит ключи:
        ключи User / AKA / Role / Channel util.
      (это соответствует вашему nodeDb.txt)
    """
    node_meta: Dict[str, Dict[str, Any]] = {}
    debug = {"nodeDb_nodes_loaded": 0, "nodeDb_nodes_with_longName": 0}

    nodedb_path = None
    for base in node_search:
        cand = base / "nodeDb.txt"
        if cand.is_file():
            nodedb_path = cand
            break
    if nodedb_path is None:
        # fallback search by patterns
        # RU: запасной поиск по шаблонам
        for base in node_search:
            cand = find_latest_file(["nodeDb*.txt", "nodeDb*.TXT"], base)
            if cand:
                nodedb_path = cand
                break

    if nodedb_path:
        ndb = load_json_fuzzy(nodedb_path)
        if isinstance(ndb, dict) and isinstance(ndb.get("nodes"), dict):
            for nid, rec in ndb["nodes"].items():
                if not (isinstance(nid, str) and re.fullmatch(r"![0-9a-fA-F]{8}", nid) and isinstance(rec, dict)):
                    continue

                cur = rec.get("current") if isinstance(rec.get("current"), dict) else {}
                long_name = ""
                short_name = ""
                role = ""
                ch_util = None
                first_seen_epoch: Optional[float] = None

                # Variant A: current.user is a dict
                # RU: Вариант A: current.user — словарь
                user = cur.get("user")
                if isinstance(user, dict):
                    long_name = user.get("longName") or ""
                    short_name = user.get("shortName") or ""
                    if user.get("role"):
                        role = (user.get("role") or "").upper()

                # Variant B: your nodeDb format: current.raw_nodes_row is a dict
                # RU: Вариант B: nodeDb как у вас: current.raw_nodes_row — словарь
                raw = cur.get("raw_nodes_row")
                if isinstance(raw, dict):
                    # 'User' is long name from your export
                    # RU: 'User' — длинное имя из вашего экспорта
                    if not long_name and isinstance(raw.get("User"), str):
                        long_name = raw.get("User") or ""
                    # 'AKA' often contains short tag
                    # RU: 'AKA' часто содержит короткий тег
                    if not short_name and isinstance(raw.get("AKA"), str):
                        short_name = raw.get("AKA") or ""
                    # Role
                    # RU: Роль
                    if not role and isinstance(raw.get("Role"), str):
                        role = (raw.get("Role") or "").upper()
                    # Channel utilization.
                    # RU: Утилизация канала.
                    for k in ("Channel util.", "Channel util", "channel util.", "channel util"):
                        v = raw.get(k)
                        if isinstance(v, (int, float)):
                            ch_util = float(v)
                            break
                        if isinstance(v, str):
                            m = re.search(r"(-?\d+(?:\.\d+)?)", v)
                            if m:
                                try:
                                    ch_util = float(m.group(1))
                                    break
                                except Exception:
                                    pass

                # Variant C: current.aka or current.user (string) as last resort
                # RU: Вариант C: current.aka или current.user (строка) как последний шанс
                aka = cur.get("aka")
                if isinstance(aka, str) and not short_name:
                    short_name = aka
                if isinstance(user, str) and not long_name:
                    long_name = user

                first_seen_epoch = parse_ts_to_epoch(rec.get("first_seen_utc"))

                node_meta[nid] = {
                    "longName": long_name,
                    "shortName": short_name,
                    "role": role,
                    "chUtil": ch_util,
                    "firstSeenEpoch": first_seen_epoch,
                }
                debug["nodeDb_nodes_loaded"] += 1
                if long_name:
                    debug["nodeDb_nodes_with_longName"] += 1

    node_meta.setdefault(
        UNKNOWN_ID,
        {"longName": "Unknown node", "shortName": "ffff", "role": "", "chUtil": None, "firstSeenEpoch": None},
    )
    return node_meta, nodedb_path, debug


def parse_traces_with_stats(
    trace_files: List[Path],
    include_unknown: bool,
    dt_window: Optional[Tuple[datetime, datetime]],
) -> Tuple[
    Dict[Tuple[str, str], int],
    Dict[Tuple[str, str], List[float]],
    Dict[str, int],
    List[Dict[str, Any]],
    Dict[str, Any],
    List[TraceFileStats],
    Dict[str, int],
    List[Path],
]:
    """
    Основной парсер:
      - Читает каждый файл построчно
      - Если задан dt_window: используется метка времени ТОЛЬКО из НАЧАЛА СТРОКИ
        (строки без метки игнорируются при фильтрации окна; в статистику не идут)
      - Строит:
          edge_count (направленные подтверждения)
          edge_rssi   (список RSSI для направленной связи)
          transit_count (узлы-транзиты, без Unknown если он исключён)
      - Удаляет рёбра, смежные с Unknown, когда Unknown исключён
    Также возвращает:
      статистику по файлам
      отладочные счётчики
      selected_files (файлы, где >=1 строка попала в окно, если окно активно)
    """
    edge_count: Dict[Tuple[str, str], int] = defaultdict(int)
    edge_rssi: Dict[Tuple[str, str], List[float]] = defaultdict(list)
    transit_count: Dict[str, int] = defaultdict(int)
    stats_list: List[TraceFileStats] = []

    dropped_unknown_edges = 0
    dropped_unknown_edges_with_rssi = 0

    base_bin_minutes = 5
    bin_seconds = base_bin_minutes * 60
    routing_by_bin: Dict[int, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    neighbors_by_bin: Dict[int, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
    presence_by_bin: Dict[int, set] = defaultdict(set)

    selected_files: List[Path] = []

    w_start: Optional[datetime] = None
    w_end: Optional[datetime] = None
    if dt_window:
        w_start, w_end = dt_window

    for tf in trace_files:
        unique_edges_in_file = set()
        unique_nodes_in_file = set()

        lines = tf.read_text(errors="ignore").splitlines()
        lines_total = len(lines)

        hops_total = 0
        edges_added = 0
        rssi_samples = 0
        unknown_mentions = 0
        lines_in_window = 0

        for line in lines:
            ts_line = parse_line_ts(line)
            bin_key: Optional[int] = None

            # window filter uses timestamp ONLY from line start
            # RU: фильтр окна использует метку времени ТОЛЬКО с начала строки
            if w_start and w_end:
                if ts_line is None:
                    continue
                if ts_line < w_start or ts_line > w_end:
                    continue
                lines_in_window += 1

            if ts_line is not None:
                if ts_line.tzinfo is None:
                    ts_line = ts_line.replace(tzinfo=timezone.utc)
                epoch = int(ts_line.timestamp())
                bin_key = epoch - (epoch % bin_seconds)

            if "-->" not in line:
                continue

            parts = [s.strip() for s in line.split("-->")]
            seq: List[str] = []
            for part in parts:
                m = NODE_RE.search(part)
                if m:
                    token = m.group(1)
                    if token == "Unknown":
                        unknown_mentions += 1
                    seq.append(norm_node(token))

            if len(seq) < 2:
                continue

            hops_total += (len(seq) - 1)
            for n in seq:
                unique_nodes_in_file.add(n)

            if bin_key is not None:
                for n in seq:
                    if include_unknown or n != UNKNOWN_ID:
                        presence_by_bin[bin_key].add(n)

            # transit stats (exclude Unknown unless included)
            # RU: статистика транзита (Unknown исключаем, если явно не включён)
            for n in seq[1:-1]:
                if include_unknown or n != UNKNOWN_ID:
                    transit_count[n] += 1
                    if bin_key is not None:
                        routing_by_bin[bin_key][n] += 1

            # extract RSSI samples
            # RU: извлечение выборок RSSI
            dbs: List[Optional[float]] = []
            for mdb in DB_RE.finditer(line):
                v = mdb.group(1)
                if v != "?":
                    rssi_samples += 1
                    dbs.append(float(v))
                else:
                    dbs.append(None)

            hop = 0
            for a, b in zip(seq, seq[1:]):
                if a == b:
                    hop += 1
                    continue

                # drop edges adjacent to Unknown if excluded
                # RU: удаляем рёбра, смежные с Unknown, если Unknown исключён
                if (not include_unknown) and (a == UNKNOWN_ID or b == UNKNOWN_ID):
                    dropped_unknown_edges += 1
                    if hop < len(dbs) and dbs[hop] is not None:
                        dropped_unknown_edges_with_rssi += 1
                    hop += 1
                    continue

                edge_count[(a, b)] += 1
                edges_added += 1
                unique_edges_in_file.add((a, b))

                if hop < len(dbs) and dbs[hop] is not None:
                    edge_rssi[(a, b)].append(float(dbs[hop]))
                hop += 1

                if bin_key is not None:
                    neighbors_by_bin[bin_key][a].add(b)
                    neighbors_by_bin[bin_key][b].add(a)

        # If window active: include file only if >=1 line in window
        # RU: Если окно активно: выбираем файл только если есть >=1 строка в окне
        if w_start and w_end:
            if lines_in_window > 0:
                selected_files.append(tf)
        else:
            selected_files.append(tf)

        st = tf.stat()
        stats_list.append(
            TraceFileStats(
                path=str(tf),
                size_bytes=int(st.st_size),
                mtime_iso=datetime.fromtimestamp(st.st_mtime).isoformat(sep=" ", timespec="seconds"),
                sha1sig=sha1_file(tf),
                lines_total=lines_total,
                hops_total=hops_total,
                edges_added=edges_added,
                edges_unique=len(unique_edges_in_file),
                rssi_samples=rssi_samples,
                nodes_unique=len(unique_nodes_in_file),
                unknown_mentions=unknown_mentions,
                lines_in_window=lines_in_window,
            )
        )

    debug = {
        "dropped_unknown_edges": dropped_unknown_edges,
        "dropped_unknown_edges_with_rssi": dropped_unknown_edges_with_rssi,
    }
    time_bins = sorted(set(list(routing_by_bin.keys()) + list(neighbors_by_bin.keys()) + list(presence_by_bin.keys())))
    time_series: List[Dict[str, Any]] = []
    for t in time_bins:
        routing_counts = dict(routing_by_bin.get(t, {}))
        neighbors_counts = {n: len(s) for n, s in neighbors_by_bin.get(t, {}).items()}
        uptime_counts = {n: 1 for n in presence_by_bin.get(t, set())}
        time_series.append(
            {
                "t": t,
                "routing": routing_counts,
                "neighbors": neighbors_counts,
                "uptime": uptime_counts,
            }
        )
    time_meta = {
        "baseBinMinutes": base_bin_minutes,
        "timeRangeStart": time_bins[0] if time_bins else None,
        "timeRangeEnd": time_bins[-1] if time_bins else None,
    }
    return dict(edge_count), dict(edge_rssi), dict(transit_count), time_series, time_meta, stats_list, debug, selected_files


def render_svg(dot_path: Path, svg_path: Path) -> None:
    subprocess.run(["dot", "-Tsvg", str(dot_path), "-o", str(svg_path)], check=True)


def enforce_svg_size(svg_path: Path, width_pt: str = "8000pt", height_pt: str = "4500pt") -> None:
    """
    Постобработка корневого SVG-элемента, чтобы задать нужные ширину/высоту.
    """
    s = svg_path.read_text(errors="ignore")
    # Replace width/height in <svg ...> tag.
    # RU: Заменяем width="...pt" и height="...pt" в теге <svg ...>
    # Minimal, deterministic changes.
    # RU: Делаем минимально и детерминированно.
    s2 = re.sub(r'(<svg\b[^>]*?)\swidth="[^"]*"', r'\1 width="' + width_pt + '"', s, count=1)
    s2 = re.sub(r'(<svg\b[^>]*?)\sheight="[^"]*"', r'\1 height="' + height_pt + '"', s2, count=1)

    # If width/height missing, insert after <svg
    # RU: Если width/height отсутствуют, вставляем после <svg
    if s2 == s:
        s2 = re.sub(r"<svg\b", f'<svg width="{width_pt}" height="{height_pt}"', s, count=1)

    svg_path.write_text(s2, encoding="utf-8")


def write_d3_html(html_path: Path, graph_payload: Dict[str, Any]) -> None:
    payload_json = json.dumps(graph_payload, ensure_ascii=False)
    html = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Meshtastic Graph (D3)</title>
    <style>
      html, body {{
        margin: 0;
        padding: 0;
        background: #0b0b0b;
        color: #f5f5f5;
        font-family: "Helvetica Neue", Arial, sans-serif;
        height: 100%;
      }}
      .toolbar {{
        position: fixed;
        left: 16px;
        top: 16px;
        background: rgba(20, 20, 20, 0.9);
        border: 1px solid #333;
        border-radius: 8px;
        padding: 12px 14px;
        font-size: 13px;
        z-index: 10;
      }}
      .toolbar h1 {{
        font-size: 16px;
        margin: 0 0 8px 0;
        font-weight: 600;
      }}
      .toolbar label {{
        display: block;
        margin-top: 6px;
      }}
      .toolbar input[type="number"] {{
        width: 64px;
        background: #101010;
        color: #f5f5f5;
        border: 1px solid #333;
        border-radius: 4px;
        padding: 2px 4px;
        margin-left: 6px;
      }}
      #graph {{
        width: 100vw;
        height: 100vh;
      }}
    </style>
    <script src="https://d3js.org/d3.v7.min.js"></script>
  </head>
  <body>
    <div class="toolbar">
      <h1>Meshtastic D3</h1>
      <div id="meta"></div>
      <label>Sort by:
        <select id="sortMetric">
          <option value="routing">routing</option>
          <option value="neighbors">neighbors</option>
          <option value="uptime">uptime</option>
        </select>
      </label>
      <label>Top N:
        <input type="number" id="topN" min="5" max="200" value="30" />
      </label>
      <label>Min neighbors:
        <input type="number" id="minNeighbors" min="0" max="200" value="0" />
      </label>
      <label>Time window:
        <input type="datetime-local" id="timeStart" />
        <input type="datetime-local" id="timeEnd" />
      </label>
    </div>
    <svg id="graph"></svg>
    <script>
      const graph = {payload_json};
      const meta = document.getElementById("meta");
      const tsCount = (graph.timeSeries || []).length;
      meta.textContent = `Nodes: ${{graph.meta.nodes}} | Links: ${{graph.meta.links}} | Min edge: ${{graph.meta.minEdge}} | Unknown: ${{graph.meta.includeUnknown ? "yes" : "no"}} | TS bins: ${{tsCount}}`;

      const width = window.innerWidth;
      const height = window.innerHeight;
      const svg = d3.select("#graph");
      svg.attr("width", width).attr("height", height);
      const zoomLayer = svg.append("g");

      svg.call(
        d3.zoom().scaleExtent([0.2, 4]).on("zoom", (event) => {{
          zoomLayer.attr("transform", event.transform);
        }})
      );

      const link = zoomLayer
        .append("g")
        .attr("class", "links")
        .selectAll("line")
        .data(graph.links)
        .enter()
        .append("line")
        .attr("stroke", (d) => d.color || "#666")
        .attr("stroke-width", (d) => d.width || 1.5)
        .attr("stroke-opacity", 0.75);

      const node = zoomLayer
        .append("g")
        .attr("class", "nodes")
        .selectAll("g")
        .data(graph.nodes)
        .enter()
        .append("g")
        .call(d3.drag().on("start", dragstarted).on("drag", dragged).on("end", dragended));

      node.append("circle")
        .attr("r", (d) => Math.max(6, d.neighbors * 1.2 + 6))
        .attr("fill", (d) => d.fill || "#888");

      node.append("text")
        .attr("x", 10)
        .attr("y", 4)
        .attr("fill", "#f5f5f5")
        .text((d) => d.label || d.id);

      const simulation = d3.forceSimulation(graph.nodes)
        .force("link", d3.forceLink(graph.links).id((d) => d.id).distance((d) => 160 + Math.min(220, d.count * 8)).strength(0.6))
        .force("charge", d3.forceManyBody().strength(-650))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collision", d3.forceCollide().radius((d) => Math.max(24, d.neighbors * 1.8 + 16)));

      simulation.on("tick", () => {{
        link
          .attr("x1", (d) => d.source.x)
          .attr("y1", (d) => d.source.y)
          .attr("x2", (d) => d.target.x)
          .attr("y2", (d) => d.target.y);
        node.attr("transform", (d) => `translate(${{d.x}},${{d.y}})`);
      }});

      function dragstarted(event, d) {{
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      }}
      function dragged(event, d) {{
        d.fx = event.x;
        d.fy = event.y;
      }}
      function dragended(event, d) {{
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      }}

      const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));

      function toLocalInputValue(d) {{
        const pad = (v) => String(v).padStart(2, "0");
        return (
          d.getFullYear() +
          "-" +
          pad(d.getMonth() + 1) +
          "-" +
          pad(d.getDate()) +
          "T" +
          pad(d.getHours()) +
          ":" +
          pad(d.getMinutes())
        );
      }}

      function initTimeInputs() {{
        const s = graph.meta.timeRangeStart ? new Date(graph.meta.timeRangeStart * 1000) : null;
        const e = graph.meta.timeRangeEnd ? new Date(graph.meta.timeRangeEnd * 1000) : null;
        const timeStart = document.getElementById("timeStart");
        const timeEnd = document.getElementById("timeEnd");
        if (s && timeStart) {{
          timeStart.value = toLocalInputValue(s);
          timeStart.min = toLocalInputValue(s);
          timeStart.max = e ? toLocalInputValue(e) : "";
        }}
        if (e && timeEnd) {{
          timeEnd.value = toLocalInputValue(e);
          timeEnd.min = s ? toLocalInputValue(s) : "";
          timeEnd.max = toLocalInputValue(e);
        }}
      }}

      function getTimeWindow() {{
        const timeStart = document.getElementById("timeStart");
        const timeEnd = document.getElementById("timeEnd");
        const sVal = timeStart && timeStart.value ? new Date(timeStart.value) : null;
        const eVal = timeEnd && timeEnd.value ? new Date(timeEnd.value) : null;
        const startEpoch = sVal ? Math.floor(sVal.getTime() / 1000) : graph.meta.timeRangeStart;
        const endEpoch = eVal ? Math.floor(eVal.getTime() / 1000) : graph.meta.timeRangeEnd;
        return {{
          start: startEpoch || 0,
          end: endEpoch || 0
        }};
      }}

      function applyFilters() {{
        if (!graph.timeSeries || graph.timeSeries.length === 0) {{
          node.attr("opacity", 1).attr("display", null);
          link.attr("opacity", 0.75).attr("display", null);
          return;
        }}
        const sortKey = document.getElementById("sortMetric").value;
        const metrics = {{
          routing: (d) => Math.max(0, d.routingPct || 0),
          neighbors: (d) => Math.max(0, d.neighbors || 0),
          uptime: (d) => Math.max(0, d.uptimeHours || 0),
        }};
        const metricKey = sortKey;

        const minNeighbors = Math.max(
          0,
          Math.min(200, parseInt(document.getElementById("minNeighbors").value || "0", 10))
        );
        const topN = Math.max(5, Math.min(200, parseInt(document.getElementById("topN").value || "30", 10)));
        const binMinutes = 5;
        const window = getTimeWindow();

        const baseSeries = (graph.timeSeries || []).filter((d) => d.t >= window.start && d.t <= window.end);
        const activeNodes = new Set();
        for (const b of baseSeries) {{
          for (const nid of Object.keys(b.routing || {{}})) activeNodes.add(nid);
          for (const nid of Object.keys(b.neighbors || {{}})) activeNodes.add(nid);
          for (const nid of Object.keys(b.uptime || {{}})) activeNodes.add(nid);
        }}
        const buckets = new Map();
        for (let i = 0; i < baseSeries.length; i++) {{
          const b = baseSeries[i];
          const idx = Math.floor((b.t - window.start) / (binMinutes * 60));
          const key = window.start + idx * binMinutes * 60;
          if (!buckets.has(key)) buckets.set(key, {{ t: key, routing: {{}}, neighbors: {{}}, uptime: {{}} }});
          const bucket = buckets.get(key);
          for (const [nid, val] of Object.entries(b.routing || {{}})) {{
            bucket.routing[nid] = (bucket.routing[nid] || 0) + val;
          }}
          for (const [nid, val] of Object.entries(b.neighbors || {{}})) {{
            bucket.neighbors[nid] = Math.max(bucket.neighbors[nid] || 0, val);
          }}
          for (const [nid, val] of Object.entries(b.uptime || {{}})) {{
            bucket.uptime[nid] = Math.max(bucket.uptime[nid] || 0, val);
          }}
        }}

        const merged = Array.from(buckets.values()).sort((a, b) => a.t - b.t);
        const totals = new Map();
        for (const b of merged) {{
          const series = b[metricKey] || {{}};
          for (const [nid, val] of Object.entries(series)) {{
            const node = nodeById.get(nid);
            if (!node || (node.neighbors || 0) < minNeighbors) continue;
            totals.set(nid, (totals.get(nid) || 0) + Number(val || 0));
          }}
        }}

        const topNodes = Array.from(totals.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, topN)
          .map((x) => x[0]);

        const topSet = new Set(topNodes);
        node
          .attr("display", null)
          .attr("opacity", (d) => {{
            if (activeNodes.size > 0 && !activeNodes.has(d.id)) return 0.12;
            return topSet.has(d.id) ? 1.0 : 0.2;
          }});
        link
          .attr("display", null)
          .attr("opacity", (d) => {{
            const active = activeNodes.size === 0 || (activeNodes.has(d.source.id) && activeNodes.has(d.target.id));
            if (!active) return 0.06;
            return (topSet.has(d.source.id) && topSet.has(d.target.id)) ? 0.75 : 0.12;
          }});
      }}

      const topNInput = document.getElementById("topN");
      const minNeighborsInput = document.getElementById("minNeighbors");
      if (topNInput) topNInput.value = String(graph.meta.d3TopN || 30);
      if (minNeighborsInput) minNeighborsInput.value = String(graph.meta.d3MinNeighbors || 0);
      initTimeInputs();

      document.getElementById("sortMetric").addEventListener("change", applyFilters);
      document.getElementById("topN").addEventListener("input", applyFilters);
      document.getElementById("minNeighbors").addEventListener("input", applyFilters);
      document.getElementById("timeStart").addEventListener("change", applyFilters);
      document.getElementById("timeEnd").addEventListener("change", applyFilters);
      applyFilters();
    </script>
  </body>
</html>
"""
    html_path.write_text(html, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="graphGen.py: build Meshtastic graph (DOT+SVG) from trace files. RU: построение графа Meshtastic (DOT+SVG) из трасс."
    )

    # Keep existing args. RU: Сохраняем существующие аргументы.
    ap.add_argument("--root", default=".", help="Directory with input files (default: current). RU: Папка входных файлов (по умолчанию: текущая).")
    ap.add_argument("--min-edge", type=int, default=3, help="Minimum confirmations to keep a directed link (default: 3). RU: минимум подтверждений (по умолчанию: 3).")
    ap.add_argument("--rankdir", default="LR", choices=["LR", "TB", "RL", "BT"], help="Graphviz rankdir (default: LR). RU: направление rankdir (по умолчанию: LR).")
    ap.add_argument("--no-d3", action="store_true", help="Disable D3.js output (HTML/JSON). RU: отключить D3.js (HTML/JSON).")
    ap.add_argument("--d3-top", type=int, default=30, help="D3 filter: top N nodes (default: 30). RU: D3 фильтр top N (по умолчанию: 30).")
    ap.add_argument("--d3-min-neighbors", type=int, default=0, help="D3 filter: min neighbors (default: 0). RU: D3 фильтр по соседям (по умолчанию: 0).")
    ap.add_argument(
        "--include-unknown",
        action="store_true",
        help="Include Unknown node (!ffffffff) and all adjacent edges (default: excluded). RU: включить Unknown (!ffffffff) и смежные рёбра (по умолчанию: исключено).",
    )
    ap.add_argument("--top", type=int, default=15, help="Top N lines in summary lists (default: 15). RU: top N в сводках (по умолчанию: 15).")

    # Time window option. RU: Опция временного окна.
    ap.add_argument(
        "--datetime",
        default=None,
        help=(
            "Date/time window filter STRICTLY by timestamps at the BEGINNING of EACH TRACE LINE inside the files "
            "(NOT filename, NOT mtime). Examples: '2026-01-22', '2026-01-22 - 2026-01-23', "
            "'2026-01-22 23:33 - 2026-01-22 23:40', '2026-01-22 23:33:08 - 2026-01-22 23:33:20'. "
            "RU: фильтр по времени берётся ТОЛЬКО из начала строки трассы (НЕ имя файла, НЕ mtime)."
        ),
    )

    # Edge width scaling. RU: Масштаб толщины рёбер.
    ap.add_argument(
        "--minwidthline",
        type=float,
        default=1.0,
        help="Min edge penwidth in relative scaling (default: 1.0). RU: минимум толщины (по умолчанию: 1.0).",
    )
    ap.add_argument(
        "--maxwidthline",
        type=float,
        default=30.0,
        help="Max edge penwidth in relative scaling (default: 30.0). RU: максимум толщины (по умолчанию: 30.0).",
    )

    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    trace_root, out_dir, node_search = fixed_paths(root)
    include_unknown = bool(args.include_unknown)
    d3_enabled = not bool(args.no_d3)

    print(f"graphGen.py version {__version__}")
    print(f"cwd: {Path.cwd()}")
    print(f"root: {root}")
    print("")
    print(f"trace search root (fixed): {trace_root}")
    print(f"output dir (fixed): {out_dir}")
    print("nodeDb search order (fixed):")
    print(f"  1) cwd:    {node_search[0]}")
    print(f"  2) script: {node_search[1]}")
    print(f"  3) home:   {node_search[2]}")
    print("")

    dot_bin = which_dot()
    if not dot_bin:
        eprint("ERROR: Graphviz 'dot' not found in PATH. Install graphviz and retry.")
        return 4
    print(f"Graphviz: {dot_bin}")
    print("")

    trace_files = find_trace_files(trace_root)
    if not trace_files:
        eprint("ERROR: no trace files found. Expected patterns in ~/meshLogger: 'YYYY-MM-DD !xxxxxxxx*.txt'")
        return 2

    measurer_id, id_counts = detect_measurer_id_from_filenames(trace_files)

    node_meta, nodedb_path, meta_debug = build_node_meta(node_search)

    # Parse --datetime window
    # RU: Разбор окна --datetime
    dt_window: Optional[Tuple[datetime, datetime]] = None
    if args.datetime is not None:
        try:
            dt_window = parse_datetime_window(args.datetime)
        except Exception:
            eprint("ERROR: bad --datetime: bad --datetime format")
            return 6

        w_start, w_end = dt_window
        print("date/time window filter (--datetime):")
        print(f"  expr: '{args.datetime}'")
        print(f"  window: {w_start.strftime('%Y-%m-%d %H:%M:%S')} - {w_end.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  traces in folder: {len(trace_files)}")
        # selection known after parsing
        # RU: выборка будет известна после парсинга
        print("")

    edge_count, edge_rssi, transit_count, time_series, time_meta, per_file_stats, parse_debug, selected_files = parse_traces_with_stats(
        trace_files=trace_files,
        include_unknown=include_unknown,
        dt_window=dt_window,
    )

    if args.datetime is not None:
        print("date/time window filter (--datetime):")
        print(f"  expr: '{args.datetime}'")
        w_start, w_end = dt_window  # type: ignore
        print(f"  window: {w_start.strftime('%Y-%m-%d %H:%M:%S')} - {w_end.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  traces in folder: {len(trace_files)}")
        print(f"  traces selected:  {len([p for p in selected_files if p in trace_files])}")
        print("")
        if len([p for p in selected_files if p in trace_files]) == 0:
            eprint("ERROR: --datetime window selected 0 trace files (by line timestamps).")
            return 7

    out_dir.mkdir(parents=True, exist_ok=True)

    out_base = build_auto_out(measurer_id)
    dot_path = out_dir / f"{out_base}.dot"
    svg_path = out_dir / f"{out_base}.svg"
    json_path = out_dir / f"{out_base}.json"
    html_path = out_dir / f"{out_base}.html"

    print("Read files:")
    print(f"node database: {nodedb_path if nodedb_path else '(not found)'}")
    print(f"nodeDb nodes loaded: {meta_debug.get('nodeDb_nodes_loaded', 0)}")
    print(f"nodeDb nodes with longName: {meta_debug.get('nodeDb_nodes_with_longName', 0)}")
    if nodedb_path and meta_debug.get("nodeDb_nodes_loaded", 0) > 0 and meta_debug.get("nodeDb_nodes_with_longName", 0) == 0:
        print("WARNING: nodeDb loaded, but ALL longName are empty => labels will become 'Unknown node'.")
        print("         This usually means your nodeDb.txt does not contain user/longName fields in expected places.")
    print("")

    print("Trace filenames measurer-id detection:")
    if id_counts:
        for k, v in id_counts.most_common():
            print(f"  {k} : {v} file(s)")
        print(f"Selected measurer-id: {measurer_id}")
    else:
        print("  No 'YYYY-MM-DD !xxxxxxxx*.txt' filenames detected; fallback to !ffffffff")
        print(f"Selected measurer-id: {measurer_id}")
    print("")

    print(f"Unknown handling: {'INCLUDED' if include_unknown else 'EXCLUDED (as if node does not exist)'}")
    if not include_unknown:
        print(f"  Dropped edges adjacent to Unknown: {parse_debug.get('dropped_unknown_edges', 0)}")
        print(f"  Dropped adjacent edges that had RSSI: {parse_debug.get('dropped_unknown_edges_with_rssi', 0)}")
    print("")

    print(f"Output basename (auto): {out_base}")
    print("")

    print("trace log files summary:")
    # print per-file stats; show hits for window
    # RU: печатаем статистику по файлам; при окне показываем попадания
    for st in per_file_stats:
        print(st.path)
        print(f"  size: {human_bytes(st.size_bytes)} | mtime: {st.mtime_iso} | sig: {st.sha1sig[:12]}…")
        print(f"  lines: {st.lines_total}")
        if args.datetime is not None:
            print(f"  lines in --datetime window: {st.lines_in_window}")
        print(f"  total hops: {st.hops_total}")
        print(f"  edges added: {st.edges_added}")
        print(f"  edges unique: {st.edges_unique}")
        print(f"  rssi samples: {st.rssi_samples}")
        print(f"  nodes unique: {st.nodes_unique}")
        print(f"  unknown mentions: {st.unknown_mentions}")
        print("")

    # filter edges by confirmations
    # RU: фильтруем рёбра по числу подтверждений
    edge_count_f = {
        k: v
        for k, v in edge_count.items()
        if v >= args.min_edge and k[0] != k[1]
        and (include_unknown or (k[0] != UNKNOWN_ID and k[1] != UNKNOWN_ID))
    }

    # build neighbors (unique visible)
    # RU: строим соседей (уникальные видимые)
    neighbors: Dict[str, set] = defaultdict(set)
    for (a, b), _c in edge_count_f.items():
        neighbors[a].add(b)
        neighbors[b].add(a)

    nodes = sorted([n for n in neighbors.keys() if len(neighbors[n]) > 0])
    if not nodes:
        eprint("ERROR: after filtering, no nodes remain. Try lower --min-edge, or enable --include-unknown.")
        return 3

    deg_u = {n: len(neighbors[n]) for n in nodes}
    vmax_neighbors = max(deg_u.values()) if deg_u else 1

    # routing percentage by transit_count, limited to kept nodes
    # RU: процент маршрутизации по transit_count, ограниченный сохранёнными узлами
    total_transit = 0
    for n, c in transit_count.items():
        if n in nodes:
            total_transit += c
    total_transit = total_transit or 1
    routing_pct = {n: (transit_count.get(n, 0) / total_transit) * 100.0 for n in nodes}

    # global min/max RSSI only for kept edges
    # RU: глобальные min/max RSSI только по сохранённым рёбрам
    all_rssi_vals: List[float] = []
    missing_rssi_edges = 0
    for (a, b), _cnt in edge_count_f.items():
        vals = edge_rssi.get((a, b), [])
        if vals:
            all_rssi_vals.extend(vals)
        else:
            missing_rssi_edges += 1
    vmin, vmax = (min(all_rssi_vals), max(all_rssi_vals)) if all_rssi_vals else (-25.0, 5.0)

    # EDGE WIDTH (RELATIVE) — only algorithm change:
    # RU: ТОЛЩИНА РЁБЕР (ОТНОСИТЕЛЬНО) — единственное изменение алгоритма толщины:
    # max confirmations in THIS run => 100% => maxwidthline
    # RU: максимум подтверждений В ЭТОМ запуске => 100% => maxwidthline
    max_conf = max(edge_count_f.values()) if edge_count_f else 1
    min_w = float(args.minwidthline)
    max_w = float(args.maxwidthline)
    if max_w < min_w:
        # keep determinism, do not touch the rest
        # RU: сохраняем детерминированность, не трогая остальное
        max_w, min_w = min_w, max_w

    def penwidth_from_count_relative(cnt: int) -> float:
        if max_conf <= 0:
            return round(min_w, 2)
        t = cnt / float(max_conf)  # 0..1. RU: от 0 до 1
        w = min_w + t * (max_w - min_w)
        return round(w, 2)

    print("global:")
    print(f"  Traces used: {len(trace_files)} file(s)")
    print(f"  Nodes kept: {len(nodes)}")
    print(f"  Links kept: {len(edge_count_f)} (min_edge={args.min_edge})")
    print(f"  Links kept without RSSI: {missing_rssi_edges}")
    print(f"  RSSI gradient range: {vmin:.2f} dB .. {vmax:.2f} dB")
    print(f"  Edge max confirmations in this run: {max_conf} (=> 100% thickness)")
    print("")

    top = max(1, int(args.top))

    def pretty_name(nid: str) -> str:
        m = node_meta.get(nid, {})
        ln = m.get("longName") or "Unknown node"
        sn = m.get("shortName") or (nid[-4:] if nid.startswith("!") else "")
        return f"{ln} [{sn}] {nid}"

    top_neighbors = sorted(nodes, key=lambda n: deg_u.get(n, 0), reverse=True)[:top]
    top_routing = sorted(nodes, key=lambda n: transit_count.get(n, 0), reverse=True)[:top]

    print(f"TOP {top} by neighbors (unique visible nodes):")
    for n in top_neighbors:
        print(f"  {deg_u.get(n,0):>3}  {pretty_name(n)}")
    print("")

    print(f"TOP {top} by routing (transit count):")
    for n in top_routing:
        if n not in nodes:
            continue
        pct = (transit_count.get(n, 0) / total_transit) * 100.0
        print(f"  {transit_count.get(n,0):>5}  {pct:>5.1f}%  {pretty_name(n)}")
    print("")

    if d3_enabled:
        now_epoch = datetime.now(tz=timezone.utc).timestamp()
        nodes_payload: List[Dict[str, Any]] = []
        for nid in nodes:
            meta = node_meta.get(
                nid, {"longName": "", "shortName": "", "role": "", "chUtil": None, "firstSeenEpoch": None}
            )
            ln = meta.get("longName") or "Unknown"
            sn = meta.get("shortName") or (nid[-4:] if nid.startswith("!") else "")
            role = (meta.get("role") or "").upper()
            fill = role_fill(role)

            cu = meta.get("chUtil")
            neigh = deg_u.get(nid, 0)
            first_seen_epoch = meta.get("firstSeenEpoch")
            uptime_hours = None
            if isinstance(first_seen_epoch, (int, float)):
                uptime_hours = max(0.0, (now_epoch - float(first_seen_epoch)) / 3600.0)

            nodes_payload.append(
                {
                    "id": nid,
                    "label": f"{ln} [{sn}]",
                    "longName": ln,
                    "shortName": sn,
                    "role": role or "UNKNOWN",
                    "neighbors": neigh,
                    "routingPct": round(routing_pct.get(nid, 0.0), 2),
                    "chUtil": float(cu) if isinstance(cu, (int, float)) else None,
                    "uptimeHours": round(uptime_hours, 2) if uptime_hours is not None else None,
                    "fill": fill,
                }
            )

        links_payload: List[Dict[str, Any]] = []
        for (a, b), cnt in edge_count_f.items():
            vals = edge_rssi.get((a, b), [])
            avg = (sum(vals) / len(vals)) if vals else None
            color = grad_rssi(avg, vmin, vmax)
            pw = penwidth_from_count_relative(cnt)
            links_payload.append(
                {
                    "source": a,
                    "target": b,
                    "count": cnt,
                    "avgRssi": round(avg, 2) if avg is not None else None,
                    "color": color,
                    "width": pw,
                }
            )

        payload = {
            "meta": {
                "generatedAt": datetime.now().isoformat(timespec="seconds"),
                "nodes": len(nodes_payload),
                "links": len(links_payload),
                "minEdge": args.min_edge,
                "includeUnknown": include_unknown,
                "rssiRange": {"min": round(vmin, 2), "max": round(vmax, 2)},
                "maxConfirmations": max_conf,
                "d3TopN": args.d3_top,
                "d3MinNeighbors": args.d3_min_neighbors,
                "baseBinMinutes": time_meta.get("baseBinMinutes"),
                "timeRangeStart": time_meta.get("timeRangeStart"),
                "timeRangeEnd": time_meta.get("timeRangeEnd"),
            },
            "nodes": nodes_payload,
            "links": links_payload,
            "timeSeries": time_series,
        }

        json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        write_d3_html(html_path, payload)
        print(f"OK: wrote {json_path}")
        print(f"OK: wrote {html_path}")
        print("Tip: open HTML via a local web server to avoid browser file:// restrictions.")
        print("")

    # build DOT
    # RU: сборка DOT
    dot_lines: List[str] = []
    dot_lines.append("digraph Meshtastic {")
    dot_lines.append(f'  graph [rankdir={args.rankdir}, bgcolor="black", nodesep=0.55, ranksep=0.90, charset="UTF-8"];')
    dot_lines.append(
        '  node [shape=box, style="rounded,filled", fontcolor="#000000", color="#333333", fontname="DejaVu Sans"];'
    )
    dot_lines.append('  edge [arrowsize=0.8];')
    dot_lines.append("")

    for nid in nodes:
        meta = node_meta.get(nid, {"longName": "", "shortName": "", "role": "", "chUtil": None})
        ln = meta.get("longName") or "Unknown"
        sn = meta.get("shortName") or (nid[-4:] if nid.startswith("!") else "")
        role = (meta.get("role") or "").upper()
        fill = role_fill(role)

        cu = meta.get("chUtil")
        cu_str = f"{cu:.1f}%" if isinstance(cu, (int, float)) else "n/a"

        neigh = deg_u.get(nid, 0)
        fs = fontsize_from_neighbors(neigh, vmax_neighbors)
        margin = margin_from_neighbors(neigh, vmax_neighbors)

        line1 = f"{ln} [{sn}]"
        line2 = nid
        line3 = fmt_role(role)
        line4 = f"neighbors:{neigh} | routing:{routing_pct.get(nid, 0.0):.1f}% | chUtil:{cu_str}"

        label = "\\n".join(
            [
                esc_dot_label(line1),
                esc_dot_label(line2),
                esc_dot_label(line3),
                esc_dot_label(line4),
            ]
        )
        dot_lines.append(
            f'  "{nid}" [fillcolor="{fill}", fontsize={fs}, margin="{margin}", label="{label}"];'
        )

    dot_lines.append("")
    for (a, b), cnt in edge_count_f.items():
        vals = edge_rssi.get((a, b), [])
        avg = (sum(vals) / len(vals)) if vals else None
        color = grad_rssi(avg, vmin, vmax)

        # ONLY here the width formula is applied:
        # RU: ТОЛЬКО здесь меняется формула толщины:
        pw = penwidth_from_count_relative(cnt)

        dot_lines.append(f'  "{a}" -> "{b}" [penwidth={pw}, color="{color}"];')
    dot_lines.append("}")

    dot_path.write_text("\n".join(dot_lines), encoding="utf-8")

    try:
        render_svg(dot_path, svg_path)
        enforce_svg_size(svg_path, width_pt="8000pt", height_pt="4500pt")
    except subprocess.CalledProcessError as e:
        eprint("ERROR: dot failed:", e)
        return 5

    print(f"OK: wrote {dot_path}")
    print(f"OK: wrote {svg_path}")
    print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
