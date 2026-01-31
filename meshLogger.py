#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime as _dt
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

VERSION = "1.8.5"

# ----------------------------
# Global stop + current child process (fast Ctrl+C shutdown)
# RU: Глобальная остановка + текущий дочерний процесс (для мгновенного Ctrl+C)
# ----------------------------

STOP = False
CURRENT_PROC: Optional[subprocess.Popen] = None


def _sigint_handler(_signum, _frame):
    global STOP, CURRENT_PROC
    STOP = True
    if CURRENT_PROC is not None:
        _terminate_process(CURRENT_PROC)


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


def fmt_line(ts: str, pct: str, cyc: str, hop: str, msg: str) -> str:
    # TS<space>PCT<TAB>[cycle][i/n]<space>HOP<TAB>MESSAGE
    # RU: TS<пробел>PCT<TAB>[cycle][i/n]<пробел>HOP<TAB>MESSAGE
    return f"{ts} {pct}\t{cyc} {hop}\t{msg}"


# ----------------------------
# Node ID normalization
# RU: Нормализация id узла
# ----------------------------

_NODE_HEX8 = re.compile(r"^[0-9a-fA-F]{8}$")
_NODE_BANG_HEX8 = re.compile(r"^![0-9a-fA-F]{8}$")
_BANG_ID_FINDER = re.compile(r"![0-9a-fA-F]{8}")


def normalize_node_id(s: str) -> Optional[str]:
    """
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


def run_cmd(cmd: List[str], timeout: int, tick: float = 0.2) -> Tuple[int, str, str]:
    """
    Запускает команду с:
      - отдельной группой процесса (чтобы мгновенно убить по Ctrl+C)
      - периодическими тик‑таймаутами для частой проверки STOP
    """
    global CURRENT_PROC, STOP

    p = None
    try:
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
Periodically performs "meshtastic --traceroute" to selected mesh nodes and logs raw routes to a daily file:
  meshTools/YYYY-MM-DD !selfid.txt
RU: Периодически выполняет "meshtastic --traceroute" к выбранным узлам и пишет сырой маршрут в ежедневный файл:
  meshTools/YYYY-MM-DD !selfid.txt

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
    log_file: str,
    defaults: dict,
) -> None:
    line = "=" * 70
    out(line)
    out("CURRENT CONFIGURATION")
    out(line)
    out(f"Script version:        {VERSION}")
    out(f"Device port:           {port} (default: {defaults['port']})")
    out(f"Activity window:       {hours} (default: {defaults['hours']})")
    out(f"Traceroute timeout:    {timeout_s} (default: {defaults['timeout']})")
    out(f"Pause after response:  {pause_s} (default: {defaults['pause']})")
    out(f"Mode:                  {mode}")
    out(f"Filter:                {filter_str}")
    out(f"Quiet mode:            {'Yes' if quiet else 'No'}")
    out("")
    out(f"Self node:             {self_id} {self_long}[{self_short}]")
    out(f"Total nodes in mesh:   {total_nodes}")
    out(f"Active nodes to poll:  {active_nodes}")
    out(f"Log file:              {log_file}")
    out(line)


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
    nodes: Dict[str, dict] = {}
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
        nonlocal last_info_refresh, nodes, self_id, self_long, self_short, banner_printed

        now = time.time()
        if STOP:
            raise KeyboardInterrupt

        if (not force) and (now - last_info_refresh) < 3600 and nodes and self_id:
            active0 = load_active_nodes(nodes, args.hours, self_id)
            active0 = filter_ids(active0, want_ids)
            active0 = filter_hops(active0, args.minhops, args.maxhops)
            return active0

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

        if not banner_printed:
            mode = "Continuous loop" if loop_forever else "One pass"
            log_file = log_filename_for_day(self_id)
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
                log_file=log_file,
                defaults=DEFAULTS,
            )
            banner_printed = True

        last_info_refresh = now

        if not args.quiet:
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

            log_path = log_filename_for_day(self_id)
            append_log_line(log_path, f"{req_ts_str}\t{towards}")
            if back:
                append_log_line(log_path, f"{ans_ts_str}\t{back}")

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
