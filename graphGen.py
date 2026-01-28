#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
graphGen.py — Meshtastic traces → D3.js HTML/JSON generator (chatty terminal output)

Version: 0.8.0
Date: 2026-02-01

CHANGELOG:
0.8.0 (2026-02-01)
  - Switched graph output to D3.js (HTML + JSON), removed Graphviz dependency.
  - HTML includes interactive force layout with zoom/drag and tooltips.
  - JSON includes node metadata, routing %, RSSI, and edge thickness.

0.7.9 (2026-01-25)
  - --datetime window filter now uses timestamps STRICTLY from the beginning of EACH TRACE LINE
    inside the file (NOT filename, NOT file mtime/ctime).
  - Edge thickness scaling changed to RELATIVE normalization per current selection:
      max confirmations => 100% => maxwidthline
      others => proportional between minwidthline..maxwidthline
    Added: --minwidthline / --maxwidthline (defaults 1..30).
  - JPG DPI default set to 75.
  - SVG post-process enforced: width="8000pt" height="4500pt".

0.7.5 (2026-01-19)
  - Unknown node excluded by default (acts like it doesn't exist):
      * drops all edges adjacent to Unknown (!ffffffff)
      * does NOT "bridge" A->B across Unknown
      * removes Unknown from routing/transit stats
    Use --include-unknown to revert to old behavior.
  - Terminal output reports how many edges were dropped due to Unknown.
  - Output basename auto-format: "YYYY-MM-DD HH:MM:SS !<measurer_id>"
  - Auto measurer id detection from filenames; DOT+SVG+JPG by default

IMPORTANT FIXED PATHS (as per your setup):
  - traces folder:   <root>/meshLogger
  - output folder:   <root>/graphGen
  - nodeDb search:   1) cwd, 2) script dir, 3) home

Trace filename pattern expected in <root>/meshLogger:
  'YYYY-MM-DD !xxxxxxxx*.txt'
"""

__version__ = "0.8.0"

import argparse
import colorsys
import hashlib
import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
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
NODE_RE = re.compile(r"(![0-9a-fA-F]{8}|Unknown)")
DB_RE = re.compile(r"\((-?\d+(?:\.\d+)?|\?)dB\)")

# filename measurer-id detection
TRACE_NAME_ID_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\s+(![0-9a-fA-F]{8})", re.I)

# timestamp at beginning of each trace line (we filter by THIS, only)
# Accept:
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


def fixed_paths() -> Tuple[Path, Path, List[Path]]:
    """
    root = cwd (where you run it) OR script dir (same in your case ~/meshTools)
    We follow your 'fixed' layout:
      traces:  <root>/meshLogger
      output:  <root>/graphGen
      nodeDb:  search order: cwd, script dir, home
    """
    cwd = Path.cwd().resolve()
    script_dir = Path(__file__).resolve().parent
    home = Path.home().resolve()

    # In your usage, you run inside ~/meshTools, and script is in same dir.
    # We'll take root as cwd to keep current behaviour.
    root = cwd

    trace_root = root / "meshLogger"
    out_dir = root / "graphGen"
    node_search = [cwd, script_dir, home]
    return trace_root, out_dir, node_search


def find_trace_files(trace_root: Path) -> List[Path]:
    """
    Only pattern requested:
      'YYYY-MM-DD !xxxxxxxx*.txt'
    Inside fixed folder: <root>/meshLogger
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


def build_auto_out(measurer_id: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"{ts} {measurer_id}"


def parse_line_ts(line: str) -> Optional[datetime]:
    """
    Parse timestamp STRICTLY from the beginning of the line.
    Accept:
      YYYY-MM-DD
      YYYY-MM-DD HH:MM
      YYYY-MM-DD HH:MM:SS
    If only date => time 00:00:00.
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
    Parse a single endpoint.
    Returns (dt, has_time).
    has_time=True if string included HH:MM (with optional :SS).
    """
    s = (s or "").strip()
    # try full
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt, True
        except Exception:
            pass
    # date-only
    try:
        dt = datetime.strptime(s, "%Y-%m-%d")
        return dt, False
    except Exception:
        raise ValueError("bad --datetime format")


def parse_datetime_window(expr: str) -> Tuple[datetime, datetime]:
    """
    --datetime supports:
      'YYYY-MM-DD'
      'YYYY-MM-DD - YYYY-MM-DD'
      'YYYY-MM-DD HH:MM - YYYY-MM-DD HH:MM'
      'YYYY-MM-DD HH:MM:SS - YYYY-MM-DD HH:MM:SS'
    Split ONLY by ' - ' (space-hyphen-space) to avoid breaking dates.
    """
    expr = (expr or "").strip()
    if not expr:
        raise ValueError("bad --datetime format")

    if " - " in expr:
        a_str, b_str = expr.split(" - ", 1)
        a_dt, a_has_time = parse_datetime_point(a_str)
        b_dt, b_has_time = parse_datetime_point(b_str)

        # If end is date-only => end of that day
        if not b_has_time:
            b_dt = b_dt + timedelta(days=1) - timedelta(seconds=1)

        # If start is date-only => start of day already ok
        if not a_has_time:
            a_dt = a_dt.replace(hour=0, minute=0, second=0)

        if b_dt < a_dt:
            raise ValueError("bad --datetime format")
        return a_dt, b_dt

    # single endpoint:
    a_dt, a_has_time = parse_datetime_point(expr)
    if a_has_time:
        # exact minute/second point => treat as [dt .. dt] (single moment)
        return a_dt, a_dt
    # date-only => full day
    b_dt = a_dt + timedelta(days=1) - timedelta(seconds=1)
    return a_dt, b_dt


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
    Robust nodeDb parser:
    - First try Meshtastic JSON export shape: nodes -> {id: {current:{user:{longName, shortName, role}, ...}}}
    - If missing, also support nodeDb where current.raw_nodes_row holds keys:
        User / AKA / Role / Channel util.
      (this matches your provided nodeDb.txt)
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
        # fallback by patterns if needed
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

                # Path A: current.user is dict
                user = cur.get("user")
                if isinstance(user, dict):
                    long_name = user.get("longName") or ""
                    short_name = user.get("shortName") or ""
                    if user.get("role"):
                        role = (user.get("role") or "").upper()

                # Path B: nodeDb like yours: current.raw_nodes_row is dict
                raw = cur.get("raw_nodes_row")
                if isinstance(raw, dict):
                    # 'User' is the long visible name in your export
                    if not long_name and isinstance(raw.get("User"), str):
                        long_name = raw.get("User") or ""
                    # 'AKA' often holds short tag
                    if not short_name and isinstance(raw.get("AKA"), str):
                        short_name = raw.get("AKA") or ""
                    # Role
                    if not role and isinstance(raw.get("Role"), str):
                        role = (raw.get("Role") or "").upper()
                    # Channel util.
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

                # Path C: current.aka or current.user string as last resort
                aka = cur.get("aka")
                if isinstance(aka, str) and not short_name:
                    short_name = aka
                if isinstance(user, str) and not long_name:
                    long_name = user

                node_meta[nid] = {
                    "longName": long_name,
                    "shortName": short_name,
                    "role": role,
                    "chUtil": ch_util,
                }
                debug["nodeDb_nodes_loaded"] += 1
                if long_name:
                    debug["nodeDb_nodes_with_longName"] += 1

    node_meta.setdefault(
        UNKNOWN_ID,
        {"longName": "Unknown node", "shortName": "ffff", "role": "", "chUtil": None},
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
    List[TraceFileStats],
    Dict[str, int],
    List[Path],
]:
    """
    Main parser:
      - Reads each file line-by-line
      - If dt_window is set: uses timestamp parsed from LINE START only
        (lines without timestamp are ignored for window filtering; they won't count)
      - Builds:
          edge_count (directed confirmations)
          edge_rssi   (list of RSSI per directed link)
          transit_count (nodes appearing as transit, excluding Unknown unless included)
      - Drops edges adjacent to Unknown when Unknown excluded
    Also returns:
      per-file stats
      debug counters
      selected_files (files which had >=1 trace line in window, if window active)
    """
    edge_count: Dict[Tuple[str, str], int] = defaultdict(int)
    edge_rssi: Dict[Tuple[str, str], List[float]] = defaultdict(list)
    transit_count: Dict[str, int] = defaultdict(int)
    stats_list: List[TraceFileStats] = []

    dropped_unknown_edges = 0
    dropped_unknown_edges_with_rssi = 0

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
            # window filter uses timestamp from line start ONLY
            if w_start and w_end:
                ts = parse_line_ts(line)
                if ts is None:
                    continue
                if ts < w_start or ts > w_end:
                    continue
                lines_in_window += 1

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

            # transit stats (exclude Unknown unless explicitly included)
            for n in seq[1:-1]:
                if include_unknown or n != UNKNOWN_ID:
                    transit_count[n] += 1

            # RSSI samples extraction
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

                # drop edges adjacent to Unknown if Unknown is excluded
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

        # If window active: select file only if it had >=1 line_in_window
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
    return dict(edge_count), dict(edge_rssi), dict(transit_count), stats_list, debug, selected_files


def write_d3_html(html_path: Path, graph_payload: Dict[str, Any]) -> None:
    payload_json = json.dumps(graph_payload, ensure_ascii=False, indent=2)
    html = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Meshtastic Graph</title>
    <style>
      html, body {{
        margin: 0;
        padding: 0;
        background: #0b0b0b;
        color: #f5f5f5;
        font-family: "Helvetica Neue", Arial, sans-serif;
        height: 100%;
        overflow: hidden;
      }}
      .toolbar {{
        position: absolute;
        left: 16px;
        top: 16px;
        background: rgba(20, 20, 20, 0.9);
        border: 1px solid #333;
        border-radius: 8px;
        padding: 12px 14px;
        font-size: 14px;
        z-index: 10;
      }}
      .toolbar h1 {{
        font-size: 16px;
        margin: 0 0 8px 0;
        font-weight: 600;
      }}
      .toolbar .meta {{
        font-size: 12px;
        color: #c0c0c0;
        line-height: 1.4;
      }}
      svg {{
        width: 100vw;
        height: 100vh;
      }}
      .link {{
        stroke-opacity: 0.75;
      }}
      .node circle {{
        stroke: #222;
        stroke-width: 1px;
      }}
      .node text {{
        fill: #f0f0f0;
        pointer-events: none;
        font-size: 11px;
      }}
      .tooltip {{
        position: absolute;
        pointer-events: none;
        background: rgba(25, 25, 25, 0.95);
        border: 1px solid #444;
        padding: 8px 10px;
        border-radius: 6px;
        color: #f0f0f0;
        font-size: 12px;
        line-height: 1.4;
        opacity: 0;
        transition: opacity 0.1s ease;
      }}
    </style>
  </head>
  <body>
    <div class="toolbar">
      <h1>Meshtastic Graph (D3.js)</h1>
      <div class="meta" id="meta"></div>
    </div>
    <div class="tooltip" id="tooltip"></div>
    <svg></svg>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script>
      window.addEventListener("load", () => {{
      if (typeof d3 === "undefined") {{
        const meta = document.getElementById("meta");
        meta.textContent = "D3.js failed to load (check network or local hosting).";
        return;
      }}
      const graph = {payload_json};
      const meta = document.getElementById("meta");
      meta.textContent = `Nodes: ${{graph.meta.nodes}} | Links: ${{graph.meta.links}} | Min edge: ${{graph.meta.minEdge}} | Unknown: ${{graph.meta.includeUnknown ? "yes" : "no"}}`;

      const width = window.innerWidth;
      const height = window.innerHeight;
      const svg = d3.select("svg");
      svg.attr("width", width).attr("height", height);
      const zoomLayer = svg.append("g");

      const tooltip = d3.select("#tooltip");

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
        .attr("class", "link")
        .attr("stroke", (d) => d.color || "#666")
        .attr("stroke-width", (d) => d.width || 1.5);

      const node = zoomLayer
        .append("g")
        .attr("class", "nodes")
        .selectAll("g")
        .data(graph.nodes)
        .enter()
        .append("g")
        .attr("class", "node")
        .call(
          d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended)
        );

      node
        .append("circle")
        .attr("r", (d) => Math.max(6, d.neighbors * 1.2 + 6))
        .attr("fill", (d) => d.fill || "#888")
        .on("mouseover", (event, d) => {{
          tooltip
            .style("opacity", 1)
            .html(
              `<strong>${{d.longName}}</strong> [${{d.shortName}}]<br/>` +
              `${{d.id}}<br/>` +
              `Role: ${{d.role || "UNKNOWN"}}<br/>` +
              `Neighbors: ${{d.neighbors}}<br/>` +
              `Routing: ${{d.routingPct.toFixed(1)}}%<br/>` +
              `chUtil: ${{d.chUtil === null ? "n/a" : d.chUtil.toFixed(1) + "%"}}`
            );
        }})
        .on("mousemove", (event) => {{
          tooltip.style("left", event.pageX + 12 + "px").style("top", event.pageY + 12 + "px");
        }})
        .on("mouseout", () => {{
          tooltip.style("opacity", 0);
        }});

      node
        .append("text")
        .attr("x", 10)
        .attr("y", 4)
        .text((d) => d.label);

      if (!graph.nodes || graph.nodes.length === 0) {{
        meta.textContent = "No nodes to display (check filters or input data).";
        return;
      }}

      const simulation = d3
        .forceSimulation(graph.nodes)
        .force(
          "link",
          d3
            .forceLink(graph.links)
            .id((d) => d.id)
            .distance((d) => 160 + Math.min(220, d.count * 8))
            .strength(0.6)
        )
        .force("charge", d3.forceManyBody().strength(-650))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force(
          "radial",
          d3
            .forceRadial((d) => 140 + d.neighbors * 24, width / 2, height / 2)
            .strength(0.75)
        )
        .force(
          "collision",
          d3.forceCollide().radius((d) => {{
            const labelBoost = d.label ? Math.min(24, d.label.length * 0.7) : 0;
            return Math.max(24, d.neighbors * 1.8 + 16 + labelBoost);
          }})
        );

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

      window.addEventListener("resize", () => {{
        const w = window.innerWidth;
        const h = window.innerHeight;
        svg.attr("width", w).attr("height", h);
        simulation.force("center", d3.forceCenter(w / 2, h / 2));
        simulation.force(
          "radial",
          d3.forceRadial((d) => 140 + d.neighbors * 24, w / 2, h / 2).strength(0.75)
        );
        simulation.alpha(0.3).restart();
      }});
      }});
    </script>
  </body>
</html>
"""
    html_path.write_text(html, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="graphGen.py: build Meshtastic graph (D3.js HTML/JSON) from trace files.")

    # Keep existing args (as you used)
    ap.add_argument("--root", default=".", help="Directory with input files (default: current).")
    ap.add_argument("--min-edge", type=int, default=3, help="Minimum confirmations to keep a directed link (default: 3).")
    ap.add_argument(
        "--include-unknown",
        action="store_true",
        help="Include Unknown node (!ffffffff) and all edges adjacent to it (default: excluded).",
    )
    ap.add_argument("--top", type=int, default=15, help="Top N lines in summary lists (default: 15).")

    # Your time window option
    ap.add_argument(
        "--datetime",
        default=None,
        help=(
            "Date/time window filter STRICTLY by timestamps at the BEGINNING of EACH TRACE LINE inside the files "
            "(NOT filename, NOT mtime). Examples: '2026-01-22', '2026-01-22 - 2026-01-23', "
            "'2026-01-22 23:33 - 2026-01-22 23:40', '2026-01-22 23:33:08 - 2026-01-22 23:33:20'."
        ),
    )

    # Only thickness scaling change (relative range)
    ap.add_argument(
        "--minwidthline",
        type=float,
        default=1.0,
        help="Min edge penwidth in relative scaling (default: 1.0).",
    )
    ap.add_argument(
        "--maxwidthline",
        type=float,
        default=30.0,
        help="Max edge penwidth in relative scaling (default: 30.0).",
    )

    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    # Fixed paths
    trace_root, out_dir, node_search = fixed_paths()

    root = Path(args.root).resolve()  # printed only (kept as before)
    include_unknown = bool(args.include_unknown)

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

    trace_files = find_trace_files(trace_root)
    if not trace_files:
        eprint("ERROR: no trace files found. Expected patterns in ~/meshLogger: 'YYYY-MM-DD !xxxxxxxx*.txt'")
        return 2

    measurer_id, id_counts = detect_measurer_id_from_filenames(trace_files)

    node_meta, nodedb_path, meta_debug = build_node_meta(node_search)

    # --datetime window parse
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
        # selection will be known after parse
        print("")

    edge_count, edge_rssi, transit_count, per_file_stats, parse_debug, selected_files = parse_traces_with_stats(
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
    # print stats only for files; show window hit counts if window used
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

    # filter edges by confirmation count
    edge_count_f = {
        k: v
        for k, v in edge_count.items()
        if v >= args.min_edge and k[0] != k[1]
        and (include_unknown or (k[0] != UNKNOWN_ID and k[1] != UNKNOWN_ID))
    }

    # build neighbors (unique visible)
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

    # routing percent based on transit_count limited to kept nodes
    total_transit = 0
    for n, c in transit_count.items():
        if n in nodes:
            total_transit += c
    total_transit = total_transit or 1
    routing_pct = {n: (transit_count.get(n, 0) / total_transit) * 100.0 for n in nodes}

    # rssi global min/max from kept edges only
    all_rssi_vals: List[float] = []
    missing_rssi_edges = 0
    for (a, b), _cnt in edge_count_f.items():
        vals = edge_rssi.get((a, b), [])
        if vals:
            all_rssi_vals.extend(vals)
        else:
            missing_rssi_edges += 1
    vmin, vmax = (min(all_rssi_vals), max(all_rssi_vals)) if all_rssi_vals else (-25.0, 5.0)

    # EDGE THICKNESS (RELATIVE) — единственное изменение алгоритма толщины:
    # max confirmations in THIS run => 100% => maxwidthline
    max_conf = max(edge_count_f.values()) if edge_count_f else 1
    min_w = float(args.minwidthline)
    max_w = float(args.maxwidthline)
    if max_w < min_w:
        # keep deterministic behaviour, but do not change other parts
        max_w, min_w = min_w, max_w

    def penwidth_from_count_relative(cnt: int) -> float:
        if max_conf <= 0:
            return round(min_w, 2)
        denom = math.log1p(max_conf)
        t = math.log1p(cnt) / denom if denom > 0 else 0.0  # 0..1, logarithmic
        w = min_w + (t**0.7) * (max_w - min_w)
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

    # D3 payload
    nodes_payload: List[Dict[str, Any]] = []
    for nid in nodes:
        meta = node_meta.get(nid, {"longName": "", "shortName": "", "role": "", "chUtil": None})
        ln = meta.get("longName") or "Unknown"
        sn = meta.get("shortName") or (nid[-4:] if nid.startswith("!") else "")
        role = (meta.get("role") or "").upper()
        fill = role_fill(role)

        cu = meta.get("chUtil")
        neigh = deg_u.get(nid, 0)
        fs = fontsize_from_neighbors(neigh, vmax_neighbors)
        margin = margin_from_neighbors(neigh, vmax_neighbors)

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
                "fill": fill,
                "fontSize": fs,
                "margin": margin,
            }
        )

    links_payload: List[Dict[str, Any]] = []
    for (a, b), cnt in edge_count_f.items():
        vals = edge_rssi.get((a, b), [])
        avg = (sum(vals) / len(vals)) if vals else None
        color = grad_rssi(avg, vmin, vmax)

        # ONLY thickness formula changed here:
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
        },
        "nodes": nodes_payload,
        "links": links_payload,
    }

    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_d3_html(html_path, payload)

    print(f"OK: wrote {json_path}")
    print(f"OK: wrote {html_path}")
    print("Tip: open HTML via a local web server to avoid browser file:// restrictions.")
    print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
