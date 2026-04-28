#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""
Metrics/telemetry store for meshTalk.

Design goals:
- pure-Python (no Qt), so it can be unit-tested easily
- per-second buckets with a fixed retention window
- snapshot returns a continuous time range (missing seconds => empty dict)
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple


METRICS_GRAPH_WINDOW_SECONDS = 15 * 60  # default window: 15 minutes
METRICS_RETENTION_SECONDS = 24 * 60 * 60  # keep 24h so UI can switch time scale


class MetricsStore:
    def __init__(self, retention_seconds: int = METRICS_RETENTION_SECONDS) -> None:
        self._retention_seconds = int(retention_seconds)
        self._lock = threading.Lock()
        self._series: Deque[Tuple[int, Dict[str, float]]] = deque()

    def _row_for_sec(self, sec: int) -> Dict[str, float]:
        if self._series and int(self._series[-1][0]) == int(sec):
            return self._series[-1][1]
        row: Dict[str, float] = {}
        self._series.append((int(sec), row))
        return row

    def _trim(self, now_sec: int) -> None:
        cutoff = int(now_sec) - int(self._retention_seconds) - 5
        while self._series and int(self._series[0][0]) < cutoff:
            self._series.popleft()

    def inc(self, key: str, delta: float = 1.0, now: Optional[float] = None) -> None:
        k = str(key or "").strip()
        if not k:
            return
        try:
            d = float(delta)
        except Exception:
            d = 1.0
        try:
            sec = int(time.time() if now is None else float(now))
        except Exception:
            sec = int(time.time())
        with self._lock:
            row = self._row_for_sec(sec)
            row[k] = float(row.get(k, 0.0) or 0.0) + float(d)
            self._trim(sec)

    def set(self, key: str, value: float, now: Optional[float] = None) -> None:
        k = str(key or "").strip()
        if not k:
            return
        try:
            v = float(value)
        except Exception:
            return
        try:
            sec = int(time.time() if now is None else float(now))
        except Exception:
            sec = int(time.time())
        with self._lock:
            row = self._row_for_sec(sec)
            row[k] = float(v)
            self._trim(sec)

    def snapshot_rows(self, window_s: int = METRICS_GRAPH_WINDOW_SECONDS, now: Optional[float] = None) -> List[Tuple[int, Dict[str, float]]]:
        try:
            window_s_i = max(60, int(window_s))
        except Exception:
            window_s_i = int(METRICS_GRAPH_WINDOW_SECONDS)
        try:
            now_sec = int(time.time() if now is None else float(now))
        except Exception:
            now_sec = int(time.time())
        start = int(now_sec) - int(window_s_i) + 1
        with self._lock:
            rows = [(int(s), dict(r)) for (s, r) in self._series]
        by_sec = {int(s): r for (s, r) in rows}
        out: List[Tuple[int, Dict[str, float]]] = []
        for sec in range(int(start), int(now_sec) + 1):
            out.append((int(sec), by_sec.get(int(sec), {})))
        return out

    def get_last_value(self, key: str, default: float = 0.0, window_s: int = METRICS_GRAPH_WINDOW_SECONDS) -> float:
        k = str(key or "").strip()
        if not k:
            return float(default)
        try:
            rows = self.snapshot_rows(window_s=int(window_s))
            if not rows:
                return float(default)
            last = rows[-1][1] or {}
            v = last.get(k, default)
            return float(v) if v is not None else float(default)
        except Exception:
            return float(default)


# Global singleton used by meshTalk runtime.
METRICS = MetricsStore()


def metrics_inc(key: str, delta: float = 1.0, now: Optional[float] = None) -> None:
    METRICS.inc(key, delta=delta, now=now)


def metrics_set(key: str, value: float, now: Optional[float] = None) -> None:
    METRICS.set(key, value=value, now=now)


def metrics_snapshot_rows(window_s: int = METRICS_GRAPH_WINDOW_SECONDS) -> List[Tuple[int, Dict[str, float]]]:
    return METRICS.snapshot_rows(window_s=window_s)


def metrics_get_last_value(key: str, default: float = 0.0, window_s: int = METRICS_GRAPH_WINDOW_SECONDS) -> float:
    return METRICS.get_last_value(key=key, default=default, window_s=window_s)


def activity_record(
    direction: str,
    kind: str,
    n: int = 1,
    now: Optional[float] = None,
    bytes_count: int = 0,
    subkind: Optional[str] = None,
) -> None:
    """
    direction: "out"|"in"
    kind: "msg"|"srv"|"std" (Meshtastic TEXT_MESSAGE_APP)
    """
    d = "out" if str(direction) == "out" else "in"
    kind_s = str(kind or "").strip().lower()
    if kind_s == "srv":
        k = "srv"
    elif kind_s == "std":
        k = "std"
    else:
        k = "msg"
    try:
        inc = max(0, int(n))
    except Exception:
        inc = 1
    metrics_inc(f"{d}_{k}", float(inc), now=now)
    try:
        b = max(0, int(bytes_count))
    except Exception:
        b = 0
    if b:
        metrics_inc(f"{d}_{k}_bytes", float(b), now=now)
    if k == "srv" and subkind:
        sk = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in str(subkind).strip().lower())
        sk = sk.strip("_")
        if sk:
            metrics_inc(f"{d}_srv_{sk}", float(inc), now=now)
            if b:
                metrics_inc(f"{d}_srv_{sk}_bytes", float(b), now=now)
