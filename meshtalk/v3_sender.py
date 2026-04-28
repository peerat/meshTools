#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple


def _cfg_int(cfg: Dict[str, Any], key: str, default: int, min_v: int, max_v: int) -> int:
    try:
        v = int(cfg.get(key, default))
    except Exception:
        v = int(default)
    if v < int(min_v):
        return int(min_v)
    if v > int(max_v):
        return int(max_v)
    return int(v)


def peer_fast_profile(cfg: Dict[str, Any], peer_meta: Dict[str, Any], peer_norm: str) -> Tuple[int, int, int]:
    base_retries = _cfg_int(cfg, "activity_fast_retries", 0, 0, 3)
    base_min_ms = _cfg_int(cfg, "activity_fast_retry_min_ms", 350, 50, 5000)
    base_max_ms = _cfg_int(cfg, "activity_fast_retry_max_ms", 850, base_min_ms, 8000)
    try:
        rec = peer_meta.get(peer_norm, {})
    except Exception:
        rec = {}
    if not isinstance(rec, dict):
        return (base_retries, base_min_ms, base_max_ms)
    try:
        pr = int(rec.get("activity_fast_retries", base_retries))
    except Exception:
        pr = base_retries
    try:
        pmin = int(rec.get("activity_fast_retry_min_ms", base_min_ms))
    except Exception:
        pmin = base_min_ms
    try:
        pmax = int(rec.get("activity_fast_retry_max_ms", base_max_ms))
    except Exception:
        pmax = base_max_ms
    pr = max(0, min(3, int(pr)))
    pmin = max(50, min(5000, int(pmin)))
    pmax = max(pmin, min(8000, int(pmax)))
    return (pr, pmin, pmax)


def collect_fast_retry_candidates(pending_by_peer: Dict[str, Dict[str, Dict[str, Any]]], now: float) -> List[Tuple[str, Dict[str, Any]]]:
    fast_candidates: List[Tuple[str, Dict[str, Any]]] = []
    for peer_norm, peer_pending in (pending_by_peer or {}).items():
        if not peer_pending:
            continue
        for rec in peer_pending.values():
            try:
                fl = int(rec.get("fast_left", 0) or 0)
                nt = float(rec.get("fast_next_ts", 0.0) or 0.0)
            except Exception:
                fl, nt = 0, 0.0
            if fl > 0 and nt > 0.0 and now >= nt:
                fast_candidates.append((peer_norm, rec))
    fast_candidates.sort(key=lambda pr: float(pr[1].get("created", 0.0) or 0.0))
    return fast_candidates


def prepare_send_window(
    *,
    now: float,
    rate_s: float,
    send_window_start_ts: float,
    send_window_count: int,
    send_window_last_tx_ts: float,
) -> Tuple[float, int, float]:
    if rate_s > 0.0:
        if (send_window_start_ts <= 0.0) or ((now - send_window_start_ts) >= rate_s):
            return (float(now), 0, 0.0)
    return (float(send_window_start_ts), int(send_window_count), float(send_window_last_tx_ts))


def send_budget_blocked(
    *,
    now: float,
    rate_s: float,
    send_window_count: int,
    parallel: int,
    intra_gap_s: float,
    send_window_last_tx_ts: float,
) -> bool:
    if rate_s > 0.0 and int(send_window_count) >= max(1, int(parallel)):
        return True
    if int(send_window_count) > 0 and intra_gap_s > 0.0 and (now - float(send_window_last_tx_ts)) < intra_gap_s:
        return True
    return False


def collect_candidate_peers(
    pending_peers: Iterable[str],
    tracked_peers: Iterable[str],
) -> List[str]:
    peer_list = set(pending_peers or [])
    peer_list |= set(tracked_peers or [])
    return sorted(peer_list)


def round_robin_peers(peers_sorted: List[str], send_rr_offset: int) -> Tuple[int, List[Tuple[int, str]]]:
    n_peers = len(peers_sorted or [])
    if n_peers <= 0:
        return (0, [])
    start = int(send_rr_offset) % max(1, n_peers)
    ordered: List[Tuple[int, str]] = []
    for i in range(n_peers):
        ordered.append((i, peers_sorted[(start + i) % n_peers]))
    return (start, ordered)
