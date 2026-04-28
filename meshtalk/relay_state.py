#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class NeighborMetrics:
    peer_id: str
    last_seen_ts: float = 0.0
    delivery_ema: float = 0.50
    rtt_ema: float = 0.0
    queue_depth: int = 0
    snr_ema: float = 0.0
    battery_powered: bool = False
    sleepy: bool = False

    def score(self) -> float:
        score = 0.0
        score += float(self.delivery_ema) * 1.5
        score -= min(1.5, float(self.rtt_ema) / 10.0)
        score -= min(1.0, float(max(0, self.queue_depth)) / 8.0)
        score += max(-0.5, min(0.5, float(self.snr_ema) / 20.0))
        if self.battery_powered:
            score -= 0.25
        if self.sleepy:
            score -= 0.75
        return float(score)


@dataclass
class Reachability:
    relay_token: bytes
    via_peer: str
    score: float
    updated_ts: float
    hops: int = 1


@dataclass
class SeenRecord:
    msg_hex: str
    from_peer: str
    ttl_seen: int
    seen_ts: float
    forwarded_to: List[str] = field(default_factory=list)


class RelayState:
    def __init__(self, seen_ttl_s: float = 3600.0) -> None:
        self.seen_ttl_s = float(max(30.0, seen_ttl_s))
        self.neighbors: Dict[str, NeighborMetrics] = {}
        self.reachability: Dict[bytes, List[Reachability]] = {}
        self.seen: Dict[str, SeenRecord] = {}

    @staticmethod
    def _seen_key(msg_id: bytes, relay_token: bytes) -> str:
        msg_hex = bytes(msg_id or b"").hex()
        token_hex = bytes(relay_token or b"").hex()
        return f"{msg_hex}|{token_hex}"

    def prune(self, now: Optional[float] = None) -> None:
        t = time.time() if now is None else float(now)
        stale = []
        for msg_hex, rec in self.seen.items():
            if (t - float(rec.seen_ts)) > self.seen_ttl_s:
                stale.append(msg_hex)
        for key in stale:
            self.seen.pop(key, None)
        for token, rows in list(self.reachability.items()):
            keep = [row for row in rows if (t - float(row.updated_ts)) <= self.seen_ttl_s]
            if keep:
                self.reachability[token] = keep
            else:
                self.reachability.pop(token, None)

    def update_neighbor(
        self,
        peer_id: str,
        *,
        delivery_ema: Optional[float] = None,
        rtt_ema: Optional[float] = None,
        queue_depth: Optional[int] = None,
        snr_ema: Optional[float] = None,
        battery_powered: Optional[bool] = None,
        sleepy: Optional[bool] = None,
        now: Optional[float] = None,
    ) -> NeighborMetrics:
        pid = str(peer_id or "").strip()
        rec = self.neighbors.get(pid)
        if rec is None:
            rec = NeighborMetrics(peer_id=pid)
            self.neighbors[pid] = rec
        rec.last_seen_ts = time.time() if now is None else float(now)
        if delivery_ema is not None:
            rec.delivery_ema = float(delivery_ema)
        if rtt_ema is not None:
            rec.rtt_ema = float(rtt_ema)
        if queue_depth is not None:
            rec.queue_depth = int(queue_depth)
        if snr_ema is not None:
            rec.snr_ema = float(snr_ema)
        if battery_powered is not None:
            rec.battery_powered = bool(battery_powered)
        if sleepy is not None:
            rec.sleepy = bool(sleepy)
        return rec

    def learn_token(
        self,
        relay_token: bytes,
        via_peer: str,
        *,
        advertised_score: float = 0.0,
        hops: int = 1,
        now: Optional[float] = None,
    ) -> Dict[str, object]:
        token = bytes(relay_token or b"")[:8]
        if not token:
            return {
                "changed": False,
                "prev_best": "",
                "best_via": "",
                "candidates": [],
            }
        pid = str(via_peer or "").strip()
        t = time.time() if now is None else float(now)
        prev_rows = list(self.reachability.get(token, []))
        prev_best = str(prev_rows[0].via_peer) if prev_rows else ""
        nscore = self.neighbors.get(pid).score() if pid in self.neighbors else 0.0
        score = float(advertised_score) + float(nscore)
        rows = [row for row in self.reachability.get(token, []) if row.via_peer != pid]
        rows.append(Reachability(relay_token=token, via_peer=pid, score=score, updated_ts=t, hops=max(1, int(hops))))
        rows.sort(key=lambda r: (-float(r.score), int(r.hops), -float(r.updated_ts)))
        self.reachability[token] = rows[:8]
        best_via = str(rows[0].via_peer) if rows else ""
        candidates = [str(row.via_peer) for row in rows[:3] if str(row.via_peer)]
        return {
            "changed": bool(best_via) and (best_via != prev_best),
            "prev_best": prev_best,
            "best_via": best_via,
            "candidates": candidates,
        }

    def mark_seen(
        self,
        msg_id: bytes,
        from_peer: str,
        ttl_seen: int,
        now: Optional[float] = None,
        relay_token: bytes = b"",
    ) -> Tuple[bool, SeenRecord]:
        seen_key = self._seen_key(msg_id, relay_token)
        msg_hex = bytes(msg_id or b"").hex()
        t = time.time() if now is None else float(now)
        self.prune(now=t)
        prev = self.seen.get(seen_key)
        if prev is not None:
            return (False, prev)
        rec = SeenRecord(msg_hex=msg_hex, from_peer=str(from_peer or "").strip(), ttl_seen=int(ttl_seen), seen_ts=t)
        self.seen[seen_key] = rec
        return (True, rec)

    def choose_forward_peers(
        self,
        relay_token: bytes,
        *,
        exclude_peer: str = "",
        max_candidates: int = 1,
    ) -> List[str]:
        token = bytes(relay_token or b"")[:8]
        rows = list(self.reachability.get(token, []))
        out: List[str] = []
        ex = str(exclude_peer or "").strip()
        for row in rows:
            if row.via_peer and row.via_peer != ex and row.via_peer not in out:
                out.append(row.via_peer)
            if len(out) >= max(1, int(max_candidates)):
                break
        return out

    def should_forward(
        self,
        *,
        msg_id: bytes,
        from_peer: str,
        ttl: int,
        relay_token: bytes,
        max_candidates: int = 1,
    ) -> Tuple[bool, List[str]]:
        is_new, rec = self.mark_seen(msg_id, from_peer, ttl, relay_token=relay_token)
        if not is_new:
            return (False, [])
        if int(ttl) <= 1:
            return (False, [])
        peers = self.choose_forward_peers(relay_token, exclude_peer=from_peer, max_candidates=max_candidates)
        if not peers:
            return (False, [])
        rec.forwarded_to.extend(peers)
        return (True, peers)
