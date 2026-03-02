#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""
Lightweight route selection and forward policy for meshTalk.

Design goals:
- local-only observations (no topology flooding)
- multi-factor route scoring with EMA smoothing
- anti-flapping (hysteresis + sticky route)
- fast failover on sharp degradation
- separate policies for data/broadcast/control traffic
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, Iterable, List, Optional, Tuple


def _f(v: object, default: float) -> float:
    try:
        x = float(v)
        if not math.isfinite(x):
            return float(default)
        return float(x)
    except Exception:
        return float(default)


def _i(v: object, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


@dataclass
class RoutingConfig:
    # Scoring weights.
    w_delivery: float = 1.30
    w_timeout: float = 1.05
    w_rtt: float = 0.35
    w_hops: float = 0.25
    w_retry: float = 0.40
    w_micro: float = 0.20
    w_congestion: float = 0.50
    w_snr_bonus: float = 0.08
    # Smoothing/decay.
    ema_alpha: float = 0.22
    decay_half_life_s: float = 20.0 * 60.0
    min_samples: int = 6
    route_ttl_s: float = 30.0 * 60.0
    # Feature normalization.
    rtt_ref_s: float = 12.0
    hops_ref: float = 4.0
    retry_ref: float = 3.0
    queue_ref: float = 16.0
    snr_ref_db: float = 10.0
    # Anti-flapping / failover.
    hysteresis_rel: float = 0.12
    hysteresis_abs: float = 0.04
    sticky_hold_s: float = 45.0
    failover_timeout_ema: float = 0.55
    failover_delivery_ema: float = 0.25
    failover_rtt_s: float = 25.0
    # Broadcast/group.
    group_fanout_cap: int = 8
    group_min_score: float = -0.20
    # Control-plane shaping (token bucket).
    control_rate_per_s: float = 0.20  # ~= 1 token each 5s
    control_burst: float = 3.0
    control_floor_per_kind_s: float = 2.0

    @classmethod
    def from_cfg(cls, cfg: Dict[str, object]) -> "RoutingConfig":
        c = cls()
        c.w_delivery = _f(cfg.get("routing_score_w_delivery", c.w_delivery), c.w_delivery)
        c.w_timeout = _f(cfg.get("routing_score_w_timeout", c.w_timeout), c.w_timeout)
        c.w_rtt = _f(cfg.get("routing_score_w_rtt", c.w_rtt), c.w_rtt)
        c.w_hops = _f(cfg.get("routing_score_w_hops", c.w_hops), c.w_hops)
        c.w_retry = _f(cfg.get("routing_score_w_retry", c.w_retry), c.w_retry)
        c.w_micro = _f(cfg.get("routing_score_w_micro", c.w_micro), c.w_micro)
        c.w_congestion = _f(cfg.get("routing_score_w_congestion", c.w_congestion), c.w_congestion)
        c.w_snr_bonus = _f(cfg.get("routing_score_w_snr_bonus", c.w_snr_bonus), c.w_snr_bonus)
        c.ema_alpha = max(0.01, min(1.0, _f(cfg.get("routing_ema_alpha", c.ema_alpha), c.ema_alpha)))
        c.decay_half_life_s = max(30.0, _f(cfg.get("routing_decay_half_life_seconds", c.decay_half_life_s), c.decay_half_life_s))
        c.min_samples = max(1, _i(cfg.get("routing_min_samples", c.min_samples), c.min_samples))
        c.route_ttl_s = max(30.0, _f(cfg.get("routing_route_ttl_seconds", c.route_ttl_s), c.route_ttl_s))
        c.rtt_ref_s = max(0.5, _f(cfg.get("routing_rtt_ref_seconds", c.rtt_ref_s), c.rtt_ref_s))
        c.hops_ref = max(1.0, _f(cfg.get("routing_hops_ref", c.hops_ref), c.hops_ref))
        c.retry_ref = max(1.0, _f(cfg.get("routing_retry_ref", c.retry_ref), c.retry_ref))
        c.queue_ref = max(1.0, _f(cfg.get("routing_queue_ref", c.queue_ref), c.queue_ref))
        c.snr_ref_db = max(1.0, _f(cfg.get("routing_snr_ref_db", c.snr_ref_db), c.snr_ref_db))
        c.hysteresis_rel = max(0.0, min(1.0, _f(cfg.get("routing_hysteresis_rel", c.hysteresis_rel), c.hysteresis_rel)))
        c.hysteresis_abs = max(0.0, _f(cfg.get("routing_hysteresis_abs", c.hysteresis_abs), c.hysteresis_abs))
        c.sticky_hold_s = max(0.0, _f(cfg.get("routing_sticky_hold_seconds", c.sticky_hold_s), c.sticky_hold_s))
        c.failover_timeout_ema = max(0.0, min(1.0, _f(cfg.get("routing_failover_timeout_ema", c.failover_timeout_ema), c.failover_timeout_ema)))
        c.failover_delivery_ema = max(0.0, min(1.0, _f(cfg.get("routing_failover_delivery_ema", c.failover_delivery_ema), c.failover_delivery_ema)))
        c.failover_rtt_s = max(1.0, _f(cfg.get("routing_failover_rtt_seconds", c.failover_rtt_s), c.failover_rtt_s))
        c.group_fanout_cap = max(1, _i(cfg.get("routing_group_fanout_cap", c.group_fanout_cap), c.group_fanout_cap))
        c.group_min_score = _f(cfg.get("routing_group_min_score", c.group_min_score), c.group_min_score)
        c.control_rate_per_s = max(0.01, _f(cfg.get("routing_control_rate_per_second", c.control_rate_per_s), c.control_rate_per_s))
        c.control_burst = max(1.0, _f(cfg.get("routing_control_burst", c.control_burst), c.control_burst))
        c.control_floor_per_kind_s = max(0.0, _f(cfg.get("routing_control_min_interval_seconds", c.control_floor_per_kind_s), c.control_floor_per_kind_s))
        return c


@dataclass
class LinkStats:
    route_id: str
    samples: int = 0
    last_ts: float = 0.0
    delivery_ema: float = 0.50
    timeout_ema: float = 0.0
    retry_ema: float = 0.0
    micro_ema: float = 0.0
    snr_ema: float = 0.0
    hops_ema: float = 1.0
    rtt_ema: float = 0.0
    rtt_hist: Deque[float] = field(default_factory=lambda: deque(maxlen=64))

    def decay(self, now: float, half_life_s: float) -> None:
        if self.last_ts <= 0.0:
            return
        dt = max(0.0, float(now) - float(self.last_ts))
        if dt <= 0.0:
            return
        keep = 0.5 ** (dt / max(1.0, float(half_life_s)))
        # Pull metrics gently towards neutral priors.
        self.delivery_ema = (self.delivery_ema * keep) + ((1.0 - keep) * 0.50)
        self.timeout_ema = self.timeout_ema * keep
        self.retry_ema = self.retry_ema * keep
        self.micro_ema = self.micro_ema * keep
        self.snr_ema = self.snr_ema * keep
        self.hops_ema = (self.hops_ema * keep) + ((1.0 - keep) * 1.0)
        self.rtt_ema = self.rtt_ema * keep
        self.last_ts = float(now)

    def update_tx_result(
        self,
        *,
        now: float,
        alpha: float,
        success: bool,
        timeout: bool,
        rtt_s: Optional[float],
        attempts: int,
        hops: Optional[int],
        micro_retries: int,
    ) -> None:
        self.samples = int(self.samples) + 1
        self.last_ts = float(now)
        a = max(0.01, min(1.0, float(alpha)))
        suc = 1.0 if bool(success) else 0.0
        tout = 1.0 if bool(timeout) else 0.0
        self.delivery_ema = (1.0 - a) * self.delivery_ema + (a * suc)
        self.timeout_ema = (1.0 - a) * self.timeout_ema + (a * tout)
        retry_norm = max(0.0, float(max(1, int(attempts)) - 1))
        self.retry_ema = (1.0 - a) * self.retry_ema + (a * retry_norm)
        self.micro_ema = (1.0 - a) * self.micro_ema + (a * float(max(0, int(micro_retries))))
        if isinstance(hops, int) and int(hops) >= 0:
            self.hops_ema = (1.0 - a) * self.hops_ema + (a * float(hops))
        if isinstance(rtt_s, (int, float)):
            r = max(0.0, float(rtt_s))
            self.rtt_ema = (1.0 - a) * self.rtt_ema + (a * r)
            self.rtt_hist.append(r)

    def update_rx_telemetry(
        self,
        *,
        now: float,
        alpha: float,
        snr_db: Optional[float],
        hops: Optional[int],
    ) -> None:
        self.last_ts = float(now)
        a = max(0.01, min(1.0, float(alpha)))
        if isinstance(snr_db, (int, float)):
            self.snr_ema = (1.0 - a) * self.snr_ema + (a * float(snr_db))
        if isinstance(hops, int) and int(hops) >= 0:
            self.hops_ema = (1.0 - a) * self.hops_ema + (a * float(hops))

    def p50_rtt(self) -> float:
        if not self.rtt_hist:
            return max(0.0, float(self.rtt_ema))
        vals = sorted(float(v) for v in self.rtt_hist)
        return float(vals[len(vals) // 2])

    def p95_rtt(self) -> float:
        if not self.rtt_hist:
            return max(0.0, float(self.rtt_ema))
        vals = sorted(float(v) for v in self.rtt_hist)
        idx = int(round((len(vals) - 1) * 0.95))
        return float(vals[max(0, min(len(vals) - 1, idx))])


@dataclass
class PeerRoutingState:
    routes: Dict[str, LinkStats] = field(default_factory=dict)
    selected_route: str = ""
    selected_score: float = -1e9
    selected_ts: float = 0.0
    selected_reason: str = ""
    last_k_best: List[Tuple[str, float]] = field(default_factory=list)
    muted_return_count: int = 0


@dataclass
class RouteDecision:
    peer_id: str
    route_id: str
    score: float
    k_best: List[Tuple[str, float]]
    switched: bool
    reason: str
    factors: Dict[str, float]
    trust: float


class TokenBucket:
    def __init__(self, rate_per_s: float, burst: float) -> None:
        self.rate_per_s = max(0.0001, float(rate_per_s))
        self.burst = max(1.0, float(burst))
        self.tokens = float(self.burst)
        self.last_ts = time.time()

    def allow(self, now: float, cost: float = 1.0) -> bool:
        t = float(now)
        dt = max(0.0, t - float(self.last_ts))
        self.last_ts = t
        self.tokens = min(self.burst, self.tokens + (dt * self.rate_per_s))
        c = max(0.0001, float(cost))
        if self.tokens >= c:
            self.tokens -= c
            return True
        return False


class RoutingController:
    def __init__(self, cfg: Dict[str, object], log_fn: Optional[Callable[[str], None]] = None) -> None:
        self.cfg = RoutingConfig.from_cfg(cfg)
        self.log_fn = log_fn
        self._peers: Dict[str, PeerRoutingState] = {}
        self.counters: Dict[str, float] = {
            "route_select_total": 0.0,
            "route_switch_total": 0.0,
            "route_hold_hysteresis": 0.0,
            "route_failover_total": 0.0,
            "control_dropped_total": 0.0,
        }
        self._control_bucket = TokenBucket(self.cfg.control_rate_per_s, self.cfg.control_burst)
        self._control_last_by_kind: Dict[str, float] = {}

    def update_config(self, cfg: Dict[str, object]) -> None:
        self.cfg = RoutingConfig.from_cfg(cfg)
        self._control_bucket = TokenBucket(self.cfg.control_rate_per_s, self.cfg.control_burst)

    def _peer(self, peer_id: str) -> PeerRoutingState:
        pid = str(peer_id or "").strip().lower()
        st = self._peers.get(pid)
        if st is None:
            st = PeerRoutingState()
            self._peers[pid] = st
        return st

    def _route(self, peer_id: str, route_id: str, now: float) -> LinkStats:
        p = self._peer(peer_id)
        rid = str(route_id or "").strip()
        rs = p.routes.get(rid)
        if rs is None:
            rs = LinkStats(route_id=rid, last_ts=float(now))
            p.routes[rid] = rs
        rs.decay(float(now), self.cfg.decay_half_life_s)
        return rs

    def observe_tx_result(
        self,
        peer_id: str,
        route_id: str,
        *,
        now: Optional[float] = None,
        success: bool,
        timeout: bool = False,
        rtt_s: Optional[float] = None,
        attempts: int = 1,
        hops: Optional[int] = None,
        micro_retries: int = 0,
    ) -> None:
        t = time.time() if now is None else float(now)
        rs = self._route(peer_id, route_id, t)
        rs.update_tx_result(
            now=t,
            alpha=self.cfg.ema_alpha,
            success=bool(success),
            timeout=bool(timeout),
            rtt_s=rtt_s,
            attempts=max(1, int(attempts)),
            hops=hops,
            micro_retries=max(0, int(micro_retries)),
        )

    def observe_rx_telemetry(
        self,
        peer_id: str,
        route_id: str,
        *,
        now: Optional[float] = None,
        snr_db: Optional[float] = None,
        hops: Optional[int] = None,
    ) -> None:
        t = time.time() if now is None else float(now)
        rs = self._route(peer_id, route_id, t)
        # RX telemetry is not a full delivery confirmation, but it is a live
        # observation and should gradually increase trust above pure cold-start.
        rs.samples = int(rs.samples) + 1
        rs.update_rx_telemetry(now=t, alpha=self.cfg.ema_alpha, snr_db=snr_db, hops=hops)

    def observe_local_send_attempt(
        self,
        peer_id: str,
        route_id: str,
        *,
        now: Optional[float] = None,
    ) -> None:
        t = time.time() if now is None else float(now)
        rs = self._route(peer_id, route_id, t)
        # A local send accepted by the Meshtastic API is not a delivery signal.
        # We only refresh route recency so the path is not treated as stale.
        rs.last_ts = float(t)

    @staticmethod
    def _cold_start_tiebreak(route_id: str) -> int:
        rid = str(route_id or "").strip()
        # Prefer the native/plain path when scores are still effectively equal.
        if rid == "meshtastic_text":
            return 2
        if rid == "meshTalk":
            return 1
        return 0

    def observe_muted_return(self, peer_id: str) -> None:
        p = self._peer(peer_id)
        p.muted_return_count = int(p.muted_return_count) + 1

    def _trust(self, rs: LinkStats, now: float) -> float:
        n = max(0.0, float(rs.samples))
        n_trust = min(1.0, n / max(1.0, float(self.cfg.min_samples)))
        age = max(0.0, float(now) - float(rs.last_ts))
        if self.cfg.route_ttl_s <= 0.0:
            age_trust = 1.0
        else:
            age_trust = max(0.0, 1.0 - (age / float(self.cfg.route_ttl_s)))
        return max(0.0, min(1.0, n_trust * age_trust))

    def _score(self, rs: LinkStats, queue_depth: int, now: float) -> Tuple[float, Dict[str, float], float]:
        cfg = self.cfg
        delivery = max(0.0, min(1.0, float(rs.delivery_ema)))
        timeout_rate = max(0.0, min(1.0, float(rs.timeout_ema)))
        rtt_norm = min(1.0, max(0.0, rs.p50_rtt() / max(0.1, cfg.rtt_ref_s)))
        hops_norm = min(1.0, max(0.0, float(rs.hops_ema) / max(1.0, cfg.hops_ref)))
        retry_norm = min(1.0, max(0.0, float(rs.retry_ema) / max(1.0, cfg.retry_ref)))
        micro_norm = min(1.0, max(0.0, float(rs.micro_ema) / max(1.0, cfg.retry_ref)))
        congestion_norm = min(1.0, max(0.0, float(max(0, int(queue_depth))) / max(1.0, cfg.queue_ref)))
        snr_bonus = max(0.0, min(1.0, float(rs.snr_ema) / max(1.0, cfg.snr_ref_db)))
        trust = self._trust(rs, now)
        raw = (
            (cfg.w_delivery * delivery)
            - (cfg.w_timeout * timeout_rate)
            - (cfg.w_rtt * rtt_norm)
            - (cfg.w_hops * hops_norm)
            - (cfg.w_retry * retry_norm)
            - (cfg.w_micro * micro_norm)
            - (cfg.w_congestion * congestion_norm)
            + (cfg.w_snr_bonus * snr_bonus)
        )
        score = raw * max(0.05, trust)
        factors = {
            "delivery": delivery,
            "timeout": timeout_rate,
            "rtt_norm": rtt_norm,
            "hops_norm": hops_norm,
            "retry_norm": retry_norm,
            "micro_norm": micro_norm,
            "congestion_norm": congestion_norm,
            "snr_bonus": snr_bonus,
            "trust": trust,
            "raw": raw,
        }
        return (score, factors, trust)

    def select_unicast_route(
        self,
        peer_id: str,
        candidates: Iterable[str],
        *,
        queue_depth: int = 0,
        now: Optional[float] = None,
    ) -> RouteDecision:
        t = time.time() if now is None else float(now)
        p = self._peer(peer_id)
        cand = [str(c).strip() for c in candidates if str(c).strip()]
        if not cand:
            return RouteDecision(
                peer_id=str(peer_id or ""),
                route_id="",
                score=-1e9,
                k_best=[],
                switched=False,
                reason="no_candidates",
                factors={},
                trust=0.0,
            )
        scored: List[Tuple[str, float, Dict[str, float], float]] = []
        for rid in cand:
            rs = self._route(peer_id, rid, t)
            s, f, tr = self._score(rs, int(queue_depth), t)
            scored.append((rid, s, f, tr))
        scored.sort(
            key=lambda x: (
                float(x[1]),
                float(x[3]),
                float(x[2].get("delivery", 0.0)),
                self._cold_start_tiebreak(x[0]),
            ),
            reverse=True,
        )
        best_id, best_score, best_factors, best_trust = scored[0]
        k_best = [(rid, float(sc)) for (rid, sc, _f, _t) in scored[:3]]
        switched = False
        reason = "best_score"
        chosen_id = best_id
        chosen_score = float(best_score)
        chosen_factors = dict(best_factors)
        chosen_trust = float(best_trust)

        prev_id = str(p.selected_route or "")
        prev_score = float(p.selected_score)
        prev_ts = float(p.selected_ts or 0.0)

        if prev_id and prev_id in cand:
            prev_row = None
            for row in scored:
                if row[0] == prev_id:
                    prev_row = row
                    break
            if prev_row is not None:
                prev_live_score = float(prev_row[1])
                prev_factors = dict(prev_row[2])
                hold_elapsed = (t - prev_ts) if prev_ts > 0.0 else 1e9
                failover = (
                    float(prev_factors.get("timeout", 0.0)) >= float(self.cfg.failover_timeout_ema)
                    or float(prev_factors.get("delivery", 1.0)) <= float(self.cfg.failover_delivery_ema)
                    or (float(prev_row[2].get("rtt_norm", 0.0)) * float(self.cfg.rtt_ref_s)) >= float(self.cfg.failover_rtt_s)
                )
                improvement = float(best_score) - float(prev_live_score)
                thresh = max(float(self.cfg.hysteresis_abs), abs(float(prev_live_score)) * float(self.cfg.hysteresis_rel))
                if prev_id != best_id:
                    if failover:
                        chosen_id = best_id
                        chosen_score = float(best_score)
                        chosen_factors = dict(best_factors)
                        chosen_trust = float(best_trust)
                        switched = True
                        reason = "fast_failover"
                        self.counters["route_failover_total"] = self.counters.get("route_failover_total", 0.0) + 1.0
                    elif hold_elapsed < float(self.cfg.sticky_hold_s):
                        chosen_id = prev_id
                        chosen_score = prev_live_score
                        chosen_factors = prev_factors
                        chosen_trust = float(prev_row[3])
                        reason = "sticky_hold"
                    elif improvement > thresh:
                        chosen_id = best_id
                        chosen_score = float(best_score)
                        chosen_factors = dict(best_factors)
                        chosen_trust = float(best_trust)
                        switched = True
                        reason = "hysteresis_pass"
                    else:
                        chosen_id = prev_id
                        chosen_score = prev_live_score
                        chosen_factors = prev_factors
                        chosen_trust = float(prev_row[3])
                        reason = "hysteresis_hold"
                        self.counters["route_hold_hysteresis"] = self.counters.get("route_hold_hysteresis", 0.0) + 1.0

        p.selected_route = str(chosen_id)
        p.selected_score = float(chosen_score)
        p.selected_ts = float(t)
        p.selected_reason = str(reason)
        p.last_k_best = list(k_best)

        self.counters["route_select_total"] = self.counters.get("route_select_total", 0.0) + 1.0
        if switched:
            self.counters["route_switch_total"] = self.counters.get("route_switch_total", 0.0) + 1.0

        if self.log_fn is not None:
            try:
                top = sorted(
                    [
                        ("delivery", chosen_factors.get("delivery", 0.0)),
                        ("timeout", -chosen_factors.get("timeout", 0.0)),
                        ("rtt_norm", -chosen_factors.get("rtt_norm", 0.0)),
                        ("hops_norm", -chosen_factors.get("hops_norm", 0.0)),
                        ("retry_norm", -chosen_factors.get("retry_norm", 0.0)),
                        ("congestion_norm", -chosen_factors.get("congestion_norm", 0.0)),
                    ],
                    key=lambda x: abs(float(x[1])),
                    reverse=True,
                )[:3]
                parts = ",".join(f"{k}={v:.2f}" for (k, v) in top)
                try:
                    alt = ",".join(f"{str(rid)}:{float(score):.2f}" for rid, score in list(k_best or [])[:2])
                except Exception:
                    alt = ""
                self.log_fn(
                    f"ROUTE2: peer={peer_id} pick={chosen_id} score={chosen_score:.2f} trust={chosen_trust:.2f} "
                    f"reason={reason}"
                    + (f" alt=[{alt}]" if alt else "")
                    + (f" top=[{parts}]" if parts else "")
                )
            except Exception:
                pass

        return RouteDecision(
            peer_id=str(peer_id or ""),
            route_id=str(chosen_id),
            score=float(chosen_score),
            k_best=list(k_best),
            switched=bool(switched),
            reason=str(reason),
            factors=dict(chosen_factors),
            trust=float(chosen_trust),
        )

    def choose_group_targets(
        self,
        peers: Iterable[str],
        *,
        now: Optional[float] = None,
        queue_depth: int = 0,
    ) -> List[str]:
        t = time.time() if now is None else float(now)
        scored: List[Tuple[str, float]] = []
        for peer in peers:
            p = str(peer or "").strip().lower()
            if not p:
                continue
            rs = self._route(p, "meshTalk", t)
            score, _factors, _trust = self._score(rs, int(queue_depth), t)
            if score >= float(self.cfg.group_min_score):
                scored.append((p, float(score)))
        scored.sort(key=lambda x: x[1], reverse=True)
        cap = max(1, int(self.cfg.group_fanout_cap))
        return [p for (p, _s) in scored[:cap]]

    def allow_control(self, kind: str, now: Optional[float] = None) -> bool:
        t = time.time() if now is None else float(now)
        k = str(kind or "ctrl").strip().lower()
        last = float(self._control_last_by_kind.get(k, 0.0) or 0.0)
        if last > 0.0 and (t - last) < float(self.cfg.control_floor_per_kind_s):
            self.counters["control_dropped_total"] = self.counters.get("control_dropped_total", 0.0) + 1.0
            return False
        ok = self._control_bucket.allow(t, cost=1.0)
        if not ok:
            self.counters["control_dropped_total"] = self.counters.get("control_dropped_total", 0.0) + 1.0
            return False
        self._control_last_by_kind[k] = t
        return True

    def export_peer_stats(self, peer_id: str) -> Dict[str, object]:
        p = self._peer(peer_id)
        out: Dict[str, object] = {
            "selected_route": p.selected_route,
            "selected_score": float(p.selected_score),
            "selected_reason": p.selected_reason,
            "k_best": list(p.last_k_best),
            "muted_return_count": int(p.muted_return_count),
            "routes": {},
        }
        routes_out: Dict[str, object] = {}
        for rid, rs in p.routes.items():
            routes_out[rid] = {
                "samples": int(rs.samples),
                "delivery_ema": float(rs.delivery_ema),
                "timeout_ema": float(rs.timeout_ema),
                "retry_ema": float(rs.retry_ema),
                "micro_ema": float(rs.micro_ema),
                "rtt_p50_s": float(rs.p50_rtt()),
                "rtt_p95_s": float(rs.p95_rtt()),
                "hops_ema": float(rs.hops_ema),
                "snr_ema": float(rs.snr_ema),
                "last_ts": float(rs.last_ts),
            }
        out["routes"] = routes_out
        return out
