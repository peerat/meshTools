#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Optional, Tuple


@dataclass(frozen=True)
class AckSample:
    ts: float
    rtt_s: float
    attempts: int


@dataclass(frozen=True)
class DropSample:
    ts: float
    reason: str


class AdaptivePacer:
    """Adaptive pacing for meshTalk sender loop.

    Goal: maximize delivery throughput while staying conservative when the mesh becomes lossy.

    The app has two knobs:
    - rate_seconds: window length (seconds)
    - parallel_sends: how many packets can be sent within one window

    Effective send rate ~= parallel_sends / rate_seconds (packets per second).
    This pacer nudges that rate up/down using ACK feedback (attempts, timeouts).
    """

    def __init__(
        self,
        rate_seconds: int,
        parallel_sends: int,
        enabled: bool = False,
        *,
        min_rate_seconds: int = 3,
        max_rate_seconds: int = 60,
        min_parallel: int = 1,
        max_parallel: int = 6,
        adjust_interval_seconds: float = 30.0,
        stats_window_seconds: float = 120.0,
        parallel_penalty: float = 0.03,
    ) -> None:
        self._lock = threading.Lock()
        self.enabled = bool(enabled)
        self.min_rate_seconds = max(1, int(min_rate_seconds))
        self.max_rate_seconds = max(self.min_rate_seconds, int(max_rate_seconds))
        self.min_parallel = max(1, int(min_parallel))
        self.max_parallel = max(self.min_parallel, int(max_parallel))
        self.adjust_interval_seconds = max(5.0, float(adjust_interval_seconds))
        self.stats_window_seconds = max(self.adjust_interval_seconds, float(stats_window_seconds))
        self.parallel_penalty = max(0.0, float(parallel_penalty))

        self.rate_seconds = max(self.min_rate_seconds, min(self.max_rate_seconds, int(rate_seconds or 1)))
        self.parallel_sends = max(self.min_parallel, min(self.max_parallel, int(parallel_sends or 1)))

        self._acks: Deque[AckSample] = deque()
        self._drops: Deque[DropSample] = deque()
        self._last_adjust_ts = 0.0

    def set_enabled(self, enabled: bool) -> None:
        with self._lock:
            self.enabled = bool(enabled)

    def set_current(self, rate_seconds: int, parallel_sends: int) -> None:
        """Sync current knobs (e.g. after manual settings change)."""
        with self._lock:
            self.rate_seconds = max(self.min_rate_seconds, min(self.max_rate_seconds, int(rate_seconds or 1)))
            self.parallel_sends = max(self.min_parallel, min(self.max_parallel, int(parallel_sends or 1)))

    def observe_ack(self, rtt_s: float, attempts: int, now: Optional[float] = None) -> None:
        if now is None:
            now = time.time()
        try:
            rtt = float(rtt_s)
        except Exception:
            rtt = 0.0
        if rtt < 0.0:
            rtt = 0.0
        att = max(1, int(attempts or 1))
        with self._lock:
            self._acks.append(AckSample(ts=float(now), rtt_s=rtt, attempts=att))
            self._prune_locked(float(now))

    def observe_drop(self, reason: str, now: Optional[float] = None) -> None:
        if now is None:
            now = time.time()
        with self._lock:
            self._drops.append(DropSample(ts=float(now), reason=str(reason or "")))
            self._prune_locked(float(now))

    def suggest(
        self, pending_count: int, now: Optional[float] = None
    ) -> Optional[Tuple[int, int, str]]:
        """Return (rate_seconds, parallel_sends, reason) when adjustment is recommended."""
        if now is None:
            now = time.time()
        t = float(now)
        pend = max(0, int(pending_count or 0))

        with self._lock:
            if not self.enabled or pend <= 0:
                return None
            if self._last_adjust_ts > 0.0 and (t - self._last_adjust_ts) < self.adjust_interval_seconds:
                return None
            self._prune_locked(t)
            if len(self._acks) < 6:
                return None

            acks = list(self._acks)
            attempts_avg = sum(a.attempts for a in acks) / float(len(acks))
            retries_ratio = sum(1 for a in acks if a.attempts > 1) / float(len(acks))
            rtts = sorted(a.rtt_s for a in acks)
            rtt_p50 = rtts[len(rtts) // 2] if rtts else 0.0
            # Consider only timeouts that happened since the last adjustment.
            # Otherwise, a single old timeout in the stats window could keep
            # halving the rate multiple times, which hurts throughput.
            timeout_drops = sum(
                1
                for d in self._drops
                if (d.reason == "timeout" and d.ts > float(self._last_adjust_ts))
            )

            cur_rate = int(self.rate_seconds)
            cur_par = int(self.parallel_sends)
            cur_score = self._score(cur_rate, cur_par)
            desired = cur_score
            why = ""

            if timeout_drops > 0:
                desired = cur_score * 0.5
                why = f"timeout_drops={timeout_drops}"
            elif attempts_avg >= 1.60 or retries_ratio >= 0.25:
                desired = cur_score * 0.70
                why = f"attempts_avg={attempts_avg:.2f} retries_ratio={retries_ratio:.2f}"
            elif attempts_avg <= 1.05 and retries_ratio <= 0.05:
                factor = 1.10
                if pend >= 50:
                    factor = 1.25
                elif pend >= 10:
                    factor = 1.15
                desired = cur_score * factor
                why = f"good attempts_avg={attempts_avg:.2f}"
            else:
                return None

            desired = self._clamp_score(desired)
            new_rate, new_par = self._pick_pair(desired, cur_rate, cur_par)
            self._last_adjust_ts = t
            if new_rate == cur_rate and new_par == cur_par:
                return None

            old_score = cur_score
            new_score = self._score(new_rate, new_par)
            self.rate_seconds = new_rate
            self.parallel_sends = new_par
            return (
                new_rate,
                new_par,
                f"{why} score={old_score:.4f}->{new_score:.4f} rtt_p50={rtt_p50:.1f}s pending={pend}",
            )

    def _prune_locked(self, now: float) -> None:
        cutoff = float(now) - float(self.stats_window_seconds)
        while self._acks and self._acks[0].ts < cutoff:
            self._acks.popleft()
        while self._drops and self._drops[0].ts < cutoff:
            self._drops.popleft()

    def _clamp_score(self, score: float) -> float:
        try:
            s = float(score)
        except Exception:
            s = 0.0
        min_s = self._score(self.max_rate_seconds, self.min_parallel)
        max_s = self._score(self.min_rate_seconds, self.max_parallel)
        if s < min_s:
            return min_s
        if s > max_s:
            return max_s
        return s

    @staticmethod
    def _score(rate_seconds: int, parallel_sends: int) -> float:
        r = max(1.0, float(rate_seconds))
        p = max(1.0, float(parallel_sends))
        return p / r

    def _pick_pair(self, desired_score: float, cur_rate: int, cur_par: int) -> Tuple[int, int]:
        best_rate = cur_rate
        best_par = cur_par
        best_cost = 1e9

        d = max(1e-9, float(desired_score))
        for rate in range(self.min_rate_seconds, self.max_rate_seconds + 1):
            for par in range(self.min_parallel, self.max_parallel + 1):
                score = self._score(rate, par)
                rel_err = abs(score - d) / d
                # Penalize large bursts (parallel) slightly to reduce collision spikes.
                burst_pen = self.parallel_penalty * float(max(0, par - 1))
                # Stabilize: avoid flapping by penalizing big knob jumps.
                jump_pen = 0.01 * abs(rate - cur_rate) + 0.03 * abs(par - cur_par)
                cost = rel_err + burst_pen + jump_pen
                if cost < best_cost:
                    best_cost = cost
                    best_rate = int(rate)
                    best_par = int(par)
        return (best_rate, best_par)
