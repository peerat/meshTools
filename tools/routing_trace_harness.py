#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Replay harness for routing controller on recorded JSONL traces.

Trace line format:
1) TX decision/evaluation event (required for before/after comparison):
   {
     "type": "tx",
     "t": 1000.0,
     "peer": "11223344",
     "queue_depth": 3,
     "candidates": ["meshTalk", "meshtastic_text"],
     "outcomes": {
       "meshTalk": {"success": 1, "latency_s": 2.3, "attempts": 2, "bytes": 120, "hops": 2, "micro_retries": 1},
       "meshtastic_text": {"success": 0, "latency_s": 0.0, "attempts": 1, "bytes": 80, "hops": 0, "micro_retries": 0}
     }
   }
2) Optional passive observation event:
   {
     "type": "observe",
     "t": 1001.0,
     "peer": "11223344",
     "route": "meshTalk",
     "success": 1,
     "timeout": 0,
     "rtt_s": 1.8,
     "attempts": 1,
     "hops": 1,
     "micro_retries": 0
   }
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from meshtalk.routing import RoutingController


@dataclass
class Agg:
    tx_total: int = 0
    success_total: int = 0
    bytes_total: int = 0
    latency_sum: float = 0.0
    latencies: List[float] = None  # type: ignore[assignment]
    retries_sum: float = 0.0
    pps_est: float = 0.0

    def __post_init__(self) -> None:
        if self.latencies is None:
            self.latencies = []

    def add(self, outcome: Dict[str, object]) -> None:
        self.tx_total += 1
        success = bool(int(outcome.get("success", 0) or 0))
        if success:
            self.success_total += 1
        b = int(outcome.get("bytes", 0) or 0)
        self.bytes_total += max(0, b)
        lat = float(outcome.get("latency_s", 0.0) or 0.0)
        if success and lat > 0.0:
            self.latencies.append(lat)
            self.latency_sum += lat
        self.retries_sum += max(0.0, float(int(outcome.get("attempts", 1) or 1) - 1))

    def report(self) -> Dict[str, float]:
        tx = max(1, self.tx_total)
        lats = sorted(self.latencies)
        p95 = lats[int(round((len(lats) - 1) * 0.95))] if lats else 0.0
        mean_lat = (self.latency_sum / len(lats)) if lats else 0.0
        return {
            "tx_total": float(self.tx_total),
            "delivery_ratio": float(self.success_total) / float(tx),
            "goodput_bytes": float(self.bytes_total),
            "mean_latency_s": float(mean_lat),
            "p95_latency_s": float(p95),
            "retry_rate": float(self.retries_sum) / float(tx),
        }


def baseline_pick(candidates: Iterable[str]) -> str:
    c = [str(x) for x in candidates]
    if "meshTalk" in c:
        return "meshTalk"
    if "meshtastic_text" in c:
        return "meshtastic_text"
    return c[0] if c else ""


def run_trace(path: Path, cfg: Dict[str, object]) -> Tuple[Dict[str, float], Dict[str, float]]:
    ctl = RoutingController(cfg)
    ctl_base = RoutingController(cfg)
    agg_new = Agg()
    agg_base = Agg()

    lines = path.read_text(encoding="utf-8").splitlines()
    for raw in lines:
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        ev = json.loads(raw)
        t = float(ev.get("t", 0.0) or 0.0)
        typ = str(ev.get("type", "") or "")
        peer = str(ev.get("peer", "") or "").strip().lower()
        if not peer:
            continue
        if typ == "observe":
            route = str(ev.get("route", "meshTalk") or "meshTalk")
            success = bool(int(ev.get("success", 0) or 0))
            timeout = bool(int(ev.get("timeout", 0) or 0))
            ctl.observe_tx_result(
                peer,
                route,
                now=t,
                success=success,
                timeout=timeout,
                rtt_s=(float(ev["rtt_s"]) if "rtt_s" in ev and ev.get("rtt_s") is not None else None),
                attempts=int(ev.get("attempts", 1) or 1),
                hops=(int(ev["hops"]) if "hops" in ev and ev.get("hops") is not None else None),
                micro_retries=int(ev.get("micro_retries", 0) or 0),
            )
            ctl_base.observe_tx_result(
                peer,
                route,
                now=t,
                success=success,
                timeout=timeout,
                rtt_s=(float(ev["rtt_s"]) if "rtt_s" in ev and ev.get("rtt_s") is not None else None),
                attempts=int(ev.get("attempts", 1) or 1),
                hops=(int(ev["hops"]) if "hops" in ev and ev.get("hops") is not None else None),
                micro_retries=int(ev.get("micro_retries", 0) or 0),
            )
            continue
        if typ != "tx":
            continue

        candidates = ev.get("candidates", ["meshTalk", "meshtastic_text"])
        if not isinstance(candidates, list):
            candidates = ["meshTalk", "meshtastic_text"]
        outcomes = ev.get("outcomes", {})
        if not isinstance(outcomes, dict):
            continue

        qd = int(ev.get("queue_depth", 0) or 0)
        dec = ctl.select_unicast_route(peer, candidates, queue_depth=qd, now=t)
        pick_new = dec.route_id if dec.route_id in outcomes else baseline_pick(outcomes.keys())
        pick_base = baseline_pick(candidates)
        if pick_base not in outcomes:
            pick_base = baseline_pick(outcomes.keys())

        out_new = outcomes.get(pick_new, {})
        out_base = outcomes.get(pick_base, {})
        if isinstance(out_new, dict):
            agg_new.add(out_new)
            ctl.observe_tx_result(
                peer,
                pick_new,
                now=t,
                success=bool(int(out_new.get("success", 0) or 0)),
                timeout=not bool(int(out_new.get("success", 0) or 0)),
                rtt_s=(float(out_new["latency_s"]) if out_new.get("latency_s") else None),
                attempts=int(out_new.get("attempts", 1) or 1),
                hops=(int(out_new["hops"]) if out_new.get("hops") is not None else None),
                micro_retries=int(out_new.get("micro_retries", 0) or 0),
            )
        if isinstance(out_base, dict):
            agg_base.add(out_base)
            ctl_base.observe_tx_result(
                peer,
                pick_base,
                now=t,
                success=bool(int(out_base.get("success", 0) or 0)),
                timeout=not bool(int(out_base.get("success", 0) or 0)),
                rtt_s=(float(out_base["latency_s"]) if out_base.get("latency_s") else None),
                attempts=int(out_base.get("attempts", 1) or 1),
                hops=(int(out_base["hops"]) if out_base.get("hops") is not None else None),
                micro_retries=int(out_base.get("micro_retries", 0) or 0),
            )

    return (agg_base.report(), agg_new.report())


def main() -> int:
    ap = argparse.ArgumentParser(description="meshTalk routing trace replay harness")
    ap.add_argument("trace", help="Path to JSONL trace")
    args = ap.parse_args()
    path = Path(args.trace)
    base, new = run_trace(path, cfg={})
    print("BASELINE:", json.dumps(base, ensure_ascii=False, sort_keys=True))
    print("ROUTING2 :", json.dumps(new, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
