#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from meshtalk.relay_state import RelayState
from meshtalk.routing import RoutingController


@dataclass
class TransportSnapshot:
    step: str
    now: float
    selected: str
    reason: str
    score: float
    k_best: List[tuple[str, float]]


@dataclass
class RelaySnapshot:
    step: str
    token: str
    best_via: str
    candidates: List[str]


def simulate_transport_route_progression() -> List[TransportSnapshot]:
    cfg = {
        "routing_hysteresis_rel": 0.25,
        "routing_hysteresis_abs": 0.05,
        "routing_sticky_hold_seconds": 10.0,
        "routing_failover_timeout_ema": 0.30,
        "routing_failover_delivery_ema": 0.25,
        "routing_min_samples": 1,
    }
    ctl = RoutingController(cfg)
    peer = "peer_demo"
    out: List[TransportSnapshot] = []

    def snap(step: str, now: float) -> None:
        d = ctl.select_unicast_route(peer, ["meshTalk", "meshtastic_text"], queue_depth=0, now=now)
        out.append(
            TransportSnapshot(
                step=step,
                now=float(now),
                selected=str(d.route_id),
                reason=str(d.reason),
                score=float(d.score),
                k_best=list(d.k_best),
            )
        )

    snap("cold_start", 1000.0)
    ctl.observe_tx_result(peer, "meshTalk", now=1001.0, success=True, attempts=1, rtt_s=1.2, hops=1)
    ctl.observe_tx_result(peer, "meshTalk", now=1002.0, success=True, attempts=1, rtt_s=1.0, hops=1)
    ctl.observe_tx_result(peer, "meshtastic_text", now=1001.0, success=True, attempts=1, rtt_s=1.8, hops=2)
    # Cold-start tie now prefers plain text. Simulate that meshTalk was then
    # explicitly selected and proven before we test failover semantics.
    ctl.select_unicast_route(peer, ["meshTalk"], queue_depth=0, now=1002.5)
    snap("meshTalk_proven", 1003.0)

    ctl.observe_tx_result(peer, "meshTalk", now=1004.0, success=False, timeout=True, attempts=3, rtt_s=None, hops=None)
    ctl.observe_tx_result(peer, "meshTalk", now=1005.0, success=False, timeout=True, attempts=3, rtt_s=None, hops=None)
    snap("failover_after_timeouts", 1006.0)

    ctl.observe_tx_result(peer, "meshTalk", now=1017.0, success=True, attempts=1, rtt_s=0.9, hops=1)
    ctl.observe_tx_result(peer, "meshTalk", now=1018.0, success=True, attempts=1, rtt_s=0.8, hops=1)
    snap("meshTalk_recovered", 1019.0)
    return out


def render_transport_route_ascii(rows: List[TransportSnapshot]) -> str:
    header = "step                  selected         reason              score    k_best"
    sep = "-" * len(header)
    lines = [header, sep]
    for row in rows:
        kb = ", ".join(f"{rid}:{score:.3f}" for rid, score in row.k_best)
        lines.append(
            f"{row.step:<21} {row.selected:<16} {row.reason:<18} {row.score:>6.3f}   {kb}"
        )
    return "\n".join(lines)


def render_transport_route_dot(rows: List[TransportSnapshot]) -> str:
    lines = [
        "digraph transport_route_sim {",
        '  rankdir=LR;',
        '  node [shape=box, style="rounded,filled", fillcolor="#1d1f21", fontcolor="#f2f2f2", color="#666666"];',
    ]
    for idx, row in enumerate(rows):
        node = f"s{idx}"
        label = f"{row.step}\\n{row.selected}\\n{row.reason}\\nscore={row.score:.3f}"
        lines.append(f'  {node} [label="{label}"];')
        if idx > 0:
            lines.append(f"  s{idx-1} -> {node};")
    lines.append("}")
    return "\n".join(lines)


def simulate_relay_route_learning() -> List[RelaySnapshot]:
    rs = RelayState()
    token = b"ROUTETKN"
    out: List[RelaySnapshot] = []

    def snap(step: str) -> None:
        candidates = rs.choose_forward_peers(token, exclude_peer="", max_candidates=4)
        best = candidates[0] if candidates else ""
        out.append(
            RelaySnapshot(
                step=step,
                token=token.hex(),
                best_via=str(best),
                candidates=list(candidates),
            )
        )

    rs.update_neighbor("peer_b", now=1000.0, snr_ema=6.0, delivery_ema=0.8)
    rs.learn_token(token, "peer_b", advertised_score=0.90, hops=1, now=1000.0)
    snap("learn_via_peer_b")

    rs.update_neighbor("peer_c", now=1001.0, snr_ema=8.0, delivery_ema=0.9)
    rs.learn_token(token, "peer_c", advertised_score=0.95, hops=1, now=1001.0)
    snap("peer_c_becomes_best")

    rs.update_neighbor("peer_c", now=1002.0, snr_ema=-15.0, delivery_ema=0.1, sleepy=True)
    rs.learn_token(token, "peer_c", advertised_score=0.10, hops=3, now=1002.0)
    snap("peer_c_degrades")
    return out


def render_relay_route_ascii(rows: List[RelaySnapshot]) -> str:
    header = "step                  token              best_via         candidates"
    sep = "-" * len(header)
    lines = [header, sep]
    for row in rows:
        lines.append(
            f"{row.step:<21} {row.token[:16]:<18} {row.best_via:<16} {', '.join(row.candidates)}"
        )
    return "\n".join(lines)


def render_demo() -> str:
    transport = render_transport_route_ascii(simulate_transport_route_progression())
    relay = render_relay_route_ascii(simulate_relay_route_learning())
    transport_dot = render_transport_route_dot(simulate_transport_route_progression())
    return (
        "=== Transport Route Simulation ===\n"
        f"{transport}\n\n"
        "=== Transport Route DOT ===\n"
        f"{transport_dot}\n\n"
        "=== Relay Route Simulation ===\n"
        f"{relay}\n"
    )
