#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from meshtalk.relay_protocol import RELAY_DEFAULT_TTL
from meshtalk.v3_receiver import compute_end_ack_forward, parse_token_adv_score


def plan_ack_frame(
    relay_state: Any,
    relay_frame: Any,
    *,
    peer_norm: str,
    ack_part: int,
    token_matches_self: bool,
) -> Dict[str, Any]:
    delivered_local = bool(token_matches_self)
    next_peers: List[str] = []
    if not delivered_local:
        next_peers = compute_end_ack_forward(relay_state, relay_frame, peer_norm or "")
    return {
        "ack_part": max(1, int(ack_part or 1)),
        "delivered_local": delivered_local,
        "next_peers": list(next_peers),
    }


def plan_token_adv_frame(relay_state: Any, relay_frame: Any, *, peer_norm: str, now: float) -> Dict[str, Any]:
    adv_score = parse_token_adv_score(relay_frame)
    next_peers: List[str] = []
    route_update: Dict[str, Any] = {
        "changed": False,
        "prev_best": "",
        "best_via": "",
        "candidates": [],
    }
    if peer_norm:
        route_update = relay_state.learn_token(
            relay_frame.relay_token,
            peer_norm,
            advertised_score=float(adv_score) / 1000.0,
            hops=max(1, int(RELAY_DEFAULT_TTL) - int(relay_frame.ttl)),
            now=now,
        )
        should_fwd, next_peers = relay_state.should_forward(
            msg_id=relay_frame.msg_id,
            from_peer=peer_norm,
            ttl=int(relay_frame.ttl),
            relay_token=relay_frame.relay_token,
            max_candidates=2,
        )
        if not should_fwd:
            next_peers = []
    return {
        "adv_score": int(adv_score),
        "next_peers": list(next_peers),
        "route_update": dict(route_update or {}),
    }


def plan_data_forward(relay_state: Any, relay_frame: Any, *, peer_norm: str) -> List[str]:
    should_fwd, next_peers = relay_state.should_forward(
        msg_id=relay_frame.msg_id,
        from_peer=peer_norm or "",
        ttl=int(relay_frame.ttl),
        relay_token=relay_frame.relay_token,
        max_candidates=1,
    )
    if should_fwd and next_peers:
        return list(next_peers)
    return []


def build_recv_event(
    peer_norm: str,
    relay_frame: Any,
    packet: Dict[str, Any],
    text: str,
    compression_v3: int,
    *,
    chunk_payload: bytes | None = None,
) -> Optional[Tuple[Any, ...]]:
    if not peer_norm:
        return None
    hop_start = packet.get("hopStart")
    hop_limit = packet.get("hopLimit")
    fwd_hops = None
    if isinstance(hop_start, int) and isinstance(hop_limit, int):
        fwd_hops = max(0, hop_start - hop_limit)
    chunk_b64 = None
    try:
        if isinstance(chunk_payload, (bytes, bytearray)) and chunk_payload:
            chunk_b64 = base64.b64encode(bytes(chunk_payload)).decode("ascii")
    except Exception:
        chunk_b64 = None
    return (
        peer_norm,
        text,
        fwd_hops,
        None,
        relay_frame.msg_id.hex(),
        1,
        1,
        None,
        chunk_b64,
        int(compression_v3),
        None,
        ("mc" if int(compression_v3 or 0) == 1 else "none"),
        bool(int(compression_v3 or 0) == 1),
    )
import base64
