#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import time
from typing import Any, Callable, Dict, Iterable, List, Optional

from meshtalk.v3_runtime import build_forward_relay_record

_TOKEN_ADV_RX_LOG_TS: Dict[str, float] = {}


def handle_ack_effects(
    *,
    relay_frame: Any,
    ack_plan: Dict[str, Any],
    peer_norm: str,
    consume_hop_ack_fn: Callable[[bytes, int, str], Any],
    queue_relay_prebuilt_fn: Callable[[str, bytes], bool],
    serialize_decremented_fn: Callable[[Any], bytes],
    ui_emit_fn: Callable[[str, Any], None],
    ts_local_fn: Callable[[], str],
) -> None:
    ack_part = int(ack_plan.get("ack_part", 1) or 1)
    removed_rec = None
    if int(getattr(relay_frame, "frame_type", 0) or 0) == 2:
        removed_rec = consume_hop_ack_fn(relay_frame.msg_id, ack_part, "hop_ack")
        if isinstance(removed_rec, dict):
            try:
                created_ts = float(removed_rec.get("created", 0.0) or 0.0)
            except Exception:
                created_ts = 0.0
            delivery_s = max(0.0, time.time() - created_ts) if created_ts > 0.0 else 0.0
            try:
                attempts_v = float(removed_rec.get("attempts", 0) or 0)
            except Exception:
                attempts_v = 0.0
            try:
                total_v = int(removed_rec.get("total", 1) or 1)
            except Exception:
                total_v = 1
            group_id = str(
                removed_rec.get("relay_msg_hex")
                or removed_rec.get("group")
                or relay_frame.msg_id.hex()
            )
            ui_emit_fn(
                "ack",
                (
                    str(peer_norm or ""),
                    group_id,
                    float(delivery_s),
                    float(attempts_v),
                    int(max(1, total_v)),
                    None,
                    None,
                ),
            )
    if int(getattr(relay_frame, "frame_type", 0) or 0) == 3 and ack_plan.get("delivered_local"):
        ui_emit_fn(
            "log",
            f"{ts_local_fn()} RELAY: delivered msg={relay_frame.msg_id.hex()} via={peer_norm or '-'}",
        )
        ui_emit_fn(
            "log",
            f"{ts_local_fn()} FLOW: delivered flow={relay_frame.msg_id.hex()} via={peer_norm or '-'}",
        )
    elif int(getattr(relay_frame, "frame_type", 0) or 0) == 3:
        next_peers = list(ack_plan.get("next_peers") or [])
        if next_peers:
            forwarded_ack = serialize_decremented_fn(relay_frame)
            for next_peer in next_peers:
                queue_relay_prebuilt_fn(next_peer, forwarded_ack)
            ui_emit_fn(
                "log",
                f"{ts_local_fn()} RELAY: end_ack fwd msg={relay_frame.msg_id.hex()} via={','.join(next_peers)} ttl={max(0, int(relay_frame.ttl) - 1)}",
            )
    frame_type = int(getattr(relay_frame, "frame_type", 0) or 0)
    should_log_ack = True
    if frame_type in (2, 3):
        # HOP_ACK already logs detailed RTT/attempts in consume_hop_ack_fn(),
        # END_ACK already logs either delivered_local or end_ack forwarding.
        # A generic "ack type=..." line adds noise and, for duplicate HOP_ACK,
        # looks like a second real acknowledgement.
        should_log_ack = False
    if should_log_ack:
        ui_emit_fn(
            "log",
            f"{ts_local_fn()} RELAY: ack type={relay_frame.frame_type} msg={relay_frame.msg_id.hex()} part={ack_part} from={peer_norm or '-'}",
        )


def handle_token_adv_effects(
    *,
    relay_frame: Any,
    token_adv_plan: Dict[str, Any],
    peer_norm: str,
    queue_relay_prebuilt_fn: Callable[[str, bytes], bool],
    serialize_decremented_fn: Callable[[Any], bytes],
    ui_emit_fn: Callable[[str, Any], None],
    ts_local_fn: Callable[[], str],
) -> None:
    adv_score = int(token_adv_plan.get("adv_score", 0) or 0)
    token_key = f"{peer_norm or '-'}:{relay_frame.relay_token.hex()}:{adv_score}"
    now_ts = time.time()
    try:
        last_log_ts = float(_TOKEN_ADV_RX_LOG_TS.get(token_key, 0.0) or 0.0)
    except Exception:
        last_log_ts = 0.0
    if (now_ts - last_log_ts) >= 10.0:
        _TOKEN_ADV_RX_LOG_TS[token_key] = now_ts
        ui_emit_fn(
            "log",
            f"{ts_local_fn()} RELAY: route_learn token={relay_frame.relay_token.hex()} via={peer_norm or '-'} score={adv_score} src=token_adv",
        )
    route_update = dict(token_adv_plan.get("route_update") or {})
    if bool(route_update.get("changed")):
        best_via = str(route_update.get("best_via") or "-")
        prev_best = str(route_update.get("prev_best") or "-")
        candidates = list(route_update.get("candidates") or [])
        cand_text = ",".join(str(x) for x in candidates if str(x)) or best_via
        ui_emit_fn(
            "log",
            f"{ts_local_fn()} RELAY: route_best token={relay_frame.relay_token.hex()} best_via={best_via} prev={prev_best} candidates={cand_text}",
        )
    next_peers = list(token_adv_plan.get("next_peers") or [])
    if next_peers:
        forwarded_adv = serialize_decremented_fn(relay_frame)
        for next_peer in next_peers:
            queue_relay_prebuilt_fn(next_peer, forwarded_adv)
        ui_emit_fn(
            "log",
            f"{ts_local_fn()} RELAY: route_adv fwd token={relay_frame.relay_token.hex()} via={','.join(next_peers)}",
        )


def handle_data_local_delivery_effects(
    *,
    relay_frame: Any,
    peer_norm: str,
    recv_event: Any,
    relay_incoming: Dict[str, Any],
    send_end_ack_fn: Callable[[Any], bool],
    ui_emit_fn: Callable[[str, Any], None],
) -> None:
    if recv_event is not None:
        ui_emit_fn("recv", recv_event)
    relay_incoming.pop(f"{peer_norm or '-'}:{relay_frame.msg_id.hex()}", None)
    send_end_ack_fn(relay_frame)


def handle_data_forward_effects(
    *,
    relay_frame: Any,
    next_peers: Iterable[str],
    add_forward_record_fn: Callable[[str, Any], None],
    serialize_decremented_fn: Callable[[Any], bytes],
    ui_emit_fn: Callable[[str, Any], None],
    ts_local_fn: Callable[[], str],
) -> None:
    rows = list(next_peers or [])
    if not rows:
        return
    forwarded = serialize_decremented_fn(relay_frame)
    for next_peer in rows:
        add_forward_record_fn(next_peer, forwarded)
    ui_emit_fn(
        "log",
        f"{ts_local_fn()} RELAY: fwd msg={relay_frame.msg_id.hex()} via={','.join(rows)} ttl={max(0, int(relay_frame.ttl) - 1)}",
    )


def handle_data_forward_effects_direct(
    *,
    relay_frame: Any,
    next_peers: Iterable[str],
    pending_by_peer: Dict[str, Dict[str, Dict[str, Any]]],
    created_ts: float,
    pending_lock: Any,
    save_state_fn: Callable[[Any], None],
    serialize_decremented_fn: Callable[[Any], bytes],
    ui_emit_fn: Callable[[str, Any], None],
    ts_local_fn: Callable[[], str],
) -> bool:
    rows = list(next_peers or [])
    if not rows:
        return False
    with pending_lock:
        forwarded = serialize_decremented_fn(relay_frame)
        for next_peer in rows:
            peer_pending = pending_by_peer.setdefault(next_peer, {})
            rec_fwd = build_forward_relay_record(
                frame_obj=relay_frame,
                next_peer=next_peer,
                raw_forwarded=forwarded,
                created_ts=created_ts,
                route_reason="relay_forward",
            )
            peer_pending[str(rec_fwd["id"])] = rec_fwd
        save_state_fn(pending_by_peer)
    ui_emit_fn(
        "log",
        f"{ts_local_fn()} RELAY: fwd msg={relay_frame.msg_id.hex()} via={','.join(rows)} ttl={max(0, int(relay_frame.ttl) - 1)}",
    )
    return True
