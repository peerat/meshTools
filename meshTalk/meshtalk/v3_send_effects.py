#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Callable, Dict


def remove_pending_record(
    pending_by_peer: Dict[str, Dict[str, Dict[str, Any]]],
    *,
    peer_norm: str,
    rec_id: str,
) -> None:
    pending_by_peer.get(peer_norm, {}).pop(str(rec_id or ""), None)
    if not pending_by_peer.get(peer_norm):
        pending_by_peer.pop(peer_norm, None)


def handle_timeout_drop_action(
    *,
    action: Any,
    pending_by_peer: Dict[str, Dict[str, Dict[str, Any]]],
    save_state_fn: Callable[[Dict[str, Dict[str, Dict[str, Any]]]], None],
    append_history_fn: Callable[[str, str, str, str, str], None],
    pacer: Any,
    routing_ctl: Any,
    ui_emit_fn: Callable[[str, Any], None],
    ts_local_fn: Callable[[], str],
    now: float,
) -> None:
    rec = action.rec or {}
    remove_pending_record(pending_by_peer, peer_norm=action.peer_norm, rec_id=str(rec.get("id", "")))
    save_state_fn(pending_by_peer)
    append_history_fn("drop", action.peer_norm, rec["id"], str(rec.get("text", "")), "timeout")
    try:
        pacer.observe_drop("timeout", now=now)
    except Exception:
        pass
    try:
        routing_ctl.observe_tx_result(
            action.peer_norm,
            str(rec.get("route_id", "meshTalk") or "meshTalk"),
            now=now,
            success=False,
            timeout=True,
            rtt_s=None,
            attempts=int(rec.get("attempts", 0) or 0),
            hops=None,
            micro_retries=int(rec.get("micro_retries_sent", 0) or 0),
        )
    except Exception:
        pass
    ui_emit_fn("log", f"{ts_local_fn()} DROP: {rec['id']} timeout for {action.peer_norm}")
    ui_emit_fn(
        "failed",
        (
            action.peer_norm,
            str(rec.get("group") or rec.get("id") or rec["id"]),
            "timeout",
            int(rec.get("attempts", 0)),
            int(rec.get("total", 1) or 1),
        ),
    )


def handle_drop_action(
    *,
    action: Any,
    pending_by_peer: Dict[str, Dict[str, Dict[str, Any]]],
    save_state_fn: Callable[[Dict[str, Dict[str, Dict[str, Any]]]], None],
    append_history_fn: Callable[[str, str, str, str, str], None],
    ui_emit_fn: Callable[[str, Any], None],
    ts_local_fn: Callable[[], str],
) -> None:
    rec = action.rec or {}
    remove_pending_record(pending_by_peer, peer_norm=action.peer_norm, rec_id=str(rec.get("id", "")))
    save_state_fn(pending_by_peer)
    append_history_fn("drop", action.peer_norm, rec["id"], action.text, action.reason)
    ui_emit_fn("log", f"{ts_local_fn()} DROP: {rec['id']} {action.reason} for {action.peer_norm}")
    ui_emit_fn(
        "failed",
        (
            action.peer_norm,
            str(rec.get("group") or rec.get("id") or rec["id"]),
            action.reason,
            int(rec.get("attempts", 0)),
            int(rec.get("total", 1) or 1),
        ),
    )


def handle_send_success(
    *,
    peer_norm: str,
    rec: Dict[str, Any],
    text: str,
    cmp_name: str,
    pending_by_peer: Dict[str, Dict[str, Dict[str, Any]]],
    save_state_fn: Callable[[Dict[str, Dict[str, Dict[str, Any]]]], None],
    append_history_fn: Callable[[str, str, str, str, str], None],
    ui_emit_fn: Callable[[str, Any], None],
    ts_local_fn: Callable[[], str],
    proto_version: int,
) -> None:
    if bool(rec.get("no_retry", False)):
        remove_pending_record(pending_by_peer, peer_norm=peer_norm, rec_id=str(rec.get("id", "")))
        save_state_fn(pending_by_peer)
    else:
        pending_by_peer.setdefault(peer_norm, {})[rec["id"]] = rec
        save_state_fn(pending_by_peer)
    if int(rec.get("attempts", 0) or 0) == 1:
        frame_type = str(rec.get("relay_frame_type") or ("data" if bool(rec.get("relay_v3", False)) else "legacy")).strip().lower()
        flow_id = str(rec.get("relay_msg_hex") or rec.get("group") or rec.get("id") or "-")
        part_idx = max(1, int(rec.get("part", 1) or 1))
        total_parts = max(1, int(rec.get("total", 1) or 1))
        route_id = str(rec.get("route_id") or "-").strip() or "-"
        route_reason = str(rec.get("route_reason") or "").strip()
        route_tag = route_id + (f"/{route_reason}" if route_reason else "")
        append_history_fn("send", peer_norm, rec["id"], text, f"attempt={rec['attempts']} cmp={cmp_name}")
        log_prefix = "SEND_DATA" if frame_type in ("data", "legacy") else "SEND_CTRL"
        ui_emit_fn(
            "log",
            f"{ts_local_fn()} {log_prefix}: {rec['id']} flow={flow_id} part={part_idx}/{total_parts} "
            f"attempt={rec['attempts']} type={frame_type or '-'} route={route_tag} cmp={cmp_name} -> {peer_norm} "
            f"wire=MT-WIREv{int(proto_version)} aes-256-gcm",
        )
        ui_emit_fn(
            "log",
            f"{ts_local_fn()} FLOW: tx flow={flow_id} part={part_idx}/{total_parts} "
            f"to={peer_norm} kind={frame_type or '-'} route={route_tag}",
        )


def metrics_inc_now(metrics_inc_fn: Callable[[str, float], None], *, name: str, value: float, now: float) -> None:
    metrics_inc_fn(name, value, now=now)


def activity_record_now(activity_record_fn: Callable[..., None], *, now: float, bytes_count: int) -> None:
    activity_record_fn("out", "msg", 1, now=now, bytes_count=bytes_count)
