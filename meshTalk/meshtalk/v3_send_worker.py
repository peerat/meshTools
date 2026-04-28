#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

from meshtalk.v3_send_record import prepare_record_send, record_is_expired, record_retry_due
from meshtalk.v3_sender import (
    collect_candidate_peers,
    prepare_send_window,
    round_robin_peers,
    send_budget_blocked,
)


@dataclass
class SendWindowState:
    start_ts: float = 0.0
    count: int = 0
    last_tx_ts: float = 0.0
    rr_offset: int = 0
    last_group_by_peer: Dict[str, str] = field(default_factory=dict)


@dataclass
class SendAction:
    kind: str
    peer_norm: str = ""
    rec: Optional[Dict[str, Any]] = None
    payload: bytes = b""
    text: str = ""
    cmp_name: str = ""
    attempts_next: int = 0
    reason: str = ""
    rr_next_offset: int = 0
    group_key: str = ""


class V3SendWorker:
    def __init__(self, state: Optional[SendWindowState] = None) -> None:
        self.state = state or SendWindowState()

    def next_action(
        self,
        *,
        now: float,
        rate_s: float,
        parallel: int,
        intra_gap_s: float,
        pending_by_peer: Dict[str, Dict[str, Dict[str, Any]]],
        tracked_peers: Iterable[str],
        get_peer_state: Callable[[str], Any],
        norm_id_for_filename: Callable[[str], str],
        self_id: str,
        max_seconds: float,
        max_plain: int,
        max_bytes: int,
        build_wire_pt_fn: Callable[[Dict[str, Any], int], bytes],
        pack_payload_fn: Callable[[Dict[str, Any], Any, float], bytes],
    ) -> SendAction:
        self.state.start_ts, self.state.count, self.state.last_tx_ts = prepare_send_window(
            now=now,
            rate_s=rate_s,
            send_window_start_ts=self.state.start_ts,
            send_window_count=self.state.count,
            send_window_last_tx_ts=self.state.last_tx_ts,
        )
        if send_budget_blocked(
            now=now,
            rate_s=rate_s,
            send_window_count=self.state.count,
            parallel=parallel,
            intra_gap_s=intra_gap_s,
            send_window_last_tx_ts=self.state.last_tx_ts,
        ):
            return SendAction(kind="none")

        peers_sorted = collect_candidate_peers(list(pending_by_peer.keys()), tracked_peers)
        if not peers_sorted:
            return SendAction(kind="none")
        n_peers = len(peers_sorted)
        start, ordered_peers = round_robin_peers(peers_sorted, self.state.rr_offset)

        for i, peer_norm in ordered_peers:
            norm_peer = norm_id_for_filename(peer_norm)
            if norm_peer:
                peer_norm = norm_peer
            st = get_peer_state(peer_norm)
            if not st:
                continue
            if not getattr(st, "key_ready", False):
                if not getattr(st, "force_key_req", False):
                    continue
                if peer_norm == self_id:
                    return SendAction(kind="set_self_aes", peer_norm=peer_norm)
                if now >= float(getattr(st, "next_key_req_ts", 0.0) or 0.0):
                    return SendAction(kind="key_request_due", peer_norm=peer_norm)
                continue

            items = list((pending_by_peer.get(peer_norm) or {}).values())
            if not items:
                continue
            last_group = str(self.state.last_group_by_peer.get(peer_norm, "") or "")
            def _item_priority(rec: Dict[str, Any]) -> tuple[int, float, float, float]:
                frame_type = str(rec.get("relay_frame_type") or "")
                pri = {
                    "data": 0,
                    "rekey1": 1,
                    "rekey2": 1,
                    "rekey3": 1,
                    "caps": 2,
                    "caps_req": 2,
                    "end_ack": 2,
                    "hop_ack": 2,
                    "token_withdraw": 3,
                    "token_adv": 4,
                }.get(frame_type, 2)
                if frame_type == "data":
                    # Prefer fresh data parts over retries of older parts.
                    # Without this, a few slow retrying fragments can block the
                    # rest of a large message for minutes on high-RTT links.
                    group_key = str(
                        rec.get("group_id")
                        or rec.get("relay_msg_hex")
                        or rec.get("msg_hex")
                        or ""
                    )
                    same_group_penalty = 1.0 if (last_group and group_key == last_group) else 0.0
                    attempts = float(rec.get("attempts", 0) or 0.0)
                    part = float(rec.get("part", 0) or 0.0)
                    created = float(rec.get("created", 0.0) or 0.0)
                    return (pri, same_group_penalty, attempts, part + (created * 1e-9))
                return (
                    pri,
                    float(rec.get("created", 0.0) or 0.0),
                    0.0,
                    0.0,
                )

            items.sort(key=_item_priority)
            for rec in items:
                if record_is_expired(rec, now=now, max_seconds=max_seconds):
                    return SendAction(
                        kind="timeout_drop",
                        peer_norm=peer_norm,
                        rec=rec,
                        reason="timeout",
                    )
                if not record_retry_due(rec, now=now):
                    continue
                if not getattr(st, "aes", None):
                    return SendAction(kind="need_aes", peer_norm=peer_norm)
                send_plan = prepare_record_send(
                    rec,
                    now=now,
                    max_plain=max_plain,
                    max_bytes=max_bytes,
                    build_wire_pt_fn=build_wire_pt_fn,
                    pack_payload_fn=lambda item, ts: pack_payload_fn(item, st, ts),
                )
                if str(send_plan["status"]) == "drop":
                    return SendAction(
                        kind="drop",
                        peer_norm=peer_norm,
                        rec=rec,
                        text=str(send_plan["text"]),
                        cmp_name=str(send_plan["cmp_name"]),
                        attempts_next=int(send_plan["attempts_next"]),
                        reason=str(send_plan["reason"]),
                    )
                return SendAction(
                    kind="send_ready",
                    peer_norm=peer_norm,
                    rec=rec,
                    payload=bytes(send_plan["payload"]),
                    text=str(send_plan["text"]),
                    cmp_name=str(send_plan["cmp_name"]),
                    attempts_next=int(send_plan["attempts_next"]),
                    rr_next_offset=(start + i + 1) % max(1, n_peers),
                    group_key=str(
                        rec.get("group_id")
                        or rec.get("relay_msg_hex")
                        or rec.get("msg_hex")
                        or ""
                    ),
                )
        return SendAction(kind="none")

    def mark_sent(self, *, now: float, rr_next_offset: int, peer_norm: str = "", group_key: str = "") -> None:
        self.state.count += 1
        self.state.last_tx_ts = float(now)
        self.state.rr_offset = int(rr_next_offset)
        if peer_norm and group_key:
            self.state.last_group_by_peer[str(peer_norm)] = str(group_key)
