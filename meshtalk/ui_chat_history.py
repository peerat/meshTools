#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional

from meshtalk.ui_helpers import split_chat_timestamp, strip_parenthesized_prefix


def history_has_msg(chat_history: Dict[str, list], dialog_id: str, msg_id: str) -> bool:
    if not msg_id:
        return False
    for entry in chat_history.get(dialog_id, []):
        if isinstance(entry, dict) and entry.get("msg_id") == msg_id:
            return True
    return False


def _extract_outgoing_entry_state(
    *,
    entry: Dict[str, Any],
    normalize_compression_name_fn: Callable[[str], Optional[str]],
) -> Dict[str, Any]:
    text = str(entry.get("text", ""))
    ts, msg = split_chat_timestamp(text, fallback_ts=time.strftime("%H:%M", time.localtime()))
    msg = strip_parenthesized_prefix(msg)
    sent_at_ts = None
    compression_name = None
    compression_eff_pct = None
    compression_norm = None
    old_meta_data = entry.get("meta_data")
    if isinstance(old_meta_data, dict):
        try:
            raw_sent = float(old_meta_data.get("sent_at_ts", 0.0) or 0.0)
        except Exception:
            raw_sent = 0.0
        if raw_sent > 0.0:
            sent_at_ts = raw_sent
        compression_name = normalize_compression_name_fn(str(old_meta_data.get("compression_name", "") or ""))
        try:
            raw_eff = old_meta_data.get("compression_eff_pct")
            if raw_eff is not None:
                compression_eff_pct = float(raw_eff)
        except Exception:
            compression_eff_pct = None
        try:
            raw_norm = str(old_meta_data.get("compression_norm", "") or "").strip()
            compression_norm = raw_norm.upper() if raw_norm else None
        except Exception:
            compression_norm = None
    return {
        "ts": ts,
        "msg": msg,
        "sent_at_ts": sent_at_ts,
        "compression_name": compression_name,
        "compression_eff_pct": compression_eff_pct,
        "compression_norm": compression_norm,
    }


def update_outgoing_delivery_state(
    *,
    chat_history: Dict[str, list],
    dialog_id: str,
    msg_id: str,
    delivery: float,
    attempts: float,
    forward_hops: Optional[float],
    ack_hops: Optional[float],
    packets: Optional[tuple[int, int]],
    format_meta_fn: Callable[..., str],
    normalize_compression_name_fn: Callable[[str], Optional[str]],
    update_dialog_fn: Callable[[str, str, bool], None],
    render_chat_fn: Callable[[str], None],
    refresh_list_fn: Callable[[], None],
    append_history_fn: Callable[..., None],
    current_dialog: Optional[str],
) -> bool:
    entries = chat_history.get(dialog_id, [])
    if not entries:
        return False
    for i in range(len(entries) - 1, -1, -1):
        entry = entries[i]
        if not isinstance(entry, dict):
            continue
        if entry.get("dir") != "out":
            continue
        if entry.get("msg_id") != msg_id:
            continue
        state = _extract_outgoing_entry_state(entry=entry, normalize_compression_name_fn=normalize_compression_name_fn)
        delivered_at_ts = None
        if packets is not None:
            done_now, total_now = packets
            if int(done_now) >= int(total_now):
                delivered_at_ts = time.time()
        entry["meta"] = format_meta_fn(
            delivery,
            attempts,
            forward_hops,
            ack_hops,
            packets,
            delivered_at_ts=delivered_at_ts,
            incoming=False,
            done=(delivered_at_ts is not None),
            row_time_hhmm=state["ts"],
            sent_at_ts=state["sent_at_ts"],
            compression_name=state["compression_name"],
            compression_eff_pct=state["compression_eff_pct"],
            compression_norm=state["compression_norm"],
        )
        meta_data_out: Dict[str, object] = {
            "delivery": delivery,
            "attempts": attempts,
            "forward_hops": forward_hops,
            "ack_hops": ack_hops,
            "incoming": False,
            "done": (delivered_at_ts is not None),
            "compression_name": state["compression_name"],
            "compression_eff_pct": state["compression_eff_pct"],
            "compression_norm": state["compression_norm"],
        }
        if packets is not None:
            meta_data_out["packets"] = (int(packets[0]), int(packets[1]))
        if delivered_at_ts is not None:
            meta_data_out["delivered_at_ts"] = delivered_at_ts
        if state["sent_at_ts"] is not None:
            meta_data_out["sent_at_ts"] = state["sent_at_ts"]
        entry["meta_data"] = meta_data_out
        entry["text"] = f"{state['ts']} {state['msg']}"
        if i == len(entries) - 1:
            update_dialog_fn(dialog_id, entry["text"], False)
        if current_dialog == dialog_id:
            render_chat_fn(dialog_id)
        else:
            refresh_list_fn()
        if packets is not None:
            done, total = packets
            if int(done) >= int(total) and not entry.get("logged"):
                append_history_fn("sent", dialog_id, msg_id, state["msg"], meta_data=meta_data_out)
                entry["logged"] = True
        return True
    return False


def update_outgoing_failed_state(
    *,
    chat_history: Dict[str, list],
    dialog_id: str,
    msg_id: str,
    reason: str,
    attempts: int,
    total: int,
    format_meta_fn: Callable[..., str],
    normalize_compression_name_fn: Callable[[str], Optional[str]],
    update_dialog_fn: Callable[[str, str, bool], None],
    render_chat_fn: Callable[[str], None],
    refresh_list_fn: Callable[[], None],
    current_dialog: Optional[str],
) -> bool:
    entries = chat_history.get(dialog_id, [])
    if not entries:
        return False
    for i in range(len(entries) - 1, -1, -1):
        entry = entries[i]
        if not isinstance(entry, dict):
            continue
        if entry.get("dir") != "out":
            continue
        if entry.get("msg_id") != msg_id:
            continue
        state = _extract_outgoing_entry_state(entry=entry, normalize_compression_name_fn=normalize_compression_name_fn)
        entry["meta"] = format_meta_fn(
            None,
            float(attempts),
            None,
            None,
            (0, int(max(1, total))),
            status=reason,
            sent_at_ts=state["sent_at_ts"],
            compression_name=state["compression_name"],
            compression_eff_pct=state["compression_eff_pct"],
            compression_norm=state["compression_norm"],
        )
        entry["meta_data"] = {
            "delivery": None,
            "attempts": float(attempts),
            "forward_hops": None,
            "ack_hops": None,
            "packets": (0, int(max(1, total))),
            "status": reason,
            "incoming": False,
            "done": False,
            "compression_name": state["compression_name"],
            "compression_eff_pct": state["compression_eff_pct"],
            "compression_norm": state["compression_norm"],
        }
        if state["sent_at_ts"] is not None:
            entry["meta_data"]["sent_at_ts"] = state["sent_at_ts"]
        entry["text"] = f"{state['ts']} {state['msg']}"
        if i == len(entries) - 1:
            update_dialog_fn(dialog_id, entry["text"], False)
        if current_dialog == dialog_id:
            render_chat_fn(dialog_id)
        else:
            refresh_list_fn()
        return True
    return False
