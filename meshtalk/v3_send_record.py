#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import random
from typing import Any, Callable, Dict, Optional, Tuple


def record_is_expired(rec: Dict[str, Any], *, now: float, max_seconds: float) -> bool:
    created = float(rec.get("created", 0.0) or 0.0)
    return (now - created) > float(max_seconds)


def record_retry_due(rec: Dict[str, Any], *, now: float) -> bool:
    next_retry_at = float(rec.get("next_retry_at", 0.0) or 0.0)
    return now >= next_retry_at


def prepare_record_send(
    rec: Dict[str, Any],
    *,
    now: float,
    max_plain: int,
    max_bytes: int,
    build_wire_pt_fn: Callable[[Dict[str, Any], int], bytes],
    pack_payload_fn: Callable[[Dict[str, Any], float], bytes],
) -> Dict[str, Any]:
    text = str(rec.get("text", ""))
    attempts_next = int(rec.get("attempts", 0) or 0) + 1
    cmp_name = str(rec.get("cmp", "none") or "none")
    pt = build_wire_pt_fn(rec, int(attempts_next))
    if (not pt) or len(pt) > int(max_plain):
        return {
            "status": "drop",
            "reason": "too_long" if pt else "legacy_wire_disabled",
            "text": text,
            "attempts_next": attempts_next,
            "cmp_name": cmp_name,
            "payload": b"",
        }
    payload = pack_payload_fn(rec, now)
    if len(payload) > int(max_bytes):
        return {
            "status": "drop",
            "reason": "payload_too_big",
            "text": text,
            "attempts_next": attempts_next,
            "cmp_name": cmp_name,
            "payload": b"",
        }
    return {
        "status": "ready",
        "reason": "",
        "text": text,
        "attempts_next": attempts_next,
        "cmp_name": cmp_name,
        "payload": payload,
    }


def apply_post_send_state(
    rec: Dict[str, Any],
    *,
    now: float,
    attempts_next: int,
    fast_profile: Tuple[int, int, int],
    schedule_next_retry_fn: Callable[[Dict[str, Any], Any, float, float, int], float],
    peer_state: Any,
    retry_seconds: float,
) -> Dict[str, Any]:
    rec["attempts"] = int(attempts_next)
    rec["last_send"] = float(now)
    if int(attempts_next) == 1:
        fr, fmin, fmax = fast_profile
        if int(fr) > 0:
            rec["fast_left"] = int(fr)
            rec["fast_min_ms"] = int(fmin)
            rec["fast_max_ms"] = int(fmax)
            rec["fast_next_ts"] = float(now) + (random.uniform(float(fmin), float(fmax)) / 1000.0)
            rec["micro_retries_sent"] = 0
    delay_s = schedule_next_retry_fn(rec, peer_state, now, float(retry_seconds), int(attempts_next))
    rec["next_retry_at"] = float(now) + float(delay_s)
    return {
        "attempts": int(rec["attempts"]),
        "next_retry_at": float(rec["next_retry_at"]),
    }
