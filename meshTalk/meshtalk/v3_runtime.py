#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import struct
from typing import Any, Dict, List, Optional, Tuple

from meshtalk.relay_protocol import (
    RELAY_TYPE_CAPS,
    RELAY_TYPE_CAPS_REQ,
    RELAY_TYPE_DATA,
    RELAY_TYPE_END_ACK,
    RELAY_TYPE_HOP_ACK,
    RELAY_TYPE_REKEY1,
    RELAY_TYPE_REKEY2,
    RELAY_TYPE_REKEY3,
    RELAY_TYPE_TOKEN_ADV,
    RELAY_TYPE_TOKEN_WITHDRAW,
    build_data_frame,
    build_hop_ack_frame,
    current_epoch_slot,
    parse_frame as parse_relay_frame,
)
from meshtalk.protocol import b64d, b64e
from meshtalk.envelope_v3 import pack_envelope_v3


def relay_frame_type_name(frame_type: int) -> str:
    return {
        RELAY_TYPE_DATA: "data",
        RELAY_TYPE_HOP_ACK: "hop_ack",
        RELAY_TYPE_END_ACK: "end_ack",
        RELAY_TYPE_TOKEN_ADV: "token_adv",
        RELAY_TYPE_TOKEN_WITHDRAW: "token_withdraw",
        RELAY_TYPE_CAPS_REQ: "caps_req",
        RELAY_TYPE_CAPS: "caps",
        RELAY_TYPE_REKEY1: "rekey1",
        RELAY_TYPE_REKEY2: "rekey2",
        RELAY_TYPE_REKEY3: "rekey3",
    }.get(int(frame_type), "control")


def duplicate_requires_hop_ack(frame_type: int) -> bool:
    return int(frame_type) in {
        int(RELAY_TYPE_DATA),
        int(RELAY_TYPE_TOKEN_ADV),
        int(RELAY_TYPE_CAPS_REQ),
        int(RELAY_TYPE_CAPS),
        int(RELAY_TYPE_REKEY1),
        int(RELAY_TYPE_REKEY2),
        int(RELAY_TYPE_REKEY3),
    }


def decode_hop_ack_part(frame_obj: object) -> int:
    frag_index = int(getattr(frame_obj, "frag_index", 1) or 1)
    if int(getattr(frame_obj, "frame_type", 0) or 0) == int(RELAY_TYPE_HOP_ACK):
        body = bytes(getattr(frame_obj, "body", b"") or b"")
        if len(body) >= 2:
            try:
                frag_index = max(1, int(struct.unpack(">H", body[:2])[0]))
            except Exception:
                frag_index = int(getattr(frame_obj, "frag_index", 1) or 1)
    return max(1, int(frag_index))


def build_prebuilt_relay_record(
    *,
    raw: bytes,
    group_id: str,
    peer_id: str,
    route_reason: str,
    created_ts: float,
) -> Dict[str, Any]:
    relay_frame = parse_relay_frame(bytes(raw or b""))
    relay_msg_hex = ""
    relay_frag_index = 1
    relay_frag_total = 1
    relay_frame_type = "control"
    if relay_frame is not None:
        relay_msg_hex = str(relay_frame.msg_id.hex())
        relay_frag_index = decode_hop_ack_part(relay_frame)
        relay_frag_total = int(relay_frame.frag_total)
        relay_frame_type = relay_frame_type_name(int(relay_frame.frame_type))
    no_retry = relay_frame_type in {"token_adv"}
    return {
        "id": os.urandom(8).hex(),
        "group": str(group_id or os.urandom(4).hex()),
        "relay_msg_hex": relay_msg_hex,
        "relay_frame_type": relay_frame_type,
        "no_retry": bool(no_retry),
        "part": int(relay_frag_index),
        "total": int(relay_frag_total),
        "text": "",
        "relay_v3": True,
        "relay_prebuilt_b64": b64e(bytes(raw or b"")),
        "relay_ttl": 1,
        "created": float(created_ts),
        "attempts": 0,
        "last_send": 0.0,
        "next_retry_at": 0.0,
        "retry_phase": "active",
        "retry_phase_attempts": 0,
        "next_probe_ts": 0.0,
        "probe_until_ts": 0.0,
        "probe_attempts": 0,
        "peer": str(peer_id or ""),
        "route_id": "relay_v3",
        "route_score": 0.0,
        "route_reason": str(route_reason or "relay_control"),
    }


def pop_matching_relay_pending(
    peer_pending: Dict[str, Dict[str, Any]],
    *,
    frame_msg_id: bytes,
    frame_part: int,
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    relay_mid = bytes(frame_msg_id or b"").hex()
    target_part = max(1, int(frame_part or 1))
    for pending_id, pending_rec in list((peer_pending or {}).items()):
        if not isinstance(pending_rec, dict):
            continue
        if not bool(pending_rec.get("relay_v3", False)):
            continue
        pending_mid = str(pending_rec.get("relay_msg_hex") or pending_rec.get("group") or "").strip().lower()
        pending_part = max(1, int(pending_rec.get("part", 1) or 1))
        if pending_mid == relay_mid and pending_part == target_part:
            return pending_id, peer_pending.pop(pending_id, None)
    return None, None


def build_hop_ack_for_frame(frame_obj: object) -> bytes:
    return build_hop_ack_frame(
        msg_id=getattr(frame_obj, "msg_id", b""),
        return_token=getattr(frame_obj, "return_token", b""),
        frag_index=decode_hop_ack_part(frame_obj),
        epoch_slot=getattr(frame_obj, "epoch_slot", None),
    )


def build_forward_relay_record(
    *,
    frame_obj: object,
    next_peer: str,
    raw_forwarded: bytes,
    created_ts: float,
    route_reason: str = "relay_forward",
) -> Dict[str, Any]:
    return {
        "id": os.urandom(8).hex(),
        "group": getattr(frame_obj, "msg_id", b"").hex(),
        "relay_msg_hex": getattr(frame_obj, "msg_id", b"").hex(),
        "relay_frame_type": relay_frame_type_name(int(getattr(frame_obj, "frame_type", RELAY_TYPE_DATA) or RELAY_TYPE_DATA)),
        "part": int(getattr(frame_obj, "frag_index", 1) or 1),
        "total": int(getattr(frame_obj, "frag_total", 1) or 1),
        "text": "",
        "relay_v3": True,
        "relay_prebuilt_b64": b64e(bytes(raw_forwarded or b"")),
        "relay_ttl": max(0, int(getattr(frame_obj, "ttl", 0) or 0) - 1),
        "created": float(created_ts),
        "attempts": 0,
        "last_send": 0.0,
        "next_retry_at": 0.0,
        "retry_phase": "active",
        "retry_phase_attempts": 0,
        "next_probe_ts": 0.0,
        "probe_until_ts": 0.0,
        "probe_attempts": 0,
        "peer": str(next_peer or ""),
        "route_id": "relay_v3",
        "route_score": 0.0,
        "route_reason": str(route_reason or "relay_forward"),
    }


def build_relay_plaintext_from_record(rec: Dict[str, Any], *, now: float) -> bytes:
    if not bool(rec.get("relay_v3", False)):
        return b""
    prebuilt_b64 = str(rec.get("relay_prebuilt_b64", "") or "")
    if prebuilt_b64:
        try:
            return b64d(prebuilt_b64)
        except Exception:
            return b""
    group_id = str(rec.get("relay_msg_hex") or rec.get("group") or rec.get("id") or "")
    try:
        relay_msg_id = bytes.fromhex(group_id)
    except Exception:
        try:
            relay_msg_id = bytes.fromhex(str(rec.get("id") or "")[:16].ljust(16, "0"))
        except Exception:
            relay_msg_id = b"\x00" * 8
    try:
        body_chunk = b64d(str(rec.get("relay_body_b64", "") or ""))
    except Exception:
        body_chunk = b""
    try:
        relay_token = b64d(str(rec.get("relay_token_b64", "") or ""))
    except Exception:
        relay_token = b""
    try:
        return_token = b64d(str(rec.get("relay_return_token_b64", "") or ""))
    except Exception:
        return_token = b""
    return build_data_frame(
        msg_id=relay_msg_id,
        relay_token=relay_token,
        return_token=return_token,
        body=body_chunk,
        ttl=int(rec.get("relay_ttl", 5) or 5),
        frag_index=int(rec.get("part", 1) or 1),
        frag_total=int(rec.get("total", 1) or 1),
        epoch_slot=current_epoch_slot(now=float(rec.get("created", now) or now)),
    )


def pack_v3_record(rec: Dict[str, Any], aes: Any, *, now: float) -> bytes:
    pt = build_relay_plaintext_from_record(rec, now=now)
    if not pt:
        return b""
    try:
        msg_id = bytes.fromhex(str(rec.get("id") or "")[:16].ljust(16, "0"))
    except Exception:
        msg_id = os.urandom(8)
    return pack_envelope_v3(msg_id, aes, pt)


def pack_v3_record_for_peer_state(rec: Dict[str, Any], peer_state: Any, now: float) -> bytes:
    aes = getattr(peer_state, "aes", None)
    return pack_v3_record(rec, aes, now=now)
