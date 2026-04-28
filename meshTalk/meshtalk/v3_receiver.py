#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import struct
from typing import Any, Callable, Dict, List, Optional, Tuple

from meshtalk.relay_protocol import RELAY_TYPE_HOP_ACK


def detect_legacy_control_drop(
    raw_pt: bytes,
    *,
    peer_norm: str,
    from_id: Optional[str],
    caps_req_prefix: bytes,
    caps_ctrl_prefix: bytes,
    rekey1_prefix: bytes,
    rekey2_prefix: bytes,
    rekey3_prefix: bytes,
) -> Optional[str]:
    if peer_norm and from_id:
        if raw_pt == caps_req_prefix:
            return "caps_req"
        if raw_pt.startswith(caps_ctrl_prefix) and len(raw_pt) >= (len(caps_ctrl_prefix) + 1):
            return "caps"
    if raw_pt.startswith(rekey1_prefix) and len(raw_pt) == (3 + 4 + 32) and peer_norm and from_id:
        return "rk1"
    if raw_pt.startswith(rekey2_prefix) and len(raw_pt) == (3 + 4 + 32) and peer_norm and from_id:
        return "rk2"
    if raw_pt.startswith(rekey3_prefix) and len(raw_pt) == (3 + 4) and peer_norm and from_id:
        return "rk3"
    return None


def learn_relay_neighbor(
    relay_state: Any,
    peer_norm: str,
    relay_frame: Any,
    *,
    relay_token_for_peer: Callable[[str, int], bytes],
    now: float,
) -> None:
    if not peer_norm:
        return
    relay_state.update_neighbor(peer_norm, now=now)
    relay_state.learn_token(relay_token_for_peer(peer_norm, relay_frame.epoch_slot), peer_norm, now=now)


def compute_end_ack_forward(relay_state: Any, relay_frame: Any, peer_norm: str) -> List[str]:
    end_ack_key = b"\xEE" + bytes(relay_frame.msg_id or b"")[1:8]
    should_fwd, next_peers = relay_state.should_forward(
        msg_id=end_ack_key,
        from_peer=peer_norm or "",
        ttl=int(relay_frame.ttl),
        relay_token=relay_frame.return_token,
        max_candidates=1,
    )
    if should_fwd and next_peers:
        return list(next_peers)
    return []


def parse_token_adv_score(relay_frame: Any) -> int:
    if len(relay_frame.body) < 2:
        return 0
    return int(struct.unpack(">H", relay_frame.body[:2])[0])


def update_caps_from_body(
    peer_state: Any,
    body: bytes,
    *,
    parse_caps_frame: Callable[[bytes], Optional[Dict[str, Any]]],
    parse_caps_versions: Callable[[Any], List[int]],
    supported_mc_modes: List[int],
    now: float,
) -> Optional[Dict[str, Any]]:
    caps = parse_caps_frame(bytes(body or b"")) or {}
    if not isinstance(caps, dict) or not caps:
        return None
    peer_state.caps = {str(k): str(v) for k, v in caps.items()}
    peer_state.caps_recv_ts = float(now)
    wire_versions = parse_caps_versions(caps.get("wire"))
    if wire_versions:
        peer_state.peer_wire_versions = set(wire_versions)
    msg_versions = parse_caps_versions(caps.get("msg"))
    if msg_versions:
        peer_state.peer_msg_versions = set(msg_versions)
    mc_versions = parse_caps_versions(caps.get("mc"))
    if mc_versions:
        peer_state.peer_mc_versions = {1}
        local_modes = {int(m) for m in (supported_mc_modes or [])}
        peer_state.compression_modes = {int(m) for m in mc_versions if int(m) in local_modes}
    aad_raw = str(caps.get("aad", "") or "").strip().lower()
    if aad_raw:
        peer_state.aad_type_bound = aad_raw in ("1", "true", "yes", "on")
    return {str(k): str(v) for k, v in caps.items()}


RelayIncomingRecord = Dict[str, Any]


def ingest_relay_fragment(relay_incoming: Dict[str, RelayIncomingRecord], peer_norm: str, relay_frame: Any) -> Tuple[RelayIncomingRecord, bool]:
    relay_key = f"{peer_norm or '-'}:{relay_frame.msg_id.hex()}"
    rec = relay_incoming.get(relay_key)
    if rec is None:
        rec = {
            "total": int(relay_frame.frag_total),
            "parts": {},
            "seen_parts": set(),
            "compression": None,
        }
        relay_incoming[relay_key] = rec
    frag_index = int(relay_frame.frag_index)
    if frag_index not in rec["seen_parts"]:
        rec["seen_parts"].add(frag_index)
        rec["parts"][frag_index] = bytes(relay_frame.body or b"")
    return rec, len(rec["parts"]) >= int(rec["total"])


def decode_completed_relay_text(rec: RelayIncomingRecord, *, decompress_text: Callable[[bytes], str]) -> Tuple[str, int, bytes]:
    blob = b"".join(bytes(rec["parts"].get(i, b"")) for i in range(1, int(rec["total"]) + 1))
    compression_v3 = int(blob[0]) if blob else 0
    msg_blob = bytes(blob[1:]) if len(blob) > 0 else b""
    if compression_v3 == 1:
        try:
            text = decompress_text(msg_blob)
        except Exception:
            text = msg_blob.decode("utf-8", errors="replace")
    else:
        text = msg_blob.decode("utf-8", errors="replace")
    return text, compression_v3, msg_blob
