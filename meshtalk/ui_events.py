from __future__ import annotations

from typing import Dict, Optional, Sequence, Tuple


def as_optional_float(value: object) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def parse_trace_update_payload(payload: object) -> Optional[Tuple[str, str, float]]:
    if not isinstance(payload, (tuple, list)) or len(payload) < 3:
        return None
    peer_norm = str(payload[0] or "")
    trace_id = str(payload[1] or "")
    if not peer_norm or not trace_id:
        return None
    try:
        attempts_val = float(payload[2])
    except Exception:
        attempts_val = 0.0
    return peer_norm, trace_id, attempts_val


def parse_recv_payload(payload: object) -> Optional[Dict[str, object]]:
    if not isinstance(payload, tuple) or len(payload) < 8:
        return None
    result: Dict[str, object] = {
        "from_id": payload[0],
        "text": payload[1],
        "fwd_hops": payload[2],
        "delivery": payload[3],
        "group_id": payload[4],
        "part": payload[5],
        "total": payload[6],
        "attempt_in": payload[7],
        "chunk_b64": payload[8] if len(payload) >= 9 else None,
        "compression_flag": 0,
        "legacy_codec": None,
        "payload_cmp": "none",
        "compact_wire": False,
    }
    if len(payload) >= 13:
        result["compression_flag"] = int(payload[9] or 0)
        result["legacy_codec"] = payload[10]
        result["payload_cmp"] = str(payload[11] or "none")
        result["compact_wire"] = bool(payload[12])
    elif len(payload) == 12:
        result["compression_flag"] = int(payload[9] or 0)
        result["legacy_codec"] = payload[10]
        result["payload_cmp"] = str(payload[11] or "none")
    elif len(payload) == 11:
        result["legacy_codec"] = payload[9]
        result["compact_wire"] = bool(payload[10])
        result["payload_cmp"] = str(payload[9] or "none")
    else:
        for item in list(payload[9:]):
            if isinstance(item, bool):
                result["compact_wire"] = item
            elif isinstance(item, (int, float)) and int(item) in (0, 1):
                result["compression_flag"] = int(item)
            elif isinstance(item, str):
                low = item.lower().strip()
                if low in ("none", "mc", "deflate", "zlib", "bz2", "lzma"):
                    result["payload_cmp"] = low
                    if low in ("deflate", "zlib", "bz2", "lzma"):
                        result["legacy_codec"] = low
                else:
                    result["legacy_codec"] = item
    return result


def parse_recv_plain_payload(payload: object) -> Optional[Tuple[str, str, str, str]]:
    if not isinstance(payload, (tuple, list)) or len(payload) < 3:
        return None
    peer_norm = str(payload[0] or "")
    text_plain = str(payload[1] or "")
    msg_id_plain = str(payload[2] or "")
    dialog_id_plain = peer_norm
    if len(payload) >= 4:
        try:
            candidate = str(payload[3] or "").strip()
        except Exception:
            candidate = ""
        if candidate:
            dialog_id_plain = candidate
    if not (peer_norm and text_plain and msg_id_plain):
        return None
    return peer_norm, text_plain, msg_id_plain, dialog_id_plain


def parse_queued_payload(payload: object) -> Optional[Tuple[str, Optional[str], Optional[int], Optional[int], Optional[str]]]:
    if not isinstance(payload, tuple) or not payload:
        return None
    peer_norm = str(payload[0] or "")
    if len(payload) >= 5:
        try:
            nbytes = int(payload[2] or 0)
        except Exception:
            nbytes = 0
        try:
            parts = int(payload[3] or 0)
        except Exception:
            parts = 0
        return peer_norm, str(payload[1] or ""), nbytes, parts, str(payload[4] or "")
    if len(payload) >= 2:
        return peer_norm, str(payload[1] or ""), None, None, None
    return None


def update_outgoing_ack_tracker(store: Dict[str, Dict[str, object]], payload: object) -> Optional[Tuple[str, str, float, Optional[float], Optional[float], Optional[float], Tuple[int, int]]]:
    if not isinstance(payload, (tuple, list)) or len(payload) < 7:
        return None
    peer_norm, group_id, delivery, attempts, total, fwd_hops, ack_hops = payload
    group_key = str(group_id)
    rec = store.get(group_key) or {
        "total": int(total),
        "acked": 0,
        "attempts_sum": 0.0,
        "delivery": delivery,
        "fwd_sum": 0.0,
        "fwd_n": 0,
        "ack_sum": 0.0,
        "ack_n": 0,
    }
    rec["total"] = int(total)
    rec["acked"] = int(rec.get("acked", 0)) + 1
    rec["attempts_sum"] = float(rec.get("attempts_sum", 0.0)) + float(attempts)
    rec["delivery"] = delivery
    if fwd_hops is not None:
        rec["fwd_sum"] = float(rec.get("fwd_sum", 0.0)) + float(fwd_hops)
        rec["fwd_n"] = int(rec.get("fwd_n", 0)) + 1
    if ack_hops is not None:
        rec["ack_sum"] = float(rec.get("ack_sum", 0.0)) + float(ack_hops)
        rec["ack_n"] = int(rec.get("ack_n", 0)) + 1
    store[group_key] = rec
    avg_attempts = None
    if rec.get("acked", 0):
        avg_attempts = float(rec.get("attempts_sum", 0.0)) / float(rec.get("acked", 1))
    avg_fwd = None
    if rec.get("fwd_n", 0):
        avg_fwd = float(rec.get("fwd_sum", 0.0)) / float(rec.get("fwd_n", 1))
    avg_ack = None
    if rec.get("ack_n", 0):
        avg_ack = float(rec.get("ack_sum", 0.0)) / float(rec.get("ack_n", 1))
    packets = (int(rec["acked"]), int(rec["total"]))
    if rec["acked"] >= rec["total"]:
        store.pop(group_key, None)
    return str(peer_norm), group_key, float(rec["delivery"]), avg_attempts, avg_fwd, avg_ack, packets


def parse_peer_meta_records(
    payload: object,
    normalize_peer_id,
) -> Dict[str, Dict[str, float]]:
    records: Dict[str, Dict[str, float]] = {}
    if not isinstance(payload, dict):
        return records
    for peer_id_raw, meta_raw in payload.items():
        if not isinstance(peer_id_raw, str) or not isinstance(meta_raw, dict):
            continue
        peer_norm = normalize_peer_id(peer_id_raw)
        if not peer_norm:
            continue
        rec: Dict[str, float] = {}
        for src_key, dst_key in (
            ("last_seen_ts", "last_seen_ts"),
            ("device_seen_ts", "device_seen_ts"),
            ("key_confirmed_ts", "key_confirmed_ts"),
        ):
            try:
                val = meta_raw.get(src_key)
                if isinstance(val, (int, float)) and float(val) > 0.0:
                    rec[dst_key] = float(val)
            except Exception:
                pass
        if rec:
            records[peer_norm] = rec
    return records


def parse_groups_config(payload: object) -> Dict[str, set[str]]:
    groups: Dict[str, set[str]] = {}
    if not isinstance(payload, dict):
        return groups
    for key, value in payload.items():
        if isinstance(key, str) and isinstance(value, list):
            groups[key] = set(value)
    return groups
