from __future__ import annotations

from typing import Any, Callable, Dict


def ingest_incoming_ui_fragment(
    *,
    incoming_state: Dict[str, Dict[str, Any]],
    peer_norm: str,
    group_id: str,
    total: int,
    delivery,
    fwd_hops,
    attempt_in,
    compact_wire: bool,
    compression_flag: int,
    legacy_codec,
    payload_cmp,
    chunk_b64,
    text,
    part,
    recv_now_ts: float,
    effective_payload_cmp_label: Callable[..., str],
    merge_compact_compression: Callable[[int, int], int],
    assemble_incoming_text: Callable[..., tuple[str, bool]],
    infer_compact_cmp_label_from_joined_parts: Callable[..., str | None],
    normalize_compression_name: Callable[[object], str | None],
    infer_compact_norm_from_joined_parts: Callable[..., str | None],
    compression_efficiency_pct: Callable[[int, int], float | None],
    b64d: Callable[[str], bytes],
) -> Dict[str, Any]:
    key = f"{peer_norm}:{group_id}"
    rec = incoming_state.get(key) or {
        "total": total,
        "parts": {},
        "delivery": delivery,
        "hops_sum": 0.0,
        "hops_n": 0,
        "attempts_sum": 0.0,
        "attempts_n": 0,
        "peer": peer_norm,
        "group_id": group_id,
        "compact": bool(compact_wire),
        "compression": int(compression_flag or 0),
        "legacy_codec": (str(legacy_codec) if legacy_codec else None),
        "payload_cmp": effective_payload_cmp_label(
            payload_cmp,
            compact_wire=bool(compact_wire),
            compression_flag=int(compression_flag or 0),
            legacy_codec=legacy_codec,
            chunk_b64=(str(chunk_b64) if chunk_b64 is not None else None),
        ),
        "incoming_started_ts": recv_now_ts,
    }
    if not rec.get("incoming_started_ts"):
        rec["incoming_started_ts"] = recv_now_ts
    rec["total"] = total
    if compact_wire:
        rec["compact"] = True
        rec["compression"] = merge_compact_compression(
            int(rec.get("compression", 0) or 0),
            int(compression_flag or 0),
        )
        rec["legacy_codec"] = (str(legacy_codec) if legacy_codec else None)
    if delivery is not None:
        rec["delivery"] = delivery
    if fwd_hops is not None:
        rec["hops_sum"] = float(rec.get("hops_sum", 0.0)) + float(fwd_hops)
        rec["hops_n"] = int(rec.get("hops_n", 0)) + 1
    if attempt_in is not None:
        rec["attempts_sum"] = float(rec.get("attempts_sum", 0.0)) + float(attempt_in)
        rec["attempts_n"] = int(rec.get("attempts_n", 0)) + 1
    part_key = str(int(part))
    if rec.get("compact", False):
        rec["parts"][part_key] = str(chunk_b64 or "")
    else:
        rec["parts"][part_key] = str(text)
    rec["payload_cmp"] = effective_payload_cmp_label(
        payload_cmp,
        compact_wire=bool(rec.get("compact", False)),
        compression_flag=int(rec.get("compression", 0) or 0),
        legacy_codec=rec.get("legacy_codec"),
        parts=rec.get("parts"),
        chunk_b64=(str(chunk_b64) if chunk_b64 is not None else None),
    )
    rec["last_part"] = int(part)
    incoming_state[key] = rec

    full, decode_ok = assemble_incoming_text(
        rec.get("parts"),
        int(total),
        bool(rec.get("compact", False)),
        int(rec.get("compression", 0) or 0),
        (str(rec.get("legacy_codec")) if rec.get("legacy_codec") else None),
        show_partial=True,
    )
    avg_hops = None
    if rec.get("hops_n", 0):
        avg_hops = float(rec.get("hops_sum", 0.0)) / float(rec.get("hops_n", 1))
    avg_attempts = None
    if rec.get("attempts_n", 0):
        avg_attempts = float(rec.get("attempts_sum", 0.0)) / float(rec.get("attempts_n", 1))
    done_now = len(rec["parts"]) >= int(total)
    status = "decode_error" if (done_now and not decode_ok) else None
    cmp_raw = effective_payload_cmp_label(
        rec.get("payload_cmp"),
        compact_wire=bool(rec.get("compact", False)),
        compression_flag=int(rec.get("compression", 0) or 0),
        legacy_codec=rec.get("legacy_codec"),
        parts=rec.get("parts"),
    )
    try:
        inferred_exact = infer_compact_cmp_label_from_joined_parts(rec.get("parts"), int(total))
    except Exception:
        inferred_exact = None
    if inferred_exact:
        cmp_raw = inferred_exact
    compression_name = normalize_compression_name(cmp_raw)
    if bool(rec.get("compact", False)) and str(compression_name or "").strip().upper() == "MC":
        compression_name = None
    compression_norm = infer_compact_norm_from_joined_parts(rec.get("parts"), int(total))
    if compression_norm:
        compression_norm = str(compression_norm).upper()
    compression_eff_pct = None
    if compression_name and bool(rec.get("compact", False)) and done_now and decode_ok:
        compressed_size = 0
        for part_payload in rec.get("parts", {}).values():
            try:
                compressed_size += len(b64d(str(part_payload)))
            except Exception:
                compressed_size = 0
                break
        if compressed_size > 0:
            compression_eff_pct = compression_efficiency_pct(
                len(full.encode("utf-8")),
                compressed_size,
            )
    rec_received_ts = None
    if done_now:
        try:
            raw_received = float(rec.get("received_at_ts", 0.0) or 0.0)
        except Exception:
            raw_received = 0.0
        if raw_received > 0.0:
            rec_received_ts = raw_received
        else:
            rec_received_ts = recv_now_ts
            rec["received_at_ts"] = rec_received_ts
            incoming_state[key] = rec
    return {
        "key": key,
        "record": rec,
        "full_text": full,
        "decode_ok": bool(decode_ok),
        "avg_hops": avg_hops,
        "avg_attempts": avg_attempts,
        "done_now": bool(done_now),
        "status": status,
        "compression_name": compression_name,
        "compression_eff_pct": compression_eff_pct,
        "compression_norm": compression_norm,
        "received_at_ts": rec_received_ts,
    }
