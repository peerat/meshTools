#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from meshtalk.v3_send_effects import (
    activity_record_now,
    handle_drop_action,
    handle_send_success,
    handle_timeout_drop_action,
    metrics_inc_now,
)
from meshtalk.v3_send_record import apply_post_send_state
from meshtalk.v3_sender import peer_fast_profile


def process_non_send_action(
    *,
    action: Any,
    now: float,
    get_peer_state: Callable[[str], Any],
    derive_key_fn: Callable[[Any, Any], bytes],
    priv: Any,
    pub_self: Any,
    wire_id_from_norm: Callable[[str], str],
    send_key_request_fn: Callable[[str], None],
    retry_seconds: float,
    ts_local_fn: Callable[[], str],
    print_fn: Callable[[str], None],
    timeout_drop_fn: Callable[[Any], None],
    drop_fn: Callable[[Any], None],
) -> str:
    if action.kind == "none":
        return "return"
    if action.kind == "set_self_aes":
        st_self = get_peer_state(action.peer_norm)
        if st_self is not None:
            st_self.aes = AESGCM(derive_key_fn(priv, pub_self))
        return "continue"
    if action.kind == "key_request_due":
        st_req = get_peer_state(action.peer_norm)
        if st_req is not None:
            if (now - float(getattr(st_req, "last_key_req_ts", 0.0) or 0.0)) >= 5.0:
                print_fn(f"{ts_local_fn()} KEY: request -> {wire_id_from_norm(action.peer_norm)}")
                send_key_request_fn(action.peer_norm)
            st_req.next_key_req_ts = now + max(1.0, float(retry_seconds))
        return "continue"
    if action.kind == "need_aes":
        return "return"
    if action.kind == "timeout_drop":
        timeout_drop_fn(action)
        return "continue"
    if action.kind == "drop":
        drop_fn(action)
        return "continue"
    return "unhandled"


def process_non_send_action_direct(
    *,
    action: Any,
    now: float,
    get_peer_state: Callable[[str], Any],
    derive_key_fn: Callable[[Any, Any], bytes],
    priv: Any,
    pub_self: Any,
    wire_id_from_norm: Callable[[str], str],
    send_key_request_base_fn: Callable[..., None],
    retry_seconds: float,
    ts_local_fn: Callable[[], str],
    print_fn: Callable[[str], None],
    pending_by_peer: Any,
    save_state_fn: Callable[[Any], None],
    append_history_fn: Callable[[str, str, str, str, str], None],
    pacer: Any,
    routing_ctl: Any,
    ui_emit_fn: Callable[[str, Any], None],
) -> str:
    return process_non_send_action(
        action=action,
        now=now,
        get_peer_state=get_peer_state,
        derive_key_fn=derive_key_fn,
        priv=priv,
        pub_self=pub_self,
        wire_id_from_norm=wire_id_from_norm,
        send_key_request_fn=lambda peer: send_key_request_base_fn(peer, require_confirm=True, reason="await_confirm_retry"),
        retry_seconds=retry_seconds,
        ts_local_fn=ts_local_fn,
        print_fn=print_fn,
        timeout_drop_fn=lambda act: handle_timeout_drop_action(
            action=(
                print_fn(f"DROP: {act.rec['id']} timeout"),
                act,
            )[1],
            pending_by_peer=pending_by_peer,
            save_state_fn=save_state_fn,
            append_history_fn=append_history_fn,
            pacer=pacer,
            routing_ctl=routing_ctl,
            ui_emit_fn=ui_emit_fn,
            ts_local_fn=ts_local_fn,
            now=now,
        ),
        drop_fn=lambda act: handle_drop_action(
            action=(
                print_fn(f"DROP: {act.rec['id']} {act.reason}"),
                act,
            )[1],
            pending_by_peer=pending_by_peer,
            save_state_fn=save_state_fn,
            append_history_fn=append_history_fn,
            ui_emit_fn=ui_emit_fn,
            ts_local_fn=ts_local_fn,
        ),
    )


def finalize_send_success(
    *,
    action: Any,
    now: float,
    get_peer_state: Callable[[str], Any],
    metrics_inc_fn: Callable[[str, float], None],
    activity_record_fn: Callable[[int], None],
    post_send_state_fn: Callable[[Any, Any, int], None],
    commit_send_fn: Callable[[str, Any, str, str], None],
    mark_sent_fn: Callable[[float, int], None],
) -> bool:
    if action.kind != "send_ready" or action.rec is None:
        return False
    peer_norm = action.peer_norm
    rec = action.rec
    attempts_next = int(action.attempts_next)
    st = get_peer_state(peer_norm)
    if not st:
        return False
    activity_record_fn(len(bytes(action.payload or b"")))
    metrics_inc_fn("out_send", 1.0)
    if int(attempts_next) > 1:
        metrics_inc_fn("out_retry", 1.0)
    try:
        relay_frame_type = str((rec or {}).get("relay_frame_type") or "")
        if relay_frame_type == "data":
            st.rekey_sent_msgs = int(getattr(st, "rekey_sent_msgs", 0) or 0) + 1
    except Exception:
        pass
    post_send_state_fn(rec, st, attempts_next)
    commit_send_fn(peer_norm, rec, str(action.text), str(action.cmp_name))
    mark_sent_fn(now, int(action.rr_next_offset))
    return True


def finalize_send_success_direct(
    *,
    action: Any,
    now: float,
    get_peer_state: Callable[[str], Any],
    metrics_inc_base_fn: Callable[..., None],
    activity_record_base_fn: Callable[..., None],
    schedule_next_retry_fn: Callable[[Any, Any, float, float, int], float],
    retry_seconds: float,
    cfg: Any,
    peer_meta: Any,
    pending_by_peer: Any,
    save_state_fn: Callable[[Any], None],
    append_history_fn: Callable[[str, str, str, str, str], None],
    ui_emit_fn: Callable[[str, Any], None],
    ts_local_fn: Callable[[], str],
    proto_version: int,
    send_worker: Any,
) -> bool:
    def _post_send_state(record: Any, peer_state: Any, attempts: int) -> None:
        apply_post_send_state(
            record,
            now=now,
            attempts_next=attempts,
            fast_profile=peer_fast_profile(cfg, peer_meta, action.peer_norm),
            schedule_next_retry_fn=schedule_next_retry_fn,
            peer_state=peer_state,
            retry_seconds=retry_seconds,
        )

    def _commit_send(peer_norm: str, rec: Any, text: str, cmp_name: str) -> None:
        handle_send_success(
            peer_norm=peer_norm,
            rec=rec,
            text=text,
            cmp_name=cmp_name,
            pending_by_peer=pending_by_peer,
            save_state_fn=save_state_fn,
            append_history_fn=append_history_fn,
            ui_emit_fn=ui_emit_fn,
            ts_local_fn=ts_local_fn,
            proto_version=proto_version,
        )

    return finalize_send_success(
        action=action,
        now=now,
        get_peer_state=get_peer_state,
        metrics_inc_fn=lambda name, value: metrics_inc_now(metrics_inc_base_fn, name=name, value=value, now=now),
        activity_record_fn=lambda size: activity_record_now(activity_record_base_fn, now=now, bytes_count=size),
        post_send_state_fn=_post_send_state,
        commit_send_fn=_commit_send,
        mark_sent_fn=lambda sent_now, rr_next: send_worker.mark_sent(
            now=sent_now,
            rr_next_offset=rr_next,
            peer_norm=action.peer_norm,
            group_key=str(getattr(action, "group_key", "") or ""),
        ),
    )
