#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Callable

from meshtalk.relay_protocol import build_end_ack_frame, decrement_ttl, serialize_frame as serialize_relay_frame
from meshtalk.v3_dispatch import build_recv_event, plan_ack_frame, plan_data_forward, plan_token_adv_frame
from meshtalk.v3_receive_effects import (
    handle_ack_effects,
    handle_data_forward_effects_direct,
    handle_data_local_delivery_effects,
    handle_token_adv_effects,
)
from meshtalk.v3_receiver import decode_completed_relay_text, ingest_relay_fragment


def process_ack_frame(
    *,
    relay_frame: Any,
    peer_norm: str,
    ack_plan_fn: Callable[[Any], Any],
    ack_effects_fn: Callable[[Any, Any], None],
) -> None:
    ack_plan = ack_plan_fn(relay_frame)
    ack_effects_fn(relay_frame, ack_plan)


def process_ack_frame_direct(
    *,
    relay_frame: Any,
    relay_state: Any,
    peer_norm: str,
    ack_part: int,
    token_matches_self: bool,
    consume_hop_ack_fn: Callable[[bytes, int, str], Any],
    queue_relay_prebuilt_fn: Callable[[str, bytes, str, str], bool],
    ui_emit_fn: Callable[[str, Any], None],
    ts_local_fn: Callable[[], str],
) -> bool:
    ack_plan = plan_ack_frame(
        relay_state,
        relay_frame,
        peer_norm=peer_norm,
        ack_part=ack_part,
        token_matches_self=token_matches_self,
    )
    handle_ack_effects(
        relay_frame=relay_frame,
        ack_plan=ack_plan,
        peer_norm=peer_norm,
        consume_hop_ack_fn=consume_hop_ack_fn,
        queue_relay_prebuilt_fn=lambda peer, payload_raw: queue_relay_prebuilt_fn(
            peer,
            payload_raw,
            f"endack:{relay_frame.msg_id.hex()}",
            "end_ack_forward",
        ),
        serialize_decremented_fn=lambda item: serialize_relay_frame(decrement_ttl(item)),
        ui_emit_fn=ui_emit_fn,
        ts_local_fn=ts_local_fn,
    )


def process_token_adv_frame(
    *,
    relay_frame: Any,
    token_adv_plan_fn: Callable[[Any], Any],
    token_adv_effects_fn: Callable[[Any, Any], None],
) -> None:
    plan = token_adv_plan_fn(relay_frame)
    token_adv_effects_fn(relay_frame, plan)


def process_token_adv_frame_direct(
    *,
    relay_frame: Any,
    relay_state: Any,
    peer_norm: str,
    now: float,
    queue_relay_prebuilt_fn: Callable[[str, bytes, str, str], bool],
    ui_emit_fn: Callable[[str, Any], None],
    ts_local_fn: Callable[[], str],
) -> None:
    plan = plan_token_adv_frame(
        relay_state,
        relay_frame,
        peer_norm=peer_norm,
        now=now,
    )
    handle_token_adv_effects(
        relay_frame=relay_frame,
        token_adv_plan=plan,
        peer_norm=peer_norm,
        queue_relay_prebuilt_fn=lambda peer, payload_raw: queue_relay_prebuilt_fn(
            peer,
            payload_raw,
            f"adv:{relay_frame.relay_token.hex()}",
            "token_adv_forward",
        ),
        serialize_decremented_fn=lambda item: serialize_relay_frame(decrement_ttl(item)),
        ui_emit_fn=ui_emit_fn,
        ts_local_fn=ts_local_fn,
    )


def process_data_frame(
    *,
    relay_frame: Any,
    ingest_fn: Callable[[Any], Any],
    local_deliver: bool,
    decode_local_fn: Callable[[Any], Any],
    local_effects_fn: Callable[[Any, Any], None],
    forward_plan_fn: Callable[[Any], Any],
    forward_effects_fn: Callable[[Any, Any], None],
) -> None:
    rec, all_parts_ready = ingest_fn(relay_frame)
    if local_deliver and all_parts_ready:
        recv_event = decode_local_fn(rec)
        local_effects_fn(relay_frame, recv_event)
        return
    next_peers = forward_plan_fn(relay_frame)
    if next_peers:
        forward_effects_fn(relay_frame, next_peers)


def process_data_frame_direct(
    *,
    relay_frame: Any,
    relay_incoming: Any,
    peer_norm: str,
    packet: Any,
    local_deliver: bool,
    relay_state: Any,
    now: float,
    decompress_text_fn: Callable[[bytes], tuple[str, str]],
    from_id: str,
    peer_state: Any,
    send_relay_control_frame_fn: Callable[[str, Any, bytes], bool],
    pending_by_peer: Any,
    pending_lock: Any,
    save_state_fn: Callable[[Any], None],
    ui_emit_fn: Callable[[str, Any], None],
    ts_local_fn: Callable[[], str],
) -> bool:
    rec, all_parts_ready = ingest_relay_fragment(relay_incoming, peer_norm, relay_frame)
    if local_deliver and all_parts_ready:
        text, compression_v3, msg_blob = decode_completed_relay_text(rec, decompress_text=decompress_text_fn)
        recv_event = build_recv_event(peer_norm, relay_frame, packet, text, compression_v3, chunk_payload=msg_blob)
        handle_data_local_delivery_effects(
            relay_frame=relay_frame,
            peer_norm=peer_norm,
            recv_event=recv_event,
            relay_incoming=relay_incoming,
            send_end_ack_fn=lambda item: bool(from_id) and send_relay_control_frame_fn(
                from_id,
                peer_state,
                build_end_ack_frame(
                    msg_id=item.msg_id,
                    return_token=item.return_token,
                    ttl=5,
                    epoch_slot=item.epoch_slot,
                ),
            ),
            ui_emit_fn=ui_emit_fn,
        )
        return False
    next_peers = plan_data_forward(relay_state, relay_frame, peer_norm=peer_norm)
    if next_peers:
        return handle_data_forward_effects_direct(
            relay_frame=relay_frame,
            next_peers=next_peers,
            pending_by_peer=pending_by_peer,
            created_ts=now,
            pending_lock=pending_lock,
            save_state_fn=save_state_fn,
            serialize_decremented_fn=lambda item: serialize_relay_frame(decrement_ttl(item)),
            ui_emit_fn=ui_emit_fn,
            ts_local_fn=ts_local_fn,
        )
    return False
