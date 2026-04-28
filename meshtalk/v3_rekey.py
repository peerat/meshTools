#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from meshtalk.relay_protocol import build_rekey2_frame, build_rekey3_frame


def handle_rekey1(
    peer_state: Any,
    peer_norm: str,
    relay_frame: Any,
    *,
    now: Optional[float] = None,
    derive_aes_fn: Callable[[str, bytes], Any],
) -> Dict[str, Any]:
    ts = time.time() if now is None else float(now)
    rid = bytes(relay_frame.body[:4])
    peer_epub_raw = bytes(relay_frame.body[4:36])
    if peer_state.rekey_candidate_id == rid and peer_state.rekey_candidate_pub and peer_state.rekey_candidate_aes is not None:
        return {
            "response_frame": build_rekey2_frame(
                rid=rid,
                repub=peer_state.rekey_candidate_pub,
                epoch_slot=relay_frame.epoch_slot,
            ),
            "response_aes_override": None,
            "log": None,
            "rid": rid,
        }
    peer_epub = x25519.X25519PublicKey.from_public_bytes(peer_epub_raw)
    rpriv = x25519.X25519PrivateKey.generate()
    repub_raw = rpriv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    eph_shared = rpriv.exchange(peer_epub)
    new_aes = derive_aes_fn(peer_norm, eph_shared)
    if new_aes is None:
        return {"response_frame": None, "response_aes_override": None, "log": None, "rid": rid}
    peer_state.rekey_candidate_id = rid
    peer_state.rekey_candidate_pub = repub_raw
    peer_state.rekey_candidate_aes = new_aes
    peer_state.rekey_candidate_ts = ts
    return {
        "response_frame": build_rekey2_frame(
            rid=rid,
            repub=repub_raw,
            epoch_slot=relay_frame.epoch_slot,
        ),
        "response_aes_override": None,
        "log": f"KEY: rekey candidate ready peer={peer_norm} id={rid.hex()}",
        "rid": rid,
    }


def handle_rekey2(
    peer_state: Any,
    peer_norm: str,
    relay_frame: Any,
    *,
    now: Optional[float] = None,
    derive_aes_fn: Callable[[str, bytes], Any],
    prev_key_grace_seconds: float,
) -> Dict[str, Any]:
    ts = time.time() if now is None else float(now)
    rid = bytes(relay_frame.body[:4])
    peer_repub_raw = bytes(relay_frame.body[4:36])
    if not (bool(getattr(peer_state, "rekey_inflight", False)) and peer_state.rekey_id == rid and peer_state.rekey_priv is not None):
        return {"response_frame": None, "response_aes_override": None, "log": None, "rid": rid}
    peer_repub = x25519.X25519PublicKey.from_public_bytes(peer_repub_raw)
    eph_shared = peer_state.rekey_priv.exchange(peer_repub)
    new_aes = derive_aes_fn(peer_norm, eph_shared)
    if new_aes is None:
        return {"response_frame": None, "response_aes_override": None, "log": None, "rid": rid}
    response_frame = build_rekey3_frame(
        rid=rid,
        epoch_slot=relay_frame.epoch_slot,
    )
    peer_state.prev_aes = peer_state.aes
    peer_state.prev_aes_until_ts = ts + float(prev_key_grace_seconds)
    peer_state.aes = new_aes
    peer_state.last_rekey_ts = ts
    peer_state.rekey_sent_msgs = 0
    peer_state.rekey_inflight = False
    peer_state.rekey_priv = None
    peer_state.rekey_id = b""
    peer_state.rekey_attempts = 0
    peer_state.rekey_next_retry_ts = 0.0
    return {
        "response_frame": response_frame,
        "response_aes_override": new_aes,
        "log": f"KEY: rekey switched (initiator) peer={peer_norm} id={rid.hex()}",
        "rid": rid,
    }


def handle_rekey3(
    peer_state: Any,
    relay_frame: Any,
    *,
    now: Optional[float] = None,
    prev_key_grace_seconds: float,
    peer_norm: str,
) -> Dict[str, Any]:
    ts = time.time() if now is None else float(now)
    rid = bytes(relay_frame.body[:4])
    if not (peer_state.rekey_candidate_aes is not None and peer_state.rekey_candidate_id == rid):
        return {"log": None, "rid": rid}
    peer_state.prev_aes = peer_state.aes
    peer_state.prev_aes_until_ts = ts + float(prev_key_grace_seconds)
    peer_state.aes = peer_state.rekey_candidate_aes
    peer_state.last_rekey_ts = ts
    peer_state.rekey_sent_msgs = 0
    peer_state.rekey_candidate_aes = None
    peer_state.rekey_candidate_id = b""
    peer_state.rekey_candidate_pub = b""
    peer_state.rekey_candidate_ts = 0.0
    return {
        "log": f"KEY: rekey switched (responder) peer={peer_norm} id={rid.hex()}",
        "rid": rid,
    }
