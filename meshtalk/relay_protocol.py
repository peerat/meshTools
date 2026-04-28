#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import os
import struct
import time
from dataclasses import dataclass
from typing import List, Optional


RELAY_MAGIC = b"MR3"
RELAY_VERSION = 1

RELAY_TYPE_DATA = 1
RELAY_TYPE_HOP_ACK = 2
RELAY_TYPE_END_ACK = 3
RELAY_TYPE_TOKEN_ADV = 4
RELAY_TYPE_TOKEN_WITHDRAW = 5
RELAY_TYPE_CAPS_REQ = 6
RELAY_TYPE_CAPS = 7
RELAY_TYPE_REKEY1 = 8
RELAY_TYPE_REKEY2 = 9
RELAY_TYPE_REKEY3 = 10

RELAY_FLAG_STORE = 0x01
RELAY_FLAG_ALLOW_MULTI = 0x02
RELAY_FLAG_LOW_LATENCY = 0x04
RELAY_FLAG_LOW_NOISE = 0x08

RELAY_HEADER_STRUCT = struct.Struct(">3sBBBBHHI8s8s8s")
RELAY_HEADER_LEN = RELAY_HEADER_STRUCT.size

RELAY_DEFAULT_TTL = 5
RELAY_TOKEN_EPOCH_SECONDS = 15 * 60


@dataclass(frozen=True)
class RelayFrame:
    frame_type: int
    flags: int
    ttl: int
    frag_index: int
    frag_total: int
    epoch_slot: int
    msg_id: bytes
    relay_token: bytes
    return_token: bytes
    body: bytes


def current_epoch_slot(now: Optional[float] = None, slot_seconds: int = RELAY_TOKEN_EPOCH_SECONDS) -> int:
    t = time.time() if now is None else float(now)
    s = max(60, int(slot_seconds))
    return int(max(0.0, t) // float(s))


def generate_msg_id() -> bytes:
    return os.urandom(8)


def derive_relay_token(peer_id_norm: str, epoch_slot: int, salt: bytes = b"meshTalk-relay-v3") -> bytes:
    peer_raw = str(peer_id_norm or "").strip().lower().encode("utf-8", errors="replace")
    slot_raw = struct.pack(">I", int(epoch_slot) & 0xFFFFFFFF)
    digest = hashlib.sha256(bytes(salt) + b"|" + peer_raw + b"|" + slot_raw).digest()
    return digest[:8]


def split_payload_chunks(payload: bytes, max_chunk_size: int) -> List[bytes]:
    chunk = max(1, int(max_chunk_size))
    raw = bytes(payload or b"")
    if not raw:
        return [b""]
    return [raw[i : i + chunk] for i in range(0, len(raw), chunk)]


def build_frame(
    *,
    frame_type: int,
    msg_id: bytes,
    relay_token: bytes,
    return_token: bytes,
    body: bytes = b"",
    flags: int = 0,
    ttl: int = RELAY_DEFAULT_TTL,
    frag_index: int = 1,
    frag_total: int = 1,
    epoch_slot: Optional[int] = None,
) -> bytes:
    et = current_epoch_slot() if epoch_slot is None else int(epoch_slot)
    mid = bytes(msg_id or b"")[:8].ljust(8, b"\x00")
    rtk = bytes(relay_token or b"")[:8].ljust(8, b"\x00")
    ret = bytes(return_token or b"")[:8].ljust(8, b"\x00")
    header = RELAY_HEADER_STRUCT.pack(
        RELAY_MAGIC,
        int(RELAY_VERSION),
        int(frame_type) & 0xFF,
        int(flags) & 0xFF,
        max(0, min(255, int(ttl))),
        max(1, min(0xFFFF, int(frag_index))),
        max(1, min(0xFFFF, int(frag_total))),
        int(et) & 0xFFFFFFFF,
        mid,
        rtk,
        ret,
    )
    return header + bytes(body or b"")


def build_data_frame(
    *,
    msg_id: bytes,
    relay_token: bytes,
    return_token: bytes,
    body: bytes,
    ttl: int = RELAY_DEFAULT_TTL,
    flags: int = 0,
    frag_index: int = 1,
    frag_total: int = 1,
    epoch_slot: Optional[int] = None,
) -> bytes:
    return build_frame(
        frame_type=RELAY_TYPE_DATA,
        msg_id=msg_id,
        relay_token=relay_token,
        return_token=return_token,
        body=body,
        ttl=ttl,
        flags=flags,
        frag_index=frag_index,
        frag_total=frag_total,
        epoch_slot=epoch_slot,
    )


def build_hop_ack_frame(
    *,
    msg_id: bytes,
    return_token: bytes,
    frag_index: int = 1,
    epoch_slot: Optional[int] = None,
) -> bytes:
    return build_frame(
        frame_type=RELAY_TYPE_HOP_ACK,
        msg_id=msg_id,
        relay_token=b"",
        return_token=return_token,
        body=struct.pack(">H", max(1, min(0xFFFF, int(frag_index)))),
        ttl=1,
        epoch_slot=epoch_slot,
    )


def build_end_ack_frame(
    *,
    msg_id: bytes,
    return_token: bytes,
    ttl: int = RELAY_DEFAULT_TTL,
    epoch_slot: Optional[int] = None,
) -> bytes:
    return build_frame(
        frame_type=RELAY_TYPE_END_ACK,
        msg_id=msg_id,
        relay_token=b"",
        return_token=return_token,
        body=b"",
        ttl=ttl,
        epoch_slot=epoch_slot,
    )


def build_token_adv_frame(
    *,
    relay_token: bytes,
    reach_score: int,
    ttl: int = RELAY_DEFAULT_TTL,
    epoch_slot: Optional[int] = None,
) -> bytes:
    body = struct.pack(">H", max(0, min(0xFFFF, int(reach_score))))
    return build_frame(
        frame_type=RELAY_TYPE_TOKEN_ADV,
        msg_id=generate_msg_id(),
        relay_token=relay_token,
        return_token=b"",
        body=body,
        ttl=ttl,
        epoch_slot=epoch_slot,
    )


def build_caps_req_frame(*, msg_id: Optional[bytes] = None, epoch_slot: Optional[int] = None) -> bytes:
    return build_frame(
        frame_type=RELAY_TYPE_CAPS_REQ,
        msg_id=(generate_msg_id() if msg_id is None else msg_id),
        relay_token=b"",
        return_token=b"",
        body=b"",
        ttl=1,
        epoch_slot=epoch_slot,
    )


def build_caps_frame(*, body: bytes, msg_id: Optional[bytes] = None, epoch_slot: Optional[int] = None) -> bytes:
    return build_frame(
        frame_type=RELAY_TYPE_CAPS,
        msg_id=(generate_msg_id() if msg_id is None else msg_id),
        relay_token=b"",
        return_token=b"",
        body=bytes(body or b""),
        ttl=1,
        epoch_slot=epoch_slot,
    )


def build_rekey1_frame(*, rid: bytes, epub: bytes, msg_id: Optional[bytes] = None, epoch_slot: Optional[int] = None) -> bytes:
    return build_frame(
        frame_type=RELAY_TYPE_REKEY1,
        msg_id=(generate_msg_id() if msg_id is None else msg_id),
        relay_token=b"",
        return_token=b"",
        body=bytes(rid or b"")[:4].ljust(4, b"\x00") + bytes(epub or b"")[:32].ljust(32, b"\x00"),
        ttl=1,
        epoch_slot=epoch_slot,
    )


def build_rekey2_frame(*, rid: bytes, repub: bytes, msg_id: Optional[bytes] = None, epoch_slot: Optional[int] = None) -> bytes:
    return build_frame(
        frame_type=RELAY_TYPE_REKEY2,
        msg_id=(generate_msg_id() if msg_id is None else msg_id),
        relay_token=b"",
        return_token=b"",
        body=bytes(rid or b"")[:4].ljust(4, b"\x00") + bytes(repub or b"")[:32].ljust(32, b"\x00"),
        ttl=1,
        epoch_slot=epoch_slot,
    )


def build_rekey3_frame(*, rid: bytes, msg_id: Optional[bytes] = None, epoch_slot: Optional[int] = None) -> bytes:
    return build_frame(
        frame_type=RELAY_TYPE_REKEY3,
        msg_id=(generate_msg_id() if msg_id is None else msg_id),
        relay_token=b"",
        return_token=b"",
        body=bytes(rid or b"")[:4].ljust(4, b"\x00"),
        ttl=1,
        epoch_slot=epoch_slot,
    )


def parse_frame(payload: bytes) -> Optional[RelayFrame]:
    raw = bytes(payload or b"")
    if len(raw) < RELAY_HEADER_LEN:
        return None
    try:
        magic, version, frame_type, flags, ttl, frag_index, frag_total, epoch_slot, msg_id, relay_token, return_token = RELAY_HEADER_STRUCT.unpack(
            raw[:RELAY_HEADER_LEN]
        )
    except Exception:
        return None
    if magic != RELAY_MAGIC or int(version) != int(RELAY_VERSION):
        return None
    if int(frame_type) not in (
        RELAY_TYPE_DATA,
        RELAY_TYPE_HOP_ACK,
        RELAY_TYPE_END_ACK,
        RELAY_TYPE_TOKEN_ADV,
        RELAY_TYPE_TOKEN_WITHDRAW,
        RELAY_TYPE_CAPS_REQ,
        RELAY_TYPE_CAPS,
        RELAY_TYPE_REKEY1,
        RELAY_TYPE_REKEY2,
        RELAY_TYPE_REKEY3,
    ):
        return None
    return RelayFrame(
        frame_type=int(frame_type),
        flags=int(flags),
        ttl=int(ttl),
        frag_index=max(1, int(frag_index)),
        frag_total=max(1, int(frag_total)),
        epoch_slot=int(epoch_slot),
        msg_id=bytes(msg_id),
        relay_token=bytes(relay_token),
        return_token=bytes(return_token),
        body=bytes(raw[RELAY_HEADER_LEN:]),
    )


def decrement_ttl(frame: RelayFrame) -> RelayFrame:
    ttl = max(0, int(frame.ttl) - 1)
    return RelayFrame(
        frame_type=frame.frame_type,
        flags=frame.flags,
        ttl=ttl,
        frag_index=frame.frag_index,
        frag_total=frame.frag_total,
        epoch_slot=frame.epoch_slot,
        msg_id=frame.msg_id,
        relay_token=frame.relay_token,
        return_token=frame.return_token,
        body=frame.body,
    )


def serialize_frame(frame: RelayFrame) -> bytes:
    return build_frame(
        frame_type=frame.frame_type,
        msg_id=frame.msg_id,
        relay_token=frame.relay_token,
        return_token=frame.return_token,
        body=frame.body,
        flags=frame.flags,
        ttl=frame.ttl,
        frag_index=frame.frag_index,
        frag_total=frame.frag_total,
        epoch_slot=frame.epoch_slot,
    )
