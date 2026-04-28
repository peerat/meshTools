#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ENVELOPE_V3_VERSION = 3
ENVELOPE_V3_TYPE_DATA = 1


def pack_envelope_v3(msg_id: bytes, aes: AESGCM, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    mid = bytes(msg_id or b"")[:8].ljust(8, b"\x00")
    aad = bytes([ENVELOPE_V3_VERSION, ENVELOPE_V3_TYPE_DATA]) + mid
    ct = aes.encrypt(nonce, bytes(plaintext or b""), aad)
    return bytes([ENVELOPE_V3_VERSION, ENVELOPE_V3_TYPE_DATA]) + mid + nonce + ct


def try_unpack_envelope_v3(payload: bytes, aes: AESGCM) -> Tuple[str, Optional[bytes], Optional[bytes]]:
    raw = bytes(payload or b"")
    if len(raw) < (1 + 1 + 8 + 12 + 16):
        return ("nope", None, None)
    if int(raw[0]) != int(ENVELOPE_V3_VERSION):
        return ("nope", None, None)
    if int(raw[1]) != int(ENVELOPE_V3_TYPE_DATA):
        return ("nope", None, None)
    msg_id = bytes(raw[2:10])
    nonce = bytes(raw[10:22])
    ct = bytes(raw[22:])
    aad = bytes([ENVELOPE_V3_VERSION, ENVELOPE_V3_TYPE_DATA]) + msg_id
    try:
        pt = aes.decrypt(nonce, ct, aad)
    except Exception:
        return ("decrypt_fail", msg_id, None)
    return ("ok", msg_id, pt)
