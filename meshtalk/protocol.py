#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import hashlib
import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from meshtalk_utils import (
    compress_for_encrypt_with_method,
    compression_method_from_payload,
    maybe_decompress_after_decrypt,
)


PROTO_VERSION = 1
TYPE_MSG = 1
TYPE_ACK = 2


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def load_priv(path: str) -> x25519.X25519PrivateKey:
    raw = b64d(open(path, "r", encoding="utf-8").read().strip())
    return x25519.X25519PrivateKey.from_private_bytes(raw)


def load_pub(path: str) -> x25519.X25519PublicKey:
    raw = b64d(open(path, "r", encoding="utf-8").read().strip())
    return x25519.X25519PublicKey.from_public_bytes(raw)


def derive_key(priv: x25519.X25519PrivateKey, peer: x25519.X25519PublicKey) -> bytes:
    shared = priv.exchange(peer)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"meshTalk v1",
        info=b"meshTalk v1",
    )
    return hkdf.derive(shared)


def pub_fingerprint(pub_raw: bytes) -> str:
    """Short stable fingerprint for UI/logs (SHA-256, 16 hex chars)."""
    try:
        raw = bytes(pub_raw)
    except Exception:
        raw = b""
    return hashlib.sha256(raw).hexdigest()[:16]


class PeerKeyPinnedError(Exception):
    def __init__(self, peer_id_norm: str, old_fp: str, new_fp: str) -> None:
        super().__init__(f"pinned key mismatch for {peer_id_norm}: {old_fp} != {new_fp}")
        self.peer_id_norm = peer_id_norm
        self.old_fp = old_fp
        self.new_fp = new_fp


def pack_message(
    msg_type: int,
    msg_id: bytes,
    aes: AESGCM,
    plaintext: bytes,
    allow_payload_compress: bool = True,
    bind_aad_type: bool = False,
) -> Tuple[bytes, str]:
    nonce = os.urandom(12)
    if allow_payload_compress:
        pt_wrapped, compression_method = compress_for_encrypt_with_method(plaintext)
    else:
        pt_wrapped = plaintext
        compression_method = "none"
    aad = msg_id
    if bind_aad_type:
        aad = bytes([PROTO_VERSION, int(msg_type) & 0xFF]) + msg_id
    ct = aes.encrypt(nonce, pt_wrapped, aad)
    return bytes([PROTO_VERSION, msg_type]) + msg_id + nonce + ct, compression_method


def try_unpack_message(
    payload: bytes, aes: AESGCM, bind_aad_type: bool = False
) -> Tuple[str, Optional[int], Optional[bytes], Optional[bytes], str]:
    if len(payload) < (1 + 1 + 8 + 12 + 16):
        return ("nope", None, None, None, "n/a")
    ver = payload[0]
    if ver != PROTO_VERSION:
        return ("nope", None, None, None, "n/a")
    msg_type = payload[1]
    if msg_type not in (TYPE_MSG, TYPE_ACK):
        return ("nope", None, None, None, "n/a")
    msg_id = payload[2:10]
    nonce = payload[10:22]
    ct = payload[22:]
    try:
        aad_v1 = msg_id
        aad_v2 = bytes([ver, int(msg_type) & 0xFF]) + msg_id
        aad_first = aad_v2 if bind_aad_type else aad_v1
        aad_second = aad_v1 if bind_aad_type else aad_v2
        try:
            pt = aes.decrypt(nonce, ct, aad_first)
        except Exception:
            pt = aes.decrypt(nonce, ct, aad_second)
    except Exception:
        return ("decrypt_fail", msg_type, msg_id, None, "n/a")
    compression_method = compression_method_from_payload(pt)
    pt = maybe_decompress_after_decrypt(pt)
    return ("ok", msg_type, msg_id, pt, compression_method)


def parse_payload(raw) -> Optional[bytes]:
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    if isinstance(raw, str):
        try:
            return base64.b64decode(raw)
        except Exception:
            return None
    return None

