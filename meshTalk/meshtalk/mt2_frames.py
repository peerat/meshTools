# SPDX-License-Identifier: Apache-2.0

"""
meshTalk protocol v2 plaintext frames that ride inside Meshtastic PRIVATE_APP payload.

These frames are intentionally small to minimize plaintext metadata leakage:
- HELLO is a broadcast presence beacon with no public key.
- KR1/KR2 are unicast key exchange frames with X25519 public key (32 bytes).

CAPS (CP1/CPR) are NOT plaintext: they are encrypted service-info exchanged inside MT-WIRE.
This module only parses CP1 payloads after decryption (so it's still "plaintext" at this layer).
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple


MT2_MAGIC = b"MT"
MT2_FRAME_VER = 1

MT2_F_KR1 = 0x01
MT2_F_KR2 = 0x02
MT2_F_HELLO = 0x10

# Encrypted (inside MT-WIRE) capability exchange payloads:
CAPS_CTRL_PREFIX = b"CP1"  # caps payload: CP1|k=v|...


def build_hello_frame(nonce4: bytes) -> bytes:
    if not isinstance(nonce4, (bytes, bytearray)) or len(nonce4) != 4:
        raise ValueError("nonce4 must be 4 bytes")
    return MT2_MAGIC + bytes([MT2_F_HELLO, MT2_FRAME_VER, 0]) + bytes(nonce4)


def build_kr1_frame(pub32: bytes, nonce4: bytes) -> bytes:
    if not isinstance(pub32, (bytes, bytearray)) or len(pub32) != 32:
        raise ValueError("pub32 must be 32 bytes")
    if not isinstance(nonce4, (bytes, bytearray)) or len(nonce4) != 4:
        raise ValueError("nonce4 must be 4 bytes")
    return MT2_MAGIC + bytes([MT2_F_KR1, MT2_FRAME_VER, 0]) + bytes(pub32) + bytes(nonce4)


def build_kr2_frame(pub32: bytes, nonce4: bytes) -> bytes:
    if not isinstance(pub32, (bytes, bytearray)) or len(pub32) != 32:
        raise ValueError("pub32 must be 32 bytes")
    if not isinstance(nonce4, (bytes, bytearray)) or len(nonce4) != 4:
        raise ValueError("nonce4 must be 4 bytes")
    return MT2_MAGIC + bytes([MT2_F_KR2, MT2_FRAME_VER, 0]) + bytes(pub32) + bytes(nonce4)


def parse_mt2_frame(payload: bytes) -> Optional[Tuple[str, Optional[bytes], Optional[bytes]]]:
    """
    Returns (kind, pub_raw, nonce4) for MT2 plaintext frames:
    - kind: "hello", "req" (KR1), "resp" (KR2)
    - pub_raw: 32 bytes for KR1/KR2, None for hello
    - nonce4: 4 bytes if present, otherwise None
    """
    if not isinstance(payload, (bytes, bytearray)):
        return None
    raw = bytes(payload)
    if len(raw) < 4:
        return None
    if not raw.startswith(MT2_MAGIC):
        return None
    ftype = raw[2]
    ver = raw[3]
    if int(ver) != int(MT2_FRAME_VER):
        return None
    if int(ftype) == int(MT2_F_HELLO):
        # hello: MT + ftype + ver + flags + nonce4 (exactly 9 bytes in v2).
        if len(raw) != 9:
            return None
        return ("hello", None, raw[5:9])
    if int(ftype) in (int(MT2_F_KR1), int(MT2_F_KR2)):
        # Fixed-size frame in v2: reject trailing bytes to avoid parser ambiguity.
        if len(raw) != (2 + 3 + 32 + 4):
            return None
        pub_raw = raw[5 : 5 + 32]
        nonce4 = raw[5 + 32 : 5 + 32 + 4]
        kind = "req" if int(ftype) == int(MT2_F_KR1) else "resp"
        return (kind, pub_raw, nonce4)
    return None


def parse_caps_frame(pt: bytes) -> Optional[Dict[str, str]]:
    """
    Parse encrypted CAPS payload after decryption: b"CP1|k=v|...".
    Only allow-listed keys are returned to keep logs safe.
    Values are truncated to 64 chars.
    """
    if not isinstance(pt, (bytes, bytearray)):
        return None
    raw = bytes(pt)
    if not raw.startswith(CAPS_CTRL_PREFIX + b"|"):
        return None
    rest = raw[len(CAPS_CTRL_PREFIX) + 1 :]
    allowed = {"wire", "msg", "mc", "aad"}
    out: Dict[str, str] = {}
    for chunk in rest.split(b"|"):
        if not chunk:
            continue
        if b"=" not in chunk:
            continue
        k, v = chunk.split(b"=", 1)
        try:
            ks = k.decode("ascii", errors="ignore").strip().lower()
        except Exception:
            continue
        if ks not in allowed:
            continue
        try:
            vs = v.decode("utf-8", errors="replace").strip()
        except Exception:
            vs = ""
        if len(vs) > 64:
            vs = vs[:64]
        out[ks] = vs
    return out
