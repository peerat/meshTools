#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import os
import time
import bz2
import hashlib
import lzma
import re
import struct
import zlib
from typing import Dict, Iterable, List, Optional, Set, Tuple

COMPRESS_TAG = b"Z1|"
COMPRESS_TAG_BZ2 = b"B1|"
COMPRESS_TAG_LZMA = b"L1|"
COMPRESS_METHOD_NONE = "none"
COMPRESS_METHOD_ZLIB = "zlib"
COMPRESS_METHOD_BZ2 = "bz2"
COMPRESS_METHOD_LZMA = "lzma"
COMPRESS_METHOD_DEFLATE = "deflate"
MC_MAGIC = b"MC"
MC_VERSION = 1
MC_DICT_ID = 2
MC_MODE_BYTE_DICT = 0
MC_MODE_FIXED_BITS = 1
MC_MODE_DEFLATE = 2
MC_MODE_ZLIB = 3
MC_MODE_BZ2 = 4
MC_MODE_LZMA = 5
MC_MODE_NLTK = 6
MC_MODE_SPACY = 7
MC_MODE_TENSORFLOW = 8
HISTORY_TEXT_PREFIX = "b64:"
HISTORY_TEXT_ENC_PREFIX = "enc1:"

_HISTORY_ENC_KEY: Optional[bytes] = None


def set_history_encryption_key(key: Optional[bytes]) -> None:
    """Set AES-256-GCM key for encrypting message text stored in history/state logs.

    When unset (default), history uses legacy b64: encoding for backwards compatibility.
    """
    global _HISTORY_ENC_KEY
    if key is None:
        _HISTORY_ENC_KEY = None
        return
    if isinstance(key, (bytes, bytearray)) and len(key) == 32:
        _HISTORY_ENC_KEY = bytes(key)
        return
    _HISTORY_ENC_KEY = None

MESSAGE_CODEC_NONE = "none"
MESSAGE_CODEC_DEFLATE = "deflate"
MESSAGE_CODEC_ZLIB = "zlib"
MESSAGE_CODEC_BZ2 = "bz2"
MESSAGE_CODEC_LZMA = "lzma"

MESSAGE_CODEC_TO_ID = {
    MESSAGE_CODEC_NONE: 0,
    MESSAGE_CODEC_DEFLATE: 1,
    MESSAGE_CODEC_ZLIB: 2,
    MESSAGE_CODEC_BZ2: 3,
    MESSAGE_CODEC_LZMA: 4,
}

MESSAGE_CODEC_FROM_ID = {
    0: MESSAGE_CODEC_NONE,
    1: MESSAGE_CODEC_DEFLATE,
    2: MESSAGE_CODEC_ZLIB,
    3: MESSAGE_CODEC_BZ2,
    4: MESSAGE_CODEC_LZMA,
}

TS_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b")
TS_DUP_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"(?:(?:\s+)\1\b)+\s*"
)


def message_codec_to_id(codec: str) -> int:
    return int(MESSAGE_CODEC_TO_ID.get(codec, 0))


def message_codec_from_id(codec_id: int) -> str:
    return str(MESSAGE_CODEC_FROM_ID.get(int(codec_id), MESSAGE_CODEC_NONE))


def normalize_log_text_line(text: object, fallback_ts: Optional[str] = None) -> Tuple[str, str]:
    line = str(text).lstrip()
    if not TS_PREFIX_RE.match(line):
        if fallback_ts is None:
            fallback_ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        line = f"{fallback_ts} {line}"
    line = TS_DUP_RE.sub(r"\1 ", line)
    body = TS_PREFIX_RE.sub("", line, count=1).lstrip()
    return line, body


def compression_method_from_payload(payload: bytes) -> str:
    if payload.startswith(COMPRESS_TAG):
        return COMPRESS_METHOD_ZLIB
    if payload.startswith(COMPRESS_TAG_BZ2):
        return COMPRESS_METHOD_BZ2
    if payload.startswith(COMPRESS_TAG_LZMA):
        return COMPRESS_METHOD_LZMA
    return COMPRESS_METHOD_NONE


def looks_like_mc_block(data: bytes) -> bool:
    if not isinstance(data, (bytes, bytearray)):
        return False
    raw = bytes(data)
    if len(raw) < 6:
        return False
    if raw[:2] != MC_MAGIC:
        return False
    ver = int(raw[2])
    mode = int(raw[3])
    dict_id = int(raw[4])
    if ver != MC_VERSION:
        return False
    if mode not in (
        MC_MODE_BYTE_DICT,
        MC_MODE_FIXED_BITS,
        MC_MODE_DEFLATE,
        MC_MODE_ZLIB,
        MC_MODE_BZ2,
        MC_MODE_LZMA,
        MC_MODE_NLTK,
        MC_MODE_SPACY,
        MC_MODE_TENSORFLOW,
    ):
        return False
    if dict_id != MC_DICT_ID:
        return False
    return True


def compress_message_blob_best(plaintext: bytes) -> Tuple[bytes, str]:
    if not plaintext:
        return plaintext, MESSAGE_CODEC_NONE
    candidates = [(plaintext, MESSAGE_CODEC_NONE)]
    try:
        cobj = zlib.compressobj(level=9, wbits=-15)
        raw = cobj.compress(plaintext) + cobj.flush()
        candidates.append((raw, MESSAGE_CODEC_DEFLATE))
    except Exception:
        pass
    try:
        candidates.append((zlib.compress(plaintext, level=9), MESSAGE_CODEC_ZLIB))
    except Exception:
        pass
    try:
        candidates.append((bz2.compress(plaintext, compresslevel=9), MESSAGE_CODEC_BZ2))
    except Exception:
        pass
    try:
        candidates.append((lzma.compress(plaintext, preset=9), MESSAGE_CODEC_LZMA))
    except Exception:
        pass
    return min(candidates, key=lambda item: len(item[0]))


def decompress_message_blob(data: bytes, codec: str) -> bytes:
    if codec == MESSAGE_CODEC_NONE:
        return data
    if codec == MESSAGE_CODEC_DEFLATE:
        try:
            return zlib.decompress(data, wbits=-15)
        except Exception:
            return data
    if codec == MESSAGE_CODEC_ZLIB:
        try:
            return zlib.decompress(data)
        except Exception:
            return data
    if codec == MESSAGE_CODEC_BZ2:
        try:
            return bz2.decompress(data)
        except Exception:
            return data
    if codec == MESSAGE_CODEC_LZMA:
        try:
            return lzma.decompress(data)
        except Exception:
            return data
    return data


def try_decompress_message_blob(data: bytes, codec: str) -> Tuple[bytes, bool]:
    if codec == MESSAGE_CODEC_NONE:
        return (data, True)
    if codec == MESSAGE_CODEC_DEFLATE:
        try:
            return (zlib.decompress(data, wbits=-15), True)
        except Exception:
            return (b"", False)
    if codec == MESSAGE_CODEC_ZLIB:
        try:
            return (zlib.decompress(data), True)
        except Exception:
            return (b"", False)
    if codec == MESSAGE_CODEC_BZ2:
        try:
            return (bz2.decompress(data), True)
        except Exception:
            return (b"", False)
    if codec == MESSAGE_CODEC_LZMA:
        try:
            return (lzma.decompress(data), True)
        except Exception:
            return (b"", False)
    return (b"", False)


def compress_for_encrypt_with_method(plaintext: bytes) -> Tuple[bytes, str]:
    if not plaintext:
        return plaintext, COMPRESS_METHOD_NONE
    candidates = [(plaintext, COMPRESS_METHOD_NONE)]
    try:
        candidates.append((COMPRESS_TAG + zlib.compress(plaintext, level=9), COMPRESS_METHOD_ZLIB))
    except Exception:
        pass
    try:
        candidates.append((COMPRESS_TAG_BZ2 + bz2.compress(plaintext, compresslevel=9), COMPRESS_METHOD_BZ2))
    except Exception:
        pass
    try:
        candidates.append((COMPRESS_TAG_LZMA + lzma.compress(plaintext, preset=9), COMPRESS_METHOD_LZMA))
    except Exception:
        pass
    return min(candidates, key=lambda item: len(item[0]))


def maybe_compress_for_encrypt(plaintext: bytes) -> bytes:
    out, _method = compress_for_encrypt_with_method(plaintext)
    return out


def maybe_decompress_after_decrypt(plaintext: bytes) -> bytes:
    if plaintext.startswith(COMPRESS_TAG):
        try:
            return zlib.decompress(plaintext[len(COMPRESS_TAG):])
        except Exception:
            return plaintext
    if plaintext.startswith(COMPRESS_TAG_BZ2):
        try:
            return bz2.decompress(plaintext[len(COMPRESS_TAG_BZ2):])
        except Exception:
            return plaintext
    if plaintext.startswith(COMPRESS_TAG_LZMA):
        try:
            return lzma.decompress(plaintext[len(COMPRESS_TAG_LZMA):])
        except Exception:
            return plaintext
    return plaintext


def split_text_utf8_chunks(text: str, max_bytes: int) -> List[str]:
    if max_bytes <= 0:
        return [text]
    parts: List[str] = []
    buf = ""
    buf_len = 0
    for ch in text:
        ch_bytes = ch.encode("utf-8")
        if buf and (buf_len + len(ch_bytes)) > max_bytes:
            parts.append(buf)
            buf = ch
            buf_len = len(ch_bytes)
        else:
            buf += ch
            buf_len += len(ch_bytes)
    if buf or not parts:
        parts.append(buf)
    return parts


def build_legacy_chunks(text: str, max_plain: int, created_s: int, group_id: str, attempts_hint: int = 1) -> List[str]:
    total = 1
    attempt_val = max(1, int(attempts_hint))
    for _ in range(4):
        header = f"T{int(created_s)}|{group_id}|{total}/{total}|{attempt_val}|"
        max_chunk = max(1, int(max_plain) - len(header.encode("utf-8")))
        chunks = split_text_utf8_chunks(text, max_chunk)
        new_total = len(chunks)
        if new_total == total:
            break
        total = new_total
    header = f"T{int(created_s)}|{group_id}|{total}/{total}|{attempt_val}|"
    max_chunk = max(1, int(max_plain) - len(header.encode("utf-8")))
    return split_text_utf8_chunks(text, max_chunk)


def build_legacy_wire_payload(
    created_s: int,
    group_id: str,
    part: int,
    total: int,
    attempt: int,
    chunk_text: str,
) -> bytes:
    wire_text = f"T{int(created_s)}|{group_id}|{int(part)}/{int(total)}|{int(attempt)}|{chunk_text}"
    return wire_text.encode("utf-8")


def build_compact_wire_payload(
    prefix: bytes,
    created_s: int,
    group_id: str,
    part: int,
    total: int,
    attempt: int,
    compression_flag: int,
    chunk: bytes,
) -> bytes:
    if len(prefix) != 2:
        raise ValueError("compact prefix must be 2 bytes")
    try:
        group_raw = bytes.fromhex(group_id)
        if len(group_raw) != 4:
            raise ValueError("group id size")
    except Exception:
        group_raw = hashlib.sha256(group_id.encode("utf-8")).digest()[:4]
    part_u16 = max(1, min(65535, int(part)))
    total_u16 = max(1, min(65535, int(total)))
    attempt_u8 = max(1, min(255, int(attempt)))
    meta_u8 = int(compression_flag) & 0x01
    header = (
        prefix
        + struct.pack(">I", int(created_s))
        + group_raw
        + struct.pack(">HHBB", part_u16, total_u16, attempt_u8, meta_u8)
    )
    return header + bytes(chunk)


def parse_compact_meta(meta_u8: int, body: bytes = b"") -> Tuple[int, Optional[str], str]:
    meta_u8 = int(meta_u8) & 0xFF
    if meta_u8 == 0:
        return (0, None, "none")
    if meta_u8 == 1:
        # meta=1 is ambiguous with legacy deflate.
        # Treat as MC only when payload has valid MC header.
        legacy = message_codec_from_id(meta_u8)
        if looks_like_mc_block(body):
            try:
                mc_mode = int(body[3])
            except Exception:
                mc_mode = -1
            mode_label = {
                MC_MODE_BYTE_DICT: "mc_byte_dict",
                MC_MODE_FIXED_BITS: "mc_fixed_bits",
                MC_MODE_DEFLATE: "mc_deflate",
                MC_MODE_ZLIB: "mc_zlib",
                MC_MODE_BZ2: "mc_bz2",
                MC_MODE_LZMA: "mc_lzma",
                MC_MODE_NLTK: "mc_nltk",
                MC_MODE_SPACY: "mc_spacy",
                MC_MODE_TENSORFLOW: "mc_tensorflow",
            }.get(mc_mode, "mc")
            return (1, legacy, mode_label)
        return (0, legacy, str(legacy or "none"))
    legacy_codec = message_codec_from_id(meta_u8)
    return (0, legacy_codec, str(legacy_codec or "none"))


def parse_key_exchange_frame(
    payload: bytes,
    key_req_prefix: bytes,
    key_resp_prefix: bytes,
    supported_modes: Set[int],
) -> Optional[
    Tuple[
        str,
        str,
        bytes,
        Optional[Set[int]],
        Optional[Set[str]],
        Optional[Set[int]],
        Optional[Set[int]],
        Optional[Set[int]],
    ]
]:
    if not isinstance(payload, (bytes, bytearray)):
        return None
    raw = bytes(payload)
    if raw.startswith(key_req_prefix):
        kind = "req"
        rest = raw[len(key_req_prefix):]
    elif raw.startswith(key_resp_prefix):
        kind = "resp"
        rest = raw[len(key_resp_prefix):]
    else:
        return None
    try:
        parts = rest.split(b"|")
        if len(parts) < 2:
            return None
        peer_id = parts[0].decode("utf-8", errors="ignore")
        if not peer_id:
            return None
        pub_raw = base64.b64decode(parts[1], validate=True)
        if len(pub_raw) != 32:
            return None
        peer_modes: Optional[Set[int]] = None
        peer_caps: Optional[Set[str]] = None
        peer_wire: Optional[Set[int]] = None
        peer_msg: Optional[Set[int]] = None
        peer_mc: Optional[Set[int]] = None
        for extra_raw in parts[2:]:
            try:
                extra = extra_raw.decode("utf-8", errors="ignore").strip()
            except Exception:
                continue
            if extra.startswith("mt_caps="):
                caps_raw = extra[len("mt_caps="):]
                parsed_caps = {c.strip() for c in caps_raw.split(",") if c.strip()}
                if parsed_caps:
                    peer_caps = set(parsed_caps)
                continue

            def parse_int_csv(raw_text: str) -> Set[int]:
                out: Set[int] = set()
                for item in raw_text.split(","):
                    item = item.strip()
                    if not item:
                        continue
                    try:
                        out.add(int(item))
                    except Exception:
                        continue
                return out

            if extra.startswith("mt_wire="):
                parsed = parse_int_csv(extra[len("mt_wire="):])
                if parsed:
                    peer_wire = set(parsed)
                continue

            if extra.startswith("mt_msg="):
                parsed = parse_int_csv(extra[len("mt_msg="):])
                if parsed:
                    peer_msg = set(parsed)
                continue

            if extra.startswith("mt_mc="):
                parsed = parse_int_csv(extra[len("mt_mc="):])
                if parsed:
                    peer_mc = set(parsed)
                continue

            if extra.startswith("mc_modes="):
                try:
                    parsed = {
                        int(item)
                        for item in extra[len("mc_modes="):].split(",")
                        if item != ""
                    }
                except Exception:
                    parsed = set()
                parsed = {m for m in parsed if m in supported_modes}
                if parsed:
                    peer_modes = set(parsed)
                continue
        return (kind, peer_id, pub_raw, peer_modes, peer_caps, peer_wire, peer_msg, peer_mc)
    except Exception:
        return None


def _normalize_wire_node_id(node_id: object) -> str:
    text = str(node_id or "").strip()
    if text.startswith("!"):
        text = text[1:]
    return text.lower()


def validate_key_frame_source(
    peer_id: str,
    from_id_raw: object,
    is_broadcast: bool,
) -> Tuple[bool, bool, str]:
    from_text = str(from_id_raw or "").strip()
    if not from_text:
        return (False, False, "missing_from_id")
    if _normalize_wire_node_id(from_text) != _normalize_wire_node_id(peer_id):
        return (False, False, "id_mismatch")
    trusted_capabilities = not bool(is_broadcast)
    return (True, trusted_capabilities, "")


def is_broadcast_destination(to_id: object, broadcast_addr: object) -> bool:
    aliases = {"^all", "all", "broadcast"}
    broadcast_int: Optional[int] = None
    if isinstance(broadcast_addr, int):
        broadcast_int = int(broadcast_addr)
        aliases.add(str(broadcast_int))
    elif isinstance(broadcast_addr, str):
        addr_text = broadcast_addr.strip().lower()
        if addr_text:
            aliases.add(addr_text)
        try:
            broadcast_int = int(broadcast_addr, 0)
        except Exception:
            broadcast_int = None

    if isinstance(to_id, int):
        return bool((broadcast_int is not None) and (int(to_id) == int(broadcast_int)))

    if isinstance(to_id, str):
        text = to_id.strip().lower()
        if text in aliases:
            return True
        if broadcast_int is not None:
            if text == str(int(broadcast_int)):
                return True
            try:
                return int(to_id, 0) == int(broadcast_int)
            except Exception:
                return False
    return False


def key_frame_receive_policy(
    peer_id: str,
    from_id_raw: object,
    to_id: object,
    broadcast_addr: object,
    discovery_reply: bool,
) -> Tuple[bool, bool, str, bool, Optional[str]]:
    from_id = str(from_id_raw).strip() if from_id_raw else None
    is_broadcast = is_broadcast_destination(to_id, broadcast_addr)
    if is_broadcast and not discovery_reply:
        return (False, False, "broadcast_disabled", True, from_id)
    accepted, trusted_capabilities, reject_reason = validate_key_frame_source(
        peer_id=peer_id,
        from_id_raw=from_id_raw,
        is_broadcast=is_broadcast,
    )
    return (accepted, trusted_capabilities, reject_reason, is_broadcast, from_id)


def merge_compact_compression(prev_flag: int, incoming_flag: int) -> int:
    return 1 if int(prev_flag) == 1 or int(incoming_flag) == 1 else 0


def _encrypt_history_token(plaintext: bytes, aad: bytes) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = _HISTORY_ENC_KEY
    if not key:
        raise ValueError("history encryption key not configured")
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return HISTORY_TEXT_ENC_PREFIX + base64.b64encode(nonce + ct).decode("ascii")


def _decrypt_history_token(token: str, aad: bytes, strict: bool) -> Optional[str]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = _HISTORY_ENC_KEY
    if not key:
        return None if strict else "[locked]"
    payload = token[len(HISTORY_TEXT_ENC_PREFIX):]
    try:
        raw = base64.b64decode(payload.encode("ascii"), validate=True)
        if len(raw) < (12 + 16):
            raise ValueError("ciphertext too short")
        nonce = raw[:12]
        ct = raw[12:]
        pt = AESGCM(key).decrypt(nonce, ct, aad)
        return pt.decode("utf-8", errors="replace")
    except Exception:
        return None if strict else "[decode error]"


def encode_history_text(text: str, aad: Optional[bytes] = None) -> str:
    raw = str(text).encode("utf-8")
    if _HISTORY_ENC_KEY:
        try:
            return _encrypt_history_token(raw, aad or b"")
        except Exception:
            pass
    return HISTORY_TEXT_PREFIX + base64.b64encode(raw).decode("ascii")


def decode_history_text(value: str, strict: bool = False, aad: Optional[bytes] = None) -> Optional[str]:
    if not isinstance(value, str):
        return str(value)
    if value.startswith(HISTORY_TEXT_ENC_PREFIX):
        return _decrypt_history_token(value, aad or b"", strict=strict)
    if not value.startswith(HISTORY_TEXT_PREFIX):
        return value
    payload = value[len(HISTORY_TEXT_PREFIX):]
    try:
        out = base64.b64decode(payload.encode("ascii"), validate=True)
        return out.decode("utf-8", errors="replace")
    except Exception:
        return None if strict else value


def parse_history_line(line: str, strict_encoded: bool = True) -> Optional[Tuple[str, str, str, str, str]]:
    if not isinstance(line, str):
        return None
    parts = line.rstrip("\n").split(" | ")
    if len(parts) < 5:
        return None
    if strict_encoded and len(parts) != 5:
        return None
    ts_part = parts[0]
    direction = parts[1]
    peer_id = parts[2]
    msg_id = parts[3]
    text_wire = " | ".join(parts[4:])
    if strict_encoded and not (
        text_wire.startswith(HISTORY_TEXT_PREFIX) or text_wire.startswith(HISTORY_TEXT_ENC_PREFIX)
    ):
        return None
    aad = f"{direction}|{peer_id}|{msg_id}".encode("utf-8", errors="replace")
    text = decode_history_text(text_wire, strict=strict_encoded, aad=aad)
    if text is None:
        return None
    return (ts_part, direction, peer_id, msg_id, text)


def assemble_compact_parts(
    parts: object,
    total: int,
    compression: int,
    legacy_codec: Optional[str],
    show_partial: bool = True,
) -> Tuple[str, bool]:
    # Local import keeps utility module lightweight and avoids hard dependency
    # during contexts where message_text_compression is not used.
    from message_text_compression import decompress_text

    if not isinstance(parts, dict) or int(total) <= 0:
        return ("", True)
    total_i = int(total)
    if len(parts) < total_i:
        return ("..." if show_partial else "", True)
    blob = bytearray()
    for i in range(1, total_i + 1):
        raw = parts.get(str(i))
        if raw is None:
            raw = parts.get(i)
        if raw is None:
            continue
        try:
            blob.extend(base64.b64decode(str(raw).encode("ascii")))
        except Exception:
            pass
    block = bytes(blob)
    mc_magic = looks_like_mc_block(block)
    should_try_mc = bool(int(compression) == 1) or mc_magic
    if should_try_mc:
        try:
            return (decompress_text(block), True)
        except Exception:
            if mc_magic or int(compression) == 1:
                return ("[decode error]", False)
    if legacy_codec:
        out, ok = try_decompress_message_blob(block, str(legacy_codec))
        if not ok:
            return ("[decode error]", False)
        try:
            return (out.decode("utf-8", errors="replace"), True)
        except Exception:
            return ("", False)
    try:
        return (block.decode("utf-8", errors="replace"), True)
    except Exception:
        return ("", False)


def parse_legacy_wire_payload(payload: bytes) -> Tuple[int, str, int, int, int, str]:
    text = payload.decode("utf-8", errors="strict")
    if not text.startswith("T"):
        raise ValueError("legacy payload must start with T")
    parts = text.split("|", 4)
    if len(parts) != 5:
        raise ValueError("invalid legacy payload shape")
    created_s = int(parts[0][1:])
    group_id = parts[1]
    p_s, t_s = parts[2].split("/", 1)
    part = int(p_s)
    total = int(t_s)
    attempt = int(parts[3])
    return (created_s, group_id, part, total, attempt, parts[4])


def format_duration_mmss(seconds: float) -> str:
    total = max(0, int(round(seconds)))
    mm = total // 60
    ss = total % 60
    return f"{mm:02d}:{ss:02d}"


def _fmt_num(val: Optional[float]) -> str:
    if val is None:
        return "?"
    if abs(val - round(val)) < 0.001:
        return str(int(round(val)))
    return f"{val:.1f}"


def format_meta_text(
    lang: str,
    delivery: Optional[float],
    attempts: Optional[float],
    forward_hops: Optional[float],
    ack_hops: Optional[float],
    packets: Optional[Tuple[int, int]] = None,
    status: Optional[str] = None,
    delivered_at_ts: Optional[float] = None,
    incoming: bool = False,
    done: Optional[bool] = None,
    row_time_hhmm: Optional[str] = None,
    received_at_ts: Optional[float] = None,
    sent_at_ts: Optional[float] = None,
    incoming_started_ts: Optional[float] = None,
    now_ts: Optional[float] = None,
    compression_name: Optional[str] = None,
    compression_eff_pct: Optional[float] = None,
) -> str:
    is_ru = (lang == "ru")
    dur = format_duration_mmss(delivery) if delivery is not None else None
    done_count = 0
    total_count = 1
    if packets is not None:
        done_count, total_count = int(packets[0]), int(packets[1])
        if total_count <= 0:
            total_count = 1
    one_packet = (total_count == 1)
    details: list[str] = []
    if attempts is not None and attempts > 0:
        a = _fmt_num(attempts)
        if is_ru:
            details.append(f"с {a} попытки" if one_packet else f"попытки {a}")
        else:
            details.append(f"on the {a} attempt" if one_packet else f"attempts {a}")
    if forward_hops is not None:
        fwd = _fmt_num(forward_hops)
        if (not incoming) and (ack_hops is not None):
            back = _fmt_num(ack_hops)
            if is_ru:
                details.append(f"хопы туда {fwd} обратно {back}")
            else:
                details.append(f"hops there {fwd} back {back}")
        else:
            if incoming:
                if is_ru:
                    details.append(f"хопов {fwd}")
                else:
                    details.append(f"hops {fwd}")
            else:
                if is_ru:
                    details.append(f"хопы туда {fwd}")
                else:
                    details.append(f"hops there {fwd}")
    if packets is not None and total_count > 1:
        if is_ru:
            details.append(f"части {done_count}/{total_count}")
        else:
            details.append(f"parts {done_count}/{total_count}")
    cmp_name = str(compression_name or "").strip()
    cmp_name_l = cmp_name.lower()
    cmp_tail = ""
    if cmp_name and cmp_name_l not in ("none", "n/a", "-", "null"):
        if compression_eff_pct is not None:
            eff = _fmt_num(float(compression_eff_pct))
            if is_ru:
                details.append(f"сжатие {cmp_name} {eff}%")
                cmp_tail = f", сжатие {cmp_name} {eff}%"
            else:
                details.append(f"compression {cmp_name} {eff}%")
                cmp_tail = f", compression {cmp_name} {eff}%"
        else:
            if is_ru:
                details.append(f"сжатие {cmp_name}")
                cmp_tail = f", сжатие {cmp_name}"
            else:
                details.append(f"compression {cmp_name}")
                cmp_tail = f", compression {cmp_name}"
    status_map_ru = {
        "timeout": "таймаут",
        "queue_limit": "лимит очереди",
        "too_long": "слишком длинное",
        "payload_too_big": "слишком большой пакет",
        "nack": "nack",
        "decode_error": "ошибка декодирования",
    }
    status_map_en = {
        "timeout": "timeout",
        "queue_limit": "queue limit",
        "too_long": "too long",
        "payload_too_big": "payload too big",
        "nack": "nack",
        "decode_error": "decode error",
    }
    if is_ru:
        status_text = status_map_ru.get(status, status or "")
    else:
        status_text = status_map_en.get(status, status or "")
    if status:
        if is_ru:
            prefix = f"ошибка ({status_text})"
            if dur:
                prefix = f"{prefix} через {dur}"
        else:
            prefix = f"failed ({status_text})"
            if dur:
                prefix = f"{prefix} after {dur}"
        return f"{prefix}, {', '.join(details)}" if details else prefix
    if incoming:
        if done is True:
            t = received_at_ts if received_at_ts is not None else (time.time() if now_ts is None else now_ts)
            recv_at = time.strftime("%H:%M", time.localtime(t))
            if is_ru:
                if delivery is not None:
                    sent_ts = max(0.0, float(t) - float(delivery))
                    sent_at = time.strftime("%H:%M", time.localtime(sent_ts))
                    prefix = f"отправлено в {sent_at} получено в {recv_at}" + (f" за {dur}" if dur else "")
                else:
                    prefix = f"получено в {recv_at}" + (f" за {dur}" if dur else "")
            else:
                if delivery is not None:
                    sent_ts = max(0.0, float(t) - float(delivery))
                    sent_at = time.strftime("%H:%M", time.localtime(sent_ts))
                    prefix = f"sent at {sent_at} received at {recv_at}" + (f" in {dur}" if dur else "")
                else:
                    prefix = f"received at {recv_at}" + (f" in {dur}" if dur else "")
            return f"{prefix}, {', '.join(details)}" if details else prefix
        now_ref = time.time() if now_ts is None else now_ts
        start_ts = incoming_started_ts if incoming_started_ts is not None else now_ref
        start_hhmm = time.strftime("%H:%M", time.localtime(start_ts))
        elapsed = max(0.0, float(now_ref) - float(start_ts))
        timer = format_duration_mmss(elapsed)
        if is_ru:
            text = f"в {start_hhmm} начали прием, прошло {timer}"
            if packets is not None and total_count > 1:
                text += f" частей {done_count}/{total_count}"
            if attempts is not None and attempts > 0:
                text += f" с {_fmt_num(attempts)} попытки"
            if forward_hops is not None:
                if (attempts is not None and attempts > 0) or (packets is not None and total_count > 1):
                    text += f", хопов {_fmt_num(forward_hops)}"
                else:
                    text += f" хопов {_fmt_num(forward_hops)}"
        else:
            text = f"at {start_hhmm} started receiving, elapsed {timer}"
            if packets is not None and total_count > 1:
                text += f" parts {done_count}/{total_count}"
            if attempts is not None and attempts > 0:
                text += f" attempts {_fmt_num(attempts)}"
            if forward_hops is not None:
                text += f", hops {_fmt_num(forward_hops)}"
        if cmp_tail:
            text += cmp_tail
        return text
    if delivered_at_ts is not None:
        sent_at = None
        if sent_at_ts is not None:
            sent_at = time.strftime("%H:%M", time.localtime(sent_at_ts))
        delivered_at = time.strftime("%H:%M", time.localtime(delivered_at_ts))
        if is_ru:
            if sent_at:
                prefix = f"отправлена в {sent_at} доставлено в {delivered_at}" + (f" за {dur}" if dur else "")
            elif row_time_hhmm and row_time_hhmm == delivered_at:
                prefix = "доставлено" + (f" за {dur}" if dur else "")
            else:
                prefix = f"доставлено в {delivered_at}" + (f" за {dur}" if dur else "")
        else:
            if sent_at:
                prefix = f"sent at {sent_at} delivered at {delivered_at}" + (f" in {dur}" if dur else "")
            else:
                prefix = f"delivered at {delivered_at}" + (f" in {dur}" if dur else "")
        return f"{prefix}, {', '.join(details)}" if details else prefix
    if sent_at_ts is not None:
        now_ref = time.time() if now_ts is None else now_ts
        elapsed = max(0.0, float(now_ref) - float(sent_at_ts))
        timer = format_duration_mmss(elapsed)
        sent_at = time.strftime("%H:%M", time.localtime(sent_at_ts))
        prefix = f"отправлено в {sent_at} прошло {timer}" if is_ru else f"sent at {sent_at} elapsed {timer}"
        return f"{prefix}, {', '.join(details)}" if details else prefix
    if details:
        return ", ".join(details)
    return "в процессе" if is_ru else "in progress"


def snapshot_runtime_state(
    peer_states: Dict[str, object],
    known_peers: Dict[str, object],
    tracked_peers: Iterable[str],
    retries: int = 8,
) -> Tuple[Set[str], float]:
    attempts = max(1, int(retries))
    for _ in range(attempts):
        try:
            peer_items = list(peer_states.items())
            known_keys = list(known_peers.keys())
            tracked = list(tracked_peers)
            peer_ids = set(k for k, _ in peer_items) | set(known_keys) | set(tracked)
            rtts = []
            for _, st in peer_items:
                cnt = int(getattr(st, "rtt_count", 0) or 0)
                if cnt > 0:
                    rtts.append(float(getattr(st, "rtt_avg", 0.0) or 0.0))
            avg_rtt = (sum(rtts) / len(rtts)) if rtts else 0.0
            return (peer_ids, avg_rtt)
        except RuntimeError:
            time.sleep(0.001)
    return (set(), 0.0)
