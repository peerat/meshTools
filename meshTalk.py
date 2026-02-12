#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""
Experimental point-to-point payload exchange over Meshtastic with ACK/retry and cryptographic primitives.
RU: Экспериментальный P2P обмен полезной нагрузкой поверх Meshtastic: ACK/повторы и криптографические примитивы.
"""

from __future__ import annotations

import argparse
import atexit
import base64
import faulthandler
import os
import queue
import sys
import threading
import time
import traceback
import hashlib
import math
import colorsys
import re
import random
import struct
from typing import Dict, Optional, Tuple

from meshtastic.serial_interface import SerialInterface
from pubsub import pub
import meshtastic
from meshtastic import portnums_pb2
from serial.tools import list_ports

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from meshtalk_utils import (
    format_meta_text,
    snapshot_runtime_state,
    normalize_log_text_line,
    build_legacy_chunks,
    build_legacy_wire_payload,
    build_compact_wire_payload,
    parse_compact_meta,
    parse_key_exchange_frame,
    key_frame_receive_policy,
    merge_compact_compression,
    assemble_compact_parts,
)
from meshtalk.protocol import (
    PROTO_VERSION,
    TYPE_MSG,
    TYPE_ACK,
    PeerKeyPinnedError,
    b64d,
    b64e,
    derive_key,
    load_priv,
    load_pub,
    pack_message,
    parse_payload,
    pub_fingerprint,
    try_unpack_message,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from meshtalk.storage import (
    Storage,
    decode_history_meta_token,
    encode_history_meta_token,
    harden_dir,
    harden_file,
    maybe_set_private_umask,
    parse_history_record_line,
)
from meshtalk.pacing import AdaptivePacer
from message_text_compression import (
    MODE_BZ2,
    MODE_DEFLATE,
    MODE_BYTE_DICT,
    MODE_FIXED_BITS,
    MODE_LZMA,
    MODE_ZSTD,
    MODE_ZLIB,
    compress_text,
    mode_name,
    normalization_stats,
)


VERSION = "0.4.0"
DEFAULT_PORTNUM = portnums_pb2.PortNum.PRIVATE_APP
PAYLOAD_OVERHEAD = 1 + 1 + 8 + 12 + 16  # ver + type + msg_id + nonce + tag
KEY_REQ_PREFIX = b"KR1|"
KEY_RESP_PREFIX = b"KR2|"
APP_OFFLINE_PREFIX = b"KOF1|"
MSG_V2_PREFIX = b"M2"
MSG_V2_HEADER_LEN = 16  # prefix(2) + ts(4) + group(4) + part(2) + total(2) + attempt(1) + meta(1)
MAX_PENDING_PER_PEER = 128
RETRY_BACKOFF_MAX_SECONDS = 300.0
RETRY_JITTER_RATIO = 0.25
KEY_RESPONSE_MIN_INTERVAL_SECONDS = 300.0
KEY_RESPONSE_RETRY_INTERVAL_SECONDS = 5.0
REKEY_CTRL_PREFIX1 = b"RK1"
REKEY_CTRL_PREFIX2 = b"RK2"
REKEY_CTRL_PREFIX3 = b"RK3"
# Enabled by default: low-noise, infrequent rekey only when peers are active and confirmed.
REKEY_MAX_ATTEMPTS = 3
REKEY_RETRY_BASE_SECONDS = 30.0
REKEY_PREV_KEY_GRACE_SECONDS = 300.0
REKEY_MIN_INTERVAL_SECONDS = 6 * 3600.0
REKEY_MIN_MESSAGES = 50
CONTACT_ONLINE_SECONDS = 30.0 * 60.0
CONTACT_STALE_SECONDS = 24.0 * 3600.0
BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
LEGACY_BASE_DIR = "meshTalk"
DATA_DIR = BASE_DIR
STATE_FILE = os.path.join(DATA_DIR, "state.json")
HISTORY_FILE = os.path.join(DATA_DIR, "history.log")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
INCOMING_FILE = os.path.join(DATA_DIR, "incoming.json")
RUNTIME_LOG_FILE = os.path.join(DATA_DIR, "runtime.log")
keydir = os.path.join(DATA_DIR, "keyRings")
_STORAGE = Storage(
    config_file=CONFIG_FILE,
    state_file=STATE_FILE,
    history_file=HISTORY_FILE,
    incoming_file=INCOMING_FILE,
    runtime_log_file=RUNTIME_LOG_FILE,
    keydir=keydir,
)
COMPRESSION_MODES = (
    int(MODE_BYTE_DICT),
    int(MODE_FIXED_BITS),
    # Default local capabilities; actual supported modes are controlled by Settings and runtime dependencies.
    int(MODE_DEFLATE),
    int(MODE_ZLIB),
    int(MODE_BZ2),
    int(MODE_LZMA),
)
LEGACY_COMPRESSION_MODES = tuple(COMPRESSION_MODES)
AUTO_MIN_GAIN_BYTES = 2

try:
    import zstandard as _mt_zstd  # type: ignore

    _ZSTD_AVAILABLE = True
except Exception:
    _mt_zstd = None
    _ZSTD_AVAILABLE = False

# Global config dict.
# Some worker threads call helpers defined at module scope (e.g. discovery broadcast),
# so config must exist as a module global to avoid NameError.
cfg: Dict[str, object] = {}


def supported_mc_modes_for_config(cfg_obj: dict) -> tuple[int, ...]:
    """Return local MC mode IDs to advertise/use based on Settings and installed optional deps."""
    # ZSTD is now a required dependency, but keep runtime check for broken installs.
    modes = [
        int(MODE_BYTE_DICT),
        int(MODE_FIXED_BITS),
        int(MODE_DEFLATE),
        int(MODE_ZLIB),
        int(MODE_BZ2),
        int(MODE_LZMA),
    ]
    if _ZSTD_AVAILABLE:
        modes.append(int(MODE_ZSTD))
    # Stable order for wire advertisement.
    return tuple(sorted({int(m) for m in modes}))


def ts_local() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def ensure_storage_key() -> Optional[bytes]:
    return _STORAGE.ensure_storage_key()


def ensure_data_dir() -> None:
    harden_dir(DATA_DIR)


def set_data_dir_for_node(node_id_norm: Optional[str]) -> None:
    global DATA_DIR, STATE_FILE, HISTORY_FILE, CONFIG_FILE, INCOMING_FILE, RUNTIME_LOG_FILE, keydir, _STORAGE
    if node_id_norm:
        DATA_DIR = os.path.join(BASE_DIR, node_id_norm)
    else:
        DATA_DIR = BASE_DIR
    STATE_FILE = os.path.join(DATA_DIR, "state.json")
    HISTORY_FILE = os.path.join(DATA_DIR, "history.log")
    CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
    INCOMING_FILE = os.path.join(DATA_DIR, "incoming.json")
    RUNTIME_LOG_FILE = os.path.join(DATA_DIR, "runtime.log")
    keydir = os.path.join(DATA_DIR, "keyRings")
    harden_dir(DATA_DIR)
    harden_dir(keydir)
    _STORAGE.set_paths(
        config_file=CONFIG_FILE,
        state_file=STATE_FILE,
        history_file=HISTORY_FILE,
        incoming_file=INCOMING_FILE,
        runtime_log_file=RUNTIME_LOG_FILE,
        keydir=keydir,
    )


def migrate_data_dir(base_dir: str, node_dir: str) -> None:
    if not base_dir or not node_dir:
        return
    if os.path.abspath(base_dir) == os.path.abspath(node_dir):
        return
    try:
        os.makedirs(node_dir, exist_ok=True)
        for name in ("config.json", "state.json", "incoming.json", "history.log", "runtime.log"):
            src = os.path.join(base_dir, name)
            dst = os.path.join(node_dir, name)
            if os.path.isfile(src) and not os.path.isfile(dst):
                os.replace(src, dst)
        src_keydir = os.path.join(base_dir, "keyRings")
        dst_keydir = os.path.join(node_dir, "keyRings")
        if os.path.isdir(src_keydir):
            os.makedirs(dst_keydir, exist_ok=True)
            for fname in os.listdir(src_keydir):
                src = os.path.join(src_keydir, fname)
                dst = os.path.join(dst_keydir, fname)
                if os.path.isfile(src) and not os.path.isfile(dst):
                    os.replace(src, dst)
    except Exception:
        pass


def load_state(default_peer: Optional[str] = None) -> Dict[str, Dict[str, Dict[str, object]]]:
    return _STORAGE.load_state(default_peer=default_peer)


def save_state(pending_by_peer: Dict[str, Dict[str, Dict[str, object]]]) -> None:
    _STORAGE.save_state(pending_by_peer)


def load_incoming_state() -> Dict[str, Dict[str, object]]:
    return _STORAGE.load_incoming_state()


def save_incoming_state(incoming: Dict[str, Dict[str, object]]) -> None:
    _STORAGE.save_incoming_state(incoming)


def append_history(
    direction: str,
    peer_id: str,
    msg_id: str,
    text: str,
    extra: str = "",
    meta_data: Optional[Dict[str, object]] = None,
) -> None:
    _STORAGE.append_history(direction, peer_id, msg_id, text, extra=extra, meta_data=meta_data, peer_norm_fn=norm_id_for_filename)


def purge_history_peer(peer_id: str) -> None:
    _STORAGE.purge_history_peer(peer_id, peer_norm_fn=norm_id_for_filename)


def rewrite_history_peer_field(old_peer_id: str, new_peer_id: Optional[str]) -> None:
    _STORAGE.rewrite_history_peer_field(old_peer_id, new_peer_id)


def append_runtime_log(line: str) -> None:
    _STORAGE.append_runtime_log(line)


def load_config() -> Dict[str, object]:
    return _STORAGE.load_config()


def save_config(cfg: Dict[str, object]) -> None:
    _STORAGE.save_config(cfg)


def infer_compact_cmp_label_from_chunk(chunk: bytes) -> Optional[str]:
    raw = bytes(chunk or b"")
    if len(raw) >= 4 and raw[:2] == b"MC":
        try:
            return str(mode_name(int(raw[3])))
        except Exception:
            return "mc"
    try:
        _compression, _legacy_codec, label = parse_compact_meta(1, raw)
    except Exception:
        return None
    low = str(label or "").strip().lower()
    if low.startswith("mc_") or low == "mc":
        return low
    return None


def infer_compact_cmp_label_from_parts(parts: object) -> Optional[str]:
    if not isinstance(parts, dict):
        return None
    raw_part = parts.get("1")
    if raw_part is None:
        raw_part = parts.get(1)
    if raw_part in (None, ""):
        return None
    try:
        chunk = b64d(str(raw_part))
    except Exception:
        return None
    return infer_compact_cmp_label_from_chunk(chunk)


def infer_compact_cmp_label_from_joined_parts(parts: object, total: object) -> Optional[str]:
    if not isinstance(parts, dict):
        return None
    try:
        total_i = int(total)
    except Exception:
        total_i = 0
    if total_i <= 0:
        return None
    blob = bytearray()
    for i in range(1, total_i + 1):
        raw_part = parts.get(str(i))
        if raw_part is None:
            raw_part = parts.get(i)
        if raw_part in (None, ""):
            return None
        try:
            blob.extend(b64d(str(raw_part)))
        except Exception:
            return None
    return infer_compact_cmp_label_from_chunk(bytes(blob))


def infer_compact_norm_from_chunk(chunk: bytes) -> Optional[str]:
    raw = bytes(chunk or b"")
    if len(raw) < 6 or raw[:2] != b"MC":
        return None
    try:
        flags = int(raw[5]) & 0xFF
    except Exception:
        return None
    # message_text_compression.FLAG_TOKEN_STREAM
    if (flags & (1 << 4)) != 0:
        return "TOKEN_STREAM"
    return "off"


def infer_compact_norm_from_joined_parts(parts: object, total: object) -> Optional[str]:
    if not isinstance(parts, dict):
        return None
    try:
        total_i = int(total)
    except Exception:
        total_i = 0
    if total_i <= 0:
        return None
    blob = bytearray()
    for i in range(1, total_i + 1):
        raw_part = parts.get(str(i))
        if raw_part is None:
            raw_part = parts.get(i)
        if raw_part in (None, ""):
            return None
        try:
            blob.extend(b64d(str(raw_part)))
        except Exception:
            return None
    return infer_compact_norm_from_chunk(bytes(blob))


def effective_payload_cmp_label(
    payload_cmp: object,
    compact_wire: bool,
    compression_flag: int,
    legacy_codec: object = None,
    parts: object = None,
    chunk_b64: Optional[str] = None,
) -> str:
    cmp_low = str(payload_cmp or "").strip().lower()
    if compact_wire and int(compression_flag or 0) == 1:
        if cmp_low.startswith("mc_") or cmp_low == "mc":
            return cmp_low
        if chunk_b64:
            try:
                inferred = infer_compact_cmp_label_from_chunk(b64d(str(chunk_b64)))
            except Exception:
                inferred = None
            if inferred:
                return inferred
        inferred = infer_compact_cmp_label_from_parts(parts)
        if inferred:
            return inferred
        return "mc"
    if cmp_low and cmp_low not in ("none", "n/a", "-", "null"):
        return cmp_low
    legacy_low = str(legacy_codec or "").strip().lower()
    if legacy_low and legacy_low not in ("none", "n/a", "-", "null"):
        return legacy_low
    return "none"


# Protocol/crypto helpers live in meshtalk.protocol and are imported above.


def detect_serial_port() -> Optional[str]:
    ports = list(list_ports.comports())
    if not ports:
        return None

    def score(p) -> int:
        name = f"{p.device} {p.description} {p.manufacturer}".lower()
        s = 0
        if "meshtastic" in name:
            s += 10
        if "usb" in name:
            s += 4
        if "acm" in p.device.lower():
            s += 4
        if "ttyusb" in p.device.lower():
            s += 4
        if p.device.lower().startswith("com"):
            s += 3
        if "cp210" in name or "ftdi" in name or "ch340" in name:
            s += 2
        return s

    ports_sorted = sorted(ports, key=score, reverse=True)
    return ports_sorted[0].device if ports_sorted else None


def norm_id_for_filename(node_id: str) -> str:
    if not node_id:
        return "self"
    nid = node_id.strip()
    if nid.startswith("!"):
        nid = nid[1:]
    # Canonicalize standard Meshtastic node IDs for stable filenames/dict keys.
    # Keep non-node identifiers (e.g. "group:...") case-preserving.
    if re.fullmatch(r"[0-9a-fA-F]{8}", nid):
        nid = nid.lower()
    return nid


def canonicalize_keyring_filenames(keydir: str) -> None:
    """Best-effort: rename hex keyring filenames to lowercase.

    This avoids subtle bugs on case-sensitive filesystems when peer/self ids
    appear in mixed case (wire validation is case-insensitive).
    """
    if not keydir or not os.path.isdir(keydir):
        return
    try:
        for name in os.listdir(keydir):
            path = os.path.join(keydir, name)
            if not os.path.isfile(path):
                continue
            stem, ext = os.path.splitext(name)
            if ext not in (".pub", ".key"):
                continue
            if not re.fullmatch(r"[0-9a-fA-F]{8}", stem):
                continue
            canon = stem.lower()
            if canon == stem:
                continue
            dst = os.path.join(keydir, canon + ext)
            if os.path.isfile(dst):
                # If both exist and are identical, remove the non-canonical duplicate.
                try:
                    with open(path, "rb") as f1:
                        a = f1.read()
                    with open(dst, "rb") as f2:
                        b = f2.read()
                    if a == b:
                        os.remove(path)
                except Exception:
                    pass
                continue
            try:
                os.replace(path, dst)
                harden_file(dst)
            except Exception:
                pass
    except Exception:
        pass


def norm_id_for_wire(node_id: str) -> str:
    if not node_id:
        return node_id
    nid = node_id.strip()
    if not nid.startswith("!"):
        nid = "!" + nid
    return nid


def resolve_peer_arg(peer_arg: str, keydir: str) -> Tuple[Optional[str], Optional[str]]:
    if not peer_arg:
        return (None, None)
    if ("/" in peer_arg) or ("\\" in peer_arg) or peer_arg.endswith(".pub"):
        base = os.path.basename(peer_arg)
        stem = os.path.splitext(base)[0]
        peer_id_norm = norm_id_for_filename(stem)
        return (peer_id_norm, peer_arg)
    peer_id_norm = norm_id_for_filename(peer_arg)
    return (peer_id_norm, os.path.join(keydir, f"{peer_id_norm}.pub"))


def wire_id_from_norm(peer_id_norm: str) -> str:
    if not peer_id_norm:
        return peer_id_norm
    return norm_id_for_wire(peer_id_norm)


def is_broadcast_dest(dest_id: object) -> bool:
    try:
        raw = str(dest_id or "").strip().lower()
    except Exception:
        raw = ""
    if not raw:
        return False
    known = {
        str(meshtastic.BROADCAST_ADDR).strip().lower(),
        "^all",
        "all",
        "!ffffffff",
        "ffffffff",
    }
    if raw in known:
        return True
    try:
        norm = norm_id_for_filename(raw).lower()
    except Exception:
        norm = raw
    return norm == "ffffffff"


class PeerState:
    def __init__(self, peer_id_norm: str, aes: Optional[AESGCM] = None) -> None:
        self.peer_id_norm = peer_id_norm
        self.aes = aes
        # Rekey (session) state: encrypted control messages upgrade `aes` without changing pinned peer pubkey.
        self.rekey_inflight = False
        self.rekey_id = b""
        self.rekey_priv: Optional[x25519.X25519PrivateKey] = None
        self.rekey_started_ts = 0.0
        self.rekey_next_retry_ts = 0.0
        self.rekey_attempts = 0
        self.rekey_candidate_id = b""
        self.rekey_candidate_aes: Optional[AESGCM] = None
        self.rekey_candidate_pub = b""
        self.rekey_candidate_ts = 0.0
        self.prev_aes: Optional[AESGCM] = None
        self.prev_aes_until_ts = 0.0
        self.last_rekey_ts = 0.0
        self.rekey_sent_msgs = 0
        self.last_seen_ts = 0.0
        # Last explicit meshTalk-offline signal received from this peer.
        self.app_offline_ts = 0.0
        # Peer node was observed in mesh network (any packet / node DB signal).
        self.device_seen_ts = 0.0
        # Set only after confirmed two-way key exchange (peer has our pub and we have peer pub).
        self.key_confirmed_ts = 0.0
        self.compression_capable = False
        # Local MC mode capabilities are resolved from config at runtime.
        self.compression_modes = set(LEGACY_COMPRESSION_MODES)
        self.aad_type_bound = False
        # Peer-advertised protocol versions (from KR1/KR2 frames).
        # Defaults keep backwards compatibility with legacy clients that do not advertise these fields.
        self.peer_wire_versions = {int(PROTO_VERSION)}
        self.peer_msg_versions = {1}  # legacy "T..." framing
        self.peer_mc_versions = {1}   # MC block VERSION
        self.pending: Dict[str, Dict[str, object]] = {}
        self.last_send_ts = 0.0
        self.next_key_req_ts = 0.0
        self.rtt_avg = 0.0
        self.rtt_count = 0
        self.force_key_req = False
        self.decrypt_fail_count = 0
        self.last_decrypt_fail_ts = 0.0
        self.last_key_ok_ts = 0.0
        self.last_key_req_ts = 0.0
        self.last_key_req_reason = ""
        self.last_key_req_initiator = ""
        self.next_key_refresh_ts = 0.0
        self.await_key_confirm = False
        # TOFU pinning / key mismatch diagnostics (peer rotated key, but we keep old key until user resets).
        self.pinned_mismatch = False
        self.pinned_old_fp = ""
        self.pinned_new_fp = ""
        self.pinned_new_pub_b64 = ""
        self.last_pinned_mismatch_log_ts = 0.0

    @property
    def key_ready(self) -> bool:
        return self.aes is not None


def _int_cfg(value: object, default: int, min_v: int, max_v: int) -> int:
    try:
        v = int(value)
    except Exception:
        v = int(default)
    if v < int(min_v):
        return int(min_v)
    if v > int(max_v):
        return int(max_v)
    return int(v)


def resolve_peer_path(peer_arg: str) -> str:
    # If peer_arg is a bare id (no path separators, no .pub), map to keyRings/<id>.pub
    if not peer_arg:
        return peer_arg
    if ("/" not in peer_arg) and ("\\" not in peer_arg) and (not peer_arg.endswith(".pub")):
        return os.path.join(keydir, f"{norm_id_for_filename(peer_arg)}.pub")
    return peer_arg


def peer_request_id(args_user: Optional[str]) -> Optional[str]:
    if not args_user:
        return None
    if ("/" in args_user) or ("\\" in args_user) or args_user.endswith(".pub"):
        return None
    return args_user


def parse_key_frame(
    payload: bytes,
) -> Optional[
    Tuple[
        str,
        str,
        bytes,
        Optional[set[int]],
        Optional[set[str]],
        Optional[set[int]],
        Optional[set[int]],
        Optional[set[int]],
    ]
]:
    parsed = parse_key_exchange_frame(
        payload=payload,
        key_req_prefix=KEY_REQ_PREFIX,
        key_resp_prefix=KEY_RESP_PREFIX,
        supported_modes=set(supported_mc_modes_for_config(cfg)),
    )
    if parsed is None:
        return None
    kind, peer_id, pub_raw, peer_modes, peer_caps, peer_wire, peer_msg, peer_mc = parsed
    return (
        kind,
        peer_id,
        pub_raw,
        set(peer_modes) if peer_modes else None,
        set(peer_caps) if peer_caps else None,
        set(peer_wire) if peer_wire else None,
        set(peer_msg) if peer_msg else None,
        set(peer_mc) if peer_mc else None,
    )


def parse_app_offline_frame(payload: bytes) -> Optional[str]:
    try:
        raw = bytes(payload or b"")
    except Exception:
        return None
    if not raw.startswith(APP_OFFLINE_PREFIX):
        return None
    try:
        peer_raw = raw[len(APP_OFFLINE_PREFIX) :].split(b"|", 1)[0].decode("utf-8", errors="ignore")
    except Exception:
        return None
    peer_norm = norm_id_for_filename(peer_raw)
    return peer_norm if peer_norm else None


def load_known_peers(keydir: str, self_id_norm: str) -> Dict[str, x25519.X25519PublicKey]:
    peers: Dict[str, x25519.X25519PublicKey] = {}
    if not os.path.isdir(keydir):
        return peers
    for name in os.listdir(keydir):
        if not name.endswith(".pub"):
            continue
        stem = os.path.splitext(name)[0]
        peer_norm = norm_id_for_filename(stem)
        if not peer_norm or peer_norm == self_id_norm:
            continue
        path = os.path.join(keydir, name)
        try:
            peers[peer_norm] = load_pub(path)
        except Exception:
            continue
    return peers


def get_self_id(interface: SerialInterface) -> Optional[str]:
    try:
        info = interface.getMyNodeInfo()
        if isinstance(info, dict):
            user = info.get("user") if isinstance(info.get("user"), dict) else {}
            nid = user.get("id") or info.get("id")
            if isinstance(nid, str) and nid:
                return nid
    except Exception:
        pass
    try:
        user = interface.getMyUser()
        if isinstance(user, dict):
            nid = user.get("id")
            if isinstance(nid, str) and nid:
                return nid
    except Exception:
        pass
    return None


def main() -> int:
    maybe_set_private_umask()
    cfg_cli: Dict[str, object] = {}
    discovery_enabled = True
    discovery_send = discovery_enabled
    discovery_reply = discovery_enabled
    ap = argparse.ArgumentParser(
        prog="meshTalk.py",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
    )
    ap.add_argument("-h", "--help", action="store_true", help="show this help message and exit. RU: показать помощь и выйти.")
    ap.add_argument("--version", action="store_true", help="print version and exit. RU: вывести версию и выйти.")

    ap.add_argument("--port", default="auto", help="serial port or 'auto' (default: auto). RU: серийный порт или 'auto' (по умолчанию: auto).")
    ap.add_argument("--channel", type=int, default=None, help="Meshtastic channel index (default: main). RU: индекс канала Meshtastic (по умолчанию: основной).")

    # self id is auto-detected from radio

    ap.add_argument("--retry-seconds", type=int, default=30, help="retry interval in seconds (default: 30). RU: интервал повторов, сек (по умолчанию: 30).")
    ap.add_argument("--max-seconds", type=int, default=3600, help="max time to wait for ACK (default: 3600). RU: максимум ожидания ACK, сек (по умолчанию: 3600).")
    ap.add_argument("--max-bytes", type=int, default=200, help="max payload bytes per packet (default: 200). RU: максимум байт полезной нагрузки (по умолчанию: 200).")
    ap.add_argument("--rate-seconds", type=int, default=30, help="min seconds between sends (default: 30). RU: минимум секунд между отправками (по умолчанию: 30).")
    ap.add_argument(
        "--parallel-sends",
        type=int,
        default=1,
        help="packets per rate window (default: 1). RU: сколько пакетов можно отправить подряд в одном окне rate (по умолчанию: 1).",
    )
    ap_pacing = ap.add_mutually_exclusive_group()
    ap_pacing.add_argument(
        "--auto-pacing",
        dest="auto_pacing",
        action="store_true",
        help="auto tune rate/parallel (default: on). RU: автоподбор rate/параллельности (по умолчанию: вкл).",
    )
    ap_pacing.add_argument(
        "--no-auto-pacing",
        dest="auto_pacing",
        action="store_false",
        help="disable auto pacing. RU: выключить автоподбор скорости.",
    )
    ap.set_defaults(auto_pacing=True)


    args = ap.parse_args()
    initial_port_arg = args.port

    startup_crash_log = os.path.join(DATA_DIR, "startup_crash.log")
    _crash_fh = None

    def startup_log(msg: str) -> None:
        try:
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            with open(startup_crash_log, "a", encoding="utf-8") as f:
                f.write(f"{ts} {msg}\n")
        except Exception:
            pass

    startup_log(f"BOOT: start v{VERSION} platform={sys.platform} port={args.port}")
    try:
        _crash_fh = open(startup_crash_log, "a", encoding="utf-8")
        faulthandler.enable(file=_crash_fh, all_threads=True)

        def _close_crash_fh() -> None:
            try:
                if _crash_fh is not None:
                    _crash_fh.flush()
                    _crash_fh.close()
            except Exception:
                pass

        atexit.register(_close_crash_fh)
        startup_log("BOOT: faulthandler enabled")
    except Exception as e:
        startup_log(f"BOOT: faulthandler enable failed: {type(e).__name__}: {e}")

    _prev_excepthook = sys.excepthook

    def _startup_excepthook(exc_type, exc_value, exc_tb):
        try:
            startup_log("BOOT: unhandled exception:")
            startup_log("".join(traceback.format_exception(exc_type, exc_value, exc_tb)).rstrip())
        except Exception:
            pass
        try:
            _prev_excepthook(exc_type, exc_value, exc_tb)
        except Exception:
            pass

    sys.excepthook = _startup_excepthook

    pacer = AdaptivePacer(
        rate_seconds=int(getattr(args, "rate_seconds", 30) or 30),
        parallel_sends=int(getattr(args, "parallel_sends", 1) or 1),
        enabled=bool(getattr(args, "auto_pacing", False)),
    )

    if args.help:
        ap.print_help()
        return 0
    if args.version:
        print(VERSION)
        return 0


    startup_events = []
    interface: Optional[SerialInterface] = None
    self_id_raw: Optional[str] = None
    self_id = ""
    priv_path: Optional[str] = None
    pub_path: Optional[str] = None
    priv: Optional[x25519.X25519PrivateKey] = None
    pub_self: Optional[x25519.X25519PublicKey] = None
    pub_self_raw: bytes = b""
    generated_now = False
    radio_ready = False

    # GUI-only mode: no CLI validation needed

    peer_id_norm, peer_path = (None, None)
    known_peers: Dict[str, x25519.X25519PublicKey] = {}
    peer_names: Dict[str, Dict[str, str]] = {}
    peer_names_lock = threading.Lock()
    incoming_state: Dict[str, Dict[str, object]] = {}

    def _peer_name_parts(peer_id_any: str) -> Tuple[str, str]:
        """Return (long_name, short_name) from Meshtastic node DB cache.

        peer_id_any can be wire form (!xxxxxxxx) or normalized form (xxxxxxxx).
        """
        try:
            norm_raw = norm_id_for_filename(str(peer_id_any or ""))
            norm = norm_raw.lower() if re.fullmatch(r"[0-9a-fA-F]{8}", norm_raw) else norm_raw
        except Exception:
            norm_raw = str(peer_id_any or "")
            norm = norm_raw
        with peer_names_lock:
            rec = peer_names.get(norm) or peer_names.get(norm_raw) or {}
            if not isinstance(rec, dict):
                return ("", "")
            return (str(rec.get("long", "") or "").strip(), str(rec.get("short", "") or "").strip())

    def update_peer_names_from_nodes(peer_norm: Optional[str] = None) -> None:
        try:
            if interface is None:
                return
            nodes = getattr(interface, "nodes", None)
            if not isinstance(nodes, dict):
                return
            want = None
            if isinstance(peer_norm, str) and peer_norm:
                want = peer_norm
                if re.fullmatch(r"[0-9a-fA-F]{8}", want):
                    want = want.lower()
            # Copy values to reduce risk of RuntimeError if `nodes` mutates during iteration.
            node_vals = list(nodes.values())
            for node in node_vals:
                if not isinstance(node, dict):
                    continue
                user = node.get("user") if isinstance(node.get("user"), dict) else {}
                nid = user.get("id") or node.get("id")
                if not isinstance(nid, str) or not nid:
                    continue
                norm_raw = norm_id_for_filename(nid)
                norm = norm_raw.lower() if re.fullmatch(r"[0-9a-fA-F]{8}", norm_raw) else norm_raw
                if want and norm != want:
                    continue
                long_name = user.get("longName") or user.get("longname") or node.get("longName")
                short_name = user.get("shortName") or user.get("shortname") or node.get("shortName")
                last_heard_ts = 0.0
                try:
                    lh = node.get("lastHeard")
                    if isinstance(lh, (int, float)) and float(lh) > 0.0:
                        last_heard_ts = float(lh)
                except Exception:
                    last_heard_ts = 0.0
                if long_name or short_name or last_heard_ts > 0.0:
                    rec = {"long": str(long_name or ""), "short": str(short_name or "")}
                    if last_heard_ts > 0.0:
                        rec["last_heard_ts"] = float(last_heard_ts)
                    with peer_names_lock:
                        peer_names[norm] = rec
                        # Preserve original-case key too (if different), for UI lookups from user input/history.
                        if norm_raw != norm:
                            peer_names[norm_raw] = rec
                    if last_heard_ts > 0.0:
                        st = get_peer_state(norm)
                        if st and float(last_heard_ts) > float(getattr(st, "device_seen_ts", 0.0) or 0.0):
                            st.device_seen_ts = float(last_heard_ts)
        except Exception:
            return

    def try_init_radio() -> tuple[bool, str]:
        nonlocal interface, self_id_raw, self_id, priv, pub_self, pub_self_raw, generated_now, known_peers, radio_ready, priv_path, pub_path
        nonlocal subscriptions_registered
        # Auto-detect port
        port = args.port
        if port.lower() == "auto":
            detected = detect_serial_port()
            if not detected:
                return (False, "Waiting for radio (no ports)")
            port = detected
        elif port == "/dev/ttyUSB0" and sys.platform.startswith("win"):
            detected = detect_serial_port()
            if detected:
                port = detected
            else:
                return (False, "Waiting for radio (port not found)")
        try:
            interface = SerialInterface(devPath=port)
        except Exception:
            interface = None
            return (False, "Waiting for radio (open failed)")
        args.port = port
        startup_events.append(f"{ts_local()} PORT: opened {port}")
        self_id_raw = get_self_id(interface)
        if not self_id_raw:
            interface = None
            return (False, "Waiting for radio (no self id)")
        startup_events.append(f"{ts_local()} NODE: self id {self_id_raw}")
        self_id = norm_id_for_filename(self_id_raw)
        raw_stem = str(self_id_raw or "").strip()
        if raw_stem.startswith("!"):
            raw_stem = raw_stem[1:]
        peer_id_norm = self_id
        set_data_dir_for_node(self_id)
        # Migrate old per-node dir if the radio reports a mixed-case id and we now canonicalize to lowercase.
        if raw_stem and raw_stem != self_id:
            migrate_data_dir(os.path.join(BASE_DIR, raw_stem), DATA_DIR)
            migrate_data_dir(os.path.join(LEGACY_BASE_DIR, raw_stem), DATA_DIR)
        migrate_data_dir(os.path.join(LEGACY_BASE_DIR, self_id), DATA_DIR)
        migrate_data_dir(LEGACY_BASE_DIR, DATA_DIR)
        canonicalize_keyring_filenames(keydir)
        ensure_storage_key()
        ui_emit(
            "log",
            f"{ts_local()} CRYPTO: mt_key=KR1/KR2 plaintext pub=X25519(32b,b64) kdf=HKDF-SHA256 aead=MT-WIREv1 AES-256-GCM storage=AES-256-GCM(keyRings/storage.key)",
        )
        try:
            max_payload = int(getattr(args, "max_bytes", 200) or 200)
        except Exception:
            max_payload = 200
        wire_overhead = int(PAYLOAD_OVERHEAD)
        max_plain = max(0, max_payload - wire_overhead)
        max_m2_chunk = max(1, max_plain - int(MSG_V2_HEADER_LEN))
        ui_emit(
            "log",
            f"{ts_local()} LIMITS: max_bytes={max_payload} wire_overhead={wire_overhead} max_plain={max_plain} m2_header={int(MSG_V2_HEADER_LEN)} max_m2_chunk={max_m2_chunk}",
        )
        priv_path = os.path.join(keydir, f"{self_id}.key")
        pub_path = os.path.join(keydir, f"{self_id}.pub")
        # Ensure key files exist (auto-generate if missing)
        if not os.path.isfile(priv_path) or not os.path.isfile(pub_path):
            os.makedirs(os.path.dirname(priv_path) or ".", exist_ok=True)
            priv = x25519.X25519PrivateKey.generate()
            pub_key = priv.public_key()
            priv_raw = priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_raw = pub_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            with open(priv_path, "w", encoding="utf-8") as f:
                f.write(b64e(priv_raw))
            with open(pub_path, "w", encoding="utf-8") as f:
                f.write(b64e(pub_raw))
            harden_file(priv_path)
            harden_file(pub_path)
            generated_now = True
            ui_emit("log", f"{ts_local()} KEY: auto-generated keys -> {priv_path}, {pub_path}")
        harden_file(priv_path)
        harden_file(pub_path)
        priv = load_priv(priv_path)
        pub_self = load_pub(pub_path)
        pub_self_raw = pub_self.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        known_peers = load_known_peers(keydir, self_id)
        radio_ready = True
        update_peer_names_from_nodes()
        ui_emit("log", f"{ts_local()} RADIO: self {wire_id_from_norm(self_id)}")
        if not subscriptions_registered:
            try:
                pub.subscribe(on_receive, "meshtastic.receive.data")
                try:
                    pub.subscribe(on_receive, "meshtastic.receive")
                except Exception:
                    pass

                def _on_conn_status(*_args, **_kwargs):
                    try:
                        evt = _kwargs.get("evt")
                        if isinstance(evt, dict) and evt.get("connected") is False:
                            ui_emit("radio_lost", None)
                            return
                    except Exception:
                        pass

                pub.subscribe(_on_conn_status, "meshtastic.connection.status")
                subscriptions_registered = True
            except Exception:
                pass
        ui_emit("config_reload", load_config())
        return (True, f"Connected {port}")

    update_peer_names_from_nodes()

    pending_by_peer: Dict[str, Dict[str, Dict[str, object]]] = {}
    pending_lock = threading.Lock()
    seen_msgs: Dict[str, float] = {}
    seen_parts: Dict[str, float] = {}
    key_response_last_ts: Dict[str, float] = {}
    seen_lock = threading.Lock()
    subscriptions_registered = False
    peer_states: Dict[str, PeerState] = {}
    tracked_peers = set()
    ui_events: "queue.Queue[Tuple[str, object]]" = queue.Queue()
    gui_enabled = True
    last_activity_ts = time.time()
    last_key_sent_ts = 0.0
    # Config must be available to sender_loop/key exchange/discovery even before GUI starts.
    global cfg
    cfg = load_config()
    # Security policy (TOFU key rotation). Must be visible to on_receive().
    security_policy = "auto"  # auto|strict|always
    # Session rekey (ephemeral X25519) to reduce impact of long-term key compromise.
    session_rekey_enabled = True

    def ui_emit(evt: str, payload: object) -> None:
        if gui_enabled:
            ui_events.put((evt, payload))

    decode_guard_installed = False

    def install_meshtastic_decode_guard() -> None:
        nonlocal decode_guard_installed
        if decode_guard_installed:
            return
        try:
            from google.protobuf.message import DecodeError  # type: ignore
            from meshtastic import mesh_interface as _mesh_interface
            if getattr(_mesh_interface.MeshInterface, "_meshtalk_decode_guard", False):
                decode_guard_installed = True
                return
            original_handle = _mesh_interface.MeshInterface._handleFromRadio

            def _guarded_handle(self_iface, from_radio_bytes):
                try:
                    return original_handle(self_iface, from_radio_bytes)
                except DecodeError as ex:
                    try:
                        ui_emit("log", f"{ts_local()} RADIO: protobuf decode error, reconnecting ({ex})")
                        ui_emit("radio_lost", None)
                    except Exception:
                        pass
                    return None

            _mesh_interface.MeshInterface._handleFromRadio = _guarded_handle
            _mesh_interface.MeshInterface._meshtalk_decode_guard = True
            decode_guard_installed = True
        except Exception:
            pass

    install_meshtastic_decode_guard()

    def get_peer_state(peer_norm: Optional[str]) -> Optional[PeerState]:
        if not peer_norm:
            return None
        if not radio_ready:
            return None
        st = peer_states.get(peer_norm)
        if st is None:
            if peer_norm == self_id:
                aes_local = AESGCM(derive_key(priv, pub_self))
                st = PeerState(peer_norm, aes_local)
                st.compression_capable = True
                st.compression_modes = set(supported_mc_modes_for_config(cfg))
                st.last_key_ok_ts = time.time()
                peer_states[peer_norm] = st
                return st
            pub = known_peers.get(peer_norm)
            aes_local = AESGCM(derive_key(priv, pub)) if pub else None
            st = PeerState(peer_norm, aes_local)
            if aes_local:
                st.last_key_ok_ts = time.time()
            peer_states[peer_norm] = st
        return st

    def update_peer_pub(peer_norm: str, pub_raw: bytes) -> None:
        try:
            pub_local = x25519.X25519PublicKey.from_public_bytes(pub_raw)
        except Exception:
            return
        known_peers[peer_norm] = pub_local
        st = get_peer_state(peer_norm)
        if st:
            st.aes = AESGCM(derive_key(priv, pub_local))
            st.last_key_ok_ts = time.time()

    def store_peer_pub(peer_id: str, pub_raw: bytes) -> str:
        if not isinstance(pub_raw, (bytes, bytearray)):
            raise ValueError("invalid peer public key type")
        pub_raw_bytes = bytes(pub_raw)
        if len(pub_raw_bytes) != 32:
            raise ValueError("invalid peer public key length")
        # Validate key bytes before persisting key file.
        x25519.X25519PublicKey.from_public_bytes(pub_raw_bytes)
        peer_id_norm = norm_id_for_filename(peer_id)
        # Defensive: peer_id is untrusted input from the wire; never allow
        # path traversal / weird filenames to end up in key storage.
        if not re.fullmatch(r"[0-9a-fA-F]{8}", peer_id_norm):
            raise ValueError("invalid peer id")
        path = os.path.join(keydir, f"{peer_id_norm}.pub")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        # TOFU pinning: never silently overwrite an existing peer key.
        if os.path.isfile(path):
            try:
                prev = b64d(open(path, "r", encoding="utf-8").read().strip())
                if isinstance(prev, (bytes, bytearray)) and bytes(prev) != pub_raw_bytes:
                    raise PeerKeyPinnedError(peer_id_norm, pub_fingerprint(bytes(prev)), pub_fingerprint(pub_raw_bytes))
            except PeerKeyPinnedError:
                raise
            except Exception:
                # Corrupted key file: allow overwrite to recover.
                pass
        with open(path, "w", encoding="utf-8") as f:
            f.write(b64e(pub_raw_bytes))
        harden_file(path)
        update_peer_pub(peer_id_norm, pub_raw_bytes)
        # Clear pinned mismatch state on successful store.
        st = get_peer_state(peer_id_norm)
        if st:
            st.pinned_mismatch = False
            st.pinned_old_fp = ""
            st.pinned_new_fp = ""
            st.pinned_new_pub_b64 = ""
        return path

    def force_store_peer_pub(peer_id: str, pub_raw: bytes) -> str:
        """Store peer public key even if it overwrites an existing pinned key (used by policy)."""
        if not isinstance(pub_raw, (bytes, bytearray)):
            raise ValueError("invalid peer public key type")
        pub_raw_bytes = bytes(pub_raw)
        if len(pub_raw_bytes) != 32:
            raise ValueError("invalid peer public key length")
        x25519.X25519PublicKey.from_public_bytes(pub_raw_bytes)
        peer_id_norm = norm_id_for_filename(peer_id)
        if not re.fullmatch(r"[0-9a-fA-F]{8}", peer_id_norm):
            raise ValueError("invalid peer id")
        path = os.path.join(keydir, f"{peer_id_norm}.pub")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(b64e(pub_raw_bytes))
        harden_file(path)
        update_peer_pub(peer_id_norm, pub_raw_bytes)
        st = get_peer_state(peer_id_norm)
        if st:
            st.pinned_mismatch = False
            st.pinned_old_fp = ""
            st.pinned_new_fp = ""
            st.pinned_new_pub_b64 = ""
        return path

    def should_auto_accept_peer_key_rotation(peer_norm: str, st: Optional[PeerState]) -> tuple[bool, str]:
        # Read policy from config at call-time to avoid relying on closure state.
        pol = str(cfg.get("security_key_rotation_policy", "auto") or "auto").strip().lower()
        try:
            key_conf = float(getattr(st, "key_confirmed_ts", 0.0) or 0.0) if st else 0.0
        except Exception:
            key_conf = 0.0

        if pol == "always":
            return True, f"policy=always key_confirmed={1 if key_conf > 0.0 else 0}"
        if pol == "strict":
            return False, f"policy=strict key_confirmed={1 if key_conf > 0.0 else 0}"

        # AUTO (without time heuristics): accept rotation only if the previous pinned key was never confirmed.
        # Once a key was confirmed, require explicit user action (Reset key) to accept a new key.
        if key_conf <= 0.0:
            return True, "policy=auto reason=unconfirmed_old_key"
        return False, "policy=auto reason=confirmed_old_key action=reset_key_required"

    def _rekey_derive_aes(peer_norm: str, eph_shared: bytes) -> Optional[AESGCM]:
        """Derive a new session AES key from (static X25519 shared || ephemeral X25519 shared)."""
        try:
            if not re.fullmatch(r"[0-9a-fA-F]{8}", peer_norm or ""):
                return None
            peer_pub = known_peers.get(peer_norm)
            if peer_pub is None or priv is None:
                return None
            base_shared = priv.exchange(peer_pub)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"meshTalk rekey v1",
                info=b"meshTalk rekey v1",
            )
            key = hkdf.derive(bytes(base_shared) + bytes(eph_shared))
            return AESGCM(key)
        except Exception:
            return None

    def _rekey_should_start(st: PeerState, now: float) -> bool:
        if not st or not st.key_ready:
            return False
        if not bool(getattr(st, "key_confirmed_ts", 0.0) or 0.0):
            return False
        if bool(getattr(st, "pinned_mismatch", False)):
            return False
        if bool(getattr(st, "rekey_inflight", False)):
            return False
        if (now - float(getattr(st, "last_rekey_ts", 0.0) or 0.0)) < float(REKEY_MIN_INTERVAL_SECONDS):
            return False
        if int(getattr(st, "rekey_sent_msgs", 0) or 0) < int(REKEY_MIN_MESSAGES):
            return False
        return True

    def _send_control(peer_norm: str, pt: bytes, aes: AESGCM, label: str) -> bool:
        """Send encrypted control message (not stored in history)."""
        nonlocal last_activity_ts
        if not radio_ready or interface is None:
            return False
        if not peer_norm or peer_norm.startswith("group:"):
            return False
        if not re.fullmatch(r"[0-9a-fA-F]{8}", peer_norm):
            return False
        try:
            msg_id = os.urandom(8)
            payload, _cmp = pack_message(
                TYPE_MSG,
                msg_id,
                aes,
                pt,
                allow_payload_compress=False,
                bind_aad_type=True,
            )
            if len(payload) > int(getattr(args, "max_bytes", 200) or 200):
                return False
            interface.sendData(
                payload,
                destinationId=wire_id_from_norm(peer_norm),
                wantAck=False,
                portNum=DEFAULT_PORTNUM,
                channelIndex=(args.channel if args.channel is not None else 0),
            )
            last_activity_ts = time.time()
            ui_emit("log", f"{ts_local()} KEY: rekey {label} -> {peer_norm} wire=MT-WIREv1 aes-256-gcm")
            return True
        except Exception:
            return False

    def _rekey_send_rk1(peer_norm: str, st: PeerState, now: float) -> None:
        try:
            if not st.aes:
                return
            st.rekey_inflight = True
            st.rekey_started_ts = now
            st.rekey_attempts = int(getattr(st, "rekey_attempts", 0) or 0) + 1
            if not st.rekey_id or len(st.rekey_id) != 4:
                st.rekey_id = os.urandom(4)
            if st.rekey_priv is None:
                st.rekey_priv = x25519.X25519PrivateKey.generate()
            epub = st.rekey_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            pt = REKEY_CTRL_PREFIX1 + st.rekey_id + epub
            ok = _send_control(peer_norm, pt, st.aes, f"rk1 attempt={st.rekey_attempts}")
            st.rekey_next_retry_ts = now + retry_delay_seconds(float(REKEY_RETRY_BASE_SECONDS), st.rekey_attempts)
            if not ok:
                # Don't spin.
                st.rekey_inflight = False
        except Exception:
            st.rekey_inflight = False

    def on_receive(packet, interface=None):
        nonlocal last_activity_ts
        # Device presence signal: any packet from peer means node is present in mesh.
        try:
            now_seen = time.time()
            from_id_any = packet.get("fromId")
            peer_norm_any = norm_id_for_filename(from_id_any) if from_id_any else None
            if peer_norm_any:
                st_any = get_peer_state(peer_norm_any)
                if st_any:
                    st_any.device_seen_ts = now_seen
        except Exception:
            pass
        decoded = packet.get("decoded") or {}
        portnum = decoded.get("portnum")
        # Standard Meshtastic text chat compatibility (for peers that never used meshTalk app).
        is_text_port = False
        if isinstance(portnum, str):
            is_text_port = (portnum == "TEXT_MESSAGE_APP")
        elif isinstance(portnum, int):
            is_text_port = (portnum == int(portnums_pb2.PortNum.TEXT_MESSAGE_APP))
        if is_text_port:
            from_id_text = packet.get("fromId")
            peer_norm_text = norm_id_for_filename(from_id_text) if from_id_text else None
            if not peer_norm_text or peer_norm_text == self_id:
                return
            to_id_text = packet.get("toId") or packet.get("to")
            dialog_id_text = "group:Primary" if is_broadcast_dest(to_id_text) else peer_norm_text
            payload_text = parse_payload(decoded.get("payload"))
            text_plain = ""
            if isinstance(payload_text, (bytes, bytearray)) and payload_text:
                try:
                    text_plain = bytes(payload_text).decode("utf-8", errors="replace").strip()
                except Exception:
                    text_plain = ""
            if not text_plain:
                try:
                    txt = decoded.get("text")
                    if txt is None:
                        txt = packet.get("text")
                    text_plain = str(txt or "").strip()
                except Exception:
                    text_plain = ""
            if not text_plain:
                ui_emit("log", f"{ts_local()} RECVSTD: empty text payload from {peer_norm_text}")
                return
            packet_id = packet.get("id")
            if isinstance(packet_id, int):
                std_msg_id = f"mtxt:{int(packet_id) & 0xFFFFFFFF:08x}"
            else:
                try:
                    rx_time = packet.get("rxTime")
                    if rx_time is None:
                        rx_time = decoded.get("rxTime")
                    basis = "|".join(
                        [
                            str(peer_norm_text or ""),
                            str(to_id_text or ""),
                            str(rx_time or ""),
                            str(text_plain or ""),
                        ]
                    ).encode("utf-8", errors="replace")
                    std_msg_id = f"mtxt:{(zlib.crc32(basis) & 0xFFFFFFFF):08x}"
                except Exception:
                    std_msg_id = f"mtxt:{os.urandom(4).hex()}"
            ui_emit("recv_plain", (peer_norm_text, text_plain, std_msg_id, dialog_id_text))
            return
        if isinstance(portnum, str):
            if portnum != "PRIVATE_APP":
                return
        elif isinstance(portnum, int):
            if portnum != int(DEFAULT_PORTNUM):
                return
        payload = parse_payload(decoded.get("payload"))
        if not payload:
            return

        app_offline_peer = parse_app_offline_frame(payload)
        if app_offline_peer:
            from_id_seen = packet.get("fromId")
            from_norm = norm_id_for_filename(from_id_seen) if from_id_seen else None
            peer_norm = app_offline_peer
            if from_norm and from_norm != peer_norm:
                ui_emit(
                    "log",
                    f"{ts_local()} PRESENCE: ignored offline frame id mismatch from={from_norm} payload={peer_norm}",
                )
                return
            st_off = get_peer_state(peer_norm)
            now_seen = time.time()
            if st_off:
                st_off.last_seen_ts = 0.0
                st_off.app_offline_ts = now_seen
                st_off.await_key_confirm = False
                st_off.force_key_req = False
                st_off.next_key_req_ts = float("inf")
            try:
                rec = peer_meta.setdefault(peer_norm, {})
                if isinstance(rec, dict):
                    rec["last_seen_ts"] = 0.0
                    rec["app_offline_ts"] = now_seen
            except Exception:
                pass
            ui_emit("refresh", None)
            ui_emit("log", f"{ts_local()} PRESENCE: app offline broadcast from {peer_norm}")
            return

        # Key exchange frames are plaintext
        key_frame = parse_key_frame(payload)
        if key_frame:
            kind, peer_id, pub_raw, peer_modes, peer_caps, peer_wire, peer_msg, peer_mc = key_frame
            from_id_raw = packet.get("fromId")
            to_id = packet.get("toId") or packet.get("to")
            accepted_frame, trusted_capabilities, reject_reason, is_broadcast, from_id = key_frame_receive_policy(
                peer_id=peer_id,
                from_id_raw=from_id_raw,
                to_id=to_id,
                broadcast_addr=meshtastic.BROADCAST_ADDR,
                discovery_reply=bool(discovery_reply),
            )
            if not accepted_frame and reject_reason == "broadcast_disabled":
                return
            peer_norm = norm_id_for_filename(peer_id)
            update_peer_names_from_nodes(peer_norm)
            if not accepted_frame and reject_reason == "missing_from_id":
                ui_emit("log", f"{ts_local()} KEY: reject frame from {peer_id} (missing fromId).")
                return
            if not accepted_frame and reject_reason == "id_mismatch":
                ui_emit(
                    "log",
                    f"{ts_local()} KEY: reject frame id mismatch from={from_id_raw} payload={peer_id}.",
                )
                return
            if not accepted_frame:
                ui_emit("log", f"{ts_local()} KEY: reject frame from {peer_id}.")
                return
            try:
                st_seen = get_peer_state(peer_norm)
                if st_seen:
                    st_seen.last_seen_ts = time.time()
                    st_seen.app_offline_ts = 0.0
            except Exception:
                pass
            try:
                store_peer_pub(peer_id, pub_raw)
            except PeerKeyPinnedError as ex:
                st = get_peer_state(peer_norm)
                auto_ok, auto_why = should_auto_accept_peer_key_rotation(peer_norm, st)
                if auto_ok:
                    # Overwrite pinned key according to policy (AUTO/ALWAYS).
                    try:
                        path = os.path.join(keydir, f"{norm_id_for_filename(peer_id)}.pub")
                        try:
                            if os.path.isfile(path):
                                os.remove(path)
                        except Exception:
                            pass
                        force_store_peer_pub(peer_id, pub_raw)
                        ui_emit(
                            "log",
                            f"{ts_local()} KEY: pinned key mismatch peer={peer_id} old={ex.old_fp} new={ex.new_fp} action=auto_accept {auto_why}",
                        )
                    except Exception as e:
                        ui_emit(
                            "log",
                            f"{ts_local()} KEY: pinned key mismatch peer={peer_id} old={ex.old_fp} new={ex.new_fp} action=reset_key_required auto_accept_failed={type(e).__name__}",
                        )
                        # Fall through to pinned-mismatch behavior (manual reset).
                    else:
                        # Continue processing this key frame normally.
                        last_activity_ts = time.time()
                        st2 = get_peer_state(peer_norm)
                        if st2 and trusted_capabilities:
                            if peer_modes:
                                st2.compression_capable = True
                                st2.compression_modes = set(peer_modes)
                            else:
                                st2.compression_capable = False
                                st2.compression_modes = set(LEGACY_COMPRESSION_MODES)
                            st2.aad_type_bound = bool(peer_caps and ("aad_type" in peer_caps))
                            if peer_wire:
                                st2.peer_wire_versions = set(peer_wire)
                            else:
                                st2.peer_wire_versions = {int(PROTO_VERSION)}
                            if peer_msg:
                                st2.peer_msg_versions = set(peer_msg)
                            else:
                                st2.peer_msg_versions = {1}
                            if peer_mc:
                                st2.peer_mc_versions = set(peer_mc)
                            else:
                                st2.peer_mc_versions = {1}
                        if st2 and st2.key_ready and kind == "resp":
                            st2.last_key_ok_ts = time.time()
                            st2.key_confirmed_ts = st2.last_key_ok_ts
                            ui_emit(
                                "log",
                                f"{ts_local()} KEYOK: confirmed_by=resp peer={peer_id} initiator=remote wire=MT-WIREv1 aes-256-gcm",
                            )
                            st2.force_key_req = False
                            st2.await_key_confirm = False
                            st2.next_key_req_ts = float('inf')
                        ui_emit("peer_update", peer_norm)
                        return

                # Peer rotated key. Keep old pinned key until user resets explicitly.
                # Suppress repeated logs to avoid noisy spam loops.
                if st:
                    st.pinned_mismatch = True
                    st.pinned_old_fp = str(ex.old_fp or "")
                    st.pinned_new_fp = str(ex.new_fp or "")
                    st.pinned_new_pub_b64 = b64e(bytes(pub_raw))
                    st.force_key_req = False
                    st.await_key_confirm = False
                    st.next_key_req_ts = float("inf")
                    # Don't keep trying to decrypt with a known-stale key.
                    st.aes = None
                    now = time.time()
                    if (now - float(getattr(st, "last_pinned_mismatch_log_ts", 0.0) or 0.0)) >= 30.0:
                        st.last_pinned_mismatch_log_ts = now
                        ui_emit(
                            "log",
                            f"{ts_local()} KEY: pinned key mismatch peer={peer_id} old={ex.old_fp} new={ex.new_fp} action=reset_key_required {auto_why}",
                        )
                    ui_emit("key_conflict", (peer_norm, str(ex.old_fp or ""), str(ex.new_fp or "")))
                else:
                    ui_emit(
                        "log",
                        f"{ts_local()} KEY: pinned key mismatch peer={peer_id} old={ex.old_fp} new={ex.new_fp} action=reset_key_required {auto_why}",
                    )
                    ui_emit("key_conflict", (peer_norm, str(ex.old_fp or ""), str(ex.new_fp or "")))
                return
            except ValueError:
                ui_emit("log", f"{ts_local()} KEY: reject invalid key frame from {peer_id}.")
                return
            except Exception:
                ui_emit("log", f"{ts_local()} KEY: reject invalid public key from {peer_id}.")
                return
            last_activity_ts = time.time()
            st = get_peer_state(peer_norm)
            if st and trusted_capabilities:
                # Capabilities from key frames are accepted only for verifiable unicast sources.
                if peer_modes:
                    st.compression_capable = True
                    st.compression_modes = set(peer_modes)
                else:
                    # Missing modes means peer is legacy or downgraded: reset stale capabilities.
                    st.compression_capable = False
                    st.compression_modes = set(LEGACY_COMPRESSION_MODES)
                st.aad_type_bound = bool(peer_caps and ("aad_type" in peer_caps))
                if peer_wire:
                    st.peer_wire_versions = set(peer_wire)
                else:
                    st.peer_wire_versions = {int(PROTO_VERSION)}
                if peer_msg:
                    st.peer_msg_versions = set(peer_msg)
                else:
                    st.peer_msg_versions = {1}
                if peer_mc:
                    st.peer_mc_versions = set(peer_mc)
                else:
                    st.peer_mc_versions = {1}
                if peer_wire and int(PROTO_VERSION) not in st.peer_wire_versions:
                    ui_emit(
                        "log",
                        f"{ts_local()} WARN: peer {peer_id} advertises mt_wire={sorted(st.peer_wire_versions)}, local={int(PROTO_VERSION)}.",
                    )
            if st and st.key_ready and kind == "resp":
                st.last_key_ok_ts = time.time()
                st.key_confirmed_ts = st.last_key_ok_ts
                ui_emit(
                    "log",
                    f"{ts_local()} KEYOK: confirmed_by=resp peer={peer_id} initiator=remote wire=MT-WIREv1 aes-256-gcm",
                )
                st.force_key_req = False
                st.await_key_confirm = False
                st.next_key_req_ts = float("inf")
            if kind == "req":
                ui_emit("log", f"{ts_local()} KEY: request from {peer_id} initiator=remote event=req")
                now = time.time()
                last_resp = float(key_response_last_ts.get(peer_norm, 0.0) or 0.0)
                retrying_confirm = bool(st and st.await_key_confirm and not is_broadcast)
                min_reply_interval = (
                    float(KEY_RESPONSE_RETRY_INTERVAL_SECONDS)
                    if retrying_confirm
                    else float(KEY_RESPONSE_MIN_INTERVAL_SECONDS)
                )
                if (now - last_resp) < min_reply_interval:
                    left_s = int(max(0.0, min_reply_interval - (now - last_resp)))
                    ui_emit(
                        "log",
                        f"{ts_local()} KEY: response suppressed peer={peer_id} initiator=remote reason=recent_response wait={left_s}s",
                    )
                else:
                    modes_bytes = ",".join(str(m) for m in supported_mc_modes_for_config(cfg)).encode("ascii")
                    wire_bytes = str(int(PROTO_VERSION)).encode("ascii")
                    msg_bytes = b"1,2"
                    mc_bytes = b"1"
                    resp = (
                        KEY_RESP_PREFIX
                        + self_id.encode("utf-8")
                        + b"|"
                        + b64e(pub_self_raw).encode("ascii")
                        + b"|mc_modes="
                        + modes_bytes
                        + b"|mt_wire="
                        + wire_bytes
                        + b"|mt_msg="
                        + msg_bytes
                        + b"|mt_mc="
                        + mc_bytes
                        + b"|mt_caps=aad_type"
                    )
                    if from_id:
                        interface.sendData(
                            resp,
                            destinationId=from_id,
                            wantAck=False,
                            portNum=DEFAULT_PORTNUM,
                            channelIndex=(args.channel if args.channel is not None else 0),
                        )
                        key_response_last_ts[peer_norm] = now
                    ui_emit(
                        "log",
                        f"{ts_local()} KEY: response sent to {peer_id} initiator=remote event=req_reply retry_confirm={1 if retrying_confirm else 0} frame=KR2 plaintext x25519+hkdf-sha256->aes-256-gcm",
                    )
                if st and not is_broadcast and bool(st.await_key_confirm):
                    # Receiving peer KR1 must not start a new local confirm loop by itself.
                    # Only extend timer if we already have our own confirm flow in progress.
                    st.next_key_req_ts = now + max(1.0, float(args.retry_seconds))
            else:
                if st:
                    st.force_key_req = False
                    st.await_key_confirm = False
                    st.next_key_req_ts = float("inf")
                    st.last_key_ok_ts = time.time()
                    if st.key_ready and st.key_confirmed_ts <= 0.0:
                        # Response implies peer received our pub key, so this is confirmed.
                        st.key_confirmed_ts = st.last_key_ok_ts
            ui_emit("peer_update", peer_norm)
            return

        from_id = packet.get("fromId")
        peer_norm = norm_id_for_filename(from_id) if from_id else None
        update_peer_names_from_nodes(peer_norm)
        st = get_peer_state(peer_norm)
        if not st or not st.aes:
            if peer_norm and from_id:
                st = get_peer_state(peer_norm)
                if st:
                    st.force_key_req = True
                    now = time.time()
                    if now >= st.next_key_req_ts:
                        send_key_request(peer_norm, require_confirm=True, reason="rx_no_key")
                        st.next_key_req_ts = now + max(1.0, float(args.retry_seconds))
                        ui_emit("log", f"{ts_local()} KEY: request (no key) -> {from_id}")
                        ui_emit("peer_update", peer_norm)
            return

        # Rekey can temporarily accept multiple keys to avoid network churn during switch.
        aes_used = st.aes
        status, msg_type, msg_id, pt, rx_compression = try_unpack_message(
            payload, st.aes, bind_aad_type=bool(getattr(st, "aad_type_bound", False))
        )
        if status == "decrypt_fail":
            now_try = time.time()
            alt_keys: list[AESGCM] = []
            try:
                if st.rekey_candidate_aes is not None:
                    alt_keys.append(st.rekey_candidate_aes)
            except Exception:
                pass
            try:
                if st.prev_aes is not None and now_try <= float(getattr(st, "prev_aes_until_ts", 0.0) or 0.0):
                    alt_keys.append(st.prev_aes)
            except Exception:
                pass
            for alt in alt_keys:
                if alt is None:
                    continue
                if alt is st.aes:
                    continue
                status2, msg_type2, msg_id2, pt2, rx_cmp2 = try_unpack_message(
                    payload, alt, bind_aad_type=bool(getattr(st, "aad_type_bound", False))
                )
                if status2 == "ok" and msg_type2 is not None and msg_id2 is not None:
                    status, msg_type, msg_id, pt, rx_compression = status2, msg_type2, msg_id2, pt2, rx_cmp2
                    aes_used = alt
                    break
        if status == "decrypt_fail":
            now = time.time()
            if (st.last_decrypt_fail_ts <= 0.0) or ((now - st.last_decrypt_fail_ts) > 30.0):
                st.decrypt_fail_count = 0
            st.decrypt_fail_count += 1
            st.last_decrypt_fail_ts = now
            if bool(getattr(st, "pinned_mismatch", False)):
                ui_emit(
                    "log",
                    f"{ts_local()} KEY: decrypt failed peer={from_id} but key is pinned_mismatch; action=reset_key_required",
                )
                return
            ui_emit(
                "log",
                f"{ts_local()} KEY: decrypt failed peer={from_id} count={st.decrypt_fail_count} (possible stale key) initiator=remote event=decrypt_fail wire=MT-WIREv1 aes-256-gcm",
            )
            if peer_norm:
                st.force_key_req = True
                if st.decrypt_fail_count >= 2:
                    # Suspend old key without deleting; wait for fresh exchange
                    st.aes = None
                    st.next_key_req_ts = 0.0
                    ui_emit(
                        "log",
                        f"{ts_local()} KEY: suspend key peer={from_id} initiator=local reason=decrypt_fail",
                    )
                if now >= st.next_key_req_ts:
                    send_key_request(peer_norm, require_confirm=True, reason="decrypt_fail")
                    st.next_key_req_ts = now + max(1.0, float(args.retry_seconds))
                ui_emit("peer_update", peer_norm)
            return
        if status != "ok" or msg_type is None or msg_id is None:
            return
        try:
            st.last_seen_ts = time.time()
            st.app_offline_ts = 0.0
        except Exception:
            pass
        # If peer already started using the candidate session key, switch implicitly to avoid churn.
        try:
            if (
                st.rekey_candidate_aes is not None
                and aes_used is st.rekey_candidate_aes
                and st.aes is not aes_used
            ):
                st.prev_aes = st.aes
                st.prev_aes_until_ts = time.time() + float(REKEY_PREV_KEY_GRACE_SECONDS)
                st.aes = aes_used
                st.last_rekey_ts = time.time()
                st.rekey_sent_msgs = 0
                st.rekey_candidate_aes = None
                st.rekey_candidate_id = b""
                st.rekey_candidate_pub = b""
                st.rekey_candidate_ts = 0.0
                ui_emit("log", f"{ts_local()} KEY: rekey switched (implicit) peer={peer_norm}")
        except Exception:
            pass
        msg_hex = msg_id.hex()
        st.decrypt_fail_count = 0
        if st.await_key_confirm:
            st.await_key_confirm = False
            st.force_key_req = False
            st.next_key_req_ts = float("inf")
            st.last_key_ok_ts = time.time()
            st.key_confirmed_ts = st.last_key_ok_ts
            if from_id:
                ui_emit(
                    "log",
                    f"{ts_local()} KEYOK: confirmed_by=payload peer={from_id} initiator=remote wire=MT-WIREv1 aes-256-gcm",
                )

        def build_ack_text(hops: Optional[int]) -> bytes:
            parts = ["ACK", "mc=1", f"mc_modes={','.join(str(m) for m in supported_mc_modes_for_config(cfg))}"]
            if hops is not None:
                parts.append(f"hops={hops}")
            return "|".join(parts).encode("utf-8")

        if msg_type == TYPE_ACK:
            now = time.time()
            ack_forward_hops: Optional[int] = None
            if pt:
                try:
                    ack_text = pt.decode("utf-8", errors="ignore")
                except Exception:
                    ack_text = ""
                m_mc = re.search(r"\bmc=(\d+)\b", ack_text)
                if m_mc:
                    try:
                        if int(m_mc.group(1)) == 1:
                            st.compression_capable = True
                    except Exception:
                        pass
                m_modes = re.search(r"\bmc_modes=([0-9,]+)\b", ack_text)
                if m_modes:
                    try:
                        parsed_modes = {
                            int(item)
                            for item in m_modes.group(1).split(",")
                            if item != ""
                        }
                        parsed_modes = {m for m in parsed_modes if m in set(supported_mc_modes_for_config(cfg))}
                        if parsed_modes:
                            st.compression_modes = set(parsed_modes)
                            st.compression_capable = True
                    except Exception:
                        pass
                m = re.search(r"\bhops=(\d+)\b", ack_text)
                if m:
                    try:
                        ack_forward_hops = int(m.group(1))
                    except Exception:
                        ack_forward_hops = None
            with pending_lock:
                peer_pending = pending_by_peer.get(peer_norm or "", {})
                rec = peer_pending.pop(msg_hex, None)
                if rec is not None:
                    if not peer_pending and peer_norm:
                        pending_by_peer.pop(peer_norm, None)
                    save_state(pending_by_peer)
            if rec is not None and st:
                last_send = rec.get("last_send", 0.0) or 0.0
                attempts = rec.get("attempts", 0) or 0
                created = rec.get("created", 0.0) or 0.0
                rtt = max(0.0, now - float(last_send))
                delivery = max(0.0, now - float(created))
                st.rtt_count += 1
                st.rtt_avg = st.rtt_avg + (rtt - st.rtt_avg) / float(st.rtt_count)
                ui_emit(
                    "log",
                    f"{ts_local()} ACK: {msg_hex} rtt={rtt:.2f}s avg={st.rtt_avg:.2f}s attempts={attempts} wire=MT-WIREv1 aes-256-gcm",
                )
                try:
                    pacer.observe_ack(rtt_s=rtt, attempts=int(attempts or 1), now=now)
                except Exception:
                    pass
                if peer_norm:
                    hop_start = packet.get("hopStart")
                    hop_limit = packet.get("hopLimit")
                    hops = None
                    if isinstance(hop_start, int) and isinstance(hop_limit, int):
                        hops = max(0, hop_start - hop_limit)
                    group_id = str(rec.get("group") or msg_hex)
                    total = int(rec.get("total", 1) or 1)
                    ui_emit("ack", (peer_norm, group_id, delivery, attempts, total, ack_forward_hops, hops))
            return

        if msg_type == TYPE_MSG:
            msg_key = f"{peer_norm}:{msg_hex}"
            with seen_lock:
                last = seen_msgs.get(msg_key)
                now = time.time()
                if last and (now - last) < 3600:
                    # Duplicate, still ACK but no re-print.
                    if from_id:
                        hop_start = packet.get("hopStart")
                        hop_limit = packet.get("hopLimit")
                        hops = None
                        if isinstance(hop_start, int) and isinstance(hop_limit, int):
                            hops = max(0, hop_start - hop_limit)
                        ack_payload, _ack_cmp = pack_message(
                            TYPE_ACK,
                            msg_id,
                            aes_used,
                            build_ack_text(hops),
                            bind_aad_type=bool(getattr(st, "aad_type_bound", False)),
                        )
                        try:
                            interface.sendData(
                                ack_payload,
                                destinationId=from_id,
                                wantAck=False,
                                portNum=DEFAULT_PORTNUM,
                                channelIndex=(args.channel if args.channel is not None else 0),
                            )
                        except Exception:
                            ui_emit("radio_lost", None)
                            return
                    return
                seen_msgs[msg_key] = now

            # Rekey control messages (binary, internal).
            try:
                raw_pt = bytes(pt) if isinstance(pt, (bytes, bytearray)) else b""
            except Exception:
                raw_pt = b""
            if raw_pt.startswith(REKEY_CTRL_PREFIX1) and len(raw_pt) == (3 + 4 + 32) and peer_norm and from_id:
                rid = raw_pt[3:7]
                peer_epub_raw = raw_pt[7:39]
                # If we already computed a candidate for this rid, just re-send RK2 (idempotent).
                if st.rekey_candidate_id == rid and st.rekey_candidate_pub and st.rekey_candidate_aes is not None:
                    _send_control(peer_norm, REKEY_CTRL_PREFIX2 + rid + st.rekey_candidate_pub, aes_used, "rk2 resend")
                else:
                    try:
                        peer_epub = x25519.X25519PublicKey.from_public_bytes(peer_epub_raw)
                        rpriv = x25519.X25519PrivateKey.generate()
                        repub_raw = rpriv.public_key().public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw,
                        )
                        eph_shared = rpriv.exchange(peer_epub)
                        new_aes = _rekey_derive_aes(peer_norm, eph_shared)
                        if new_aes is not None:
                            st.rekey_candidate_id = rid
                            st.rekey_candidate_pub = repub_raw
                            st.rekey_candidate_aes = new_aes
                            st.rekey_candidate_ts = time.time()
                            _send_control(peer_norm, REKEY_CTRL_PREFIX2 + rid + repub_raw, aes_used, "rk2")
                            ui_emit("log", f"{ts_local()} KEY: rekey candidate ready peer={peer_norm} id={rid.hex()}")
                    except Exception:
                        pass
                # ACK with the key that decrypted RK1.
                try:
                    ack_payload, _ack_cmp = pack_message(
                        TYPE_ACK,
                        msg_id,
                        aes_used,
                        build_ack_text(None),
                        bind_aad_type=bool(getattr(st, "aad_type_bound", False)),
                    )
                    interface.sendData(
                        ack_payload,
                        destinationId=from_id,
                        wantAck=False,
                        portNum=DEFAULT_PORTNUM,
                        channelIndex=(args.channel if args.channel is not None else 0),
                    )
                except Exception:
                    ui_emit("radio_lost", None)
                return

            if raw_pt.startswith(REKEY_CTRL_PREFIX2) and len(raw_pt) == (3 + 4 + 32) and peer_norm and from_id:
                rid = raw_pt[3:7]
                peer_repub_raw = raw_pt[7:39]
                if bool(getattr(st, "rekey_inflight", False)) and st.rekey_id == rid and st.rekey_priv is not None:
                    try:
                        peer_repub = x25519.X25519PublicKey.from_public_bytes(peer_repub_raw)
                        eph_shared = st.rekey_priv.exchange(peer_repub)
                        new_aes = _rekey_derive_aes(peer_norm, eph_shared)
                        if new_aes is not None:
                            # Send RK3 under the new key to confirm and then switch locally.
                            _send_control(peer_norm, REKEY_CTRL_PREFIX3 + rid, new_aes, "rk3")
                            st.prev_aes = st.aes
                            st.prev_aes_until_ts = time.time() + float(REKEY_PREV_KEY_GRACE_SECONDS)
                            st.aes = new_aes
                            st.last_rekey_ts = time.time()
                            st.rekey_sent_msgs = 0
                            st.rekey_inflight = False
                            st.rekey_priv = None
                            st.rekey_id = b""
                            st.rekey_attempts = 0
                            st.rekey_next_retry_ts = 0.0
                            ui_emit("log", f"{ts_local()} KEY: rekey switched (initiator) peer={peer_norm} id={rid.hex()}")
                    except Exception:
                        pass
                # ACK RK2 with the key that decrypted it (old).
                try:
                    ack_payload, _ack_cmp = pack_message(
                        TYPE_ACK,
                        msg_id,
                        aes_used,
                        build_ack_text(None),
                        bind_aad_type=bool(getattr(st, "aad_type_bound", False)),
                    )
                    interface.sendData(
                        ack_payload,
                        destinationId=from_id,
                        wantAck=False,
                        portNum=DEFAULT_PORTNUM,
                        channelIndex=(args.channel if args.channel is not None else 0),
                    )
                except Exception:
                    ui_emit("radio_lost", None)
                return

            if raw_pt.startswith(REKEY_CTRL_PREFIX3) and len(raw_pt) == (3 + 4) and peer_norm and from_id:
                rid = raw_pt[3:7]
                # Switch to candidate key if it matches.
                if st.rekey_candidate_aes is not None and st.rekey_candidate_id == rid:
                    st.prev_aes = st.aes
                    st.prev_aes_until_ts = time.time() + float(REKEY_PREV_KEY_GRACE_SECONDS)
                    st.aes = st.rekey_candidate_aes
                    st.last_rekey_ts = time.time()
                    st.rekey_sent_msgs = 0
                    st.rekey_candidate_aes = None
                    st.rekey_candidate_id = b""
                    st.rekey_candidate_pub = b""
                    st.rekey_candidate_ts = 0.0
                    ui_emit("log", f"{ts_local()} KEY: rekey switched (responder) peer={peer_norm} id={rid.hex()}")
                # ACK RK3 with the key that decrypted it (new).
                try:
                    ack_payload, _ack_cmp = pack_message(
                        TYPE_ACK,
                        msg_id,
                        aes_used,
                        build_ack_text(None),
                        bind_aad_type=bool(getattr(st, "aad_type_bound", False)),
                    )
                    interface.sendData(
                        ack_payload,
                        destinationId=from_id,
                        wantAck=False,
                        portNum=DEFAULT_PORTNUM,
                        channelIndex=(args.channel if args.channel is not None else 0),
                    )
                except Exception:
                    ui_emit("radio_lost", None)
                return

            delivery = None
            group_id = None
            part = 1
            total = 1
            attempt_in = None
            chunk_b64 = None
            payload_cmp = "none"
            compression_flag = 0
            legacy_codec = None
            compact_wire = False
            if pt.startswith(MSG_V2_PREFIX) and len(pt) >= MSG_V2_HEADER_LEN:
                compact_wire = True
                try:
                    created_s = struct.unpack(">I", pt[2:6])[0]
                    delivery = max(0.0, now - float(created_s))
                except Exception:
                    delivery = None
                group_id = pt[6:10].hex()
                try:
                    part, total, attempt_byte, meta_byte = struct.unpack(">HHBB", pt[10:16])
                    attempt_in = int(attempt_byte)
                    meta_u8 = int(meta_byte)
                    compression_flag, legacy_codec, payload_cmp = parse_compact_meta(meta_u8, pt[16:])
                except Exception:
                    part = 1
                    total = 1
                    attempt_in = None
                    payload_cmp = "none"
                chunk_b64 = b64e(pt[16:])
                text = ""
                if compression_flag == 1:
                    st.compression_capable = True
                    label_to_mode = {
                        "mc_byte_dict": MODE_BYTE_DICT,
                        "mc_fixed_bits": MODE_FIXED_BITS,
                        "mc_deflate": MODE_DEFLATE,
                        "mc_zlib": MODE_ZLIB,
                        "mc_bz2": MODE_BZ2,
                        "mc_lzma": MODE_LZMA,
                        # Legacy / removed experimental mode ids are not supported anymore.
                    }
                    if payload_cmp in label_to_mode:
                        st.compression_modes.add(int(label_to_mode[payload_cmp]))
            else:
                try:
                    text = pt.decode("utf-8", errors="replace")
                    if text.startswith("T"):
                        parts = text.split("|", 4)
                        if len(parts) == 5:
                            try:
                                created_s = int(parts[0][1:])
                                delivery = max(0.0, now - float(created_s))
                            except Exception:
                                delivery = None
                            group_id = parts[1]
                            try:
                                p, t = parts[2].split("/", 1)
                                part = int(p)
                                total = int(t)
                            except Exception:
                                part = 1
                                total = 1
                            try:
                                attempt_in = int(parts[3])
                            except Exception:
                                attempt_in = None
                            text = parts[4]
                except Exception:
                    text = repr(pt)
            if peer_norm:
                if group_id is None:
                    group_id = msg_hex
                part_key = f"{peer_norm}:{group_id}:{int(part)}"
                with seen_lock:
                    last_part = seen_parts.get(part_key)
                    if last_part and (now - last_part) < 3600:
                        # Duplicate part via different path, ACK only.
                        if from_id:
                            hop_start = packet.get("hopStart")
                            hop_limit = packet.get("hopLimit")
                            hops = None
                            if isinstance(hop_start, int) and isinstance(hop_limit, int):
                                hops = max(0, hop_start - hop_limit)
                            ack_payload, _ack_cmp = pack_message(
                                TYPE_ACK,
                                msg_id,
                                aes_used,
                                build_ack_text(hops),
                                bind_aad_type=bool(getattr(st, "aad_type_bound", False)),
                            )
                            try:
                                interface.sendData(
                                    ack_payload,
                                    destinationId=from_id,
                                    wantAck=False,
                                    portNum=DEFAULT_PORTNUM,
                                    channelIndex=(args.channel if args.channel is not None else 0),
                                )
                            except Exception:
                                ui_emit("radio_lost", None)
                            return
                    seen_parts[part_key] = now
            recv_group = group_id if group_id is not None else msg_hex
            print(f"RECV from {from_id}: id={recv_group} part {part}/{total}")
            log_cmp = (
                effective_payload_cmp_label(
                    payload_cmp,
                    compact_wire=True,
                    compression_flag=int(compression_flag or 0),
                    legacy_codec=legacy_codec,
                    chunk_b64=(str(chunk_b64) if chunk_b64 is not None else None),
                )
                if compact_wire
                else rx_compression
            )
            ui_emit("log", f"{ts_local()} RECV: {msg_hex} cmp={log_cmp} wire=MT-WIREv1 aes-256-gcm")
            if not (total and int(total) > 1):
                # history is written on assembled message in UI layer
                pass
            last_activity_ts = time.time()
            if peer_norm:
                hop_start = packet.get("hopStart")
                hop_limit = packet.get("hopLimit")
                fwd_hops = None
                if isinstance(hop_start, int) and isinstance(hop_limit, int):
                    fwd_hops = max(0, hop_start - hop_limit)
                if group_id is None:
                    group_id = msg_hex
                ui_emit(
                    "recv",
                    (
                        peer_norm,
                        text,
                        fwd_hops,
                        delivery,
                        group_id,
                        part,
                        total,
                        attempt_in,
                        chunk_b64,
                        compression_flag,
                        legacy_codec,
                        payload_cmp,
                        compact_wire,
                    ),
                )
            if from_id:
                hop_start = packet.get("hopStart")
                hop_limit = packet.get("hopLimit")
                hops = None
                if isinstance(hop_start, int) and isinstance(hop_limit, int):
                    hops = max(0, hop_start - hop_limit)
                ack_payload, _ack_cmp = pack_message(
                    TYPE_ACK,
                    msg_id,
                    aes_used,
                    build_ack_text(hops),
                    bind_aad_type=bool(getattr(st, "aad_type_bound", False)),
                )
                try:
                    interface.sendData(
                        ack_payload,
                        destinationId=from_id,
                        wantAck=False,
                        portNum=DEFAULT_PORTNUM,
                        channelIndex=(args.channel if args.channel is not None else 0),
                    )
                except Exception:
                    ui_emit("radio_lost", None)
                    return
            return

    print(f"meshTalk.py v{VERSION}")
    if sys.platform.startswith("win"):
        print(f"Port: {args.port} (Windows: COM3 or auto)")
    else:
        print(f"Port: {args.port} (Linux: /dev/ttyUSB0 or /dev/ttyACM0 or auto)")
    print("Listening: ON")
    max_plain = max(0, int(args.max_bytes) - PAYLOAD_OVERHEAD)
    print(f"Max plaintext bytes: {max_plain} (payload limit {args.max_bytes}, overhead {PAYLOAD_OVERHEAD})")
    print(
        f"Rate limit: {args.rate_seconds}s x{max(1, int(getattr(args, 'parallel_sends', 1) or 1))}, "
        f"retry: {args.retry_seconds}s, max: {args.max_seconds}s"
    )

    if interface is not None:
        if not subscriptions_registered:
            try:
                pub.subscribe(on_receive, "meshtastic.receive.data")
                try:
                    pub.subscribe(on_receive, "meshtastic.receive")
                except Exception:
                    pass
                subscriptions_registered = True
            except Exception:
                pass

    def regenerate_keys() -> None:
        nonlocal priv, pub_self, pub_self_raw
        if not priv_path or not pub_path:
            return
        if os.path.isfile(priv_path):
            os.remove(priv_path)
        if os.path.isfile(pub_path):
            os.remove(pub_path)
        os.makedirs(os.path.dirname(priv_path) or ".", exist_ok=True)
        priv_new = x25519.X25519PrivateKey.generate()
        pub_new = priv_new.public_key()
        priv_raw = priv_new.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_raw = pub_new.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        with open(priv_path, "w", encoding="utf-8") as f:
            f.write(b64e(priv_raw))
        with open(pub_path, "w", encoding="utf-8") as f:
            f.write(b64e(pub_raw))
        harden_file(priv_path)
        harden_file(pub_path)
        priv = load_priv(priv_path)
        pub_self = load_pub(pub_path)
        pub_self_raw = pub_self.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        ui_emit("self_update", None)
        for st in peer_states.values():
            st.aes = None
            st.rtt_avg = 0.0
            st.rtt_count = 0
            st.next_key_req_ts = 0.0
        ui_emit("log", f"{ts_local()} KEY: regenerated, waiting for exchange.")
        for peer_norm in list(tracked_peers):
            send_key_request(peer_norm, require_confirm=True, reason="regen_keys")

    def send_key_request(peer_norm: str, require_confirm: bool = True, reason: str = "") -> None:
        nonlocal last_activity_ts, last_key_sent_ts
        if not radio_ready or interface is None:
            return
        if peer_norm == self_id:
            return
        st = get_peer_state(peer_norm)
        if st and bool(getattr(st, "pinned_mismatch", False)):
            # If peer rotated key and it's pinned, do not auto-spam key requests.
            # Allow explicit user actions to re-initiate.
            if str(reason or "") not in ("reset_key", "manual_request_key"):
                ui_emit(
                    "log",
                    f"{ts_local()} KEY: suppressed peer={wire_id_from_norm(peer_norm)} initiator=local reason=pinned_key_mismatch action=reset_key_required",
                )
                return
        now = time.time()
        if st and (now - st.last_key_req_ts) < 5.0:
            left_s = int(max(0.0, 5.0 - (now - st.last_key_req_ts)))
            ui_emit(
                "log",
                f"{ts_local()} KEY: suppressed (local rate-limit {left_s}s) peer={wire_id_from_norm(peer_norm)} initiator=local reason={reason or '-'}",
            )
            return
        dest_id = wire_id_from_norm(peer_norm)
        modes_bytes = ",".join(str(m) for m in supported_mc_modes_for_config(cfg)).encode("ascii")
        wire_bytes = str(int(PROTO_VERSION)).encode("ascii")
        msg_bytes = b"1,2"
        mc_bytes = b"1"
        req = (
            KEY_REQ_PREFIX
            + self_id.encode("utf-8")
            + b"|"
            + b64e(pub_self_raw).encode("ascii")
            + b"|mc_modes="
            + modes_bytes
            + b"|mt_wire="
            + wire_bytes
            + b"|mt_msg="
            + msg_bytes
            + b"|mt_mc="
            + mc_bytes
            + b"|mt_caps=aad_type"
        )
        try:
            interface.sendData(
                req,
                destinationId=dest_id,
                wantAck=False,
                portNum=DEFAULT_PORTNUM,
                channelIndex=(args.channel if args.channel is not None else 0),
            )
        except Exception:
            ui_emit("radio_lost", None)
            return
        last_activity_ts = now
        last_key_sent_ts = last_activity_ts
        if st:
            st.last_key_req_ts = last_activity_ts
            st.last_key_req_reason = str(reason or "")
            st.last_key_req_initiator = "local"
            st.next_key_refresh_ts = last_activity_ts + 3600.0 + random.uniform(0, 600)
            if require_confirm:
                st.await_key_confirm = True
                st.next_key_req_ts = last_activity_ts + max(1.0, float(args.retry_seconds))
        ui_emit(
            "log",
            f"{ts_local()} KEY: request sent to {dest_id} initiator=local reason={reason or '-'} confirm={1 if require_confirm else 0} frame=KR1 plaintext x25519+hkdf-sha256->aes-256-gcm",
        )

    def send_discovery_broadcast() -> None:
        if not radio_ready or interface is None:
            return
        modes_bytes = ",".join(str(m) for m in supported_mc_modes_for_config(cfg)).encode("ascii")
        wire_bytes = str(int(PROTO_VERSION)).encode("ascii")
        msg_bytes = b"1,2"
        mc_bytes = b"1"
        req = (
            KEY_REQ_PREFIX
            + self_id.encode("utf-8")
            + b"|"
            + b64e(pub_self_raw).encode("ascii")
            + b"|mc_modes="
            + modes_bytes
            + b"|mt_wire="
            + wire_bytes
            + b"|mt_msg="
            + msg_bytes
            + b"|mt_mc="
            + mc_bytes
            + b"|mt_caps=aad_type"
        )
        try:
            interface.sendData(
                req,
                destinationId=meshtastic.BROADCAST_ADDR,
                wantAck=False,
                portNum=DEFAULT_PORTNUM,
                channelIndex=(args.channel if args.channel is not None else 0),
            )
            ui_emit("log", f"{ts_local()} DISCOVERY: broadcast")
        except Exception:
            ui_emit("radio_lost", None)
            return

    def send_app_offline_broadcast() -> None:
        if not radio_ready or interface is None:
            return
        payload = APP_OFFLINE_PREFIX + self_id.encode("utf-8")
        try:
            interface.sendData(
                payload,
                destinationId=meshtastic.BROADCAST_ADDR,
                wantAck=False,
                portNum=DEFAULT_PORTNUM,
                channelIndex=(args.channel if args.channel is not None else 0),
            )
            ui_emit("log", f"{ts_local()} PRESENCE: app offline broadcast")
        except Exception:
            pass

    def split_bytes(data: bytes, max_bytes: int) -> list[bytes]:
        if max_bytes <= 0:
            return [data]
        if not data:
            return [b""]
        parts: list[bytes] = []
        for i in range(0, len(data), max_bytes):
            parts.append(data[i : i + max_bytes])
        return parts

    def retry_delay_seconds(base: float, attempts_next: int) -> float:
        # Exponential backoff with jitter to reduce synchronized retries.
        step = max(1, int(attempts_next) - 1)
        raw = max(1.0, float(base)) * (2.0 ** step)
        capped = min(float(RETRY_BACKOFF_MAX_SECONDS), raw)
        jitter = capped * float(RETRY_JITTER_RATIO) * random.uniform(-1.0, 1.0)
        return max(1.0, capped + jitter)

    def compression_efficiency_pct(plain_size: int, packed_size: int) -> Optional[float]:
        try:
            plain = int(plain_size)
            packed = int(packed_size)
        except Exception:
            return None
        if plain <= 0 or packed < 0:
            return None
        # Unified metric everywhere: resulting packed size as % of original.
        return (float(packed) / float(plain)) * 100.0

    def normalize_compression_name(raw_name: Optional[str]) -> Optional[str]:
        name = str(raw_name or "").strip()
        low = name.lower()
        if not name or low in ("none", "n/a", "-", "null"):
            return None
        aliases = {
            "mc": "MC",
            "mc_byte_dict": "BYTE_DICT",
            "mc_fixed_bits": "FIXED_BITS",
            "mc_deflate": "DEFLATE",
            "mc_zlib": "ZLIB",
            "mc_bz2": "BZ2",
            "mc_lzma": "LZMA",
            "mc_zstd": "ZSTD",
            "mc_unknown": "MC",
            "deflate": "DEFLATE",
            "zlib": "ZLIB",
            "bz2": "BZ2",
            "lzma": "LZMA",
        }
        return aliases.get(low, name)

    def queue_message(peer_norm: str, text: str) -> Optional[tuple[str, int, Optional[str], Optional[float], Optional[str]]]:
        nonlocal last_activity_ts
        peer_norm = norm_id_for_filename(peer_norm)
        st = get_peer_state(peer_norm)
        if not st:
            return None
        st.force_key_req = True
        created = time.time()
        created_s = int(created)
        group_id = os.urandom(4).hex()  # 4-byte id, compact on wire
        text_bytes = text.encode("utf-8")
        payload_blob = text_bytes
        use_compact_wire = False
        compression_flag = 0
        cmp_label = "none"
        cmp_norm_label = "off"
        packed_blob_len = len(text_bytes)
        cmp_eff_pct: Optional[float] = None
        peer_supports_mc = bool(st.compression_capable)
        peer_supports_msg_v2 = bool(
            (getattr(st, "peer_msg_versions", None) is None)
            or (2 in set(getattr(st, "peer_msg_versions", {1})))
        )
        local_modes = set(supported_mc_modes_for_config(cfg))
        peer_supported_modes = sorted(
            {int(m) for m in getattr(st, "compression_modes", set()) if int(m) in local_modes}
        )
        if not peer_supported_modes:
            peer_supported_modes = list(LEGACY_COMPRESSION_MODES)
        compression_policy = str(cfg.get("compression_policy", "auto") or "auto").strip().lower()
        compression_force_mode = int(cfg.get("compression_force_mode", int(MODE_DEFLATE)) or int(MODE_DEFLATE))
        plain_fits_one_packet = len(
            build_legacy_wire_payload(
                created_s=created_s,
                group_id=group_id,
                part=1,
                total=1,
                attempt=1,
                chunk_text=text,
            )
        ) <= max_plain
        chunks_bytes: list[bytes] = []
        chunks_text: list[str] = []
        if compression_policy != "off" and peer_supports_mc and peer_supports_msg_v2 and (not plain_fits_one_packet):
            best_blob: Optional[bytes] = None
            best_mode: Optional[int] = None
            best_norm_mode = "off"
            compression_normalize = str(cfg.get("compression_normalize", "auto") or "auto").strip().lower()
            if compression_policy == "force":
                if compression_force_mode in peer_supported_modes:
                    mode_order = [compression_force_mode]
                else:
                    mode_order = list(peer_supported_modes)
                    ui_emit(
                        "log",
                        f"{ts_local()} COMPRESS: force mode {compression_force_mode} not supported by {peer_norm}, using AUTO",
                    )
            else:
                mode_order = list(peer_supported_modes)
            # Full auto only when BOTH selectors are AUTO.
            if compression_policy == "auto" and compression_normalize == "auto":
                norm_order = ["off", "tokens", "sp_vocab"]
            elif compression_normalize in ("off", "tokens", "sp_vocab"):
                norm_order = [compression_normalize]
            else:
                norm_order = ["off"]
            for normalize_mode in norm_order:
                try:
                    norm_stat = normalization_stats(text, normalize=normalize_mode)
                    plain_n = int(norm_stat.get("plain_bytes", 0) or 0)
                    norm_n = int(norm_stat.get("normalized_bytes", 0) or 0)
                    norm_size_pct = (100.0 * norm_n / max(1, plain_n))
                    ui_emit(
                        "log",
                        f"{ts_local()} NORM: group={group_id} mode={norm_stat.get('mode')} "
                        f"plain={plain_n} "
                        f"normalized={norm_n} "
                        f"tokens={int(norm_stat.get('tokens', 0) or 0)} "
                        f"size={norm_size_pct:.1f}%",
                    )
                except Exception:
                    pass
                for mode_try in mode_order:
                    try:
                        candidate = compress_text(text, mode=mode_try, preserve_case=True, normalize=normalize_mode)
                    except Exception:
                        continue
                    if (best_blob is None) or (len(candidate) < len(best_blob)):
                        best_blob = candidate
                        best_mode = mode_try
                        best_norm_mode = normalize_mode
            if best_blob is not None and len(best_blob) < (len(text_bytes) - int(AUTO_MIN_GAIN_BYTES)):
                payload_blob = best_blob
                use_compact_wire = True
                compression_flag = 1
                cmp_label = mode_name(int(best_mode))
                cmp_norm_label = best_norm_mode
                packed_blob_len = len(best_blob)
                cmp_eff_pct = compression_efficiency_pct(len(text_bytes), len(best_blob))
                ui_emit(
                    "log",
                    f"{ts_local()} COMPRESS: group={group_id} mode={normalize_compression_name(cmp_label) or cmp_label} "
                    f"norm={cmp_norm_label} plain={len(text_bytes)} packed={packed_blob_len} "
                    f"size={(cmp_eff_pct if cmp_eff_pct is not None else 0.0):.1f}%",
                )
        if use_compact_wire:
            max_chunk = max(1, max_plain - MSG_V2_HEADER_LEN)
            chunks_bytes = split_bytes(payload_blob, max_chunk)
            total = len(chunks_bytes)
        else:
            # Legacy text frame for backward compatibility with old clients.
            chunks_text = build_legacy_chunks(
                text=text,
                max_plain=max_plain,
                created_s=created_s,
                group_id=group_id,
                attempts_hint=1,
            )
            total = len(chunks_text)
        with pending_lock:
            peer_pending = pending_by_peer.setdefault(peer_norm, {})
            overflow = (len(peer_pending) + int(total)) - int(MAX_PENDING_PER_PEER)
            if overflow > 0:
                oldest_ids = sorted(
                    peer_pending.keys(),
                    key=lambda mid: float(peer_pending.get(mid, {}).get("created", 0.0)),
                )[:overflow]
                for mid in oldest_ids:
                    dropped = peer_pending.pop(mid, None)
                    if isinstance(dropped, dict):
                        append_history("drop", peer_norm, str(dropped.get("id", mid)), str(dropped.get("text", "")), "queue_limit")
                        ui_emit(
                            "failed",
                            (
                                peer_norm,
                                str(dropped.get("group") or dropped.get("id") or mid),
                                "queue_limit",
                                int(dropped.get("attempts", 0)),
                                int(dropped.get("total", 1) or 1),
                            ),
                        )
                ui_emit("log", f"{ts_local()} DROP: queue limit for {peer_norm} pruned={len(oldest_ids)}")
            for idx in range(1, int(total) + 1):
                mid = os.urandom(8).hex()
                rec = {
                    "id": mid,
                    "group": group_id,
                    "part": idx,
                    "total": total,
                    "text": text,
                    "use_compact": bool(use_compact_wire),
                    "compression": compression_flag,
                    "cmp": cmp_label,
                    "cmp_norm": cmp_norm_label,
                    "cmp_eff_pct": cmp_eff_pct,
                    "created": created,
                    "attempts": 0,
                    "last_send": 0.0,
                    "next_retry_at": 0.0,
                    "peer": peer_norm,
                }
                if use_compact_wire:
                    rec["chunk_b64"] = b64e(chunks_bytes[idx - 1])
                else:
                    rec["chunk_text"] = chunks_text[idx - 1]
                peer_pending[mid] = rec
            save_state(pending_by_peer)
        append_history("queue", peer_norm, group_id, text, f"parts={total} cmp={cmp_label}")
        try:
            comp_stats["total_msgs"] = int(comp_stats.get("total_msgs", 0)) + 1
            comp_stats["plain_bytes_total"] = int(comp_stats.get("plain_bytes_total", 0)) + int(len(text_bytes))
            comp_stats["packed_bytes_total"] = int(comp_stats.get("packed_bytes_total", 0)) + int(packed_blob_len)
            if int(compression_flag) == 1:
                comp_stats["compressed_msgs"] = int(comp_stats.get("compressed_msgs", 0)) + 1
                by_mode = dict(comp_stats.get("by_mode", {}) or {})
                by_norm = dict(comp_stats.get("by_norm", {}) or {})
                mode_key = str(normalize_compression_name(cmp_label) or cmp_label or "MC")
                norm_key = str(cmp_norm_label or "off")
                by_mode[mode_key] = int(by_mode.get(mode_key, 0)) + 1
                by_norm[norm_key] = int(by_norm.get(norm_key, 0)) + 1
                comp_stats["by_mode"] = by_mode
                comp_stats["by_norm"] = by_norm
        except Exception:
            pass
        last_activity_ts = time.time()
        if st.key_ready:
            print(f"QUEUE: {group_id} parts={total} bytes={len(text_bytes)} cmp={cmp_label}")
        else:
            print(f"WAITING KEY: queued for {peer_norm} id={group_id}")
        ui_emit("queued", (peer_norm, group_id, len(text_bytes), int(total), str(cmp_label)))
        tracked_peers.add(peer_norm)
        return (group_id, total, normalize_compression_name(cmp_label), cmp_eff_pct, str(cmp_norm_label or "off").upper())

    send_window_start_ts = 0.0
    send_window_count = 0
    send_rr_offset = 0
    comp_stats = {
        "total_msgs": 0,
        "compressed_msgs": 0,
        "plain_bytes_total": 0,
        "packed_bytes_total": 0,
        "by_mode": {},
        "by_norm": {},
    }

    def send_due() -> None:
        nonlocal send_window_start_ts, send_window_count, send_rr_offset
        if not radio_ready or interface is None:
            return
        now = time.time()
        try:
            rate_s = float(getattr(args, "rate_seconds", 0) or 0)
        except Exception:
            rate_s = 0.0
        try:
            parallel = int(getattr(args, "parallel_sends", 1) or 1)
        except Exception:
            parallel = 1
        parallel = max(1, parallel)

        if rate_s > 0.0:
            if (send_window_start_ts <= 0.0) or ((now - send_window_start_ts) >= rate_s):
                send_window_start_ts = now
                send_window_count = 0
            if send_window_count >= parallel:
                return
        with pending_lock:
            peer_list = set(pending_by_peer.keys())
        peer_list |= set(tracked_peers)

        peers_sorted = sorted(peer_list)
        if not peers_sorted:
            return
        n_peers = len(peers_sorted)
        start = int(send_rr_offset) % max(1, n_peers)
        for i in range(n_peers):
            peer_norm = peers_sorted[(start + i) % n_peers]
            norm_peer = norm_id_for_filename(peer_norm)
            if norm_peer != peer_norm and peer_norm in pending_by_peer:
                with pending_lock:
                    pending_by_peer.setdefault(norm_peer, {}).update(pending_by_peer.pop(peer_norm, {}))
                    save_state(pending_by_peer)
                peer_norm = norm_peer
            st = get_peer_state(peer_norm)
            if not st:
                continue

            # Key exchange
            if not st.key_ready:
                if not st.force_key_req:
                    continue
                if peer_norm == self_id:
                    st.aes = AESGCM(derive_key(priv, pub_self))
                    continue
                if now >= st.next_key_req_ts:
                    if (now - st.last_key_req_ts) >= 5.0:
                        print(f"{ts_local()} KEY: request -> {wire_id_from_norm(peer_norm)}")
                        send_key_request(peer_norm, require_confirm=True, reason="await_confirm_retry")
                    st.next_key_req_ts = now + max(1.0, float(args.retry_seconds))
                continue

            with pending_lock:
                items = list(pending_by_peer.get(peer_norm, {}).values())

            if not items:
                continue

            # Oldest first
            items.sort(key=lambda r: float(r.get("created", 0.0)))
            for rec in items:
                created = float(rec.get("created", 0.0))
                if (now - created) > float(args.max_seconds):
                    with pending_lock:
                        pending_by_peer.get(peer_norm, {}).pop(rec["id"], None)
                        if not pending_by_peer.get(peer_norm):
                            pending_by_peer.pop(peer_norm, None)
                        save_state(pending_by_peer)
                    print(f"DROP: {rec['id']} timeout")
                    append_history("drop", peer_norm, rec["id"], str(rec.get("text", "")), "timeout")
                    try:
                        pacer.observe_drop("timeout", now=now)
                    except Exception:
                        pass
                    ui_emit("log", f"{ts_local()} DROP: {rec['id']} timeout for {peer_norm}")
                    ui_emit("failed", (peer_norm, str(rec.get("group") or rec.get("id") or rec["id"]), "timeout", int(rec.get("attempts", 0)), int(rec.get("total", 1) or 1)))
                    continue

                next_retry_at = float(rec.get("next_retry_at", 0.0) or 0.0)
                if now < next_retry_at:
                    continue

                text = str(rec.get("text", ""))
                created_s = int(float(rec.get("created", now)))
                group_id = str(rec.get("group") or rec.get("id") or "")
                part = int(rec.get("part", 1) or 1)
                total = int(rec.get("total", 1) or 1)
                attempts_next = int(rec.get("attempts", 0)) + 1
                compression_flag = 1 if int(rec.get("compression", 0) or 0) else 0
                cmp_name = str(rec.get("cmp", "none") or "none")
                use_compact_wire = bool(rec.get("use_compact", False))
                if (not use_compact_wire) and ("chunk_b64" in rec) and compression_flag == 1:
                    use_compact_wire = True
                if use_compact_wire:
                    chunk_b64 = str(rec.get("chunk_b64", "") or "")
                    try:
                        chunk = b64d(chunk_b64) if chunk_b64 else b""
                    except Exception:
                        chunk = b""
                    pt = build_compact_wire_payload(
                        prefix=MSG_V2_PREFIX,
                        created_s=int(created_s),
                        group_id=group_id,
                        part=int(part),
                        total=int(total),
                        attempt=int(attempts_next),
                        compression_flag=int(compression_flag),
                        chunk=chunk,
                    )
                else:
                    chunk_text = rec.get("chunk_text")
                    if not isinstance(chunk_text, str):
                        if "chunk_b64" in rec:
                            try:
                                chunk_text = b64d(str(rec.get("chunk_b64", "") or "")).decode("utf-8", errors="replace")
                            except Exception:
                                chunk_text = None
                    if not isinstance(chunk_text, str):
                        chunk_text = text
                    pt = build_legacy_wire_payload(
                        created_s=int(created_s),
                        group_id=group_id,
                        part=int(part),
                        total=int(total),
                        attempt=int(attempts_next),
                        chunk_text=chunk_text,
                    )
                if len(pt) > max_plain:
                    with pending_lock:
                        pending_by_peer.get(peer_norm, {}).pop(rec["id"], None)
                        if not pending_by_peer.get(peer_norm):
                            pending_by_peer.pop(peer_norm, None)
                        save_state(pending_by_peer)
                    print(f"DROP: {rec['id']} too long")
                    append_history("drop", peer_norm, rec["id"], text, "too_long")
                    ui_emit("log", f"{ts_local()} DROP: {rec['id']} too long for {peer_norm}")
                    ui_emit("failed", (peer_norm, str(rec.get("group") or rec.get("id") or rec["id"]), "too_long", int(rec.get("attempts", 0)), int(rec.get("total", 1) or 1)))
                    continue

                if not st.aes:
                    return

                payload, _wire_compression = pack_message(
                    TYPE_MSG,
                    bytes.fromhex(rec["id"]),
                    st.aes,
                    pt,
                    allow_payload_compress=False,
                    bind_aad_type=bool(getattr(st, "aad_type_bound", False)),
                )
                if len(payload) > args.max_bytes:
                    with pending_lock:
                        pending_by_peer.get(peer_norm, {}).pop(rec["id"], None)
                        if not pending_by_peer.get(peer_norm):
                            pending_by_peer.pop(peer_norm, None)
                        save_state(pending_by_peer)
                    print(f"DROP: {rec['id']} payload too big")
                    append_history("drop", peer_norm, rec["id"], text, "payload_too_big")
                    ui_emit("log", f"{ts_local()} DROP: {rec['id']} payload too big for {peer_norm}")
                    ui_emit("failed", (peer_norm, str(rec.get("group") or rec.get("id") or rec["id"]), "payload_too_big", int(rec.get("attempts", 0)), int(rec.get("total", 1) or 1)))
                    continue

                try:
                    interface.sendData(
                        payload,
                        destinationId=wire_id_from_norm(peer_norm),
                        wantAck=False,
                        portNum=DEFAULT_PORTNUM,
                        channelIndex=(args.channel if args.channel is not None else 0),
                    )
                except Exception:
                    ui_emit("radio_lost", None)
                    return
                try:
                    st.rekey_sent_msgs = int(getattr(st, "rekey_sent_msgs", 0) or 0) + 1
                except Exception:
                    pass
                rec["attempts"] = attempts_next
                rec["last_send"] = now
                rec["next_retry_at"] = now + retry_delay_seconds(float(args.retry_seconds), attempts_next)
                with pending_lock:
                    pending_by_peer.setdefault(peer_norm, {})[rec["id"]] = rec
                    save_state(pending_by_peer)
                send_window_count += 1
                send_rr_offset = (start + i + 1) % max(1, n_peers)
                if rec["attempts"] == 1:
                    append_history("send", peer_norm, rec["id"], text, f"attempt={rec['attempts']} cmp={cmp_name}")
                ui_emit(
                    "log",
                    f"{ts_local()} SEND: {rec['id']} attempt={rec['attempts']} cmp={cmp_name} -> {peer_norm} wire=MT-WIREv1 aes-256-gcm",
                )
                return

    # If we just generated our keys or peer key is missing, request exchange immediately.
        if peer_id_norm:
            st = get_peer_state(peer_id_norm)
            if generated_now or (st is not None and not st.key_ready):
                print(f"{ts_local()} KEY: startup request to {wire_id_from_norm(peer_id_norm)}")
                send_key_request(peer_id_norm, require_confirm=True, reason="startup")
                if st:
                    st.next_key_req_ts = time.time() + max(1.0, float(args.retry_seconds))

    discovery_state = {"start_ts": time.time(), "next_ts": time.time() + random.uniform(20, 60)}

    def reset_discovery_schedule(now: Optional[float] = None) -> None:
        t = time.time() if now is None else now
        discovery_state["start_ts"] = t
        discovery_state["next_ts"] = t + random.uniform(20, 60)

    def sender_loop() -> None:
        last_key_refresh_ts = 0.0
        last_health_ts = 0.0
        last_names_refresh_ts = 0.0
        last_rekey_tick_ts = 0.0
        last_compstats_ts = 0.0
        while True:
            send_due()
            now = time.time()
            if radio_ready and interface is not None and (now - last_names_refresh_ts) >= 60.0:
                last_names_refresh_ts = now
                update_peer_names_from_nodes()
                # Refresh contact list titles if names have changed.
                ui_emit("names_update", None)
            if (now - last_key_refresh_ts) >= 5.0:
                last_key_refresh_ts = now
                peers, _ = snapshot_runtime_state(peer_states, known_peers, tracked_peers)
                for peer_norm in peers:
                    if not peer_norm or peer_norm == self_id:
                        continue
                    st = get_peer_state(peer_norm)
                    if not st:
                        continue
                    if st.key_ready and st.await_key_confirm and now >= st.next_key_req_ts:
                        send_key_request(peer_norm, require_confirm=True, reason="await_confirm_retry")
                        continue
                    if st.next_key_refresh_ts <= 0.0:
                        st.next_key_refresh_ts = now + 3600.0 + random.uniform(0, 600)
                    if now >= st.next_key_refresh_ts:
                        send_key_request(peer_norm, require_confirm=False, reason="refresh_timer")
                # Session rekey: low-noise, only for active peers with confirmed keys.
                if bool(session_rekey_enabled) and (now - last_rekey_tick_ts) >= 5.0:
                    last_rekey_tick_ts = now
                    for peer_norm in peers:
                        if not peer_norm or peer_norm == self_id or peer_norm.startswith("group:"):
                            continue
                        st = get_peer_state(peer_norm)
                        if not st or not st.key_ready:
                            continue
                        # Expire candidate if it was never confirmed and no peer traffic used it.
                        if (
                            st.rekey_candidate_aes is not None
                            and st.rekey_candidate_ts > 0.0
                            and (now - st.rekey_candidate_ts) > 600.0
                        ):
                            st.rekey_candidate_aes = None
                            st.rekey_candidate_id = b""
                            st.rekey_candidate_pub = b""
                            st.rekey_candidate_ts = 0.0
                        if bool(getattr(st, "rekey_inflight", False)):
                            # Retry RK1 if no RK2 arrived yet.
                            if st.rekey_attempts >= int(REKEY_MAX_ATTEMPTS) or (now - float(st.rekey_started_ts or 0.0)) > 600.0:
                                st.rekey_inflight = False
                                st.rekey_id = b""
                                st.rekey_priv = None
                                st.rekey_attempts = 0
                                st.rekey_next_retry_ts = 0.0
                                ui_emit("log", f"{ts_local()} KEY: rekey aborted peer={peer_norm}")
                                continue
                            if now >= float(st.rekey_next_retry_ts or 0.0):
                                _rekey_send_rk1(peer_norm, st, now)
                            continue
                        if not _rekey_should_start(st, now):
                            continue
                        # Only when there is active outbound traffic for this peer.
                        with pending_lock:
                            has_pending = bool(pending_by_peer.get(peer_norm))
                        if not has_pending:
                            continue
                        _rekey_send_rk1(peer_norm, st, now)
                if discovery_send and radio_ready:
                    start_ts = discovery_state["start_ts"]
                    next_discovery_ts = discovery_state["next_ts"]
                    if now - start_ts <= 300.0:
                        if now >= next_discovery_ts:
                            ui_emit("log", f"{ts_local()} DISCOVERY: burst")
                            send_discovery_broadcast()
                            discovery_state["next_ts"] = now + random.uniform(45, 75)
                    else:
                        idle = (now - last_activity_ts) > 300.0
                        if idle and now >= next_discovery_ts:
                            ui_emit("log", f"{ts_local()} DISCOVERY: normal")
                            send_discovery_broadcast()
                            discovery_state["next_ts"] = now + random.uniform(1800, 3600)
                        elif not idle and now >= next_discovery_ts:
                            ui_emit("log", f"{ts_local()} DISCOVERY: silent (activity)")
                            discovery_state["next_ts"] = now + random.uniform(1800, 3600)
                try:
                    pacing_enabled = bool(getattr(args, "auto_pacing", False))
                    pacer.set_enabled(pacing_enabled)
                    pacer.set_current(
                        rate_seconds=int(getattr(args, "rate_seconds", 30) or 30),
                        parallel_sends=int(getattr(args, "parallel_sends", 1) or 1),
                    )
                    if pacing_enabled and radio_ready:
                        with pending_lock:
                            pending_count = sum(len(v) for v in pending_by_peer.values())
                        suggested = pacer.suggest(pending_count=pending_count, now=now)
                        if suggested is not None:
                            new_rate, new_parallel, reason = suggested
                            args.rate_seconds = int(new_rate)
                            args.parallel_sends = int(new_parallel)
                            ui_emit("pacing_update", (int(new_rate), int(new_parallel)))
                            ui_emit(
                                "log",
                                f"{ts_local()} PACE: rate={int(new_rate)}s parallel={int(new_parallel)} ({reason})",
                            )
                except Exception:
                    pass
            if radio_ready and (now - last_health_ts) >= 300.0:
                last_health_ts = now
                with pending_lock:
                    pending_count = sum(len(v) for v in pending_by_peer.values())
                peers_snapshot, avg_rtt = snapshot_runtime_state(peer_states, known_peers, tracked_peers)
                ui_emit(
                    "log",
                    f"{ts_local()} HEALTH: peers={len(peers_snapshot)} tracked={len(tracked_peers)} pending={pending_count} avg_rtt={avg_rtt:.2f}s",
                )
            if (now - last_compstats_ts) >= 300.0:
                last_compstats_ts = now
                try:
                    total_msgs = int(comp_stats.get("total_msgs", 0) or 0)
                    comp_msgs = int(comp_stats.get("compressed_msgs", 0) or 0)
                    plain_total = int(comp_stats.get("plain_bytes_total", 0) or 0)
                    packed_total = int(comp_stats.get("packed_bytes_total", 0) or 0)
                    size_pct = compression_efficiency_pct(plain_total, packed_total)
                    by_mode = dict(comp_stats.get("by_mode", {}) or {})
                    by_norm = dict(comp_stats.get("by_norm", {}) or {})
                    top_mode = "-"
                    top_norm = "-"
                    if by_mode:
                        top_mode = max(by_mode.items(), key=lambda kv: kv[1])[0]
                    if by_norm:
                        top_norm = max(by_norm.items(), key=lambda kv: kv[1])[0]
                    ui_emit(
                        "log",
                        f"{ts_local()} COMPSTAT: total={total_msgs} compressed={comp_msgs} "
                        f"ratio={(100.0 * comp_msgs / max(1, total_msgs)):.1f}% "
                        f"plain={plain_total} packed={packed_total} "
                        f"size={(size_pct if size_pct is not None else 0.0):.1f}% "
                        f"top_mode={top_mode} top_norm={top_norm}",
                    )
                except Exception:
                    pass
            if (now % 60.0) < 0.25:
                cutoff = now - 3600.0
                with seen_lock:
                    for k in list(seen_msgs.keys()):
                        if seen_msgs.get(k, 0.0) < cutoff:
                            seen_msgs.pop(k, None)
                    for k in list(seen_parts.keys()):
                        if seen_parts.get(k, 0.0) < cutoff:
                            seen_parts.pop(k, None)
            time.sleep(0.2)

    threading.Thread(target=sender_loop, daemon=True).start()

    def run_cli(target_norm: str) -> int:
        tracked_peers.add(target_norm)
        st = get_peer_state(target_norm)
        if st:
            st.force_key_req = True
        key_status = "READY" if st and st.key_ready else "WAITING KEY"
        print(f"Key state: {key_status}")
        if st and st.key_ready:
            print("Type message and press Enter. /keys to rotate keys.")
        else:
            print("Waiting for key exchange. You can type; messages will be queued. /keys to rotate keys.")
        if pending_by_peer.get(target_norm):
            print(f"PENDING: {len(pending_by_peer.get(target_norm, {}))} message(s) in queue")

        try:
            while True:
                line = sys.stdin.readline()
                if not line:
                    return 0
                line = line.rstrip("\n")
                if not line:
                    continue
                if line.strip() == "/keys":
                    regenerate_keys()
                    continue
                queue_message(target_norm, line)
        except KeyboardInterrupt:
            return 0

    def run_gui_qt() -> int:
        try:
            from PySide6 import QtCore, QtGui, QtWidgets
        except Exception:
            return -1

        nonlocal security_policy, session_rekey_enabled
        if sys.platform.startswith("win"):
            # Some Windows + Qt + GPU driver combinations crash on startup in native GL paths.
            # Force software backend for startup stability.
            os.environ.setdefault("QT_OPENGL", "software")
            os.environ.setdefault("QT_QUICK_BACKEND", "software")
            os.environ.setdefault("QSG_RHI_BACKEND", "software")
            try:
                QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_UseSoftwareOpenGL, True)
            except Exception:
                pass
        app = QtWidgets.QApplication(sys.argv)
        win = QtWidgets.QWidget()
        win.setWindowTitle(f"meshTalk v{VERSION}")
        win.resize(1100, 700)
        print("GUI: Qt")

        def set_mono(widget, size=11, bold=False):
            font = QtGui.QFont("Ubuntu Mono", size)
            font.setBold(bold)
            widget.setFont(font)

        translations = {
            "en": {
                "dialogs": "Dialogs",
                "contacts": "Contact list",
                "search": "Search ID",
                "group_name": "Group name",
                "create_group_ctx": "Create group from selection",
                "status": "Status",
                "dialog": "Dialog",
                "message": "Message...",
                "log": "Log",
                "settings": "⚙",
                "settings_title": "Settings",
                "tab_general": "General",
                "tab_contacts": "Contacts",
                "tab_security": "Security",
                "tab_compression": "Compression",
                "tab_theme": "Themes",
                "tab_log": "Log",
                "tab_about": "About",
                "language": "Language",
                "lang_ru": "Russian",
                "lang_en": "English",
                "send": "Send",
                "select_dialog": "Select dialog or contact.",
                "group_empty": "Group name is empty.",
                "group_send_none": "No group members are available for sending.",
                "select_peers": "Select peers from Contacts first.",
                "log": "Log",
                "verbose_events": "Verbose events",
                "runtime_log_file": "Write runtime.log",
                "pin": "Pin",
                "unpin": "Unpin",
                "group_rename": "Rename group",
                "group_delete": "Delete group",
                "group_delete_confirm": "Delete group '{name}'?",
                "group_exists": "Group already exists.",
                "group_rename_failed": "Group not found.",
                "pinned": "Pinned",
                "recent": "Contact list",
                "last_seen": "Last seen",
                "key_age": "Key",
                "status_device_online": "device online",
                "status_app_online": "meshTalk online",
                "peer_delete": "Delete contact",
                "peer_delete_confirm": "Delete contact '{name}'?",
                "clear_history": "Clear history",
                "clear_history_confirm": "Clear chat history with '{name}'?",
                "group_add": "Add selected to group",
                "actions": "Actions",
                "key_request": "Send and request public key",
                "key_reset": "Reset key",
                "key_conflict_title": "Key conflict detected",
                "key_conflict_text": "Pinned key mismatch for {peer}. Stored: {old_fp}, received: {new_fp}.",
                "key_conflict_replace": "accept",
                "key_conflict_paranoid": "ignore",
                "key_conflict_header_notice": "ID: {peer}{peer_name} sent a new public key",
                "key_conflict_header_replace_tip": "Accept new key",
                "key_conflict_header_ignore_tip": "Keep current pinned key",
                "settings_runtime": "Runtime settings",
                "port": "Port",
                "channel": "Channel",
                "retry": "Retry seconds",
                "max_seconds": "Max seconds",
                "max_bytes": "Max bytes",
                "rate": "Rate seconds",
                "parallel_sends": "Parallel packets",
                "auto_pacing": "Auto pacing",
                "hint_port": "Serial port path or 'auto' to scan USB ports.",
                "hint_retry": "Base retry interval used for resend/backoff.",
                "hint_max_seconds": "Drop a pending packet after this many seconds without ACK.",
                "hint_max_bytes": "Max Meshtastic payload bytes per packet (includes encryption overhead).",
                "hint_rate": "Minimum delay between send windows (used when Auto pacing is off).",
                "hint_parallel": "How many packets can be sent per send window.",
                "hint_auto_pacing": "Auto tunes rate/parallel based on recent ACK stats.",
                "discovery": "Discovery",
                "discovery_send": "Send broadcast discovery",
                "discovery_reply": "Reply to broadcast discovery",
                "clear_pending_on_switch": "Clear pending when profile switches",
                "hint_verbose": "Show more internal events in the GUI log.",
                "hint_runtime_log_file": "Write runtime events to runtime.log on disk.",
                "hint_discovery_send": "Sends discovery broadcasts (extra traffic).",
                "hint_discovery_reply": "Replies to discovery broadcasts (extra traffic).",
                "hint_clear_pending": "Clears pending queue when switching profile/dialog.",
                "contacts_visibility": "Contacts visibility",
                "contacts_visibility_all": "Show all devices",
                "contacts_visibility_online": "Show online",
                "contacts_visibility_app": "Show meshTalk contacts",
                "contacts_visibility_device": "Show Meshtastic-only",
                "hint_contacts_visibility_all": "Show all known contacts, regardless of online status.",
                "hint_contacts_visibility_online": "Show only contacts currently online.",
                "hint_contacts_visibility_app": "Show contacts seen by meshTalk app traffic (online or recently offline).",
                "hint_contacts_visibility_device": "Show contacts seen only by Meshtastic device traffic.",
                "contacts_status_legend_title": "Status legend",
                "hint_status_green": "Green: app active within last 30 minutes and keys are valid.",
                "hint_status_blue": "Dark green: meshTalk contact is temporarily offline (seen within last 24 hours).",
                "hint_status_yellow": "Yellow: Meshtastic-only contact is currently online.",
                "hint_status_orange": "Dark yellow: Meshtastic-only contact is offline (seen within last 24 hours).",
                "hint_status_none": "No status: empty.",
                "security": "Security",
                "security_policy": "Key rotation policy",
                "security_policy_auto": "AUTO (recommended)",
                "security_policy_strict": "STRICT",
                "security_policy_always": "ALWAYS ACCEPT",
                "security_policy_hint": "Controls what happens when a peer key changes (TOFU).",
                "security_crypto_summary": "Transport: MT-WIREv1 (AES-256-GCM AEAD). Key exchange: KR1/KR2 with X25519 public key. Key derivation: HKDF-SHA256. Local profile storage: AES-256-GCM.",
                "session_rekey": "Session rekey (ephemeral)",
                "session_rekey_hint": "When enabled, periodically refreshes the session key using ephemeral X25519 inside the encrypted channel. This reduces impact of long-term key compromise, but increases control traffic slightly.",
                "compression_title": "Compression",
                "compression_policy": "Compression policy",
                "compression_policy_auto": "AUTO (recommended)",
                "compression_policy_off": "OFF (disable compression)",
                "compression_policy_force": "Force algorithm",
                "compression_force_algo": "Algorithm",
                "compression_normalize": "Normalization (preprocess)",
                "compression_normalize_auto": "AUTO (recommended)",
                "compression_normalize_off": "OFF",
                "compression_normalize_tokens": "Token stream (basic, reversible)",
                "compression_normalize_sp_vocab": "SentencePiece vocab (reversible)",
                "compression_normalize_hint": "Normalization runs before compression and is lossless: the receiver reconstructs the exact original text.",
                # kept for backward config parsing (no longer shown in UI)
                "compression_allow_zstd": "Zstandard (ZSTD)",
                "compression_allow_zstd_hint": "Zstandard is a required dependency (requirements.txt).",
                "compression_force_hint": "Force is applied only when peer supports MC+MSGv2; otherwise AUTO/plain is used.",
                "theme_title": "Color theme",
                "theme_select": "Theme",
                "theme_ubuntu_style": "ubuntu style",
                "theme_brutal_man": "brutal man",
                "theme_hint": "Applies immediately to the main window and settings dialog.",
                "security_auto_stale_hours": "Auto accept if key age, h",
                "security_auto_seen_minutes": "Auto accept if seen within, min",
                "security_auto_mode": "Auto rule",
                "security_auto_mode_or": "OR (either is enough)",
                "security_auto_mode_and": "AND (both required)",
                "security_auto_hint": "AUTO accepts a changed peer key only if the previously pinned key was never confirmed. If a key was confirmed before, manual reset is required. STRICT always requires manual reset. ALWAYS ACCEPT is most convenient but weakest against key substitution.",
                "full_reset": "Full reset",
                "full_reset_confirm": "Delete all profile settings, history, pending state and keys for '{name}'?\n\nThis action cannot be undone.",
                "full_reset_done": "Profile data and keys were reset.",
                "full_reset_unavailable": "Full reset is available after node/profile initialization.",
                "copy_log": "Copy log",
                "clear_log": "Clear log",
                "ack_alerts": "Acknowledge alerts",
                "alerts_show": "Show alert",
                "msg_ctx_copy": "Copy",
                "msg_ctx_route": "Traceroute request",
                "meta_std_text": "Meshtastic text",
                "msg_route_title": "Message route",
                "msg_route_na": "Route information is not available yet for this message.",
                "msg_route_hops": "Hops",
                "msg_route_hops_tb": "Hops (there/back)",
                "msg_route_attempts": "Attempts (avg)",
                "msg_route_packets": "Packets",
                "trace_request": "Trace request",
                "trace_timeout": "Timed out waiting for traceroute",
                "trace_towards": "Route traced towards destination:",
                "trace_back": "Route traced back to us:",
                "about_author": "Author",
                "about_callsign": "Callsign",
                "about_telegram": "Telegram",
                "about_vision": "Vision: Civilian/Hobby/Research mesh messaging study only",
                "about_author_position": "Author position: Military and any unlawful use are explicitly prohibited",
                "about_disclaimer": "Disclaimer: provided AS IS, without warranties; author is not liable for damages",
            },
            "ru": {
                "dialogs": "Диалоги",
                "contacts": "Список контактов",
                "search": "Search ID",
                "group_name": "Имя группы",
                "create_group_ctx": "Создать группу из выделенных",
                "status": "Статус",
                "dialog": "Диалог",
                "message": "Сообщение...",
                "log": "Лог",
                "settings": "⚙",
                "settings_title": "Настройки",
                "tab_general": "Общие",
                "tab_contacts": "Контакты",
                "tab_security": "Безопасность",
                "tab_compression": "Сжатие",
                "tab_theme": "Темы",
                "tab_log": "Лог",
                "tab_about": "О программе",
                "language": "Язык",
                "lang_ru": "Русский",
                "lang_en": "Английский",
                "send": "Отправить",
                "select_dialog": "Выберите диалог или контакт.",
                "group_empty": "Имя группы пустое.",
                "group_send_none": "Нет доступных участников группы для отправки.",
                "select_peers": "Сначала выберите контакты.",
                "log": "Лог",
                "verbose_events": "Подробные события",
                "runtime_log_file": "Писать runtime.log",
                "pin": "Закрепить",
                "unpin": "Открепить",
                "group_rename": "Переименовать группу",
                "group_delete": "Удалить группу",
                "group_delete_confirm": "Удалить группу '{name}'?",
                "group_exists": "Группа уже существует.",
                "group_rename_failed": "Группа не найдена.",
                "pinned": "Закреплённые",
                "recent": "Список контактов",
                "last_seen": "В сети",
                "key_age": "Ключ",
                "status_device_online": "device online",
                "status_app_online": "meshTalk online",
                "peer_delete": "Удалить собеседника",
                "peer_delete_confirm": "Удалить собеседника '{name}'?",
                "clear_history": "Очистить историю",
                "clear_history_confirm": "Очистить историю чата с '{name}'?",
                "group_add": "Добавить выделенных в группу",
                "actions": "Действия",
                "key_request": "Отправить и запросить public key",
                "key_reset": "Сбросить ключ",
                "key_conflict_title": "Обнаружен конфликт ключа",
                "key_conflict_text": "Конфликт закрепленного ключа для {peer}. В базе: {old_fp}, получен: {new_fp}.",
                "key_conflict_replace": "принять",
                "key_conflict_paranoid": "отклонить",
                "key_conflict_header_notice": "ID: {peer}{peer_name} прислал новый public key",
                "key_conflict_header_replace_tip": "Заменить ключ в базе",
                "key_conflict_header_ignore_tip": "Оставить текущий закрепленный ключ",
                "settings_runtime": "Параметры запуска",
                "port": "Порт",
                "channel": "Канал",
                "retry": "Повтор, сек",
                "max_seconds": "Макс ожидание, сек",
                "max_bytes": "Макс байт",
                "rate": "Мин интервал, сек",
                "parallel_sends": "Параллельно, пакетов",
                "auto_pacing": "Автоподбор скорости",
                "hint_port": "Серийный порт или 'auto' для поиска по USB.",
                "hint_retry": "Базовый интервал повторов (resend/backoff).",
                "hint_max_seconds": "Сбросить пакет из очереди после этого времени без ACK.",
                "hint_max_bytes": "Макс. размер payload Meshtastic на пакет (включая оверхед шифрования).",
                "hint_rate": "Минимальная пауза между окнами отправки (когда автоподбор выключен).",
                "hint_parallel": "Сколько пакетов можно отправить подряд в одном окне.",
                "hint_auto_pacing": "Автоподбор rate/параллельности по статистике ACK.",
                "discovery": "Обнаружение",
                "discovery_send": "Отправлять broadcast discovery",
                "discovery_reply": "Отвечать на broadcast discovery",
                "clear_pending_on_switch": "Очищать очередь при смене профиля",
                "hint_verbose": "Показывать больше внутренних событий в GUI-логе.",
                "hint_runtime_log_file": "Писать runtime события в runtime.log на диск.",
                "hint_discovery_send": "Отправляет discovery broadcasts (доп. трафик).",
                "hint_discovery_reply": "Отвечает на discovery broadcasts (доп. трафик).",
                "hint_clear_pending": "Очищает очередь при переключении профиля/диалога.",
                "contacts_visibility": "Отображение контактов",
                "contacts_visibility_all": "Показывать все устройства",
                "contacts_visibility_online": "Показывать онлайн",
                "contacts_visibility_app": "Показывать meshTalk контакты",
                "contacts_visibility_device": "Показывать только Meshtastic",
                "hint_contacts_visibility_all": "Показывает все известные контакты, даже если сейчас нет онлайн-сигнала.",
                "hint_contacts_visibility_online": "Показывает только контакты, которые сейчас онлайн.",
                "hint_contacts_visibility_app": "Показывает контакты, замеченные по трафику meshTalk (онлайн или недавно оффлайн).",
                "hint_contacts_visibility_device": "Показывает контакты, замеченные только по трафику Meshtastic устройства.",
                "contacts_status_legend_title": "Подсказки по статусам",
                "hint_status_green": "Зеленый: приложение активно за последние 30 минут и ключи валидны.",
                "hint_status_blue": "Темно-зеленый: meshTalk контакт временно оффлайн (был замечен за последние 24 часа).",
                "hint_status_yellow": "Желтый: контакт без meshTalk, но устройство сейчас онлайн.",
                "hint_status_orange": "Темно-желтый: контакт без meshTalk, устройство оффлайн (было замечено за последние 24 часа).",
                "hint_status_none": "Без статуса: пустой.",
                "security": "Безопасность",
                "security_policy": "Политика смены ключа",
                "security_policy_auto": "AUTO (рекомендуется)",
                "security_policy_strict": "STRICT",
                "security_policy_always": "ALWAYS ACCEPT",
                "security_policy_hint": "Определяет поведение при смене публичного ключа пира (TOFU).",
                "security_crypto_summary": "Транспорт: MT-WIREv1 (AES-256-GCM AEAD). Обмен ключами: KR1/KR2 с X25519 public key. Вывод ключа: HKDF-SHA256. Локальное хранение профиля: AES-256-GCM.",
                "session_rekey": "Rekey сессии (ephemeral)",
                "session_rekey_hint": "Если включено, периодически обновляет ключ сессии через ephemeral X25519 внутри зашифрованного канала. Это снижает эффект компрометации долгоживущего ключа, но чуть увеличивает служебный трафик.",
                "compression_title": "Сжатие",
                "compression_policy": "Политика сжатия",
                "compression_policy_auto": "AUTO (рекомендуется)",
                "compression_policy_off": "OFF (не сжимать)",
                "compression_policy_force": "Принудительный алгоритм",
                "compression_force_algo": "Алгоритм",
                "compression_normalize": "Нормализация (подготовка)",
                "compression_normalize_auto": "AUTO (рекомендуется)",
                "compression_normalize_off": "OFF",
                "compression_normalize_tokens": "Token stream (базовый, обратимый)",
                "compression_normalize_sp_vocab": "SentencePiece vocab (обратимый)",
                "compression_normalize_hint": "Нормализация выполняется перед сжатием и обратима: получатель восстановит точный исходный текст.",
                # kept for backward config parsing (no longer shown in UI)
                "compression_allow_zstd": "Zstandard (ZSTD)",
                "compression_allow_zstd_hint": "Zstandard теперь обязательная зависимость (requirements.txt).",
                "compression_force_hint": "Принудительный режим применяется только при поддержке peer MC+MSGv2; иначе используется AUTO/plain.",
                "theme_title": "Цветовая тема",
                "theme_select": "Тема",
                "theme_ubuntu_style": "ubuntu style",
                "theme_brutal_man": "brutal man",
                "theme_hint": "Применяется сразу к главному окну и окну настроек.",
                "security_auto_stale_hours": "Автопринять если ключ старше, ч",
                "security_auto_seen_minutes": "Автопринять если был в сети, мин",
                "security_auto_mode": "Правило AUTO",
                "security_auto_mode_or": "ИЛИ (достаточно одного)",
                "security_auto_mode_and": "И (нужно оба условия)",
                "security_auto_hint": "AUTO принимает смену ключа только если старый закрепленный ключ никогда не был подтвержден. Если ключ уже подтверждался, нужен ручной сброс. STRICT всегда требует ручной сброс. ALWAYS ACCEPT удобнее всего, но слабее к подмене ключа.",
                "full_reset": "Полный сброс",
                "full_reset_confirm": "Удалить все настройки профиля, историю, очередь и ключи для '{name}'?\n\nДействие необратимо.",
                "full_reset_done": "Данные профиля и ключи сброшены.",
                "full_reset_unavailable": "Полный сброс доступен после инициализации ноды/профиля.",
                "copy_log": "Копировать лог",
                "clear_log": "Очистить лог",
                "ack_alerts": "Подтвердить тревоги",
                "alerts_show": "Показать тревогу",
                "msg_ctx_copy": "Копировать",
                "msg_ctx_route": "Запрос traceroute",
                "meta_std_text": "Meshtastic text",
                "msg_route_title": "Маршрут сообщения",
                "msg_route_na": "Информация о маршруте для этого сообщения пока недоступна.",
                "msg_route_hops": "Хопов",
                "msg_route_hops_tb": "Хопы туда/обратно",
                "msg_route_attempts": "Попытки (ср.)",
                "msg_route_packets": "Пакеты",
                "trace_request": "Запрос маршрута",
                "trace_timeout": "Таймаут ожидания трассировки",
                "trace_towards": "Маршрут до получателя:",
                "trace_back": "Маршрут обратно:",
                "about_author": "Автор",
                "about_callsign": "Позывной",
                "about_telegram": "Telegram",
                "about_vision": "Видение: только гражданское/любительское/исследовательское изучение mesh-месседжинга",
                "about_author_position": "Позиция автора: военное и любое незаконное использование прямо запрещено",
                "about_disclaimer": "Отказ от ответственности: ПО «как есть», без гарантий; автор не отвечает за ущерб",
            },
        }
        # Load persisted config before rendering the UI so Settings reflect saved values.
        try:
            cfg_new = load_config()
            if isinstance(cfg_new, dict):
                cfg.clear()
                cfg.update(cfg_new)
        except Exception:
            pass
        log_startup = []
        for line in startup_events:
            log_startup.append(line)
        current_lang = str(cfg.get("lang", "ru")).lower()
        verbose_log = bool(cfg.get("log_verbose", True))
        runtime_log_file = bool(cfg.get("runtime_log_file", True))
        auto_pacing = bool(cfg.get("auto_pacing", True))
        session_rekey_enabled = bool(cfg.get("session_rekey", session_rekey_enabled))
        security_policy = str(cfg.get("security_key_rotation_policy", security_policy) or "auto").strip().lower()
        if security_policy not in ("auto", "strict", "always"):
            security_policy = "auto"
        contacts_visibility = str(cfg.get("contacts_visibility", "all") or "all").strip().lower()
        if contacts_visibility not in ("all", "online", "app", "device"):
            contacts_visibility = "all"
        last_pacing_save_ts = 0.0
        pinned_dialogs = set(cfg.get("pinned_dialogs", []))
        hidden_contacts = set(cfg.get("hidden_contacts", []))
        groups_cfg = cfg.get("groups", {}) if isinstance(cfg.get("groups", {}), dict) else {}
        clear_pending_on_switch = bool(cfg.get("clear_pending_on_switch", True))
        last_limits_logged: Optional[Tuple[int, int, int, int]] = None
        _STORAGE.set_runtime_log_enabled(runtime_log_file)
        if current_lang not in ("ru", "en"):
            current_lang = "ru"

        def tr(key: str) -> str:
            return translations.get(current_lang, translations["en"]).get(key, key)

        # Layouts
        root_layout = QtWidgets.QHBoxLayout(win)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        left_col = QtWidgets.QVBoxLayout()
        left_col.setContentsMargins(0, 0, 0, 0)
        left_col.setSpacing(0)
        right_col = QtWidgets.QVBoxLayout()
        right_col.setContentsMargins(0, 0, 0, 0)
        right_col.setSpacing(0)
        root_layout.addLayout(left_col, 1)
        root_layout.addLayout(right_col, 2)

        list_group = QtWidgets.QGroupBox("")
        list_group.setObjectName("listGroup")
        list_layout = QtWidgets.QVBoxLayout(list_group)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.setSpacing(0)
        search_field = QtWidgets.QLineEdit()
        set_mono(search_field)
        search_field.setPlaceholderText(tr("search"))
        search_field.setFixedHeight(32)
        search_click_state = {"last_ts": 0.0, "count": 0}
        items_list = QtWidgets.QListWidget()
        items_list.setObjectName("contactsList")
        set_mono(items_list)
        items_list.setIconSize(QtCore.QSize(44, 44))
        items_list.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        items_list.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        items_list.setSpacing(0)
        items_list.setUniformItemSizes(False)
        items_list.setContentsMargins(0, 0, 0, 0)
        items_list.viewport().setContentsMargins(0, 0, 0, 0)
        items_list.setFrameShape(QtWidgets.QFrame.NoFrame)
        search_row = QtWidgets.QHBoxLayout()
        search_row.setContentsMargins(0, 0, 0, 0)
        search_row.setSpacing(0)
        search_row.addWidget(search_field, 1)
        list_layout.addLayout(search_row)
        list_layout.addWidget(items_list, 4)
        left_col.addWidget(list_group, 1)

        settings_row = QtWidgets.QHBoxLayout()
        settings_row.setContentsMargins(0, 0, 0, 0)
        settings_row.setSpacing(0)
        header_bar = QtWidgets.QWidget()
        header_bar.setObjectName("headerBar")
        header_bar.setAutoFillBackground(True)
        header_bar.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        header_layout = QtWidgets.QHBoxLayout(header_bar)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(0)
        chat_label = QtWidgets.QLabel("")
        chat_label.setObjectName("section")
        set_mono(chat_label, 13)
        chat_label.setFixedHeight(32)
        chat_label.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        chat_label.setContentsMargins(8, 0, 0, 0)
        chat_label.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        chat_label.setTextInteractionFlags(QtCore.Qt.NoTextInteraction)
        chat_label.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        settings_spacer = QtWidgets.QSpacerItem(10, 10, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        key_renew_btn = QtWidgets.QPushButton("Renew")
        key_renew_btn.setFixedSize(108, 32)
        key_renew_btn.setStyleSheet("QPushButton { background:#2f5f3a; color:#ecfff0; font-weight:600; border:1px solid #4f8a60; } QPushButton:hover { background:#3c7449; }")
        key_renew_btn.hide()
        key_ignore_btn = QtWidgets.QPushButton("Ignore")
        key_ignore_btn.setFixedSize(108, 32)
        key_ignore_btn.setStyleSheet("QPushButton { background:#5f3a2f; color:#fff2ec; font-weight:600; border:1px solid #8a5f4f; } QPushButton:hover { background:#74493c; }")
        key_ignore_btn.hide()
        alert_btn = QtWidgets.QPushButton("!")
        alert_btn.setFixedSize(32, 32)
        alert_btn.setToolTip(tr("alerts_show"))
        alert_btn.hide()
        settings_btn = QtWidgets.QPushButton(tr("settings"))
        settings_btn.setFixedHeight(32)
        header_layout.addWidget(chat_label, 1)
        header_layout.addItem(settings_spacer)
        header_layout.addWidget(key_renew_btn, 0)
        header_layout.addWidget(key_ignore_btn, 0)
        header_layout.addWidget(alert_btn, 0)
        header_layout.addWidget(settings_btn, 0)
        header_bar.setFixedHeight(32)
        settings_row.addWidget(header_bar, 1)
        alert_overlay = QtWidgets.QFrame(header_bar)
        alert_overlay.hide()
        alert_overlay.raise_()
        alert_overlay.setFixedHeight(32)
        alert_overlay.setStyleSheet("background:#7a1e1e;border:none;")
        alert_overlay_layout = QtWidgets.QHBoxLayout(alert_overlay)
        alert_overlay_layout.setContentsMargins(10, 0, 10, 0)
        alert_overlay_layout.setSpacing(0)
        alert_overlay_label = QtWidgets.QLabel("")
        set_mono(alert_overlay_label, 11)
        alert_overlay_label.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        alert_overlay_label.setStyleSheet("color:#fff2f2;font-weight:600;")
        alert_overlay_layout.addWidget(alert_overlay_label, 1)
        alert_anim = QtCore.QPropertyAnimation(alert_overlay, b"pos")
        alert_anim.setDuration(220)
        alert_anim.setEasingCurve(QtCore.QEasingCurve.OutCubic)
        alert_overlay_visible = False
        _orig_header_resize_event = header_bar.resizeEvent
        def _header_resize_event(e):
            try:
                w = max(1, header_bar.width())
                h = header_bar.height()
                alert_overlay.setFixedWidth(w)
                alert_overlay.setFixedHeight(h)
                if alert_overlay_visible:
                    alert_overlay.move(0, 0)
                else:
                    alert_overlay.move(w, 0)
            except Exception:
                pass
            try:
                _orig_header_resize_event(e)
            except Exception:
                pass
        header_bar.resizeEvent = _header_resize_event
        right_col.addLayout(settings_row, 0)
        chat_text = QtWidgets.QListWidget()
        chat_text.setObjectName("chatList")
        set_mono(chat_text)
        chat_text.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        chat_text.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        chat_text.setSpacing(1)
        chat_text.setUniformItemSizes(False)
        chat_text.setContentsMargins(0, 0, 0, 0)
        chat_text.setFrameShape(QtWidgets.QFrame.NoFrame)
        right_col.addWidget(chat_text, 4)
        _orig_chat_resize_event = chat_text.resizeEvent
        _chat_layout_state = {"viewport_w": -1}
        def _chat_resize_event(e):
            try:
                _orig_chat_resize_event(e)
            except Exception:
                pass
            try:
                vpw = int(chat_text.viewport().width())
                if vpw != int(_chat_layout_state.get("viewport_w", -1)):
                    _chat_layout_state["viewport_w"] = vpw
                    relayout_chat_items(chat_text)
            except Exception:
                pass
        chat_text.resizeEvent = _chat_resize_event

        class InputBox(QtWidgets.QTextEdit):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._send_cb = None
                self.setAcceptRichText(False)

            def set_send_callback(self, cb):
                self._send_cb = cb

            def keyPressEvent(self, event: QtGui.QKeyEvent) -> None:
                if event.key() in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
                    if event.modifiers() & QtCore.Qt.ShiftModifier:
                        return super().keyPressEvent(event)
                    if self._send_cb:
                        self._send_cb()
                        return
                super().keyPressEvent(event)

        msg_entry = InputBox()
        set_mono(msg_entry)
        msg_entry.setPlaceholderText(tr("message"))
        msg_entry.setFixedHeight(32)
        send_btn = QtWidgets.QPushButton(tr("send"))
        send_btn.setFixedHeight(32)
        msg_row = QtWidgets.QHBoxLayout()
        msg_row.setContentsMargins(0, 0, 0, 0)
        msg_row.setSpacing(0)
        msg_row.addWidget(msg_entry, 1)
        send_col = QtWidgets.QVBoxLayout()
        send_col.setContentsMargins(0, 0, 0, 0)
        send_col.setSpacing(0)
        send_col.addStretch(1)
        send_col.addWidget(send_btn, 0, QtCore.Qt.AlignBottom)
        msg_row.addLayout(send_col)
        right_col.addLayout(msg_row, 0)

        def adjust_input_height() -> None:
            doc = msg_entry.document()
            doc_height = int(doc.size().height())
            fm = QtGui.QFontMetrics(msg_entry.font())
            line_h = max(1, fm.lineSpacing())
            content_h = max(32, doc_height + 8)
            max_h = max(32, int(win.height() / 3))
            msg_entry.setFixedHeight(min(content_h, max_h))

        def adjust_contacts_panel_width() -> None:
            try:
                fm = QtGui.QFontMetrics(items_list.font())
                max_line = 0
                for i in range(items_list.count()):
                    it = items_list.item(i)
                    if it is None:
                        continue
                    txt = str(it.text() or "")
                    for ln in (txt.splitlines() or [txt]):
                        max_line = max(max_line, int(fm.horizontalAdvance(ln)))
                # icon + paddings + status marker reserve
                needed = max(260, max_line + 44 + 42)
                cap = max(280, int(win.width() * 0.48))
                target = min(needed, cap)
                list_group.setMinimumWidth(target)
            except Exception:
                pass

        msg_entry.textChanged.connect(adjust_input_height)
        _orig_win_resize_event = win.resizeEvent
        def _win_resize_event(e):
            try:
                _orig_win_resize_event(e)
            except Exception:
                pass
            try:
                adjust_input_height()
            except Exception:
                pass
            try:
                adjust_contacts_panel_width()
            except Exception:
                pass
        win.resizeEvent = _win_resize_event

        peer_logo_cache: Dict[Tuple[str, int], "QtGui.QPixmap"] = {}

        def _peer_logo_pixmap(peer_id: str, side: int) -> "QtGui.QPixmap":
            s = max(16, int(side))
            key = (str(peer_id or ""), s)
            cached = peer_logo_cache.get(key)
            if cached is not None:
                return cached
            token = str(key[0]).encode("utf-8", errors="ignore")
            digest = hashlib.blake2s(token, digest_size=32).digest()
            base_h = (digest[0] / 255.0) % 1.0
            sat = 0.18 + (digest[1] / 255.0) * 0.12
            lum = 0.40 + (digest[2] / 255.0) * 0.10

            def _col(h_off: float, l_off: float, s_mul: float = 1.0) -> "QtGui.QColor":
                h = (base_h + h_off) % 1.0
                l = min(0.82, max(0.16, lum + l_off))
                s_local = max(0.08, min(0.50, sat * s_mul))
                r, g, b = colorsys.hls_to_rgb(h, l, s_local)
                return QtGui.QColor(int(r * 255), int(g * 255), int(b * 255))

            c_bg = _col(0.00, -0.16, 0.7)
            c_line = _col(0.00, 0.06, 1.0)
            c_line.setAlpha(118)

            pm = QtGui.QPixmap(s, s)
            pm.fill(QtCore.Qt.transparent)
            p = QtGui.QPainter(pm)
            p.setRenderHint(QtGui.QPainter.Antialiasing, True)
            p.setRenderHint(QtGui.QPainter.SmoothPixmapTransform, True)

            outer = QtCore.QRectF(0.5, 0.5, float(s - 1), float(s - 1))
            p.setPen(QtCore.Qt.NoPen)
            p.setBrush(c_bg)
            p.drawRoundedRect(outer, max(2.0, s * 0.22), max(2.0, s * 0.22))

            # Deterministic RNG-like values from digest.
            vals = []
            ctr = 0
            while len(vals) < 96:
                block = hashlib.blake2s(token + ctr.to_bytes(2, "big"), digest_size=32).digest()
                vals.extend(block)
                ctr += 1
            vi = 0

            def _v01() -> float:
                nonlocal vi
                b = vals[vi % len(vals)]
                vi += 1
                return float(b) / 255.0

            cx = outer.center().x()
            cy = outer.center().y()
            rad = min(outer.width(), outer.height()) * 0.42

            # One continuous "finger signature" stroke with a few loops.
            freq1 = 0.9 + _v01() * 1.3
            freq2 = 1.2 + _v01() * 1.6
            phase1 = _v01() * math.pi * 2.0
            phase2 = _v01() * math.pi * 2.0
            amp_x = rad * (0.78 + _v01() * 0.30)
            amp_y = rad * (0.58 + _v01() * 0.26)
            drift_x = (-0.28 + _v01() * 0.56) * rad
            drift_y = (-0.18 + _v01() * 0.36) * rad
            width_base = max(2.0, s * (0.105 + _v01() * 0.075))
            width_jitter = width_base * 0.30
            steps = 56

            def _stroke_point(t: float) -> "QtCore.QPointF":
                # Short compact signature-like motion with 2-4 soft loops.
                t2 = t - 0.5
                x = cx + drift_x * t2
                y = cy + drift_y * t2
                x += amp_x * (
                    0.70 * math.sin((freq1 * 2.0 * math.pi * t) + phase1)
                    + 0.22 * math.sin((freq2 * 2.0 * math.pi * t) + phase2)
                    + 0.08 * math.sin(((freq2 + 1.4) * 2.0 * math.pi * t) + (phase1 * 0.6))
                )
                y += amp_y * (
                    0.66 * math.sin(((freq1 + 0.45) * 2.0 * math.pi * t) + (phase2 * 0.85))
                    + 0.24 * math.sin(((freq2 + 0.25) * 2.0 * math.pi * t) + (phase1 * 1.1))
                    + 0.10 * math.sin(((freq2 + 1.00) * 2.0 * math.pi * t) + (phase2 * 0.7))
                )
                # Keep stroke open: soften center over-crossing density.
                center_soft = 0.82 + (0.18 * abs((t * 2.0) - 1.0))
                x = cx + (x - cx) * center_soft
                y = cy + (y - cy) * center_soft
                return QtCore.QPointF(x, y)

            prev_pt = _stroke_point(0.0)
            for st_i in range(1, steps + 1):
                t = float(st_i) / float(steps)
                cur_pt = _stroke_point(t)
                tx = cur_pt.x() - prev_pt.x()
                ty = cur_pt.y() - prev_pt.y()
                tl = max(1e-6, math.hypot(tx, ty))
                jnx = -ty / tl
                jny = tx / tl
                jitter_amp = rad * (0.007 + _v01() * 0.016)
                j = (-0.5 + _v01()) * 2.0 * jitter_amp
                cur_pt = QtCore.QPointF(cur_pt.x() + (jnx * j), cur_pt.y() + (jny * j))
                # Finger-pressure profile: gentle attack -> peak -> release.
                if t < 0.25:
                    pressure_shape = 0.86 + (t / 0.25) * 0.22
                elif t < 0.70:
                    pressure_shape = 1.08 - ((t - 0.25) / 0.45) * 0.06
                else:
                    pressure_shape = 1.02 - ((t - 0.70) / 0.30) * 0.34
                pressure = pressure_shape + ((-0.5 + _v01()) * 0.14) + (0.07 * math.sin((2.0 * math.pi * t) + (phase1 * 0.45)))
                w = max(1.0, (width_base + ((-0.5 + _v01()) * 2.0 * width_jitter)) * pressure)
                # Keep stroke translucent with subtle alpha changes along the gesture.
                # Slightly stronger color drift along the stroke path.
                h_drift = (-0.070 + (0.140 * t))
                l_drift = (-0.090 + (0.200 * t))
                s_drift = 0.78 + (0.38 * t)
                col = _col(h_drift, l_drift, s_drift)
                alpha = int(80 + max(0.0, min(1.0, pressure - 0.64)) * 110)
                col.setAlpha(max(66, min(182, alpha)))
                pen = QtGui.QPen(col, w, QtCore.Qt.SolidLine, QtCore.Qt.RoundCap, QtCore.Qt.RoundJoin)
                p.setPen(pen)
                p.setBrush(QtCore.Qt.NoBrush)
                p.drawLine(prev_pt, cur_pt)
                prev_pt = cur_pt

            p.end()
            peer_logo_cache[key] = pm
            return pm

        class ContactDelegate(QtWidgets.QStyledItemDelegate):
            def paint(self, painter: QtGui.QPainter, option: QtWidgets.QStyleOptionViewItem, index: QtCore.QModelIndex) -> None:
                super().paint(painter, option, index)
                data = index.data(QtCore.Qt.UserRole)
                if not isinstance(data, dict):
                    return
                unread = int(data.get("unread", 0) or 0)
                rect = option.rect
                pad = 4
                selected = bool(option.state & QtWidgets.QStyle.State_Selected)
                panel_size = max(8, int(rect.height() / 5))
                icon_w = int(option.decorationSize.width()) if option.decorationSize.isValid() else 44
                icon_h = int(option.decorationSize.height()) if option.decorationSize.isValid() else 44
                icon_side = max(16, min(max(icon_w, icon_h), max(16, rect.height() - 8)))
                icon_left = rect.left() + 6
                icon_top = rect.top() + max(2, int((rect.height() - icon_side) / 2))
                panel_left = icon_left + icon_side - panel_size
                panel_top = icon_top + icon_side - panel_size
                panel_left = min(max(rect.left(), panel_left), max(rect.left(), rect.right() - panel_size))
                panel_top = min(max(rect.top(), panel_top), max(rect.top(), rect.bottom() - panel_size))
                panel_rect = QtCore.QRect(panel_left, panel_top, panel_size, panel_size)
                text_rect = QtCore.QRect(rect.left() + pad, rect.top(), max(1, rect.width() - (pad * 2)), rect.height())
                painter.save()
                status_code = str(data.get("status_code", "") or "")
                panel_color = None
                if status_code == "app_online":
                    panel_color = QtGui.QColor("#2bbf66")
                elif status_code == "app_offline":
                    panel_color = QtGui.QColor("#1f6b3f")
                elif status_code == "mesh_online":
                    panel_color = QtGui.QColor("#d9b233")
                elif status_code == "mesh_offline":
                    panel_color = QtGui.QColor("#8f6f18")
                if panel_color is not None:
                    painter.setPen(QtCore.Qt.NoPen)
                    painter.setBrush(panel_color)
                    r = max(1.5, panel_size * 0.18)
                    painter.drawRoundedRect(QtCore.QRectF(panel_rect), r, r)
                if unread > 0:
                    # Unread counter is rendered in a separate pink square at the bottom-right of contact row.
                    badge_size = max(11, int(icon_side * 0.34))
                    badge_left = rect.right() - badge_size - 4
                    badge_top = rect.bottom() - badge_size - 4
                    badge_rect = QtCore.QRect(
                        int(max(rect.left(), min(badge_left, rect.right() - badge_size))),
                        int(max(rect.top(), min(badge_top, rect.bottom() - badge_size))),
                        int(badge_size),
                        int(badge_size),
                    )
                    painter.setPen(QtCore.Qt.NoPen)
                    painter.setBrush(QtGui.QColor("#e1499a"))
                    rr = max(1.5, badge_size * 0.20)
                    painter.drawRoundedRect(QtCore.QRectF(badge_rect), rr, rr)
                    txt = str(int(unread)) if int(unread) <= 99 else "99+"
                    f = painter.font()
                    f.setBold(True)
                    f.setPointSize(max(6, int(badge_size * 0.52)))
                    painter.setFont(f)
                    painter.setPen(QtGui.QColor("#fff6fb"))
                    painter.drawText(badge_rect, int(QtCore.Qt.AlignCenter), txt)
                    # Left of unread badge: last received message time (and date when day differs).
                    try:
                        rx_ts = float(data.get("last_rx_ts", 0.0) or 0.0)
                    except Exception:
                        rx_ts = 0.0
                    if rx_ts > 0.0:
                        try:
                            dt = datetime.fromtimestamp(rx_ts)
                            now_dt = datetime.now()
                            if dt.date() == now_dt.date():
                                rx_text = dt.strftime("%H:%M")
                            else:
                                rx_text = dt.strftime("%d.%m %H:%M")
                            tf = painter.font()
                            tf.setBold(False)
                            tf.setPointSize(max(7, int(badge_size * 0.45)))
                            painter.setFont(tf)
                            painter.setPen(QtGui.QColor("#bcaec0"))
                            tw = int(painter.fontMetrics().horizontalAdvance(rx_text))
                            tx = int(max(rect.left() + 2, badge_rect.left() - tw - 6))
                            ty = int(badge_rect.top() + badge_rect.height() - 1)
                            painter.drawText(tx, ty, rx_text)
                        except Exception:
                            pass
                painter.restore()

        items_list.setItemDelegate(ContactDelegate(items_list))

        THEME_UBUNTU_STYLE = """
            QWidget { background: #300a24; color: #eeeeec; }
            QGroupBox { border: 0; margin-top: 0; font-weight: 600; }
            QGroupBox::title { subcontrol-origin: margin; left: 4px; color: #cfcfcf; }
            QGroupBox#listGroup::title { height: 0px; }
            QGroupBox#listGroup { margin-top: 0px; }
            QListWidget { background: #2b0a22; border: 1px solid #3c0f2e; padding: 0px; }
            QListWidget#chatList::item { background: transparent; border: none; padding: 2px 0px; }
            QListWidget#chatList::item:selected { background: transparent; }
            QListWidget#chatList::item:selected:!active { background: transparent; }
            QTextEdit { background: #2b0a22; border: 1px solid #3c0f2e; padding: 0px; }
            QLineEdit { background: #2b0a22; border: 1px solid #6f4a7a; padding: 6px; }
            QPushButton { background: #5c3566; border: 1px solid #6f4a7a; padding: 6px 10px; }
            QPushButton:hover { background: #6f4a7a; }
            QTabWidget::pane { border: 1px solid #6f4a7a; top: -1px; }
            QTabBar::tab {
                background: #43264a;
                color: #efe7f2;
                border: 1px solid #6f4a7a;
                border-bottom: 0;
                padding: 6px 12px;
                margin-right: 2px;
                min-height: 22px;
            }
            QTabBar::tab:selected {
                background: #ff9800;
                color: #2b0a22;
                font-weight: 700;
            }
            QTabBar::tab:!selected:hover {
                background: #5a3363;
                color: #ffffff;
            }
            QMenu { background: #2b0a22; border: 1px solid #6f4a7a; padding: 2px; }
            QMenu::item { padding: 6px 14px; color: #eeeeec; }
            QMenu::item:selected { background: #ff9800; color: #2b0a22; }
            QLabel#muted { color: #c0b7c2; }
            QLabel#hint { color: #bcaec0; font-size: 10px; }
            QLabel#section { color: #c0b7c2; font-size: 13px; font-weight: 400; }
            QWidget#headerBar { background: #c24f00; }
            QWidget#headerBar QLabel { background: transparent; font-weight: 600; color: #2b0a22; }
            QWidget#headerBar[mtStatus="ok"] { background: #0b3d1f; }
            QWidget#headerBar[mtStatus="ok"] QLabel { color: #fffff0; }
            QWidget#headerBar[mtStatus="warn"] { background: #8a5a00; }
            QWidget#headerBar[mtStatus="warn"] QLabel { color: #fff7df; }
            QWidget#headerBar[mtStatus="error"] { background: #6b1d1d; }
            QWidget#headerBar[mtStatus="error"] QLabel { color: #ffecec; }
            QListWidget#contactsList::item { padding: 8px 0px; }
            QListWidget#contactsList::item:selected { background: #4d351f; }
            QListWidget#contactsList::item:selected:!active { background: #4d351f; }
            QScrollBar:vertical {
                background: transparent;
                width: 8px;
                margin: 0px;
                border: none;
            }
            QScrollBar::handle:vertical {
                background: rgba(210, 170, 220, 0.42);
                min-height: 24px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: rgba(230, 190, 240, 0.62);
            }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                height: 0px;
                border: none;
                background: transparent;
            }
            QScrollBar::add-page:vertical,
            QScrollBar::sub-page:vertical {
                background: transparent;
            }
            """
        THEME_BRUTAL_MAN = """
            QWidget { background: #101214; color: #e8e8e8; }
            QGroupBox { border: 0; margin-top: 0; font-weight: 700; }
            QGroupBox::title { subcontrol-origin: margin; left: 4px; color: #c9c9c9; }
            QGroupBox#listGroup::title { height: 0px; }
            QGroupBox#listGroup { margin-top: 0px; }
            QListWidget { background: #15181b; border: 1px solid #3a3f46; padding: 0px; }
            QListWidget#chatList::item { background: transparent; border: none; padding: 2px 0px; }
            QListWidget#chatList::item:selected { background: transparent; }
            QListWidget#chatList::item:selected:!active { background: transparent; }
            QTextEdit { background: #15181b; border: 1px solid #3a3f46; padding: 0px; }
            QLineEdit { background: #15181b; border: 1px solid #5a6069; padding: 6px; }
            QPushButton { background: #2b3036; border: 1px solid #5a6069; padding: 6px 10px; color:#f0f0f0; }
            QPushButton:hover { background: #383e45; }
            QTabWidget::pane { border: 1px solid #5a6069; top: -1px; }
            QTabBar::tab {
                background: #242a30;
                color: #d6d6d6;
                border: 1px solid #5a6069;
                border-bottom: 0;
                padding: 6px 12px;
                margin-right: 2px;
                min-height: 22px;
            }
            QTabBar::tab:selected {
                background: #f05d23;
                color: #111417;
                font-weight: 800;
            }
            QTabBar::tab:!selected:hover { background: #2f353c; color: #ffffff; }
            QMenu { background: #15181b; border: 1px solid #5a6069; padding: 2px; }
            QMenu::item { padding: 6px 14px; color: #e8e8e8; }
            QMenu::item:selected { background: #f05d23; color: #101214; }
            QLabel#muted { color: #b8b8b8; }
            QLabel#hint { color: #999fa8; font-size: 10px; }
            QLabel#section { color: #b8b8b8; font-size: 13px; font-weight: 500; }
            QWidget#headerBar { background: #f05d23; }
            QWidget#headerBar QLabel { background: transparent; font-weight: 700; color: #101214; }
            QWidget#headerBar[mtStatus="ok"] { background: #1f5f2f; }
            QWidget#headerBar[mtStatus="ok"] QLabel { color: #fffff0; }
            QWidget#headerBar[mtStatus="warn"] { background: #8a5a00; }
            QWidget#headerBar[mtStatus="warn"] QLabel { color: #fff7df; }
            QWidget#headerBar[mtStatus="error"] { background: #7a1e1e; }
            QWidget#headerBar[mtStatus="error"] QLabel { color: #ffecec; }
            QListWidget#contactsList::item { padding: 8px 0px; }
            QListWidget#contactsList::item:selected { background: #3e2a24; }
            QListWidget#contactsList::item:selected:!active { background: #3e2a24; }
            QScrollBar:vertical {
                background: transparent;
                width: 8px;
                margin: 0px;
                border: none;
            }
            QScrollBar::handle:vertical {
                background: rgba(170, 175, 185, 0.45);
                min-height: 24px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: rgba(200, 205, 215, 0.62);
            }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                height: 0px;
                border: none;
                background: transparent;
            }
            QScrollBar::add-page:vertical,
            QScrollBar::sub-page:vertical {
                background: transparent;
            }
            """
        THEME_STYLES = {
            "ubuntu_style": THEME_UBUNTU_STYLE,
            "brutal_man": THEME_BRUTAL_MAN,
        }
        current_theme = str(cfg.get("ui_theme", "ubuntu_style") or "ubuntu_style").strip().lower()
        if current_theme not in THEME_STYLES:
            current_theme = "ubuntu_style"

        def apply_theme(theme_id: str) -> None:
            nonlocal current_theme
            tid = str(theme_id or "ubuntu_style").strip().lower()
            if tid not in THEME_STYLES:
                tid = "ubuntu_style"
            current_theme = tid
            win.setStyleSheet(THEME_STYLES[tid])
            try:
                win.update()
            except Exception:
                pass

        apply_theme(current_theme)

        class _NoCtrlWheelZoom(QtCore.QObject):
            def eventFilter(self, obj: QtCore.QObject, event: QtCore.QEvent) -> bool:
                try:
                    if event.type() == QtCore.QEvent.Type.Wheel:
                        mods = event.modifiers()
                        if mods & QtCore.Qt.ControlModifier:
                            # Prevent QTextEdit Ctrl+Wheel zoom. Keep scrolling behavior instead.
                            try:
                                sb = obj.verticalScrollBar()  # type: ignore[attr-defined]
                                dy = int(event.angleDelta().y())  # type: ignore[attr-defined]
                                if sb is not None and dy:
                                    sb.setValue(int(sb.value()) - int(dy))
                            except Exception:
                                pass
                            return True
                except Exception:
                    pass
                return False

        _no_ctrl_zoom = _NoCtrlWheelZoom(win)
        try:
            chat_text.installEventFilter(_no_ctrl_zoom)
            chat_text.viewport().installEventFilter(_no_ctrl_zoom)
        except Exception:
            pass

        header_status = "init"
        errors_need_ack = False  # backward compatibility flag; derived from unseen_error_count
        unseen_error_count = 0
        unseen_warn_count = 0
        last_error_summary = ""
        last_warn_summary = ""
        last_error_ts = 0.0
        last_warn_ts = 0.0
        current_alert_level = ""
        current_alert_text = ""
        key_conflict_peer: str = ""
        key_conflict_notice: str = ""
        key_conflict_sig: str = ""
        key_conflict_ignored: Dict[str, Dict[str, object]] = {}
        key_conflict_hidden_log_ts: Dict[str, float] = {}
        header_bar.setProperty("mtStatus", header_status)
        try:
            chat_label.setStyleSheet("color:#c0b7c2;")
        except Exception:
            pass

        def _set_key_conflict_header(peer_norm: str, conflict_sig: str = "") -> None:
            nonlocal key_conflict_peer, key_conflict_notice, key_conflict_sig
            p = norm_id_for_filename(peer_norm)
            if not re.fullmatch(r"[0-9a-fA-F]{8}", p):
                return
            key_conflict_peer = p
            key_conflict_sig = str(conflict_sig or "")
            long_name, short_name = _peer_name_parts(p)
            peer_name = long_name
            if short_name:
                peer_name = f"{peer_name}[{short_name}]" if peer_name else f"[{short_name}]"
            peer_name_text = f" {peer_name}" if peer_name else ""
            key_conflict_notice = tr("key_conflict_header_notice").format(
                peer=norm_id_for_wire(p),
                peer_name=peer_name_text,
            )
            key_renew_btn.show()
            key_ignore_btn.show()
            key_renew_btn.setText(tr("key_conflict_replace"))
            key_ignore_btn.setText(tr("key_conflict_paranoid"))
            key_renew_btn.setToolTip(tr("key_conflict_header_replace_tip"))
            key_ignore_btn.setToolTip(tr("key_conflict_header_ignore_tip"))
            alert_btn.hide()

        def _clear_key_conflict_header() -> None:
            nonlocal key_conflict_peer, key_conflict_notice, key_conflict_sig
            key_conflict_peer = ""
            key_conflict_sig = ""
            key_conflict_notice = ""
            key_renew_btn.hide()
            key_ignore_btn.hide()

        def _strip_log_prefix(s: str) -> str:
            txt = str(s or "").strip()
            m = re.match(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+", txt)
            if m:
                txt = txt[m.end() :].strip()
            return txt

        def _alert_summary(s: str, limit: int = 78) -> str:
            txt = _strip_log_prefix(s)
            if len(txt) > limit:
                return txt[: max(0, limit - 1)] + "..."
            return txt

        def _human_alert_text(raw_text: str, level: str) -> str:
            raw = _strip_log_prefix(raw_text)
            low = raw.lower()

            # User-facing bilingual summaries (RU / EN)
            if "pinned key mismatch" in low:
                peer_txt = ""
                try:
                    m_peer = re.search(r"\bpeer=(!?[0-9a-fA-F]{8})\b", raw)
                    if m_peer:
                        peer_norm = norm_id_for_filename(m_peer.group(1))
                        peer_wire = norm_id_for_wire(peer_norm)
                        peer_txt = f" ({peer_wire})"
                except Exception:
                    peer_txt = ""
                return f"Конфликт ключа контакта{peer_txt} / Contact key mismatch"
            if "decrypt failed" in low:
                return "Не удалось расшифровать сообщение / Failed to decrypt message"
            if "reject invalid public key" in low or "reject invalid key frame" in low:
                return "Некорректный ключевой пакет / Invalid key frame"
            if "radio: disconnected" in low:
                return "Радиомодуль отключен / Radio disconnected"
            if "radio: protobuf decode error" in low:
                return "Ошибка данных радиомодуля / Radio decode error"
            if "trace: done" in low and "timeout" in low:
                return "Трассировка не ответила вовремя / Traceroute timed out"
            if "send failed" in low:
                return "Ошибка отправки пакета / Packet send failed"
            if "drop:" in low and "timeout" in low:
                return "Пакет не доставлен вовремя / Packet delivery timeout"
            if "exception" in low or "traceback" in low:
                return "Внутренняя ошибка приложения / Internal application error"
            if low.startswith("warn:"):
                return "Предупреждение системы / System warning"

            # Fallback: short readable raw event + bilingual marker.
            short = _alert_summary(raw, limit=64)
            if str(level or "").lower() == "error":
                return f"Ошибка: {short} / Error: {short}"
            return f"Предупреждение: {short} / Warning: {short}"

        def _compose_header_title() -> str:
            if key_conflict_notice:
                return key_conflict_notice
            return self_title()

        def _apply_alert_visual(level: str) -> None:
            lv = str(level or "").strip().lower()
            if lv == "error":
                alert_btn.setStyleSheet(
                    "QPushButton { background:#8f1d1d; border:1px solid #c85a5a; color:#fff2f2; font-weight:700; }"
                    "QPushButton:hover { background:#a82424; }"
                )
                alert_overlay.setStyleSheet("background:#7a1e1e;border:none;")
                alert_overlay_label.setStyleSheet("color:#fff2f2;font-weight:600;")
            elif lv == "warn":
                alert_btn.setStyleSheet(
                    "QPushButton { background:#8a5a00; border:1px solid #d3a33d; color:#fff7df; font-weight:700; }"
                    "QPushButton:hover { background:#a36b00; }"
                )
                alert_overlay.setStyleSheet("background:#8a5a00;border:none;")
                alert_overlay_label.setStyleSheet("color:#fff7df;font-weight:600;")
            else:
                alert_btn.setStyleSheet("")

        def _hide_alert_overlay() -> None:
            nonlocal alert_overlay_visible
            if not alert_overlay_visible:
                return
            alert_overlay_visible = False
            try:
                alert_anim.stop()
            except Exception:
                pass
            start_pos = QtCore.QPoint(max(0, header_bar.width() - alert_overlay.width()), 0)
            end_pos = QtCore.QPoint(header_bar.width(), 0)
            try:
                alert_overlay.move(start_pos)
            except Exception:
                pass
            def _after_hide():
                if not alert_overlay_visible:
                    alert_overlay.hide()
                    if current_alert_level:
                        alert_btn.show()
            try:
                alert_anim.finished.disconnect()
            except Exception:
                pass
            alert_anim.finished.connect(_after_hide)
            alert_anim.setStartValue(start_pos)
            alert_anim.setEndValue(end_pos)
            alert_anim.start()

        def _show_alert_overlay() -> None:
            nonlocal alert_overlay_visible
            if not current_alert_text:
                return
            alert_overlay_visible = True
            alert_btn.hide()
            alert_overlay_label.setText(current_alert_text)
            w = max(1, header_bar.width())
            h = header_bar.height()
            alert_overlay.setFixedWidth(w)
            alert_overlay.setFixedHeight(h)
            alert_overlay.show()
            alert_overlay.raise_()
            try:
                alert_anim.stop()
            except Exception:
                pass
            start_pos = QtCore.QPoint(w, 0)
            end_pos = QtCore.QPoint(0, 0)
            alert_overlay.move(start_pos)
            try:
                alert_anim.finished.disconnect()
            except Exception:
                pass
            alert_anim.setStartValue(start_pos)
            alert_anim.setEndValue(end_pos)
            alert_anim.start()

        def _update_alert_indicator() -> None:
            nonlocal current_alert_level, current_alert_text
            if unseen_error_count > 0:
                current_alert_level = "error"
                current_alert_text = _human_alert_text(last_error_summary or "error", "error")
            elif unseen_warn_count > 0:
                current_alert_level = "warn"
                current_alert_text = _human_alert_text(last_warn_summary or "warning", "warn")
            else:
                current_alert_level = ""
                current_alert_text = ""
            if current_alert_level:
                _apply_alert_visual(current_alert_level)
                cnt = int(unseen_error_count if current_alert_level == "error" else unseen_warn_count)
                if cnt <= 0:
                    cnt = 1
                alert_btn.setText(str(cnt if cnt < 100 else "99+"))
                if key_conflict_peer:
                    alert_btn.hide()
                elif not alert_overlay_visible:
                    alert_btn.show()
                if alert_overlay_visible:
                    alert_overlay_label.setText(current_alert_text)
                    _apply_alert_visual(current_alert_level)
            else:
                alert_btn.setText("!")
                alert_btn.hide()
                _hide_alert_overlay()

        def set_header_status(status: str) -> None:
            nonlocal header_status
            st = str(status or "init").strip().lower()
            if st not in ("init", "ok", "warn", "error"):
                st = "init"
            # Warning/error must not repaint the whole header bar:
            # base bar reflects only connection/init state.
            if st in ("warn", "error"):
                st = "ok" if (radio_ready and not initializing) else "init"

            def _header_text_color_for(st_local: str) -> str:
                # Keep high contrast against current theme/status background.
                if st_local == "ok":
                    return "#fffff0"  # ivory on dark green
                if st_local == "error":
                    return "#ffecec"
                if st_local == "warn":
                    return "#fff7df"
                # init color depends on theme's orange header shade
                if str(current_theme or "") == "brutal_man":
                    return "#101214"
                return "#2b0a22"
            if st == header_status:
                try:
                    chat_label.setStyleSheet(f"color:{_header_text_color_for(st)};")
                    chat_label.setText(_compose_header_title())
                except Exception:
                    pass
                return
            header_status = st
            header_bar.setProperty("mtStatus", st)
            try:
                header_bar.style().unpolish(header_bar)
                header_bar.style().polish(header_bar)
            except Exception:
                pass
            # Force header title color explicitly (QLabel#section rule may override theme selectors).
            try:
                chat_label.setStyleSheet(f"color:{_header_text_color_for(st)};")
            except Exception:
                pass
            try:
                chat_label.setText(_compose_header_title())
            except Exception:
                pass
            header_bar.update()

        peer_meta: Dict[str, Dict[str, float]] = {}
        peer_meta_dirty = False

        groups: Dict[str, set] = {k: set(v) for k, v in groups_cfg.items() if isinstance(k, str) and isinstance(v, list)}
        dialogs: Dict[str, Dict[str, object]] = {}
        chat_history: Dict[str, list] = {}
        list_index: list[Optional[str]] = []
        current_dialog: Optional[str] = None
        last_loaded_profile: Optional[str] = None

        def save_gui_config() -> None:
            save_config(
                {
                    "lang": current_lang,
                    "log_verbose": verbose_log,
                    "runtime_log_file": runtime_log_file,
                    "auto_pacing": auto_pacing,
                    "pinned_dialogs": sorted(pinned_dialogs),
                    "hidden_contacts": sorted(hidden_contacts),
                    "groups": {k: sorted(list(v)) for k, v in groups.items()},
                    "port": cfg.get("port", args.port),
                    "channel": cfg.get("channel", args.channel),
                    "retry_seconds": cfg.get("retry_seconds", args.retry_seconds),
                    "max_seconds": cfg.get("max_seconds", args.max_seconds),
                    "max_bytes": cfg.get("max_bytes", args.max_bytes),
                    "rate_seconds": cfg.get("rate_seconds", args.rate_seconds),
                    "parallel_sends": cfg.get("parallel_sends", getattr(args, "parallel_sends", 1)),
                    "discovery_enabled": bool(discovery_send and discovery_reply),
                    "discovery_send": discovery_send,
                    "discovery_reply": discovery_reply,
                    "clear_pending_on_switch": clear_pending_on_switch,
                    "contacts_visibility": contacts_visibility,
                    "ui_theme": current_theme,
                    "peer_meta": peer_meta,
                }
            )

        def apply_language() -> None:
            list_group.setTitle("")
            update_status()
            msg_entry.setPlaceholderText(tr("message"))
            settings_btn.setText(tr("settings"))
            key_renew_btn.setText(tr("key_conflict_replace"))
            key_ignore_btn.setText(tr("key_conflict_paranoid"))
            key_renew_btn.setToolTip(tr("key_conflict_header_replace_tip"))
            key_ignore_btn.setToolTip(tr("key_conflict_header_ignore_tip"))
            if key_conflict_peer:
                _set_key_conflict_header(key_conflict_peer, key_conflict_sig)
            send_btn.setText(tr("send"))
            search_field.setPlaceholderText(tr("search"))

        def update_peer_meta(peer_norm: Optional[str]) -> None:
            nonlocal peer_meta_dirty
            if not peer_norm:
                return
            st = peer_states.get(peer_norm)
            if not st:
                return
            prev_rec = peer_meta.get(peer_norm, {})
            rec: Dict[str, float] = dict(prev_rec) if isinstance(prev_rec, dict) else {}
            changed = False
            if float(getattr(st, "last_seen_ts", 0.0) or 0.0) > 0.0:
                prev = float(rec.get("last_seen_ts", 0.0) or 0.0)
                if float(st.last_seen_ts) > (prev + 1.0):
                    rec["last_seen_ts"] = float(st.last_seen_ts)
                    changed = True
            if float(getattr(st, "device_seen_ts", 0.0) or 0.0) > 0.0:
                prev = float(rec.get("device_seen_ts", 0.0) or 0.0)
                if float(st.device_seen_ts) > (prev + 1.0):
                    rec["device_seen_ts"] = float(st.device_seen_ts)
                    changed = True
            if float(getattr(st, "key_confirmed_ts", 0.0) or 0.0) > 0.0:
                prev = float(rec.get("key_confirmed_ts", 0.0) or 0.0)
                if float(st.key_confirmed_ts) > (prev + 1.0):
                    rec["key_confirmed_ts"] = float(st.key_confirmed_ts)
                    changed = True
            if changed:
                peer_meta[peer_norm] = rec
                peer_meta_dirty = True

        settings_log_view: Optional["QtWidgets.QTextEdit"] = None
        settings_rate_edit: Optional["QtWidgets.QLineEdit"] = None
        settings_parallel_edit: Optional["QtWidgets.QLineEdit"] = None
        settings_auto_pacing_cb: Optional["QtWidgets.QCheckBox"] = None
        settings_panel_widget: Optional["QtWidgets.QDialog"] = None

        def open_settings() -> None:
            nonlocal current_lang
            nonlocal verbose_log
            nonlocal runtime_log_file
            nonlocal auto_pacing
            nonlocal settings_rate_edit, settings_parallel_edit, settings_auto_pacing_cb
            nonlocal discovery_send, discovery_reply
            nonlocal clear_pending_on_switch
            nonlocal contacts_visibility
            nonlocal security_policy
            nonlocal session_rekey_enabled
            nonlocal errors_need_ack
            nonlocal settings_panel_widget

            if settings_panel_widget is not None:
                try:
                    settings_panel_widget.raise_()
                    settings_panel_widget.activateWindow()
                except Exception:
                    pass
                return

            # Rebuild the dialog when language changes so all labels/hints are translated.
            while True:
                dlg = QtWidgets.QDialog(win)
                dlg.setWindowTitle(tr("settings_title"))
                dlg.resize(820, 600)
                dlg.setMinimumSize(760, 560)
                # Embedded settings panel in-place (inside the main window).
                try:
                    dlg.setWindowFlags(QtCore.Qt.Widget)
                except Exception:
                    pass
                dlg.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
                try:
                    class _NoMinimizeSettings(QtCore.QObject):
                        def eventFilter(self, obj, event):  # type: ignore[override]
                            try:
                                if event.type() == QtCore.QEvent.WindowStateChange:
                                    if isinstance(obj, QtWidgets.QWidget) and obj.windowState() & QtCore.Qt.WindowMinimized:
                                        obj.setWindowState(obj.windowState() & ~QtCore.Qt.WindowMinimized)
                                        obj.showNormal()
                                        obj.raise_()
                                        obj.activateWindow()
                                        return True
                            except Exception:
                                pass
                            return False

                    _no_min_settings = _NoMinimizeSettings(dlg)
                    dlg.installEventFilter(_no_min_settings)
                    dlg._no_min_settings = _no_min_settings  # type: ignore[attr-defined]
                except Exception:
                    pass
                layout = QtWidgets.QVBoxLayout(dlg)
                layout.setContentsMargins(10, 10, 10, 10)
                layout.setSpacing(10)

                tabs = QtWidgets.QTabWidget(dlg)
                layout.addWidget(tabs, 1)

                reopen = {"flag": False}

                # -------------------
                # General tab
                # -------------------
                tab_general = QtWidgets.QWidget()
                tabs.addTab(tab_general, tr("tab_general"))
                general_layout = QtWidgets.QHBoxLayout(tab_general)
                general_layout.setContentsMargins(14, 12, 14, 10)
                general_layout.setSpacing(26)

                left_panel = QtWidgets.QVBoxLayout()
                left_panel.setContentsMargins(0, 0, 0, 0)
                left_panel.setSpacing(12)
                right_panel = QtWidgets.QVBoxLayout()
                right_panel.setContentsMargins(0, 0, 0, 0)
                right_panel.setSpacing(12)

                # Keep panels compact; use stretch between them so resizing doesn't inflate either side.
                general_layout.addLayout(left_panel)
                general_layout.addStretch(1)
                general_layout.addLayout(right_panel)

                runtime_title = QtWidgets.QLabel(tr("settings_runtime"))
                runtime_title.setObjectName("muted")
                runtime_title.setStyleSheet("font-weight:600;")
                runtime_title.setContentsMargins(6, 8, 0, 0)
                left_panel.addWidget(runtime_title)

                runtime_group = QtWidgets.QGroupBox("")
                runtime_layout = QtWidgets.QFormLayout(runtime_group)
                runtime_layout.setLabelAlignment(QtCore.Qt.AlignLeft)
                runtime_layout.setFormAlignment(QtCore.Qt.AlignTop)
                runtime_layout.setVerticalSpacing(6)
                runtime_layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.ExpandingFieldsGrow)
                runtime_layout.setRowWrapPolicy(QtWidgets.QFormLayout.WrapLongRows)
                try:
                    runtime_layout.setContentsMargins(10, 10, 10, 10)
                except Exception:
                    pass

                def compact_field(widget, width: int = 240):
                    # Keep input fields stable: do not scale with Settings window resizing.
                    w = max(140, int(width))
                    try:
                        widget.setFixedWidth(w)
                    except Exception:
                        widget.setMinimumWidth(w)
                        widget.setMaximumWidth(w)
                    # Stable height (do not scale by height).
                    try:
                        widget.setFixedHeight(28)
                    except Exception:
                        pass
                    widget.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
                    return widget

                def int_text(value, fallback: int) -> str:
                    try:
                        return str(int(float(value)))
                    except Exception:
                        return str(int(fallback))

                # Port is auto-detected; do not expose it in UI.
                retry_edit = QtWidgets.QLineEdit(int_text(cfg.get("retry_seconds", args.retry_seconds), int(args.retry_seconds)))
                maxsec_edit = QtWidgets.QLineEdit(int_text(cfg.get("max_seconds", args.max_seconds), int(args.max_seconds)))
                maxbytes_edit = QtWidgets.QLineEdit(int_text(cfg.get("max_bytes", args.max_bytes), int(args.max_bytes)))
                rate_edit = QtWidgets.QLineEdit(int_text(cfg.get("rate_seconds", args.rate_seconds), int(args.rate_seconds)))
                parallel_edit = QtWidgets.QLineEdit(
                    int_text(
                        cfg.get("parallel_sends", getattr(args, "parallel_sends", 1)),
                        int(getattr(args, "parallel_sends", 1) or 1),
                    )
                )

                compact_field(retry_edit, width=240)
                compact_field(maxsec_edit, width=240)
                compact_field(maxbytes_edit, width=240)
                compact_field(rate_edit, width=240)
                compact_field(parallel_edit, width=160)

                int_validator = QtGui.QIntValidator(0, 999999, dlg)
                parallel_validator = QtGui.QIntValidator(1, 128, dlg)
                retry_edit.setValidator(int_validator)
                maxsec_edit.setValidator(int_validator)
                maxbytes_edit.setValidator(int_validator)
                rate_edit.setValidator(int_validator)
                parallel_edit.setValidator(parallel_validator)

                runtime_layout.addRow(tr("retry"), retry_edit)
                retry_hint = QtWidgets.QLabel(tr("hint_retry"))
                retry_hint.setObjectName("hint")
                retry_hint.setWordWrap(True)
                runtime_layout.addRow("", retry_hint)

                runtime_layout.addRow(tr("max_seconds"), maxsec_edit)
                maxsec_hint = QtWidgets.QLabel(tr("hint_max_seconds"))
                maxsec_hint.setObjectName("hint")
                maxsec_hint.setWordWrap(True)
                runtime_layout.addRow("", maxsec_hint)

                runtime_layout.addRow(tr("max_bytes"), maxbytes_edit)
                maxbytes_hint = QtWidgets.QLabel(tr("hint_max_bytes"))
                maxbytes_hint.setObjectName("hint")
                maxbytes_hint.setWordWrap(True)
                runtime_layout.addRow("", maxbytes_hint)

                runtime_layout.addRow(tr("rate"), rate_edit)
                rate_hint = QtWidgets.QLabel(tr("hint_rate"))
                rate_hint.setObjectName("hint")
                rate_hint.setWordWrap(True)
                runtime_layout.addRow("", rate_hint)

                runtime_layout.addRow(tr("parallel_sends"), parallel_edit)
                parallel_hint = QtWidgets.QLabel(tr("hint_parallel"))
                parallel_hint.setObjectName("hint")
                parallel_hint.setWordWrap(True)
                runtime_layout.addRow("", parallel_hint)

                cb_auto_pacing = QtWidgets.QCheckBox("")
                cb_auto_pacing.setChecked(bool(cfg.get("auto_pacing", auto_pacing)))
                runtime_layout.addRow(tr("auto_pacing"), cb_auto_pacing)
                auto_pacing_hint = QtWidgets.QLabel(tr("hint_auto_pacing"))
                auto_pacing_hint.setObjectName("hint")
                auto_pacing_hint.setWordWrap(True)
                runtime_layout.addRow("", auto_pacing_hint)

                settings_rate_edit = rate_edit
                settings_parallel_edit = parallel_edit
                settings_auto_pacing_cb = cb_auto_pacing

                def sync_auto_pacing_fields() -> None:
                    on = cb_auto_pacing.isChecked()
                    rate_edit.setEnabled(not on)
                    parallel_edit.setEnabled(not on)

                sync_auto_pacing_fields()
                cb_auto_pacing.toggled.connect(lambda _checked: sync_auto_pacing_fields())

                left_panel.addWidget(runtime_group)

                left_panel.addStretch(1)

                lang_title = QtWidgets.QLabel(tr("language"))
                lang_title.setObjectName("muted")
                lang_title.setStyleSheet("font-weight:600;")
                lang_title.setContentsMargins(6, 8, 0, 0)
                right_panel.addWidget(lang_title)

                lang_group = QtWidgets.QGroupBox("")
                lang_v = QtWidgets.QVBoxLayout(lang_group)
                rb_ru = QtWidgets.QRadioButton(tr("lang_ru"))
                rb_en = QtWidgets.QRadioButton(tr("lang_en"))
                if current_lang == "en":
                    rb_en.setChecked(True)
                else:
                    rb_ru.setChecked(True)
                lang_row = QtWidgets.QHBoxLayout()
                lang_row.setContentsMargins(0, 0, 0, 0)
                lang_row.addWidget(rb_ru)
                lang_row.addWidget(rb_en)
                lang_row.addStretch(1)
                lang_v.addLayout(lang_row)
                right_panel.addWidget(lang_group)

                log_title = QtWidgets.QLabel(tr("log") + " (events)")
                log_title.setObjectName("muted")
                log_title.setStyleSheet("font-weight:600;")
                log_title.setContentsMargins(6, 8, 0, 0)
                # Log settings moved to the Log tab to reduce clutter in General.

                discovery_title = QtWidgets.QLabel(tr("discovery"))
                discovery_title.setObjectName("muted")
                discovery_title.setStyleSheet("font-weight:600;")
                discovery_title.setContentsMargins(6, 8, 0, 0)
                right_panel.addWidget(discovery_title)

                discovery_group = QtWidgets.QGroupBox("")
                discovery_v = QtWidgets.QVBoxLayout(discovery_group)
                cb_discovery_send = QtWidgets.QCheckBox(tr("discovery_send"))
                cb_discovery_send.setChecked(discovery_send)
                discovery_v.addWidget(cb_discovery_send)
                discovery_send_hint = QtWidgets.QLabel(tr("hint_discovery_send"))
                discovery_send_hint.setObjectName("hint")
                discovery_send_hint.setWordWrap(True)
                discovery_v.addWidget(discovery_send_hint)

                cb_discovery_reply = QtWidgets.QCheckBox(tr("discovery_reply"))
                cb_discovery_reply.setChecked(discovery_reply)
                discovery_v.addWidget(cb_discovery_reply)
                discovery_reply_hint = QtWidgets.QLabel(tr("hint_discovery_reply"))
                discovery_reply_hint.setObjectName("hint")
                discovery_reply_hint.setWordWrap(True)
                discovery_v.addWidget(discovery_reply_hint)

                cb_clear_pending = QtWidgets.QCheckBox(tr("clear_pending_on_switch"))
                cb_clear_pending.setChecked(clear_pending_on_switch)
                discovery_v.addWidget(cb_clear_pending)
                clear_pending_hint = QtWidgets.QLabel(tr("hint_clear_pending"))
                clear_pending_hint.setObjectName("hint")
                clear_pending_hint.setWordWrap(True)
                discovery_v.addWidget(clear_pending_hint)

                right_panel.addWidget(discovery_group)

                right_panel.addStretch(1)

                # -------------------
                # Contacts tab
                # -------------------
                tab_contacts = QtWidgets.QWidget()
                tabs.addTab(tab_contacts, tr("tab_contacts"))
                contacts_root = QtWidgets.QVBoxLayout(tab_contacts)
                contacts_root.setContentsMargins(14, 12, 14, 10)
                contacts_root.setSpacing(12)

                visibility_title = QtWidgets.QLabel(tr("contacts_visibility"))
                visibility_title.setObjectName("muted")
                visibility_title.setStyleSheet("font-weight:600;")
                visibility_title.setContentsMargins(6, 8, 0, 0)
                contacts_root.addWidget(visibility_title)

                visibility_group = QtWidgets.QGroupBox("")
                visibility_v = QtWidgets.QVBoxLayout(visibility_group)
                contacts_visibility_combo = QtWidgets.QComboBox()
                contacts_visibility_combo.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
                try:
                    contacts_visibility_combo.setFixedHeight(28)
                except Exception:
                    pass
                contacts_visibility_combo.addItem(tr("contacts_visibility_all"), "all")
                contacts_visibility_combo.addItem(tr("contacts_visibility_online"), "online")
                contacts_visibility_combo.addItem(tr("contacts_visibility_app"), "app")
                contacts_visibility_combo.addItem(tr("contacts_visibility_device"), "device")
                _vis_idx = contacts_visibility_combo.findData(str(contacts_visibility or "all"))
                contacts_visibility_combo.setCurrentIndex(_vis_idx if _vis_idx >= 0 else 0)
                visibility_v.addWidget(contacts_visibility_combo)

                visibility_hint_all = QtWidgets.QLabel(tr("hint_contacts_visibility_all"))
                visibility_hint_all.setObjectName("hint")
                visibility_hint_all.setWordWrap(True)
                visibility_v.addWidget(visibility_hint_all)

                visibility_hint_online = QtWidgets.QLabel(tr("hint_contacts_visibility_online"))
                visibility_hint_online.setObjectName("hint")
                visibility_hint_online.setWordWrap(True)
                visibility_v.addWidget(visibility_hint_online)

                visibility_hint_app = QtWidgets.QLabel(tr("hint_contacts_visibility_app"))
                visibility_hint_app.setObjectName("hint")
                visibility_hint_app.setWordWrap(True)
                visibility_v.addWidget(visibility_hint_app)

                visibility_hint_device = QtWidgets.QLabel(tr("hint_contacts_visibility_device"))
                visibility_hint_device.setObjectName("hint")
                visibility_hint_device.setWordWrap(True)
                visibility_v.addWidget(visibility_hint_device)

                contacts_root.addWidget(visibility_group)

                status_title = QtWidgets.QLabel(tr("contacts_status_legend_title"))
                status_title.setObjectName("muted")
                status_title.setStyleSheet("font-weight:600;")
                status_title.setContentsMargins(6, 8, 0, 0)
                contacts_root.addWidget(status_title)

                status_group = QtWidgets.QGroupBox("")
                status_v = QtWidgets.QVBoxLayout(status_group)
                def _status_hint_label(text: str, color: Optional[str] = None, empty: bool = False) -> QtWidgets.QLabel:
                    lbl = QtWidgets.QLabel()
                    lbl.setObjectName("hint")
                    lbl.setWordWrap(True)
                    if color:
                        mark = "□" if empty else "■"
                        lbl.setTextFormat(QtCore.Qt.RichText)
                        lbl.setText(f"<span style='color:{color};font-weight:700;'>{mark}</span> {text}")
                    else:
                        lbl.setText(text)
                    return lbl

                status_hint_green = _status_hint_label(tr("hint_status_green"), "#2bbf66")
                status_v.addWidget(status_hint_green)
                status_hint_blue = _status_hint_label(tr("hint_status_blue"), "#1f6b3f")
                status_v.addWidget(status_hint_blue)
                status_hint_yellow = _status_hint_label(tr("hint_status_yellow"), "#d9b233")
                status_v.addWidget(status_hint_yellow)
                status_hint_orange = _status_hint_label(tr("hint_status_orange"), "#8f6f18")
                status_v.addWidget(status_hint_orange)
                status_hint_none = _status_hint_label(tr("hint_status_none"), "#8a7f8b", empty=True)
                status_v.addWidget(status_hint_none)
                contacts_root.addWidget(status_group)
                contacts_root.addStretch(1)

                # -------------------
                # Theme tab
                # -------------------
                tab_theme = QtWidgets.QWidget()
                tabs.addTab(tab_theme, tr("tab_theme"))
                theme_root = QtWidgets.QVBoxLayout(tab_theme)
                theme_root.setContentsMargins(14, 12, 14, 10)
                theme_root.setSpacing(12)

                theme_title = QtWidgets.QLabel(tr("theme_title"))
                theme_title.setObjectName("muted")
                theme_title.setStyleSheet("font-weight:600;")
                theme_title.setContentsMargins(6, 8, 0, 0)
                theme_root.addWidget(theme_title)

                theme_group = QtWidgets.QGroupBox("")
                theme_layout = QtWidgets.QFormLayout(theme_group)
                theme_layout.setLabelAlignment(QtCore.Qt.AlignLeft)
                theme_layout.setFormAlignment(QtCore.Qt.AlignTop)
                theme_layout.setVerticalSpacing(8)
                theme_layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.FieldsStayAtSizeHint)
                try:
                    theme_layout.setContentsMargins(10, 10, 10, 10)
                except Exception:
                    pass

                theme_combo = QtWidgets.QComboBox()
                theme_combo.addItem(tr("theme_ubuntu_style"), "ubuntu_style")
                theme_combo.addItem(tr("theme_brutal_man"), "brutal_man")
                try:
                    idx = theme_combo.findData(current_theme)
                    theme_combo.setCurrentIndex(idx if idx >= 0 else 0)
                except Exception:
                    pass
                compact_field(theme_combo, width=320)
                theme_layout.addRow(tr("theme_select"), theme_combo)
                theme_hint = QtWidgets.QLabel(tr("theme_hint"))
                theme_hint.setObjectName("hint")
                theme_hint.setWordWrap(True)
                theme_layout.addRow("", theme_hint)

                theme_root.addWidget(theme_group)
                theme_root.addStretch(1)

                # -------------------
                # Security tab
                # -------------------
                tab_sec = QtWidgets.QWidget()
                tabs.addTab(tab_sec, tr("tab_security"))
                sec_root = QtWidgets.QVBoxLayout(tab_sec)
                sec_root.setContentsMargins(14, 12, 14, 10)
                sec_root.setSpacing(12)

                sec_title = QtWidgets.QLabel(tr("security"))
                sec_title.setObjectName("muted")
                sec_title.setStyleSheet("font-weight:600;")
                sec_title.setContentsMargins(6, 8, 0, 0)
                sec_root.addWidget(sec_title)

                sec_group = QtWidgets.QGroupBox("")
                sec_layout = QtWidgets.QFormLayout(sec_group)
                sec_layout.setLabelAlignment(QtCore.Qt.AlignLeft)
                sec_layout.setFormAlignment(QtCore.Qt.AlignTop)
                sec_layout.setVerticalSpacing(8)
                sec_layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.FieldsStayAtSizeHint)
                try:
                    sec_layout.setContentsMargins(10, 10, 10, 10)
                except Exception:
                    pass

                sec_policy = QtWidgets.QComboBox()
                sec_policy.addItem(tr("security_policy_auto"), "auto")
                sec_policy.addItem(tr("security_policy_strict"), "strict")
                sec_policy.addItem(tr("security_policy_always"), "always")
                try:
                    idx = sec_policy.findData(security_policy)
                    sec_policy.setCurrentIndex(idx if idx >= 0 else 0)
                except Exception:
                    pass
                compact_field(sec_policy, width=320)
                sec_policy_label = QtWidgets.QLabel(tr("security_policy"))
                sec_policy_label.setWordWrap(True)
                sec_layout.addRow(sec_policy_label, sec_policy)
                sec_policy_hint = QtWidgets.QLabel(tr("security_auto_hint"))
                sec_policy_hint.setObjectName("hint")
                sec_policy_hint.setWordWrap(True)
                sec_layout.addRow("", sec_policy_hint)

                sec_crypto_hint = QtWidgets.QLabel(tr("security_crypto_summary"))
                sec_crypto_hint.setObjectName("hint")
                sec_crypto_hint.setWordWrap(True)
                sec_layout.addRow("", sec_crypto_hint)

                cb_rekey = QtWidgets.QCheckBox(tr("session_rekey"))
                cb_rekey.setChecked(bool(session_rekey_enabled))
                cb_rekey.setToolTip(tr("session_rekey_hint"))
                sec_layout.addRow("", cb_rekey)
                cb_rekey_hint = QtWidgets.QLabel(tr("session_rekey_hint"))
                cb_rekey_hint.setObjectName("hint")
                cb_rekey_hint.setWordWrap(True)
                sec_layout.addRow("", cb_rekey_hint)

                sec_root.addWidget(sec_group)

                # Place the "Full reset" button centered, but not at the very bottom.
                sec_root.addSpacing(10)
                danger_row = QtWidgets.QHBoxLayout()
                danger_row.setContentsMargins(0, 8, 0, 0)
                danger_row.addStretch(1)
                btn_full_reset = QtWidgets.QPushButton(tr("full_reset"))
                try:
                    btn_full_reset.setFixedWidth(220)
                except Exception:
                    pass
                btn_full_reset.setStyleSheet(
                    "QPushButton { background:#8f1d1d; border:1px solid #c85a5a; color:#ffecec; font-weight:600; }"
                    "QPushButton:hover { background:#a82424; }"
                )
                danger_row.addWidget(btn_full_reset)
                danger_row.addStretch(1)
                sec_root.addLayout(danger_row)
                sec_root.addStretch(1)

                # -------------------
                # Compression tab
                # -------------------
                tab_cmp = QtWidgets.QWidget()
                tabs.addTab(tab_cmp, tr("tab_compression"))
                cmp_root = QtWidgets.QVBoxLayout(tab_cmp)
                cmp_root.setContentsMargins(14, 12, 14, 10)
                cmp_root.setSpacing(12)

                cmp_title = QtWidgets.QLabel(tr("compression_title"))
                cmp_title.setObjectName("muted")
                cmp_title.setStyleSheet("font-weight:600;")
                cmp_title.setContentsMargins(6, 8, 0, 0)
                cmp_root.addWidget(cmp_title)

                cmp_group = QtWidgets.QGroupBox("")
                cmp_layout = QtWidgets.QFormLayout(cmp_group)
                cmp_layout.setLabelAlignment(QtCore.Qt.AlignLeft)
                cmp_layout.setFormAlignment(QtCore.Qt.AlignTop)
                cmp_layout.setVerticalSpacing(8)
                cmp_layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.FieldsStayAtSizeHint)
                try:
                    cmp_layout.setContentsMargins(10, 10, 10, 10)
                except Exception:
                    pass

                compression_policy = str(cfg.get("compression_policy", "auto") or "auto").strip().lower()
                compression_force_mode = int(cfg.get("compression_force_mode", int(MODE_DEFLATE)) or int(MODE_DEFLATE))
                compression_normalize = str(cfg.get("compression_normalize", "auto") or "auto").strip().lower()
                cmp_norm = QtWidgets.QComboBox()
                cmp_norm.addItem(tr("compression_normalize_auto"), "auto")
                cmp_norm.addItem(tr("compression_normalize_off"), "off")
                cmp_norm.addItem(tr("compression_normalize_tokens"), "tokens")
                cmp_norm.addItem(tr("compression_normalize_sp_vocab"), "sp_vocab")
                try:
                    idx = cmp_norm.findData(compression_normalize)
                    cmp_norm.setCurrentIndex(idx if idx >= 0 else 0)
                except Exception:
                    pass
                compact_field(cmp_norm, width=320)
                cmp_layout.addRow(tr("compression_normalize"), cmp_norm)
                norm_hint = QtWidgets.QLabel(tr("compression_normalize_hint"))
                norm_hint.setObjectName("hint")
                norm_hint.setWordWrap(True)
                cmp_layout.addRow("", norm_hint)

                # Single dropdown: AUTO/OFF or pick an algorithm directly (force).
                cmp_choice = QtWidgets.QComboBox()
                cmp_choice.addItem(tr("compression_policy_auto"), "auto")
                cmp_choice.addItem(tr("compression_policy_off"), "off")
                cmp_choice.addItem("BYTE_DICT", int(MODE_BYTE_DICT))
                cmp_choice.addItem("FIXED_BITS", int(MODE_FIXED_BITS))
                cmp_choice.addItem("DEFLATE", int(MODE_DEFLATE))
                cmp_choice.addItem("ZLIB", int(MODE_ZLIB))
                cmp_choice.addItem("BZ2", int(MODE_BZ2))
                cmp_choice.addItem("LZMA", int(MODE_LZMA))
                # ZSTD: required dependency, but keep disabled if import failed (broken install).
                cmp_choice.addItem("ZSTD", int(MODE_ZSTD))
                try:
                    model = cmp_choice.model()
                    if model is not None:
                        item = model.item(cmp_choice.count() - 1)
                        if item is not None and not _ZSTD_AVAILABLE:
                            item.setEnabled(False)
                except Exception:
                    pass

                # Apply stored policy/mode into the single dropdown.
                try:
                    if compression_policy == "off":
                        idx = cmp_choice.findData("off")
                    elif compression_policy == "force":
                        idx = cmp_choice.findData(int(compression_force_mode))
                    else:
                        idx = cmp_choice.findData("auto")
                    cmp_choice.setCurrentIndex(idx if idx >= 0 else 0)
                except Exception:
                    pass
                compact_field(cmp_choice, width=320)
                cmp_layout.addRow(tr("compression_policy"), cmp_choice)
                force_hint = QtWidgets.QLabel(tr("compression_force_hint"))
                force_hint.setObjectName("hint")
                force_hint.setWordWrap(True)
                cmp_layout.addRow("", force_hint)

                cmp_root.addWidget(cmp_group)
                cmp_root.addStretch(1)

                # -------------------
                # Log tab
                # -------------------
                tab_log = QtWidgets.QWidget()
                tabs.addTab(tab_log, tr("tab_log"))
                tab_log_l = QtWidgets.QVBoxLayout(tab_log)
                tab_log_l.setContentsMargins(14, 12, 14, 10)
                tab_log_l.setSpacing(10)

                # Log settings (moved from General tab).
                cb_verbose = QtWidgets.QCheckBox(tr("verbose_events"))
                cb_verbose.setChecked(verbose_log)
                tab_log_l.addWidget(cb_verbose)
                verbose_hint = QtWidgets.QLabel(tr("hint_verbose"))
                verbose_hint.setObjectName("hint")
                verbose_hint.setWordWrap(True)
                tab_log_l.addWidget(verbose_hint)

                cb_runtime_log = QtWidgets.QCheckBox(tr("runtime_log_file"))
                cb_runtime_log.setChecked(runtime_log_file)
                tab_log_l.addWidget(cb_runtime_log)
                runtime_log_hint = QtWidgets.QLabel(tr("hint_runtime_log_file"))
                runtime_log_hint.setObjectName("hint")
                runtime_log_hint.setWordWrap(True)
                tab_log_l.addWidget(runtime_log_hint)

                try:
                    sep = QtWidgets.QFrame()
                    sep.setFrameShape(QtWidgets.QFrame.HLine)
                    sep.setFrameShadow(QtWidgets.QFrame.Sunken)
                    tab_log_l.addWidget(sep)
                except Exception:
                    pass

                log_view = QtWidgets.QTextEdit()
                log_view.setReadOnly(True)
                set_mono(log_view, 10)
                try:
                    log_view.installEventFilter(_no_ctrl_zoom)
                    log_view.viewport().installEventFilter(_no_ctrl_zoom)
                except Exception:
                    pass
                tab_log_l.addWidget(log_view, 1)
                nonlocal settings_log_view
                settings_log_view = log_view

                copy_row = QtWidgets.QHBoxLayout()
                copy_row.setContentsMargins(0, 0, 0, 0)
                copy_row.addStretch(1)
                btn_ack = QtWidgets.QPushButton(tr("ack_alerts"))
                btn_clear = QtWidgets.QPushButton(tr("clear_log"))
                btn_copy = QtWidgets.QPushButton(tr("copy_log"))
                copy_row.addWidget(btn_ack)
                copy_row.addWidget(btn_clear)
                copy_row.addWidget(btn_copy)
                tab_log_l.addLayout(copy_row)

                # -------------------
                # About tab
                # -------------------
                tab_about = QtWidgets.QWidget()
                tabs.addTab(tab_about, tr("tab_about"))
                about_l = QtWidgets.QVBoxLayout(tab_about)
                about_l.setContentsMargins(14, 12, 14, 10)
                about_l.setSpacing(10)

                author_label = QtWidgets.QLabel(
                    f"meshTalk v{VERSION}\n"
                    f"{tr('about_author')}: Anton Vologzhanin\n"
                    f"{tr('about_callsign')}: R3VAF\n"
                    f"{tr('about_telegram')}: @peerat33\n"
                    f"{tr('about_vision')}\n"
                    f"{tr('about_author_position')}\n"
                    f"{tr('about_disclaimer')}"
                )
                set_mono(author_label, 10)
                author_label.setObjectName("muted")
                author_label.setWordWrap(True)
                about_l.addWidget(author_label)
                about_l.addStretch(1)

                # Custom bottom buttons to enforce consistent order and styling:
                # OK, Cancel, Apply (left-to-right), without theme icons.
                btn_row = QtWidgets.QHBoxLayout()
                btn_row.setContentsMargins(0, 0, 0, 0)
                btn_row.addStretch(1)

                if current_lang == "en":
                    ok_text, cancel_text, apply_text = ("OK", "Cancel", "Apply")
                else:
                    ok_text, cancel_text, apply_text = ("ОК", "Отмена", "Применить")
                btn_ok = QtWidgets.QPushButton(ok_text)
                btn_cancel = QtWidgets.QPushButton(cancel_text)
                btn_apply = QtWidgets.QPushButton(apply_text)
                try:
                    btn_ok.setIcon(QtGui.QIcon())
                    btn_cancel.setIcon(QtGui.QIcon())
                    btn_apply.setIcon(QtGui.QIcon())
                except Exception:
                    pass

                btn_ok.setStyleSheet(
                    "QPushButton { background:#1f6f3a; border:1px solid #2fa760; color:#eafff1; font-weight:600; }"
                    "QPushButton:hover { background:#238042; }"
                    "QPushButton:pressed { background:#1a5f32; }"
                )
                btn_apply.setStyleSheet(
                    "QPushButton { background:#1f6f3a; border:1px solid #2fa760; color:#eafff1; font-weight:600; }"
                    "QPushButton:hover { background:#238042; }"
                    "QPushButton:pressed { background:#1a5f32; }"
                )
                btn_cancel.setStyleSheet(
                    "QPushButton { background:#8f1d1d; border:1px solid #c85a5a; color:#ffecec; font-weight:600; }"
                    "QPushButton:hover { background:#a82424; }"
                    "QPushButton:pressed { background:#7b1818; }"
                )

                btn_row.addWidget(btn_ok)
                btn_row.addWidget(btn_cancel)
                btn_row.addWidget(btn_apply)
                layout.addLayout(btn_row)

                for text, level in log_buffer[-500:]:
                    log_append_view(log_view, text, level)

                def parse_int_field(edit: QtWidgets.QLineEdit, default: int) -> int:
                    try:
                        raw = edit.text().strip()
                        return int(raw) if raw else int(default)
                    except Exception:
                        return int(default)

                def apply_settings(close_dialog: bool) -> None:
                    nonlocal verbose_log, runtime_log_file, auto_pacing, discovery_send, discovery_reply, clear_pending_on_switch
                    nonlocal contacts_visibility
                    nonlocal security_policy, session_rekey_enabled
                    nonlocal max_plain, current_lang, last_limits_logged, current_theme
                    verbose_log = cb_verbose.isChecked()
                    runtime_log_file = cb_runtime_log.isChecked()
                    auto_pacing = cb_auto_pacing.isChecked()
                    _STORAGE.set_runtime_log_enabled(runtime_log_file)
                    prev_send = discovery_send
                    discovery_send = cb_discovery_send.isChecked()
                    discovery_reply = cb_discovery_reply.isChecked()
                    clear_pending_on_switch = cb_clear_pending.isChecked()

                    prev_lang = current_lang
                    next_lang = "ru" if rb_ru.isChecked() else "en"
                    cfg["lang"] = next_lang
                    if prev_lang != next_lang:
                        set_language(next_lang, persist=False)
                    else:
                        current_lang = next_lang

                    # Port is auto-detected.
                    cfg["port"] = "auto"
                    cfg["retry_seconds"] = parse_int_field(retry_edit, 30)
                    cfg["max_seconds"] = parse_int_field(maxsec_edit, 3600)
                    cfg["max_bytes"] = parse_int_field(maxbytes_edit, 200)
                    cfg["rate_seconds"] = parse_int_field(rate_edit, 30)
                    cfg["parallel_sends"] = max(1, parse_int_field(parallel_edit, 1))
                    cfg["auto_pacing"] = bool(auto_pacing)
                    cfg["discovery_enabled"] = bool(discovery_send and discovery_reply)
                    cfg["discovery_send"] = discovery_send
                    cfg["discovery_reply"] = discovery_reply
                    cfg["runtime_log_file"] = runtime_log_file
                    cfg["clear_pending_on_switch"] = clear_pending_on_switch
                    contacts_visibility = str(contacts_visibility_combo.currentData() or "all").strip().lower()
                    if contacts_visibility not in ("all", "online", "app", "device"):
                        contacts_visibility = "all"
                    cfg["contacts_visibility"] = contacts_visibility

                    # Theme settings
                    next_theme = str(theme_combo.currentData() or "ubuntu_style").strip().lower()
                    if next_theme not in THEME_STYLES:
                        next_theme = "ubuntu_style"
                    cfg["ui_theme"] = next_theme
                    if next_theme != current_theme:
                        apply_theme(next_theme)

                    # Compression settings
                    choice = cmp_choice.currentData()
                    if choice == "off":
                        cfg["compression_policy"] = "off"
                    elif choice == "auto":
                        cfg["compression_policy"] = "auto"
                    else:
                        cfg["compression_policy"] = "force"
                        try:
                            cfg["compression_force_mode"] = int(choice)
                        except Exception:
                            cfg["compression_force_mode"] = int(MODE_DEFLATE)
                    cfg["compression_normalize"] = str(cmp_norm.currentData() or "auto").strip().lower()
                    # ZSTD is a required dependency; keep no per-user toggle.

                    # Apply numeric settings immediately.
                    try:
                        args.retry_seconds = int(cfg["retry_seconds"])
                        args.max_seconds = int(cfg["max_seconds"])
                        args.max_bytes = int(cfg["max_bytes"])
                        args.rate_seconds = int(cfg["rate_seconds"])
                        args.parallel_sends = int(cfg["parallel_sends"])
                    except Exception:
                        pass
                    try:
                        max_plain = max(0, int(getattr(args, "max_bytes", 200) or 200) - int(PAYLOAD_OVERHEAD))
                    except Exception:
                        pass

                    security_policy = str(sec_policy.currentData() or "auto").strip().lower()
                    if security_policy not in ("auto", "strict", "always"):
                        security_policy = "auto"
                    cfg["security_key_rotation_policy"] = security_policy
                    session_rekey_enabled = bool(cb_rekey.isChecked())
                    cfg["session_rekey"] = bool(session_rekey_enabled)
                    try:
                        args.auto_pacing = bool(auto_pacing)
                    except Exception:
                        pass

                    # One diagnostic line when auto pacing is toggled (avoid spam).
                    try:
                        prev_auto = bool(getattr(args, "_prev_auto_pacing", auto_pacing))
                        setattr(args, "_prev_auto_pacing", bool(auto_pacing))
                        if bool(prev_auto) != bool(auto_pacing):
                            state = "enabled" if auto_pacing else "disabled"
                            log_line(
                                f"{ts_local()} PACE: {state} rate={int(getattr(args, 'rate_seconds', 30) or 30)}s "
                                f"parallel={int(getattr(args, 'parallel_sends', 1) or 1)}",
                                "pace",
                            )
                    except Exception:
                        pass

                    # Confirm runtime application of limits in the log.
                    try:
                        limits_now = (
                            int(getattr(args, "max_bytes", 200) or 200),
                            int(max_plain),
                            int(getattr(args, "retry_seconds", 30) or 30),
                            int(getattr(args, "max_seconds", 3600) or 3600),
                        )
                        if limits_now != last_limits_logged:
                            log_line(
                                f"{ts_local()} LIMITS: max_bytes={limits_now[0]} "
                                f"max_plain={limits_now[1]} retry={limits_now[2]}s max={limits_now[3]}s",
                                "info",
                            )
                            last_limits_logged = limits_now
                    except Exception:
                        pass

                    save_gui_config()
                    refresh_list()
                    if discovery_send and not prev_send:
                        reset_discovery_schedule()
                        ui_emit("log", f"{ts_local()} DISCOVERY: enabled (burst)")

                    if close_dialog:
                        dlg.accept()
                        return
                    if prev_lang != next_lang:
                        reopen["flag"] = True
                        dlg.accept()
                        return

                def on_accept():
                    apply_settings(close_dialog=True)

                def on_apply():
                    apply_settings(close_dialog=False)

                def on_copy():
                    try:
                        text = log_view.toPlainText().strip()
                        if not text:
                            text = "\n".join(t for t, _lvl in log_buffer)
                        cb = QtWidgets.QApplication.clipboard()
                        if cb is None:
                            return
                        cb.setText(text)
                        try:
                            cb.setText(text, QtGui.QClipboard.Mode.Clipboard)
                        except Exception:
                            pass
                        try:
                            cb.setText(text, QtGui.QClipboard.Mode.Selection)
                        except Exception:
                            pass
                    except Exception:
                        pass

                def on_clear():
                    try:
                        log_buffer.clear()
                        if settings_log_view is not None:
                            settings_log_view.clear()
                        _STORAGE.clear_runtime_log()
                    except Exception:
                        pass

                def on_ack_alerts():
                    nonlocal unseen_error_count, unseen_warn_count, last_error_summary, last_warn_summary, errors_need_ack
                    unseen_error_count = 0
                    unseen_warn_count = 0
                    last_error_summary = ""
                    last_warn_summary = ""
                    errors_need_ack = False
                    update_status()

                def on_full_reset():
                    nonlocal current_lang, verbose_log, runtime_log_file
                    nonlocal discovery_send, discovery_reply, clear_pending_on_switch
                    if not self_id or not priv_path or not pub_path:
                        QtWidgets.QMessageBox.information(win, "meshTalk", tr("full_reset_unavailable"))
                        return
                    name = norm_id_for_wire(self_id)
                    reply = QtWidgets.QMessageBox.warning(
                        win,
                        "meshTalk",
                        tr("full_reset_confirm").format(name=name),
                        QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                        QtWidgets.QMessageBox.No,
                    )
                    if reply != QtWidgets.QMessageBox.Yes:
                        return
                    import shutil

                    # Clear in-memory profile state first so UI immediately reflects reset.
                    with pending_lock:
                        pending_by_peer.clear()
                    incoming_state.clear()
                    with seen_lock:
                        seen_msgs.clear()
                        seen_parts.clear()
                    key_response_last_ts.clear()
                    key_conflict_ignored.clear()
                    key_conflict_hidden_log_ts.clear()
                    tracked_peers.clear()
                    known_peers.clear()
                    peer_states.clear()
                    with peer_names_lock:
                        peer_names.clear()
                    dialogs.clear()
                    chat_history.clear()
                    list_index.clear()
                    groups.clear()
                    pinned_dialogs.clear()
                    hidden_contacts.clear()
                    cfg.clear()
                    log_buffer.clear()
                    if settings_log_view is not None:
                        settings_log_view.clear()

                    # Delete persisted profile files.
                    for path in (CONFIG_FILE, STATE_FILE, HISTORY_FILE, INCOMING_FILE, RUNTIME_LOG_FILE):
                        try:
                            if os.path.isfile(path):
                                os.remove(path)
                        except Exception:
                            pass
                    try:
                        if os.path.isdir(keydir):
                            shutil.rmtree(keydir, ignore_errors=True)
                    except Exception:
                        pass
                    try:
                        os.makedirs(keydir, exist_ok=True)
                    except Exception:
                        pass

                    # New storage key for history/state at rest.
                    _STORAGE.set_paths(
                        config_file=CONFIG_FILE,
                        state_file=STATE_FILE,
                        history_file=HISTORY_FILE,
                        incoming_file=INCOMING_FILE,
                        runtime_log_file=RUNTIME_LOG_FILE,
                        keydir=keydir,
                    )
                    ensure_storage_key()

                    # Reset runtime options to defaults.
                    current_lang = "ru"
                    verbose_log = True
                    runtime_log_file = True
                    auto_pacing = True
                    discovery_send = True
                    discovery_reply = True
                    clear_pending_on_switch = True
                    contacts_visibility = "all"
                    _STORAGE.set_runtime_log_enabled(runtime_log_file)
                    try:
                        args.retry_seconds = 30
                        args.max_seconds = 3600
                        args.max_bytes = 200
                        args.rate_seconds = 30
                        args.parallel_sends = 1
                        args.auto_pacing = True
                    except Exception:
                        pass

                    regenerate_keys()
                    try:
                        search_field.clear()
                        msg_entry.clear()
                        chat_text.clear()
                        items_list.clear()
                    except Exception:
                        pass
                    apply_language()
                    select_dialog(None)
                    refresh_list()
                    if discovery_send:
                        try:
                            reset_discovery_schedule()
                            send_discovery_broadcast()
                            log_line(f"{ts_local()} DISCOVERY: enabled (after reset)", "info")
                        except Exception:
                            pass
                    log_line(f"{ts_local()} RESET: full profile reset completed", "warn")
                    QtWidgets.QMessageBox.information(win, "meshTalk", tr("full_reset_done"))
                    dlg.accept()

                btn_ok.clicked.connect(on_accept)
                btn_cancel.clicked.connect(dlg.reject)
                btn_apply.clicked.connect(on_apply)
                btn_ack.clicked.connect(on_ack_alerts)
                btn_copy.clicked.connect(on_copy)
                btn_clear.clicked.connect(on_clear)
                btn_full_reset.clicked.connect(on_full_reset)

                def _close_inplace_settings(*_args):
                    nonlocal settings_panel_widget
                    nonlocal settings_log_view, settings_rate_edit, settings_parallel_edit, settings_auto_pacing_cb
                    settings_log_view = None
                    settings_rate_edit = None
                    settings_parallel_edit = None
                    settings_auto_pacing_cb = None
                    try:
                        right_col.removeWidget(dlg)
                    except Exception:
                        pass
                    try:
                        dlg.hide()
                        dlg.deleteLater()
                    except Exception:
                        pass
                    settings_panel_widget = None
                    try:
                        list_group.show()
                        header_bar.show()
                        root_layout.setStretch(0, 1)
                        root_layout.setStretch(1, 2)
                        chat_text.show()
                        msg_entry.show()
                        send_btn.show()
                    except Exception:
                        pass
                    if reopen["flag"]:
                        reopen["flag"] = False
                        QtCore.QTimer.singleShot(0, open_settings)

                try:
                    dlg.finished.connect(_close_inplace_settings)
                except Exception:
                    pass

                settings_panel_widget = dlg
                try:
                    list_group.hide()
                    header_bar.hide()
                    root_layout.setStretch(0, 0)
                    root_layout.setStretch(1, 1)
                    chat_text.hide()
                    msg_entry.hide()
                    send_btn.hide()
                except Exception:
                    pass
                right_col.insertWidget(1, dlg, 1)
                dlg.show()
                return

        settings_btn.clicked.connect(open_settings)
        def _toggle_alert_overlay() -> None:
            if not current_alert_level:
                return
            if alert_overlay_visible:
                _hide_alert_overlay()
            else:
                _show_alert_overlay()

        alert_btn.clicked.connect(_toggle_alert_overlay)
        click_state = {"last_ts": 0.0, "count": 0}

        def _header_text_left_x(text: str) -> float:
            rect = chat_label.contentsRect()
            fm = QtGui.QFontMetrics(chat_label.font())
            text_w = float(fm.horizontalAdvance(text))
            align = int(chat_label.alignment())
            if align & int(QtCore.Qt.AlignRight):
                return float(rect.right()) - text_w + 1.0
            if align & int(QtCore.Qt.AlignHCenter):
                return float(rect.left()) + max(0.0, (float(rect.width()) - text_w) * 0.5)
            return float(rect.left())

        def _chat_label_click(e):
            if e.button() != QtCore.Qt.LeftButton:
                return
            text = chat_label.text()
            pub_idx = text.find("public key ")
            if pub_idx < 0:
                pub_idx = text.find("pubkey ")
            if pub_idx < 0:
                pub_idx = text.find("pub:")
            if pub_idx >= 0:
                fm = QtGui.QFontMetrics(chat_label.font())
                left_text = text[:pub_idx]
                left_boundary_x = _header_text_left_x(text) + float(fm.horizontalAdvance(left_text))
                if float(e.position().x()) < left_boundary_x:
                    copy_client_id()
                    return
                now = time.time()
                if (now - click_state["last_ts"]) <= 0.6:
                    click_state["count"] += 1
                else:
                    click_state["count"] = 1
                click_state["last_ts"] = now
                if click_state["count"] >= 3:
                    click_state["count"] = 0
                    reply = QtWidgets.QMessageBox.question(
                        win,
                        "meshTalk",
                        "Regenerate your keys and broadcast update?",
                        QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                    )
                    if reply == QtWidgets.QMessageBox.Yes:
                        regenerate_keys()
                        send_discovery_broadcast()
                return
            copy_client_id()
        chat_label.mousePressEvent = _chat_label_click

        def html_escape(s: str) -> str:
            # Chat entries can contain multi-line text (Shift+Enter, traceroute output).
            # Preserve line breaks when rendering HTML.
            return (
                s.replace("&", "&amp;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;")
                 .replace("\r\n", "\n")
                 .replace("\r", "\n")
                 .replace("\n", "<br>")
            )

        def make_avatar_pixmap(seed: str, size: int) -> QtGui.QPixmap:
            # Use the same deterministic logo generator everywhere (list + dialogs).
            return _peer_logo_pixmap(seed, size)

        def avatar_base_color(seed: str) -> str:
            palette = [
                "#ff6b6b", "#ffa94d", "#ffd43b", "#a9e34b",
                "#4cd4b0", "#38d9a9", "#63e6be", "#4dabf7",
                "#74c0fc", "#9775fa", "#b197fc", "#f783ac",
                "#ff8787", "#ffc078", "#8ce99a", "#5c7cfa",
            ]
            h = hashlib.sha256(seed.encode("utf-8")).digest()
            idx0 = h[0] % len(palette)
            return palette[idx0]

        def mix_hex(a: str, b: str, t: float) -> str:
            a = a.lstrip("#")
            b = b.lstrip("#")
            ar, ag, ab = int(a[0:2], 16), int(a[2:4], 16), int(a[4:6], 16)
            br, bg, bb = int(b[0:2], 16), int(b[2:4], 16), int(b[4:6], 16)
            r = int(ar + (br - ar) * t)
            g = int(ag + (bg - ag) * t)
            bl = int(ab + (bb - ab) * t)
            return "#{:02x}{:02x}{:02x}".format(r, g, bl)

        def color_pair_for_id(seed: str) -> Tuple[str, str]:
            base_bg = "#35102a"  # dialog background
            accent = avatar_base_color(seed)
            # Contact list cards: deliberately muted tint.
            bg_hex = mix_hex(base_bg, accent, 0.05)
            tx_hex = mix_hex("#e8e0e8", accent, 0.16)
            return (bg_hex, tx_hex)

        def color_pair_for_message(seed: str) -> Tuple[str, str]:
            base_bg = "#35102a"
            accent = avatar_base_color(seed)
            bg_hex = mix_hex(base_bg, accent, 0.12)
            tx_hex = mix_hex("#eeeeec", accent, 0.35)
            return (bg_hex, tx_hex)

        avatar_cache: Dict[Tuple[str, int], str] = {}

        def avatar_data_uri(seed: str, size: int) -> str:
            key = (seed, size)
            cached = avatar_cache.get(key)
            if cached:
                return cached
            pm = make_avatar_pixmap(seed, size)
            ba = QtCore.QByteArray()
            buf = QtCore.QBuffer(ba)
            buf.open(QtCore.QIODevice.WriteOnly)
            pm.save(buf, "PNG")
            data = bytes(ba.toBase64()).decode("ascii")
            uri = f"data:image/png;base64,{data}"
            avatar_cache[key] = uri
            return uri

        def append_html(view: QtWidgets.QListWidget, text: str, color: str) -> None:
            row_wrap = QtWidgets.QWidget()
            row_wrap.setStyleSheet("background: transparent; border: none;")
            row_l = QtWidgets.QHBoxLayout(row_wrap)
            row_l.setContentsMargins(4, 1, 4, 1)
            row_l.setSpacing(0)
            lbl = QtWidgets.QLabel(str(text))
            lbl.setWordWrap(True)
            lbl.setStyleSheet(f"color:{color};")
            row_l.addWidget(lbl, 1)
            row_wrap.setMinimumWidth(max(100, int(view.viewport().width()) - 4))
            item = QtWidgets.QListWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)
            item.setData(QtCore.Qt.UserRole, -1)
            item.setSizeHint(QtCore.QSize(max(100, int(view.viewport().width()) - 4), row_wrap.sizeHint().height()))
            view.addItem(item)
            view.setItemWidget(item, row_wrap)

        def append_chat_entry(
            view: QtWidgets.QListWidget,
            text: str,
            peer_id: str,
            outgoing: bool,
            row_index: int,
            meta: str = "",
            actions: Optional[List[Dict[str, str]]] = None,
        ) -> None:
            del actions  # Action buttons are handled in header/context flow.
            bg, tx = color_pair_for_message(peer_id)
            if " " in text and len(text) >= 6:
                ts = text[:5]
                msg = text[6:]
            else:
                ts = ""
                msg = text
            if meta:
                meta_l = meta.lower().strip()
                if (
                    meta_l.startswith("отправлена в ")
                    or meta_l.startswith("отправлено в ")
                    or meta_l.startswith("доставлено в ")
                    or meta_l.startswith("получено в ")
                    or meta_l.startswith("sent at ")
                    or meta_l.startswith("delivered at ")
                    or meta_l.startswith("received at ")
                    or bool(re.match(r"^в\s+\d{2}:\d{2}\b", meta_l))
                ):
                    combined = meta
                else:
                    combined = f"{ts} {meta}".strip()
            else:
                combined = ts
            combined_l = combined.lower()
            pending = (
                ("in progress" in combined_l)
                or ("receiving" in combined_l)
                or ("в процессе" in combined_l)
                or ("получение" in combined_l)
                or ("sent and" in combined_l)
                or ("отправлено и" in combined_l)
                or ("elapsed " in combined_l)
                or ("прошло " in combined_l)
            )
            failed = (("failed (" in combined_l) or ("ошибка (" in combined_l))
            ts_color = "#ff5a5f" if failed else ("#ff9800" if pending else "#8a7f8b")
            tag = short_tag(peer_id)

            row_wrap = QtWidgets.QWidget()
            row_wrap.setStyleSheet("background: transparent; border: none;")
            row_l = QtWidgets.QHBoxLayout(row_wrap)
            row_l.setContentsMargins(4, 1, 4, 1)
            row_l.setSpacing(0)
            if outgoing:
                row_l.addStretch(1)

            bubble = QtWidgets.QFrame()
            bubble.setObjectName("chatBubble")
            bubble.setProperty("peer_id", str(peer_id))
            bubble.setStyleSheet(
                f"QFrame#chatBubble {{ background:{bg}; border:1px solid rgba(255,255,255,0.10); border-radius:9px; }}"
            )
            bubble_l = QtWidgets.QVBoxLayout(bubble)
            bubble_l.setContentsMargins(8, 6, 10, 6)
            bubble_l.setSpacing(4)

            top_row = QtWidgets.QHBoxLayout()
            top_row.setContentsMargins(0, 0, 0, 0)
            top_row.setSpacing(6)
            av_col = QtWidgets.QVBoxLayout()
            av_col.setContentsMargins(0, 0, 0, 0)
            av_col.setSpacing(2)
            av = QtWidgets.QLabel()
            av.setFixedSize(42, 42)
            av.setStyleSheet("background: transparent; border: none;")
            av.setAttribute(QtCore.Qt.WA_TranslucentBackground, True)
            av.setAlignment(QtCore.Qt.AlignCenter)
            av.setScaledContents(False)
            av.setPixmap(make_avatar_pixmap(peer_id, 42))
            av_col.addWidget(av, 0, QtCore.Qt.AlignHCenter)
            if tag:
                tag_lbl = QtWidgets.QLabel(tag)
                tag_lbl.setObjectName("chatAvatarTag")
                tag_lbl.setFixedWidth(42)
                tag_lbl.setStyleSheet(f"background: transparent; border: none; color:{tx}; font-size:11px; font-weight:600; padding-top:1px;")
                tag_lbl.setAlignment(QtCore.Qt.AlignHCenter)
                av_col.addWidget(tag_lbl, 0, QtCore.Qt.AlignHCenter)
            else:
                av_col.addSpacing(14)
            top_row.addLayout(av_col, 0)

            msg_lbl = QtWidgets.QLabel(msg)
            msg_lbl.setObjectName("chatMessage")
            msg_lbl.setWordWrap(True)
            msg_lbl.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
            msg_lbl.setStyleSheet(f"background: transparent; border: none; color:{tx};")
            msg_lbl.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
            top_row.addWidget(msg_lbl, 1)
            bubble_l.addLayout(top_row, 1)

            meta_lbl = QtWidgets.QLabel(combined)
            meta_lbl.setObjectName("chatMeta")
            meta_lbl.setStyleSheet(f"background: transparent; border: none; color:{ts_color}; font-size:10px;")
            meta_lbl.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
            meta_lbl.setWordWrap(False)
            meta_lbl.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Fixed)
            meta_lbl.setProperty("full_meta", combined)
            bubble_l.addWidget(meta_lbl, 0, QtCore.Qt.AlignRight)

            row_wrap.setMinimumWidth(max(100, int(view.viewport().width()) - 2))
            # Prefer width that fits both message and full delivery-status line.
            max_w = max(360, int(view.viewport().width()) - 12)
            try:
                fm_msg = msg_lbl.fontMetrics()
                msg_lines = [ln for ln in str(msg).splitlines() if ln] or [str(msg)]
                msg_px = max(fm_msg.horizontalAdvance(ln) for ln in msg_lines)
            except Exception:
                msg_px = int(len(msg) * 7)
            try:
                fm_meta = meta_lbl.fontMetrics()
                meta_px = fm_meta.horizontalAdvance(combined)
            except Exception:
                meta_px = int(len(combined) * 6)
            # +70 for avatar column and inner paddings.
            min_visual = max(300, int(view.viewport().width() * 0.70))
            preferred = max(min_visual, int(msg_px + 62), int(meta_px + 10))
            preferred = min(max_w, preferred)
            bubble.setMinimumWidth(min(220, preferred))
            bubble.setMaximumWidth(preferred)
            bubble.setSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Preferred)
            try:
                meta_max = max(90, preferred - 18)
                meta_lbl.setMinimumWidth(meta_max)
                meta_lbl.setMaximumWidth(meta_max)
                fm = meta_lbl.fontMetrics()
                fitted = fm.elidedText(combined, QtCore.Qt.ElideRight, meta_max)
                meta_lbl.setText(fitted)
                if fitted != combined:
                    meta_lbl.setToolTip(combined)
                else:
                    meta_lbl.setToolTip("")
            except Exception:
                pass
            row_l.addWidget(bubble, 0)
            if not outgoing:
                row_l.addStretch(1)

            item = QtWidgets.QListWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)
            item.setData(QtCore.Qt.UserRole, int(row_index))
            try:
                row_wrap.layout().activate()
                row_wrap.adjustSize()
            except Exception:
                pass
            h = max(row_wrap.sizeHint().height(), row_wrap.minimumSizeHint().height()) + 16
            item.setSizeHint(QtCore.QSize(max(100, int(view.viewport().width()) - 4), h))
            view.addItem(item)
            view.setItemWidget(item, row_wrap)
            try:
                view.doItemsLayout()
            except Exception:
                pass
            view.scrollToBottom()

        def relayout_chat_items(view: QtWidgets.QListWidget) -> None:
            try:
                target_w = max(100, int(view.viewport().width()) - 2)
                for i in range(view.count()):
                    item = view.item(i)
                    if item is None:
                        continue
                    w = view.itemWidget(item)
                    if w is not None:
                        try:
                            w.setFixedWidth(target_w)
                        except Exception:
                            pass
                        try:
                            bubble = w.findChild(QtWidgets.QFrame, "chatBubble")
                            if bubble is not None:
                                max_w = max(360, int(view.viewport().width()) - 12)
                                bubble.setMaximumWidth(max_w)
                                meta_lbl = bubble.findChild(QtWidgets.QLabel, "chatMeta")
                                msg_lbl = bubble.findChild(QtWidgets.QLabel, "chatMessage")
                                if meta_lbl is not None:
                                    full_meta = str(meta_lbl.property("full_meta") or meta_lbl.toolTip() or meta_lbl.text() or "")
                                else:
                                    full_meta = ""
                                if msg_lbl is not None and full_meta:
                                    try:
                                        fm_msg = msg_lbl.fontMetrics()
                                        msg_lines = [ln for ln in str(msg_lbl.text()).splitlines() if ln] or [str(msg_lbl.text())]
                                        msg_px = max(fm_msg.horizontalAdvance(ln) for ln in msg_lines)
                                    except Exception:
                                        msg_px = int(len(str(msg_lbl.text())) * 7)
                                    try:
                                        fm_meta = meta_lbl.fontMetrics() if meta_lbl is not None else None
                                        meta_px = fm_meta.horizontalAdvance(full_meta) if fm_meta is not None else int(len(full_meta) * 6)
                                    except Exception:
                                        meta_px = int(len(full_meta) * 6)
                                    min_visual = max(300, int(view.viewport().width() * 0.70))
                                    preferred = min(max_w, max(min_visual, int(msg_px + 62), int(meta_px + 10)))
                                    bubble.setMaximumWidth(preferred)
                                    if meta_lbl is not None:
                                        fm = meta_lbl.fontMetrics()
                                        meta_max = max(90, preferred - 18)
                                        meta_lbl.setMinimumWidth(meta_max)
                                        meta_lbl.setMaximumWidth(meta_max)
                                        fitted = fm.elidedText(full_meta, QtCore.Qt.ElideRight, meta_max)
                                        meta_lbl.setText(fitted)
                                        if fitted != full_meta:
                                            meta_lbl.setToolTip(full_meta)
                                        else:
                                            meta_lbl.setToolTip("")
                        except Exception:
                            pass
                        try:
                            w.layout().activate()
                            w.adjustSize()
                            h = max(w.sizeHint().height(), w.minimumSizeHint().height()) + 16
                            item.setSizeHint(QtCore.QSize(target_w, h))
                        except Exception:
                            pass
            except Exception:
                pass

        def dialog_title(dialog_id: str) -> str:
            if dialog_id.startswith("group:"):
                return f"{dialog_id[6:]}"
            wire = norm_id_for_wire(dialog_id)
            long_name, short_name = _peer_name_parts(dialog_id)
            if long_name or short_name:
                second = long_name
                if short_name:
                    second = f"{second} [{short_name}]" if second else f"[{short_name}]"
                return f"{wire}\n{second}"
            return wire

        def short_tag(peer_id: str) -> str:
            _long_name, short_name = _peer_name_parts(peer_id)
            if short_name:
                return f"{short_name}"
            return ""

        def self_title() -> str:
            if not radio_ready:
                return "Waiting for radio..."
            wire = norm_id_for_wire(self_id)
            long_name, short_name = _peer_name_parts(self_id)
            second = ""
            if long_name or short_name:
                second = long_name
                if short_name:
                    second = f"{second}[{short_name}]" if second else f"[{short_name}]"
            pub_full = b64e(pub_self_raw) if pub_self_raw else "-----"
            pub_mask = f"{pub_full[:5]}****{pub_full[-5:]}" if len(pub_full) > 10 else pub_full
            return f"Client ID: {wire} {second} public key: {pub_mask}".strip()

        def update_dialog(dialog_id: str, text: str, recv: bool = False) -> None:
            rec = dialogs.get(dialog_id) or {}
            rec["last_text"] = text
            rec["last_ts"] = time.time()
            if recv:
                rec["last_rx_ts"] = rec["last_ts"]
            dialogs[dialog_id] = rec

        def render_chat(dialog_id: Optional[str]) -> None:
            chat_text.clear()
            if not dialog_id:
                return

            def as_float(val: object) -> Optional[float]:
                if val is None:
                    return None
                try:
                    return float(val)
                except Exception:
                    return None

            for idx, entry in enumerate(chat_history.get(dialog_id, [])):
                if isinstance(entry, dict):
                    text = str(entry.get("text", ""))
                    direction = str(entry.get("dir", "in"))
                    peer_id = self_id if direction == "out" else dialog_id
                    meta = str(entry.get("meta", "") or "")
                    meta_data = entry.get("meta_data")
                    if isinstance(meta_data, dict):
                        if direction != "out" and dialog_id.startswith("group:"):
                            try:
                                from_peer = norm_id_for_filename(str(meta_data.get("from_peer", "") or ""))
                            except Exception:
                                from_peer = ""
                            if from_peer:
                                peer_id = from_peer
                        if str(meta_data.get("transport", "") or "") == "meshtastic_text":
                            meta = format_plain_transport_meta(
                                incoming=bool(meta_data.get("incoming", direction != "out")),
                                sent_at_ts=as_float(meta_data.get("sent_at_ts")),
                                received_at_ts=as_float(meta_data.get("received_at_ts")),
                            )
                        else:
                            row_hhmm = text[:5] if (len(text) >= 5 and text[2] == ":" and text[5:6] == " ") else None
                            packets = None
                            packets_raw = meta_data.get("packets")
                            if isinstance(packets_raw, (tuple, list)) and len(packets_raw) >= 2:
                                try:
                                    packets = (int(packets_raw[0]), int(packets_raw[1]))
                                except Exception:
                                    packets = None
                            status_raw = meta_data.get("status")
                            status = str(status_raw).strip() if status_raw is not None else ""
                            done_raw = meta_data.get("done")
                            done = bool(done_raw) if done_raw is not None else None
                            meta = format_meta(
                                as_float(meta_data.get("delivery")),
                                as_float(meta_data.get("attempts")),
                                as_float(meta_data.get("forward_hops")),
                                as_float(meta_data.get("ack_hops")),
                                packets,
                                status=status or None,
                                delivered_at_ts=as_float(meta_data.get("delivered_at_ts")),
                                incoming=bool(meta_data.get("incoming", direction != "out")),
                                done=done,
                                row_time_hhmm=row_hhmm,
                                received_at_ts=as_float(meta_data.get("received_at_ts")),
                                sent_at_ts=as_float(meta_data.get("sent_at_ts")),
                                incoming_started_ts=as_float(meta_data.get("incoming_started_ts")),
                                compression_name=(str(meta_data.get("compression_name", "") or "") or None),
                                compression_eff_pct=as_float(meta_data.get("compression_eff_pct")),
                                compression_norm=(str(meta_data.get("compression_norm", "") or "") or None),
                            )
                        entry["meta"] = meta
                    entry_actions = entry.get("actions")
                    actions = entry_actions if isinstance(entry_actions, list) else None
                    append_chat_entry(chat_text, text, peer_id, direction == "out", idx, meta=meta, actions=actions)
                else:
                    line = str(entry)
                    append_html(chat_text, line, "#66d9ef")
            relayout_chat_items(chat_text)

        def _mtmsg_index_at_pos(pos: "QtCore.QPoint") -> Optional[int]:
            try:
                idx = chat_text.indexAt(pos)
            except Exception:
                return None
            try:
                return int(idx.row()) if idx.isValid() else None
            except Exception:
                return None

        def _handle_mt_action(href: str) -> bool:
            nonlocal unseen_error_count, last_error_summary, errors_need_ack
            if not href.startswith("mtact:"):
                return False
            parts = href.split(":", 3)
            if len(parts) < 4:
                return False
            _tag, scope, action, peer_id = parts[0], parts[1], parts[2], parts[3]
            peer_norm = norm_id_for_filename(peer_id)
            if scope != "key" or not re.fullmatch(r"[0-9a-fA-F]{8}", peer_norm):
                return False
            if action == "replace":
                accept_pinned_mismatch_key(peer_norm)
                # Suppress duplicate conflict events already queued for the same key signature.
                if key_conflict_sig:
                    key_conflict_ignored[peer_norm] = {
                        "sig": key_conflict_sig,
                        "until": float(time.time() + 30.0),
                    }
                key_conflict_hidden_log_ts.pop(peer_norm, None)
                # Clear current red alert if it was exactly this key-mismatch event.
                try:
                    low = str(last_error_summary or "").lower()
                    if ("pinned key mismatch" in low) and (peer_norm.lower() in low):
                        unseen_error_count = 0
                        last_error_summary = ""
                        errors_need_ack = False
                        _update_alert_indicator()
                except Exception:
                    pass
                if key_conflict_peer == peer_norm:
                    _clear_key_conflict_header()
                return True
            if action == "ignore":
                log_line(f"{ts_local()} KEY: mismatch ignored by user for {peer_norm}", "warn")
                if key_conflict_peer == peer_norm and key_conflict_sig:
                    key_conflict_ignored[peer_norm] = {
                        "sig": key_conflict_sig,
                        "until": float(time.time() + 30.0),
                    }
                    key_conflict_hidden_log_ts.pop(peer_norm, None)
                if key_conflict_peer == peer_norm:
                    _clear_key_conflict_header()
                return True
            return False

        def _on_key_header_replace() -> None:
            if not key_conflict_peer:
                return
            _handle_mt_action(f"mtact:key:replace:{key_conflict_peer}")
            update_status()

        def _on_key_header_ignore() -> None:
            if not key_conflict_peer:
                return
            _handle_mt_action(f"mtact:key:ignore:{key_conflict_peer}")
            update_status()

        key_renew_btn.clicked.connect(_on_key_header_replace)
        key_ignore_btn.clicked.connect(_on_key_header_ignore)

        def _fmt_ctx_num(value: object) -> Optional[str]:
            if value is None:
                return None
            try:
                f = float(value)
            except Exception:
                return None
            if f < 0.0:
                f = 0.0
            if abs(f - round(f)) < 0.05:
                return str(int(round(f)))
            return "{:.1f}".format(f)

        def _copy_text_to_clipboard(text: str) -> None:
            try:
                cb = QtWidgets.QApplication.clipboard()
                if cb is None:
                    return
                cb.setText(text, QtGui.QClipboard.Clipboard)
                try:
                    cb.setText(text, QtGui.QClipboard.Selection)
                except Exception:
                    pass
            except Exception:
                pass

        def _copy_message_entry(entry: Dict[str, object]) -> None:
            try:
                raw = str(entry.get("text", "") or "")
                msg = raw[6:] if (len(raw) >= 6 and raw[5] == " ") else raw
                if msg:
                    _copy_text_to_clipboard(msg)
            except Exception:
                pass

        def _show_message_route(entry: Dict[str, object]) -> None:
            meta_data = entry.get("meta_data")
            if not isinstance(meta_data, dict):
                QtWidgets.QMessageBox.information(win, "meshTalk", tr("msg_route_na"))
                return
            forward_hops = _fmt_ctx_num(meta_data.get("forward_hops"))
            ack_hops = _fmt_ctx_num(meta_data.get("ack_hops"))
            attempts = _fmt_ctx_num(meta_data.get("attempts"))
            packets_line = None
            packets_raw = meta_data.get("packets")
            if isinstance(packets_raw, (tuple, list)) and len(packets_raw) >= 2:
                try:
                    packets_line = f"{int(packets_raw[0])}/{int(packets_raw[1])}"
                except Exception:
                    packets_line = None
            lines: list[str] = []
            if forward_hops is not None and ack_hops is not None:
                lines.append(f"{tr('msg_route_hops_tb')}: {forward_hops} / {ack_hops}")
            elif forward_hops is not None:
                lines.append(f"{tr('msg_route_hops')}: {forward_hops}")
            if attempts is not None:
                lines.append(f"{tr('msg_route_attempts')}: {attempts}")
            if packets_line:
                lines.append(f"{tr('msg_route_packets')}: {packets_line}")
            if not lines:
                body = tr("msg_route_na")
            else:
                body = "\n".join(lines)
            QtWidgets.QMessageBox.information(win, tr("msg_route_title"), body)

        def _show_chat_default_menu(pos: "QtCore.QPoint") -> None:
            _ = pos

        def _on_chat_context_menu(pos: "QtCore.QPoint") -> None:
            idx = _mtmsg_index_at_pos(pos)
            dialog_id = current_dialog
            if idx is None or not dialog_id:
                _show_chat_default_menu(pos)
                return
            entries = chat_history.get(dialog_id, [])
            if idx < 0 or idx >= len(entries) or not isinstance(entries[idx], dict):
                _show_chat_default_menu(pos)
                return
            entry = entries[idx]
            menu = QtWidgets.QMenu(win)
            act_copy = menu.addAction(tr("msg_ctx_copy"))
            picked = menu.exec(chat_text.viewport().mapToGlobal(pos))
            if picked == act_copy:
                _copy_message_entry(entry)

        def _on_chat_context_menu_widget(pos: "QtCore.QPoint") -> None:
            _on_chat_context_menu(pos)

        chat_text.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        chat_text.customContextMenuRequested.connect(_on_chat_context_menu_widget)

        def select_dialog(dialog_id: Optional[str]) -> None:
            nonlocal current_dialog
            current_dialog = dialog_id
            if dialog_id and dialog_id.startswith("group:"):
                tracked_peers.update(groups.get(dialog_id[6:], set()))
            if dialog_id and dialog_id in dialogs:
                dialogs[dialog_id]["unread"] = 0
                refresh_list()
            render_chat(dialog_id)
            update_status()

        def update_status() -> None:
            # Status is shown in Settings dialog; no-op placeholder for list refresh.
            return

        def refresh_list() -> None:
            nonlocal current_dialog
            items_list.clear()
            now_ts = time.time()
            visibility_mode = str(contacts_visibility or "all").strip().lower()
            ordered = sorted(
                dialogs.items(),
                key=lambda kv: float(kv[1].get("last_rx_ts", kv[1].get("last_ts", 0.0))),
                reverse=True,
            )
            list_index.clear()
            filter_text = search_field.text().strip().lower()
            known = (set(known_peers.keys()) | set(peer_states.keys())) - set(hidden_contacts)
            groups_all = set(groups.keys())
            groups_all.add("Primary")
            seen = set()

            def make_avatar(seed: str) -> QtGui.QIcon:
                try:
                    return QtGui.QIcon(_peer_logo_pixmap(seed, 44))
                except Exception:
                    return QtGui.QIcon(make_avatar_pixmap(seed, 44))

            def add_header(title: str) -> None:
                item = QtWidgets.QListWidgetItem(title)
                item.setFlags(QtCore.Qt.ItemIsEnabled)
                item.setForeground(QtGui.QColor("#c0b7c2"))
                font = QtGui.QFont("Ubuntu Mono", 13)
                font.setBold(False)
                item.setFont(font)
                items_list.addItem(item)
                list_index.append(None)

            def add_item(item_id: str, last_text: str = "") -> None:
                title = dialog_title(item_id)
                if filter_text and filter_text not in title.lower():
                    return
                item = QtWidgets.QListWidgetItem(title)
                size = item.sizeHint()
                base_h = max(74, int(size.height()) + 30)
                item.setSizeHint(QtCore.QSize(size.width(), base_h))
                if item_id.startswith("group:"):
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                bg_hex, tx_hex = color_pair_for_id(item_id)
                if current_dialog and item_id == current_dialog:
                    try:
                        bg_hex = QtGui.QColor(bg_hex).darker(135).name()
                    except Exception:
                        pass
                item.setBackground(QtGui.QColor(bg_hex))
                item.setForeground(QtGui.QColor(tx_hex))
                item.setIcon(make_avatar(item_id))
                unread = int(dialogs.get(item_id, {}).get("unread", 0) or 0)
                status_code: Optional[str] = None
                app_recent = False
                app_seen_any = False
                device_recent = False
                app_seen_fresh = False
                device_seen_fresh = False
                if not item_id.startswith("group:"):
                    st = peer_states.get(item_id)
                    # Apply persisted peer metadata (if any) to in-memory state for UI purposes.
                    if st is not None:
                        meta = peer_meta.get(item_id, {})
                        if isinstance(meta, dict):
                            try:
                                ls = meta.get("last_seen_ts")
                                if float(getattr(st, "last_seen_ts", 0.0) or 0.0) <= 0.0 and isinstance(ls, (int, float)) and float(ls) > 0.0:
                                    st.last_seen_ts = float(ls)
                            except Exception:
                                pass
                            try:
                                ds = meta.get("device_seen_ts")
                                if float(getattr(st, "device_seen_ts", 0.0) or 0.0) <= 0.0 and isinstance(ds, (int, float)) and float(ds) > 0.0:
                                    st.device_seen_ts = float(ds)
                            except Exception:
                                pass
                            try:
                                kc = meta.get("key_confirmed_ts")
                                if float(getattr(st, "key_confirmed_ts", 0.0) or 0.0) <= 0.0 and isinstance(kc, (int, float)) and float(kc) > 0.0:
                                    st.key_confirmed_ts = float(kc)
                            except Exception:
                                pass
                    seen_ts = 0.0
                    device_ts = 0.0
                    if st:
                        try:
                            seen_ts = float(getattr(st, "last_seen_ts", 0.0) or 0.0)
                        except Exception:
                            seen_ts = 0.0
                        try:
                            device_ts = float(getattr(st, "device_seen_ts", 0.0) or 0.0)
                        except Exception:
                            device_ts = 0.0
                    if seen_ts > 0.0:
                        app_seen_any = True
                        app_age_s = float(now_ts) - float(seen_ts)
                        app_recent = app_age_s <= float(CONTACT_ONLINE_SECONDS)
                        app_seen_fresh = app_age_s <= float(CONTACT_STALE_SECONDS)
                    if device_ts > 0.0:
                        dev_age_s = float(now_ts) - float(device_ts)
                        device_recent = dev_age_s <= float(CONTACT_ONLINE_SECONDS)
                        device_seen_fresh = dev_age_s <= float(CONTACT_STALE_SECONDS)
                    keys_ok = False
                    if st:
                        try:
                            keys_ok = bool(
                                st.key_ready
                                and not bool(getattr(st, "await_key_confirm", False))
                                and not bool(getattr(st, "pinned_mismatch", False))
                                and float(getattr(st, "key_confirmed_ts", 0.0) or 0.0) > 0.0
                            )
                        except Exception:
                            keys_ok = False
                    if app_seen_any and keys_ok:
                        if app_recent:
                            status_code = "app_online"
                        elif app_seen_fresh:
                            status_code = "app_offline"
                        else:
                            status_code = None
                    elif not app_seen_any:
                        if device_recent:
                            status_code = "mesh_online"
                        elif device_seen_fresh:
                            status_code = "mesh_offline"
                        else:
                            status_code = None
                    else:
                        # App was seen, but keys are not valid now (e.g. mismatch/reset):
                        # keep device presence indicator instead of hiding status completely.
                        if device_recent:
                            status_code = "mesh_online"
                        elif device_seen_fresh:
                            status_code = "mesh_offline"
                        else:
                            status_code = None
                    if visibility_mode == "online" and status_code not in ("app_online", "mesh_online"):
                        return
                    if visibility_mode == "app" and status_code not in ("app_online", "app_offline"):
                        return
                    if visibility_mode == "device" and status_code not in ("mesh_online", "mesh_offline"):
                        return
                item.setData(
                    QtCore.Qt.UserRole,
                    {
                        "id": item_id,
                        "pinned": item_id in pinned_dialogs,
                        "unread": unread,
                        "last_rx_ts": float(dialogs.get(item_id, {}).get("last_rx_ts", 0.0) or 0.0),
                        "status_code": status_code,
                    },
                )
                items_list.addItem(item)
                list_index.append(item_id)
                seen.add(item_id)

            pinned = [d for d in pinned_dialogs if d in dialogs or d in known or d.startswith("group:")]
            for dialog_id in pinned:
                rec = dialogs.get(dialog_id) or {}
                add_item(dialog_id, str(rec.get("last_text", "")))

            for dialog_id, rec in ordered:
                if dialog_id in pinned_dialogs:
                    continue
                add_item(dialog_id, str(rec.get("last_text", "")))

            for peer in sorted(known):
                if peer not in seen:
                    add_item(peer, "")
            for g in sorted(groups_all):
                gid = f"group:{g}"
                if gid not in seen:
                    add_item(gid, "")
            # Keep one dialog always selected. If current selection disappeared, pick first available dialog.
            selected_dialog: Optional[str] = None
            if current_dialog and current_dialog in list_index:
                selected_dialog = current_dialog
            else:
                for did in list_index:
                    if did:
                        selected_dialog = did
                        break
            if selected_dialog and selected_dialog in list_index:
                row_sel = list_index.index(selected_dialog)
                prev_dialog = current_dialog
                current_dialog = selected_dialog
                old_block = items_list.blockSignals(True)
                try:
                    items_list.setCurrentRow(row_sel)
                finally:
                    items_list.blockSignals(old_block)
                if prev_dialog != selected_dialog:
                    render_chat(selected_dialog)
            else:
                current_dialog = None
                chat_text.clear()
            adjust_contacts_panel_width()
            update_status()

        def set_language(lang: str, persist: bool = False) -> None:
            nonlocal current_lang
            if lang not in ("ru", "en"):
                lang = "ru"
            changed = (lang != current_lang)
            current_lang = lang
            if persist:
                save_gui_config()
            apply_language()
            refresh_list()
            render_chat(current_dialog)
            # Avoid forced repaint of all child widgets: on some Qt/KDE Breeze stacks
            # it can trigger cross-thread style-engine warnings.
            win.update()
            if changed:
                print(f"GUI: lang={current_lang}")

        set_language(current_lang, persist=False)

        def start_dialog_by_id(raw_id: str) -> None:
            peer_norm = norm_id_for_filename(raw_id.strip())
            if not peer_norm:
                return
            if peer_norm == self_id:
                return
            if peer_norm in hidden_contacts:
                hidden_contacts.discard(peer_norm)
                save_gui_config()
            update_dialog(peer_norm, "new chat")
            tracked_peers.add(peer_norm)
            st = get_peer_state(peer_norm)
            if peer_norm != self_id and st and not st.key_ready and peer_used_meshtalk(peer_norm):
                st.force_key_req = True
                st.next_key_req_ts = 0.0
                send_key_request(peer_norm, require_confirm=True, reason="dialog_open")
            refresh_list()
            if peer_norm in list_index:
                items_list.setCurrentRow(list_index.index(peer_norm))
                select_dialog(peer_norm)

        def refresh_contacts() -> None:
            refresh_list()

        def add_group_from_selection() -> None:
            name, ok = QtWidgets.QInputDialog.getText(win, "meshTalk", tr("group_name"))
            if not ok:
                return
            name = name.strip()
            if not name:
                QtWidgets.QMessageBox.information(win, "meshTalk", tr("group_empty"))
                return
            selected = [list_index[i.row()] for i in items_list.selectedIndexes()]
            peers_selected = [s for s in selected if not s.startswith("group:")]
            if not peers_selected:
                QtWidgets.QMessageBox.information(win, "meshTalk", tr("select_peers"))
                return
            valid = []
            for peer_norm in peers_selected:
                st = get_peer_state(peer_norm)
                if st and st.key_ready:
                    valid.append(peer_norm)
                else:
                    log_line(f"Skip {peer_norm}: key not ready.", "warn")
            if not valid:
                return
            groups.setdefault(name, set()).update(valid)
            tracked_peers.update(valid)
            update_dialog(f"group:{name}", "group created")
            save_gui_config()
            refresh_list()

        def add_selected_to_group(group_id: str) -> None:
            name = group_id[6:]
            selected = [list_index[i.row()] for i in items_list.selectedIndexes()]
            peers_selected = [s for s in selected if not s.startswith("group:")]
            if not peers_selected:
                QtWidgets.QMessageBox.information(win, "meshTalk", tr("select_peers"))
                return
            valid = []
            for peer_norm in peers_selected:
                st = get_peer_state(peer_norm)
                if st and st.key_ready:
                    valid.append(peer_norm)
                else:
                    log_line(f"Skip {peer_norm}: key not ready.", "warn")
            if not valid:
                return
            groups.setdefault(name, set()).update(valid)
            tracked_peers.update(valid)
            update_dialog(group_id, "group updated")
            save_gui_config()
            refresh_list()

        def add_peers_to_group_by_name(peers: list[str], group_name: str) -> None:
            valid = []
            for peer_norm in peers:
                st = get_peer_state(peer_norm)
                if st and st.key_ready:
                    valid.append(peer_norm)
                else:
                    log_line(f"Skip {peer_norm}: key not ready.", "warn")
            if not valid:
                return
            groups.setdefault(group_name, set()).update(valid)
            tracked_peers.update(valid)
            update_dialog(f"group:{group_name}", "group updated")
            refresh_list()

        def rewrite_history_dialog_entries(old_dialog_id: str, new_dialog_id: Optional[str] = None) -> None:
            if not old_dialog_id:
                return
            if new_dialog_id is None:
                purge_history_peer(old_dialog_id)
            else:
                rewrite_history_peer_field(old_dialog_id, new_dialog_id)

        def rename_group(group_id: str) -> None:
            old_name = group_id[6:]
            if old_name not in groups:
                groups[old_name] = set()
            new_name, ok = QtWidgets.QInputDialog.getText(win, "meshTalk", tr("group_name"), text=old_name)
            if not ok:
                return
            new_name = new_name.strip()
            if not new_name or new_name == old_name:
                return
            if new_name in groups:
                QtWidgets.QMessageBox.information(win, "meshTalk", tr("group_exists"))
                return
            groups[new_name] = groups.pop(old_name, set())
            old_id = f"group:{old_name}"
            new_id = f"group:{new_name}"
            if old_id in dialogs:
                dialogs[new_id] = dialogs.pop(old_id)
            if old_id in chat_history:
                chat_history[new_id] = chat_history.pop(old_id)
            if old_id in pinned_dialogs:
                pinned_dialogs.discard(old_id)
                pinned_dialogs.add(new_id)
            rewrite_history_dialog_entries(old_id, new_id)
            if current_dialog == old_id:
                select_dialog(new_id)
            save_gui_config()
            refresh_list()
            log_line(f"GROUP: renamed {old_name} -> {new_name}", "info")

        def delete_group(group_id: str) -> None:
            name = group_id[6:]
            groups.pop(name, None)
            dialogs.pop(group_id, None)
            chat_history.pop(group_id, None)
            pinned_dialogs.discard(group_id)
            rewrite_history_dialog_entries(group_id, None)
            if current_dialog == group_id:
                select_dialog(None)
            save_gui_config()
            refresh_list()

        def delete_peer(peer_id: str) -> None:
            # Remove from groups
            for gname, members in list(groups.items()):
                if peer_id in members:
                    members.discard(peer_id)
            tracked_peers.discard(peer_id)
            dialogs.pop(peer_id, None)
            chat_history.pop(peer_id, None)
            pinned_dialogs.discard(peer_id)
            hidden_contacts.discard(peer_id)
            known_peers.pop(peer_id, None)
            peer_states.pop(peer_id, None)
            with pending_lock:
                pending_by_peer.pop(peer_id, None)
                save_state(pending_by_peer)
            purge_history_peer(peer_id)
            # Remove peer keys
            peer_key = os.path.join(keydir, f"{peer_id}.pub")
            try:
                if os.path.isfile(peer_key):
                    os.remove(peer_key)
            except Exception:
                pass
            if current_dialog == peer_id:
                select_dialog(None)
            save_gui_config()
            refresh_list()

        def request_key(peer_id: str) -> None:
            if not peer_id or peer_id.startswith("group:"):
                return
            # Must be hex node id (8 hex chars) after normalization
            if not re.fullmatch(r"[0-9a-fA-F]{8}", peer_id):
                log_line(f"KEY: invalid peer id '{peer_id}'", "warn")
                return
            st = get_peer_state(peer_id)
            if st:
                st.force_key_req = True
                st.next_key_req_ts = 0.0
            send_key_request(peer_id, require_confirm=True, reason="manual_request_key")

        def reset_peer_key(peer_id: str) -> None:
            if not peer_id or peer_id.startswith("group:"):
                return
            if not re.fullmatch(r"[0-9a-fA-F]{8}", peer_id):
                log_line(f"KEY: invalid peer id '{peer_id}'", "warn")
                return
            peer_key = os.path.join(keydir, f"{peer_id}.pub")
            try:
                if os.path.isfile(peer_key):
                    os.remove(peer_key)
            except Exception:
                pass
            known_peers.pop(peer_id, None)
            st = get_peer_state(peer_id)
            if st:
                st.aes = None
                st.pinned_mismatch = False
                st.pinned_old_fp = ""
                st.pinned_new_fp = ""
                st.pinned_new_pub_b64 = ""
                st.force_key_req = True
                st.next_key_req_ts = 0.0
            send_key_request(peer_id, require_confirm=True, reason="reset_key")
            log_line(f"{ts_local()} KEY: reset for {peer_id}", "warn")

        def accept_pinned_mismatch_key(peer_id: str) -> None:
            if not peer_id or peer_id.startswith("group:"):
                return
            if not re.fullmatch(r"[0-9a-fA-F]{8}", peer_id):
                log_line(f"KEY: invalid peer id '{peer_id}'", "warn")
                return
            st = get_peer_state(peer_id)
            pending_b64 = str(getattr(st, "pinned_new_pub_b64", "") or "").strip() if st else ""
            if not pending_b64:
                log_line(f"{ts_local()} KEY: no pending mismatched key for {peer_id}", "warn")
                return
            try:
                pub_raw = b64d(pending_b64)
                force_store_peer_pub(peer_id, pub_raw)
            except Exception as ex:
                log_line(f"{ts_local()} KEY: failed to replace pinned key for {peer_id} ({type(ex).__name__})", "error")
                return
            st2 = get_peer_state(peer_id)
            if st2:
                st2.pinned_mismatch = False
                st2.pinned_old_fp = ""
                st2.pinned_new_fp = ""
                st2.pinned_new_pub_b64 = ""
                st2.force_key_req = True
                st2.await_key_confirm = True
                st2.next_key_req_ts = 0.0
            send_key_request(peer_id, require_confirm=True, reason="replace_pinned_key")
            log_line(f"{ts_local()} KEY: pinned key replaced for {peer_id}, confirmation requested", "info")

        trace_inflight: set[str] = set()
        trace_lock = threading.Lock()

        def trace_route(peer_id: str) -> None:
            if not peer_id or peer_id.startswith("group:"):
                return
            if not re.fullmatch(r"[0-9a-fA-F]{8}", peer_id):
                log_line(f"TRACE: invalid peer id '{peer_id}'", "warn")
                return
            if peer_id == self_id:
                return
            if not radio_ready or interface is None:
                log_line(f"{ts_local()} TRACE: radio not connected", "warn")
                return
            with trace_lock:
                if peer_id in trace_inflight:
                    log_line(f"{ts_local()} TRACE: already running for {peer_id}", "warn")
                    return
                trace_inflight.add(peer_id)

            trace_id = f"trace:{peer_id}:{os.urandom(4).hex()}"
            sent_at_ts = time.time()
            meta_data_out: Dict[str, object] = {
                "delivery": None,
                "attempts": 0.0,
                "forward_hops": None,
                "ack_hops": None,
                "incoming": False,
                "done": False,
                "sent_at_ts": sent_at_ts,
            }
            chat_line(
                peer_id,
                tr("trace_request"),
                "#fd971f",
                outgoing=True,
                msg_id=trace_id,
                meta=format_meta(None, 0.0, None, None, None, sent_at_ts=sent_at_ts),
                meta_data=meta_data_out,
            )

            def _worker(peer_norm: str) -> None:
                try:
                    iface = interface
                    if not radio_ready or iface is None:
                        delivered_at_ts = time.time()
                        ui_emit("log", f"{ts_local()} TRACE: start {peer_norm} (radio not connected)")
                        ui_emit(
                            "trace_done",
                            (
                                peer_norm,
                                trace_id,
                                {
                                    **meta_data_out,
                                    "delivery": max(0.0, float(delivered_at_ts - sent_at_ts)),
                                    "attempts": float(meta_data_out.get("attempts", 0.0) or 0.0),
                                    "status": "timeout",
                                    "done": False,
                                },
                                "",
                            ),
                        )
                        return
                    from meshtastic import mesh_pb2

                    # Refresh name cache from Meshtastic node DB (best-effort).
                    update_peer_names_from_nodes()

                    dest = wire_id_from_norm(peer_norm)
                    hop_limit = 8
                    ui_emit("log", f"{ts_local()} TRACE: start {peer_norm} dest={dest} hop_limit={hop_limit}")
                    done = threading.Event()  # global traceroute completion
                    result: Dict[str, object] = {"text": "", "forward_hops": None, "ack_hops": None, "status": None}
                    result_lock = threading.Lock()

                    def _node_label(node_num: object, is_dest: bool) -> str:
                        try:
                            n = int(node_num)
                        except Exception:
                            return str(node_num)
                        try:
                            s = iface._nodeNumToId(n, is_dest)  # type: ignore[attr-defined]
                        except Exception:
                            s = None
                        node_id = str(s) if s else f"!{n:08x}"
                        try:
                            if (not node_id.startswith("!")) and re.fullmatch(r"[0-9a-fA-F]{8}", node_id):
                                node_id = f"!{node_id.lower()}"
                        except Exception:
                            pass
                        name = ""
                        try:
                            long_name, short_name = _peer_name_parts(node_id)
                            if long_name and short_name:
                                name = f"{long_name} [{short_name}]"
                            elif long_name:
                                name = long_name
                            elif short_name:
                                name = f"[{short_name}]"
                        except Exception:
                            name = ""
                        if name:
                            # Keep node id outside parentheses to avoid nested parens with SNR output.
                            return f"{name} {node_id}"
                        return node_id

                    def _snr_str(raw_val: object) -> str:
                        try:
                            v = int(raw_val)
                        except Exception:
                            return "?"
                        if v == -128:
                            return "?"
                        try:
                            return str(float(v) / 4.0)
                        except Exception:
                            return "?"

                    def _format_traceroute_response(p: Dict[str, object]) -> Tuple[str, Optional[int], Optional[int]]:
                        decoded = p.get("decoded") if isinstance(p, dict) else None
                        decoded = decoded if isinstance(decoded, dict) else {}
                        payload = decoded.get("payload")
                        if not isinstance(payload, (bytes, bytearray)):
                            return (tr("trace_timeout"), None, None)
                        rd = mesh_pb2.RouteDiscovery()
                        rd.ParseFromString(bytes(payload))
                        lines: list[str] = []
                        lines.append(tr("trace_towards"))
                        to_num = p.get("to")
                        from_num = p.get("from")
                        route_str = _node_label(to_num, False)
                        snr_towards = list(getattr(rd, "snr_towards", []))
                        route = list(getattr(rd, "route", []))
                        fwd_hops = len(route) + 1
                        snr_valid = len(snr_towards) == (len(route) + 1)
                        for idx, node_num in enumerate(route):
                            snr = _snr_str(snr_towards[idx]) if snr_valid else "?"
                            route_str += f" --> {_node_label(node_num, False)} ({snr}dB)"
                        snr_last = _snr_str(snr_towards[-1]) if snr_valid and snr_towards else "?"
                        route_str += f" --> {_node_label(from_num, False)} ({snr_last}dB)"
                        lines.append(route_str)

                        route_back = list(getattr(rd, "route_back", []))
                        snr_back = list(getattr(rd, "snr_back", []))
                        back_valid = ("hopStart" in p) and (len(snr_back) == (len(route_back) + 1))
                        ack_hops = None
                        if back_valid:
                            ack_hops = len(route_back) + 1
                            lines.append(tr("trace_back"))
                            route_str = _node_label(from_num, False)
                            for idx, node_num in enumerate(route_back):
                                snr = _snr_str(snr_back[idx]) if snr_back else "?"
                                route_str += f" --> {_node_label(node_num, False)} ({snr}dB)"
                            snr_last = _snr_str(snr_back[-1]) if snr_back else "?"
                            route_str += f" --> {_node_label(to_num, False)} ({snr_last}dB)"
                            lines.append(route_str)
                        return ("\n".join(lines), fwd_hops, ack_hops)

                    def _on_resp(p: Dict[str, object]) -> None:
                        with result_lock:
                            if done.is_set():
                                return
                            try:
                                text, fwd_hops, ack_hops = _format_traceroute_response(p)
                                result["text"] = text
                                result["forward_hops"] = float(fwd_hops) if fwd_hops is not None else None
                                result["ack_hops"] = float(ack_hops) if ack_hops is not None else None
                                result["status"] = None
                                ui_emit(
                                    "log",
                                    f"{ts_local()} TRACE: response {peer_norm} hops={fwd_hops if fwd_hops is not None else '?'} back={ack_hops if ack_hops is not None else '?'}",
                                )
                                # Log the full traceroute output lines (diagnostic).
                                try:
                                    for ln in str(text or "").splitlines():
                                        if ln.strip():
                                            ui_emit("log", f"{ts_local()} TRACE: {peer_norm} {ln}")
                                except Exception:
                                    pass
                            except Exception:
                                result["text"] = tr("trace_timeout")
                                result["status"] = "timeout"
                            finally:
                                done.set()

                    nodes_obj = getattr(iface, "nodes", None)
                    try:
                        nodes_len = len(nodes_obj) if nodes_obj else 0
                    except Exception:
                        nodes_len = 0
                    wait_factor = min(max(0, int(nodes_len) - 1), int(hop_limit))
                    try:
                        base_timeout = float(getattr(getattr(iface, "_timeout", None), "expireTimeout", 20) or 20)
                    except Exception:
                        base_timeout = 20.0
                    # Defensive: Meshtastic timeout values can vary wildly depending on platform/build.
                    # Traceroute is a diagnostic; keep per-attempt waits bounded so we can retry/finish
                    # within the overall max_total_s window without stalling the worker thread.
                    base_timeout = max(5.0, min(60.0, float(base_timeout)))
                    timeout_s = base_timeout * float(max(1, wait_factor))
                    try:
                        max_total_s = float(getattr(args, "max_seconds", 600) or 600)
                    except Exception:
                        max_total_s = 600.0
                    # Traceroute is a diagnostic tool; cap retry window to avoid generating excessive traffic.
                    max_total_s = min(600.0, max(10.0, float(max_total_s)))
                    # Ensure one attempt doesn't block longer than the overall retry window.
                    timeout_s = max(2.0, min(float(timeout_s), float(max_total_s), 60.0))
                    ui_emit(
                        "log",
                        f"{ts_local()} TRACE: params {peer_norm} timeout_s={timeout_s:.1f} max_total_s={max_total_s:.1f} base_timeout={base_timeout:.1f} nodes={nodes_len}",
                    )

                    attempt = 0
                    next_retry_at = sent_at_ts
                    while not done.is_set():
                        now = time.time()
                        if (now - sent_at_ts) >= max_total_s:
                            break
                        if now < next_retry_at:
                            done.wait(timeout=min(0.2, max(0.0, next_retry_at - now)))
                            continue
                        attempt += 1
                        ui_emit("trace_update", (peer_norm, trace_id, float(attempt)))
                        ui_emit("log", f"{ts_local()} TRACE: attempt={attempt} {peer_norm}")
                        req = mesh_pb2.RouteDiscovery()
                        send_err: list[BaseException] = []
                        send_done = threading.Event()

                        def _send_req() -> None:
                            try:
                                ch_idx = int(args.channel if args.channel is not None else 0)
                                # Meshtastic API differs between releases/bundles; try modern call first,
                                # then progressively degrade to older signatures.
                                try:
                                    iface.sendData(
                                        req,
                                        destinationId=dest,
                                        portNum=portnums_pb2.PortNum.TRACEROUTE_APP,
                                        wantResponse=True,
                                        onResponse=_on_resp,
                                        channelIndex=ch_idx,
                                        hopLimit=hop_limit,
                                    )
                                except TypeError:
                                    try:
                                        iface.sendData(
                                            req,
                                            destinationId=dest,
                                            portNum=portnums_pb2.PortNum.TRACEROUTE_APP,
                                            wantResponse=True,
                                            onResponse=_on_resp,
                                            channelIndex=ch_idx,
                                        )
                                    except TypeError:
                                        iface.sendData(
                                            req,
                                            destinationId=dest,
                                            portNum=portnums_pb2.PortNum.TRACEROUTE_APP,
                                            wantResponse=True,
                                            onResponse=_on_resp,
                                        )
                            except BaseException as ex:
                                send_err.append(ex)
                            finally:
                                send_done.set()

                        t0 = time.time()
                        threading.Thread(target=_send_req, daemon=True).start()
                        if not send_done.wait(timeout=5.0):
                            # If Meshtastic sendData blocks, avoid spinning retries; mark trace as failed.
                            ui_emit("log", f"{ts_local()} TRACE: sendData blocked >5s, abort {peer_norm}")
                            with result_lock:
                                result["status"] = "send_blocked"
                                result["text"] = ""
                            done.set()
                            break
                        if send_err:
                            err = send_err[0]
                            ui_emit(
                                "log",
                                f"{ts_local()} TRACE: send failed ({type(err).__name__}: {err}), retry later {peer_norm}",
                            )
                            next_retry_at = time.time() + retry_delay_seconds(float(args.retry_seconds), int(attempt))
                            continue
                        ui_emit("log", f"{ts_local()} TRACE: send ok dt={(time.time() - t0):.2f}s {peer_norm}")
                        done.wait(timeout=timeout_s)
                        if done.is_set():
                            break
                        next_retry_at = time.time() + retry_delay_seconds(float(args.retry_seconds), int(attempt))
                        ui_emit(
                            "log",
                            f"{ts_local()} TRACE: no response, schedule retry in {max(0.0, next_retry_at - time.time()):.1f}s {peer_norm}",
                        )
                    delivered_at_ts = time.time()
                    attempts_val = float(attempt)
                    text = str(result.get("text", "") or "")
                    status = None
                    with result_lock:
                        status_raw = result.get("status")
                        status = str(status_raw).strip() if status_raw is not None else None
                    if not done.is_set():
                        status = "timeout"
                    if status and not text:
                        text = tr("trace_timeout")
                    if status:
                        ui_emit("log", f"{ts_local()} TRACE: done {peer_norm} status={status} attempts={attempt}")
                    else:
                        fwd = result.get("forward_hops")
                        back = result.get("ack_hops")
                        ui_emit(
                            "log",
                            f"{ts_local()} TRACE: done {peer_norm} ok attempts={attempt} hops={fwd if fwd is not None else '?'} back={back if back is not None else '?'}",
                        )
                    meta_data_final: Dict[str, object] = {
                        **meta_data_out,
                        "delivery": max(0.0, float(delivered_at_ts - sent_at_ts)),
                        "attempts": attempts_val,
                        "forward_hops": result.get("forward_hops"),
                        "ack_hops": result.get("ack_hops"),
                    }
                    if status:
                        meta_data_final["status"] = status
                        meta_data_final["done"] = False
                    else:
                        meta_data_final["delivered_at_ts"] = delivered_at_ts
                        meta_data_final["done"] = True
                    resp_text = text if not status else ""
                    ui_emit("trace_done", (peer_norm, trace_id, meta_data_final, resp_text))
                finally:
                    with trace_lock:
                        trace_inflight.discard(peer_norm)

            threading.Thread(target=_worker, args=(peer_id,), daemon=True).start()

        def chat_line(
            dialog_id: str,
            text: str,
            color: str,
            outgoing: bool = False,
            msg_id: Optional[str] = None,
            meta: str = "",
            meta_data: Optional[Dict[str, object]] = None,
            replace_msg_id: Optional[str] = None,
            keep_ts_on_replace: bool = False,
        ) -> None:
            ts = time.strftime("%H:%M", time.localtime())
            line = f"{ts} {text}"
            history = chat_history.setdefault(dialog_id, [])
            if replace_msg_id:
                for i in range(len(history) - 1, -1, -1):
                    entry = history[i]
                    if isinstance(entry, dict) and entry.get("msg_id") == replace_msg_id:
                        if keep_ts_on_replace:
                            try:
                                old_text = str(entry.get("text", "") or "")
                                if len(old_text) >= 6 and old_text[2] == ":" and old_text[5] == " ":
                                    line = f"{old_text[:5]} {text}"
                            except Exception:
                                pass
                        entry["text"] = line
                        if meta:
                            entry["meta"] = meta
                        if meta_data is not None:
                            entry["meta_data"] = dict(meta_data)
                            acts = meta_data.get("actions") if isinstance(meta_data, dict) else None
                            if isinstance(acts, list):
                                entry["actions"] = acts
                        if msg_id:
                            entry["msg_id"] = msg_id
                        update_dialog(dialog_id, line, recv=not outgoing)
                        refresh_list()
                        if current_dialog == dialog_id:
                            render_chat(dialog_id)
                        return
            entry = {"text": line, "dir": "out" if outgoing else "in"}
            if msg_id:
                entry["msg_id"] = msg_id
            if meta:
                entry["meta"] = meta
            if meta_data is not None:
                entry["meta_data"] = dict(meta_data)
                acts = meta_data.get("actions") if isinstance(meta_data, dict) else None
                if isinstance(acts, list):
                    entry["actions"] = acts
            history.append(entry)
            update_dialog(dialog_id, line, recv=not outgoing)
            if not outgoing and current_dialog != dialog_id:
                rec = dialogs.get(dialog_id) or {}
                rec["unread"] = int(rec.get("unread", 0) or 0) + 1
                dialogs[dialog_id] = rec
            refresh_list()
            if current_dialog == dialog_id:
                peer_id = self_id if outgoing else dialog_id
                idx = len(chat_history.get(dialog_id, [])) - 1
                entry_actions = entry.get("actions")
                actions = entry_actions if isinstance(entry_actions, list) else None
                append_chat_entry(chat_text, line, peer_id, outgoing, idx, meta=meta, actions=actions)
            update_status()

        def history_has_msg(dialog_id: str, msg_id: str) -> bool:
            if not msg_id:
                return False
            for entry in chat_history.get(dialog_id, []):
                if isinstance(entry, dict) and entry.get("msg_id") == msg_id:
                    return True
            return False

        def restore_outgoing_state() -> None:
            for peer_norm, peer_pending in list(pending_by_peer.items()):
                if not peer_norm or not isinstance(peer_pending, dict):
                    continue
                grouped: Dict[str, Dict[str, object]] = {}
                for rec in peer_pending.values():
                    if not isinstance(rec, dict):
                        continue
                    group_id = str(rec.get("group") or rec.get("id") or "").strip()
                    if not group_id:
                        continue
                    grouped_rec = grouped.setdefault(
                        group_id,
                        {
                            "text": "",
                            "total": 1,
                            "parts": set(),
                            "attempts": 0,
                            "created": 0.0,
                            "compression_name": None,
                            "compression_eff_pct": None,
                            "compression_norm": None,
                            "compressed_size": 0,
                        },
                    )
                    text = str(rec.get("text", ""))
                    if text and not grouped_rec.get("text"):
                        grouped_rec["text"] = text
                    try:
                        total_now = int(rec.get("total", 1) or 1)
                    except Exception:
                        total_now = 1
                    grouped_rec["total"] = max(int(grouped_rec.get("total", 1) or 1), max(1, total_now))
                    try:
                        part_now = int(rec.get("part", 0) or 0)
                    except Exception:
                        part_now = 0
                    if part_now > 0:
                        try:
                            grouped_rec["parts"].add(part_now)  # type: ignore[attr-defined]
                        except Exception:
                            pass
                    try:
                        attempts_now = int(rec.get("attempts", 0) or 0)
                    except Exception:
                        attempts_now = 0
                    grouped_rec["attempts"] = max(int(grouped_rec.get("attempts", 0) or 0), max(0, attempts_now))
                    try:
                        created_now = float(rec.get("created", 0.0) or 0.0)
                    except Exception:
                        created_now = 0.0
                    if created_now > 0.0:
                        created_prev = float(grouped_rec.get("created", 0.0) or 0.0)
                        if (created_prev <= 0.0) or (created_now < created_prev):
                            grouped_rec["created"] = created_now
                    if int(rec.get("compression", 0) or 0) == 1:
                        cmp_name_now = normalize_compression_name(str(rec.get("cmp", "") or ""))
                        if cmp_name_now and not grouped_rec.get("compression_name"):
                            grouped_rec["compression_name"] = cmp_name_now
                        cmp_norm_now = str(rec.get("cmp_norm", "") or "").strip()
                        if cmp_norm_now and not grouped_rec.get("compression_norm"):
                            grouped_rec["compression_norm"] = cmp_norm_now.upper()
                        try:
                            eff_now = float(rec.get("cmp_eff_pct"))
                        except Exception:
                            eff_now = None
                        if eff_now is not None and grouped_rec.get("compression_eff_pct") is None:
                            grouped_rec["compression_eff_pct"] = eff_now
                        chunk_b64 = str(rec.get("chunk_b64", "") or "")
                        if chunk_b64:
                            try:
                                grouped_rec["compressed_size"] = int(grouped_rec.get("compressed_size", 0) or 0) + len(
                                    b64d(chunk_b64)
                                )
                            except Exception:
                                pass

                for group_id, grouped_rec in grouped.items():
                    if history_has_msg(peer_norm, group_id):
                        continue
                    text = str(grouped_rec.get("text", ""))
                    if not text:
                        continue
                    total = max(1, int(grouped_rec.get("total", 1) or 1))
                    try:
                        pending_parts = len(grouped_rec.get("parts") or set())
                    except Exception:
                        pending_parts = total
                    pending_parts = max(1, pending_parts)
                    done_parts = max(0, min(total, total - pending_parts))
                    attempts_raw = int(grouped_rec.get("attempts", 0) or 0)
                    attempts_val = float(attempts_raw) if attempts_raw > 0 else 0.0
                    sent_at_raw = float(grouped_rec.get("created", 0.0) or 0.0)
                    sent_at_ts = sent_at_raw if sent_at_raw > 0.0 else None
                    packets = (done_parts, total)
                    compression_name = normalize_compression_name(
                        str(grouped_rec.get("compression_name", "") or "")
                    )
                    compression_norm = str(grouped_rec.get("compression_norm", "") or "").strip().upper() or None
                    compression_eff_pct = None
                    try:
                        raw_eff = grouped_rec.get("compression_eff_pct")
                        if raw_eff is not None:
                            compression_eff_pct = float(raw_eff)
                    except Exception:
                        compression_eff_pct = None
                    if compression_name and compression_eff_pct is None and pending_parts >= total:
                        compressed_size = int(grouped_rec.get("compressed_size", 0) or 0)
                        if compressed_size > 0:
                            compression_eff_pct = compression_efficiency_pct(len(text.encode("utf-8")), compressed_size)
                    meta_data_out: Dict[str, object] = {
                        "delivery": None,
                        "attempts": attempts_val,
                        "forward_hops": None,
                        "ack_hops": None,
                        "packets": packets,
                        "incoming": False,
                        "done": False,
                        "compression_name": compression_name,
                        "compression_eff_pct": compression_eff_pct,
                        "compression_norm": compression_norm,
                    }
                    if sent_at_ts is not None:
                        meta_data_out["sent_at_ts"] = sent_at_ts
                    meta = format_meta(
                        None,
                        attempts_val,
                        None,
                        None,
                        packets,
                        sent_at_ts=sent_at_ts,
                        compression_name=compression_name,
                        compression_eff_pct=compression_eff_pct,
                        compression_norm=compression_norm,
                    )
                    chat_line(
                        peer_norm,
                        text,
                        "#a6e22e",
                        outgoing=True,
                        msg_id=group_id,
                        meta=meta,
                        meta_data=meta_data_out,
                    )

        def assemble_incoming_text(
            parts: object,
            total: int,
            compact: bool,
            compression: int,
            legacy_codec: Optional[str],
            show_partial: bool = True,
        ) -> Tuple[str, bool]:
            if not isinstance(parts, dict) or total <= 0:
                return ("", True)
            if compact:
                return assemble_compact_parts(parts, total, compression, legacy_codec, show_partial=show_partial)
            full = "".join(str(parts.get(str(i), parts.get(i, ""))) for i in range(1, total + 1))
            if show_partial and len(parts) < total:
                full = full + "..."
            return (full, True)

        def restore_incoming_state() -> None:
            pruned = False
            for key, rec in list(incoming_state.items()):
                peer_norm = str(rec.get("peer", "")).strip()
                group_id = str(rec.get("group_id", "")).strip()
                if not peer_norm or not group_id:
                    incoming_state.pop(key, None)
                    pruned = True
                    continue
                if history_has_msg(peer_norm, group_id):
                    incoming_state.pop(key, None)
                    pruned = True
                    continue
                parts = rec.get("parts") or {}
                total = int(rec.get("total", 0) or 0)
                if total <= 0 or not isinstance(parts, dict):
                    incoming_state.pop(key, None)
                    pruned = True
                    continue
                compact = bool(rec.get("compact", False))
                compression = int(rec.get("compression", 0) or 0)
                legacy_codec = rec.get("legacy_codec")
                if legacy_codec is not None:
                    legacy_codec = str(legacy_codec)
                elif rec.get("codec") is not None:
                    legacy_codec = str(rec.get("codec"))
                full, decode_ok = assemble_incoming_text(
                    parts,
                    total,
                    compact,
                    compression,
                    legacy_codec,
                    show_partial=True,
                )
                avg_hops = None
                if rec.get("hops_n", 0):
                    avg_hops = float(rec.get("hops_sum", 0.0)) / float(rec.get("hops_n", 1))
                avg_attempts = None
                if rec.get("attempts_n", 0):
                    avg_attempts = float(rec.get("attempts_sum", 0.0)) / float(rec.get("attempts_n", 1))
                done_now = (len(parts) >= total)
                status = "decode_error" if (done_now and not decode_ok) else None
                cmp_raw = effective_payload_cmp_label(
                    rec.get("payload_cmp"),
                    compact_wire=compact,
                    compression_flag=int(compression or 0),
                    legacy_codec=legacy_codec,
                    parts=parts,
                )
                try:
                    inferred_exact = infer_compact_cmp_label_from_joined_parts(parts, total)
                except Exception:
                    inferred_exact = None
                if inferred_exact:
                    cmp_raw = inferred_exact
                compression_name = normalize_compression_name(cmp_raw)
                compression_norm = infer_compact_norm_from_joined_parts(parts, total)
                if compression_norm:
                    compression_norm = str(compression_norm).upper()
                compression_eff_pct = None
                if compression_name and compact and done_now and decode_ok:
                    compressed_size = 0
                    for part_payload in parts.values():
                        try:
                            compressed_size += len(b64d(str(part_payload)))
                        except Exception:
                            compressed_size = 0
                            break
                    if compressed_size > 0:
                        compression_eff_pct = compression_efficiency_pct(len(full.encode("utf-8")), compressed_size)
                received_at_ts = None
                if done_now:
                    raw_received = float(rec.get("received_at_ts", 0.0) or 0.0)
                    received_at_ts = raw_received if raw_received > 0.0 else None
                incoming_started_ts = None
                raw_started = float(rec.get("incoming_started_ts", 0.0) or 0.0)
                if raw_started > 0.0:
                    incoming_started_ts = raw_started
                meta = format_meta(
                    rec.get("delivery"),
                    avg_attempts,
                    avg_hops,
                    None,
                    (len(parts), total),
                    status=status,
                    incoming=True,
                    done=done_now,
                    received_at_ts=received_at_ts,
                    incoming_started_ts=incoming_started_ts,
                    compression_name=compression_name,
                    compression_eff_pct=compression_eff_pct,
                    compression_norm=compression_norm,
                )
                meta_data_in: Dict[str, object] = {
                    "delivery": rec.get("delivery"),
                    "attempts": avg_attempts,
                    "forward_hops": avg_hops,
                    "ack_hops": None,
                    "packets": (len(parts), total),
                    "status": status,
                    "incoming": True,
                    "done": done_now,
                    "received_at_ts": received_at_ts,
                    "incoming_started_ts": incoming_started_ts,
                    "compression_name": compression_name,
                    "compression_eff_pct": compression_eff_pct,
                    "compression_norm": compression_norm,
                }
                chat_line(
                    peer_norm,
                    full,
                    "#66d9ef",
                    meta=meta,
                    meta_data=meta_data_in,
                    msg_id=group_id,
                    replace_msg_id=group_id,
                )
                if done_now:
                    if decode_ok:
                        append_history("recv", peer_norm, group_id, full, meta_data=meta_data_in)
                    else:
                        append_history("recv_error", peer_norm, group_id, "[decode error]", "compressed_payload_decode_failed")
                    incoming_state.pop(key, None)
                    pruned = True
            if pruned:
                save_incoming_state(incoming_state)

        log_buffer: list[tuple[str, str]] = []
        for line in log_startup:
            line_norm, _ = normalize_log_text_line(line, fallback_ts=ts_local())
            log_buffer.append((line_norm, "info"))
            append_runtime_log(line_norm)

        def log_append_view(view: QtWidgets.QTextEdit, text: str, level: str) -> None:
            # Severity palette:
            # - red: critical
            # - orange: needs attention
            # - yellow: informational
            # - green: success/healthy
            if level == "error":
                color = "#f92672"
            elif level in ("warn", "key"):
                color = "#fd971f"
            elif level == "keyok":
                color = "#6be5b5"
            else:
                color = "#ffd75f"
            try:
                esc = html_escape(str(text))
            except Exception:
                esc = str(text)
            try:
                view.append(f"<span style='color:{color};'>{esc}</span>")
            except Exception:
                # Fallback to plain text if rich append fails.
                try:
                    view.append(str(text))
                except Exception:
                    pass

        def log_line(text: str, level: str = "info") -> None:
            nonlocal errors_need_ack, unseen_error_count, unseen_warn_count
            nonlocal last_error_summary, last_warn_summary, last_error_ts, last_warn_ts
            try:
                # Avoid touching Qt widgets from non-GUI threads.
                if QtCore.QThread.currentThread() != app.thread():
                    ui_emit("log", str(text))
                    return
            except Exception:
                pass
            text, body = normalize_log_text_line(text, fallback_ts=ts_local())
            now = time.time()
            if not hasattr(log_line, "_last"):
                log_line._last = {"body": "", "ts": 0.0}
            last = log_line._last
            # Suppress immediate duplicate lines (print + ui_emit of same event).
            if body and body == str(last.get("body", "")) and (now - float(last.get("ts", 0.0))) < 0.6:
                return
            log_line._last = {"body": body, "ts": now}
            lvl = str(level or "info").strip().lower()
            low = text.lower()
            if lvl == "info":
                # TRACE logs (diagnostics) get their own color in the UI.
                if "trace:" in low and "traceback" not in low:
                    lvl = "trace"
                elif "pace:" in low:
                    lvl = "pace"
                elif "health:" in low:
                    lvl = "health"
                elif "discovery:" in low:
                    lvl = "discovery"
                elif "radio:" in low:
                    lvl = "radio"
                elif "gui:" in low:
                    lvl = "gui"
                elif "queue:" in low:
                    lvl = "queue"
                if ("pinned key mismatch" in low) or ("reject invalid public key" in low):
                    lvl = "error"
                elif ("exception" in low) or ("traceback" in low):
                    # Explicit crash/exception markers only (avoid false positives from plain text).
                    lvl = "error"
                elif low.startswith("error:"):
                    lvl = "error"
                elif low.startswith("warn:"):
                    lvl = "warn"
                elif "keyok:" in low:
                    lvl = "keyok"
                elif ("key:" in low) or ("crypto:" in low):
                    lvl = "key"
            now_ts = time.time()
            if settings_log_view is None:
                if lvl == "error":
                    unseen_error_count += 1
                    last_error_summary = _alert_summary(text)
                    last_error_ts = now_ts
                elif lvl == "warn":
                    unseen_warn_count += 1
                    last_warn_summary = _alert_summary(text)
                    last_warn_ts = now_ts
            errors_need_ack = bool(unseen_error_count > 0)
            log_buffer.append((text, lvl))
            append_runtime_log(text)
            if settings_log_view is not None:
                log_append_view(settings_log_view, text, lvl)
            update_status()

        import builtins as _builtins

        def _gui_print(*args, **kwargs) -> None:
            text = " ".join(str(a) for a in args)
            if text:
                ui_emit("log", text)

        _builtins.print = _gui_print

        def format_meta(
            delivery: Optional[float],
            attempts: Optional[float],
            forward_hops: Optional[float],
            ack_hops: Optional[float],
            packets: Optional[tuple[int, int]] = None,
            status: Optional[str] = None,
            delivered_at_ts: Optional[float] = None,
            incoming: bool = False,
            done: Optional[bool] = None,
            row_time_hhmm: Optional[str] = None,
            received_at_ts: Optional[float] = None,
            sent_at_ts: Optional[float] = None,
            incoming_started_ts: Optional[float] = None,
            compression_name: Optional[str] = None,
            compression_eff_pct: Optional[float] = None,
            compression_norm: Optional[str] = None,
        ) -> str:
            return format_meta_text(
                current_lang,
                delivery,
                attempts,
                forward_hops,
                ack_hops,
                packets,
                status=status,
                delivered_at_ts=delivered_at_ts,
                incoming=incoming,
                done=done,
                row_time_hhmm=row_time_hhmm,
                received_at_ts=received_at_ts,
                sent_at_ts=sent_at_ts,
                incoming_started_ts=incoming_started_ts,
                compression_name=compression_name,
                compression_eff_pct=compression_eff_pct,
                compression_norm=compression_norm,
            )

        def format_plain_transport_meta(
            incoming: bool,
            sent_at_ts: Optional[float] = None,
            received_at_ts: Optional[float] = None,
        ) -> str:
            try:
                ts_val = float(received_at_ts if incoming else sent_at_ts)
            except Exception:
                ts_val = 0.0
            if ts_val <= 0.0:
                ts_val = time.time()
            hhmm = time.strftime("%H:%M", time.localtime(ts_val))
            is_ru = (current_lang == "ru")
            if incoming:
                return f"пришло в {hhmm}" if is_ru else f"received at {hhmm}"
            return f"отправлено в {hhmm}" if is_ru else f"sent at {hhmm}"

        def update_sent_delivery(
            dialog_id: str,
            msg_id: str,
            delivery: float,
            attempts: float,
            forward_hops: Optional[float],
            ack_hops: Optional[float],
            packets: Optional[tuple[int, int]],
        ) -> None:
            entries = chat_history.get(dialog_id, [])
            if not entries:
                return
            for i in range(len(entries) - 1, -1, -1):
                entry = entries[i]
                if not isinstance(entry, dict):
                    continue
                if entry.get("dir") != "out":
                    continue
                if entry.get("msg_id") != msg_id:
                    continue
                text = str(entry.get("text", ""))
                if len(text) >= 6 and text[5] == " ":
                    ts = text[:5]
                    msg = text[6:]
                else:
                    ts = time.strftime("%H:%M", time.localtime())
                    msg = text
                if msg.startswith("("):
                    end = msg.find(") ")
                    if end != -1:
                        msg = msg[end + 2 :]
                delivered_at_ts = None
                if packets is not None:
                    done_now, total_now = packets
                    if int(done_now) >= int(total_now):
                        delivered_at_ts = time.time()
                sent_at_ts = None
                compression_name = None
                compression_eff_pct = None
                compression_norm = None
                old_meta_data = entry.get("meta_data")
                if isinstance(old_meta_data, dict):
                    try:
                        raw_sent = float(old_meta_data.get("sent_at_ts", 0.0) or 0.0)
                    except Exception:
                        raw_sent = 0.0
                    if raw_sent > 0.0:
                        sent_at_ts = raw_sent
                    compression_name = normalize_compression_name(str(old_meta_data.get("compression_name", "") or ""))
                    try:
                        raw_eff = old_meta_data.get("compression_eff_pct")
                        if raw_eff is not None:
                            compression_eff_pct = float(raw_eff)
                    except Exception:
                        compression_eff_pct = None
                    try:
                        raw_norm = str(old_meta_data.get("compression_norm", "") or "").strip()
                        compression_norm = raw_norm.upper() if raw_norm else None
                    except Exception:
                        compression_norm = None
                entry["meta"] = format_meta(
                    delivery,
                    attempts,
                    forward_hops,
                    ack_hops,
                    packets,
                    delivered_at_ts=delivered_at_ts,
                    incoming=False,
                    done=(delivered_at_ts is not None),
                    row_time_hhmm=ts,
                    sent_at_ts=sent_at_ts,
                    compression_name=compression_name,
                    compression_eff_pct=compression_eff_pct,
                    compression_norm=compression_norm,
                )
                meta_data_out: Dict[str, object] = {
                    "delivery": delivery,
                    "attempts": attempts,
                    "forward_hops": forward_hops,
                    "ack_hops": ack_hops,
                    "incoming": False,
                    "done": (delivered_at_ts is not None),
                    "compression_name": compression_name,
                    "compression_eff_pct": compression_eff_pct,
                    "compression_norm": compression_norm,
                }
                if packets is not None:
                    meta_data_out["packets"] = (int(packets[0]), int(packets[1]))
                if delivered_at_ts is not None:
                    meta_data_out["delivered_at_ts"] = delivered_at_ts
                if sent_at_ts is not None:
                    meta_data_out["sent_at_ts"] = sent_at_ts
                entry["meta_data"] = meta_data_out
                entry["text"] = f"{ts} {msg}"
                if i == len(entries) - 1:
                    update_dialog(dialog_id, entry["text"], recv=False)
                if current_dialog == dialog_id:
                    render_chat(dialog_id)
                else:
                    refresh_list()
                if packets is not None:
                    done, total = packets
                    if int(done) >= int(total) and not entry.get("logged"):
                        append_history("sent", dialog_id, msg_id, msg, meta_data=meta_data_out)
                        entry["logged"] = True
                return

        def update_sent_failed(
            dialog_id: str,
            msg_id: str,
            reason: str,
            attempts: int,
            total: int,
        ) -> None:
            entries = chat_history.get(dialog_id, [])
            if not entries:
                return
            for i in range(len(entries) - 1, -1, -1):
                entry = entries[i]
                if not isinstance(entry, dict):
                    continue
                if entry.get("dir") != "out":
                    continue
                if entry.get("msg_id") != msg_id:
                    continue
                text = str(entry.get("text", ""))
                if len(text) >= 6 and text[5] == " ":
                    ts = text[:5]
                    msg = text[6:]
                else:
                    ts = time.strftime("%H:%M", time.localtime())
                    msg = text
                if msg.startswith("("):
                    end = msg.find(") ")
                    if end != -1:
                        msg = msg[end + 2 :]
                sent_at_ts = None
                compression_name = None
                compression_eff_pct = None
                compression_norm = None
                old_meta_data = entry.get("meta_data")
                if isinstance(old_meta_data, dict):
                    try:
                        raw_sent = float(old_meta_data.get("sent_at_ts", 0.0) or 0.0)
                    except Exception:
                        raw_sent = 0.0
                    if raw_sent > 0.0:
                        sent_at_ts = raw_sent
                    compression_name = normalize_compression_name(str(old_meta_data.get("compression_name", "") or ""))
                    try:
                        raw_eff = old_meta_data.get("compression_eff_pct")
                        if raw_eff is not None:
                            compression_eff_pct = float(raw_eff)
                    except Exception:
                        compression_eff_pct = None
                    try:
                        raw_norm = str(old_meta_data.get("compression_norm", "") or "").strip()
                        compression_norm = raw_norm.upper() if raw_norm else None
                    except Exception:
                        compression_norm = None
                entry["meta"] = format_meta(
                    None,
                    float(attempts),
                    None,
                    None,
                    (0, int(max(1, total))),
                    status=reason,
                    sent_at_ts=sent_at_ts,
                    compression_name=compression_name,
                    compression_eff_pct=compression_eff_pct,
                    compression_norm=compression_norm,
                )
                entry["meta_data"] = {
                    "delivery": None,
                    "attempts": float(attempts),
                    "forward_hops": None,
                    "ack_hops": None,
                    "packets": (0, int(max(1, total))),
                    "status": reason,
                    "incoming": False,
                    "done": False,
                    "compression_name": compression_name,
                    "compression_eff_pct": compression_eff_pct,
                    "compression_norm": compression_norm,
                }
                if sent_at_ts is not None:
                    entry["meta_data"]["sent_at_ts"] = sent_at_ts
                entry["text"] = f"{ts} {msg}"
                if i == len(entries) - 1:
                    update_dialog(dialog_id, entry["text"], recv=False)
                if current_dialog == dialog_id:
                    render_chat(dialog_id)
                else:
                    refresh_list()
                return

        def peer_used_meshtalk(peer_norm: str) -> bool:
            peer_id = norm_id_for_filename(peer_norm)
            if not peer_id:
                return False
            now_ts = time.time()
            try:
                pinned_pub_exists = os.path.isfile(os.path.join(keydir, f"{peer_id}.pub"))
            except Exception:
                pinned_pub_exists = False
            st = peer_states.get(peer_id)
            if st:
                try:
                    seen_ts = float(getattr(st, "last_seen_ts", 0.0) or 0.0)
                    offline_ts = float(getattr(st, "app_offline_ts", 0.0) or 0.0)
                    if offline_ts > 0.0 and (float(now_ts) - offline_ts) <= float(CONTACT_STALE_SECONDS) and seen_ts <= offline_ts:
                        return False
                    key_ready_now = bool(getattr(st, "key_ready", False))
                    if (key_ready_now or pinned_pub_exists) and seen_ts > 0.0 and (float(now_ts) - seen_ts) <= float(CONTACT_STALE_SECONDS):
                        return True
                except Exception:
                    pass
            rec = peer_meta.get(peer_id, {})
            if isinstance(rec, dict):
                try:
                    seen_ts = float(rec.get("last_seen_ts", 0.0) or 0.0)
                    offline_ts = float(rec.get("app_offline_ts", 0.0) or 0.0)
                    if offline_ts > 0.0 and (float(now_ts) - offline_ts) <= float(CONTACT_STALE_SECONDS) and seen_ts <= offline_ts:
                        return False
                    if pinned_pub_exists and seen_ts > 0.0 and (float(now_ts) - seen_ts) <= float(CONTACT_STALE_SECONDS):
                        return True
                except Exception:
                    pass
            return False

        def send_plain_meshtastic_text(peer_norm: str, text: str) -> bool:
            peer_id = norm_id_for_filename(peer_norm)
            if not peer_id or not radio_ready or interface is None:
                return False
            try:
                pkt = interface.sendText(
                    text,
                    destinationId=wire_id_from_norm(peer_id),
                    wantAck=False,
                    channelIndex=(args.channel if args.channel is not None else 0),
                )
            except Exception as ex:
                log_line(f"{ts_local()} SENDSTD: failed -> {peer_id} ({type(ex).__name__}: {ex})", "warn")
                return False
            msg_id = f"mtxt:{os.urandom(4).hex()}"
            try:
                if isinstance(pkt, dict):
                    pid = pkt.get("id")
                    if isinstance(pid, int):
                        msg_id = f"mtxt:{int(pid) & 0xFFFFFFFF:08x}"
            except Exception:
                pass
            sent_at_ts = time.time()
            meta_data_out: Dict[str, object] = {
                "incoming": False,
                "done": True,
                "sent_at_ts": sent_at_ts,
                "transport": "meshtastic_text",
            }
            chat_line(
                peer_id,
                text,
                "#a6e22e",
                outgoing=True,
                msg_id=msg_id,
                meta=format_plain_transport_meta(incoming=False, sent_at_ts=sent_at_ts),
                meta_data=meta_data_out,
            )
            append_history("sent", peer_id, msg_id, text, meta_data=meta_data_out)
            try:
                preview = " ".join(str(text or "").split())
            except Exception:
                preview = ""
            if len(preview) > 120:
                preview = preview[:117] + "..."
            log_line(
                f"{ts_local()} SENDSTD: {msg_id} -> {peer_id} port=TEXT_MESSAGE_APP text={preview!r}",
                "info",
            )
            return True

        def send_plain_meshtastic_broadcast(text: str) -> bool:
            if not radio_ready or interface is None:
                return False
            try:
                pkt = interface.sendText(
                    text,
                    destinationId=meshtastic.BROADCAST_ADDR,
                    wantAck=False,
                    channelIndex=(args.channel if args.channel is not None else 0),
                )
            except Exception as ex:
                log_line(f"{ts_local()} SENDSTD: failed -> Primary ({type(ex).__name__}: {ex})", "warn")
                return False
            msg_id = f"mtxt:{os.urandom(4).hex()}"
            try:
                if isinstance(pkt, dict):
                    pid = pkt.get("id")
                    if isinstance(pid, int):
                        msg_id = f"mtxt:{int(pid) & 0xFFFFFFFF:08x}"
            except Exception:
                pass
            sent_at_ts = time.time()
            meta_data_out: Dict[str, object] = {
                "incoming": False,
                "done": True,
                "sent_at_ts": sent_at_ts,
                "transport": "meshtastic_text",
            }
            chat_line(
                "group:Primary",
                text,
                "#a6e22e",
                outgoing=True,
                msg_id=msg_id,
                meta=format_plain_transport_meta(incoming=False, sent_at_ts=sent_at_ts),
                meta_data=meta_data_out,
            )
            append_history("sent", "group:Primary", msg_id, text, meta_data=meta_data_out)
            try:
                preview = " ".join(str(text or "").split())
            except Exception:
                preview = ""
            if len(preview) > 120:
                preview = preview[:117] + "..."
            log_line(
                f"{ts_local()} SENDSTD: {msg_id} -> Primary port=TEXT_MESSAGE_APP text={preview!r}",
                "info",
            )
            return True

        def send_message() -> None:
            if not radio_ready:
                QtWidgets.QMessageBox.information(win, "meshTalk", "Waiting for radio...")
                return
            text = msg_entry.toPlainText().strip()
            if not text:
                return
            msg_entry.clear()
            if not current_dialog:
                QtWidgets.QMessageBox.information(win, "meshTalk", tr("select_dialog"))
                return
            if current_dialog.startswith("group:"):
                name = current_dialog[6:]
                if name.strip().lower() == "primary":
                    log_line(f"{ts_local()} ROUTE: Primary -> meshtastic_text broadcast", "info")
                    if not send_plain_meshtastic_broadcast(text):
                        QtWidgets.QMessageBox.warning(win, "meshTalk", "Meshtastic broadcast send failed.")
                    return
                queued_ok = 0
                for peer_norm in sorted(groups.get(name, set())):
                    if peer_used_meshtalk(peer_norm):
                        log_line(f"{ts_local()} ROUTE: {peer_norm} -> meshTalk", "info")
                        if queue_message(peer_norm, text) is not None:
                            queued_ok += 1
                    else:
                        log_line(f"{ts_local()} ROUTE: {peer_norm} -> meshtastic_text", "info")
                        if send_plain_meshtastic_text(peer_norm, text):
                            queued_ok += 1
                if queued_ok <= 0:
                    QtWidgets.QMessageBox.information(win, "meshTalk", tr("group_send_none"))
                    return
                chat_line(current_dialog, text, "#fd971f", outgoing=True, meta=format_meta(None, 0, None, None, None))
                append_history("sent", current_dialog, os.urandom(8).hex(), text)
                return
            if not peer_used_meshtalk(current_dialog):
                log_line(f"{ts_local()} ROUTE: {current_dialog} -> meshtastic_text", "info")
                if not send_plain_meshtastic_text(current_dialog, text):
                    QtWidgets.QMessageBox.warning(win, "meshTalk", "Meshtastic text send failed.")
                return
            log_line(f"{ts_local()} ROUTE: {current_dialog} -> meshTalk", "info")
            res = queue_message(current_dialog, text)
            if res is None:
                return
            group_id, total, cmp_name, cmp_eff_pct, cmp_norm = res
            sent_at_ts = time.time()
            chat_line(
                current_dialog,
                text,
                "#a6e22e",
                outgoing=True,
                msg_id=group_id,
                meta=format_meta(
                    None,
                    0,
                    None,
                    None,
                    (0, total),
                    sent_at_ts=sent_at_ts,
                    compression_name=cmp_name,
                    compression_eff_pct=cmp_eff_pct,
                    compression_norm=cmp_norm,
                ),
                meta_data={
                    "delivery": None,
                    "attempts": 0,
                    "forward_hops": None,
                    "ack_hops": None,
                    "packets": (0, int(total)),
                    "incoming": False,
                    "done": False,
                    "sent_at_ts": sent_at_ts,
                    "compression_name": cmp_name,
                    "compression_eff_pct": cmp_eff_pct,
                    "compression_norm": cmp_norm,
                },
            )

        def update_status() -> None:
            nonlocal unseen_error_count, unseen_warn_count, errors_need_ack
            nonlocal last_error_ts, last_warn_ts
            now = time.time()
            # Auto de-escalation windows:
            # error -> warn after 5 min without new errors; clear stale alerts after 15 min.
            error_to_warn_s = 5.0 * 60.0
            clear_stale_s = 15.0 * 60.0
            if unseen_error_count > 0 and last_error_ts > 0.0 and (now - last_error_ts) >= clear_stale_s:
                unseen_error_count = 0
            if unseen_warn_count > 0 and last_warn_ts > 0.0 and (now - last_warn_ts) >= clear_stale_s:
                unseen_warn_count = 0

            errors_need_ack = bool(unseen_error_count > 0)
            # Base header color follows only connection/init state.
            if radio_ready and not initializing:
                set_header_status("ok")
            else:
                set_header_status("init")
            _update_alert_indicator()

        def dialog_has_dynamic_pending(dialog_id: Optional[str]) -> bool:
            if not dialog_id:
                return False
            for entry in chat_history.get(dialog_id, []):
                if not isinstance(entry, dict):
                    continue
                meta_data = entry.get("meta_data")
                if not isinstance(meta_data, dict):
                    continue
                if meta_data.get("status") is not None:
                    continue
                if meta_data.get("delivered_at_ts") is not None:
                    continue
                if entry.get("dir") == "out":
                    try:
                        sent_at_ts = float(meta_data.get("sent_at_ts", 0.0) or 0.0)
                    except Exception:
                        sent_at_ts = 0.0
                    if sent_at_ts > 0.0:
                        return True
                elif bool(meta_data.get("incoming", False)) and not bool(meta_data.get("done", False)):
                    try:
                        incoming_started_ts = float(meta_data.get("incoming_started_ts", 0.0) or 0.0)
                    except Exception:
                        incoming_started_ts = 0.0
                    if incoming_started_ts > 0.0:
                        return True
            return False

        def refresh_dynamic_pending_meta() -> None:
            if not current_dialog:
                return
            if not dialog_has_dynamic_pending(current_dialog):
                return
            try:
                sb = chat_text.verticalScrollBar()
                if sb is not None and sb.value() < max(0, sb.maximum() - 4):
                    return
            except Exception:
                pass
            render_chat(current_dialog)

        def update_status_labels(l1: QtWidgets.QLabel, l2: QtWidgets.QLabel, l3: QtWidgets.QLabel) -> None:
            now = time.time()
            peers_known = len(known_peers)
            peers_tracked = len(tracked_peers)
            pending_count = sum(len(v) for v in pending_by_peer.values())
            last_act = max(0, int(now - last_activity_ts))
            last_key = "-" if last_key_sent_ts <= 0 else f"{int(now - last_key_sent_ts)}s ago"
            selected = current_dialog or "-"
            l1.setText(f"Port: {args.port} | Self: {self_id}")
            l2.setText(f"Peers: known {peers_known}, tracked {peers_tracked}, pending {pending_count} | Selected: {selected}")
            l3.setText(f"Last activity: {last_act}s ago | Last key request: {last_key}")

        def load_history() -> None:
            if not os.path.isfile(HISTORY_FILE):
                return
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()[-2000:]
            except Exception:
                return
            seen_ids: set[tuple[str, str, str, str]] = set()
            for line in lines:
                parsed = parse_history_record_line(line)
                if parsed is None:
                    continue
                ts_part, direction, peer_id, msg_id, text, meta_data = parsed
                if direction not in ("recv", "sent"):
                    continue
                peer_norm = norm_id_for_filename(peer_id)
                key = (peer_norm, msg_id, direction, text)
                if msg_id and key in seen_ids:
                    continue
                if msg_id:
                    seen_ids.add(key)
                if peer_id.startswith("group:") and peer_id[6:] not in groups and peer_id.lower() != "group:primary":
                    continue
                time_only = ts_part.split(" ")[1][:5] if " " in ts_part else ts_part[:5]
                dialog_id = peer_id if peer_id.startswith("group:") else peer_norm
                dir_flag = "out" if direction in ("send", "sent") else "in"
                entry = {"text": f"{time_only} {text}", "dir": dir_flag}
                if msg_id:
                    entry["msg_id"] = msg_id
                if isinstance(meta_data, dict):
                    entry["meta_data"] = dict(meta_data)
                chat_history.setdefault(dialog_id, []).append(entry)
                update_dialog(dialog_id, text, recv=(dir_flag == "in"))

        initializing = True
        init_step = 0
        last_init_label_ts = 0.0

        def process_ui_events() -> None:
            nonlocal init_step, last_init_label_ts, initializing
            nonlocal current_lang, verbose_log, runtime_log_file, auto_pacing, last_pacing_save_ts, pinned_dialogs, hidden_contacts, groups
            nonlocal security_policy
            nonlocal session_rekey_enabled
            nonlocal contacts_visibility
            nonlocal current_dialog, dialogs, chat_history, list_index
            nonlocal discovery_send, discovery_reply
            nonlocal incoming_state
            nonlocal interface, self_id, self_id_raw, radio_ready, known_peers, peer_states, peer_names
            nonlocal initial_port_arg
            nonlocal clear_pending_on_switch, last_loaded_profile
            nonlocal peer_meta_dirty
            if initializing:
                now = time.time()
                if (now - last_init_label_ts) >= 0.5:
                    init_step = (init_step + 1) % 3
                    dots = "." * (init_step + 1)
                    chat_label.setText(f"Initializing{dots}")
                    last_init_label_ts = now
            while True:
                try:
                    evt, payload = ui_events.get_nowait()
                except queue.Empty:
                    break
                if evt == "names_update":
                    refresh_list()
                if evt == "peer_update":
                    update_peer_meta(str(payload) if isinstance(payload, str) else None)
                    refresh_list()
                elif evt == "config_reload":
                    cfg_new = payload if isinstance(payload, dict) else {}
                    cfg.clear()
                    cfg.update(cfg_new)
                    cfg["port"] = args.port
                    current_lang = str(cfg.get("lang", current_lang)).lower()
                    if current_lang not in ("ru", "en"):
                        current_lang = "ru"
                    verbose_log = bool(cfg.get("log_verbose", verbose_log))
                    runtime_log_file = bool(cfg.get("runtime_log_file", runtime_log_file))
                    _STORAGE.set_runtime_log_enabled(runtime_log_file)
                    auto_pacing = bool(cfg.get("auto_pacing", auto_pacing))
                    try:
                        args.auto_pacing = bool(auto_pacing)
                    except Exception:
                        pass
                    session_rekey_enabled = bool(cfg.get("session_rekey", session_rekey_enabled))
                    security_policy = str(cfg.get("security_key_rotation_policy", security_policy) or "auto").strip().lower()
                    if security_policy not in ("auto", "strict", "always"):
                        security_policy = "auto"
                    legacy_discovery = cfg.get("discovery_enabled", None)
                    if "discovery_send" in cfg:
                        discovery_send = bool(cfg.get("discovery_send"))
                    elif legacy_discovery is not None:
                        discovery_send = bool(legacy_discovery)
                    else:
                        discovery_send = bool(discovery_send)
                    if "discovery_reply" in cfg:
                        discovery_reply = bool(cfg.get("discovery_reply"))
                    elif legacy_discovery is not None:
                        discovery_reply = bool(legacy_discovery)
                    else:
                        discovery_reply = bool(discovery_reply)
                    clear_pending_on_switch = bool(cfg.get("clear_pending_on_switch", True))
                    contacts_visibility = str(cfg.get("contacts_visibility", contacts_visibility) or "all").strip().lower()
                    if contacts_visibility not in ("all", "online", "app", "device"):
                        contacts_visibility = "all"
                    theme_cfg = str(cfg.get("ui_theme", current_theme) or "ubuntu_style").strip().lower()
                    if theme_cfg not in THEME_STYLES:
                        theme_cfg = "ubuntu_style"
                    if theme_cfg != current_theme:
                        apply_theme(theme_cfg)
                    args.retry_seconds = int(cfg.get("retry_seconds", args.retry_seconds))
                    args.max_seconds = int(cfg.get("max_seconds", args.max_seconds))
                    args.max_bytes = int(cfg.get("max_bytes", args.max_bytes))
                    args.rate_seconds = int(float(cfg.get("rate_seconds", args.rate_seconds)))
                    try:
                        args.parallel_sends = max(
                            1,
                            int(cfg.get("parallel_sends", getattr(args, "parallel_sends", 1))),
                        )
                    except Exception:
                        args.parallel_sends = 1
                    pinned_dialogs = set(cfg.get("pinned_dialogs", []))
                    hidden_contacts = set(cfg.get("hidden_contacts", []))
                    peer_meta_dirty = False
                    peer_meta.clear()
                    peer_meta_raw = cfg.get("peer_meta", {})
                    if isinstance(peer_meta_raw, dict):
                        for peer_id_raw, meta_raw in peer_meta_raw.items():
                            if not isinstance(peer_id_raw, str) or not isinstance(meta_raw, dict):
                                continue
                            peer_norm = norm_id_for_filename(peer_id_raw)
                            if not peer_norm:
                                continue
                            rec: Dict[str, float] = {}
                            try:
                                ls = meta_raw.get("last_seen_ts")
                                if isinstance(ls, (int, float)) and float(ls) > 0.0:
                                    rec["last_seen_ts"] = float(ls)
                            except Exception:
                                pass
                            try:
                                ds = meta_raw.get("device_seen_ts")
                                if isinstance(ds, (int, float)) and float(ds) > 0.0:
                                    rec["device_seen_ts"] = float(ds)
                            except Exception:
                                pass
                            try:
                                kc = meta_raw.get("key_confirmed_ts")
                                if isinstance(kc, (int, float)) and float(kc) > 0.0:
                                    rec["key_confirmed_ts"] = float(kc)
                            except Exception:
                                pass
                            if rec:
                                peer_meta[peer_norm] = rec
                                st = peer_states.get(peer_norm)
                                if st:
                                    if float(getattr(st, "last_seen_ts", 0.0) or 0.0) <= 0.0 and rec.get("last_seen_ts"):
                                        st.last_seen_ts = float(rec["last_seen_ts"])
                                    if float(getattr(st, "device_seen_ts", 0.0) or 0.0) <= 0.0 and rec.get("device_seen_ts"):
                                        st.device_seen_ts = float(rec["device_seen_ts"])
                                    if float(getattr(st, "key_confirmed_ts", 0.0) or 0.0) <= 0.0 and rec.get("key_confirmed_ts"):
                                        st.key_confirmed_ts = float(rec["key_confirmed_ts"])
                    groups_cfg_local = cfg.get("groups", {}) if isinstance(cfg.get("groups", {}), dict) else {}
                    groups.clear()
                    for k, v in groups_cfg_local.items():
                        if isinstance(k, str) and isinstance(v, list):
                            groups[k] = set(v)
                    dialogs.clear()
                    chat_history.clear()
                    list_index.clear()
                    current_dialog = None
                    tracked_peers.clear()
                    try:
                        with pending_lock:
                            pending_by_peer.clear()
                            profile_changed = (last_loaded_profile is not None and self_id != last_loaded_profile)
                            if clear_pending_on_switch and profile_changed:
                                save_state(pending_by_peer)
                                ui_emit("log", f"{ts_local()} QUEUE: cleared on profile switch")
                            else:
                                pending_by_peer.update(load_state(default_peer=peer_id_norm))
                    except Exception:
                        pass
                    last_loaded_profile = self_id or None
                    incoming_state = load_incoming_state()
                    load_history()
                    restore_outgoing_state()
                    restore_incoming_state()
                    apply_language()
                    refresh_list()
                    render_chat(current_dialog)
                elif evt == "pacing_update":
                    if isinstance(payload, (tuple, list)) and len(payload) >= 2:
                        try:
                            new_rate = max(1, int(payload[0]))
                            new_parallel = max(1, int(payload[1]))
                            cfg["rate_seconds"] = new_rate
                            cfg["parallel_sends"] = new_parallel
                            # If Settings dialog is open, reflect the tuned values live.
                            try:
                                if (
                                    settings_rate_edit is not None
                                    and settings_parallel_edit is not None
                                    and (settings_auto_pacing_cb is None or settings_auto_pacing_cb.isChecked())
                                ):
                                    settings_rate_edit.setText(str(new_rate))
                                    settings_parallel_edit.setText(str(new_parallel))
                            except Exception:
                                pass
                            now_save = time.time()
                            if auto_pacing and ((now_save - last_pacing_save_ts) >= 60.0):
                                last_pacing_save_ts = now_save
                                save_gui_config()
                        except Exception:
                            pass
                elif evt == "trace_update":
                    if isinstance(payload, (tuple, list)) and len(payload) >= 3:
                        peer_norm = str(payload[0] or "")
                        trace_id = str(payload[1] or "")
                        try:
                            attempts_val = float(payload[2])
                        except Exception:
                            attempts_val = 0.0
                        if not peer_norm or not trace_id:
                            continue
                        # Update the outgoing "Trace request" status line with current attempt count.
                        sent_at_ts = None
                        old_meta_data = None
                        entries = chat_history.get(peer_norm, [])
                        for entry in reversed(entries):
                            if isinstance(entry, dict) and entry.get("msg_id") == trace_id:
                                old_meta_data = entry.get("meta_data")
                                break
                        if isinstance(old_meta_data, dict):
                            try:
                                raw_sent = float(old_meta_data.get("sent_at_ts", 0.0) or 0.0)
                            except Exception:
                                raw_sent = 0.0
                            if raw_sent > 0.0:
                                sent_at_ts = raw_sent
                        new_meta_data: Dict[str, object] = {
                            "delivery": None,
                            "attempts": float(max(0.0, attempts_val)),
                            "forward_hops": None,
                            "ack_hops": None,
                            "incoming": False,
                            "done": False,
                        }
                        if sent_at_ts is not None:
                            new_meta_data["sent_at_ts"] = sent_at_ts
                        meta = format_meta(
                            None,
                            float(max(0.0, attempts_val)),
                            None,
                            None,
                            None,
                            sent_at_ts=sent_at_ts,
                        )
                        chat_line(
                            peer_norm,
                            tr("trace_request"),
                            "#fd971f",
                            outgoing=True,
                            msg_id=trace_id,
                            meta=meta,
                            meta_data=new_meta_data,
                            replace_msg_id=trace_id,
                            keep_ts_on_replace=True,
                        )
                elif evt == "trace_done":
                    if isinstance(payload, (tuple, list)) and len(payload) >= 4:
                        peer_norm = str(payload[0] or "")
                        trace_id = str(payload[1] or "")
                        meta_data = payload[2] if isinstance(payload[2], dict) else None
                        resp_text = str(payload[3] or "")
                        if not peer_norm or not trace_id:
                            continue

                        def as_float(val: object) -> Optional[float]:
                            if val is None:
                                return None
                            try:
                                return float(val)
                            except Exception:
                                return None

                        meta = ""
                        if isinstance(meta_data, dict):
                            status_raw = meta_data.get("status")
                            status = str(status_raw).strip() if status_raw is not None else None
                            done_raw = meta_data.get("done")
                            done = bool(done_raw) if done_raw is not None else None
                            meta = format_meta(
                                as_float(meta_data.get("delivery")),
                                as_float(meta_data.get("attempts")),
                                as_float(meta_data.get("forward_hops")),
                                as_float(meta_data.get("ack_hops")),
                                None,
                                status=status or None,
                                delivered_at_ts=as_float(meta_data.get("delivered_at_ts")),
                                incoming=False,
                                done=done,
                                sent_at_ts=as_float(meta_data.get("sent_at_ts")),
                            )
                        # Finalize outgoing request bubble (keep text as "Trace request").
                        chat_line(
                            peer_norm,
                            tr("trace_request"),
                            "#fd971f",
                            outgoing=True,
                            msg_id=trace_id,
                            meta=meta,
                            meta_data=meta_data,
                            replace_msg_id=trace_id,
                            keep_ts_on_replace=True,
                        )
                        # Keep traceroute request in persistent chat history.
                        # We log it only once, on completion, so it includes final status/attempts/hops.
                        try:
                            entries = chat_history.get(peer_norm, [])
                            for entry in reversed(entries):
                                if isinstance(entry, dict) and entry.get("msg_id") == trace_id:
                                    if not entry.get("logged"):
                                        append_history(
                                            "sent",
                                            peer_norm,
                                            trace_id,
                                            tr("trace_request"),
                                            meta_data=(dict(meta_data) if isinstance(meta_data, dict) else None),
                                        )
                                        entry["logged"] = True
                                    break
                        except Exception:
                            pass
                        if resp_text:
                            # Add incoming response bubble with traceroute output + node names/ids.
                            resp_id = f"{trace_id}:resp"
                            if not history_has_msg(peer_norm, resp_id):
                                received_at_ts = as_float(meta_data.get("delivered_at_ts")) if isinstance(meta_data, dict) else None
                                if received_at_ts is None:
                                    received_at_ts = time.time()
                                forward_hops = as_float(meta_data.get("forward_hops")) if isinstance(meta_data, dict) else None
                                ack_hops = as_float(meta_data.get("ack_hops")) if isinstance(meta_data, dict) else None
                                resp_meta_data: Dict[str, object] = {
                                    "delivery": None,
                                    "attempts": None,
                                    "forward_hops": forward_hops,
                                    "ack_hops": ack_hops,
                                    "incoming": True,
                                    "done": True,
                                    "received_at_ts": received_at_ts,
                                }
                                meta_resp = format_meta(
                                    None,
                                    None,
                                    forward_hops,
                                    ack_hops,
                                    None,
                                    incoming=True,
                                    done=True,
                                    received_at_ts=received_at_ts,
                                )
                                chat_line(
                                    peer_norm,
                                    resp_text,
                                    "#66d9ef",
                                    outgoing=False,
                                    msg_id=resp_id,
                                    meta=meta_resp,
                                    meta_data=resp_meta_data,
                                )
                                # Keep traceroute output in persistent chat history.
                                try:
                                    entries = chat_history.get(peer_norm, [])
                                    for entry in reversed(entries):
                                        if isinstance(entry, dict) and entry.get("msg_id") == resp_id:
                                            if not entry.get("logged"):
                                                append_history(
                                                    "recv",
                                                    peer_norm,
                                                    resp_id,
                                                    resp_text,
                                                    meta_data=resp_meta_data,
                                                )
                                                entry["logged"] = True
                                            break
                                except Exception:
                                    pass
                elif evt == "trace_result":
                    # Legacy event shape (older builds); keep best-effort behavior.
                    if isinstance(payload, (tuple, list)) and len(payload) >= 2:
                        peer_norm = str(payload[0] or "")
                        text = str(payload[1] or "")
                        if peer_norm and text:
                            chat_line(peer_norm, text, "#66d9ef", outgoing=False)
                elif evt == "recv":
                    from_id = ""
                    text = ""
                    fwd_hops = None
                    delivery = None
                    group_id = ""
                    part = 1
                    total = 1
                    attempt_in = None
                    chunk_b64 = None
                    compression_flag = 0
                    legacy_codec = None
                    payload_cmp = "none"
                    compact_wire = False
                    if isinstance(payload, tuple) and len(payload) >= 8:
                        from_id = payload[0]
                        text = payload[1]
                        fwd_hops = payload[2]
                        delivery = payload[3]
                        group_id = payload[4]
                        part = payload[5]
                        total = payload[6]
                        attempt_in = payload[7]
                        if len(payload) >= 9:
                            chunk_b64 = payload[8]
                        if len(payload) >= 13:
                            compression_flag = int(payload[9] or 0)
                            legacy_codec = payload[10]
                            payload_cmp = str(payload[11] or "none")
                            compact_wire = bool(payload[12])
                        elif len(payload) == 12:
                            compression_flag = int(payload[9] or 0)
                            legacy_codec = payload[10]
                            payload_cmp = str(payload[11] or "none")
                        elif len(payload) == 11:
                            legacy_codec = payload[9]
                            compact_wire = bool(payload[10])
                            payload_cmp = str(legacy_codec or "none")
                        else:
                            extra = list(payload[9:])
                            if extra:
                                for item in extra:
                                    if isinstance(item, bool):
                                        compact_wire = item
                                        continue
                                    if isinstance(item, (int, float)) and int(item) in (0, 1):
                                        compression_flag = int(item)
                                        continue
                                    if isinstance(item, str):
                                        low = item.lower().strip()
                                        if low in ("none", "mc", "deflate", "zlib", "bz2", "lzma"):
                                            payload_cmp = low
                                            if low in ("deflate", "zlib", "bz2", "lzma"):
                                                legacy_codec = low
                                        else:
                                            legacy_codec = item
                    else:
                        continue
                    peer_norm = norm_id_for_filename(from_id)
                    update_peer_meta(peer_norm)
                    if peer_norm:
                        recv_now_ts = time.time()
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
                        save_incoming_state(incoming_state)
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
                        done_now = (len(rec["parts"]) >= int(total))
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
                                rec_received_ts = time.time()
                                rec["received_at_ts"] = rec_received_ts
                                incoming_state[key] = rec
                                save_incoming_state(incoming_state)
                        meta = format_meta(
                            rec.get("delivery"),
                            avg_attempts,
                            avg_hops,
                            None,
                            (len(rec["parts"]), int(total)),
                            status=status,
                            incoming=True,
                            done=done_now,
                            received_at_ts=rec_received_ts,
                            incoming_started_ts=float(rec.get("incoming_started_ts", recv_now_ts) or recv_now_ts),
                            compression_name=compression_name,
                            compression_eff_pct=compression_eff_pct,
                            compression_norm=compression_norm,
                        )
                        meta_data_in: Dict[str, object] = {
                            "delivery": rec.get("delivery"),
                            "attempts": avg_attempts,
                            "forward_hops": avg_hops,
                            "ack_hops": None,
                            "packets": (len(rec["parts"]), int(total)),
                            "status": status,
                            "incoming": True,
                            "done": done_now,
                            "received_at_ts": rec_received_ts,
                            "incoming_started_ts": float(rec.get("incoming_started_ts", recv_now_ts) or recv_now_ts),
                            "compression_name": compression_name,
                            "compression_eff_pct": compression_eff_pct,
                            "compression_norm": compression_norm,
                        }
                        chat_line(
                            peer_norm,
                            full,
                            "#66d9ef",
                            meta=meta,
                            meta_data=meta_data_in,
                            msg_id=group_id,
                            replace_msg_id=group_id,
                        )
                        if done_now:
                            if decode_ok:
                                append_history("recv", peer_norm, group_id, full, meta_data=meta_data_in)
                            else:
                                append_history("recv_error", peer_norm, group_id, "[decode error]", "compressed_payload_decode_failed")
                            incoming_state.pop(key, None)
                            save_incoming_state(incoming_state)
                elif evt == "recv_plain":
                    if isinstance(payload, (tuple, list)) and len(payload) >= 3:
                        peer_norm = norm_id_for_filename(str(payload[0] or ""))
                        text_plain = str(payload[1] or "")
                        msg_id_plain = str(payload[2] or "")
                        dialog_id_plain = peer_norm
                        if len(payload) >= 4:
                            try:
                                did = str(payload[3] or "").strip()
                            except Exception:
                                did = ""
                            if did:
                                dialog_id_plain = did
                        if peer_norm and text_plain and msg_id_plain and not history_has_msg(dialog_id_plain, msg_id_plain):
                            update_peer_meta(peer_norm)
                            recv_ts = time.time()
                            meta_data_in: Dict[str, object] = {
                                "incoming": True,
                                "done": True,
                                "received_at_ts": recv_ts,
                                "transport": "meshtastic_text",
                                "from_peer": peer_norm,
                            }
                            chat_line(
                                dialog_id_plain,
                                text_plain,
                                "#66d9ef",
                                meta=format_plain_transport_meta(incoming=True, received_at_ts=recv_ts),
                                meta_data=meta_data_in,
                                msg_id=msg_id_plain,
                            )
                            append_history("recv", dialog_id_plain, msg_id_plain, text_plain, meta_data=meta_data_in)
                            try:
                                preview = " ".join(str(text_plain or "").split())
                            except Exception:
                                preview = ""
                            if len(preview) > 120:
                                preview = preview[:117] + "..."
                            log_line(
                                f"{ts_local()} RECVSTD: {msg_id_plain} <- {peer_norm} via {dialog_id_plain} port=TEXT_MESSAGE_APP text={preview!r}",
                                "info",
                            )
                elif evt == "queued":
                    if isinstance(payload, tuple) and payload:
                        peer_norm = str(payload[0] or "")
                        if len(payload) >= 5:
                            group_id = str(payload[1] or "")
                            try:
                                nbytes = int(payload[2] or 0)
                            except Exception:
                                nbytes = 0
                            try:
                                parts = int(payload[3] or 0)
                            except Exception:
                                parts = 0
                            cmp_label = str(payload[4] or "")
                            log_line(f"QUEUE -> {peer_norm}: id={group_id} parts={parts} bytes={nbytes} cmp={cmp_label}", "info")
                        elif len(payload) >= 2:
                            # Legacy payload: never log message text.
                            text_legacy = str(payload[1] or "")
                            log_line(
                                f"QUEUE -> {peer_norm}: (redacted) bytes={len(text_legacy.encode('utf-8'))}",
                                "info",
                            )
                elif evt == "ack":
                    peer_norm, group_id, delivery, attempts, total, fwd_hops, ack_hops = payload
                    update_peer_meta(str(peer_norm) if isinstance(peer_norm, str) else None)
                    if not hasattr(process_ui_events, "_outgoing"):
                        process_ui_events._outgoing = {}
                    outgoing = process_ui_events._outgoing
                    rec = outgoing.get(group_id) or {
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
                    rec["acked"] += 1
                    rec["attempts_sum"] = float(rec.get("attempts_sum", 0.0)) + float(attempts)
                    rec["delivery"] = delivery
                    if fwd_hops is not None:
                        rec["fwd_sum"] = float(rec.get("fwd_sum", 0.0)) + float(fwd_hops)
                        rec["fwd_n"] = int(rec.get("fwd_n", 0)) + 1
                    if ack_hops is not None:
                        rec["ack_sum"] = float(rec.get("ack_sum", 0.0)) + float(ack_hops)
                        rec["ack_n"] = int(rec.get("ack_n", 0)) + 1
                    outgoing[group_id] = rec
                    avg_attempts = None
                    if rec.get("acked", 0):
                        avg_attempts = float(rec.get("attempts_sum", 0.0)) / float(rec.get("acked", 1))
                    avg_fwd = None
                    if rec.get("fwd_n", 0):
                        avg_fwd = float(rec.get("fwd_sum", 0.0)) / float(rec.get("fwd_n", 1))
                    avg_ack = None
                    if rec.get("ack_n", 0):
                        avg_ack = float(rec.get("ack_sum", 0.0)) / float(rec.get("ack_n", 1))
                    update_sent_delivery(
                        peer_norm,
                        group_id,
                        float(rec["delivery"]),
                        avg_attempts,
                        avg_fwd,
                        avg_ack,
                        (int(rec["acked"]), int(rec["total"])),
                    )
                    if rec["acked"] >= rec["total"]:
                        outgoing.pop(group_id, None)
                elif evt == "failed":
                    peer_norm, group_id, reason, attempts, total = payload
                    update_peer_meta(str(peer_norm) if isinstance(peer_norm, str) else None)
                    update_sent_failed(str(peer_norm), str(group_id), str(reason), int(attempts), int(total))
                elif evt == "log":
                    log_line(str(payload), "info")
                elif evt == "key_conflict":
                    if isinstance(payload, (tuple, list)) and len(payload) >= 3:
                        peer_norm = norm_id_for_filename(str(payload[0] or ""))
                        old_fp = str(payload[1] or "")
                        new_fp = str(payload[2] or "")
                        if re.fullmatch(r"[0-9a-fA-F]{8}", peer_norm):
                            conflict_sig = f"{old_fp}:{new_fp}"
                            ignore_rec = key_conflict_ignored.get(peer_norm)
                            try:
                                ignore_sig = str((ignore_rec or {}).get("sig", "") or "")
                                ignore_until = float((ignore_rec or {}).get("until", 0.0) or 0.0)
                            except Exception:
                                ignore_sig = ""
                                ignore_until = 0.0
                            now_ts = time.time()
                            if ignore_sig and now_ts >= ignore_until:
                                key_conflict_ignored.pop(peer_norm, None)
                                ignore_sig = ""
                            if ignore_sig and (ignore_sig == conflict_sig) and now_ts < ignore_until:
                                last_hidden_log = float(key_conflict_hidden_log_ts.get(peer_norm, 0.0) or 0.0)
                                if (now_ts - last_hidden_log) >= 10.0:
                                    left = int(max(1.0, ignore_until - now_ts))
                                    ui_emit(
                                        "log",
                                        f"{ts_local()} KEY: conflict hidden peer={peer_norm} reason=user_ignore wait={left}s",
                                    )
                                    key_conflict_hidden_log_ts[peer_norm] = now_ts
                            else:
                                _set_key_conflict_header(peer_norm, conflict_sig)
                elif evt == "self_update":
                    update_status()
                elif evt == "radio_wait":
                    try:
                        chat_label.setText(str(payload or "Waiting for radio..."))
                    except Exception:
                        pass
                elif evt == "radio_ready":
                    initializing = False
                    refresh_list()
                    update_status()
                elif evt == "radio_lost":
                    if radio_ready:
                        ui_emit("log", f"{ts_local()} RADIO: disconnected")
                    radio_ready = False
                    interface = None
                    self_id = ""
                    self_id_raw = None
                    args.port = initial_port_arg
                    known_peers.clear()
                    peer_states.clear()
                    with peer_names_lock:
                        peer_names.clear()
                    key_response_last_ts.clear()
                    key_conflict_ignored.clear()
                    key_conflict_hidden_log_ts.clear()
                    incoming_state.clear()
                    with pending_lock:
                        pending_by_peer.clear()
                    dialogs.clear()
                    chat_history.clear()
                    list_index.clear()
                    current_dialog = None
                    _clear_key_conflict_header()
                    try:
                        chat_text.clear()
                        items_list.clear()
                        search_field.clear()
                        msg_entry.clear()
                    except Exception:
                        pass
                    initializing = True
                    chat_label.setText("Waiting for radio...")
                    refresh_list()
                    start_radio_loop()
            update_status()

        def copy_client_id() -> None:
            try:
                text = str(wire_id_from_norm(self_id) or "").strip()
                if not text:
                    return
                cb = QtWidgets.QApplication.clipboard()
                cb.setText(text, QtGui.QClipboard.Clipboard)
                try:
                    cb.setText(text, QtGui.QClipboard.Selection)
                except Exception:
                    pass
            except Exception:
                pass

        def on_item_clicked(item: QtWidgets.QListWidgetItem) -> None:
            row = items_list.row(item)
            if row < 0 or row >= len(list_index):
                return
            dialog_id = list_index[row]
            if not dialog_id:
                return
            select_dialog(dialog_id)

        def show_action_menu(current_id: str, global_pos: QtCore.QPoint) -> None:
            menu = QtWidgets.QMenu(win)
            menu.setTitle(tr("actions"))

            def add_action(text: str, fn) -> None:
                act = menu.addAction(text)
                act.triggered.connect(fn)

            def clear_history(dialog_id: str) -> None:
                name = norm_id_for_wire(dialog_id)
                reply = QtWidgets.QMessageBox.question(
                    win,
                    "meshTalk",
                    tr("clear_history_confirm").format(name=name),
                    QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                )
                if reply != QtWidgets.QMessageBox.Yes:
                    return
                chat_history.pop(dialog_id, None)
                if dialog_id in dialogs:
                    dialogs[dialog_id]["last_text"] = ""
                    dialogs[dialog_id]["unread"] = 0
                rewrite_history_dialog_entries(dialog_id, None)
                if current_dialog == dialog_id:
                    render_chat(dialog_id)
                refresh_list()

            add_action(tr("create_group_ctx"), add_group_from_selection)
            is_pinned = current_id in pinned_dialogs
            if not is_pinned:
                add_action(tr("pin"), lambda: (pinned_dialogs.add(current_id), save_gui_config(), refresh_list()))
            else:
                add_action(tr("unpin"), lambda: (pinned_dialogs.discard(current_id), save_gui_config(), refresh_list()))
            if current_id.startswith("group:"):
                if current_id.lower() != "group:primary":
                    add_action(tr("group_rename"), lambda: rename_group(current_id))
                    add_action(tr("group_delete"), lambda: delete_group(current_id))
            else:
                if groups:
                    def add_to_group() -> None:
                        gname, ok = QtWidgets.QInputDialog.getItem(win, "meshTalk", tr("group_add"), sorted(groups.keys()), 0, False)
                        if ok and gname:
                            add_peers_to_group_by_name([current_id], str(gname))
                    add_action(tr("group_add"), add_to_group)
                add_action(tr("msg_ctx_route"), lambda: trace_route(current_id))
                add_action(tr("key_request"), lambda: request_key(current_id))
                add_action(tr("clear_history"), lambda: clear_history(current_id))
                add_action(tr("peer_delete"), lambda: delete_peer(current_id))

            acts = menu.actions()
            if acts:
                menu.setActiveAction(acts[0])
            menu.exec(global_pos)

        def open_context_menu(pos: QtCore.QPoint) -> None:
            index = items_list.indexAt(pos)
            if index.isValid():
                row = index.row()
            else:
                row = items_list.currentRow()
            if row < 0 or row >= len(list_index):
                if list_index:
                    row = 0
                else:
                    return
            items_list.setCurrentRow(row)
            current_id = list_index[items_list.currentRow()] if items_list.currentRow() >= 0 else ""
            if current_id:
                show_action_menu(current_id, items_list.viewport().mapToGlobal(pos))

        def open_context_menu_current() -> None:
            row = items_list.currentRow()
            if row < 0 or row >= len(list_index):
                if list_index:
                    row = 0
                    items_list.setCurrentRow(row)
                else:
                    return
            current_id = list_index[row]
            if current_id:
                show_action_menu(current_id, items_list.viewport().mapToGlobal(items_list.visualItemRect(items_list.currentItem()).center()))

        items_list.itemClicked.connect(on_item_clicked)
        items_list.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        items_list.customContextMenuRequested.connect(open_context_menu)
        items_list.viewport().setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        items_list.viewport().customContextMenuRequested.connect(open_context_menu)
        shortcut_actions = QtGui.QShortcut(QtGui.QKeySequence("Ctrl+M"), win)
        shortcut_actions.setContext(QtCore.Qt.ApplicationShortcut)
        shortcut_actions.activated.connect(open_context_menu_current)
        _orig_search_mouse_press = search_field.mousePressEvent

        def _search_field_mouse_press(e):
            try:
                if e.button() == QtCore.Qt.LeftButton:
                    now = time.time()
                    if (now - float(search_click_state.get("last_ts", 0.0))) <= 0.6:
                        search_click_state["count"] = int(search_click_state.get("count", 0)) + 1
                    else:
                        search_click_state["count"] = 1
                    search_click_state["last_ts"] = now
                    if int(search_click_state.get("count", 0)) >= 3:
                        search_click_state["count"] = 0
                        log_line(f"{ts_local()} DISCOVERY: burst", "discovery")
                        send_discovery_broadcast()
            except Exception:
                pass
            try:
                _orig_search_mouse_press(e)
            except Exception:
                pass

        search_field.mousePressEvent = _search_field_mouse_press
        search_field.textChanged.connect(lambda _t: refresh_list())
        search_field.returnPressed.connect(lambda: start_dialog_by_id(search_field.text()))
        send_btn.clicked.connect(send_message)
        msg_entry.set_send_callback(send_message)

        refresh_list()
        initializing = True
        radio_loop_running = False
        log_line(f"{ts_local()} GUI: started | port={args.port} | self=waiting", "info")
        log_line(f"{ts_local()} RADIO: listening ON", "info")
        update_status()

        timer = QtCore.QTimer()
        timer.timeout.connect(process_ui_events)
        timer.start(200)

        pending_meta_timer = QtCore.QTimer()
        pending_meta_timer.timeout.connect(refresh_dynamic_pending_meta)
        pending_meta_timer.start(1000)

        def flush_peer_meta() -> None:
            nonlocal peer_meta_dirty
            if not peer_meta_dirty:
                return
            peer_meta_dirty = False
            save_gui_config()

        peer_meta_timer = QtCore.QTimer()
        peer_meta_timer.timeout.connect(flush_peer_meta)
        peer_meta_timer.start(30000)

        def radio_loop() -> None:
            nonlocal initializing, radio_loop_running
            radio_loop_running = True
            while True:
                if radio_ready:
                    radio_loop_running = False
                    return
                ok, msg = try_init_radio()
                if ok:
                    ui_emit("log", f"{ts_local()} RADIO: connected")
                    ui_emit("log", f"{ts_local()} GUI: ready | self={wire_id_from_norm(self_id)}")
                    ui_emit("radio_ready", None)
                    radio_loop_running = False
                    return
                ui_emit("radio_wait", msg)
                time.sleep(5.0)
            radio_loop_running = False

        def start_radio_loop() -> None:
            if not radio_loop_running:
                threading.Thread(target=radio_loop, daemon=True).start()

        def monitor_radio() -> None:
            while True:
                if radio_ready and interface is not None:
                    try:
                        # Port presence check (USB unplug)
                        try:
                            ports = {p.device for p in list_ports.comports()}
                            if args.port and args.port not in ("auto", "") and args.port not in ports:
                                ui_emit("radio_lost", None)
                                time.sleep(2.0)
                                continue
                        except Exception:
                            pass
                        is_conn = None
                        try:
                            is_conn = interface.isConnected if isinstance(getattr(interface, "isConnected", None), bool) else None
                        except Exception:
                            is_conn = None
                        if is_conn is False:
                            ui_emit("radio_lost", None)
                            time.sleep(2.0)
                            continue
                        nid = get_self_id(interface)
                        if not nid:
                            ui_emit("radio_lost", None)
                    except Exception:
                        ui_emit("radio_lost", None)
                time.sleep(2.0)

        start_radio_loop()
        threading.Thread(target=monitor_radio, daemon=True).start()

        def _on_app_about_to_quit() -> None:
            try:
                send_app_offline_broadcast()
            except Exception:
                pass

        app.aboutToQuit.connect(_on_app_about_to_quit)

        win.show()
        return app.exec()

    rc = run_gui_qt()
    if rc >= 0:
        return rc
    print("ERROR: Qt GUI is required (install PySide6). RU: нужен Qt GUI (установите PySide6).")
    return 2


if __name__ == "__main__":
    sys.exit(main())
