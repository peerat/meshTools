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
import signal
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
from collections import deque
from typing import Dict, Optional, Tuple

try:
    import fcntl
except Exception:
    fcntl = None  # type: ignore[assignment]

try:
    import msvcrt
except Exception:
    msvcrt = None  # type: ignore[assignment]

from meshtastic.serial_interface import SerialInterface
from pubsub import pub
import meshtastic
from meshtastic import portnums_pb2
from serial.tools import list_ports

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from meshtalk.utils import (
    format_meta_text,
    format_duration_mmss,
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
    PeerKeyPinnedError,
    b64d,
    b64e,
    derive_key,
    load_priv,
    load_pub,
    parse_payload,
    pub_fingerprint,
)
from meshtalk.envelope_v3 import (
    ENVELOPE_V3_TYPE_DATA,
    ENVELOPE_V3_VERSION,
    pack_envelope_v3,
    try_unpack_envelope_v3,
)
from meshtalk.v3_runtime import (
    build_hop_ack_for_frame,
    build_prebuilt_relay_record,
    build_relay_plaintext_from_record,
    decode_hop_ack_part,
    duplicate_requires_hop_ack,
    pack_v3_record_for_peer_state,
    pop_matching_relay_pending,
)
from meshtalk.v3_sender import collect_fast_retry_candidates
from meshtalk.v3_send_worker import SendWindowState, V3SendWorker
from meshtalk.v3_sender_service import (
    finalize_send_success_direct,
    process_non_send_action_direct,
)
from meshtalk.v3_receiver import (
    detect_legacy_control_drop,
    learn_relay_neighbor,
    update_caps_from_body,
)
from meshtalk.v3_rekey import handle_rekey1, handle_rekey2, handle_rekey3
from meshtalk.v3_radio import send_packet, send_traceroute_request, send_wire_payload, try_send_packet_nowait
from meshtalk.v3_receiver_service import (
    process_ack_frame_direct,
    process_data_frame_direct,
    process_token_adv_frame_direct,
)
from meshtalk.ui_chat_history import history_has_msg, update_outgoing_delivery_state, update_outgoing_failed_state
from meshtalk.ui_effects import handle_recv_plain_ui, handle_trace_done_ui
from meshtalk.ui_events import (
    as_optional_float,
    parse_groups_config,
    parse_peer_meta_records,
    parse_queued_payload,
    parse_recv_payload,
    parse_recv_plain_payload,
    parse_trace_update_payload,
    update_outgoing_ack_tracker,
)
from meshtalk.ui_receive import ingest_incoming_ui_fragment
from meshtalk.ui_security import (
    apply_imported_keypair_atomically,
    handle_security_keys_backup_priv,
    handle_security_keys_copy_pub,
    handle_security_keys_import_priv,
    handle_security_keys_regen,
    refresh_security_keys_view as refresh_security_keys_view_helper,
)
from meshtalk.ui_state import clear_runtime_collections, sync_peer_meta_to_states
from meshtalk.ui_helpers import build_gui_config_payload, split_chat_timestamp, strip_parenthesized_prefix
from meshtalk.ui_log import append_log_to_view, classify_log_level, should_skip_verbose_log, should_suppress_duplicate_log
from meshtalk.ui_settings import (
    build_activity_runtime_settings,
    compute_activity_preset,
    normalize_contacts_visibility,
    parse_float_text,
    parse_int_text,
)
from meshtalk.ui_settings_tabs import (
    build_compression_tab,
    build_log_tab,
    build_routing_tab,
    build_security_tab,
    build_theme_tab,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
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
from meshtalk.mt2_frames import (
    CAPS_CTRL_PREFIX,
    build_hello_frame,
    build_kr1_frame,
    build_kr2_frame,
    parse_mt2_frame,
    parse_caps_frame as parse_caps_frame_mt2,
)
from meshtalk.metrics import (
    METRICS_GRAPH_WINDOW_SECONDS,
    METRICS_RETENTION_SECONDS,
    activity_record,
    metrics_get_last_value,
    metrics_inc,
    metrics_set,
    metrics_snapshot_rows,
)
from meshtalk.handshake import HandshakeContext, handle_mt2_plaintext
from meshtalk.relay_protocol import (
    RELAY_HEADER_LEN,
    RELAY_TYPE_CAPS,
    RELAY_TYPE_CAPS_REQ,
    RELAY_TYPE_DATA,
    RELAY_TYPE_END_ACK,
    RELAY_TYPE_HOP_ACK,
    RELAY_TYPE_REKEY1,
    RELAY_TYPE_REKEY2,
    RELAY_TYPE_REKEY3,
    RELAY_TYPE_TOKEN_ADV,
    RELAY_TYPE_TOKEN_WITHDRAW,
    build_caps_frame,
    build_caps_req_frame,
    build_rekey1_frame,
    build_token_adv_frame,
    current_epoch_slot,
    derive_relay_token,
    parse_frame as parse_relay_frame,
)
from meshtalk.relay_state import RelayState
from meshtalk.routing import RoutingController
from meshtalk.compression import (
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
    decompress_text,
)


VERSION = "0.6.0"
DEFAULT_PORTNUM = portnums_pb2.PortNum.PRIVATE_APP
DEFAULT_MESHTALK_PACKET_PORT = "PRIVATE_APP"
PAYLOAD_OVERHEAD = 1 + 1 + 8 + 12 + 16  # ver + type + msg_id + nonce + tag

APP_OFFLINE_PREFIX = b"KOF1|"
MSG_V2_PREFIX = b"M2"
MSG_V2_HEADER_LEN = 16  # prefix(2) + ts(4) + group(4) + part(2) + total(2) + attempt(1) + meta(1)
MAX_PENDING_PER_PEER = 128
RETRY_BACKOFF_MAX_SECONDS = 300.0
RETRY_JITTER_RATIO = 0.25
# Message resend policy aims to minimize RF noise:
# - active phase for the first N minutes (more eager retries, capped),
# - then muted phase: probe once per interval, in a short active window, then sleep again,
# - if peer becomes responsive (ACK/inbound traffic), switch back to active immediately.
MSG_RETRY_ACTIVE_WINDOW_SECONDS = 300.0  # 5 minutes
# Legacy fixed muted/probe timings (kept as defaults/backward compat; UI exposes adaptive knobs).
MSG_RETRY_MUTED_INTERVAL_SECONDS = 3600.0  # muted: wake up once per hour
MSG_RETRY_PROBE_WINDOW_SECONDS = 300.0  # muted: stay active for 5 minutes after wakeup
PEER_RESPONSIVE_GRACE_SECONDS = 180.0  # peer considered responsive if any activity within this window
KEY_RESPONSE_MIN_INTERVAL_SECONDS = 300.0
KEY_RESPONSE_RETRY_INTERVAL_SECONDS = 5.0
HELLO_NEW_PEER_REQ_WINDOW_SECONDS = 60.0
HELLO_NEW_PEER_REQ_MAX_PER_WINDOW = 12
REKEY_CTRL_PREFIX1 = b"RK1"
REKEY_CTRL_PREFIX2 = b"RK2"
REKEY_CTRL_PREFIX3 = b"RK3"
CAPS_REQ_PREFIX = b"CPR"   # request caps
# Enabled by default: low-noise, infrequent rekey only when peers are active and confirmed.
REKEY_MAX_ATTEMPTS = 3
REKEY_RETRY_BASE_SECONDS = 30.0
REKEY_PREV_KEY_GRACE_SECONDS = 300.0
REKEY_MIN_INTERVAL_SECONDS = 6 * 3600.0
REKEY_MIN_MESSAGES = 50
CONTACT_ONLINE_SECONDS = 30.0 * 60.0
CONTACT_STALE_SECONDS = 24.0 * 3600.0
ACTIVITY_CONTROLLER_DEFAULT = "quic"
ACTIVITY_CONTROLLER_MODELS = ("trickle", "ledbat", "quic")
PRIVATE_KEY_BACKUP_MAGIC = "MTPRIV1"

def _build_portnum_name_to_value() -> Dict[str, int]:
    known: Dict[str, int] = {}
    try:
        desc = getattr(portnums_pb2.PortNum, "DESCRIPTOR", None)
        values = getattr(desc, "values", None)
        if values:
            for enum_value in values:
                try:
                    name = str(getattr(enum_value, "name", "") or "").strip().upper()
                    number = int(getattr(enum_value, "number"))
                except Exception:
                    continue
                if name:
                    known[name] = number
    except Exception:
        pass
    # Fallback for environments where enum reflection may be incomplete.
    known.setdefault("PRIVATE_APP", int(portnums_pb2.PortNum.PRIVATE_APP))
    known.setdefault("TEXT_MESSAGE_APP", int(portnums_pb2.PortNum.TEXT_MESSAGE_APP))
    known.setdefault("TRACEROUTE_APP", int(portnums_pb2.PortNum.TRACEROUTE_APP))
    return known


PORTNUM_NAME_TO_VALUE: Dict[str, int] = _build_portnum_name_to_value()
PORTNUM_VALUE_TO_NAME: Dict[int, str] = {}
for _port_name, _port_value in PORTNUM_NAME_TO_VALUE.items():
    PORTNUM_VALUE_TO_NAME.setdefault(int(_port_value), str(_port_name))
PORTNUM_ALIASES: Dict[str, str] = {
    "PRIVATE": "PRIVATE_APP",
    "TEXT": "TEXT_MESSAGE_APP",
    "TRACEROUTE": "TRACEROUTE_APP",
}


def known_portnum_choices() -> Tuple[Tuple[str, str], ...]:
    rows = []
    for name, number in PORTNUM_NAME_TO_VALUE.items():
        try:
            rows.append((int(number), str(name)))
        except Exception:
            continue
    rows.sort(key=lambda x: (x[0], x[1]))
    return tuple((f"{name} ({number})", name) for number, name in rows)


def _is_valid_portnum_value(value: int) -> bool:
    # Meshtastic portNum is a small non-negative integer in protobuf enum/int fields.
    # Keep a strict guard so malformed configs cannot silently break all TX/RX routing.
    try:
        v = int(value)
    except Exception:
        return False
    return 0 <= v <= 65535


def _portnum_to_int(raw: object) -> Optional[int]:
    try:
        if isinstance(raw, bool):
            return None
        if isinstance(raw, int):
            v = int(raw)
            return v if _is_valid_portnum_value(v) else None
        if isinstance(raw, float) and math.isfinite(raw):
            v = int(raw)
            return v if _is_valid_portnum_value(v) else None
        s = str(raw or "").strip()
        if not s:
            return None
        if s.startswith(("0x", "0X")):
            v = int(s, 16)
            return v if _is_valid_portnum_value(v) else None
        if re.fullmatch(r"[+-]?\d+", s):
            v = int(s, 10)
            return v if _is_valid_portnum_value(v) else None
        u = s.upper()
        if u in PORTNUM_NAME_TO_VALUE:
            v = int(PORTNUM_NAME_TO_VALUE[u])
            return v if _is_valid_portnum_value(v) else None
        if u in PORTNUM_ALIASES:
            v = int(PORTNUM_NAME_TO_VALUE[PORTNUM_ALIASES[u]])
            return v if _is_valid_portnum_value(v) else None
    except Exception:
        return None
    return None


def normalize_mesh_packet_port_value(raw: object) -> str:
    port_i = _portnum_to_int(raw)
    if port_i is None:
        return str(DEFAULT_MESHTALK_PACKET_PORT)
    if int(port_i) in PORTNUM_VALUE_TO_NAME:
        return str(PORTNUM_VALUE_TO_NAME[int(port_i)])
    return str(int(port_i))


def resolve_mesh_packet_port(raw: object) -> Tuple[int, str]:
    port_i = _portnum_to_int(raw)
    if port_i is None:
        port_i = int(PORTNUM_NAME_TO_VALUE[DEFAULT_MESHTALK_PACKET_PORT])
    label = PORTNUM_VALUE_TO_NAME.get(int(port_i), str(int(port_i)))
    return (int(port_i), str(label))


def peer_used_meshtalk(peer_norm: str, now_ts: Optional[float] = None) -> bool:
    """
    Helper used by both GUI and non-GUI code paths.

    Returns True if the peer is considered meshTalk-capable/recent:
    - the peer has shown meshTalk app activity recently (within CONTACT_STALE_SECONDS), AND
    - we have no explicit offline marker that is newer than last seen, AND
    - either the key exchange is established (key_ready) OR we have a pinned public key for the peer.

    IMPORTANT: This must exist at module scope, because sender/background loops should not depend on
    nested GUI helpers (which may not be defined in those threads).
    """
    peer_id = norm_id_for_filename(peer_norm)
    if not peer_id:
        return False
    now = time.time() if now_ts is None else float(now_ts)

    try:
        pinned_pub_exists = os.path.isfile(os.path.join(keydir, f"{peer_id}.pub"))
    except Exception:
        pinned_pub_exists = False

    st = None
    try:
        st = get_peer_state(peer_id)
    except Exception:
        st = None
    if st is None:
        try:
            st = peer_states.get(peer_id)
        except Exception:
            st = None

    def _is_recent_and_not_offline(seen_ts: float, offline_ts: float) -> bool:
        if offline_ts > 0.0 and (now - offline_ts) <= float(CONTACT_STALE_SECONDS) and (seen_ts <= offline_ts):
            return False
        return bool(seen_ts > 0.0 and (now - seen_ts) <= float(CONTACT_STALE_SECONDS))

    if st is not None:
        try:
            seen_ts = float(getattr(st, "last_seen_ts", 0.0) or 0.0)
            offline_ts = float(getattr(st, "app_offline_ts", 0.0) or 0.0)
            key_ready_now = bool(getattr(st, "key_ready", False))
            if _is_recent_and_not_offline(seen_ts, offline_ts) and (key_ready_now or pinned_pub_exists):
                return True
        except Exception:
            pass

    rec = None
    try:
        rec = peer_meta.get(peer_id, {})
    except Exception:
        rec = None
    if isinstance(rec, dict):
        try:
            seen_ts = float(rec.get("last_seen_ts", 0.0) or 0.0)
            offline_ts = float(rec.get("app_offline_ts", 0.0) or 0.0)
            if _is_recent_and_not_offline(seen_ts, offline_ts) and pinned_pub_exists:
                return True
        except Exception:
            pass
    return False


def peer_direct_meshtalk_ready(peer_norm: str, now_ts: Optional[float] = None) -> bool:
    """
    Returns True only when the peer has a live direct meshTalk session.

    This is intentionally stricter than peer_used_meshtalk():
    - recent meshTalk app activity is required
    - no newer explicit app-offline marker
    - key exchange must be established right now (key_ready)
    - no pinned mismatch state

    Use this helper for decisions that must follow the current direct-session
    status, such as green UI state and choosing the direct meshTalk transport.
    """
    peer_id = norm_id_for_filename(peer_norm)
    if not peer_id:
        return False
    now = time.time() if now_ts is None else float(now_ts)

    st = None
    try:
        st = get_peer_state(peer_id)
    except Exception:
        st = None
    if st is None:
        try:
            st = peer_states.get(peer_id)
        except Exception:
            st = None
    rec = None
    try:
        rec = peer_meta.get(peer_id, {})
    except Exception:
        rec = None

    try:
        st_seen = float(getattr(st, "last_seen_ts", 0.0) or 0.0) if st is not None else 0.0
        rec_seen = float(rec.get("last_seen_ts", 0.0) or 0.0) if isinstance(rec, dict) else 0.0
        st_key_conf = float(getattr(st, "key_confirmed_ts", 0.0) or 0.0) if st is not None else 0.0
        st_key_ok = float(getattr(st, "last_key_ok_ts", 0.0) or 0.0) if st is not None else 0.0
        rec_key_conf = float(rec.get("key_confirmed_ts", 0.0) or 0.0) if isinstance(rec, dict) else 0.0
        seen_ts = max(st_seen, rec_seen, st_key_conf, st_key_ok, rec_key_conf)
        offline_ts = max(
            float(getattr(st, "app_offline_ts", 0.0) or 0.0) if st is not None else 0.0,
            float(rec.get("app_offline_ts", 0.0) or 0.0) if isinstance(rec, dict) else 0.0,
        )
        if seen_ts <= 0.0:
            return False
        if (now - seen_ts) > float(CONTACT_STALE_SECONDS):
            return False
        if offline_ts > 0.0 and (now - offline_ts) <= float(CONTACT_STALE_SECONDS) and seen_ts <= offline_ts:
            return False
        key_ready_now = bool(getattr(st, "key_ready", False)) if st is not None else False
        if not key_ready_now:
            try:
                pinned_pub_exists = os.path.isfile(os.path.join(keydir, f"{peer_id}.pub"))
            except Exception:
                pinned_pub_exists = False
            key_ready_now = bool(pinned_pub_exists and max(st_key_conf, st_key_ok, rec_key_conf) > 0.0)
        if not key_ready_now:
            return False
        if bool(getattr(st, "pinned_mismatch", False)) if st is not None else False:
            return False
        return True
    except Exception:
        return False


def peer_transport_state(peer_norm: str, now_ts: Optional[float] = None) -> Tuple[str, str]:
    """
    Returns a compact transport-state snapshot for diagnostics/logging.

    States:
    - direct_ready: live direct meshTalk session
    - app_offline: explicit recent app-offline marker
    - pinned_mismatch: peer key changed and transport is suspended
    - handshake: key exchange is in progress / waiting for confirmation
    - relay_only: peer is visible in meshTalk control-plane but no live direct session
    - radio_only: peer is seen as a device/neighbor only
    - unknown: no meaningful recent state
    """
    peer_id = norm_id_for_filename(peer_norm)
    if not peer_id:
        return ("unknown", "invalid_peer")
    now = time.time() if now_ts is None else float(now_ts)

    st = None
    try:
        st = get_peer_state(peer_id)
    except Exception:
        st = None
    if st is None:
        try:
            st = peer_states.get(peer_id)
        except Exception:
            st = None

    try:
        pinned_pub_exists = os.path.isfile(os.path.join(keydir, f"{peer_id}.pub"))
    except Exception:
        pinned_pub_exists = False

    if peer_direct_meshtalk_ready(peer_id, now_ts=now):
        return ("direct_ready", "key_ready")

    rec = None
    try:
        rec = peer_meta.get(peer_id, {})
    except Exception:
        rec = None

    seen_ts = 0.0
    hello_ts = 0.0
    offline_ts = 0.0
    key_ready_now = False
    pinned_mismatch = False
    await_confirm = False
    force_req = False
    if st is not None:
        try:
            seen_ts = float(getattr(st, "last_seen_ts", 0.0) or 0.0)
        except Exception:
            pass
        try:
            hello_ts = float(getattr(st, "last_hello_rx_ts", 0.0) or 0.0)
        except Exception:
            pass
        try:
            hello_ts = max(hello_ts, float(getattr(st, "device_seen_ts", 0.0) or 0.0))
        except Exception:
            pass
        try:
            offline_ts = float(getattr(st, "app_offline_ts", 0.0) or 0.0)
        except Exception:
            pass
        try:
            key_ready_now = bool(getattr(st, "key_ready", False))
        except Exception:
            pass
        try:
            pinned_mismatch = bool(getattr(st, "pinned_mismatch", False))
        except Exception:
            pass
        try:
            await_confirm = bool(getattr(st, "await_key_confirm", False))
        except Exception:
            pass
        try:
            force_req = bool(getattr(st, "force_key_req", False))
        except Exception:
            pass

    if isinstance(rec, dict):
        try:
            seen_ts = max(seen_ts, float(rec.get("last_seen_ts", 0.0) or 0.0))
        except Exception:
            pass
        try:
            seen_ts = max(seen_ts, float(rec.get("key_confirmed_ts", 0.0) or 0.0))
        except Exception:
            pass
        try:
            hello_ts = max(hello_ts, float(rec.get("device_seen_ts", 0.0) or 0.0))
        except Exception:
            pass
        try:
            offline_ts = max(offline_ts, float(rec.get("app_offline_ts", 0.0) or 0.0))
        except Exception:
            pass

    try:
        with peer_names_lock:
            rec_name = peer_names.get(peer_id) or peer_names.get(str(peer_id).lower()) or {}
        if isinstance(rec_name, dict):
            hello_ts = max(hello_ts, float(rec_name.get("last_heard_ts", 0.0) or 0.0))
    except Exception:
        pass

    recent_seen = bool(seen_ts > 0.0 and (now - seen_ts) <= float(CONTACT_STALE_SECONDS))
    recent_hello = bool(hello_ts > 0.0 and (now - hello_ts) <= float(CONTACT_STALE_SECONDS))
    if offline_ts > 0.0 and (now - offline_ts) <= float(CONTACT_STALE_SECONDS) and (seen_ts <= offline_ts):
        return ("app_offline", "explicit_offline")
    if pinned_mismatch:
        return ("pinned_mismatch", "key_rotation")
    if (await_confirm or force_req or (pinned_pub_exists and recent_seen and not key_ready_now)):
        return ("handshake", "waiting_key")
    if pinned_pub_exists and recent_hello:
        return ("handshake", "hello_key_seen")
    if peer_used_meshtalk(peer_id, now_ts=now):
        return ("relay_only", "control_plane_only")
    try:
        reachability_map = getattr(relay_state, "reachability", {})
        if isinstance(reachability_map, dict):
            for _routes in reachability_map.values():
                try:
                    route_list = list(_routes or [])
                except Exception:
                    route_list = []
                for _row in route_list:
                    if str(getattr(_row, "via_peer", "") or "").strip() == peer_id:
                        return ("relay_only", "control_plane_route")
    except Exception:
        pass
    if recent_seen or recent_hello:
        return ("radio_only", "hello_only")
    return ("unknown", "no_recent_state")
BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
LEGACY_BASE_DIR = "meshTalk"
DATA_DIR = BASE_DIR
STATE_FILE = os.path.join(DATA_DIR, "state.json")
HISTORY_FILE = os.path.join(DATA_DIR, "history.log")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
INCOMING_FILE = os.path.join(DATA_DIR, "incoming.json")
RUNTIME_LOG_FILE = os.path.join(DATA_DIR, "runtime.log")
keydir = os.path.join(DATA_DIR, "keyRings")
INSTANCE_LOCK_PATH = os.path.join(DATA_DIR, ".meshtalk.instance.lock")
_INSTANCE_LOCK_FH = None
_INSTANCE_LOCK_HELD_PATH = ""
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
    global DATA_DIR, STATE_FILE, HISTORY_FILE, CONFIG_FILE, INCOMING_FILE, RUNTIME_LOG_FILE, keydir, INSTANCE_LOCK_PATH, _STORAGE
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
    INSTANCE_LOCK_PATH = os.path.join(DATA_DIR, ".meshtalk.instance.lock")
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


def release_instance_lock() -> None:
    global _INSTANCE_LOCK_FH, _INSTANCE_LOCK_HELD_PATH
    try:
        if _INSTANCE_LOCK_FH is None:
            return
        try:
            _INSTANCE_LOCK_FH.seek(0)
            _INSTANCE_LOCK_FH.truncate()
            _INSTANCE_LOCK_FH.flush()
        except Exception:
            pass
        if fcntl is not None:
            try:
                fcntl.flock(_INSTANCE_LOCK_FH.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
        elif msvcrt is not None:
            try:
                _INSTANCE_LOCK_FH.seek(0)
                msvcrt.locking(_INSTANCE_LOCK_FH.fileno(), msvcrt.LK_UNLCK, 1)
            except Exception:
                pass
        try:
            _INSTANCE_LOCK_FH.close()
        except Exception:
            pass
    finally:
        _INSTANCE_LOCK_FH = None
        _INSTANCE_LOCK_HELD_PATH = ""


def acquire_instance_lock() -> bool:
    global _INSTANCE_LOCK_FH, _INSTANCE_LOCK_HELD_PATH
    try:
        harden_dir(DATA_DIR)
        lock_path = os.path.abspath(INSTANCE_LOCK_PATH)
        if _INSTANCE_LOCK_FH is not None:
            if _INSTANCE_LOCK_HELD_PATH == lock_path:
                return True
            release_instance_lock()
        fh = open(lock_path, "a+", encoding="utf-8")
        fh.seek(0)
        if msvcrt is not None:
            try:
                if fh.tell() == 0 and fh.read(1) == "":
                    fh.seek(0)
                    fh.write(" ")
                    fh.flush()
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                fh.close()
                return False
        if fcntl is not None:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif msvcrt is None:
            fh.seek(0)
            current = fh.read().strip()
            if current:
                fh.close()
                return False
        try:
            fh.seek(0)
            fh.truncate()
            fh.write(str(os.getpid()))
            fh.flush()
        except Exception:
            pass
        _INSTANCE_LOCK_FH = fh
        _INSTANCE_LOCK_HELD_PATH = lock_path
        return True
    except BlockingIOError:
        return False
    except Exception:
        return False


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
    # meshtalk.compression.FLAG_TOKEN_STREAM
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
        # Defaults must not suppress modern features before CAPS exchange finishes.
        # Unknown peers are treated as "legacy-compatible + MT2-capable" until they explicitly
        # advertise otherwise; otherwise clearly compressible messages would never enter the
        # compression branch on first contact.
        self.peer_wire_versions = {int(PROTO_VERSION)}
        self.peer_msg_versions = {1, 2}  # legacy framing + current compact framing until CAPS clarifies
        self.peer_mc_versions = {1}   # MC block VERSION
        self.pending: Dict[str, Dict[str, object]] = {}
        self.last_send_ts = 0.0
        self.next_key_req_ts = 0.0
        self.rtt_avg = 0.0
        self.rtt_count = 0
        # Smoothed RTT estimators for LEDBAT/QUIC-style resend controllers.
        self.srtt_s = 0.0
        self.rttvar_s = 0.0
        self.min_rtt_s = 0.0
        self.force_key_req = False
        self.decrypt_fail_count = 0
        self.last_decrypt_fail_ts = 0.0
        self.last_decrypt_fail_log_ts = 0.0
        self.last_decrypt_fail_grace_log_ts = 0.0
        self.last_key_ok_ts = 0.0
        self.last_key_req_ts = 0.0
        self.last_key_req_reason = ""
        self.last_key_req_initiator = ""
        self.next_key_refresh_ts = 0.0
        self.await_key_confirm = False
        self.await_key_confirm_attempts = 0
        # TOFU pinning / key mismatch diagnostics (peer rotated key, but we keep old key until user resets).
        self.pinned_mismatch = False
        self.pinned_old_fp = ""
        self.pinned_new_fp = ""
        self.pinned_new_pub_b64 = ""
        self.last_pinned_mismatch_log_ts = 0.0
        # Capability exchange (encrypted, protocol v2).
        self.caps_sent_ts = 0.0
        self.caps_req_ts = 0.0
        self.caps_recv_ts = 0.0
        self.caps: Dict[str, str] = {}
        # Discovery diagnostics (throttling logs).
        self.last_hello_rx_ts = 0.0

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


def normalize_activity_controller_model(raw: object) -> str:
    try:
        s = str(raw or "").strip().lower()
    except Exception:
        s = ""
    if s in ACTIVITY_CONTROLLER_MODELS:
        return s
    return ACTIVITY_CONTROLLER_DEFAULT


def ensure_routing_defaults(cfg: Dict[str, object]) -> None:
    # Route scoring knobs.
    cfg.setdefault("routing_score_w_delivery", 1.30)
    cfg.setdefault("routing_score_w_timeout", 1.05)
    cfg.setdefault("routing_score_w_rtt", 0.35)
    cfg.setdefault("routing_score_w_hops", 0.25)
    cfg.setdefault("routing_score_w_retry", 0.40)
    cfg.setdefault("routing_score_w_micro", 0.20)
    cfg.setdefault("routing_score_w_congestion", 0.50)
    cfg.setdefault("routing_score_w_snr_bonus", 0.08)
    # EMA/decay/trust.
    cfg.setdefault("routing_ema_alpha", 0.22)
    cfg.setdefault("routing_decay_half_life_seconds", 1200.0)
    cfg.setdefault("routing_min_samples", 6)
    cfg.setdefault("routing_route_ttl_seconds", 1800.0)
    # Hysteresis/failover.
    cfg.setdefault("routing_hysteresis_rel", 0.12)
    cfg.setdefault("routing_hysteresis_abs", 0.04)
    cfg.setdefault("routing_sticky_hold_seconds", 45.0)
    cfg.setdefault("routing_failover_timeout_ema", 0.55)
    cfg.setdefault("routing_failover_delivery_ema", 0.25)
    cfg.setdefault("routing_failover_rtt_seconds", 25.0)
    # Forward policy.
    cfg.setdefault("routing_group_fanout_cap", 8)
    cfg.setdefault("routing_group_min_score", -0.20)
    cfg.setdefault("routing_control_rate_per_second", 0.20)
    cfg.setdefault("routing_control_burst", 3.0)
    cfg.setdefault("routing_control_min_interval_seconds", 2.0)


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


def parse_key_frame(payload: bytes) -> Optional[Tuple[str, Optional[bytes], Optional[bytes]]]:
    """Backward compatible wrapper for MT2 plaintext frames.

    Kept only because older code paths/tests may still call it; new code should
    use meshtalk.handshake.handle_mt2_plaintext().
    """
    try:
        return parse_mt2_frame(bytes(payload or b""))
    except Exception:
        return None


def parse_caps_frame(pt: bytes) -> Optional[Dict[str, str]]:
    try:
        return parse_caps_frame_mt2(bytes(pt or b""))
    except Exception:
        return None


def parse_caps_versions(raw: object) -> set[int]:
    vals: set[int] = set()
    try:
        text = str(raw or "").strip()
    except Exception:
        text = ""
    if not text:
        return vals
    for token in text.replace(";", ",").split(","):
        item = str(token or "").strip()
        if not item:
            continue
        try:
            vals.add(int(item))
        except Exception:
            continue
    return vals


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

    ap.add_argument("--retry-seconds", type=int, default=10, help="retry interval in seconds (default: 10). RU: интервал повторов, сек (по умолчанию: 10).")
    ap.add_argument("--max-seconds", type=int, default=3600, help="max time to wait for ACK (default: 3600). RU: максимум ожидания ACK, сек (по умолчанию: 3600).")
    ap.add_argument("--max-bytes", type=int, default=200, help="max payload bytes per packet (default: 200). RU: максимум байт полезной нагрузки (по умолчанию: 200).")
    ap.add_argument("--rate-seconds", type=int, default=5, help="min seconds between sends (default: 5). RU: минимум секунд между отправками (по умолчанию: 5).")
    ap.add_argument(
        "--parallel-sends",
        type=int,
        default=2,
        help="packets per rate window (default: 2). RU: сколько пакетов можно отправить подряд в одном окне rate (по умолчанию: 2).",
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
    ap.set_defaults(auto_pacing=False)


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
    atexit.register(release_instance_lock)
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
        rate_seconds=int(getattr(args, "rate_seconds", 5) or 5),
        parallel_sends=int(getattr(args, "parallel_sends", 2) or 2),
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
    runtime_session_started_ts = time.time()
    last_routing_monitor_tick_log_ts = 0.0
    DECRYPT_FAIL_STARTUP_GRACE_SECONDS = 120.0
    DECRYPT_FAIL_RECENT_KEYOK_GRACE_SECONDS = 45.0
    DECRYPT_FAIL_GRACE_SUSPEND_THRESHOLD = 4

    # GUI-only mode: no CLI validation needed

    peer_id_norm, peer_path = (None, None)
    known_peers: Dict[str, x25519.X25519PublicKey] = {}
    peer_names: Dict[str, Dict[str, str]] = {}
    peer_names_lock = threading.Lock()
    incoming_state: Dict[str, Dict[str, object]] = {}
    relay_incoming: Dict[str, Dict[str, object]] = {}
    relay_state = RelayState()

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

    def _relay_token_for_peer(peer_norm: str, epoch_slot: Optional[int] = None) -> bytes:
        peer_id = norm_id_for_filename(peer_norm)
        slot = current_epoch_slot() if epoch_slot is None else int(epoch_slot)
        if not peer_id:
            return b""
        return derive_relay_token(peer_id, slot)

    def _relay_token_matches_self(token: bytes, now: Optional[float] = None) -> bool:
        if not self_id:
            return False
        t = bytes(token or b"")[:8]
        if not t:
            return False
        slot_now = current_epoch_slot(now=now)
        candidates = {
            _relay_token_for_peer(self_id, slot_now),
            _relay_token_for_peer(self_id, max(0, slot_now - 1)),
        }
        return t in candidates

    def _safe_pub_subscribe_once(handler, topic: str) -> bool:
        try:
            pub.unsubscribe(handler, topic)
        except Exception:
            pass
        try:
            pub.subscribe(handler, topic)
            return True
        except Exception:
            return False

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
        if not acquire_instance_lock():
            try:
                startup_log(
                    f"BOOT: another instance is already running for node={self_id} "
                    f"lock={os.path.abspath(INSTANCE_LOCK_PATH)}"
                )
            except Exception:
                pass
            try:
                interface.close()
            except Exception:
                pass
            interface = None
            return (False, f"Another instance is already running for {wire_id_from_norm(self_id)}")
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
            f"{ts_local()} CRYPTO: mt_key=KR1/KR2 plaintext pub=X25519(32b,b64) kdf=HKDF-SHA256 aead=MT-WIREv{int(PROTO_VERSION)} AES-256-GCM storage=AES-256-GCM(keyRings/storage.key)",
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
        missing_priv = not os.path.isfile(priv_path)
        missing_pub = not os.path.isfile(pub_path)
        # Ensure key files exist (auto-generate if missing)
        if missing_priv or missing_pub:
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
            missing_parts = []
            if missing_priv:
                missing_parts.append("priv")
            if missing_pub:
                missing_parts.append("pub")
            ui_emit(
                "log",
                f"{ts_local()} KEY: auto-generated local key pair for {wire_id_from_norm(self_id)} reason=missing_{'+'.join(missing_parts) if missing_parts else 'key_files'}",
            )
        harden_file(priv_path)
        harden_file(pub_path)
        priv = load_priv(priv_path)
        pub_from_priv = priv.public_key()
        pub_from_priv_raw = pub_from_priv.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        pub_self = load_pub(pub_path)
        pub_self_raw = pub_self.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if bytes(pub_self_raw) != bytes(pub_from_priv_raw):
            with open(pub_path, "w", encoding="utf-8") as f:
                f.write(b64e(pub_from_priv_raw))
            harden_file(pub_path)
            pub_self = load_pub(pub_path)
            pub_self_raw = pub_self.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            ui_emit(
                "log",
                f"{ts_local()} KEY: local keypair mismatch detected; restored public key from private key peer={wire_id_from_norm(self_id)}",
            )
        ui_emit(
            "log",
            f"{ts_local()} KEY: local identity peer={wire_id_from_norm(self_id)} fp={pub_fingerprint(pub_self_raw)} keydir={os.path.abspath(keydir)}",
        )
        known_peers = load_known_peers(keydir, self_id)
        radio_ready = True
        update_peer_names_from_nodes()
        ui_emit("log", f"{ts_local()} RADIO: self {wire_id_from_norm(self_id)}")
        if not subscriptions_registered:
            try:
                _safe_pub_subscribe_once(on_receive, "meshtastic.receive.data")
                try:
                    _safe_pub_subscribe_once(on_receive, "meshtastic.receive")
                except Exception:
                    pass

                def _on_conn_status(*_args, **_kwargs):
                    try:
                        evt = _kwargs.get("evt")
                        if isinstance(evt, dict) and evt.get("connected") is False:
                            ui_emit("radio_lost", None)
                            return
                    except Exception as e:
                        try:
                            err_txt = f"{type(e).__name__}: {e}"
                        except Exception:
                            err_txt = "unknown"
                        try:
                            routing_summary_label.setText(f"{tr('routing_monitor_hint')} | refresh error: {err_txt}")
                        except Exception:
                            pass
                        try:
                            routing_status_transport.setText(f"error | {err_txt}")
                        except Exception:
                            pass
                        try:
                            ui_emit("log", f"{ts_local()} ROUTING_MONITOR: refresh failed {err_txt}")
                        except Exception:
                            pass

                _safe_pub_subscribe_once(_on_conn_status, "meshtastic.connection.status")
                subscriptions_registered = True
            except Exception:
                pass
        ui_emit("config_reload", dict(cfg))
        return (True, f"Connected {port}")

    update_peer_names_from_nodes()

    pending_by_peer: Dict[str, Dict[str, Dict[str, object]]] = {}
    pending_lock = threading.Lock()
    seen_msgs: Dict[str, float] = {}
    seen_parts: Dict[str, float] = {}
    recent_private_rx: Dict[str, float] = {}
    key_response_last_ts: Dict[str, float] = {}
    hello_new_peer_req_events: deque[float] = deque()
    # Persisted per-peer activity metadata (best-effort; used for contact status shading).
    # This must live in the core runtime scope because RX/TX threads update it.
    peer_meta: Dict[str, Dict[str, object]] = {}
    peer_meta_dirty = False
    # Deduplicate frequent offline presence broadcasts that can be repeated by mesh relays.
    offline_rx_last_ts: Dict[str, float] = {}
    offline_rx_last_id: Dict[str, int] = {}
    transport_state_last_by_peer: Dict[str, Tuple[str, str]] = {}
    route_selection_last_by_peer: Dict[str, Tuple[str, str, str]] = {}
    seen_lock = threading.Lock()
    subscriptions_registered = False
    peer_states: Dict[str, PeerState] = {}
    tracked_peers = set()
    # Module-scope transport helpers (peer_direct_meshtalk_ready/peer_transport_state)
    # are intentionally reused by background paths. Keep them pointed at the live
    # GUI runtime containers instead of stale module defaults.
    globals()["pending_by_peer"] = pending_by_peer
    globals()["known_peers"] = known_peers
    globals()["peer_names"] = peer_names
    globals()["peer_meta"] = peer_meta
    globals()["peer_states"] = peer_states
    globals()["relay_state"] = relay_state
    globals()["tracked_peers"] = tracked_peers
    ui_events: "queue.Queue[Tuple[str, object]]" = queue.Queue()
    gui_enabled = True
    last_activity_ts = time.time()
    hello_schedule_start_ts = time.time()
    last_key_sent_ts = 0.0
    last_hello_broadcast_log_ts = 0.0
    app_offline_sent = False
    # Config must be available to sender_loop/key exchange/discovery even before GUI starts.
    global cfg
    cfg = load_config()
    # Manual-only activity mode: disable runtime auto-pacing.
    cfg["auto_pacing"] = False
    cfg["mesh_packet_portnum"] = normalize_mesh_packet_port_value(cfg.get("mesh_packet_portnum", DEFAULT_MESHTALK_PACKET_PORT))
    cfg.setdefault("activity_timing_mode", "manual")
    cfg.setdefault("activity_intra_batch_gap_ms", 0)
    cfg.setdefault("discovery_hello_burst_count", 1)
    cfg.setdefault("discovery_hello_packet_count", 1)
    cfg.setdefault("discovery_hello_gap_seconds", 1)
    cfg.setdefault("discovery_hello_packet_gap_seconds", 1)
    cfg.setdefault("discovery_hello_interval_seconds", 60)
    cfg.setdefault("discovery_hello_runtime_seconds", 0)
    cfg.setdefault("discovery_hello_autostart", True)
    data_portnum, data_port_label = resolve_mesh_packet_port(cfg.get("mesh_packet_portnum"))
    cfg["activity_controller_model"] = normalize_activity_controller_model(
        cfg.get("activity_controller_model", ACTIVITY_CONTROLLER_DEFAULT)
    )
    ensure_routing_defaults(cfg)

    def migrate_legacy_manual_activity_defaults(cfg_map: dict) -> bool:
        try:
            if bool(cfg_map.get("activity_defaults_migrated_v2", False)):
                return False
            timing_mode = str(cfg_map.get("activity_timing_mode", "manual") or "manual").strip().lower()
            if timing_mode != "manual":
                return False
            retry_s = int(cfg_map.get("retry_seconds", 10) or 10)
            rate_s = int(float(cfg_map.get("rate_seconds", 5) or 5))
            parallel_n = int(cfg_map.get("parallel_sends", 2) or 2)
            if retry_s == 30 and rate_s == 30 and parallel_n == 1:
                cfg_map["retry_seconds"] = 10
                cfg_map["rate_seconds"] = 5
                cfg_map["parallel_sends"] = 2
                cfg_map["activity_defaults_migrated_v2"] = True
                return True
        except Exception:
            return False
        return False

    if migrate_legacy_manual_activity_defaults(cfg):
        try:
            save_config(cfg)
        except Exception:
            pass
    # Security policy (TOFU key rotation). Must be visible to on_receive().
    security_policy = "auto"  # auto|strict|always
    # Session rekey (ephemeral X25519) to reduce impact of long-term key compromise.
    session_rekey_enabled = True

    def ui_emit(evt: str, payload: object) -> None:
        if gui_enabled:
            ui_events.put((evt, payload))

    def _routing_log(msg: str) -> None:
        try:
            ui_emit("log", f"{ts_local()} {msg}")
        except Exception:
            pass

    routing_ctl = RoutingController(cfg, log_fn=_routing_log)

    def trace_suppressed(where: str, exc: BaseException) -> None:
        """
        In packet-trace mode, surface otherwise suppressed exceptions to the GUI log.
        Keep it compact to avoid log spam.
        """
        try:
            if not bool(cfg.get("log_packet_trace", False)):
                return
        except Exception:
            return
        try:
            w = str(where or "?").strip()
        except Exception:
            w = "?"
        try:
            et = type(exc).__name__
        except Exception:
            et = "Exception"
        try:
            msg = str(exc)
        except Exception:
            msg = ""
        if msg:
            msg = msg.replace("\n", " ").strip()
        if len(msg) > 160:
            msg = msg[:160] + "..."
        sig = f"{w}|{et}|{msg}"
        try:
            if not hasattr(trace_suppressed, "_last"):
                trace_suppressed._last = {"sig": "", "ts": 0.0}  # type: ignore[attr-defined]
            last = trace_suppressed._last  # type: ignore[attr-defined]
            if sig == str(last.get("sig", "")) and (time.time() - float(last.get("ts", 0.0))) < 0.8:
                return
            trace_suppressed._last = {"sig": sig, "ts": time.time()}  # type: ignore[attr-defined]
        except Exception:
            pass
        line = f"{ts_local()} SUPPRESS: {w} {et}" + (f": {msg}" if msg else "")
        try:
            ui_emit("log", (line, "trace"))
        except Exception:
            try:
                print(line, file=sys.stderr)
            except Exception:
                pass

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
                _saved_print_exc = None
                try:
                    try:
                        _saved_print_exc = traceback.print_exc
                        traceback.print_exc = lambda *args, **kwargs: None  # type: ignore[assignment]
                    except Exception:
                        _saved_print_exc = None
                    return original_handle(self_iface, from_radio_bytes)
                except DecodeError as ex:
                    try:
                        ui_emit(
                            "log",
                            f"{ts_local()} RADIO: transport decode failed in Meshtastic FromRadio parser; "
                            f"the serial stream was corrupted or the device reconnected mid-frame. "
                            f"Auto-reconnect started. detail={type(ex).__name__}: {ex}",
                        )
                        try:
                            startup_log(
                                f"{ts_local()} RADIO: transport decode failed, forcing reconnect ({type(ex).__name__}: {ex})"
                            )
                        except Exception:
                            pass
                        ui_emit("radio_lost", None)
                    except Exception:
                        pass
                    return None
                except Exception as ex:
                    try:
                        ui_emit(
                            "log",
                            f"{ts_local()} RADIO: internal transport handler error; "
                            f"auto-reconnect started. detail={type(ex).__name__}: {ex}",
                        )
                        try:
                            startup_log(
                                f"{ts_local()} RADIO: internal transport handler error, forcing reconnect ({type(ex).__name__}: {ex})"
                            )
                        except Exception:
                            pass
                        ui_emit("radio_lost", None)
                    except Exception:
                        pass
                    return None
                finally:
                    if _saved_print_exc is not None:
                        try:
                            traceback.print_exc = _saved_print_exc  # type: ignore[assignment]
                        except Exception:
                            pass

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
        del peer_norm
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

        # AUTO: trust-on-change only while the old pinned key is still unconfirmed.
        # Once a peer key was confirmed, require manual accept/reset for any rotation.
        # ALWAYS remains the explicit "accept every rotation" mode.
        if key_conf <= 0.0:
            return True, "policy=auto reason=unconfirmed_old_key action=auto_accept"
        return False, "policy=auto reason=confirmed_old_key action=manual_accept"

    def should_auto_accept_first_peer_key(peer_norm: str, st: Optional[PeerState]) -> tuple[bool, str]:
        del peer_norm, st
        pol = str(cfg.get("security_key_rotation_policy", "auto") or "auto").strip().lower()
        if pol == "strict":
            return False, "policy=strict reason=first_seen_manual_accept"
        if pol == "always":
            return True, "policy=always reason=first_seen_auto_accept"
        return True, "policy=auto reason=first_seen_tofu"

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

    def _caps_build_payload() -> bytes:
        """Build encrypted capabilities payload (protocol v2)."""
        try:
            mc_list = ",".join(str(m) for m in supported_mc_modes_for_config(cfg))
        except Exception:
            mc_list = ""
        aad = "1"  # internal control frames always bind AAD type
        body = f"wire={int(PROTO_VERSION)}|msg=2|mc={mc_list}|aad={aad}".encode("utf-8", errors="strict")
        return CAPS_CTRL_PREFIX + b"|" + body

    def _caps_send(peer_norm: str, st: Optional[PeerState], reason: str = "auto") -> None:
        if not st or not st.aes:
            return
        now = time.time()
        try:
            if (now - float(getattr(st, "caps_sent_ts", 0.0) or 0.0)) < 300.0:
                return
        except Exception:
            pass
        pt = _caps_build_payload()
        sent_ok = bool(
            queue_relay_prebuilt(
                peer_norm,
                build_caps_frame(body=pt, epoch_slot=current_epoch_slot(now=now)),
                group_id=f"caps:{peer_norm}:{int(now)}",
                route_reason="caps_v3",
            )
        )
        if sent_ok:
            try:
                st.caps_sent_ts = now
            except Exception:
                pass
            try:
                body = pt[len(CAPS_CTRL_PREFIX) :]
                if body.startswith(b"|"):
                    body = body[1:]
                ui_emit("log", f"{ts_local()} CAPS: tx peer={peer_norm} " + body.decode("utf-8", errors="ignore"))
            except Exception:
                ui_emit("log", f"{ts_local()} CAPS: tx peer={peer_norm}")

    def _caps_request(peer_norm: str, st: Optional[PeerState], reason: str = "auto") -> None:
        if not st or not st.aes:
            return
        now = time.time()
        try:
            if (now - float(getattr(st, "caps_req_ts", 0.0) or 0.0)) < 300.0:
                return
        except Exception:
            pass
        sent_ok = bool(
            queue_relay_prebuilt(
                peer_norm,
                build_caps_req_frame(epoch_slot=current_epoch_slot(now=now)),
                group_id=f"capsreq:{peer_norm}:{int(now)}",
                route_reason="caps_req_v3",
            )
        )
        # Label starts with "caps" so graphs/metrics group it as CAPS service traffic.
        if sent_ok:
            try:
                st.caps_req_ts = now
            except Exception:
                pass
            ui_emit("log", f"{ts_local()} CAPS: req tx peer={peer_norm} reason={reason}")

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
            ok = bool(
                queue_relay_prebuilt(
                    peer_norm,
                    build_rekey1_frame(
                        rid=st.rekey_id,
                        epub=epub,
                        epoch_slot=current_epoch_slot(now=now),
                    ),
                    group_id=f"rekey1:{peer_norm}:{st.rekey_id.hex()}",
                    route_reason="rekey1_v3",
                )
            )
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
            try:
                hs = packet.get("hopStart")
                hl = packet.get("hopLimit")
                hops_rx = max(0, int(hs) - int(hl)) if isinstance(hs, int) and isinstance(hl, int) else None
            except Exception:
                hops_rx = None
            try:
                routing_ctl.observe_rx_telemetry(
                    peer_norm_text,
                    "meshtastic_text",
                    now=time.time(),
                    snr_db=(float(packet.get("rxSnr")) if isinstance(packet.get("rxSnr"), (int, float)) else None),
                    hops=(int(hops_rx) if isinstance(hops_rx, int) else None),
                )
            except Exception:
                pass
            to_id_text = packet.get("toId") or packet.get("to")
            dialog_id_text = "group:Primary" if is_broadcast_dest(to_id_text) else peer_norm_text
            try:
                payload_text = parse_payload(decoded.get("payload"))
            except Exception as ex:
                trace_suppressed("rx.std.parse_payload", ex)
                payload_text = None
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
            if bool(cfg.get("log_packet_trace", False)):
                try:
                    rx_rssi = packet.get("rxRssi")
                    rx_snr = packet.get("rxSnr")
                    ui_emit(
                        "log",
                        f"{ts_local()} PKT: rx std from={peer_norm_text} to={to_id_text or '-'} "
                        f"bytes={len(str(text_plain).encode('utf-8', errors='replace'))} "
                        f"rssi={rx_rssi} snr={rx_snr}",
                    )
                except Exception:
                    pass
            # Meshtastic TEXT_MESSAGE_APP (plain transport).
            try:
                bc = len(text_plain.encode("utf-8", errors="replace"))
            except Exception:
                bc = 0
            activity_record("in", "std", 1, bytes_count=bc)
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
        portnum_int = _portnum_to_int(portnum)
        if portnum_int is not None:
            if int(portnum_int) != int(data_portnum):
                # Count traceroute packets for graphs (even though we don't parse/display them here).
                if int(portnum_int) == int(portnums_pb2.PortNum.TRACEROUTE_APP):
                    try:
                        payload = parse_payload(decoded.get("payload"))
                    except Exception as ex:
                        trace_suppressed("rx.trace.parse_payload", ex)
                        payload = None
                    if payload:
                        try:
                            activity_record("in", "srv", 1, bytes_count=len(payload), subkind="trace")
                        except Exception:
                            pass
                    return
                return
        elif isinstance(portnum, str):
            if str(portnum) != str(data_port_label):
                if str(portnum) == "TRACEROUTE_APP":
                    try:
                        payload = parse_payload(decoded.get("payload"))
                    except Exception as ex:
                        trace_suppressed("rx.trace.parse_payload", ex)
                        payload = None
                    if payload:
                        try:
                            activity_record("in", "srv", 1, bytes_count=len(payload), subkind="trace")
                        except Exception:
                            pass
                    return
                return
        try:
            payload = parse_payload(decoded.get("payload"))
        except Exception as ex:
            trace_suppressed("rx.private.parse_payload", ex)
            payload = None
        if not payload:
            return
        # Deduplicate identical PRIVATE_APP packets before any handshake/decrypt work.
        # This prevents the same RF packet from being processed twice when the
        # Meshtastic integration publishes it on multiple receive topics.
        try:
            from_id_rx = packet.get("fromId") or "?"
            pkt_id_rx = packet.get("id")
            if isinstance(pkt_id_rx, int):
                rx_sig = f"{from_id_rx}|{int(pkt_id_rx) & 0xFFFFFFFF:08x}"
            else:
                rx_time = packet.get("rxTime")
                if rx_time is None:
                    rx_time = decoded.get("rxTime")
                payload_crc = zlib.crc32(bytes(payload)) & 0xFFFFFFFF
                rx_sig = f"{from_id_rx}|{rx_time or '-'}|{payload_crc:08x}"
            now_rx = time.time()
            with seen_lock:
                cutoff = now_rx - 3.0
                for k in list(recent_private_rx.keys()):
                    if float(recent_private_rx.get(k, 0.0) or 0.0) < cutoff:
                        recent_private_rx.pop(k, None)
                last_rx = float(recent_private_rx.get(rx_sig, 0.0) or 0.0)
                if last_rx and (now_rx - last_rx) < 3.0:
                    if bool(cfg.get("log_packet_trace", False)):
                        ui_emit(
                            "log",
                            f"{ts_local()} PKT: suppress duplicate private rx from={from_id_rx} sig={rx_sig}",
                        )
                    return
                recent_private_rx[rx_sig] = now_rx
        except Exception:
            pass
        # Auto-start key exchange on HELLO RX:
        # - If we have NO pinned public key for this peer yet, initiate a key exchange (KR1).
        # - If we already have a pinned pubkey, do not re-initiate just because of HELLO (prevents churn/noise).
        #
        # This matches user expectations: nodes "meet" via HELLO, and new peers get a one-time key exchange.
        try:
            kf_auto = parse_key_frame(payload)
        except Exception:
            kf_auto = None
        try:
            from_id_auto = packet.get("fromId")
            peer_norm_auto = norm_id_for_filename(from_id_auto) if from_id_auto else None
        except Exception:
            peer_norm_auto = None
        if peer_norm_auto:
            try:
                hs = packet.get("hopStart")
                hl = packet.get("hopLimit")
                hops_rx = max(0, int(hs) - int(hl)) if isinstance(hs, int) and isinstance(hl, int) else None
            except Exception:
                hops_rx = None
            try:
                routing_ctl.observe_rx_telemetry(
                    peer_norm_auto,
                    "meshTalk",
                    now=time.time(),
                    snr_db=(float(packet.get("rxSnr")) if isinstance(packet.get("rxSnr"), (int, float)) else None),
                    hops=(int(hops_rx) if isinstance(hops_rx, int) else None),
                )
            except Exception:
                pass
        # Presence + pinned key detection.
        pinned_pub_exists_auto = False
        if peer_norm_auto:
            try:
                pinned_pub_exists_auto = os.path.isfile(os.path.join(keydir, f"{peer_norm_auto}.pub"))
            except Exception:
                pinned_pub_exists_auto = False
        if kf_auto and kf_auto[0] == "hello" and peer_norm_auto and (not pinned_pub_exists_auto):
            try:
                st_auto = get_peer_state(peer_norm_auto)
            except Exception:
                st_auto = None
            if st_auto and (not bool(getattr(st_auto, "key_ready", False))) and (not bool(getattr(st_auto, "pinned_mismatch", False))):
                now_auto = time.time()
                # Primary meeting: initiate immediately (no long throttling).
                # We still rely on send_key_request() local per-peer rate-limit (5s) to avoid duplicates
                # when HELLO is relayed multiple times.
                try:
                    st_auto.last_hello_key_req_ts = float(now_auto)
                    st_auto.force_key_req = True
                    st_auto.await_key_confirm_attempts = 0
                    st_auto.next_key_req_ts = 0.0
                    # Suppress the HELLO hint if we're auto-initiating.
                    st_auto.last_key_hint_ts = float(now_auto)
                except Exception:
                    pass
                allow_hello_req = True
                try:
                    cutoff = now_auto - float(HELLO_NEW_PEER_REQ_WINDOW_SECONDS)
                    while hello_new_peer_req_events and float(hello_new_peer_req_events[0]) < cutoff:
                        hello_new_peer_req_events.popleft()
                    if len(hello_new_peer_req_events) >= int(HELLO_NEW_PEER_REQ_MAX_PER_WINDOW):
                        allow_hello_req = False
                    else:
                        hello_new_peer_req_events.append(float(now_auto))
                except Exception:
                    allow_hello_req = True
                if allow_hello_req:
                    send_key_request(peer_norm_auto, require_confirm=True, reason="hello_rx_new_peer")
                else:
                    ui_emit("log", f"{ts_local()} KEY: hello auto-request throttled peer={peer_norm_auto}")
        if bool(cfg.get("log_packet_trace", False)):
            try:
                from_id_dbg = packet.get("fromId") or "?"
                to_id_dbg = packet.get("toId") or packet.get("to") or "?"
                kind_dbg = "wire"
                kf = parse_key_frame(payload)
                if kf:
                    kind_dbg = f"mt2_{kf[0]}"
                ui_emit(
                    "log",
                    f"{ts_local()} PKT: rx private from={from_id_dbg} to={to_id_dbg} bytes={len(payload)} kind={kind_dbg}",
                )
            except Exception:
                pass

        app_offline_peer = parse_app_offline_frame(payload)
        if app_offline_peer:
            try:
                activity_record("in", "srv", 1, now=time.time(), bytes_count=len(payload), subkind="offline")
            except Exception:
                pass
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
            # Deduplicate: the mesh can relay the same broadcast multiple times.
            # Use both a standalone dict and the state's previous timestamp (if available),
            # to be robust even when state objects are recreated.
            try:
                prev_seen = float(offline_rx_last_ts.get(peer_norm, 0.0) or 0.0)
            except Exception:
                prev_seen = 0.0
            # Also deduplicate by packet id if available (store-and-forward or replays can arrive minutes later).
            pkt_id = packet.get("id")
            try:
                pkt_id_int = int(pkt_id) if isinstance(pkt_id, int) else None
            except Exception:
                pkt_id_int = None
            try:
                prev_id = offline_rx_last_id.get(peer_norm)
            except Exception:
                prev_id = None
            try:
                if st_off is not None:
                    prev_seen = max(prev_seen, float(getattr(st_off, "app_offline_ts", 0.0) or 0.0))
            except Exception:
                pass
            # Defensive: local clock changes can make prev_seen "in the future".
            try:
                if prev_seen > 0.0 and (prev_seen - float(now_seen)) > 5.0:
                    prev_seen = 0.0
            except Exception:
                pass
            offline_rx_last_ts[peer_norm] = float(now_seen)
            if pkt_id_int is not None:
                try:
                    offline_rx_last_id[peer_norm] = int(pkt_id_int) & 0xFFFFFFFF
                except Exception:
                    pass
            if st_off:
                recent_positive_ts = 0.0
                try:
                    recent_positive_ts = max(
                        float(getattr(st_off, "last_seen_ts", 0.0) or 0.0),
                        float(getattr(st_off, "last_hello_rx_ts", 0.0) or 0.0),
                        float(getattr(st_off, "last_key_ok_ts", 0.0) or 0.0),
                    )
                except Exception:
                    recent_positive_ts = 0.0
            else:
                recent_positive_ts = 0.0
            try:
                rec_live = peer_meta.get(peer_norm, {})
                if isinstance(rec_live, dict):
                    recent_positive_ts = max(recent_positive_ts, float(rec_live.get("last_seen_ts", 0.0) or 0.0))
            except Exception:
                pass
            if recent_positive_ts > 0.0 and (now_seen - recent_positive_ts) < 90.0:
                offline_rx_last_ts[peer_norm] = float(now_seen)
                if pkt_id_int is not None:
                    try:
                        offline_rx_last_id[peer_norm] = int(pkt_id_int) & 0xFFFFFFFF
                    except Exception:
                        pass
                if not bool(cfg.get("log_packet_trace", False)):
                    try:
                        ui_emit(
                            "log",
                            f"{ts_local()} PRESENCE: ignored stale offline broadcast from {peer_norm} recent_activity={int(max(0.0, now_seen - recent_positive_ts))}s",
                        )
                    except Exception:
                        pass
                return
            if st_off:
                # Deduplicate: the mesh can relay the same broadcast multiple times.
                # Always update state, but avoid spamming the log/UI.
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
            # Suppress duplicates within 10s, unless packet trace is enabled.
            suppress = False
            if not bool(cfg.get("log_packet_trace", False)):
                try:
                    if pkt_id_int is not None and prev_id is not None and int(prev_id) == (int(pkt_id_int) & 0xFFFFFFFF):
                        suppress = True
                except Exception:
                    pass
                if (not suppress) and (prev_seen > 0.0) and ((now_seen - prev_seen) < 10.0):
                    suppress = True
            if not suppress:
                ui_emit("refresh", None)
                ui_emit("log", f"{ts_local()} PRESENCE: app offline broadcast from {peer_norm}")
            return

        # Protocol v2 plaintext frames on PRIVATE_APP (hello + key exchange).
        try:
            now_mt2 = time.time()

            def _ensure_peer_state(peer_norm: str) -> PeerState:
                st0 = get_peer_state(peer_norm)
                if st0 is None:
                    try:
                        st0 = PeerState(peer_norm, None)
                        peer_states[peer_norm] = st0
                    except Exception:
                        st0 = get_peer_state(peer_norm)
                return st0

            def _send_kr2(peer_norm: str, resp: bytes) -> bool:
                if not radio_ready or interface is None:
                    return False
                return send_packet(
                    interface=interface,
                    payload=resp,
                    destination_id=wire_id_from_norm(peer_norm),
                    port_num=data_portnum,
                    channel_index=(args.channel if args.channel is not None else 0),
                    trace_context="mt2_plaintext.kr2",
                    trace_suppressed_fn=trace_suppressed,
                    ui_emit_fn=ui_emit,
                    log_packet_trace=False,
                    log_line="",
                )

            def _on_key_conflict(peer_norm: str, old_fp: str, new_fp: str) -> None:
                ui_emit("key_conflict", (peer_norm, str(old_fp or ""), str(new_fp or "")))

            def _on_key_confirmed(peer_norm: str, st_obj: PeerState, by: str) -> None:
                del by
                try:
                    st_obj.rekey_sent_msgs = 0
                    st_obj.last_rekey_ts = time.time()
                except Exception:
                    pass
                _caps_send(peer_norm, st_obj, reason="keyok_resp")
                _caps_request(peer_norm, st_obj, reason="keyok_resp")
                ui_emit("peer_update", peer_norm)

            hs_ctx = HandshakeContext(
                self_id=self_id,
                pub_self_raw=bytes(pub_self_raw),
                keydir=keydir,
                key_response_min_interval_s=float(KEY_RESPONSE_MIN_INTERVAL_SECONDS),
                key_response_retry_interval_s=float(KEY_RESPONSE_RETRY_INTERVAL_SECONDS),
                packet_trace=bool(cfg.get("log_packet_trace", False)),
                peer_meta=peer_meta,
                key_response_last_ts=key_response_last_ts,
                norm_peer_id=(lambda pid: norm_id_for_filename(pid) if pid else None),
                wire_id_from_norm=wire_id_from_norm,
                ts_local=ts_local,
                ui_emit=ui_emit,
                activity_record=activity_record,
                get_peer_state=get_peer_state,
                ensure_peer_state=_ensure_peer_state,
                update_peer_names_from_nodes=update_peer_names_from_nodes,
                store_peer_pub=store_peer_pub,
                force_store_peer_pub=force_store_peer_pub,
                update_peer_pub=update_peer_pub,
                should_auto_accept_first_peer_key=should_auto_accept_first_peer_key,
                should_auto_accept_peer_key_rotation=should_auto_accept_peer_key_rotation,
                send_kr2=_send_kr2,
                on_key_conflict=_on_key_conflict,
                on_key_confirmed=_on_key_confirmed,
            )
            if handle_mt2_plaintext(packet, payload, now_mt2, hs_ctx):
                return
        except Exception as ex:
            trace_suppressed("mt2_plaintext", ex)

        from_id = packet.get("fromId")
        peer_norm = norm_id_for_filename(from_id) if from_id else None
        update_peer_names_from_nodes(peer_norm)
        st = get_peer_state(peer_norm)
        if not st or not st.aes:
            # Only trigger a key request when the received payload actually looks like an MT-WIRE frame.
            # Otherwise we can end up spamming KR1 in response to unrelated PRIVATE_APP traffic.
            looks_like_wire = False
            try:
                if isinstance(payload, (bytes, bytearray)) and len(payload) >= (1 + 1 + 8 + 12 + 16):
                    ver0 = int(payload[0])
                    t0 = int(payload[1])
                    if ver0 == int(ENVELOPE_V3_VERSION) and t0 == int(ENVELOPE_V3_TYPE_DATA):
                        looks_like_wire = True
            except Exception:
                looks_like_wire = False
            if not looks_like_wire:
                if bool(cfg.get("log_packet_trace", False)):
                    try:
                        ui_emit(
                            "log",
                            f"{ts_local()} PKT: rx private ignored (unknown frame) from={from_id or '?'} bytes={len(payload)}",
                        )
                    except Exception:
                        pass
                return
            if peer_norm and from_id:
                st = get_peer_state(peer_norm)
                if st:
                    st.force_key_req = True
                    st.await_key_confirm_attempts = 0
                    now = time.time()
                    if now >= st.next_key_req_ts:
                        send_key_request(peer_norm, require_confirm=True, reason="rx_no_key")
                        st.next_key_req_ts = now + max(1.0, float(args.retry_seconds))
                        ui_emit("log", f"{ts_local()} KEY: request (no key) -> {from_id}")
                        ui_emit("peer_update", peer_norm)
            return

        # Rekey can temporarily accept multiple keys to avoid network churn during switch.
        aes_used = st.aes
        outer_v3 = False
        if isinstance(payload, (bytes, bytearray)) and len(payload) >= (1 + 1 + 8 + 12 + 16) and int(payload[0]) == int(ENVELOPE_V3_VERSION):
            status3, msg_id3, pt3 = try_unpack_envelope_v3(payload, st.aes)
            if status3 == "ok":
                status, msg_type, msg_id, pt, rx_compression = ("ok", TYPE_MSG, msg_id3, pt3, "none")
                outer_v3 = True
            else:
                status, msg_type, msg_id, pt, rx_compression = (status3, TYPE_MSG, msg_id3, None, "n/a")
        else:
            ui_emit("log", f"{ts_local()} PKT: drop legacy envelope from={from_id or '?'} reason=legacy_envelope_disabled")
            return
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
                if isinstance(payload, (bytes, bytearray)) and len(payload) >= (1 + 1 + 8 + 12 + 16) and int(payload[0]) == int(ENVELOPE_V3_VERSION):
                    status2, msg_id2, pt2 = try_unpack_envelope_v3(payload, alt)
                    if status2 == "ok" and msg_id2 is not None:
                        status, msg_type, msg_id, pt, rx_compression = ("ok", TYPE_MSG, msg_id2, pt2, "none")
                        aes_used = alt
                        outer_v3 = True
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
            # Suppress duplicate noise bursts (same stale packet mirrored/retried in short window).
            if (now - float(getattr(st, "last_decrypt_fail_log_ts", 0.0) or 0.0)) >= 1.5:
                ui_emit(
                    "log",
                    f"{ts_local()} KEY: decrypt failed peer={from_id} count={st.decrypt_fail_count} (possible stale key) initiator=remote event=decrypt_fail wire=MT-WIREv{int(PROTO_VERSION)} aes-256-gcm",
                )
                st.last_decrypt_fail_log_ts = now
            if peer_norm:
                st.force_key_req = True
                recent_key_ok_ts = float(getattr(st, "last_key_ok_ts", 0.0) or 0.0)
                in_startup_grace = (now - float(runtime_session_started_ts or 0.0)) <= float(DECRYPT_FAIL_STARTUP_GRACE_SECONDS)
                in_recent_key_grace = recent_key_ok_ts > 0.0 and (now - recent_key_ok_ts) <= float(DECRYPT_FAIL_RECENT_KEYOK_GRACE_SECONDS)
                in_decrypt_fail_grace = bool(in_startup_grace or in_recent_key_grace)
                suspend_threshold = int(DECRYPT_FAIL_GRACE_SUSPEND_THRESHOLD) if in_decrypt_fail_grace else 2
                if st.decrypt_fail_count >= 2 and in_decrypt_fail_grace and st.decrypt_fail_count < suspend_threshold:
                    if (now - float(getattr(st, "last_decrypt_fail_grace_log_ts", 0.0) or 0.0)) >= 5.0:
                        ui_emit(
                            "log",
                            f"{ts_local()} KEY: decrypt_fail recovery grace peer={from_id} count={st.decrypt_fail_count} startup={1 if in_startup_grace else 0} recent_keyok={1 if in_recent_key_grace else 0} action=request_only",
                        )
                        st.last_decrypt_fail_grace_log_ts = now
                    if now >= st.next_key_req_ts:
                        send_key_request(peer_norm, require_confirm=True, reason="decrypt_fail")
                    return
                if st.decrypt_fail_count >= suspend_threshold:
                    # Suspend old key without deleting; wait for fresh exchange
                    st.aes = None
                    st.next_key_req_ts = 0.0
                    ui_emit(
                        "log",
                        f"{ts_local()} KEY: suspend key peer={from_id} initiator=local reason=decrypt_fail count={st.decrypt_fail_count}",
                    )
                    if now >= st.next_key_req_ts:
                        send_key_request(peer_norm, require_confirm=True, reason="decrypt_fail")
                ui_emit("peer_update", peer_norm)
            return
        if status != "ok" or msg_type is None or msg_id is None:
            return
        try:
            st.last_seen_ts = time.time()
            st.app_offline_ts = 0.0
        except Exception:
            pass
        try:
            if peer_norm:
                nudge_pending_peer(peer_norm, now=time.time())
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
            st.await_key_confirm_attempts = 0
            st.force_key_req = False
            st.next_key_req_ts = float("inf")
            st.last_key_ok_ts = time.time()
            st.key_confirmed_ts = st.last_key_ok_ts
            try:
                st.rekey_sent_msgs = 0
                st.last_rekey_ts = st.last_key_ok_ts
            except Exception:
                pass
            if from_id:
                ui_emit(
                    "log",
                    f"{ts_local()} KEYOK: confirmed_by=payload peer={from_id} initiator=remote wire=MT-WIREv{int(PROTO_VERSION)} aes-256-gcm",
                )
            if peer_norm:
                _caps_send(peer_norm, st, reason="keyok_payload")
                _caps_request(peer_norm, st, reason="keyok_payload")
                ui_emit("peer_update", peer_norm)

        def send_relay_control_frame(
            dest_id: Optional[str],
            peer_state: object,
            frame_payload: bytes,
            *,
            aes_override: Optional[object] = None,
        ) -> bool:
            if not dest_id or interface is None or peer_state is None:
                return False
            try:
                aes_local = aes_override if aes_override is not None else getattr(peer_state, "aes", None)
                if aes_local is None:
                    return False
                wire_payload = pack_envelope_v3(os.urandom(8), aes_local, bytes(frame_payload or b""))
                if not send_packet(
                    interface=interface,
                    payload=wire_payload,
                    destination_id=dest_id,
                    port_num=data_portnum,
                    channel_index=(args.channel if args.channel is not None else 0),
                    trace_context="send_relay_control_frame",
                    trace_suppressed_fn=trace_suppressed,
                    ui_emit_fn=ui_emit,
                    log_packet_trace=False,
                    log_line="",
                ):
                    return False
                activity_record("out", "srv", 1, bytes_count=len(wire_payload), subkind="relay_ack")
                return True
            except Exception:
                return False

        def send_relay_hop_ack(dest_id: Optional[str], peer_state: object, frame_obj: object) -> bool:
            if frame_obj is None:
                return False
            return send_relay_control_frame(dest_id, peer_state, build_hop_ack_for_frame(frame_obj))

        def consume_relay_pending_ack(frame_msg_id: bytes, frame_part: int, ack_kind: str) -> Optional[dict]:
            removed = None
            with pending_lock:
                peer_pending = pending_by_peer.get(peer_norm or "", {})
                if isinstance(peer_pending, dict):
                    _pending_id, removed = pop_matching_relay_pending(
                        peer_pending,
                        frame_msg_id=frame_msg_id,
                        frame_part=frame_part,
                    )
                if removed is not None:
                    if not peer_pending and peer_norm:
                        pending_by_peer.pop(peer_norm, None)
                    save_state(pending_by_peer)
            if removed is None:
                return None
            relay_mid = bytes(frame_msg_id or b"").hex()
            target_part = max(1, int(frame_part or 1))
            try:
                if peer_norm:
                    nudge_pending_peer(peer_norm, now=time.time())
            except Exception:
                pass
            if st:
                ack_now = time.time()
                last_send = float(removed.get("last_send", 0.0) or 0.0)
                attempts = int(removed.get("attempts", 0) or 0)
                rtt = max(0.0, ack_now - last_send) if last_send > 0.0 else 0.0
                st.rtt_count += 1
                st.rtt_avg = st.rtt_avg + (rtt - st.rtt_avg) / float(st.rtt_count)
                try:
                    st.last_ack_ts = float(ack_now)
                except Exception:
                    pass
                try:
                    pacer.observe_ack(rtt_s=rtt, attempts=max(1, attempts), now=ack_now)
                except Exception:
                    pass
                ui_emit(
                    "log",
                    f"{ts_local()} RELAY: {ack_kind} msg={relay_mid} part={target_part} rtt={rtt:.2f}s attempts={attempts}",
                )
                ui_emit(
                    "log",
                    f"{ts_local()} FLOW: ack flow={relay_mid} part={target_part} from={peer_norm or '-'} "
                    f"rtt={rtt:.2f}s attempts={attempts}",
                )
            return removed

        if msg_type == TYPE_MSG:
            try:
                raw_pt = bytes(pt) if isinstance(pt, (bytes, bytearray)) else b""
            except Exception:
                raw_pt = b""
            msg_key = f"{peer_norm}:{msg_hex}"
            with seen_lock:
                last = seen_msgs.get(msg_key)
                now = time.time()
                if last and (now - last) < 3600:
                    # Duplicate, still ACK but no re-print.
                    if from_id:
                        dup_relay = parse_relay_frame(raw_pt)
                        if dup_relay is not None:
                            if duplicate_requires_hop_ack(int(dup_relay.frame_type)):
                                send_relay_hop_ack(from_id, st, dup_relay)
                        else:
                            ui_emit(
                                "log",
                                f"{ts_local()} PKT: ignore duplicate legacy payload from={peer_norm or '-'} reason=legacy_envelope_disabled",
                            )
                    return
                seen_msgs[msg_key] = now

            legacy_drop = detect_legacy_control_drop(
                raw_pt,
                peer_norm=peer_norm or "",
                from_id=from_id,
                caps_req_prefix=CAPS_REQ_PREFIX,
                caps_ctrl_prefix=CAPS_CTRL_PREFIX,
                rekey1_prefix=REKEY_CTRL_PREFIX1,
                rekey2_prefix=REKEY_CTRL_PREFIX2,
                rekey3_prefix=REKEY_CTRL_PREFIX3,
            )
            if legacy_drop == "caps_req":
                ui_emit("log", f"{ts_local()} CAPS: drop legacy req from={peer_norm} reason=legacy_caps_disabled")
                return
            if legacy_drop == "caps":
                ui_emit("log", f"{ts_local()} CAPS: drop legacy frame from={peer_norm} reason=legacy_caps_disabled")
                return
            if legacy_drop in ("rk1", "rk2", "rk3"):
                ui_emit("log", f"{ts_local()} KEY: drop legacy {legacy_drop} from={peer_norm} reason=legacy_rekey_disabled")
                return

            relay_frame = parse_relay_frame(raw_pt)
            if relay_frame is not None:
                if peer_norm:
                    try:
                        learn_relay_neighbor(
                            relay_state,
                            peer_norm,
                            relay_frame,
                            relay_token_for_peer=_relay_token_for_peer,
                            now=now,
                        )
                    except Exception:
                        pass
                if relay_frame.frame_type in (RELAY_TYPE_HOP_ACK, RELAY_TYPE_END_ACK):
                    ack_part = decode_hop_ack_part(relay_frame)
                    process_ack_frame_direct(
                        relay_frame=relay_frame,
                        relay_state=relay_state,
                        peer_norm=peer_norm or "",
                        ack_part=ack_part,
                        token_matches_self=_relay_token_matches_self(relay_frame.return_token, now=now),
                        consume_hop_ack_fn=consume_relay_pending_ack,
                        queue_relay_prebuilt_fn=queue_relay_prebuilt,
                        ui_emit_fn=ui_emit,
                        ts_local_fn=ts_local,
                    )
                    return
                if relay_frame.frame_type == RELAY_TYPE_TOKEN_ADV:
                    try:
                        process_token_adv_frame_direct(
                            relay_frame=relay_frame,
                            relay_state=relay_state,
                            peer_norm=peer_norm or "",
                            now=now,
                            queue_relay_prebuilt_fn=queue_relay_prebuilt,
                            ui_emit_fn=ui_emit,
                            ts_local_fn=ts_local,
                        )
                    except Exception as ex:
                        trace_suppressed("relay_v3.token_adv", ex)
                    if from_id:
                        send_relay_hop_ack(from_id, st, relay_frame)
                    return
                if relay_frame.frame_type == RELAY_TYPE_CAPS_REQ:
                    activity_record("in", "srv", 1, bytes_count=len(payload), subkind="caps")
                    if peer_norm:
                        _caps_send(peer_norm, st, reason="req_v3")
                    if from_id:
                        send_relay_hop_ack(from_id, st, relay_frame)
                    return
                if relay_frame.frame_type == RELAY_TYPE_CAPS:
                    activity_record("in", "srv", 1, bytes_count=len(payload), subkind="caps")
                    try:
                        local_modes = list(supported_mc_modes_for_config(cfg))
                        caps = update_caps_from_body(
                            st,
                            bytes(relay_frame.body or b""),
                            parse_caps_frame=parse_caps_frame,
                            parse_caps_versions=parse_caps_versions,
                            supported_mc_modes=local_modes,
                            now=time.time(),
                        )
                        if caps:
                            ui_emit(
                                "log",
                                f"{ts_local()} CAPS: rx peer={peer_norm} wire={caps.get('wire','-')} msg={caps.get('msg','-')} mc={caps.get('mc','-')} aad={caps.get('aad','-')}",
                            )
                            if peer_norm:
                                ui_emit("peer_update", peer_norm)
                    except Exception:
                        pass
                    if from_id:
                        send_relay_hop_ack(from_id, st, relay_frame)
                    return
                if relay_frame.frame_type == RELAY_TYPE_REKEY1 and peer_norm and from_id:
                    activity_record("in", "srv", 1, bytes_count=len(payload), subkind="rekey")
                    try:
                        rekey_result = handle_rekey1(
                            st,
                            peer_norm,
                            relay_frame,
                            now=time.time(),
                            derive_aes_fn=_rekey_derive_aes,
                        )
                        if rekey_result.get("response_frame"):
                            send_relay_control_frame(
                                from_id,
                                st,
                                rekey_result["response_frame"],
                            )
                        if rekey_result.get("log"):
                            ui_emit("log", f"{ts_local()} {rekey_result['log']}")
                    except Exception:
                        pass
                    if from_id:
                        send_relay_hop_ack(from_id, st, relay_frame)
                    return
                if relay_frame.frame_type == RELAY_TYPE_REKEY2 and peer_norm and from_id:
                    activity_record("in", "srv", 1, bytes_count=len(payload), subkind="rekey")
                    try:
                        rekey_result = handle_rekey2(
                            st,
                            peer_norm,
                            relay_frame,
                            now=time.time(),
                            derive_aes_fn=_rekey_derive_aes,
                            prev_key_grace_seconds=REKEY_PREV_KEY_GRACE_SECONDS,
                        )
                        if rekey_result.get("response_frame"):
                            send_relay_control_frame(
                                from_id,
                                st,
                                rekey_result["response_frame"],
                                aes_override=rekey_result.get("response_aes_override"),
                            )
                        if rekey_result.get("log"):
                            ui_emit("log", f"{ts_local()} {rekey_result['log']}")
                    except Exception:
                        pass
                    if from_id:
                        send_relay_hop_ack(from_id, st, relay_frame)
                    return
                if relay_frame.frame_type == RELAY_TYPE_REKEY3 and peer_norm and from_id:
                    activity_record("in", "srv", 1, bytes_count=len(payload), subkind="rekey")
                    try:
                        rekey_result = handle_rekey3(
                            st,
                            relay_frame,
                            now=time.time(),
                            prev_key_grace_seconds=REKEY_PREV_KEY_GRACE_SECONDS,
                            peer_norm=peer_norm,
                        )
                        if rekey_result.get("log"):
                            ui_emit("log", f"{ts_local()} {rekey_result['log']}")
                    except Exception:
                        pass
                    if from_id:
                        send_relay_hop_ack(from_id, st, relay_frame)
                    return
                if relay_frame.frame_type == RELAY_TYPE_DATA:
                    try:
                        process_data_frame_direct(
                            relay_frame=relay_frame,
                            relay_incoming=relay_incoming,
                            peer_norm=peer_norm or "",
                            packet=packet,
                            local_deliver=_relay_token_matches_self(relay_frame.relay_token, now=now),
                            relay_state=relay_state,
                            now=now,
                            decompress_text_fn=decompress_text,
                            from_id=from_id or "",
                            peer_state=st,
                            send_relay_control_frame_fn=send_relay_control_frame,
                            pending_by_peer=pending_by_peer,
                            pending_lock=pending_lock,
                            save_state_fn=save_state,
                            ui_emit_fn=ui_emit,
                            ts_local_fn=ts_local,
                        )
                    except Exception as ex:
                        trace_suppressed("relay_v3.data", ex)
                    if from_id:
                        send_relay_hop_ack(from_id, st, relay_frame)
                    return

            ui_emit(
                "log",
                f"{ts_local()} RELAY: drop legacy payload from={peer_norm or '-'} reason=legacy_wire_disabled",
            )
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
                _safe_pub_subscribe_once(on_receive, "meshtastic.receive.data")
                try:
                    _safe_pub_subscribe_once(on_receive, "meshtastic.receive")
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

    def restore_public_from_private() -> bool:
        nonlocal pub_self, pub_self_raw
        if not priv_path or not pub_path:
            return False
        if not os.path.isfile(priv_path):
            return False
        try:
            priv_local = load_priv(priv_path)
            pub_local = priv_local.public_key()
            pub_raw = pub_local.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            os.makedirs(os.path.dirname(pub_path) or ".", exist_ok=True)
            with open(pub_path, "w", encoding="utf-8") as f:
                f.write(b64e(pub_raw))
            harden_file(pub_path)
            pub_self = load_pub(pub_path)
            pub_self_raw = pub_self.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            ui_emit("self_update", None)
            ui_emit("log", f"{ts_local()} KEY: restored public key from private key.")
            return True
        except Exception as ex:
            ui_emit("log", f"{ts_local()} KEY: failed to restore public key ({type(ex).__name__}).")
            return False

    def _derive_backup_key(passphrase: str, salt: bytes) -> bytes:
        kdf = Scrypt(salt=bytes(salt), length=32, n=2**15, r=8, p=1)
        return kdf.derive(str(passphrase).encode("utf-8"))

    def _pack_private_backup_encrypted(priv_raw: bytes, passphrase: str) -> str:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = _derive_backup_key(passphrase, salt)
        ct = AESGCM(key).encrypt(nonce, bytes(priv_raw), b"meshTalk private backup v1")
        return (
            f"{PRIVATE_KEY_BACKUP_MAGIC}|"
            f"{base64.b64encode(salt).decode('ascii')}|"
            f"{base64.b64encode(nonce).decode('ascii')}|"
            f"{base64.b64encode(ct).decode('ascii')}"
        )

    def _load_private_key_from_backup_blob(blob: bytes, passphrase_provider=None) -> bytes:
        # Legacy support:
        # - raw 32-byte file
        # - plain base64 text
        # - encrypted MTPRIV1 format
        if len(blob) == 32:
            return bytes(blob)
        txt = blob.decode("utf-8", errors="strict").strip()
        if txt.startswith(PRIVATE_KEY_BACKUP_MAGIC + "|"):
            parts = txt.split("|")
            if len(parts) != 4:
                raise ValueError("invalid encrypted backup format")
            if passphrase_provider is None:
                raise ValueError("passphrase required")
            passphrase = str(passphrase_provider() or "")
            if not passphrase:
                raise ValueError("empty passphrase")
            salt = base64.b64decode(parts[1].encode("ascii"), validate=True)
            nonce = base64.b64decode(parts[2].encode("ascii"), validate=True)
            ct = base64.b64decode(parts[3].encode("ascii"), validate=True)
            key = _derive_backup_key(passphrase, salt)
            raw = AESGCM(key).decrypt(nonce, ct, b"meshTalk private backup v1")
            if len(raw) != 32:
                raise ValueError("invalid private key length")
            return bytes(raw)
        raw = b64d(txt)
        if len(raw) != 32:
            raise ValueError("invalid private key length")
        return bytes(raw)

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
        if not routing_ctl.allow_control("key_req"):
            ui_emit(
                "log",
                f"{ts_local()} KEY: suppressed (control-throttle) peer={wire_id_from_norm(peer_norm)} initiator=local reason={reason or '-'}",
            )
            if st and require_confirm:
                attempts = int(max(1, int(getattr(st, "await_key_confirm_attempts", 1) or 1)))
                st.next_key_req_ts = now + retry_delay_seconds(float(args.retry_seconds), attempts)
            return
        dest_id = wire_id_from_norm(peer_norm)
        # Protocol v2: compact binary KR1 (unicast). Do not leak capabilities in plaintext.
        nonce4 = os.urandom(4)
        req = build_kr1_frame(bytes(pub_self_raw), bytes(nonce4))
        if not send_packet(
            interface=interface,
            payload=req,
            destination_id=dest_id,
            port_num=data_portnum,
            channel_index=(args.channel if args.channel is not None else 0),
            trace_context="send_key_request",
            trace_suppressed_fn=trace_suppressed,
            ui_emit_fn=ui_emit,
            log_packet_trace=False,
            log_line="",
        ):
            return
        activity_record("out", "srv", 1, now=now, bytes_count=len(req), subkind="key")
        last_activity_ts = now
        last_key_sent_ts = last_activity_ts
        if st:
            st.last_key_req_ts = last_activity_ts
            st.last_key_req_reason = str(reason or "")
            st.last_key_req_initiator = "local"
            st.next_key_refresh_ts = last_activity_ts + 3600.0 + random.uniform(0, 600)
            if require_confirm:
                st.await_key_confirm = True
                attempts = int(getattr(st, "await_key_confirm_attempts", 0) or 0) + 1
                st.await_key_confirm_attempts = int(max(1, attempts))
                if st.await_key_confirm_attempts >= 6:
                    st.await_key_confirm = False
                    st.force_key_req = False
                    st.next_key_req_ts = float("inf")
                    ui_emit(
                        "log",
                        f"{ts_local()} KEY: confirm timeout peer={dest_id} auto_retries_paused attempts={int(st.await_key_confirm_attempts)}",
                    )
                else:
                    st.next_key_req_ts = last_activity_ts + retry_delay_seconds(float(args.retry_seconds), int(st.await_key_confirm_attempts))
        ui_emit(
            "log",
            f"{ts_local()} KEY: request sent to {dest_id} initiator=local reason={reason or '-'} confirm={1 if require_confirm else 0} frame=KR1 plaintext x25519(32b)->aes-256-gcm",
        )

    def defer_stable_key_refresh(st, now: float) -> float:
        # Stable peers do not need frequent background KR1 refresh. If the key was
        # recently confirmed or refreshed, postpone the low-priority refresh tick.
        try:
            recent_key_ts = max(
                float(getattr(st, "key_confirmed_ts", 0.0) or 0.0),
                float(getattr(st, "last_key_ok_ts", 0.0) or 0.0),
                float(getattr(st, "last_key_req_ts", 0.0) or 0.0),
            )
        except Exception:
            recent_key_ts = 0.0
        if recent_key_ts <= 0.0:
            return 0.0
        stable_refresh_min_age_s = 3.0 * 3600.0
        if (float(now) - recent_key_ts) < stable_refresh_min_age_s:
            return float(recent_key_ts) + stable_refresh_min_age_s + random.uniform(0, 600)
        return 0.0

    def send_discovery_broadcast() -> bool:
        nonlocal last_hello_broadcast_log_ts
        if not radio_ready or interface is None:
            return False
        if not routing_ctl.allow_control("discovery"):
            return False
        # Protocol v2: HELLO broadcast without public key (minimize plaintext metadata).
        nonce4 = os.urandom(4)
        req = build_hello_frame(bytes(nonce4))
        if not send_packet(
            interface=interface,
            payload=req,
            destination_id=meshtastic.BROADCAST_ADDR,
            port_num=data_portnum,
            channel_index=(args.channel if args.channel is not None else 0),
            trace_context="send_discovery_broadcast",
            trace_suppressed_fn=trace_suppressed,
            ui_emit_fn=ui_emit,
            log_packet_trace=False,
            log_line="",
        ):
            return False
        activity_record("out", "srv", 1, bytes_count=len(req), subkind="disc")
        now = time.time()
        # When packet trace or verbose is enabled: show every hello TX (true packet view).
        if bool(cfg.get("log_packet_trace", False)) or bool(cfg.get("log_verbose", True)):
            ui_emit("log", f"{ts_local()} HELLO: tx -> ^all bytes={len(req)} proto=MT2")
        else:
            # Otherwise throttle to avoid spam.
            if (now - float(last_hello_broadcast_log_ts or 0.0)) >= 20.0:
                last_hello_broadcast_log_ts = now
                ui_emit("log", f"{ts_local()} HELLO: tx -> ^all bytes={len(req)} proto=MT2")
        return True

    def _hello_interval_seconds_by_uptime(elapsed_s: float) -> float:
        # Fixed HELLO schedule:
        # 0..10 min => 30s
        # 10 min..3h => 3 min
        # 3h+ => 10 min
        try:
            e = float(elapsed_s)
        except Exception:
            e = 0.0
        if e < 600.0:
            return 30.0
        if e < (3.0 * 3600.0):
            return 180.0
        return 600.0

    def send_discovery_burst() -> int:
        return 1 if send_discovery_broadcast() else 0

    def send_app_offline_broadcast(*, nowait: bool = False) -> None:
        # Guard against multiple shutdown hooks firing (Qt aboutToQuit + atexit, etc).
        nonlocal app_offline_sent
        try:
            if bool(app_offline_sent):
                return
        except Exception:
            pass
        if not radio_ready or interface is None:
            return
        if not routing_ctl.allow_control("offline"):
            return
        payload = APP_OFFLINE_PREFIX + self_id.encode("utf-8")
        send_fn = try_send_packet_nowait if nowait else send_packet
        if not send_fn(
            interface=interface,
            payload=payload,
            destination_id=meshtastic.BROADCAST_ADDR,
            port_num=data_portnum,
            channel_index=(args.channel if args.channel is not None else 0),
            trace_context="send_app_offline_broadcast",
            trace_suppressed_fn=trace_suppressed,
            ui_emit_fn=ui_emit,
            log_packet_trace=False,
            log_line="",
        ):
            return
        activity_record("out", "srv", 1, bytes_count=len(payload), subkind="offline")
        app_offline_sent = True
        ui_emit("log", f"{ts_local()} PRESENCE: app offline broadcast")

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
        def _cfg_float(key: str, default: float) -> float:
            try:
                v = float(cfg.get(key, default))
                if not math.isfinite(v):
                    return float(default)
                return float(v)
            except Exception:
                return float(default)

        step = max(1, int(attempts_next) - 1)
        raw = max(1.0, float(base)) * (2.0 ** step)
        cap_s = max(1.0, _cfg_float("activity_retry_backoff_max_seconds", float(RETRY_BACKOFF_MAX_SECONDS)))
        jitter_ratio = max(0.0, min(1.0, _cfg_float("activity_retry_jitter_ratio", float(RETRY_JITTER_RATIO))))
        capped = min(float(cap_s), raw)
        jitter = capped * float(jitter_ratio) * random.uniform(-1.0, 1.0)
        return max(1.0, capped + jitter)

    def peer_is_responsive(st: object, now: float) -> bool:
        # Peer is "responsive" if we saw any meshTalk activity recently:
        # - ACK for any packet, or
        # - inbound meshTalk packets (last_seen_ts is updated on receive).
        try:
            last_ack = float(getattr(st, "last_ack_ts", 0.0) or 0.0)
        except Exception:
            last_ack = 0.0
        try:
            last_seen = float(getattr(st, "last_seen_ts", 0.0) or 0.0)
        except Exception:
            last_seen = 0.0
        try:
            grace = float(cfg.get("activity_peer_responsive_grace_seconds", float(PEER_RESPONSIVE_GRACE_SECONDS)))
        except Exception:
            grace = float(PEER_RESPONSIVE_GRACE_SECONDS)
        grace = max(1.0, float(grace))
        if last_ack > 0.0 and (now - last_ack) <= grace:
            return True
        if last_seen > 0.0 and (now - last_seen) <= grace:
            return True
        return False

    def peer_last_activity_ts(st: object) -> float:
        # Best-effort "is peer alive" signal (meshTalk only).
        # Used to reduce retries when peer appears offline.
        try:
            la = float(getattr(st, "last_ack_ts", 0.0) or 0.0)
        except Exception:
            la = 0.0
        try:
            ls = float(getattr(st, "last_seen_ts", 0.0) or 0.0)
        except Exception:
            ls = 0.0
        return float(max(la, ls, 0.0))

    def schedule_next_retry_for_record(rec: dict, st: object, now: float, base_active_s: float, attempts_next: int) -> float:
        # Manual mode with "quiet retry":
        # - when peer is silent, wait at least 5 minutes before next try,
        # - retries keep increasing by normal backoff logic.
        rec.pop("trickle_i_s", None)
        rec.pop("trickle_t_s", None)
        delay = retry_delay_seconds(float(base_active_s), attempts_next)
        if st is not None and not peer_is_responsive(st, now):
            rec["retry_phase"] = "waiting_peer"
            return max(300.0, float(delay))
        rec["retry_phase"] = "active"
        return float(delay)

    def nudge_pending_peer(peer_norm: str, now: Optional[float] = None) -> int:
        """When peer responds, bring pending retries closer instead of waiting long quiet gaps."""
        if not peer_norm:
            return 0
        t_now = time.time() if now is None else float(now)
        try:
            base = max(1.0, float(getattr(args, "retry_seconds", 10) or 10))
        except Exception:
            base = 30.0
        next_ts = t_now + base
        touched = 0
        with pending_lock:
            items = pending_by_peer.get(peer_norm, {})
            if not isinstance(items, dict) or not items:
                return 0
            for rec in items.values():
                if not isinstance(rec, dict):
                    continue
                try:
                    cur_next = float(rec.get("next_retry_at", 0.0) or 0.0)
                except Exception:
                    cur_next = 0.0
                if cur_next <= 0.0 or cur_next > next_ts:
                    rec["next_retry_at"] = float(next_ts)
                    rec["retry_phase"] = "active"
                    touched += 1
            if touched > 0:
                save_state(pending_by_peer)
        return int(touched)

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

    # Metrics moved to meshtalk/metrics.py (pure logic + unit tests).

    def queue_message(
        peer_norm: str,
        text: str,
        route_id: str = "meshTalk",
        route_score: float = 0.0,
        route_reason: str = "",
    ) -> Optional[tuple[str, int, Optional[str], Optional[float], Optional[str]]]:
        nonlocal last_activity_ts
        peer_norm = norm_id_for_filename(peer_norm)
        st = get_peer_state(peer_norm)
        if not st:
            return None
        st.force_key_req = True
        created = time.time()
        relay_msg_id = os.urandom(8)
        group_id = relay_msg_id.hex()
        text_bytes = text.encode("utf-8")
        payload_blob = text_bytes
        compression_flag = 0
        cmp_label = "none"
        cmp_norm_label = "off"
        packed_blob_len = len(text_bytes)
        cmp_eff_pct: Optional[float] = None
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
        relay_body_chunks: list[bytes] = []
        if compression_policy != "off" and peer_supports_msg_v2:
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
            best_len = len(best_blob) if isinstance(best_blob, (bytes, bytearray)) else -1
            try:
                gain_pct = ((float(len(text_bytes)) - float(best_len)) / float(max(1, len(text_bytes)))) * 100.0 if best_len >= 0 else None
            except Exception:
                gain_pct = None

            relay_body_limit = max(1, int(max_plain) - int(RELAY_HEADER_LEN))

            def _estimate_wire_total(blob_len: int) -> int:
                parts_n = max(1, int(math.ceil(float(max(1, blob_len + 1)) / float(max(1, relay_body_limit)))))
                total_wire = 0
                remaining = int(max(1, blob_len + 1))
                for _idx in range(parts_n):
                    ch_len = min(int(relay_body_limit), int(remaining))
                    remaining = max(0, int(remaining) - int(ch_len))
                    total_wire += int(RELAY_HEADER_LEN) + int(ch_len) + int(PAYLOAD_OVERHEAD)
                return int(total_wire)

            plain_wire_total = _estimate_wire_total(len(text_bytes))
            compressed_wire_total = _estimate_wire_total(len(best_blob)) if best_blob is not None else -1

            if (
                best_blob is not None
                and compressed_wire_total > 0
                and compressed_wire_total < plain_wire_total
            ):
                payload_blob = best_blob
                compression_flag = 1
                cmp_label = mode_name(int(best_mode))
                cmp_norm_label = best_norm_mode
                packed_blob_len = len(best_blob)
                cmp_eff_pct = compression_efficiency_pct(len(text_bytes), len(best_blob))
                ui_emit(
                    "log",
                    f"{ts_local()} COMPRESS: group={group_id} mode={normalize_compression_name(cmp_label) or cmp_label} "
                    f"norm={cmp_norm_label} plain={len(text_bytes)} packed={packed_blob_len} "
                    f"size={(cmp_eff_pct if cmp_eff_pct is not None else 0.0):.1f}% "
                    f"gain={(gain_pct if gain_pct is not None else 0.0):.1f}% "
                    f"wire_plain={plain_wire_total} wire_comp={compressed_wire_total}",
                )
            else:
                # Make the decision visible in logs to aid debugging.
                try:
                    ui_emit(
                        "log",
                        f"{ts_local()} COMPRESS: skip group={group_id} reason=no_gain plain={len(text_bytes)} "
                        f"best={best_len} gain={(gain_pct if gain_pct is not None else 0.0):.1f}% "
                        f"wire_plain={plain_wire_total} wire_comp={compressed_wire_total}",
                    )
                except Exception:
                    pass
        relay_body_limit = max(1, int(max_plain) - int(RELAY_HEADER_LEN))
        relay_body = bytes([1 if int(compression_flag) == 1 else 0]) + bytes(payload_blob)
        relay_body_chunks = split_bytes(relay_body, relay_body_limit)
        total = len(relay_body_chunks)
        relay_token = _relay_token_for_peer(peer_norm, current_epoch_slot(now=created))
        return_token = _relay_token_for_peer(self_id, current_epoch_slot(now=created))
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
                    "relay_msg_hex": group_id,
                    "relay_frame_type": "data",
                    "part": idx,
                    "total": total,
                    "text": text,
                    "relay_v3": True,
                    "compression": compression_flag,
                    "cmp": cmp_label,
                    "cmp_norm": cmp_norm_label,
                    "cmp_eff_pct": cmp_eff_pct,
                    "created": created,
                    "attempts": 0,
                    "last_send": 0.0,
                    "next_retry_at": 0.0,
                    "retry_phase": "active",
                    "retry_phase_attempts": 0,
                    "next_probe_ts": 0.0,
                    "probe_until_ts": 0.0,
                    "probe_attempts": 0,
                    "peer": peer_norm,
                    "route_id": str(route_id or "meshTalk"),
                    "route_score": float(route_score),
                    "route_reason": str(route_reason or ""),
                    "text_bytes": int(len(text_bytes)),
                    "relay_body_b64": b64e(relay_body_chunks[idx - 1]),
                    "relay_token_b64": b64e(relay_token),
                    "relay_return_token_b64": b64e(return_token),
                    "relay_ttl": 5,
                }
                peer_pending[mid] = rec
            save_state(pending_by_peer)
        append_history("queue", peer_norm, group_id, text, f"parts={total} cmp={cmp_label}")
        try:
            route_tag = str(route_id or "meshTalk")
            route_reason_tag = str(route_reason or "").strip()
            if route_reason_tag:
                route_tag += f"/{route_reason_tag}"
            ui_emit(
                "log",
                f"{ts_local()} FLOW: queue flow={group_id} to={peer_norm} parts={total} "
                f"route={route_tag} cmp={normalize_compression_name(cmp_label) or cmp_label}",
            )
        except Exception:
            pass
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

    def queue_relay_prebuilt(
        peer_norm: str,
        frame_payload: bytes,
        *,
        group_id: str = "",
        route_reason: str = "relay_control",
    ) -> bool:
        peer_id = norm_id_for_filename(peer_norm)
        if not peer_id:
            return False
        raw = bytes(frame_payload or b"")
        if not raw or len(raw) > max_plain:
            return False
        with pending_lock:
            peer_pending = pending_by_peer.setdefault(peer_id, {})
            rec = build_prebuilt_relay_record(
                raw=raw,
                group_id=str(group_id or os.urandom(4).hex()),
                peer_id=peer_id,
                route_reason=str(route_reason or "relay_control"),
                created_ts=time.time(),
            )
            frame_type = str(rec.get("relay_frame_type") or "")
            if frame_type in {"token_adv", "caps", "caps_req"}:
                for old_id, old_rec in list(peer_pending.items()):
                    if not isinstance(old_rec, dict):
                        continue
                    if str(old_rec.get("relay_frame_type") or "") != frame_type:
                        continue
                    peer_pending.pop(old_id, None)
            if len(peer_pending) >= int(MAX_PENDING_PER_PEER):
                if frame_type in {"token_adv", "caps", "caps_req", "hop_ack", "end_ack"}:
                    return False
                oldest_ids = sorted(
                    peer_pending.keys(),
                    key=lambda mid: float(peer_pending.get(mid, {}).get("created", 0.0) or 0.0),
                )
                for mid in oldest_ids:
                    old_rec = peer_pending.get(mid)
                    if not isinstance(old_rec, dict):
                        continue
                    if str(old_rec.get("relay_frame_type") or "") == "data":
                        continue
                    peer_pending.pop(mid, None)
                    break
                if len(peer_pending) >= int(MAX_PENDING_PER_PEER):
                    return False
            peer_pending[str(rec["id"])] = rec
            save_state(pending_by_peer)
        tracked_peers.add(peer_id)
        return True

    def announce_self_relay_token(now_ts: Optional[float] = None) -> int:
        now_local = time.time() if now_ts is None else float(now_ts)
        if not self_id:
            return 0
        epoch = current_epoch_slot(now=now_local)
        self_token = _relay_token_for_peer(self_id, epoch)
        if not self_token:
            return 0
        adv = build_token_adv_frame(
            relay_token=self_token,
            reach_score=1000,
            ttl=4,
            epoch_slot=epoch,
        )
        sent = 0
        for peer_id in sorted(set(tracked_peers) | set(peer_states.keys())):
            if not peer_id or peer_id == self_id:
                continue
            st_adv = get_peer_state(peer_id)
            if not st_adv or not bool(getattr(st_adv, "key_ready", False)):
                continue
            if queue_relay_prebuilt(peer_id, adv, group_id=f"adv:{self_token.hex()}", route_reason="token_adv"):
                sent += 1
        if sent > 0:
            ui_emit("log", f"{ts_local()} RELAY: route_adv self={self_token.hex()} fanout={sent}")
        return int(sent)

    send_window_start_ts = 0.0
    send_window_count = 0
    send_window_last_tx_ts = 0.0
    send_rr_offset = 0
    send_worker = V3SendWorker(
        SendWindowState(
            start_ts=send_window_start_ts,
            count=send_window_count,
            last_tx_ts=send_window_last_tx_ts,
            rr_offset=send_rr_offset,
        )
    )
    fast_window_start_ts = 0.0
    fast_window_count = 0
    relay_last_adv_ts = 0.0
    comp_stats = {
        "total_msgs": 0,
        "compressed_msgs": 0,
        "plain_bytes_total": 0,
        "packed_bytes_total": 0,
        "by_mode": {},
        "by_norm": {},
    }

    def send_due() -> None:
        nonlocal send_window_start_ts, send_window_count, send_window_last_tx_ts, send_rr_offset
        nonlocal fast_window_start_ts, fast_window_count
        if not radio_ready or interface is None:
            return
        now = time.time()

        def _build_wire_pt(rec: dict, attempt_num: int) -> bytes:
            del attempt_num
            return build_relay_plaintext_from_record(rec, now=now)

        # -----------------------
        # Fast-retry (micro-retry) layer: re-send attempt=1 with short jittered delays.
        # This improves "first attempt" delivery on noisy links, but must be bounded to avoid RF spam.
        # -----------------------
        # Manual-only mode: disable automatic fast micro-retry duplicates.
        fast_budget_per_s = 0
        if fast_budget_per_s > 0:
            if (fast_window_start_ts <= 0.0) or ((now - fast_window_start_ts) >= 1.0):
                fast_window_start_ts = now
                fast_window_count = 0
            if fast_window_count < fast_budget_per_s:
                with pending_lock:
                    fast_candidates = collect_fast_retry_candidates(pending_by_peer, now)
                for peer_norm, rec in fast_candidates[:3]:
                    st = get_peer_state(peer_norm)
                    if not st or not st.key_ready or not st.aes:
                        continue
                    # Send micro-retry without touching attempts (still "attempt 1").
                    attempt_num = max(1, int(rec.get("attempts", 1) or 1))
                    if attempt_num != 1:
                        # Micro-retry only applies to the first attempt campaign.
                        with pending_lock:
                            rec.pop("fast_left", None)
                            rec.pop("fast_next_ts", None)
                            pending_by_peer.setdefault(peer_norm, {})[rec["id"]] = rec
                            save_state(pending_by_peer)
                        continue
                    pt = _build_wire_pt(rec, attempt_num=1)
                    if not pt or len(pt) > max_plain:
                        with pending_lock:
                            if bool(rec.get("relay_v3", False)):
                                rec.pop("fast_left", None)
                                rec.pop("fast_next_ts", None)
                                pending_by_peer.setdefault(peer_norm, {})[rec["id"]] = rec
                            else:
                                pending_by_peer.get(peer_norm, {}).pop(rec["id"], None)
                                if not pending_by_peer.get(peer_norm):
                                    pending_by_peer.pop(peer_norm, None)
                            save_state(pending_by_peer)
                        if not bool(rec.get("relay_v3", False)):
                            append_history("drop", peer_norm, str(rec.get("id", "")), str(rec.get("text", "")), "legacy_wire_disabled")
                            ui_emit(
                                "failed",
                                (
                                    peer_norm,
                                    str(rec.get("group") or rec.get("id") or ""),
                                    "legacy_wire_disabled",
                                    int(rec.get("attempts", 0) or 0),
                                    int(rec.get("total", 1) or 1),
                                ),
                            )
                        continue
                    payload = pack_v3_record_for_peer_state(rec, st, now)
                    if len(payload) > args.max_bytes:
                        with pending_lock:
                            rec.pop("fast_left", None)
                            rec.pop("fast_next_ts", None)
                            pending_by_peer.setdefault(peer_norm, {})[rec["id"]] = rec
                            save_state(pending_by_peer)
                        continue
                    if not send_wire_payload(
                        interface=interface,
                        payload=payload,
                        destination_id=wire_id_from_norm(peer_norm),
                        port_num=data_portnum,
                        channel_index=(args.channel if args.channel is not None else 0),
                        trace_context="send_due.fast.sendData",
                        trace_suppressed_fn=trace_suppressed,
                        ui_emit_fn=ui_emit,
                        log_packet_trace=bool(cfg.get("log_packet_trace", False)),
                        log_line=f"{ts_local()} PKT: tx wire_fast to={peer_norm} bytes={len(payload)} left={int(rec.get('fast_left', 0) or 0)}",
                    ):
                        return
                    fast_window_count += 1
                    activity_record("out", "srv", 1, now=now, bytes_count=len(payload), subkind="fast")
                    metrics_inc("out_fast_retry", 1.0, now=now)
                    try:
                        rec["micro_retries_sent"] = int(rec.get("micro_retries_sent", 0) or 0) + 1
                    except Exception:
                        pass
                    # Schedule next micro retry (if any left).
                    try:
                        left = int(rec.get("fast_left", 0) or 0)
                    except Exception:
                        left = 0
                    left = max(0, left - 1)
                    if left <= 0:
                        rec.pop("fast_left", None)
                        rec.pop("fast_next_ts", None)
                    else:
                        _min_ms = int(rec.get("fast_min_ms", 350) or 350)
                        _max_ms = int(rec.get("fast_max_ms", max(_min_ms, 850)) or max(_min_ms, 850))
                        delay_ms = random.uniform(float(_min_ms), float(_max_ms))
                        rec["fast_left"] = int(left)
                        rec["fast_next_ts"] = now + (float(delay_ms) / 1000.0)
                    with pending_lock:
                        pending_by_peer.setdefault(peer_norm, {})[rec["id"]] = rec
                        save_state(pending_by_peer)
                    return

        try:
            rate_s = float(getattr(args, "rate_seconds", 0) or 0)
        except Exception:
            rate_s = 0.0
        try:
            parallel = int(getattr(args, "parallel_sends", 2) or 2)
        except Exception:
            parallel = 1
        parallel = max(1, parallel)
        try:
            intra_gap_s = max(0.0, float(int(cfg.get("activity_intra_batch_gap_ms", 0) or 0)) / 1000.0)
        except Exception:
            intra_gap_s = 0.0

        while True:
            with pending_lock:
                for peer_key in list(pending_by_peer.keys()):
                    norm_peer = norm_id_for_filename(peer_key)
                    if norm_peer != peer_key and peer_key in pending_by_peer:
                        pending_by_peer.setdefault(norm_peer, {}).update(pending_by_peer.pop(peer_key, {}))
                save_state(pending_by_peer)
            action = send_worker.next_action(
                now=now,
                rate_s=rate_s,
                parallel=parallel,
                intra_gap_s=intra_gap_s,
                pending_by_peer=pending_by_peer,
                tracked_peers=tracked_peers,
                get_peer_state=get_peer_state,
                norm_id_for_filename=norm_id_for_filename,
                self_id=self_id,
                max_seconds=float(args.max_seconds),
                max_plain=max_plain,
                max_bytes=args.max_bytes,
                build_wire_pt_fn=_build_wire_pt,
                pack_payload_fn=pack_v3_record_for_peer_state,
            )
            send_window_start_ts = send_worker.state.start_ts
            send_window_count = send_worker.state.count
            send_window_last_tx_ts = send_worker.state.last_tx_ts
            send_rr_offset = send_worker.state.rr_offset

            action_result = process_non_send_action_direct(
                action=action,
                now=now,
                get_peer_state=get_peer_state,
                derive_key_fn=derive_key,
                priv=priv,
                pub_self=pub_self,
                wire_id_from_norm=wire_id_from_norm,
                send_key_request_base_fn=send_key_request,
                retry_seconds=float(args.retry_seconds),
                ts_local_fn=ts_local,
                print_fn=print,
                pending_by_peer=pending_by_peer,
                save_state_fn=save_state,
                append_history_fn=append_history,
                pacer=pacer,
                routing_ctl=routing_ctl,
                ui_emit_fn=ui_emit,
            )
            if action_result == "return":
                return
            if action_result == "continue":
                continue
            if action.kind != "send_ready" or action.rec is None:
                return

            peer_norm = action.peer_norm
            rec = action.rec
            attempts_next = int(action.attempts_next)
            text = str(action.text)
            cmp_name = str(action.cmp_name)
            payload = bytes(action.payload)
            st = get_peer_state(peer_norm)
            if not st:
                continue

            if not send_wire_payload(
                interface=interface,
                payload=payload,
                destination_id=wire_id_from_norm(peer_norm),
                port_num=data_portnum,
                channel_index=(args.channel if args.channel is not None else 0),
                trace_context="send_due.sendData",
                trace_suppressed_fn=trace_suppressed,
                ui_emit_fn=ui_emit,
                log_packet_trace=bool(cfg.get("log_packet_trace", False)),
                log_line=f"{ts_local()} PKT: tx wire to={peer_norm} bytes={len(payload)} attempt={int(attempts_next)}",
            ):
                return
            activity_record("out", "msg", 1, now=now, bytes_count=len(payload))
            metrics_inc("out_send", 1.0, now=now)
            if int(attempts_next) > 1:
                metrics_inc("out_retry", 1.0, now=now)
            with pending_lock:
                finalize_send_success_direct(
                    action=action,
                    now=now,
                    get_peer_state=get_peer_state,
                    metrics_inc_base_fn=metrics_inc,
                    activity_record_base_fn=activity_record,
                    schedule_next_retry_fn=schedule_next_retry_for_record,
                    retry_seconds=float(args.retry_seconds),
                    cfg=cfg,
                    peer_meta=peer_meta,
                    pending_by_peer=pending_by_peer,
                    save_state_fn=save_state,
                    append_history_fn=append_history,
                    ui_emit_fn=ui_emit,
                    ts_local_fn=ts_local,
                    proto_version=int(PROTO_VERSION),
                    send_worker=send_worker,
                )
            send_window_start_ts = send_worker.state.start_ts
            send_window_count = send_worker.state.count
            send_window_last_tx_ts = send_worker.state.last_tx_ts
            send_rr_offset = send_worker.state.rr_offset
            return

    discovery_state = {"next_ts": time.time()}
    hello_mode_active = bool(cfg.get("discovery_hello_autostart", True)) and bool(cfg.get("discovery_send", True))
    hello_mode_until_ts = 0.0
    if hello_mode_active:
        discovery_state["next_ts"] = time.time()
    else:
        discovery_state["next_ts"] = time.time() + _hello_interval_seconds_by_uptime(0.0)

    def reset_discovery_schedule(now: Optional[float] = None, immediate: bool = False) -> None:
        t = time.time() if now is None else now
        if immediate:
            discovery_state["next_ts"] = t
        else:
            elapsed = max(0.0, float(t - hello_schedule_start_ts))
            discovery_state["next_ts"] = t + _hello_interval_seconds_by_uptime(elapsed)

    def start_hello_mode(reason: str = "manual", immediate: bool = True) -> None:
        nonlocal hello_mode_active, hello_mode_until_ts
        hello_mode_active = True
        hello_mode_until_ts = 0.0
        if immediate:
            reset_discovery_schedule(immediate=True)
        ui_emit(
            "log",
            f"{ts_local()} HELLO: mode ON reason={reason} duration=inf",
        )
        ui_emit("hello_state", {"active": True, "until_ts": float(hello_mode_until_ts)})

    def stop_hello_mode(reason: str = "manual") -> None:
        nonlocal hello_mode_active, hello_mode_until_ts
        if not hello_mode_active:
            return
        hello_mode_active = False
        hello_mode_until_ts = 0.0
        ui_emit("log", f"{ts_local()} HELLO: mode OFF reason={reason}")
        ui_emit("hello_state", {"active": False, "until_ts": 0.0})

    def discovery_tick(now: float) -> int:
        """Send one HELLO by fixed uptime schedule."""
        if now < float(discovery_state.get("next_ts", 0.0) or 0.0):
            return -1
        sent = 1 if send_discovery_broadcast() else 0
        elapsed = max(0.0, float(now - hello_schedule_start_ts))
        discovery_state["next_ts"] = float(now) + _hello_interval_seconds_by_uptime(elapsed)
        return int(sent)

    def sender_loop() -> None:
        last_key_refresh_ts = 0.0
        last_health_ts = 0.0
        last_names_refresh_ts = 0.0
        last_rekey_tick_ts = 0.0
        last_compstats_ts = 0.0
        last_metrics_gauges_ts = 0.0
        while True:
            send_due()
            now = time.time()
            # Gauge metrics for the Graphs tab (best-effort; not performance-critical).
            if (now - last_metrics_gauges_ts) >= 1.0:
                last_metrics_gauges_ts = now
                try:
                    with pending_lock:
                        pending_count = sum(len(v) for v in pending_by_peer.values())
                        pending_peers = sum(1 for v in pending_by_peer.values() if v)
                    metrics_set("pending_count", float(pending_count), now=now)
                    metrics_set("pending_peers", float(pending_peers), now=now)
                except Exception:
                    pass
                try:
                    rtts: list[float] = []
                    for st in list(peer_states.values()):
                        try:
                            r = float(getattr(st, "avg_rtt", 0.0) or 0.0)
                        except Exception:
                            r = 0.0
                        if r > 0.0 and math.isfinite(r):
                            rtts.append(r)
                    avg_rtt_s = (sum(rtts) / len(rtts)) if rtts else 0.0
                    metrics_set("rtt_avg_s", float(avg_rtt_s), now=now)
                except Exception:
                    pass
                try:
                    plain = float(int(comp_stats.get("plain_bytes_total", 0) or 0))
                    packed = float(int(comp_stats.get("packed_bytes_total", 0) or 0))
                    if plain > 0.0 and packed >= 0.0:
                        metrics_set("comp_size_pct", float((packed / plain) * 100.0), now=now)
                except Exception:
                    pass
                try:
                    metrics_set("route_switch_total", float(routing_ctl.counters.get("route_switch_total", 0.0)), now=now)
                    metrics_set("route_failover_total", float(routing_ctl.counters.get("route_failover_total", 0.0)), now=now)
                    metrics_set("route_hysteresis_hold_total", float(routing_ctl.counters.get("route_hold_hysteresis", 0.0)), now=now)
                except Exception:
                    pass
            if radio_ready and interface is not None and (now - last_names_refresh_ts) >= 60.0:
                last_names_refresh_ts = now
                update_peer_names_from_nodes()
                # Refresh contact list titles if names have changed.
                ui_emit("names_update", None)
            if (now - last_key_refresh_ts) >= 5.0:
                last_key_refresh_ts = now
                peers, _ = snapshot_runtime_state(peer_states, known_peers, tracked_peers)
                # Safety: never spam KR1 refresh across the whole node DB.
                # We only refresh keys for peers that are actually meshTalk-capable (keys known + app used),
                # and we cap the number of refresh sends per tick.
                refresh_budget = 2
                for peer_norm in peers:
                    if not peer_norm or peer_norm == self_id:
                        continue
                    st = get_peer_state(peer_norm)
                    if not st:
                        continue
                    if st.key_ready and st.await_key_confirm and now >= st.next_key_req_ts:
                        send_key_request(peer_norm, require_confirm=True, reason="await_confirm_retry")
                        continue
                    # Refresh is meaningful only for established meshTalk peers.
                    # Do not refresh unknown peers or Meshtastic-only nodes (reduces noise and privacy leakage).
                    if not bool(getattr(st, "key_ready", False)):
                        continue
                    try:
                        if not peer_direct_meshtalk_ready(peer_norm, now_ts=now):
                            continue
                    except Exception:
                        continue
                    if st.next_key_refresh_ts <= 0.0:
                        st.next_key_refresh_ts = now + 3600.0 + random.uniform(0, 600)
                    if now >= st.next_key_refresh_ts:
                        if refresh_budget <= 0:
                            break
                        defer_until = defer_stable_key_refresh(st, now)
                        if defer_until > 0.0:
                            st.next_key_refresh_ts = max(float(st.next_key_refresh_ts or 0.0), float(defer_until))
                            continue
                        send_key_request(peer_norm, require_confirm=False, reason="refresh_timer")
                        refresh_budget -= 1
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
                if discovery_send and hello_mode_active and radio_ready:
                    sent = discovery_tick(now)
                    if sent >= 0:
                        elapsed = max(0.0, float(now - hello_schedule_start_ts))
                        interval_s = _hello_interval_seconds_by_uptime(elapsed)
                        ui_emit(
                            "log",
                            f"{ts_local()} HELLO: tx={int(sent)} next={int(interval_s)}s",
                        )
                try:
                    pacing_enabled = bool(getattr(args, "auto_pacing", False))
                    pacer.set_enabled(pacing_enabled)
                    pacer.set_current(
                        rate_seconds=int(getattr(args, "rate_seconds", 5) or 5),
                        parallel_sends=int(getattr(args, "parallel_sends", 2) or 2),
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
                pending_count = 0
                pending_data = 0
                pending_ctrl = 0
                pending_by_type: Dict[str, int] = {}
                pending_focus: list[str] = []
                with pending_lock:
                    pending_count = sum(len(v) for v in pending_by_peer.values())
                    for _peer_id, _peer_pending in (pending_by_peer or {}).items():
                        if not isinstance(_peer_pending, dict):
                            continue
                        _peer_focus: Dict[str, Dict[str, object]] = {}
                        for _rec in _peer_pending.values():
                            if not isinstance(_rec, dict):
                                continue
                            _frame_type = str(
                                _rec.get("relay_frame_type")
                                or ("data" if bool(_rec.get("relay_v3", False)) else "legacy")
                            ).strip().lower()
                            if _frame_type == "data":
                                pending_data += 1
                            else:
                                pending_ctrl += 1
                            pending_by_type[_frame_type] = int(pending_by_type.get(_frame_type, 0) or 0) + 1
                            _flow_id = str(_rec.get("relay_msg_hex") or _rec.get("group") or _rec.get("id") or "-")
                            _agg = _peer_focus.setdefault(
                                _flow_id,
                                {
                                    "type": _frame_type,
                                    "attempts": 0,
                                    "parts": 0,
                                },
                            )
                            try:
                                _agg["attempts"] = max(
                                    int(_agg.get("attempts", 0) or 0),
                                    int(_rec.get("attempts", 0) or 0),
                                )
                            except Exception:
                                pass
                            try:
                                _agg["parts"] = int(_agg.get("parts", 0) or 0) + 1
                            except Exception:
                                _agg["parts"] = 1
                        for _flow_id, _agg in sorted(
                            _peer_focus.items(),
                            key=lambda item: (
                                -int((item[1] or {}).get("attempts", 0) or 0),
                                str(item[0]),
                            ),
                        )[:2]:
                            pending_focus.append(
                                f"{_peer_id}:{str(_agg.get('type') or '-')}"
                                f"/a{int(_agg.get('attempts', 0) or 0)}"
                                f"/p{int(_agg.get('parts', 0) or 0)}"
                                f"/{str(_flow_id)[:12]}"
                            )
                peers_snapshot, avg_rtt = snapshot_runtime_state(peer_states, known_peers, tracked_peers)
                if bool(cfg.get("log_verbose", True)):
                    rc = routing_ctl.counters
                    pending_types_txt = ", ".join(
                        f"{_k}={int(pending_by_type.get(_k, 0) or 0)}"
                        for _k in sorted(pending_by_type.keys())
                    ) or "-"
                    ui_emit(
                        "log",
                        f"{ts_local()} HEALTH: peers={len(peers_snapshot)} tracked={len(tracked_peers)} pending={pending_count} "
                        f"(data={pending_data} ctrl={pending_ctrl} types={pending_types_txt}) "
                        f"avg_rtt={avg_rtt:.2f}s route_sw={int(rc.get('route_switch_total', 0.0))} "
                        f"route_failover={int(rc.get('route_failover_total', 0.0))} ctrl_drop={int(rc.get('control_dropped_total', 0.0))}",
                    )
                    if pending_focus:
                        ui_emit(
                            "log",
                            f"{ts_local()} PENDING_FLOWS: {' | '.join(pending_focus[:6])}",
                        )
                    try:
                        tracked_snapshot = sorted(str(p) for p in tracked_peers if p)
                        if tracked_snapshot:
                            transport_bits = []
                            for _peer in tracked_snapshot[:8]:
                                _state, _reason = peer_transport_state(_peer, now_ts=now)
                                _bit = f"{_peer}:{_state}/{_reason}"
                                if _state == "direct_ready":
                                    try:
                                        _stats = routing_ctl.export_peer_stats(_peer)
                                    except Exception:
                                        _stats = {}
                                    _selected = str((_stats or {}).get("selected_route", "") or "-")
                                    _routes = dict((_stats or {}).get("routes") or {})
                                    _mesh = _routes.get("meshTalk") if isinstance(_routes, dict) else None
                                    if isinstance(_mesh, dict):
                                        try:
                                            _delivery = float(_mesh.get("delivery_ema", 0.0) or 0.0) * 100.0
                                        except Exception:
                                            _delivery = 0.0
                                        try:
                                            _timeout = float(_mesh.get("timeout_ema", 0.0) or 0.0) * 100.0
                                        except Exception:
                                            _timeout = 0.0
                                        try:
                                            _rtt = float(_mesh.get("rtt_p50_s", 0.0) or 0.0)
                                        except Exception:
                                            _rtt = 0.0
                                        try:
                                            _hops = float(_mesh.get("hops_ema", 0.0) or 0.0)
                                        except Exception:
                                            _hops = 0.0
                                        try:
                                            _retry = float(_mesh.get("retry_ema", 0.0) or 0.0)
                                        except Exception:
                                            _retry = 0.0
                                        try:
                                            _score = float((_stats or {}).get("selected_score", 0.0) or 0.0) if _selected == "meshTalk" else None
                                        except Exception:
                                            _score = None
                                        _score_txt = f"{_score:.2f}" if isinstance(_score, float) and math.isfinite(_score) and _score > -1e8 else "-"
                                        _bit += (
                                            f" path={'active' if _selected == 'meshTalk' else 'standby'}"
                                            f" score={_score_txt} del={_delivery:.0f}% to={_timeout:.0f}%"
                                            f" rtt={_rtt:.1f}s hops={_hops:.1f} retry={_retry:.1f}"
                                        )
                                transport_bits.append(_bit)
                            extra = ""
                            if len(tracked_snapshot) > 8:
                                extra = f" +{len(tracked_snapshot) - 8}"
                            ui_emit(
                                "log",
                                f"{ts_local()} TRANSPORT_SNAPSHOT: {' | '.join(transport_bits)}{extra}",
                            )
                    except Exception:
                        pass
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
                    if bool(cfg.get("log_verbose", True)):
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
        prev_sigint_handler = None
        try:
            prev_sigint_handler = signal.getsignal(signal.SIGINT)
        except Exception:
            prev_sigint_handler = None

        def _sigint_quit(_signum, _frame):
            try:
                QtCore.QTimer.singleShot(0, app.quit)
            except Exception:
                try:
                    app.quit()
                except Exception:
                    pass

        try:
            signal.signal(signal.SIGINT, _sigint_quit)
        except Exception:
            pass

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
                "tab_routing": "Transport",
                "tab_theme": "Themes",
                "tab_log": "Log",
                "tab_about": "About",
                "tab_activity": "Activity",
                "routing_title": "Transport / runtime monitor",
                "routing_monitor_hint": "Shows transport state, learned route cache, and one unified relay buffer: transit rows are from someone to you, outgoing rows are from you to someone.",
                "routing_status_box": "Transport status",
                "routing_status_transport": "Status",
                "routing_status_role": "Role",
                "routing_status_metrics": "Metrics",
                "routing_status_policy": "Policy",
                "routing_status_weights": "Base weights",
                "routing_routes_box": "Route table",
                "routing_buffer_box": "Relay buffer",
                "routing_queue_box": "Transit buffer",
                "routing_outgoing_box": "Outgoing buffer",
                "routing_hdr_from": "From",
                "routing_hdr_to": "To",
                "routing_hdr_peer": "Peer",
                "routing_hdr_selected": "Path",
                "routing_hdr_delivery": "Delivery",
                "routing_hdr_timeout": "Timeout",
                "routing_hdr_rtt": "RTT",
                "routing_hdr_hops": "Hops",
                "routing_hdr_retry": "Retry",
                "routing_hdr_snr": "SNR",
                "routing_hdr_score": "Score",
                "routing_hdr_ttl": "TTL",
                "routing_hdr_msg": "Message",
                "routing_hdr_parts": "Parts",
                "routing_hdr_attempts": "Attempts",
                "routing_hdr_age": "Age",
                "routing_hdr_next": "Next",
                "routing_hdr_state": "State",
                "routing_hdr_type": "Type",
                "tab_graphs": "Graphs",
                "graphs_window": "Time window",
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
                "packet_trace": "Packet trace (all packets)",
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
                "key_import_pub": "Import public key",
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
                "mesh_packet_port": "meshTalk packet portNum",
                "retry": "Send/retry interval, s",
                "max_days": "Message TTL, days",
                "max_bytes": "Max bytes",
                "rate": "Rate seconds",
                "parallel_sends": "Parallel packets",
                "auto_pacing": "Auto pacing",
                "hint_port": "Serial port path or 'auto' to scan USB ports.",
                "hint_mesh_packet_port": "Choose one of known Meshtastic PortNum types used for meshTalk packets.",
                "hint_retry": "Base interval between resend attempts for a queued packet. Real delay can be larger due to adaptive backoff/jitter.",
                "hint_max_days": "Message lifetime (TTL) in queue. Each queued packet of this message uses this limit as its expiration deadline. After TTL expires, the program stops retrying, removes remaining packets, and marks the message as not delivered even if ACK never arrives.",
                "hint_max_bytes": "Max Meshtastic payload bytes per packet (includes encryption overhead).",
                "hint_rate": "Minimum delay between send windows (used when Auto pacing is off).",
                "hint_parallel": "How many packets can be sent per send window.",
                "hint_auto_pacing": "Auto tunes rate/parallel based on recent ACK stats.",
                "activity_title": "Activity / resend policy",
                "activity_profile": "Profile",
                "activity_profile_low": "Low noise (Recommended)",
                "activity_profile_bal": "Balanced",
                "activity_profile_fast": "Fast delivery",
                "activity_timing_mode": "Timing mode",
                "activity_timing_mode_auto": "Automatic (presets)",
                "activity_timing_mode_manual": "Manual",
                "activity_aggr": "Aggressiveness",
                "activity_controller_model": "Controller model",
                "activity_model_trickle": "Trickle (RFC 6206)",
                "activity_model_ledbat": "LEDBAT (RFC 6817)",
                "activity_model_quic": "QUIC-style loss+pacing",
                "hint_activity_profile": "Pick a preset tuned for low RF noise. Aggressiveness adjusts retry intensity inside the preset.",
                "hint_activity_timing_mode": "Automatic mode computes retry/rate/parallel from preset + aggressiveness. Manual mode uses explicit fields below.",
                "hint_activity_aggr": "Higher values retry more often and keep longer probe windows (more traffic). Lower values calm down sooner (less traffic).",
                "hint_activity_controller_model": "Select retry controller: Trickle for very low-noise gossip style, LEDBAT for delay-based control, QUIC-style for PTO-based loss recovery with pacing.",
                "activity_active_window_min": "Active window, min",
                "activity_probe_min_interval_min": "Probe interval (min), min",
                "activity_probe_max_interval_min": "Probe interval (max), min",
                "activity_probe_window_max_min": "Probe window (max), min",
                "activity_peer_grace_s": "Peer responsive grace, s",
                "activity_backoff_cap_s": "Retry backoff cap, s",
                "activity_jitter_pct": "Retry jitter, %",
                "hint_activity_active_window_min": "For the first N minutes after queueing, retries are more active. After that, muted mode probes periodically.",
                "hint_activity_probe_min_interval_min": "Shortest time between probe windows after recent silence. Larger values reduce traffic but may increase delivery latency.",
                "hint_activity_probe_max_interval_min": "Longest time between probe windows for long silence. This is the main 'low-noise' limiter.",
                "hint_activity_probe_window_max_min": "Max duration of active retries during a probe. Over time, the window shrinks automatically to reduce RF noise.",
                "hint_activity_peer_grace_s": "If any ACK/inbound traffic is seen within this time, peer is treated as responsive and active mode resumes.",
                "hint_activity_backoff_cap_s": "Max delay between retries inside active/probe windows.",
                "hint_activity_jitter_pct": "Randomizes retry timing to avoid synchronized bursts (percent of delay).",
                "activity_live_title": "Current values (live)",
                "activity_live_rate": "Rate window",
                "activity_live_parallel": "Parallel packets",
                "activity_live_pps": "Effective rate",
                "activity_live_active": "Active window",
                "activity_live_probe_min": "Probe interval (min)",
                "activity_live_probe_max": "Probe interval (max)",
                "activity_live_probe_win": "Probe window (max)",
                "activity_live_grace": "Peer grace",
                "activity_live_backoff": "Backoff cap",
                "activity_live_jitter": "Retry jitter",
                "activity_batch_pause": "Pause between batches, s",
                "activity_batch_count": "Packets per batch",
                "activity_batch_intra_pause": "Pause inside batch, ms",
                "activity_hello_batch_count": "HELLO per burst",
                "activity_hello_packet_count": "HELLO packets per cycle",
                "activity_hello_gap": "Pause between HELLO, s",
                "activity_hello_packet_gap": "Pause between HELLO packets, s",
                "activity_hello_interval": "HELLO burst interval, s",
                "activity_hello_runtime": "HELLO mode duration, s",
                "activity_live_fast_retries": "Fast retries",
                "activity_live_fast_delay": "Fast delay",
                "activity_live_fast_budget": "Fast budget",
                "activity_advanced": "Advanced parameters",
                "hint_activity_advanced": "Show rarely needed tuning knobs: backoff/jitter and burst shaping.",
                "hint_activity_live_rate": "Current rate_seconds (auto-tuned when Auto pacing is ON).",
                "hint_activity_live_parallel": "Current parallel_sends (auto-tuned when Auto pacing is ON).",
                "hint_activity_live_pps": "Computed throughput proxy: parallel_sends / rate_seconds (packets per second).",
                "hint_activity_live_retry": "Current retry_seconds (base interval for resend/backoff).",
                "hint_activity_live_max": "Current message TTL in seconds. After this limit, queued packets expire, retries stop, and the message is marked not delivered.",
                "hint_activity_live_active": "Active resend window after queuing a message (then probes).",
                "hint_activity_live_probe_min": "Shortest interval between probe windows.",
                "hint_activity_live_probe_max": "Longest interval between probe windows for long silence.",
                "hint_activity_live_probe_win": "Max length of a probe window (shrinks over time).",
                "hint_activity_live_grace": "If any ACK/inbound traffic arrives within this window, peer is treated responsive.",
                "hint_activity_live_backoff": "Max delay between resend attempts inside active/probe windows.",
                "hint_activity_live_jitter": "Randomization added to resend timing (percent).",
                "hint_activity_batch_pause": "Length of one send window: pause between consecutive batches for the same destination. Lower values increase throughput and RF load.",
                "hint_activity_batch_count": "Maximum packets sent in one send window before waiting for the next window. Higher values increase burstiness.",
                "hint_activity_batch_intra_pause": "Extra delay between packets inside the same window. Use >0 to smooth bursts on noisy links.",
                "hint_activity_hello_batch_count": "How many HELLO discovery packets to send in one burst.",
                "hint_activity_hello_packet_count": "How many HELLO packets to send in one HELLO cycle.",
                "hint_activity_hello_gap": "Delay between HELLO frames inside one packet/cycle.",
                "hint_activity_hello_packet_gap": "Delay between HELLO packets inside one cycle.",
                "hint_activity_hello_interval": "Delay before the next HELLO burst.",
                "hint_activity_hello_runtime": "How long HELLO mode runs after start. 0 means no auto-stop.",
                "hint_activity_live_fast_retries": "How many micro-retries (attempt=1 duplicates) we schedule per packet before normal retries.",
                "hint_activity_live_fast_delay": "Delay window for fast micro-retries (randomized). ACK cancels remaining fast retries.",
                "hint_activity_live_fast_budget": "Rate limit for fast micro-retry sends (packets per second).",
                "activity_methodology": "Methodology (goal: low RF noise)\n\nController models:\n- Trickle (RFC 6206-inspired): interval randomization with exponential interval growth (Imin..Imax) for sparse, low-noise retries.\n- LEDBAT (RFC 6817-inspired): delay-based adaptation using queueing delay estimate (SRTT - minRTT).\n- QUIC-style: PTO-based loss recovery (SRTT/RTTVAR) with paced send windows.\n\nProfiles and aggressiveness tune the same guardrails (active window, probe bounds, backoff cap, jitter, fast micro-retries) for all models.",
                "graphs_title": "Graphs (last 15 minutes)",
                "graphs_traffic": "Traffic (messages vs service)",
                "graphs_traffic_hint": "Counts per second: outgoing/incoming messages, outgoing/incoming service packets.",
                "graphs_bytes": "Bytes (proxy for airtime)",
                "graphs_bytes_hint": "Bytes per second (best-effort): helps estimate RF airtime/noise.",
                "graphs_reliability": "Reliability (send/retry/ack)",
                "graphs_reliability_hint": "Per-second counters: meshTalk sends, retries, and received ACKs.",
                "graphs_backlog": "Backlog (pending queue)",
                "graphs_backlog_hint": "Gauge: pending packets in queue and number of peers with pending traffic.",
                "graphs_latency": "Latency (RTT avg)",
                "graphs_latency_hint": "Gauge: average RTT from ACKs across peers (seconds).",
                "graphs_compression": "Compression (size %)",
                "graphs_compression_hint": "Gauge: packed size as % of original (lower is better).",
                "graphs_service_breakdown": "Service breakdown (ACK/KEY/HELLO/REKEY/TRACE)",
                "graphs_service_breakdown_hint": "Counts per second split by service type (best-effort).",
                "discovery": "HELLO",
                "discovery_send": "Send HELLO",
                "discovery_reply": "Reply HELLO",
                "clear_pending_on_switch": "Clear pending when profile switches",
                "hint_verbose": "Show more internal events in the GUI log.",
                "hint_packet_trace": "Show every TX/RX packet in the GUI log (can be very noisy). Also feeds the Graphs tab.",
                "hint_runtime_log_file": "Write runtime events to runtime.log on disk.",
                "hint_discovery_send": "Sends HELLO broadcasts (extra traffic).",
                "hint_discovery_reply": "Replies HELLO broadcasts (extra traffic).",
                "hint_clear_pending": "Clears pending queue when switching profile/dialog.",
                "hello_mode_button": "HELLO",
                "hello_mode_running_tip": "HELLO mode is active. Remaining: {seconds}s",
                "hello_mode_running_inf_tip": "HELLO mode is active (no auto-stop).",
                "hello_mode_stopped_tip": "HELLO mode is stopped. Press to start.",
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
                "security_crypto_summary": "What is encrypted:\n- All meshTalk payload traffic (message parts, ACK, CAPS, REKEY, control) goes in MT-WIREv{wire} with AES-256-GCM (AEAD).\n- Session rekey (RK1/RK2/RK3 payload exchange) runs inside encrypted meshTalk control channel.\n\nWhat stays plaintext on radio:\n- Discovery HELLO (MT2) and initial key exchange frames KR1/KR2 (X25519 public key exchange only).\n- Standard Meshtastic TEXT_MESSAGE_APP traffic is plaintext by Meshtastic design.\n\nKey material and derivation:\n- Per-peer transport key is derived via HKDF-SHA256 from X25519 shared secret.\n- Local key/profile storage uses AES-256-GCM at rest.",
                "security_keys_title": "Keyring",
                "security_keys_hint": "Your public key (copy button below).",
                "security_keys_self": "Self ID",
                "security_keys_private": "Private key",
                "security_keys_public": "Public key",
                "security_keys_fingerprint": "Public fingerprint",
                "security_keys_refresh": "Refresh keys",
                "security_keys_regen": "Regenerate key pair",
                "security_keys_restore_pub": "Restore public from private",
                "security_keys_copy_pub": "Copy public key",
                "security_keys_backup_priv": "Backup private key",
                "security_keys_import_priv": "Import private key",
                "security_keys_copied": "Copied",
                "security_keys_unavailable": "Keys are unavailable until profile initialization.",
                "security_keys_regen_confirm": "Regenerate local key pair now?\n\nOld local key pair will be replaced.",
                "security_keys_regen_done": "Local key pair regenerated.",
                "security_keys_restore_done": "Public key restored from private key.",
                "security_keys_restore_failed": "Failed to restore public key from private key.",
                "security_keys_backup_done": "Private key backup saved.",
                "security_keys_backup_failed": "Failed to save private key backup.",
                "security_keys_backup_passphrase": "Backup passphrase (required):",
                "security_keys_backup_passphrase_repeat": "Repeat backup passphrase:",
                "security_keys_backup_passphrase_mismatch": "Passphrases do not match.",
                "security_keys_import_done": "Private key imported. Public key was rebuilt.",
                "security_keys_import_failed": "Failed to import private key.",
                "security_keys_import_confirm": "Import private key from file?\n\nCurrent local key pair will be replaced.",
                "security_keys_file_filter": "Key files (*.key *.txt);;All files (*)",
                "security_keys_import_passphrase": "Backup passphrase:",
                "security_copy_pub_done": "Public key copied to clipboard.",
                "security_copy_pub_failed": "Failed to copy public key.",
                "log_legend_title": "Log colors:",
                "log_legend_error": "error",
                "log_legend_warn": "warn",
                "log_legend_key": "crypto/key",
                "log_legend_discovery": "HELLO",
                "log_legend_radio": "radio/gui",
                "log_legend_queue": "queue/route",
                "log_legend_send": "send",
                "log_legend_recv": "recv/ack",
                "log_legend_compress": "compress",
                "log_legend_pkt": "packet",
                "key_import_pub_title": "Import public key",
                "key_import_pub_prompt": "Paste public key for {peer} (base64 or hex):",
                "key_import_pub_done": "Public key imported for {peer}.",
                "key_import_pub_failed": "Failed to import public key for {peer}.",
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
                "theme_pretty_girl": "pretty girl",
                "theme_froggy": "froggy",
                "theme_spinach": "spinach",
                "theme_hint": "Applies immediately to the main window and settings dialog.",
                "security_auto_stale_hours": "Auto accept if key age, h",
                "security_auto_seen_minutes": "Auto accept if seen within, min",
                "security_auto_mode": "Auto rule",
                "security_auto_mode_or": "OR (either is enough)",
                "security_auto_mode_and": "AND (both required)",
                "security_auto_hint": "AUTO accepts a changed peer key only if the previously pinned key was never confirmed.\nSTRICT always requires manual reset.\nALWAYS ACCEPT is most convenient but weakest against key substitution.\nIf a key was confirmed before, manual reset is required.",
                "full_reset_profile": "Reset current profile",
                "full_reset_all": "Reset all settings",
                "full_reset_confirm": "Delete all profile settings, history, pending state and keys for '{name}'?\n\nThis action cannot be undone.",
                "full_reset_all_confirm": "Delete ALL profiles, keys and settings on this device?\n\nThis action cannot be undone.",
                "full_reset_done": "Current profile data and keys were reset.",
                "full_reset_all_done": "All profiles and settings were reset.",
                "full_reset_unavailable": "Full reset is available after node/profile initialization.",
                "copy_log": "Copy log",
                "clear_log": "Clear log",
                "ack_alerts": "Acknowledge alerts",
                "alerts_show": "Show alert",
                "msg_ctx_copy": "Copy",
                "msg_ctx_route": "Traceroute request",
                "msg_ctx_cancel_send": "Cancel send",
                "meta_std_text": "Meshtastic text",
                "msg_route_title": "Message route",
                "msg_route_na": "Route information is not available yet for this message.",
                "msg_route_hops": "Hops",
                "msg_route_hops_tb": "Hops (there/back)",
                "msg_route_attempts": "Attempts (avg)",
                "msg_route_packets": "Packets",
                "trace_request": "Trace request",
                "trace_timeout": "Timed out waiting for traceroute",
                "trace_send_blocked": "Traceroute request was not sent: radio interface was busy",
                "trace_towards": "Route traced towards destination:",
                "trace_back": "Route traced back to us:",
                "about_summary": (
                    "meshTalk is a desktop client for resilient messaging over Meshtastic mesh links.\n\n"
                    "How it works:\n"
                    "- Messages are split into packet groups and delivered with ACK/retry/backoff.\n"
                    "- Route is selected per peer (meshTalk protocol path or plain Meshtastic text path).\n"
                    "- Runtime status shows delivery progress, attempts, hops, and packet parts.\n\n"
                    "Cryptography and where it is used:\n"
                    "- MT-WIREv2 transport encryption: AES-256-GCM (AEAD) for protocol payload frames.\n"
                    "- Key exchange: KR1/KR2 with X25519 public keys (plaintext control frames).\n"
                    "- Key derivation: HKDF-SHA256 (from X25519 shared secret).\n"
                    "- Local profile storage encryption: AES-256-GCM for history/state/incoming files.\n"
                    "- Private-key backup file encryption: Scrypt + AES-256-GCM.\n\n"
                    "Use case: civilian/hobby/research mesh communication experiments."
                ),
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
                "tab_routing": "Транспорт",
                "tab_theme": "Темы",
                "tab_log": "Лог",
                "tab_about": "О программе",
                "tab_activity": "Активность",
                "routing_title": "Транспорт / монитор runtime",
                "routing_monitor_hint": "Показывает состояние транспортного узла, кэш маршрутов и один общий relay-буфер: транзитные строки идут от кого-то к вам, исходящие — от вас к кому-то.",
                "routing_status_box": "Состояние транспорта",
                "routing_status_transport": "Статус",
                "routing_status_role": "Роль",
                "routing_status_metrics": "Метрики",
                "routing_status_policy": "Политика",
                "routing_status_weights": "Базовые веса",
                "routing_routes_box": "Таблица маршрутов",
                "routing_buffer_box": "Общий буфер",
                "routing_queue_box": "Транзитный буфер",
                "routing_outgoing_box": "Исходящий буфер",
                "routing_hdr_from": "Откуда",
                "routing_hdr_to": "Куда",
                "routing_hdr_peer": "Пир",
                "routing_hdr_selected": "Путь",
                "routing_hdr_delivery": "Доставка",
                "routing_hdr_timeout": "Таймаут",
                "routing_hdr_rtt": "RTT",
                "routing_hdr_hops": "Хопы",
                "routing_hdr_retry": "Ретраи",
                "routing_hdr_snr": "SNR",
                "routing_hdr_score": "Оценка",
                "routing_hdr_ttl": "TTL",
                "routing_hdr_msg": "Сообщение",
                "routing_hdr_parts": "Части",
                "routing_hdr_attempts": "Попытки",
                "routing_hdr_age": "Возраст",
                "routing_hdr_next": "След.",
                "routing_hdr_state": "Сост.",
                "routing_hdr_type": "Тип",
                "tab_graphs": "Графики",
                "graphs_window": "Окно времени",
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
                "packet_trace": "Трейс пакетов (все пакеты)",
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
                "key_import_pub": "Импортировать public key",
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
                "mesh_packet_port": "portNum пакетов meshTalk",
                "retry": "Интервал отправки/повтора, сек",
                "max_days": "TTL сообщения, дни",
                "max_bytes": "Макс байт",
                "rate": "Мин интервал, сек",
                "parallel_sends": "Параллельно, пакетов",
                "auto_pacing": "Автоподбор скорости",
                "hint_port": "Серийный порт или 'auto' для поиска по USB.",
                "hint_mesh_packet_port": "Выберите известный тип Meshtastic PortNum для meshTalk пакетов.",
                "hint_retry": "Базовый шаг между повторными попытками одной посылки. Фактическая пауза может расти из-за адаптивного backoff/jitter.",
                "hint_max_days": "Время жизни сообщения (TTL) в очереди. Каждый пакет этого сообщения использует этот срок как дедлайн существования. После истечения TTL программа прекращает повторы, удаляет оставшиеся пакеты и переводит сообщение в статус недоставленного даже без ACK.",
                "hint_max_bytes": "Макс. размер payload Meshtastic на пакет (включая оверхед шифрования).",
                "hint_rate": "Минимальная пауза между окнами отправки (когда автоподбор выключен).",
                "hint_parallel": "Сколько пакетов можно отправить подряд в одном окне.",
                "hint_auto_pacing": "Автоподбор rate/параллельности по статистике ACK.",
                "activity_title": "Активность / политика повторов",
                "activity_profile": "Профиль",
                "activity_profile_low": "Тихий эфир (рекомендуется)",
                "activity_profile_bal": "Сбалансированный",
                "activity_profile_fast": "Быстрая доставка",
                "activity_timing_mode": "Режим таймингов",
                "activity_timing_mode_auto": "Автоматический (пресеты)",
                "activity_timing_mode_manual": "Ручной",
                "activity_aggr": "Агрессивность",
                "activity_controller_model": "Модель контроллера",
                "activity_model_trickle": "Trickle (RFC 6206)",
                "activity_model_ledbat": "LEDBAT (RFC 6817)",
                "activity_model_quic": "QUIC-style loss+pacing",
                "hint_activity_profile": "Готовые профили, настроенные на низкий шум в эфире. Агрессивность подстраивает интенсивность внутри профиля.",
                "hint_activity_timing_mode": "Авто-режим вычисляет retry/rate/parallel из пресета и агрессивности. Ручной режим использует поля ниже.",
                "hint_activity_aggr": "Больше значение: чаще повторы и длиннее окна проб (больше трафика). Меньше: быстрее успокаивается (меньше трафика).",
                "hint_activity_controller_model": "Выберите модель повторов: Trickle для максимально тихого gossip-режима, LEDBAT для управления по задержке, QUIC-style для PTO-восстановления потерь с пейсингом.",
                "activity_active_window_min": "Активно, мин",
                "activity_probe_min_interval_min": "Проба (мин), мин",
                "activity_probe_max_interval_min": "Проба (макс), мин",
                "activity_probe_window_max_min": "Окно проб (макс), мин",
                "activity_peer_grace_s": "Окно активности пира, сек",
                "activity_backoff_cap_s": "Потолок backoff, сек",
                "activity_jitter_pct": "Jitter, %",
                "hint_activity_active_window_min": "Первые N минут после постановки в очередь повторы идут активнее. Дальше включается приглушенный режим с периодическими окнами попыток.",
                "hint_activity_probe_min_interval_min": "Минимальный интервал между окнами проб после недавней тишины. Больше значение снижает трафик, но может увеличить задержку доставки.",
                "hint_activity_probe_max_interval_min": "Максимальный интервал между окнами проб при длительной тишине. Это главный ограничитель «не шуметь».",
                "hint_activity_probe_window_max_min": "Максимальная длительность активных попыток в окне проб. Со временем окно автоматически уменьшается, чтобы меньше шуметь.",
                "hint_activity_peer_grace_s": "Если за это время был ACK или входящий трафик, пир считается активным и режим становится активным.",
                "hint_activity_backoff_cap_s": "Максимальная задержка между попытками внутри активного/пробного окна.",
                "hint_activity_jitter_pct": "Случайная разбежка времени повторов (процент от задержки), чтобы не было синхронных всплесков.",
                "activity_live_title": "Текущие значения (live)",
                "activity_live_rate": "Окно rate",
                "activity_live_parallel": "Параллельно",
                "activity_live_pps": "Эффективная скорость",
                "activity_live_active": "Активное окно",
                "activity_live_probe_min": "Проба (мин)",
                "activity_live_probe_max": "Проба (макс)",
                "activity_live_probe_win": "Окно проб",
                "activity_live_grace": "Grace пира",
                "activity_live_backoff": "Потолок backoff",
                "activity_live_jitter": "Jitter повторов",
                "activity_batch_pause": "Пауза между пакетами, сек",
                "activity_batch_count": "Посылок в пакете",
                "activity_batch_intra_pause": "Пауза в пакете, мс",
                "activity_hello_batch_count": "HELLO в пакете",
                "activity_hello_packet_count": "HELLO пакетов в цикле",
                "activity_hello_gap": "Пауза между HELLO, сек",
                "activity_hello_packet_gap": "Пауза между HELLO пакетами, сек",
                "activity_hello_interval": "Интервал HELLO пакетов, сек",
                "activity_hello_runtime": "Длительность HELLO-режима, сек",
                "activity_live_fast_retries": "Fast повторы",
                "activity_live_fast_delay": "Fast задержка",
                "activity_live_fast_budget": "Fast лимит",
                "activity_advanced": "Расширенные параметры",
                "hint_activity_advanced": "Показать редко используемые тонкие настройки: backoff/jitter и форма пачек.",
                "hint_activity_live_rate": "Текущее rate_seconds (автоподбирается при включенном автоподборе).",
                "hint_activity_live_parallel": "Текущее parallel_sends (автоподбирается при включенном автоподборе).",
                "hint_activity_live_pps": "Прокси пропускной способности: parallel_sends / rate_seconds (пакетов в секунду).",
                "hint_activity_live_retry": "Текущее retry_seconds (база для resend/backoff).",
                "hint_activity_live_max": "Текущий TTL сообщения в секундах. После этого лимита пакеты истекают, повторы прекращаются, а сообщение получает статус недоставленного.",
                "hint_activity_live_active": "Активное окно повторов сразу после постановки в очередь (дальше пробы).",
                "hint_activity_live_probe_min": "Минимальный интервал между окнами проб.",
                "hint_activity_live_probe_max": "Максимальный интервал между окнами проб при длительной тишине.",
                "hint_activity_live_probe_win": "Максимальная длительность окна проб (со временем уменьшается).",
                "hint_activity_live_grace": "Если в это окно есть ACK/входящий трафик, пир считается активным.",
                "hint_activity_live_backoff": "Максимальная пауза между попытками внутри активного/пробного окна.",
                "hint_activity_live_jitter": "Случайная разбежка повторов (процент).",
                "hint_activity_batch_pause": "Длина окна отправки: пауза между соседними пачками на одного получателя. Меньше значение = выше скорость и выше нагрузка на эфир.",
                "hint_activity_batch_count": "Максимум пакетов, отправляемых в одном окне перед паузой. Больше значение = более «взрывная» передача.",
                "hint_activity_batch_intra_pause": "Дополнительная пауза между пакетами внутри одного окна. Полезно для сглаживания всплесков на шумном канале.",
                "hint_activity_hello_batch_count": "Сколько HELLO discovery отправлять в одном пакете.",
                "hint_activity_hello_packet_count": "Сколько HELLO пакетов отправлять за один цикл HELLO.",
                "hint_activity_hello_gap": "Пауза между HELLO кадрами внутри одного цикла.",
                "hint_activity_hello_packet_gap": "Пауза между HELLO пакетами внутри одного цикла.",
                "hint_activity_hello_interval": "Через сколько секунд отправлять следующий пакет HELLO.",
                "hint_activity_hello_runtime": "Сколько работает HELLO-режим после запуска. 0 — без автоостановки.",
                "hint_activity_live_fast_retries": "Сколько micro-retry (дубликатов attempt=1) планируется на пакет до обычных повторов.",
                "hint_activity_live_fast_delay": "Окно задержек для micro-retry (с jitter). ACK отменяет оставшиеся fast повторы.",
                "hint_activity_live_fast_budget": "Ограничение скорости fast повтора (пакетов в секунду).",
                "activity_methodology": "Методология (цель: низкий шум в эфире)\n\nМодели контроллера:\n- Trickle (по мотивам RFC 6206): рандомизация интервала и экспоненциальный рост (Imin..Imax) для редких «тихих» повторов.\n- LEDBAT (по мотивам RFC 6817): адаптация по оценке очереди (SRTT - minRTT).\n- QUIC-style: PTO-восстановление потерь (SRTT/RTTVAR) с пейсингом окон отправки.\n\nПрофиль и агрессивность настраивают общие ограничители (active window, границы probe, backoff cap, jitter, fast micro-retry) для всех моделей.",
                "graphs_title": "Графики (последние 15 минут)",
                "graphs_traffic": "Трафик (сообщения и служебные)",
                "graphs_traffic_hint": "Счетчики в секунду: исходящие/входящие сообщения, исходящие/входящие служебные пакеты.",
                "graphs_bytes": "Байты (прокси airtime)",
                "graphs_bytes_hint": "Байты в секунду (best-effort): помогает оценить эфирное время/шум.",
                "graphs_reliability": "Надежность (send/retry/ack)",
                "graphs_reliability_hint": "Счетчики в секунду: отправки meshTalk, повторы, полученные ACK.",
                "graphs_backlog": "Очередь (pending)",
                "graphs_backlog_hint": "Индикаторы: сколько пакетов ждут ACK и сколько пиров с очередью.",
                "graphs_latency": "Задержка (RTT средняя)",
                "graphs_latency_hint": "Индикатор: средняя RTT по ACK среди пиров (сек).",
                "graphs_compression": "Сжатие (size %)",
                "graphs_compression_hint": "Индикатор: итоговый размер как % от исходного (меньше лучше).",
                "graphs_service_breakdown": "Служебные (ACK/KEY/HELLO/REKEY/TRACE)",
                "graphs_service_breakdown_hint": "Счетчики в секунду по типам служебных пакетов (best-effort).",
                "discovery": "HELLO",
                "discovery_send": "Отправлять HELLO",
                "discovery_reply": "Отвечать HELLO",
                "clear_pending_on_switch": "Очищать очередь при смене профиля",
                "hint_verbose": "Показывать больше внутренних событий в GUI-логе.",
                "hint_packet_trace": "Показывать каждый TX/RX пакет в GUI-логе (может сильно шуметь). Также питает вкладку Графики.",
                "hint_runtime_log_file": "Писать runtime события в runtime.log на диск.",
                "hint_discovery_send": "Отправляет HELLO broadcasts (доп. трафик).",
                "hint_discovery_reply": "Отвечает HELLO broadcasts (доп. трафик).",
                "hint_clear_pending": "Очищает очередь при переключении профиля/диалога.",
                "hello_mode_button": "HELLO",
                "hello_mode_running_tip": "HELLO-режим активен. Осталось: {seconds}с",
                "hello_mode_running_inf_tip": "HELLO-режим активен (без автоостановки).",
                "hello_mode_stopped_tip": "HELLO-режим остановлен. Нажмите для запуска.",
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
                "security_crypto_summary": "Что шифруется:\n- Весь meshTalk payload-трафик (части сообщений, ACK, CAPS, REKEY, служебные кадры) идет в MT-WIREv{wire} с AES-256-GCM (AEAD).\n- Session rekey (RK1/RK2/RK3) выполняется внутри зашифрованного служебного канала meshTalk.\n\nЧто остается в открытом виде в эфире:\n- Discovery HELLO (MT2) и первичные ключевые кадры KR1/KR2 (только обмен X25519 public key).\n- Стандартный Meshtastic TEXT_MESSAGE_APP по дизайну Meshtastic остается plaintext.\n\nКлючи и вывод ключей:\n- Транспортный ключ на пира выводится через HKDF-SHA256 из X25519 shared secret.\n- Локальное хранение профиля/ключей: AES-256-GCM at-rest.",
                "security_keys_title": "Keyring",
                "security_keys_hint": "Ваш публичный ключ (кнопка копирования ниже).",
                "security_keys_self": "Self ID",
                "security_keys_private": "Приватный ключ",
                "security_keys_public": "Публичный ключ",
                "security_keys_fingerprint": "Отпечаток публичного ключа",
                "security_keys_refresh": "Обновить ключи",
                "security_keys_regen": "Перегенерировать пару ключей",
                "security_keys_restore_pub": "Восстановить публичный из приватного",
                "security_keys_copy_pub": "Копировать публичный ключ",
                "security_keys_backup_priv": "Сохранить приватный ключ",
                "security_keys_import_priv": "Импортировать приватный ключ",
                "security_keys_copied": "Скопировано",
                "security_keys_unavailable": "Ключи недоступны до инициализации профиля.",
                "security_keys_regen_confirm": "Перегенерировать локальную пару ключей сейчас?\n\nСтарая локальная пара будет заменена.",
                "security_keys_regen_done": "Локальная пара ключей перегенерирована.",
                "security_keys_restore_done": "Публичный ключ восстановлен из приватного.",
                "security_keys_restore_failed": "Не удалось восстановить публичный ключ из приватного.",
                "security_keys_backup_done": "Резервная копия приватного ключа сохранена.",
                "security_keys_backup_failed": "Не удалось сохранить резервную копию приватного ключа.",
                "security_keys_backup_passphrase": "Пароль для бэкапа (обязательно):",
                "security_keys_backup_passphrase_repeat": "Повторите пароль бэкапа:",
                "security_keys_backup_passphrase_mismatch": "Пароли не совпадают.",
                "security_keys_import_done": "Приватный ключ импортирован. Публичный ключ пересобран.",
                "security_keys_import_failed": "Не удалось импортировать приватный ключ.",
                "security_keys_import_confirm": "Импортировать приватный ключ из файла?\n\nТекущая локальная пара ключей будет заменена.",
                "security_keys_file_filter": "Файлы ключей (*.key *.txt);;Все файлы (*)",
                "security_keys_import_passphrase": "Пароль бэкапа:",
                "security_copy_pub_done": "Публичный ключ скопирован в буфер обмена.",
                "security_copy_pub_failed": "Не удалось скопировать публичный ключ.",
                "log_legend_title": "Цвета лога:",
                "log_legend_error": "ошибка",
                "log_legend_warn": "предупреждение",
                "log_legend_key": "крипто/ключи",
                "log_legend_discovery": "HELLO",
                "log_legend_radio": "радио/gui",
                "log_legend_queue": "очередь/маршрут",
                "log_legend_send": "отправка",
                "log_legend_recv": "приём/ack",
                "log_legend_compress": "сжатие",
                "log_legend_pkt": "пакет",
                "key_import_pub_title": "Импорт публичного ключа",
                "key_import_pub_prompt": "Вставьте публичный ключ для {peer} (base64 или hex):",
                "key_import_pub_done": "Публичный ключ импортирован для {peer}.",
                "key_import_pub_failed": "Не удалось импортировать публичный ключ для {peer}.",
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
                "theme_pretty_girl": "pretty girl",
                "theme_froggy": "froggy",
                "theme_spinach": "spinach",
                "theme_hint": "Применяется сразу к главному окну и окну настроек.",
                "security_auto_stale_hours": "Автопринять если ключ старше, ч",
                "security_auto_seen_minutes": "Автопринять если был в сети, мин",
                "security_auto_mode": "Правило AUTO",
                "security_auto_mode_or": "ИЛИ (достаточно одного)",
                "security_auto_mode_and": "И (нужно оба условия)",
                "security_auto_hint": "AUTO принимает смену ключа только если старый закрепленный ключ никогда не был подтвержден.\nSTRICT всегда требует ручной сброс.\nALWAYS ACCEPT удобнее всего, но слабее к подмене ключа.\nЕсли ключ уже подтверждался, нужен ручной сброс.",
                "full_reset_profile": "Сброс текущего профиля",
                "full_reset_all": "Сброс всех настроек",
                "full_reset_confirm": "Удалить все настройки профиля, историю, очередь и ключи для '{name}'?\n\nДействие необратимо.",
                "full_reset_all_confirm": "Удалить ВСЕ профили, ключи и настройки на этом устройстве?\n\nДействие необратимо.",
                "full_reset_done": "Данные текущего профиля и ключи сброшены.",
                "full_reset_all_done": "Все профили и настройки сброшены.",
                "full_reset_unavailable": "Полный сброс доступен после инициализации ноды/профиля.",
                "copy_log": "Копировать лог",
                "clear_log": "Очистить лог",
                "ack_alerts": "Подтвердить тревоги",
                "alerts_show": "Показать тревогу",
                "msg_ctx_copy": "Копировать",
                "msg_ctx_route": "Запрос traceroute",
                "msg_ctx_cancel_send": "Отменить отправку",
                "meta_std_text": "Meshtastic text",
                "msg_route_title": "Маршрут сообщения",
                "msg_route_na": "Информация о маршруте для этого сообщения пока недоступна.",
                "msg_route_hops": "Хопов",
                "msg_route_hops_tb": "Хопы туда/обратно",
                "msg_route_attempts": "Попытки (ср.)",
                "msg_route_packets": "Пакеты",
                "trace_request": "Запрос маршрута",
                "trace_timeout": "Таймаут ожидания трассировки",
                "trace_send_blocked": "Запрос трассировки не был отправлен: радиоинтерфейс был занят",
                "trace_towards": "Маршрут до получателя:",
                "trace_back": "Маршрут обратно:",
                "about_summary": (
                    "meshTalk - настольный клиент для устойчивого обмена сообщениями по Meshtastic mesh-сети.\n\n"
                    "Принцип работы:\n"
                    "- Сообщения делятся на группы пакетов и доставляются с ACK/повторами/backoff.\n"
                    "- Для каждого peer выбирается маршрут (собственный протокол meshTalk или обычный Meshtastic text).\n"
                    "- В статусе показываются прогресс доставки, попытки, хопы и части пакетов.\n\n"
                    "Криптография и где применяется:\n"
                    "- Шифрование транспорта MT-WIREv2: AES-256-GCM (AEAD) для полезных кадров протокола.\n"
                    "- Обмен ключами: KR1/KR2 с X25519 public key (служебные кадры в открытом виде).\n"
                    "- Вывод ключа: HKDF-SHA256 (из общего секрета X25519).\n"
                    "- Шифрование локального профиля: AES-256-GCM для файлов history/state/incoming.\n"
                    "- Шифрование файла бэкапа приватного ключа: Scrypt + AES-256-GCM.\n\n"
                    "Назначение: гражданские/любительские/исследовательские эксперименты mesh-связи."
                ),
            },
        }
        # Load persisted config before rendering the UI so Settings reflect saved values.
        try:
            cfg_new = load_config()
            if isinstance(cfg_new, dict):
                cfg.clear()
                cfg.update(cfg_new)
                cfg["activity_controller_model"] = normalize_activity_controller_model(
                    cfg.get("activity_controller_model", ACTIVITY_CONTROLLER_DEFAULT)
                )
                ensure_routing_defaults(cfg)
                routing_ctl.update_config(cfg)
        except Exception:
            pass
        log_startup = []
        for line in startup_events:
            log_startup.append(line)
        current_lang = str(cfg.get("lang", "ru")).lower()
        verbose_log = bool(cfg.get("log_verbose", True))
        # Default: ON (users can disable if they don't want noisy logs/graphs).
        packet_trace_log = bool(cfg.get("log_packet_trace", True))
        runtime_log_file = bool(cfg.get("runtime_log_file", True))
        auto_pacing = False
        cfg["auto_pacing"] = False
        session_rekey_enabled = bool(cfg.get("session_rekey", session_rekey_enabled))
        security_policy = str(cfg.get("security_key_rotation_policy", security_policy) or "auto").strip().lower()
        if security_policy not in ("auto", "strict", "always"):
            security_policy = "auto"
        contacts_visibility = normalize_contacts_visibility(cfg.get("contacts_visibility", "all"), default="all")
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
        # Do not use a dynamic minimum width for the contacts panel:
        # it can prevent shrinking the main window horizontally (deadlock: resize doesn't happen,
        # so our min-width recalculation never runs). Use a small fixed minimum + dynamic maximum.
        try:
            list_group.setMinimumWidth(220)
        except Exception:
            pass
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
        try:
            items_list.setTextElideMode(QtCore.Qt.ElideRight)
        except Exception:
            pass
        # Smooth scrolling for contacts (same feel as the chat list).
        try:
            items_list.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
            items_list.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        except Exception:
            pass
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

        # Smooth wheel scrolling for contacts list (QListWidget scrolls per-item by default).
        try:
            _contacts_scroll_anim = QtCore.QPropertyAnimation(items_list.verticalScrollBar(), b"value")
            _contacts_scroll_anim.setDuration(120)
            _contacts_scroll_anim.setEasingCurve(QtCore.QEasingCurve.OutCubic)

            class _SmoothWheelContacts(QtCore.QObject):
                def eventFilter(self, obj, event):  # type: ignore[override]
                    try:
                        if event.type() == QtCore.QEvent.Wheel:
                            sb = items_list.verticalScrollBar()
                            if sb is None:
                                return False
                            dy = 0
                            try:
                                pd = event.pixelDelta()
                                if pd is not None and not pd.isNull():
                                    dy = int(pd.y())
                            except Exception:
                                dy = 0
                            if dy == 0:
                                try:
                                    dy = int(event.angleDelta().y() / 120.0 * 60.0)
                                except Exception:
                                    dy = 0
                            if dy == 0:
                                return False
                            target = int(sb.value() - dy)
                            target = max(int(sb.minimum()), min(int(sb.maximum()), int(target)))
                            try:
                                _contacts_scroll_anim.stop()
                                _contacts_scroll_anim.setStartValue(int(sb.value()))
                                _contacts_scroll_anim.setEndValue(int(target))
                                _contacts_scroll_anim.start()
                                event.accept()
                                return True
                            except Exception:
                                return False
                    except Exception:
                        return False
                    return False

            _contacts_smooth_wheel = _SmoothWheelContacts(items_list)
            items_list.viewport().installEventFilter(_contacts_smooth_wheel)
            items_list._smooth_wheel = _contacts_smooth_wheel  # type: ignore[attr-defined]
            items_list._smooth_scroll_anim = _contacts_scroll_anim  # type: ignore[attr-defined]
        except Exception:
            pass

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
        hello_btn = QtWidgets.QPushButton(tr("hello_mode_button"))
        hello_btn.setFixedSize(108, 32)
        set_mono(hello_btn, 13, bold=False)
        try:
            hello_btn.setFont(chat_label.font())
        except Exception:
            pass
        settings_btn = QtWidgets.QPushButton(tr("settings"))
        settings_btn.setFixedHeight(32)
        header_layout.addWidget(hello_btn, 0)
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
        def _alert_overlay_reserve_px() -> int:
            # Keep the right-side controls clickable even when the alert overlay slides in.
            # Header layout spacing is 0, so we can approximate by summing visible button widths.
            reserve = 6  # small breathing room
            try:
                if key_renew_btn.isVisible():
                    reserve += int(key_renew_btn.width())
            except Exception:
                pass
            try:
                if key_ignore_btn.isVisible():
                    reserve += int(key_ignore_btn.width())
            except Exception:
                pass
            try:
                if alert_btn.isVisible():
                    reserve += int(alert_btn.width())
            except Exception:
                pass
            try:
                reserve += int(settings_btn.width())
            except Exception:
                pass
            return int(max(32, reserve))

        def _header_resize_event(e):
            try:
                w = max(1, header_bar.width())
                h = header_bar.height()
                reserve = _alert_overlay_reserve_px()
                alert_overlay.setFixedWidth(max(1, w - reserve))
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
        # Per-pixel scrolling is required for smooth wheel animation and large items.
        try:
            chat_text.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
            chat_text.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        except Exception:
            pass
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

        # Smooth wheel scrolling for the chat list (QListWidget scrolls per-item by default and feels "jumpy").
        try:
            _scroll_anim = QtCore.QPropertyAnimation(chat_text.verticalScrollBar(), b"value")
            _scroll_anim.setDuration(120)
            _scroll_anim.setEasingCurve(QtCore.QEasingCurve.OutCubic)

            class _SmoothWheel(QtCore.QObject):
                def eventFilter(self, obj, event):  # type: ignore[override]
                    try:
                        if event.type() == QtCore.QEvent.Wheel:
                            sb = chat_text.verticalScrollBar()
                            if sb is None:
                                return False
                            dy = 0
                            try:
                                pd = event.pixelDelta()
                                if pd is not None and not pd.isNull():
                                    dy = int(pd.y())
                            except Exception:
                                dy = 0
                            if dy == 0:
                                try:
                                    dy = int(event.angleDelta().y() / 120.0 * 60.0)
                                except Exception:
                                    dy = 0
                            if dy == 0:
                                return False
                            # Qt: positive dy means wheel up (scroll content up => scrollbar value decreases).
                            target = int(sb.value() - dy)
                            target = max(int(sb.minimum()), min(int(sb.maximum()), int(target)))
                            try:
                                _scroll_anim.stop()
                                _scroll_anim.setStartValue(int(sb.value()))
                                _scroll_anim.setEndValue(int(target))
                                _scroll_anim.start()
                                event.accept()
                                return True
                            except Exception:
                                return False
                    except Exception:
                        return False
                    return False

            _smooth_wheel = _SmoothWheel(chat_text)
            chat_text.viewport().installEventFilter(_smooth_wheel)
            chat_text._smooth_wheel = _smooth_wheel  # type: ignore[attr-defined]
            chat_text._smooth_scroll_anim = _scroll_anim  # type: ignore[attr-defined]
        except Exception:
            pass

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
                # Apply as maximum width so the window can still be shrunk.
                list_group.setMaximumWidth(target)
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

        # Theme-aware cache: light themes use transparent avatar background, so the cache key must include that.
        peer_logo_cache: Dict[Tuple[str, int, str], "QtGui.QPixmap"] = {}

        def _peer_logo_pixmap(peer_id: str, side: int) -> "QtGui.QPixmap":
            s = max(16, int(side))
            try:
                is_light = str(current_theme or "").strip().lower() in ("pretty_girl",)
            except Exception:
                is_light = False
            theme_kind = "light" if is_light else "dark"
            key = (str(peer_id or ""), s, theme_kind)
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
            # Keep avatar tile subtle: user requested more transparent avatar backgrounds.
            c_bg.setAlpha(74)
            c_line = _col(0.00, 0.06, 1.0)
            c_line.setAlpha(118)

            pm = QtGui.QPixmap(s, s)
            pm.fill(QtCore.Qt.transparent)
            p = QtGui.QPainter(pm)
            p.setRenderHint(QtGui.QPainter.Antialiasing, True)
            p.setRenderHint(QtGui.QPainter.SmoothPixmapTransform, True)

            outer = QtCore.QRectF(0.5, 0.5, float(s - 1), float(s - 1))
            # Avatar background:
            # - dark themes: keep a muted rounded background
            # - light themes: keep it fully transparent (no "tile" behind the strokes)
            if not is_light:
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
                status_color_hex = str(data.get("status_color", "") or "").strip()
                panel_color = None
                if status_color_hex and re.fullmatch(r"#[0-9a-fA-F]{6}", status_color_hex):
                    panel_color = QtGui.QColor(status_color_hex)
                # Fallback palette: used only when no explicit per-row color was computed.
                if panel_color is None:
                    if status_code == "app_online":
                        panel_color = QtGui.QColor("#2bbf66")
                    elif status_code == "app_offline":
                        panel_color = QtGui.QColor("#0e2d1a")
                    elif status_code == "mesh_online":
                        panel_color = QtGui.QColor("#d9b233")
                    elif status_code == "mesh_offline":
                        panel_color = QtGui.QColor("#2f2206")
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
            QListWidget#contactsList { background: #2b0a22; }
            QListWidget#chatList { background: #35102a; }
            QListWidget#chatList::item { background: transparent; border: none; padding: 2px 0px; }
            QListWidget#chatList::item:selected { background: transparent; }
            QListWidget#chatList::item:selected:!active { background: transparent; }
            QTextEdit { background: #2b0a22; border: 1px solid #3c0f2e; padding: 0px; }
            QLineEdit { background: #2b0a22; border: 1px solid #6f4a7a; padding: 6px; }
            QCheckBox, QRadioButton { color: #f0ecf2; spacing: 8px; }
            QCheckBox::indicator, QRadioButton::indicator {
                width: 14px;
                height: 14px;
                border: 1px solid #b89cc3;
                background: #23101f;
            }
            QRadioButton::indicator { border-radius: 7px; }
            QCheckBox::indicator:checked {
                background: #ff9800;
                border: 1px solid #ffb84d;
            }
            QRadioButton::indicator:checked {
                background: #ff9800;
                border: 1px solid #ffb84d;
                border-radius: 7px;
            }
            QCheckBox::indicator:unchecked:hover, QRadioButton::indicator:unchecked:hover {
                border: 1px solid #d8c5e0;
                background: #311727;
            }
            QCheckBox::indicator:disabled, QRadioButton::indicator:disabled {
                border: 1px solid #6d6072;
                background: #1c151d;
            }
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
            QLabel#hint { color: #bcaec0; font-size: 14px; }
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
            QListWidget#contactsList { background: #15181b; }
            QListWidget#chatList { background: #101214; }
            QListWidget#chatList::item { background: transparent; border: none; padding: 2px 0px; }
            QListWidget#chatList::item:selected { background: transparent; }
            QListWidget#chatList::item:selected:!active { background: transparent; }
            QTextEdit { background: #15181b; border: 1px solid #3a3f46; padding: 0px; }
            QLineEdit { background: #15181b; border: 1px solid #5a6069; padding: 6px; }
            QCheckBox, QRadioButton { color: #ececec; spacing: 8px; }
            QCheckBox::indicator, QRadioButton::indicator {
                width: 14px;
                height: 14px;
                border: 1px solid #adb3bc;
                background: #0f1113;
            }
            QRadioButton::indicator { border-radius: 7px; }
            QCheckBox::indicator:checked {
                background: #f05d23;
                border: 1px solid #ff885e;
            }
            QRadioButton::indicator:checked {
                background: #f05d23;
                border: 1px solid #ff885e;
                border-radius: 7px;
            }
            QCheckBox::indicator:unchecked:hover, QRadioButton::indicator:unchecked:hover {
                border: 1px solid #d0d6df;
                background: #1a1f24;
            }
            QCheckBox::indicator:disabled, QRadioButton::indicator:disabled {
                border: 1px solid #5b6066;
                background: #111417;
            }
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
            QLabel#hint { color: #999fa8; font-size: 14px; }
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
        THEME_PRETTY_GIRL = """
            /* Light theme, background based on Pantone 2026 (Cloud Dancer) approximation. */
            QWidget { background: #f0eee9; color: #2b1b24; }
            QGroupBox { border: 0; margin-top: 0; font-weight: 700; }
            QGroupBox::title { subcontrol-origin: margin; left: 6px; color: #3a2a33; }
            QGroupBox#listGroup::title { height: 0px; }
            QGroupBox#listGroup { margin-top: 0px; }

            QListWidget { background: #f7f5f0; border: 1px solid #d7d1c8; padding: 0px; }
            QListWidget#contactsList { background: #f7f5f0; }
            QListWidget#chatList { background: #f3f0f4; }
            QListWidget#chatList::item { background: transparent; border: none; padding: 2px 0px; }
            QListWidget#chatList::item:selected { background: transparent; }
            QListWidget#chatList::item:selected:!active { background: transparent; }

            QTextEdit { background: #f7f5f0; border: 1px solid #d7d1c8; padding: 0px; }
            QLineEdit { background: #ffffff; border: 1px solid #cdb9c4; padding: 6px; color:#2b1b24; }
            QCheckBox, QRadioButton { color: #2b1b24; spacing: 8px; }
            QCheckBox::indicator, QRadioButton::indicator {
                width: 14px;
                height: 14px;
                border: 1px solid #9e8b96;
                background: #ffffff;
            }
            QRadioButton::indicator { border-radius: 7px; }
            QCheckBox::indicator:checked {
                background: #ff76b3;
                border: 1px solid #ff94c4;
            }
            QRadioButton::indicator:checked {
                background: #ff76b3;
                border: 1px solid #ff94c4;
                border-radius: 7px;
            }
            QCheckBox::indicator:unchecked:hover, QRadioButton::indicator:unchecked:hover {
                border: 1px solid #7f6f79;
                background: #fff5fb;
            }
            QCheckBox::indicator:disabled, QRadioButton::indicator:disabled {
                border: 1px solid #c8bcc3;
                background: #f2edf0;
            }

            QPushButton { background: #f3bfd9; border: 1px solid #cdb9c4; padding: 6px 10px; color:#2b1b24; }
            QPushButton:hover { background: #f7cfe3; }

            QTabWidget::pane { border: 1px solid #cdb9c4; top: -1px; }
            QTabBar::tab {
                background: #ede2ea;
                color: #3a2a33;
                border: 1px solid #cdb9c4;
                border-bottom: 0;
                padding: 6px 12px;
                margin-right: 2px;
                min-height: 22px;
            }
            QTabBar::tab:selected {
                background: #ff76b3;
                color: #22131b;
                font-weight: 800;
            }
            QTabBar::tab:!selected:hover { background: #f3bfd9; color: #22131b; }

            QMenu { background: #ffffff; border: 1px solid #cdb9c4; padding: 2px; }
            QMenu::item { padding: 6px 14px; color: #2b1b24; }
            QMenu::item:selected { background: #ff76b3; color: #22131b; }

            QLabel#muted { color: #6b5d66; }
            QLabel#hint { color: #6b5d66; font-size: 14px; }
            QLabel#section { color: #3a2a33; font-size: 13px; font-weight: 600; }

            QWidget#headerBar { background: #f3bfd9; }
            QWidget#headerBar QLabel { background: transparent; font-weight: 700; color: #2b1b24; }
            QWidget#headerBar[mtStatus="ok"] { background: #1f6b3f; }
            QWidget#headerBar[mtStatus="ok"] QLabel { color: #fffff0; }
            QWidget#headerBar[mtStatus="warn"] { background: #b78300; }
            QWidget#headerBar[mtStatus="warn"] QLabel { color: #fff7df; }
            QWidget#headerBar[mtStatus="error"] { background: #7a1e1e; }
            QWidget#headerBar[mtStatus="error"] QLabel { color: #ffecec; }

            QListWidget#contactsList::item { padding: 8px 0px; }
            QListWidget#contactsList::item:selected { background: #f0d6e4; }
            QListWidget#contactsList::item:selected:!active { background: #f0d6e4; }

            QScrollBar:vertical {
                background: transparent;
                width: 8px;
                margin: 0px;
                border: none;
            }
            QScrollBar::handle:vertical {
                background: rgba(205, 145, 178, 0.42);
                min-height: 24px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: rgba(205, 145, 178, 0.62);
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
        THEME_FROGGY = """
            /* Soft pastel green theme with pond-like contrast and warm highlights. */
            QWidget { background: #edf5e9; color: #21312a; }
            QGroupBox { border: 0; margin-top: 0; font-weight: 700; }
            QGroupBox::title { subcontrol-origin: margin; left: 6px; color: #2f4637; }
            QGroupBox#listGroup::title { height: 0px; }
            QGroupBox#listGroup { margin-top: 0px; }

            QListWidget { background: #e6f0df; border: 1px solid #b9cbb7; padding: 0px; }
            QListWidget#contactsList { background: #e6f0df; }
            QListWidget#chatList { background: #eef6ea; }
            QListWidget#chatList::item { background: transparent; border: none; padding: 2px 0px; }
            QListWidget#chatList::item:selected { background: transparent; }
            QListWidget#chatList::item:selected:!active { background: transparent; }

            QTextEdit { background: #f3f8ef; border: 1px solid #b9cbb7; padding: 0px; }
            QLineEdit { background: #fbfdf9; border: 1px solid #adc1ab; padding: 6px; color:#21312a; }
            QCheckBox, QRadioButton { color: #21312a; spacing: 8px; }
            QCheckBox::indicator, QRadioButton::indicator {
                width: 14px;
                height: 14px;
                border: 1px solid #7fa07f;
                background: #fbfdf9;
            }
            QRadioButton::indicator { border-radius: 7px; }
            QCheckBox::indicator:checked {
                background: #8fcf97;
                border: 1px solid #6ea777;
            }
            QRadioButton::indicator:checked {
                background: #8fcf97;
                border: 1px solid #6ea777;
                border-radius: 7px;
            }
            QCheckBox::indicator:unchecked:hover, QRadioButton::indicator:unchecked:hover {
                border: 1px solid #6c8c6e;
                background: #f3faee;
            }
            QCheckBox::indicator:disabled, QRadioButton::indicator:disabled {
                border: 1px solid #c7d4c5;
                background: #eef3ec;
            }

            QPushButton { background: #cfe6bf; border: 1px solid #9db696; padding: 6px 10px; color:#21312a; }
            QPushButton:hover { background: #dcefcf; }

            QTabWidget::pane { border: 1px solid #adc1ab; top: -1px; }
            QTabBar::tab {
                background: #dbe8d2;
                color: #2f4637;
                border: 1px solid #adc1ab;
                border-bottom: 0;
                padding: 6px 12px;
                margin-right: 2px;
                min-height: 22px;
            }
            QTabBar::tab:selected {
                background: #b9d88a;
                color: #1d2b1f;
                font-weight: 800;
            }
            QTabBar::tab:!selected:hover { background: #cfe6bf; color: #1d2b1f; }

            QMenu { background: #fbfdf9; border: 1px solid #adc1ab; padding: 2px; }
            QMenu::item { padding: 6px 14px; color: #21312a; }
            QMenu::item:selected { background: #b9d88a; color: #1d2b1f; }

            QLabel#muted { color: #5a7461; }
            QLabel#hint { color: #5a7461; font-size: 14px; }
            QLabel#section { color: #2f4637; font-size: 13px; font-weight: 600; }

            QWidget#headerBar { background: #c9dea4; }
            QWidget#headerBar QLabel { background: transparent; font-weight: 700; color: #21312a; }
            QWidget#headerBar[mtStatus="ok"] { background: #3e7b50; }
            QWidget#headerBar[mtStatus="ok"] QLabel { color: #f7fff5; }
            QWidget#headerBar[mtStatus="warn"] { background: #b68a3b; }
            QWidget#headerBar[mtStatus="warn"] QLabel { color: #fff9e8; }
            QWidget#headerBar[mtStatus="error"] { background: #91504d; }
            QWidget#headerBar[mtStatus="error"] QLabel { color: #fff1ee; }

            QListWidget#contactsList::item { padding: 8px 0px; }
            QListWidget#contactsList::item:selected { background: #d7e7ca; }
            QListWidget#contactsList::item:selected:!active { background: #d7e7ca; }

            QScrollBar:vertical {
                background: transparent;
                width: 8px;
                margin: 0px;
                border: none;
            }
            QScrollBar::handle:vertical {
                background: rgba(120, 164, 122, 0.40);
                min-height: 24px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: rgba(120, 164, 122, 0.60);
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
        THEME_DARK_FROGGY = """
            /* Dark froggy theme: moss, pond, and muted lime accents. */
            QWidget { background: #132019; color: #dbead9; }
            QGroupBox { border: 0; margin-top: 0; font-weight: 700; }
            QGroupBox::title { subcontrol-origin: margin; left: 6px; color: #b9d4b6; }
            QGroupBox#listGroup::title { height: 0px; }
            QGroupBox#listGroup { margin-top: 0px; }

            QListWidget { background: #18271f; border: 1px solid #355240; padding: 0px; }
            QListWidget#contactsList { background: #18271f; }
            QListWidget#chatList { background: #1d2e24; }
            QListWidget#chatList::item { background: transparent; border: none; padding: 2px 0px; }
            QListWidget#chatList::item:selected { background: transparent; }
            QListWidget#chatList::item:selected:!active { background: transparent; }

            QTextEdit { background: #18271f; border: 1px solid #355240; padding: 0px; }
            QLineEdit { background: #21342a; border: 1px solid #476856; padding: 6px; color:#eef8ed; }
            QCheckBox, QRadioButton { color: #dbead9; spacing: 8px; }
            QCheckBox::indicator, QRadioButton::indicator {
                width: 14px;
                height: 14px;
                border: 1px solid #6c9274;
                background: #21342a;
            }
            QRadioButton::indicator { border-radius: 7px; }
            QCheckBox::indicator:checked {
                background: #7fbe6f;
                border: 1px solid #9fd58d;
            }
            QRadioButton::indicator:checked {
                background: #7fbe6f;
                border: 1px solid #9fd58d;
                border-radius: 7px;
            }
            QCheckBox::indicator:unchecked:hover, QRadioButton::indicator:unchecked:hover {
                border: 1px solid #88ad8f;
                background: #294034;
            }
            QCheckBox::indicator:disabled, QRadioButton::indicator:disabled {
                border: 1px solid #466151;
                background: #1a2a21;
            }

            QPushButton { background: #2c4737; border: 1px solid #54745f; padding: 6px 10px; color:#e7f4e5; }
            QPushButton:hover { background: #365744; }

            QTabWidget::pane { border: 1px solid #355240; top: -1px; }
            QTabBar::tab {
                background: #22372b;
                color: #c5ddc2;
                border: 1px solid #355240;
                border-bottom: 0;
                padding: 6px 12px;
                margin-right: 2px;
                min-height: 22px;
            }
            QTabBar::tab:selected {
                background: #7fbe6f;
                color: #142117;
                font-weight: 800;
            }
            QTabBar::tab:!selected:hover { background: #2d4838; color: #eef8ed; }

            QMenu { background: #18271f; border: 1px solid #355240; padding: 2px; }
            QMenu::item { padding: 6px 14px; color: #dbead9; }
            QMenu::item:selected { background: #7fbe6f; color: #142117; }

            QLabel#muted { color: #9db99c; }
            QLabel#hint { color: #9db99c; font-size: 14px; }
            QLabel#section { color: #c5ddc2; font-size: 13px; font-weight: 600; }

            QWidget#headerBar { background: #2d5a3a; }
            QWidget#headerBar QLabel { background: transparent; font-weight: 700; color: #eef8ed; }
            QWidget#headerBar[mtStatus="ok"] { background: #1e6c40; }
            QWidget#headerBar[mtStatus="ok"] QLabel { color: #f5fff3; }
            QWidget#headerBar[mtStatus="warn"] { background: #8a6c2b; }
            QWidget#headerBar[mtStatus="warn"] QLabel { color: #fff8e8; }
            QWidget#headerBar[mtStatus="error"] { background: #7a3f3c; }
            QWidget#headerBar[mtStatus="error"] QLabel { color: #fff0ed; }

            QListWidget#contactsList::item { padding: 8px 0px; }
            QListWidget#contactsList::item:selected { background: #294034; }
            QListWidget#contactsList::item:selected:!active { background: #294034; }

            QScrollBar:vertical {
                background: transparent;
                width: 8px;
                margin: 0px;
                border: none;
            }
            QScrollBar::handle:vertical {
                background: rgba(127, 190, 111, 0.34);
                min-height: 24px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: rgba(127, 190, 111, 0.54);
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
            "pretty_girl": THEME_PRETTY_GIRL,
            "froggy": THEME_DARK_FROGGY,
            "spinach": THEME_FROGGY,
            "dark_froggy": THEME_DARK_FROGGY,
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
            # Theme affects avatar rendering (light themes remove avatar background).
            try:
                peer_logo_cache.clear()
            except Exception:
                pass
            try:
                avatar_cache.clear()
            except Exception:
                pass
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
            is_ru = (str(current_lang or "ru").lower() == "ru")

            # User-facing summaries in current UI language.
            if "pinned key mismatch" in low:
                if "action=auto_accept" in low:
                    return (
                        "Ключ контакта обновлен автоматически"
                        if is_ru
                        else "Contact key updated automatically"
                    )
                peer_txt = ""
                try:
                    m_peer = re.search(r"\bpeer=(!?[0-9a-fA-F]{8})\b", raw)
                    if m_peer:
                        peer_norm = norm_id_for_filename(m_peer.group(1))
                        peer_wire = norm_id_for_wire(peer_norm)
                        peer_txt = f" ({peer_wire})"
                except Exception:
                    peer_txt = ""
                return (f"Конфликт ключа контакта{peer_txt}" if is_ru else f"Contact key mismatch{peer_txt}")
            if "decrypt failed" in low:
                return "Не удалось расшифровать сообщение" if is_ru else "Failed to decrypt message"
            if "reject invalid public key" in low or "reject invalid key frame" in low:
                return "Некорректный ключевой пакет" if is_ru else "Invalid key frame"
            if "radio: disconnected" in low:
                return "Радиомодуль отключен" if is_ru else "Radio disconnected"
            if "radio: protobuf decode error" in low:
                return "Ошибка данных радиомодуля" if is_ru else "Radio decode error"
            if "trace: done" in low and "timeout" in low:
                return "Трассировка не ответила вовремя" if is_ru else "Traceroute timed out"
            if "send failed" in low:
                return "Ошибка отправки пакета" if is_ru else "Packet send failed"
            if "sendstd: failed" in low:
                return "Ошибка отправки в стандартный порт" if is_ru else "Failed to send to standard port"
            if "drop:" in low and "timeout" in low:
                return "Пакет не доставлен вовремя" if is_ru else "Packet delivery timeout"
            if "exception" in low or "traceback" in low:
                return "Внутренняя ошибка приложения" if is_ru else "Internal application error"
            if low.startswith("warn:"):
                return "Предупреждение системы" if is_ru else "System warning"

            # Fallback: short readable raw event + localized marker.
            short = _alert_summary(raw, limit=64)
            if str(level or "").lower() == "error":
                return (f"Ошибка: {short}" if is_ru else f"Error: {short}")
            return (f"Предупреждение: {short}" if is_ru else f"Warning: {short}")

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
            # Overlay width is reserved to not cover right-side buttons.
            start_pos = QtCore.QPoint(0, 0)
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
            try:
                reserve = _alert_overlay_reserve_px()
            except Exception:
                reserve = 38
            alert_overlay.setFixedWidth(max(1, w - int(reserve)))
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

        def refresh_hello_button() -> None:
            active = bool(hello_mode_active)
            now_h = time.time()
            elapsed_h = max(0.0, float(now_h - hello_schedule_start_ts))
            interval_h = _hello_interval_seconds_by_uptime(elapsed_h)
            turbo_active = bool(active and interval_h <= 180.0)
            font_css = ""
            try:
                fi = chat_label.fontInfo()
                fam = str(fi.family() or "Ubuntu Mono").replace("'", "\\'")
                psize = max(1, int(fi.pointSize()))
                fweight = int(fi.weight())
                font_css = f"font-family:'{fam}'; font-size:{psize}pt; font-weight:{fweight};"
            except Exception:
                font_css = "font-family:'Ubuntu Mono'; font-size:13pt; font-weight:400;"
            # User requested: monospace HELLO button and green color when turbo phase ends.
            if turbo_active:
                hello_btn.setStyleSheet(
                    f"QPushButton {{ {font_css} background:#b78300; color:#fff7df; border:1px solid #d3a33d; }}"
                    "QPushButton:hover { background:#c89412; }"
                )
                if hello_mode_until_ts > 0.0:
                    left_s = max(0, int(hello_mode_until_ts - time.time()))
                    hello_btn.setToolTip(tr("hello_mode_running_tip").format(seconds=left_s))
                else:
                    hello_btn.setToolTip(tr("hello_mode_running_inf_tip"))
            else:
                if active:
                    hello_btn.setStyleSheet(
                        f"QPushButton {{ {font_css} background:#2f5f3a; color:#ecfff0; border:1px solid #4f8a60; }}"
                        "QPushButton:hover { background:#3c7449; }"
                    )
                    hello_btn.setToolTip(tr("hello_mode_running_inf_tip"))
                else:
                    hello_btn.setStyleSheet(
                        f"QPushButton {{ {font_css} background:#2f5f3a; color:#ecfff0; border:1px solid #4f8a60; }}"
                        "QPushButton:hover { background:#3c7449; }"
                    )
                    hello_btn.setToolTip(tr("hello_mode_stopped_tip"))

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

        groups: Dict[str, set] = {k: set(v) for k, v in groups_cfg.items() if isinstance(k, str) and isinstance(v, list)}
        dialogs: Dict[str, Dict[str, object]] = {}
        chat_history: Dict[str, list] = {}
        list_index: list[Optional[str]] = []
        current_dialog: Optional[str] = None
        last_loaded_profile: Optional[str] = None

        def save_gui_config() -> None:
            save_config(
                build_gui_config_payload(
                    current_lang=current_lang,
                    verbose_log=verbose_log,
                    runtime_log_file=runtime_log_file,
                    auto_pacing=auto_pacing,
                    pinned_dialogs=pinned_dialogs,
                    hidden_contacts=hidden_contacts,
                    groups=groups,
                    cfg=cfg,
                    args=args,
                    data_port_label=data_port_label,
                    normalize_activity_controller_model_fn=normalize_activity_controller_model,
                    activity_controller_default=ACTIVITY_CONTROLLER_DEFAULT,
                    msg_retry_active_window_seconds=MSG_RETRY_ACTIVE_WINDOW_SECONDS,
                    msg_retry_muted_interval_seconds=MSG_RETRY_MUTED_INTERVAL_SECONDS,
                    msg_retry_probe_window_seconds=MSG_RETRY_PROBE_WINDOW_SECONDS,
                    peer_responsive_grace_seconds=PEER_RESPONSIVE_GRACE_SECONDS,
                    retry_backoff_max_seconds=RETRY_BACKOFF_MAX_SECONDS,
                    retry_jitter_ratio=RETRY_JITTER_RATIO,
                    discovery_send=discovery_send,
                    discovery_reply=discovery_reply,
                    clear_pending_on_switch=clear_pending_on_switch,
                    contacts_visibility=contacts_visibility,
                    current_theme=current_theme,
                    peer_meta=peer_meta,
                )
            )

        def apply_language() -> None:
            list_group.setTitle("")
            update_status()
            msg_entry.setPlaceholderText(tr("message"))
            settings_btn.setText(tr("settings"))
            hello_btn.setText(tr("hello_mode_button"))
            key_renew_btn.setText(tr("key_conflict_replace"))
            key_ignore_btn.setText(tr("key_conflict_paranoid"))
            key_renew_btn.setToolTip(tr("key_conflict_header_replace_tip"))
            key_ignore_btn.setToolTip(tr("key_conflict_header_ignore_tip"))
            if key_conflict_peer:
                _set_key_conflict_header(key_conflict_peer, key_conflict_sig)
            send_btn.setText(tr("send"))
            search_field.setPlaceholderText(tr("search"))
            refresh_hello_button()

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
        settings_data_port_combo: Optional["QtWidgets.QComboBox"] = None
        settings_auto_pacing_cb: Optional["QtWidgets.QCheckBox"] = None
        # Activity tab: live "effective values" labels (updated by timer + pacing_update).
        settings_activity_rate_lbl: Optional["QtWidgets.QLabel"] = None
        settings_activity_parallel_lbl: Optional["QtWidgets.QLabel"] = None
        settings_activity_pps_lbl: Optional["QtWidgets.QLabel"] = None
        settings_activity_retry_lbl: Optional["QtWidgets.QLabel"] = None
        settings_activity_max_lbl: Optional["QtWidgets.QLabel"] = None
        settings_activity_active_lbl: Optional["QtWidgets.QLabel"] = None
        settings_activity_probe_min_lbl: Optional["QtWidgets.QLabel"] = None
        settings_activity_probe_max_lbl: Optional["QtWidgets.QLabel"] = None
        settings_activity_probe_win_lbl: Optional["QtWidgets.QLabel"] = None
        settings_activity_grace_lbl: Optional["QtWidgets.QLabel"] = None
        settings_activity_backoff_lbl: Optional["QtWidgets.QLabel"] = None
        settings_activity_jitter_lbl: Optional["QtWidgets.QLabel"] = None
        settings_activity_fast_retries_lbl: Optional["QtWidgets.QLabel"] = None
        settings_activity_fast_delay_lbl: Optional["QtWidgets.QLabel"] = None
        settings_activity_fast_budget_lbl: Optional["QtWidgets.QLabel"] = None
        settings_status_line: Optional["QtWidgets.QLabel"] = None
        settings_panel_widget: Optional["QtWidgets.QDialog"] = None
        settings_close_fn = None

        def open_settings() -> None:
            nonlocal current_lang
            nonlocal verbose_log
            nonlocal runtime_log_file
            nonlocal auto_pacing
            nonlocal settings_auto_pacing_cb
            nonlocal settings_data_port_combo
            nonlocal settings_activity_rate_lbl, settings_activity_parallel_lbl, settings_activity_pps_lbl
            nonlocal settings_activity_retry_lbl, settings_activity_max_lbl
            nonlocal settings_activity_active_lbl, settings_activity_probe_min_lbl, settings_activity_probe_max_lbl
            nonlocal settings_activity_probe_win_lbl, settings_activity_grace_lbl, settings_activity_backoff_lbl
            nonlocal settings_activity_jitter_lbl
            nonlocal settings_activity_fast_retries_lbl, settings_activity_fast_delay_lbl, settings_activity_fast_budget_lbl
            nonlocal settings_status_line
            nonlocal discovery_send, discovery_reply
            nonlocal clear_pending_on_switch
            nonlocal contacts_visibility
            nonlocal security_policy
            nonlocal session_rekey_enabled
            nonlocal errors_need_ack
            nonlocal settings_panel_widget
            nonlocal settings_close_fn

            def _purge_stale_settings_panels(skip_widget: Optional["QtWidgets.QWidget"] = None) -> None:
                try:
                    root_w = right_col.parentWidget()
                    if root_w is None:
                        return
                    for _child in root_w.findChildren(QtWidgets.QWidget):
                        if not bool(_child.property("mtSettingsPanel")):
                            continue
                        if skip_widget is not None and _child is skip_widget:
                            continue
                        try:
                            right_col.removeWidget(_child)
                        except Exception:
                            pass
                        try:
                            _child.hide()
                            _child.deleteLater()
                        except Exception:
                            pass
                except Exception:
                    pass

            if settings_panel_widget is not None:
                try:
                    if callable(settings_close_fn):
                        settings_close_fn()
                    else:
                        _purge_stale_settings_panels(skip_widget=settings_panel_widget)
                        try:
                            settings_panel_widget.reject()
                        except Exception:
                            settings_panel_widget.close()
                except Exception:
                    pass
                return
            _purge_stale_settings_panels()

            # Rebuild the dialog when language changes so all labels/hints are translated.
            while True:
                dlg = QtWidgets.QDialog(win)
                dlg.setWindowTitle(tr("settings_title"))
                dlg.resize(820, 600)
                # Embedded settings panel in-place (inside the main window).
                try:
                    dlg.setWindowFlags(QtCore.Qt.Widget)
                except Exception:
                    pass
                try:
                    dlg.setProperty("mtSettingsPanel", True)
                except Exception:
                    pass
                # When embedded, do not impose a large minimum size (it can block resizing the main window).
                try:
                    dlg.setMinimumSize(0, 0)
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

                settings_status_line = None

                settings_scroll = QtWidgets.QScrollArea(dlg)
                settings_scroll.setWidgetResizable(True)
                settings_scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
                try:
                    settings_scroll.setMinimumWidth(0)
                    settings_scroll.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
                except Exception:
                    pass
                layout.addWidget(settings_scroll, 1)

                settings_content = QtWidgets.QWidget()
                try:
                    settings_content.setMinimumWidth(0)
                    settings_content.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
                except Exception:
                    pass
                settings_scroll.setWidget(settings_content)

                settings_content_layout = QtWidgets.QVBoxLayout(settings_content)
                settings_content_layout.setContentsMargins(0, 0, 0, 0)
                settings_content_layout.setSpacing(0)

                tabs = QtWidgets.QTabWidget(settings_content)
                try:
                    tabs.setUsesScrollButtons(True)
                    tabs.setElideMode(QtCore.Qt.ElideRight)
                    _tabs_bar = tabs.tabBar()
                    if _tabs_bar is not None:
                        _tabs_bar.setExpanding(False)
                        _tabs_bar.setUsesScrollButtons(True)
                        _tabs_bar.setElideMode(QtCore.Qt.ElideRight)
                    tabs.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
                    tabs.setMinimumWidth(0)
                except Exception:
                    pass
                settings_content_layout.addWidget(tabs, 1)

                reopen = {"flag": False}

                # -------------------
                # General tab
                # -------------------
                tab_general = QtWidgets.QWidget()
                tabs.addTab(tab_general, tr("tab_general"))
                general_layout = QtWidgets.QHBoxLayout(tab_general)
                general_layout.setContentsMargins(14, 12, 14, 10)
                general_layout.setSpacing(26)

                right_panel = QtWidgets.QVBoxLayout()
                right_panel.setContentsMargins(0, 0, 0, 0)
                right_panel.setSpacing(12)
                try:
                    right_panel.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
                except Exception:
                    pass

                # Single left-aligned column (avoid giant empty space when the other column is unused).
                general_layout.addLayout(right_panel, 0)
                general_layout.addStretch(1)

                # Runtime/activity settings live on the Activity tab (keeps General clean).
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

                def compact_field(widget, width: int = 160):
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

                def row_with_hint(field_widget, hint_text: str) -> QtWidgets.QWidget:
                    # Render: [field][hint ...] on the same row (hint to the right).
                    w = QtWidgets.QWidget()
                    h = QtWidgets.QHBoxLayout(w)
                    h.setContentsMargins(0, 0, 0, 0)
                    h.setSpacing(10)
                    # Align to top so the left control doesn't "bounce" vertically when the hint wraps.
                    h.addWidget(field_widget, 0, QtCore.Qt.AlignTop)
                    hint = QtWidgets.QLabel(hint_text)
                    hint.setObjectName("hint")
                    hint.setWordWrap(True)
                    try:
                        hint.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
                    except Exception:
                        pass
                    hint.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
                    h.addWidget(hint, 1, QtCore.Qt.AlignTop)
                    return w

                def int_text(value, fallback: int) -> str:
                    try:
                        return str(int(float(value)))
                    except Exception:
                        return str(int(fallback))

                # Serial port is auto-detected; meshTalk packet portNum is configurable.
                maxbytes_edit = QtWidgets.QLineEdit(int_text(cfg.get("max_bytes", args.max_bytes), int(args.max_bytes)))
                data_port_combo = QtWidgets.QComboBox(runtime_group)
                for title, value in known_portnum_choices():
                    data_port_combo.addItem(title, value)
                current_port = normalize_mesh_packet_port_value(cfg.get("mesh_packet_portnum", data_port_label))
                current_idx = data_port_combo.findData(current_port)
                if current_idx < 0 and current_port:
                    data_port_combo.addItem(f"{current_port} (custom)", current_port)
                    current_idx = data_port_combo.count() - 1
                if current_idx >= 0:
                    data_port_combo.setCurrentIndex(current_idx)
                compact_field(maxbytes_edit, width=140)
                compact_field(data_port_combo, width=230)

                int_validator = QtGui.QIntValidator(0, 999999, dlg)
                maxbytes_edit.setValidator(int_validator)

                cb_auto_pacing = QtWidgets.QCheckBox("", runtime_group)
                cb_auto_pacing.setChecked(False)
                cb_auto_pacing.setEnabled(False)
                cb_auto_pacing.setVisible(False)

                settings_data_port_combo = data_port_combo
                settings_auto_pacing_cb = cb_auto_pacing

                def sync_auto_pacing_fields() -> None:
                    # This slot can fire during teardown (dialog accept/reject + deleteLater).
                    try:
                        if settings_panel_widget is None:
                            return
                    except Exception:
                        return
                    try:
                        on = bool(cb_auto_pacing.isChecked())
                    except Exception:
                        on = bool(cfg.get("auto_pacing", auto_pacing))
                    del on

                sync_auto_pacing_fields()
                cb_auto_pacing.toggled.connect(lambda _checked: sync_auto_pacing_fields())
                right_panel.addWidget(runtime_group)
                runtime_group.hide()
                lang_title = QtWidgets.QLabel(tr("language"))
                lang_title.setObjectName("muted")
                lang_title.setStyleSheet("font-weight:600;")
                lang_title.setContentsMargins(6, 8, 0, 0)
                right_panel.addWidget(lang_title)

                lang_group = QtWidgets.QGroupBox("")
                lang_v = QtWidgets.QVBoxLayout(lang_group)
                rb_ru = QtWidgets.QRadioButton(tr("lang_ru"), lang_group)
                rb_en = QtWidgets.QRadioButton(tr("lang_en"), lang_group)
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
                cb_discovery_send = QtWidgets.QCheckBox(tr("discovery_send"), discovery_group)
                cb_discovery_send.setChecked(discovery_send)
                discovery_v.addWidget(cb_discovery_send)
                discovery_send_hint = QtWidgets.QLabel(tr("hint_discovery_send"))
                discovery_send_hint.setObjectName("hint")
                discovery_send_hint.setWordWrap(True)
                discovery_v.addWidget(discovery_send_hint)

                cb_discovery_reply = QtWidgets.QCheckBox(tr("discovery_reply"), discovery_group)
                cb_discovery_reply.setChecked(discovery_reply)
                discovery_v.addWidget(cb_discovery_reply)
                discovery_reply_hint = QtWidgets.QLabel(tr("hint_discovery_reply"))
                discovery_reply_hint.setObjectName("hint")
                discovery_reply_hint.setWordWrap(True)
                discovery_v.addWidget(discovery_reply_hint)

                cb_clear_pending = QtWidgets.QCheckBox(tr("clear_pending_on_switch"), discovery_group)
                cb_clear_pending.setChecked(clear_pending_on_switch)
                discovery_v.addWidget(cb_clear_pending)
                clear_pending_hint = QtWidgets.QLabel(tr("hint_clear_pending"))
                clear_pending_hint.setObjectName("hint")
                clear_pending_hint.setWordWrap(True)
                discovery_v.addWidget(clear_pending_hint)

                right_panel.addWidget(discovery_group)

                right_panel.addStretch(1)

                # -------------------
                # Activity tab
                # -------------------
                tab_activity = QtWidgets.QWidget()
                tabs.addTab(tab_activity, tr("tab_activity"))
                act_root = QtWidgets.QVBoxLayout(tab_activity)
                act_root.setContentsMargins(14, 12, 14, 10)
                act_root.setSpacing(12)

                act_title = QtWidgets.QLabel(tr("activity_title"))
                act_title.setObjectName("muted")
                act_title.setStyleSheet("font-weight:600;")
                act_title.setContentsMargins(6, 8, 0, 0)
                act_root.addWidget(act_title)

                # Profile + aggressiveness (minimal UI).
                profile_group = QtWidgets.QGroupBox("")
                profile_layout = QtWidgets.QFormLayout(profile_group)
                profile_layout.setLabelAlignment(QtCore.Qt.AlignLeft)
                profile_layout.setFormAlignment(QtCore.Qt.AlignTop)
                profile_layout.setVerticalSpacing(8)
                profile_layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.ExpandingFieldsGrow)
                profile_layout.setRowWrapPolicy(QtWidgets.QFormLayout.WrapLongRows)
                try:
                    profile_layout.setContentsMargins(10, 10, 10, 10)
                except Exception:
                    pass

                timing_auto_cb = QtWidgets.QCheckBox(tr("activity_timing_mode_auto"), profile_group)
                timing_auto_cb.setChecked(False)
                timing_auto_cb.setEnabled(False)
                timing_auto_cb.setVisible(False)
                profile_layout.addRow(tr("activity_timing_mode"), row_with_hint(timing_auto_cb, tr("hint_activity_timing_mode")))

                # Default profile: low-noise
                prof_combo = QtWidgets.QComboBox(profile_group)
                prof_combo.addItem(tr("activity_profile_low"), "low")
                prof_combo.addItem(tr("activity_profile_bal"), "bal")
                prof_combo.addItem(tr("activity_profile_fast"), "fast")
                stored_prof = str(cfg.get("activity_profile", "low") or "low").strip().lower()
                if stored_prof not in ("low", "bal", "fast"):
                    stored_prof = "low"
                _pidx = prof_combo.findData(stored_prof)
                prof_combo.setCurrentIndex(_pidx if _pidx >= 0 else 0)
                compact_field(prof_combo, width=220)
                profile_layout.addRow(tr("activity_profile"), row_with_hint(prof_combo, tr("hint_activity_profile")))

                model_combo = QtWidgets.QComboBox(profile_group)
                model_combo.addItem(tr("activity_model_trickle"), "trickle")
                model_combo.addItem(tr("activity_model_ledbat"), "ledbat")
                model_combo.addItem(tr("activity_model_quic"), "quic")
                stored_model = normalize_activity_controller_model(cfg.get("activity_controller_model", ACTIVITY_CONTROLLER_DEFAULT))
                _midx = model_combo.findData(stored_model)
                model_combo.setCurrentIndex(_midx if _midx >= 0 else 0)
                compact_field(model_combo, width=260)
                profile_layout.addRow(tr("activity_controller_model"), row_with_hint(model_combo, tr("hint_activity_controller_model")))

                aggr_slider = QtWidgets.QSlider(QtCore.Qt.Horizontal, profile_group)
                aggr_slider.setMinimum(0)
                aggr_slider.setMaximum(100)
                aggr_slider.setSingleStep(1)
                aggr_slider.setPageStep(5)
                try:
                    aggr_slider.setFixedHeight(22)
                except Exception:
                    pass
                try:
                    aggr_val = int(float(cfg.get("activity_aggressiveness", 20) or 20))
                except Exception:
                    aggr_val = 20
                aggr_val = max(0, min(100, int(aggr_val)))
                aggr_slider.setValue(aggr_val)
                aggr_read = QtWidgets.QLabel(str(aggr_val), profile_group)
                aggr_read.setObjectName("hint")
                try:
                    aggr_read.setFixedWidth(40)
                except Exception:
                    pass
                aggr_row = QtWidgets.QWidget()
                aggr_h = QtWidgets.QHBoxLayout(aggr_row)
                aggr_h.setContentsMargins(0, 0, 0, 0)
                aggr_h.setSpacing(10)
                aggr_h.addWidget(aggr_slider, 1)
                aggr_h.addWidget(aggr_read, 0)
                profile_layout.addRow(tr("activity_aggr"), row_with_hint(aggr_row, tr("hint_activity_aggr")))
                aggr_slider.valueChanged.connect(lambda v: aggr_read.setText(str(int(v))))
                act_root.addWidget(profile_group)
                try:
                    profile_group.hide()
                except Exception:
                    pass

                manual_title = QtWidgets.QLabel(tr("activity_live_title"))
                manual_title.setObjectName("muted")
                manual_title.setStyleSheet("font-weight:600;")
                manual_title.setContentsMargins(6, 8, 0, 0)
                act_root.addWidget(manual_title)

                manual_group = QtWidgets.QGroupBox("")
                manual_layout = QtWidgets.QFormLayout(manual_group)
                manual_layout.setLabelAlignment(QtCore.Qt.AlignLeft)
                manual_layout.setFormAlignment(QtCore.Qt.AlignTop)
                manual_layout.setVerticalSpacing(8)
                manual_layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.ExpandingFieldsGrow)
                manual_layout.setRowWrapPolicy(QtWidgets.QFormLayout.WrapLongRows)
                try:
                    manual_layout.setContentsMargins(10, 10, 10, 10)
                except Exception:
                    pass

                interval_default = int(cfg.get("retry_seconds", cfg.get("rate_seconds", args.retry_seconds)) or args.retry_seconds)
                activity_retry_edit = QtWidgets.QLineEdit(int_text(interval_default, int(getattr(args, "retry_seconds", 10) or 10)))
                # Store max wait in seconds in config, but present it in days to users.
                try:
                    _max_seconds_cfg = int(float(cfg.get("max_seconds", args.max_seconds) or args.max_seconds))
                except Exception:
                    _max_seconds_cfg = int(getattr(args, "max_seconds", 3600) or 3600)
                _max_days_cfg = max(1, int(math.ceil(float(_max_seconds_cfg) / 86400.0)))
                activity_maxdays_edit = QtWidgets.QLineEdit(int_text(_max_days_cfg, 1))
                try:
                    _backoff_cfg = int(float(cfg.get("activity_retry_backoff_max_seconds", RETRY_BACKOFF_MAX_SECONDS) or RETRY_BACKOFF_MAX_SECONDS))
                except Exception:
                    _backoff_cfg = int(RETRY_BACKOFF_MAX_SECONDS)
                activity_backoff_cap_edit = QtWidgets.QLineEdit(int_text(_backoff_cfg, int(RETRY_BACKOFF_MAX_SECONDS)))
                try:
                    _jitter_ratio_cfg = float(cfg.get("activity_retry_jitter_ratio", RETRY_JITTER_RATIO) or RETRY_JITTER_RATIO)
                except Exception:
                    _jitter_ratio_cfg = float(RETRY_JITTER_RATIO)
                _jitter_pct_cfg = max(0, min(100, int(round(_jitter_ratio_cfg * 100.0))))
                activity_jitter_edit = QtWidgets.QLineEdit(int_text(_jitter_pct_cfg, int(round(RETRY_JITTER_RATIO * 100.0))))
                activity_batch_count_edit = QtWidgets.QLineEdit(
                    int_text(
                        cfg.get("parallel_sends", getattr(args, "parallel_sends", 2)),
                        int(getattr(args, "parallel_sends", 2) or 2),
                    )
                )
                activity_batch_intra_pause_edit = QtWidgets.QLineEdit(
                    int_text(cfg.get("activity_intra_batch_gap_ms", 0), 0)
                )
                compact_field(activity_retry_edit, width=140)
                compact_field(activity_maxdays_edit, width=140)
                compact_field(activity_backoff_cap_edit, width=140)
                compact_field(activity_jitter_edit, width=140)
                compact_field(activity_batch_count_edit, width=140)
                compact_field(activity_batch_intra_pause_edit, width=140)
                try:
                    iv = QtGui.QIntValidator(0, 999999, dlg)
                    iv_pos = QtGui.QIntValidator(1, 999999, dlg)
                    iv_pct = QtGui.QIntValidator(0, 100, dlg)
                    activity_retry_edit.setValidator(iv)
                    activity_maxdays_edit.setValidator(iv)
                    activity_backoff_cap_edit.setValidator(iv_pos)
                    activity_jitter_edit.setValidator(iv_pct)
                    activity_batch_count_edit.setValidator(iv_pos)
                    activity_batch_intra_pause_edit.setValidator(iv)
                except Exception:
                    pass

                manual_layout.addRow(
                    tr("retry"),
                    row_with_hint(activity_retry_edit, tr("hint_retry")),
                )
                manual_layout.addRow(
                    tr("max_days"),
                    row_with_hint(activity_maxdays_edit, tr("hint_max_days")),
                )

                try:
                    prof_combo.setEnabled(False)
                    model_combo.setEnabled(False)
                    aggr_slider.setEnabled(False)
                except Exception:
                    pass
                act_root.addWidget(manual_group)

                show_advanced_activity = bool(cfg.get("activity_show_advanced", False))
                cb_activity_advanced = QtWidgets.QCheckBox(tr("activity_advanced"))
                cb_activity_advanced.setChecked(show_advanced_activity)
                act_root.addWidget(row_with_hint(cb_activity_advanced, tr("hint_activity_advanced")))

                advanced_group = QtWidgets.QGroupBox("")
                advanced_layout = QtWidgets.QFormLayout(advanced_group)
                advanced_layout.setLabelAlignment(QtCore.Qt.AlignLeft)
                advanced_layout.setFormAlignment(QtCore.Qt.AlignTop)
                advanced_layout.setVerticalSpacing(8)
                advanced_layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.ExpandingFieldsGrow)
                advanced_layout.setRowWrapPolicy(QtWidgets.QFormLayout.WrapLongRows)
                try:
                    advanced_layout.setContentsMargins(10, 10, 10, 10)
                except Exception:
                    pass
                advanced_layout.addRow(
                    tr("activity_backoff_cap_s"),
                    row_with_hint(activity_backoff_cap_edit, tr("hint_activity_backoff_cap_s")),
                )
                advanced_layout.addRow(
                    tr("activity_jitter_pct"),
                    row_with_hint(activity_jitter_edit, tr("hint_activity_jitter_pct")),
                )
                advanced_layout.addRow(
                    tr("activity_batch_count"),
                    row_with_hint(activity_batch_count_edit, tr("hint_activity_batch_count")),
                )
                advanced_layout.addRow(
                    tr("activity_batch_intra_pause"),
                    row_with_hint(activity_batch_intra_pause_edit, tr("hint_activity_batch_intra_pause")),
                )
                advanced_layout.addRow(
                    tr("max_bytes"),
                    row_with_hint(maxbytes_edit, tr("hint_max_bytes")),
                )
                advanced_layout.addRow(
                    tr("mesh_packet_port"),
                    row_with_hint(data_port_combo, tr("hint_mesh_packet_port")),
                )
                advanced_group.setVisible(show_advanced_activity)
                cb_activity_advanced.toggled.connect(lambda v: advanced_group.setVisible(bool(v)))
                act_root.addWidget(advanced_group)

                # -------------------
                # Graphs section (moved into Activity tab)
                # -------------------
                graphs_title = QtWidgets.QLabel(tr("graphs_title"))
                graphs_title.setObjectName("muted")
                graphs_title.setStyleSheet("font-weight:600;")
                graphs_title.setContentsMargins(6, 8, 0, 0)
                act_root.addWidget(graphs_title)

                graphs_group = QtWidgets.QGroupBox("")
                graphs_layout = QtWidgets.QVBoxLayout(graphs_group)
                graphs_layout.setContentsMargins(10, 10, 10, 10)
                graphs_layout.setSpacing(6)

                class MetricsLineGraph(QtWidgets.QWidget):
                    def __init__(self, series: list[tuple[str, str, str]], parent=None) -> None:
                        super().__init__(parent)
                        self._series = list(series)
                        self._window_s = int(cfg.get("graphs_window_seconds", METRICS_GRAPH_WINDOW_SECONDS) or METRICS_GRAPH_WINDOW_SECONDS)
                        # Compact height: the graph should not dominate the settings page.
                        self.setMinimumHeight(110)
                        self.setMaximumHeight(130)
                        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)

                    def set_series(self, series: list[tuple[str, str, str]]) -> None:
                        self._series = list(series)
                        self.update()

                    def set_window_seconds(self, window_s: int) -> None:
                        try:
                            w = int(window_s)
                        except Exception:
                            w = int(METRICS_GRAPH_WINDOW_SECONDS)
                        w = max(60, min(int(METRICS_RETENTION_SECONDS), int(w)))
                        self._window_s = int(w)
                        self.update()

                    def paintEvent(self, event) -> None:  # type: ignore[override]
                        del event
                        p = QtGui.QPainter(self)
                        try:
                            p.setRenderHint(QtGui.QPainter.Antialiasing, True)
                        except Exception:
                            pass
                        r = self.rect()
                        # Background (subtle, independent from theme; keeps contrast in light/dark).
                        bg = QtGui.QColor("#1b1b1b")
                        bg.setAlpha(40)
                        p.setBrush(bg)
                        p.setPen(QtCore.Qt.NoPen)
                        p.drawRoundedRect(r.adjusted(0, 0, -1, -1), 8, 8)

                        rows = metrics_snapshot_rows(window_s=int(self._window_s))
                        if not rows or r.width() < 80 or r.height() < 60:
                            return
                        # Bipolar bar plot: outgoing series are above 0, incoming are below 0.
                        # Y scale is bytes/sec, symmetric around the zero line.
                        max_abs = 1.0
                        def _series_value(row: dict, key: str) -> float:
                            k = str(key or "")
                            # Base key: value = out_<k> - in_<k> (up=TX, down=RX, single color per type).
                            if not (k.startswith("out_") or k.startswith("in_")):
                                try:
                                    v_out = float(row.get("out_" + k, 0.0) or 0.0)
                                except Exception:
                                    v_out = 0.0
                                try:
                                    v_in = float(row.get("in_" + k, 0.0) or 0.0)
                                except Exception:
                                    v_in = 0.0
                                return float(v_out - v_in)
                            try:
                                v = float(row.get(k, 0.0) or 0.0)
                            except Exception:
                                v = 0.0
                            if k.startswith("in_"):
                                return -float(v)
                            return float(v)

                        for _sec, row in rows:
                            for key, _name, _color in self._series:
                                v = _series_value(row, str(key))
                                av = abs(float(v))
                                if av > max_abs:
                                    max_abs = av
                        max_abs = max(1.0, float(max_abs))
                        # Plot area with room for Y labels on the left and time labels below.
                        pad_l, pad_r, pad_t, pad_b = (46, 10, 12, 24)
                        pr = QtCore.QRect(
                            int(r.left() + pad_l),
                            int(r.top() + pad_t),
                            int(max(10, r.width() - pad_l - pad_r)),
                            int(max(10, r.height() - pad_t - pad_b)),
                        )
                        if pr.width() < 20 or pr.height() < 20:
                            return

                        def _fmt_bytes(v: float) -> str:
                            val = max(0.0, float(v))
                            if val >= 1024.0 * 1024.0:
                                return f"{(val / (1024.0 * 1024.0)):.1f}M"
                            if val >= 1024.0:
                                return f"{(val / 1024.0):.1f}K"
                            return str(int(round(val)))

                        grid_pen = QtGui.QPen(QtGui.QColor(255, 255, 255, 25))
                        p.setPen(grid_pen)
                        mid_y = pr.top() + int(pr.height() / 2)
                        zero_pen = QtGui.QPen(QtGui.QColor(255, 255, 255, 45))
                        zero_pen.setWidthF(1.2)
                        p.setPen(zero_pen)
                        p.drawLine(pr.left(), mid_y, pr.right(), mid_y)
                        p.setPen(grid_pen)
                        # Symmetric grid lines and Y labels.
                        label_pen = QtGui.QPen(QtGui.QColor(220, 220, 220, 160))
                        label_font = p.font()
                        try:
                            label_font.setPointSize(max(7, int(label_font.pointSize() or 8) - 1))
                            p.setFont(label_font)
                        except Exception:
                            pass
                        y_levels = [1.0, 0.5, 0.0, -0.5, -1.0]
                        for frac in y_levels:
                            y = int(round(float(mid_y) - (float(pr.height()) / 2.0) * float(frac)))
                            p.setPen(grid_pen if frac != 0.0 else zero_pen)
                            p.drawLine(pr.left(), y, pr.right(), y)
                            label_val = float(max_abs) * abs(float(frac))
                            p.setPen(label_pen)
                            p.drawText(
                                int(r.left() + 2),
                                int(y - 2),
                                int(max(30, pad_l - 6)),
                                12,
                                int(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter),
                                "0" if frac == 0.0 else _fmt_bytes(label_val),
                            )
                        p.setPen(grid_pen)

                        # Time ticks on X axis.
                        n = len(rows)
                        if n < 1:
                            return
                        tick_count = min(6, max(2, int(pr.width() / 90)))
                        for j in range(int(tick_count)):
                            if tick_count <= 1:
                                idx = 0
                            else:
                                idx = int(round((max(1, n - 1) * j) / float(tick_count - 1)))
                            idx = max(0, min(n - 1, idx))
                            x = int(round(pr.left() + (pr.width() * idx) / float(max(1, n - 1))))
                            p.setPen(grid_pen)
                            p.drawLine(x, pr.top(), x, pr.bottom())
                            try:
                                ts_label = time.strftime("%H:%M:%S", time.localtime(float(rows[idx][0])))
                            except Exception:
                                ts_label = str(idx)
                            p.setPen(label_pen)
                            p.drawText(
                                int(x - 34),
                                int(pr.bottom() + 6),
                                68,
                                14,
                                int(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignTop),
                                ts_label,
                            )

                        # Draw bars grouped by one-second bucket.
                        if n < 1:
                            return
                        slot_w = float(pr.width()) / float(max(1, n))
                        group_pad = min(2.0, max(0.0, slot_w * 0.08))
                        inner_w = max(1.0, slot_w - (2.0 * group_pad))
                        series_n = max(1, len(self._series))
                        bar_w = max(1.0, inner_w / float(series_n))
                        amp = float(pr.height()) / 2.0
                        for j in range(1, 3):
                            dy = int((pr.height() / 2) * (j / 3.0))
                            # keep subtle extra guides between labeled steps
                            p.setPen(grid_pen)
                            p.drawLine(pr.left(), mid_y - dy, pr.right(), mid_y - dy)
                            p.drawLine(pr.left(), mid_y + dy, pr.right(), mid_y + dy)
                        for idx, (_sec, row) in enumerate(rows):
                            base_x = float(pr.left()) + (float(idx) * slot_w) + group_pad
                            for sidx, (key, _name, color) in enumerate(self._series):
                                v = _series_value(row, str(key))
                                if abs(float(v)) <= 0.0:
                                    continue
                                h = max(1.0, amp * (abs(float(v)) / float(max_abs)))
                                x = base_x + (float(sidx) * bar_w)
                                bw = max(1.0, bar_w - 0.5)
                                if float(v) >= 0.0:
                                    rect = QtCore.QRectF(float(x), float(mid_y) - h, bw, h)
                                else:
                                    rect = QtCore.QRectF(float(x), float(mid_y), bw, h)
                                fill = QtGui.QColor(color)
                                try:
                                    fill.setAlpha(210)
                                except Exception:
                                    pass
                                p.setPen(QtCore.Qt.NoPen)
                                p.setBrush(fill)
                                p.drawRect(rect)

                # Single graph: show all real packet counters on one scale (per second).
                # This matches RF reality: everything that flies (meshTalk service/data + Meshtastic text).
                # Each series is a *packet type*. Direction is encoded by sign: up=TX, down=RX.
                # Y axis is volume: bytes/second (best-effort proxy for RF airtime).
                if current_lang == "ru":
                    packet_series: list[tuple[str, str, str]] = [
                        ("std_bytes", "MT txt", "#f5c2e7"),
                        ("msg_bytes", "MSG", "#a6e22e"),
                        ("srv_ack_bytes", "ACK", "#fd971f"),
                        ("srv_key_bytes", "KEY", "#ffd75f"),
                        ("srv_disc_bytes", "HELLO", "#b894ff"),
                        ("srv_caps_bytes", "CAPS", "#c3b38a"),
                        ("srv_rekey_bytes", "REKEY", "#74b2ff"),
                        ("srv_offline_bytes", "OFF", "#9aa0a6"),
                        ("srv_trace_bytes", "TRACE", "#ff5a5f"),
                        ("srv_fast_bytes", "FAST", "#7ee787"),
                    ]
                else:
                    packet_series = [
                        ("std_bytes", "MT txt", "#f5c2e7"),
                        ("msg_bytes", "MSG", "#a6e22e"),
                        ("srv_ack_bytes", "ACK", "#fd971f"),
                        ("srv_key_bytes", "KEY", "#ffd75f"),
                        ("srv_disc_bytes", "HELLO", "#b894ff"),
                        ("srv_caps_bytes", "CAPS", "#c3b38a"),
                        ("srv_rekey_bytes", "REKEY", "#74b2ff"),
                        ("srv_offline_bytes", "OFF", "#9aa0a6"),
                        ("srv_trace_bytes", "TRACE", "#ff5a5f"),
                        ("srv_fast_bytes", "FAST", "#7ee787"),
                    ]

                graph_widget = MetricsLineGraph(packet_series, parent=graphs_group)
                graphs_layout.addWidget(graph_widget, 0)

                # One-time explanation for bipolar graph.
                bipolar_hint = QtWidgets.QLabel(graphs_group)
                bipolar_hint.setObjectName("hint")
                bipolar_hint.setWordWrap(True)
                if current_lang == "ru":
                    bipolar_hint.setText("Верхние столбики: исходящие (TX). Нижние столбики: входящие (RX). X: время по секундам. Y: байт/сек.")
                else:
                    bipolar_hint.setText("Top bars: outgoing (TX). Bottom bars: incoming (RX). X: time in seconds. Y: bytes/s.")
                graphs_layout.addWidget(bipolar_hint, 0)

                # Compact legend: one column, only packet type + color.
                legend_wrap = QtWidgets.QWidget(graphs_group)
                legend_grid = QtWidgets.QGridLayout(legend_wrap)
                legend_grid.setContentsMargins(0, 0, 0, 0)
                legend_grid.setHorizontalSpacing(8)
                legend_grid.setVerticalSpacing(3)
                col_count = max(1, int(math.ceil(float(len(packet_series)) / 2.0)))
                for idx, (key, name, color) in enumerate(packet_series):
                    del key
                    r = idx // col_count
                    c = idx % col_count
                    cell = QtWidgets.QWidget(legend_wrap)
                    cell_h = QtWidgets.QHBoxLayout(cell)
                    cell_h.setContentsMargins(0, 0, 0, 0)
                    cell_h.setSpacing(6)
                    title = QtWidgets.QLabel(cell)
                    title.setObjectName("muted")
                    title.setTextFormat(QtCore.Qt.RichText)
                    title.setText(f"<span style='color:{html_escape(color)};font-weight:900'>■</span> {html_escape(str(name))}")
                    cell_h.addWidget(title, 0)
                    cell_h.addStretch(1)
                    legend_grid.addWidget(cell, r, c, 1, 1)
                graphs_layout.addWidget(legend_wrap, 0)

                # Time scale selector (window).
                window_row = QtWidgets.QWidget()
                window_h = QtWidgets.QHBoxLayout(window_row)
                window_h.setContentsMargins(0, 0, 0, 0)
                window_h.setSpacing(10)
                window_lbl = QtWidgets.QLabel(tr("graphs_window"))
                window_lbl.setObjectName("muted")
                window_h.addWidget(window_lbl, 0)
                window_combo = QtWidgets.QComboBox(window_row)
                compact_field(window_combo, width=160)
                # Store seconds in data; show localized label.
                if current_lang == "en":
                    window_combo.addItem("5 min", 5 * 60)
                    window_combo.addItem("15 min", 15 * 60)
                    window_combo.addItem("1 hour", 60 * 60)
                    window_combo.addItem("6 hours", 6 * 60 * 60)
                    window_combo.addItem("24 hours", 24 * 60 * 60)
                else:
                    window_combo.addItem("5 мин", 5 * 60)
                    window_combo.addItem("15 мин", 15 * 60)
                    window_combo.addItem("1 час", 60 * 60)
                    window_combo.addItem("6 часов", 6 * 60 * 60)
                    window_combo.addItem("24 часа", 24 * 60 * 60)
                try:
                    current_w = int(cfg.get("graphs_window_seconds", METRICS_GRAPH_WINDOW_SECONDS) or METRICS_GRAPH_WINDOW_SECONDS)
                except Exception:
                    current_w = int(METRICS_GRAPH_WINDOW_SECONDS)
                _widx = window_combo.findData(int(current_w))
                window_combo.setCurrentIndex(_widx if _widx >= 0 else 1)
                window_h.addWidget(window_combo, 0)
                window_h.addStretch(1)
                graphs_layout.addWidget(window_row, 0)

                def _on_window_change(_idx: int) -> None:
                    try:
                        w = int(window_combo.currentData() or METRICS_GRAPH_WINDOW_SECONDS)
                    except Exception:
                        w = int(METRICS_GRAPH_WINDOW_SECONDS)
                    w = max(60, min(int(METRICS_RETENTION_SECONDS), int(w)))
                    cfg["graphs_window_seconds"] = int(w)
                    try:
                        graph_widget.set_window_seconds(int(w))
                    except Exception:
                        pass

                window_combo.currentIndexChanged.connect(_on_window_change)
                _on_window_change(window_combo.currentIndex())

                graphs_timer = QtCore.QTimer(dlg)
                graphs_timer.setInterval(1000)
                def _graphs_tick() -> None:
                    try:
                        if graph_widget.isVisible():
                            graph_widget.update()
                    except Exception:
                        pass
                graphs_timer.timeout.connect(_graphs_tick)
                graphs_timer.start()
                act_root.addWidget(graphs_group)
                act_root.addStretch(1)

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
                theme_ui = build_theme_tab(
                    tabs=tabs,
                    tr=tr,
                    current_theme=current_theme,
                    compact_field=compact_field,
                    QtWidgets=QtWidgets,
                    QtCore=QtCore,
                )
                theme_combo = theme_ui["theme_combo"]

                sec_ui = build_security_tab(
                    tabs=tabs,
                    tr=tr,
                    security_policy=security_policy,
                    session_rekey_enabled=bool(session_rekey_enabled),
                    compact_field=compact_field,
                    QtWidgets=QtWidgets,
                    QtCore=QtCore,
                    wire_version=int(PROTO_VERSION),
                )
                sec_policy = sec_ui["sec_policy"]
                cb_rekey = sec_ui["cb_rekey"]
                btn_keys_copy_pub = sec_ui["btn_keys_copy_pub"]
                btn_keys_backup = sec_ui["btn_keys_backup"]
                btn_keys_import = sec_ui["btn_keys_import"]
                btn_keys_regen = sec_ui["btn_keys_regen"]
                btn_full_reset_profile = sec_ui["btn_full_reset_profile"]
                btn_full_reset_all = sec_ui["btn_full_reset_all"]

                def _set_copy_pub_button_text(text: str) -> None:
                    try:
                        btn_keys_copy_pub.setText(str(text or ""))
                        btn_keys_copy_pub.setToolTip(str(text or ""))
                    except Exception:
                        pass

                def _set_copy_pub_button_width(pub_text: str) -> None:
                    del pub_text
                    try:
                        w = 430
                        h = 34
                        for _btn in (
                            btn_keys_copy_pub,
                            btn_keys_regen,
                            btn_keys_backup,
                            btn_keys_import,
                            btn_full_reset_profile,
                            btn_full_reset_all,
                        ):
                            _btn.setFixedWidth(w)
                            _btn.setFixedHeight(h)
                    except Exception:
                        pass

                def _animate_copy_button_to(text: str) -> None:
                    try:
                        effect = getattr(btn_keys_copy_pub, "_fade_eff", None)
                        if effect is None:
                            effect = QtWidgets.QGraphicsOpacityEffect(btn_keys_copy_pub)
                            effect.setOpacity(1.0)
                            btn_keys_copy_pub.setGraphicsEffect(effect)
                            btn_keys_copy_pub._fade_eff = effect  # type: ignore[attr-defined]
                        anim_out = QtCore.QPropertyAnimation(effect, b"opacity", btn_keys_copy_pub)
                        anim_out.setDuration(120)
                        anim_out.setStartValue(float(effect.opacity()))
                        anim_out.setEndValue(0.0)
                        anim_in = QtCore.QPropertyAnimation(effect, b"opacity", btn_keys_copy_pub)
                        anim_in.setDuration(150)
                        anim_in.setStartValue(0.0)
                        anim_in.setEndValue(1.0)

                        def _after_out():
                            _set_copy_pub_button_text(text)
                            anim_in.start()

                        try:
                            anim_out.finished.disconnect()
                        except Exception:
                            pass
                        anim_out.finished.connect(_after_out)
                        btn_keys_copy_pub._fade_anim_out = anim_out  # type: ignore[attr-defined]
                        btn_keys_copy_pub._fade_anim_in = anim_in  # type: ignore[attr-defined]
                        anim_out.start()
                    except Exception:
                        _set_copy_pub_button_text(text)

                def refresh_security_keys_view() -> None:
                    refresh_security_keys_view_helper(
                        self_id=self_id,
                        priv_path=priv_path,
                        pub_path=pub_path,
                        fallback_text=tr("security_keys_copy_pub"),
                        set_button_text=_set_copy_pub_button_text,
                        set_button_width=_set_copy_pub_button_width,
                    )

                def on_security_keys_regen() -> None:
                    handle_security_keys_regen(
                        ask_confirm=lambda: (
                            QtWidgets.QMessageBox.question(
                                win,
                                "meshTalk",
                                tr("security_keys_regen_confirm"),
                                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                                QtWidgets.QMessageBox.No,
                            )
                            == QtWidgets.QMessageBox.Yes
                        ),
                        regenerate_keys=regenerate_keys,
                        refresh_view=refresh_security_keys_view,
                        info=lambda: QtWidgets.QMessageBox.information(win, "meshTalk", tr("security_keys_regen_done")),
                        warn=lambda: QtWidgets.QMessageBox.warning(win, "meshTalk", tr("security_keys_unavailable")),
                    )

                def on_security_keys_copy_pub() -> None:
                    def _set_clipboard_text(pub_txt: str) -> None:
                        cb = QtWidgets.QApplication.clipboard()
                        if cb is None:
                            raise RuntimeError("clipboard unavailable")
                        cb.setText(pub_txt, QtGui.QClipboard.Clipboard)
                        if not sys.platform.startswith("win"):
                            try:
                                cb.setText(pub_txt, QtGui.QClipboard.Selection)
                            except Exception:
                                pass

                    handle_security_keys_copy_pub(
                        pub_path=pub_path,
                        set_clipboard_text=_set_clipboard_text,
                        animate_copied=_animate_copy_button_to,
                        animate_restore=lambda pub_txt: QtCore.QTimer.singleShot(900, lambda: _animate_copy_button_to(pub_txt)),
                        copied_label=tr("security_keys_copied"),
                        warn=lambda: QtWidgets.QMessageBox.warning(win, "meshTalk", tr("security_copy_pub_failed")),
                    )

                def on_security_keys_backup_priv() -> None:
                    def _ask_save_path(default_name: str, file_filter: str) -> str:
                        backup_dir = os.path.join(keydir, "backups")
                        try:
                            harden_dir(backup_dir)
                        except Exception:
                            pass
                        default_path = os.path.join(backup_dir, default_name)
                        out_path, _ = QtWidgets.QFileDialog.getSaveFileName(
                            win,
                            "meshTalk",
                            default_path,
                            file_filter,
                        )
                        out_path = str(out_path or "")
                        if not out_path:
                            return ""
                        try:
                            out_abs = os.path.abspath(out_path)
                            base_abs = os.path.abspath(BASE_DIR)
                            key_abs = os.path.abspath(keydir)
                            in_project = (out_abs == base_abs) or out_abs.startswith(base_abs + os.sep)
                            in_keydir = (out_abs == key_abs) or out_abs.startswith(key_abs + os.sep)
                            if in_project and not in_keydir:
                                answer = QtWidgets.QMessageBox.question(
                                    win,
                                    "meshTalk",
                                    "Saving encrypted key backups outside keyRings inside the project folder is discouraged. Continue?",
                                    QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                                    QtWidgets.QMessageBox.No,
                                )
                                if answer != QtWidgets.QMessageBox.Yes:
                                    return ""
                        except Exception:
                            pass
                        return out_path

                    def _ask_passphrase(prompt_key: str):
                        txt, ok = QtWidgets.QInputDialog.getText(
                            win,
                            "meshTalk",
                            tr(prompt_key),
                            QtWidgets.QLineEdit.Password,
                        )
                        if not ok:
                            return None
                        return str(txt or "")

                    def _pack_private_backup(priv_txt: str, passphrase: str) -> str:
                        priv_raw = b64d(priv_txt)
                        if len(priv_raw) != 32:
                            raise ValueError("invalid local private key")
                        return _pack_private_backup_encrypted(priv_raw, passphrase)

                    handle_security_keys_backup_priv(
                        self_id=self_id,
                        priv_path=priv_path,
                        ask_save_path=_ask_save_path,
                        ask_passphrase=lambda: _ask_passphrase("security_keys_backup_passphrase"),
                        ask_passphrase_repeat=lambda: _ask_passphrase("security_keys_backup_passphrase_repeat"),
                        file_filter=tr("security_keys_file_filter"),
                        pack_private_backup=_pack_private_backup,
                        harden_file=harden_file,
                        info=lambda: QtWidgets.QMessageBox.information(win, "meshTalk", tr("security_keys_backup_done")),
                        warn_unavailable=lambda: QtWidgets.QMessageBox.warning(win, "meshTalk", tr("security_keys_unavailable")),
                        warn_failed=lambda: QtWidgets.QMessageBox.warning(win, "meshTalk", tr("security_keys_backup_failed")),
                        warn_mismatch=lambda: QtWidgets.QMessageBox.warning(win, "meshTalk", tr("security_keys_backup_passphrase_mismatch")),
                    )

                def on_security_keys_import_priv() -> None:
                    def _apply_imported_private_key(priv_raw: bytes) -> None:
                        priv_new = x25519.X25519PrivateKey.from_private_bytes(priv_raw)
                        pub_new = priv_new.public_key()
                        pub_raw = pub_new.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw,
                        )
                        apply_imported_keypair_atomically(
                            priv_path=priv_path,
                            pub_path=pub_path,
                            priv_text=b64e(priv_raw),
                            pub_text=b64e(pub_raw),
                            validate_private_file=load_priv,
                            validate_public_file=load_pub,
                            harden_file=harden_file,
                        )
                        # Reload runtime keys.
                        nonlocal priv, pub_self, pub_self_raw
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
                            st.await_key_confirm = False
                            st.await_key_confirm_attempts = 0
                            st.key_confirmed_ts = 0.0
                        ui_emit("log", f"{ts_local()} KEY: private key imported, waiting for exchange.")
                        for peer_norm in list(tracked_peers):
                            send_key_request(peer_norm, require_confirm=True, reason="import_private_key")
                        refresh_security_keys_view()

                    def _ask_open_path(file_filter: str) -> str:
                        in_path, _ = QtWidgets.QFileDialog.getOpenFileName(
                            win,
                            "meshTalk",
                            "",
                            file_filter,
                        )
                        return str(in_path or "")

                    def _ask_import_passphrase():
                        txt, ok = QtWidgets.QInputDialog.getText(
                            win,
                            "meshTalk",
                            tr("security_keys_import_passphrase"),
                            QtWidgets.QLineEdit.Password,
                        )
                        if not ok:
                            return None
                        return str(txt or "")

                    handle_security_keys_import_priv(
                        priv_path=priv_path,
                        pub_path=pub_path,
                        ask_confirm=lambda: (
                            QtWidgets.QMessageBox.question(
                                win,
                                "meshTalk",
                                tr("security_keys_import_confirm"),
                                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                                QtWidgets.QMessageBox.No,
                            )
                            == QtWidgets.QMessageBox.Yes
                        ),
                        ask_open_path=_ask_open_path,
                        file_filter=tr("security_keys_file_filter"),
                        load_private_key_from_backup_blob=_load_private_key_from_backup_blob,
                        ask_passphrase=_ask_import_passphrase,
                        apply_imported_private_key=_apply_imported_private_key,
                        info=lambda: QtWidgets.QMessageBox.information(win, "meshTalk", tr("security_keys_import_done")),
                        warn_unavailable=lambda: QtWidgets.QMessageBox.warning(win, "meshTalk", tr("security_keys_unavailable")),
                        warn_failed=lambda: QtWidgets.QMessageBox.warning(win, "meshTalk", tr("security_keys_import_failed")),
                    )

                btn_keys_copy_pub.clicked.connect(on_security_keys_copy_pub)
                btn_keys_backup.clicked.connect(on_security_keys_backup_priv)
                btn_keys_import.clicked.connect(on_security_keys_import_priv)
                btn_keys_regen.clicked.connect(on_security_keys_regen)
                refresh_security_keys_view()

                cmp_ui = build_compression_tab(
                    tabs=tabs,
                    tr=tr,
                    cfg=cfg,
                    compact_field=compact_field,
                    QtWidgets=QtWidgets,
                    QtCore=QtCore,
                    mode_byte_dict=int(MODE_BYTE_DICT),
                    mode_fixed_bits=int(MODE_FIXED_BITS),
                    mode_deflate=int(MODE_DEFLATE),
                    mode_zlib=int(MODE_ZLIB),
                    mode_bz2=int(MODE_BZ2),
                    mode_lzma=int(MODE_LZMA),
                    mode_zstd=int(MODE_ZSTD),
                    zstd_available=bool(_ZSTD_AVAILABLE),
                )
                cmp_choice = cmp_ui["cmp_choice"]
                cmp_norm = cmp_ui["cmp_norm"]

                routing_ui = build_routing_tab(
                    tabs=tabs,
                    tr=tr,
                    cfg=cfg,
                    compact_field=compact_field,
                    row_with_hint=row_with_hint,
                    QtWidgets=QtWidgets,
                    QtCore=QtCore,
                )
                routing_summary_label = routing_ui["summary_label"]
                routing_status_transport = routing_ui["status_transport"]
                routing_status_role = routing_ui["status_role"]
                routing_status_metrics = routing_ui["status_metrics"]
                routing_status_policy = routing_ui["status_policy"]
                routing_status_weights = routing_ui["status_weights"]
                routing_route_table = routing_ui["route_table"]
                routing_buffer_table = routing_ui["buffer_table"]

                def _routing_fill_table(table, rows: list[list[str]]) -> None:
                    try:
                        table.setRowCount(len(rows))
                        for r, row in enumerate(rows):
                            for c, val in enumerate(row):
                                item = QtWidgets.QTableWidgetItem(str(val))
                                try:
                                    item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
                                except Exception:
                                    pass
                                table.setItem(r, c, item)
                        try:
                            table.resizeRowsToContents()
                        except Exception:
                            pass
                    except Exception:
                        pass

                def refresh_routing_monitor() -> None:
                    try:
                        routing_status_transport.setText("refreshing...")
                    except Exception:
                        pass
                    try:
                        route_rows: list[list[str]] = []
                        now_rt = time.time()
                        route_ttl_s = float(getattr(relay_state, "seen_ttl_s", 0.0) or 0.0)
                        reachability_map = getattr(relay_state, "reachability", {}) or {}

                        def _format_monitor_score(raw_value: object) -> str:
                            try:
                                score_val = float(raw_value)
                            except Exception:
                                return "-"
                            if (not math.isfinite(score_val)) or score_val <= -1e8:
                                return "-"
                            return f"{score_val:.2f}"

                        def _best_route_row_for_peer(peer_norm: str):
                            try:
                                slot_now = current_epoch_slot(now=now_rt)
                            except Exception:
                                slot_now = current_epoch_slot()
                            token_candidates = [
                                _relay_token_for_peer(peer_norm, slot_now),
                                _relay_token_for_peer(peer_norm, max(0, int(slot_now) - 1)),
                            ]
                            best_row = None
                            for token in token_candidates:
                                rows = list(reachability_map.get(token) or [])
                                if rows:
                                    best_row = rows[0]
                                    break
                            return best_row

                        def _peer_recent_activity_ts(peer_norm: str) -> float:
                            ts_val = 0.0
                            try:
                                st_local = get_peer_state(peer_norm)
                            except Exception:
                                st_local = None
                            if st_local is not None:
                                for attr in ("last_seen_ts", "key_confirmed_ts", "last_key_ok_ts", "last_hello_rx_ts", "device_seen_ts"):
                                    try:
                                        ts_val = max(ts_val, float(getattr(st_local, attr, 0.0) or 0.0))
                                    except Exception:
                                        pass
                            try:
                                rec_local = peer_meta.get(peer_norm, {})
                            except Exception:
                                rec_local = {}
                            if isinstance(rec_local, dict):
                                for key_name in ("last_seen_ts", "key_confirmed_ts", "device_seen_ts"):
                                    try:
                                        ts_val = max(ts_val, float(rec_local.get(key_name, 0.0) or 0.0))
                                    except Exception:
                                        pass
                            try:
                                if peer_names_lock.acquire(blocking=False):
                                    try:
                                        rec_name = peer_names.get(peer_norm) or {}
                                    finally:
                                        peer_names_lock.release()
                                else:
                                    rec_name = {}
                                if isinstance(rec_name, dict):
                                    ts_val = max(ts_val, float(rec_name.get("last_heard_ts", 0.0) or 0.0))
                            except Exception:
                                pass
                            return float(ts_val)

                        peers_rt, _ = snapshot_runtime_state(peer_states, known_peers, tracked_peers)
                        peer_list_rt = sorted(
                            (
                                str(peer_raw or "").strip()
                                for peer_raw in peers_rt
                            ),
                            key=lambda x: x,
                        )
                        for peer_norm in peer_list_rt:
                            if not peer_norm or peer_norm == self_id or peer_norm.startswith("group:"):
                                continue
                            try:
                                state_name, state_reason = peer_transport_state(peer_norm, now_ts=now_rt)
                                if state_name != "direct_ready":
                                    continue
                                selected_score = None
                                try:
                                    stats = routing_ctl.export_peer_stats(peer_norm)
                                except Exception:
                                    stats = {}
                                if isinstance(stats, dict):
                                    selected_route = str(stats.get("selected_route", "") or "-")
                                    try:
                                        selected_score_raw = float(stats.get("selected_score", 0.0) or 0.0)
                                    except Exception:
                                        selected_score_raw = -1e9
                                    selected_score = selected_score_raw if selected_route == "meshTalk" else None
                                    try:
                                        routes_map = dict(stats.get("routes") or {})
                                    except Exception:
                                        routes_map = {}
                                else:
                                    selected_route = "-"
                                    routes_map = {}
                                mesh_stats = routes_map.get("meshTalk") if isinstance(routes_map, dict) else None
                                if not isinstance(mesh_stats, dict):
                                    mesh_stats = {}
                                try:
                                    delivery_ema = float(mesh_stats.get("delivery_ema", 0.0) or 0.0)
                                except Exception:
                                    delivery_ema = 0.0
                                try:
                                    timeout_ema = float(mesh_stats.get("timeout_ema", 0.0) or 0.0)
                                except Exception:
                                    timeout_ema = 0.0
                                try:
                                    retry_ema = float(mesh_stats.get("retry_ema", 0.0) or 0.0)
                                except Exception:
                                    retry_ema = 0.0
                                try:
                                    rtt_p50_s = float(mesh_stats.get("rtt_p50_s", 0.0) or 0.0)
                                except Exception:
                                    rtt_p50_s = 0.0
                                try:
                                    hops_ema = float(mesh_stats.get("hops_ema", 0.0) or 0.0)
                                except Exception:
                                    hops_ema = 0.0
                                try:
                                    snr_ema = float(mesh_stats.get("snr_ema", 0.0) or 0.0)
                                except Exception:
                                    snr_ema = 0.0
                                try:
                                    route_last_ts = float(mesh_stats.get("last_ts", 0.0) or 0.0)
                                except Exception:
                                    route_last_ts = 0.0
                                if route_last_ts <= 0.0:
                                    route_last_ts = _peer_recent_activity_ts(peer_norm)
                                age_s = max(0.0, now_rt - route_last_ts) if route_last_ts > 0.0 else 0.0
                                score_text = _format_monitor_score(selected_score if selected_score is not None else None)
                                route_rows.append([
                                    peer_norm,
                                    ("active" if selected_route == "meshTalk" else "standby"),
                                    score_text,
                                    f"{delivery_ema * 100.0:.0f}%",
                                    f"{timeout_ema * 100.0:.0f}%",
                                    f"{rtt_p50_s:.1f}s",
                                    f"{hops_ema:.1f}",
                                    f"{retry_ema:.1f}",
                                    f"{snr_ema:.1f}",
                                    format_duration_mmss(age_s),
                                ])
                            except Exception:
                                continue
                        _routing_fill_table(routing_route_table, route_rows)

                        buffer_rows: list[list[str]] = []
                        now_q = time.time()
                        relay_rx = relay_incoming or {}
                        for msg_hex in sorted(relay_rx.keys()):
                            rec = relay_rx.get(msg_hex) or {}
                            src_peer = str(rec.get("from") or rec.get("peer") or "-")
                            got = int(rec.get("got", 0) or 0)
                            total = int(rec.get("total", 1) or 1)
                            started_ts = float(rec.get("started_ts", 0.0) or 0.0)
                            age_s = max(0.0, now_q - started_ts) if started_ts > 0.0 else 0.0
                            buffer_rows.append([
                                src_peer,
                                str(self_id or "?"),
                                "transit_rx",
                                str(msg_hex)[:16],
                                f"{got}/{max(1, total)}",
                                "-",
                                ("done" if got >= max(1, total) else "assembling"),
                                format_duration_mmss(age_s),
                            ])

                        try:
                            if pending_lock.acquire(blocking=False):
                                try:
                                    pending_snapshot = {
                                        str(k): [dict(x) for x in ((v or {}).values() if isinstance(v, dict) else list(v or []))]
                                        for k, v in (pending_by_peer or {}).items()
                                    }
                                finally:
                                    pending_lock.release()
                            else:
                                pending_snapshot = {}
                        except Exception:
                            pending_snapshot = {}
                        pending_total = 0
                        pending_data = 0
                        pending_control = 0
                        for peer_norm in sorted(pending_snapshot.keys()):
                            grouped_pending: Dict[str, Dict[str, object]] = {}
                            for rec in pending_snapshot.get(peer_norm, []):
                                pending_total += 1
                                frame_type = str(rec.get("relay_frame_type") or ("data" if bool(rec.get("relay_v3", False)) else "legacy"))
                                if frame_type == "data":
                                    pending_data += 1
                                else:
                                    pending_control += 1
                                group_id = str(rec.get("group") or rec.get("id") or rec.get("relay_msg_hex") or "-")
                                agg = grouped_pending.setdefault(
                                    group_id,
                                    {
                                        "frame_type": frame_type,
                                        "total": 1,
                                        "parts_pending": set(),
                                        "attempts": 0,
                                        "created": 0.0,
                                        "next_retry_at": 0.0,
                                        "route_id": "",
                                        "route_reason": "",
                                        "text_bytes": 0,
                                    },
                                )
                                try:
                                    total_now = int(rec.get("total", 1) or 1)
                                except Exception:
                                    total_now = 1
                                agg["total"] = max(int(agg.get("total", 1) or 1), max(1, total_now))
                                try:
                                    part_now = int(rec.get("part", 0) or 0)
                                except Exception:
                                    part_now = 0
                                if part_now > 0:
                                    try:
                                        agg["parts_pending"].add(part_now)  # type: ignore[attr-defined]
                                    except Exception:
                                        pass
                                try:
                                    agg["attempts"] = max(int(agg.get("attempts", 0) or 0), int(rec.get("attempts", 0) or 0))
                                except Exception:
                                    pass
                                try:
                                    created_now = float(rec.get("created", 0.0) or 0.0)
                                except Exception:
                                    created_now = 0.0
                                if created_now > 0.0:
                                    created_prev = float(agg.get("created", 0.0) or 0.0)
                                    if created_prev <= 0.0 or created_now < created_prev:
                                        agg["created"] = created_now
                                try:
                                    next_retry_now = float(rec.get("next_retry_at", 0.0) or 0.0)
                                except Exception:
                                    next_retry_now = 0.0
                                if next_retry_now > 0.0:
                                    next_retry_prev = float(agg.get("next_retry_at", 0.0) or 0.0)
                                    if next_retry_prev <= 0.0 or next_retry_now < next_retry_prev:
                                        agg["next_retry_at"] = next_retry_now
                                route_id_now = str(rec.get("route_id", "") or "")
                                if route_id_now and not agg.get("route_id"):
                                    agg["route_id"] = route_id_now
                                route_reason_now = str(rec.get("route_reason", "") or "")
                                if route_reason_now and not agg.get("route_reason"):
                                    agg["route_reason"] = route_reason_now
                                try:
                                    text_bytes_now = int(rec.get("text_bytes", 0) or 0)
                                except Exception:
                                    text_bytes_now = 0
                                if text_bytes_now <= 0:
                                    try:
                                        text_bytes_now = len(str(rec.get("text", "") or "").encode("utf-8"))
                                    except Exception:
                                        text_bytes_now = 0
                                agg["text_bytes"] = max(int(agg.get("text_bytes", 0) or 0), max(0, text_bytes_now))
                            for group_id, agg in grouped_pending.items():
                                total = max(1, int(agg.get("total", 1) or 1))
                                try:
                                    pending_parts = len(agg.get("parts_pending") or set())
                                except Exception:
                                    pending_parts = total
                                pending_parts = max(0, min(total, pending_parts))
                                sent_parts = max(0, total - pending_parts)
                                total_bytes = max(0, int(agg.get("text_bytes", 0) or 0))
                                if total_bytes > 0:
                                    sent_bytes = int(round(float(total_bytes) * (float(sent_parts) / float(max(1, total)))))
                                    sent_bytes = max(0, min(total_bytes, sent_bytes))
                                    left_bytes = max(0, total_bytes - sent_bytes)
                                    pct_done = (100.0 * float(sent_bytes) / float(max(1, total_bytes)))
                                else:
                                    sent_bytes = 0
                                    left_bytes = 0
                                    pct_done = (100.0 * float(sent_parts) / float(max(1, total)))
                                created_ts = float(agg.get("created", 0.0) or 0.0)
                                age_s = max(0.0, now_q - created_ts) if created_ts > 0.0 else 0.0
                                next_retry_at = float(agg.get("next_retry_at", 0.0) or 0.0)
                                next_in_s = max(0.0, next_retry_at - now_q) if next_retry_at > 0.0 else 0.0
                                route_row = _best_route_row_for_peer(peer_norm)
                                via_label = ""
                                if route_row is not None:
                                    via_label = str(getattr(route_row, "via_peer", "") or "").strip()
                                route_id_text = str(agg.get("route_id", "") or "").strip()
                                route_reason_text = str(agg.get("route_reason", "") or "").strip()
                                if via_label:
                                    route_text = f"via {via_label}"
                                elif route_id_text:
                                    route_text = route_id_text
                                else:
                                    route_text = "direct"
                                if route_reason_text:
                                    route_text += f" ({route_reason_text})"
                                buffer_rows.append([
                                    str(self_id or "?"),
                                    str(peer_norm or "-"),
                                    f"{str(agg.get('frame_type', 'legacy') or 'legacy')} {route_text}",
                                    str(group_id)[:16],
                                    f"{sent_parts}/{total} {pct_done:.0f}%",
                                    f"{int(agg.get('attempts', 0) or 0)} | {sent_bytes}/{total_bytes}B",
                                    f"{format_duration_mmss(next_in_s)} | left {left_bytes}B",
                                    format_duration_mmss(age_s),
                                ])
                        _routing_fill_table(routing_buffer_table, buffer_rows)

                        counters = getattr(routing_ctl, "counters", {}) or {}
                        routing_summary_label.setText(tr("routing_monitor_hint"))
                        routing_status_transport.setText(
                            ("online" if bool(radio_ready) else "offline")
                            + f" | tracked={len(tracked_peers)}"
                        )
                        relay_fanout = 0
                        try:
                            for _peer in sorted(set(tracked_peers) | set(peer_states.keys())):
                                if not _peer or _peer == self_id:
                                    continue
                                _st_adv = get_peer_state(_peer)
                                if _st_adv and bool(getattr(_st_adv, "key_ready", False)):
                                    relay_fanout += 1
                        except Exception:
                            relay_fanout = 0
                        routing_status_role.setText(
                            f"relay active | fanout={int(relay_fanout)} | routes={len(route_rows)}"
                        )
                        try:
                            avg_rtt_local = avg_rtt()
                        except Exception:
                            avg_rtt_local = 0.0
                        routing_status_metrics.setText(
                            f"pending={pending_total} data={pending_data} ctrl={pending_control} "
                            f"transit_rx={len(relay_rx)} avg_rtt={float(avg_rtt_local):.1f}s "
                            f"switch={int(counters.get('route_switch_total', 0.0) or 0.0)} "
                            f"failover={int(counters.get('route_failover_total', 0.0) or 0.0)} "
                            f"ctrl_drop={int(counters.get('control_dropped_total', 0.0) or 0.0)}"
                        )
                        routing_status_policy.setText(
                            "peer_round_robin | "
                            f"parallel={int(getattr(args, 'parallel_sends', 2) or 2)} | "
                            f"retry={int(getattr(args, 'retry_seconds', 10) or 10)}s | "
                            f"rate={int(getattr(args, 'rate_seconds', 5) or 5)}s | "
                            f"group_fair=on"
                        )
                        cfg_rt = getattr(routing_ctl, "cfg", None)
                        if cfg_rt is not None:
                            routing_status_weights.setText(
                                f"del={float(cfg_rt.w_delivery):.2f} tmo={float(cfg_rt.w_timeout):.2f} "
                                f"rtt={float(cfg_rt.w_rtt):.2f} hops={float(cfg_rt.w_hops):.2f} "
                                f"cong={float(cfg_rt.w_congestion):.2f} "
                                f"hyst={float(cfg_rt.hysteresis_abs):.2f}/{float(cfg_rt.hysteresis_rel):.2f} "
                                f"sticky={float(cfg_rt.sticky_hold_s):.0f}s"
                            )
                        else:
                            routing_status_weights.setText("-")
                    except Exception as ex:
                        try:
                            err_txt = f"{type(ex).__name__}: {ex}"
                        except Exception:
                            err_txt = "unknown"
                        try:
                            routing_summary_label.setText(f"{tr('routing_monitor_hint')} | refresh error: {err_txt}")
                        except Exception:
                            pass
                        try:
                            routing_status_transport.setText(f"error | {err_txt}")
                        except Exception:
                            pass
                        try:
                            ui_emit("log", f"{ts_local()} ROUTING_MONITOR: refresh failed {err_txt}")
                        except Exception:
                            pass

                try:
                    try:
                        routing_status_transport.setText("timer init...")
                    except Exception:
                        pass
                    routing_timer_parent = routing_ui.get("tab") or settings_panel_widget
                    routing_timer = QtCore.QTimer(routing_timer_parent)
                    routing_timer.setInterval(1000)
                    routing_timer.timeout.connect(refresh_routing_monitor)
                    routing_timer.start()
                    try:
                        settings_panel_widget._routing_timer = routing_timer
                    except Exception:
                        pass
                    try:
                        routing_timer_parent._routing_timer = routing_timer
                    except Exception:
                        pass
                    try:
                        QtCore.QTimer.singleShot(0, refresh_routing_monitor)
                    except Exception:
                        pass
                    try:
                        routing_status_transport.setText("timer started")
                    except Exception:
                        pass
                except Exception as e:
                    try:
                        err_txt = f"{type(e).__name__}: {e}"
                    except Exception:
                        err_txt = "unknown"
                    try:
                        routing_status_transport.setText(f"timer error | {err_txt}")
                    except Exception:
                        pass
                    try:
                        ui_emit("log", f"{ts_local()} ROUTING_MONITOR: timer failed {err_txt}")
                    except Exception:
                        pass

                log_ui = build_log_tab(
                    tabs=tabs,
                    tr=tr,
                    verbose_log=bool(verbose_log),
                    packet_trace_log=bool(packet_trace_log),
                    runtime_log_file=bool(runtime_log_file),
                    log_buffer=log_buffer,
                    append_log_to_view=log_append_view,
                    set_mono=set_mono,
                    no_ctrl_zoom=_no_ctrl_zoom,
                    QtWidgets=QtWidgets,
                )
                cb_verbose = log_ui["cb_verbose"]
                cb_pkt_trace = log_ui["cb_pkt_trace"]
                cb_runtime_log = log_ui["cb_runtime_log"]
                log_view = log_ui["log_view"]
                btn_ack = log_ui["btn_ack"]
                btn_clear = log_ui["btn_clear"]
                btn_copy = log_ui["btn_copy"]
                nonlocal settings_log_view
                settings_log_view = log_view

                # -------------------
                # About tab
                # -------------------
                tab_about = QtWidgets.QWidget()
                tabs.addTab(tab_about, tr("tab_about"))
                about_l = QtWidgets.QVBoxLayout(tab_about)
                about_l.setContentsMargins(14, 12, 14, 10)
                about_l.setSpacing(10)

                author_label = QtWidgets.QLabel(
                    f"meshTalk v{VERSION}\n\n"
                    f"{tr('about_summary')}"
                )
                set_mono(author_label, 10)
                author_label.setObjectName("muted")
                author_label.setWordWrap(True)
                about_l.addWidget(author_label)
                about_l.addStretch(1)

                # No bottom buttons: settings apply immediately; exit via the header gear.

                def apply_settings(close_dialog: bool) -> None:
                    nonlocal verbose_log, packet_trace_log, runtime_log_file, auto_pacing, discovery_send, discovery_reply, clear_pending_on_switch
                    nonlocal contacts_visibility
                    nonlocal security_policy, session_rekey_enabled
                    nonlocal max_plain, current_lang, last_limits_logged, current_theme
                    nonlocal data_portnum, data_port_label
                    def _safe_is_checked(cb, default: bool = False) -> bool:
                        try:
                            return bool(cb.isChecked())
                        except Exception:
                            return bool(default)

                    # Defensive: the settings panel can be closed/recreated (language switch, in-place embed),
                    # and Qt may delete widgets before callbacks return.
                    try:
                        if settings_panel_widget is None:
                            return
                    except Exception:
                        pass

                    verbose_log = _safe_is_checked(cb_verbose, verbose_log)
                    packet_trace_log = _safe_is_checked(cb_pkt_trace, packet_trace_log)
                    cfg["log_packet_trace"] = bool(packet_trace_log)
                    runtime_log_file = _safe_is_checked(cb_runtime_log, runtime_log_file)
                    auto_pacing = False
                    _STORAGE.set_runtime_log_enabled(runtime_log_file)
                    prev_send = discovery_send
                    discovery_send = _safe_is_checked(cb_discovery_send, discovery_send)
                    discovery_reply = _safe_is_checked(cb_discovery_reply, discovery_reply)
                    clear_pending_on_switch = _safe_is_checked(cb_clear_pending, clear_pending_on_switch)

                    prev_lang = current_lang
                    next_lang = "ru" if _safe_is_checked(rb_ru, default=(current_lang == "ru")) else "en"
                    cfg["lang"] = next_lang
                    if prev_lang != next_lang:
                        set_language(next_lang, persist=False)
                    else:
                        current_lang = next_lang

                    # Port is auto-detected.
                    cfg["port"] = "auto"
                    cfg["activity_timing_mode"] = "manual"
                    activity_runtime = build_activity_runtime_settings(
                        retry_text=activity_retry_edit.text(),
                        max_days_text=activity_maxdays_edit.text(),
                        max_bytes_text=maxbytes_edit.text(),
                        batch_count_text=activity_batch_count_edit.text(),
                        intra_gap_text=activity_batch_intra_pause_edit.text(),
                        backoff_cap_text=activity_backoff_cap_edit.text(),
                        jitter_text=activity_jitter_edit.text(),
                        show_advanced=bool(_safe_is_checked(cb_activity_advanced, bool(cfg.get("activity_show_advanced", False)))),
                        parallel_default=int(cfg.get("parallel_sends", 1) or 1),
                        intra_gap_default=int(cfg.get("activity_intra_batch_gap_ms", 0) or 0),
                        backoff_default=int(cfg.get("activity_retry_backoff_max_seconds", RETRY_BACKOFF_MAX_SECONDS) or RETRY_BACKOFF_MAX_SECONDS),
                        jitter_ratio_default=float(cfg.get("activity_retry_jitter_ratio", RETRY_JITTER_RATIO) or RETRY_JITTER_RATIO),
                    )
                    cfg.update(activity_runtime)
                    unified_interval_s = int(cfg["retry_seconds"])
                    selected_port_value = cfg.get("mesh_packet_portnum", data_port_label)
                    if data_port_combo is not None:
                        try:
                            selected_port_value = data_port_combo.currentData()
                        except Exception:
                            selected_port_value = cfg.get("mesh_packet_portnum", data_port_label)
                    cfg["mesh_packet_portnum"] = normalize_mesh_packet_port_value(selected_port_value)
                    data_portnum, data_port_label = resolve_mesh_packet_port(cfg.get("mesh_packet_portnum"))
                    cfg["discovery_hello_burst_count"] = 1
                    cfg["discovery_hello_packet_count"] = 1
                    cfg["discovery_hello_gap_seconds"] = 1
                    cfg["discovery_hello_packet_gap_seconds"] = 1
                    cfg["discovery_hello_interval_seconds"] = 30
                    cfg["discovery_hello_runtime_seconds"] = 0
                    cfg["discovery_hello_autostart"] = True
                    cfg["auto_pacing"] = False
                    cfg["activity_profile"] = "manual"
                    cfg["activity_aggressiveness"] = 0
                    cfg["activity_controller_model"] = ACTIVITY_CONTROLLER_DEFAULT
                    cfg["activity_retry_backoff_max_seconds"] = float(
                        cfg.get("activity_retry_backoff_max_seconds", RETRY_BACKOFF_MAX_SECONDS) or RETRY_BACKOFF_MAX_SECONDS
                    )
                    cfg["activity_retry_jitter_ratio"] = float(
                        cfg.get("activity_retry_jitter_ratio", RETRY_JITTER_RATIO) or RETRY_JITTER_RATIO
                    )
                    cfg["activity_fast_retries"] = float(cfg.get("activity_fast_retries", 0) or 0)
                    cfg["activity_fast_budget_per_second"] = float(cfg.get("activity_fast_budget_per_second", 0) or 0)
                    # Model-specific knobs (advanced, hidden from UI for now).
                    cfg["activity_ledbat_target_delay_seconds"] = float(cfg.get("activity_ledbat_target_delay_seconds", 2.0) or 2.0)
                    cfg["activity_ledbat_gain"] = float(cfg.get("activity_ledbat_gain", 0.7) or 0.7)
                    cfg["activity_quic_max_ack_delay_seconds"] = float(cfg.get("activity_quic_max_ack_delay_seconds", 1.0) or 1.0)
                    cfg["activity_quic_timer_granularity_seconds"] = float(
                        cfg.get("activity_quic_timer_granularity_seconds", 0.01) or 0.01
                    )
                    ensure_routing_defaults(cfg)
                    routing_ctl.update_config(cfg)
                    # Backward-compat keys (older builds may read them).
                    cfg["activity_muted_interval_seconds"] = int(cfg.get("activity_probe_interval_max_seconds", MSG_RETRY_MUTED_INTERVAL_SECONDS))
                    cfg["activity_probe_window_seconds"] = int(cfg.get("activity_probe_window_max_seconds", MSG_RETRY_PROBE_WINDOW_SECONDS))
                    cfg["discovery_enabled"] = bool(discovery_send and discovery_reply)
                    cfg["discovery_send"] = discovery_send
                    cfg["discovery_reply"] = discovery_reply
                    cfg["runtime_log_file"] = runtime_log_file
                    cfg["clear_pending_on_switch"] = clear_pending_on_switch
                    contacts_visibility = normalize_contacts_visibility(contacts_visibility_combo.currentData(), default="all")
                    cfg["contacts_visibility"] = contacts_visibility

                    # Graphs tab: time window selection (single combined graph).
                    try:
                        cfg["graphs_window_seconds"] = int(cfg.get("graphs_window_seconds", METRICS_GRAPH_WINDOW_SECONDS) or METRICS_GRAPH_WINDOW_SECONDS)
                    except Exception:
                        cfg["graphs_window_seconds"] = int(METRICS_GRAPH_WINDOW_SECONDS)
                    # (dataset toggles removed)

                    # Theme settings
                    next_theme = str(theme_combo.currentData() or "ubuntu_style").strip().lower()
                    if next_theme not in THEME_STYLES:
                        next_theme = "ubuntu_style"
                    cfg["ui_theme"] = next_theme
                    if next_theme != current_theme:
                        apply_theme(next_theme)
                        # Re-render dynamic widgets that use inline styles (bubbles/contact cards).
                        try:
                            refresh_list()
                        except Exception:
                            pass
                        try:
                            render_chat(current_dialog)
                        except Exception:
                            pass

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
                    session_rekey_enabled = _safe_is_checked(cb_rekey, session_rekey_enabled)
                    cfg["session_rekey"] = bool(session_rekey_enabled)
                    try:
                        args.auto_pacing = False
                    except Exception:
                        pass

                    setattr(args, "_prev_auto_pacing", False)

                    # Confirm runtime application of limits in the log.
                    try:
                        limits_now = (
                            int(getattr(args, "max_bytes", 200) or 200),
                            int(max_plain),
                            int(getattr(args, "retry_seconds", 10) or 10),
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
                        start_hello_mode(reason="settings_enable", immediate=True)
                        ui_emit("log", f"{ts_local()} HELLO: enabled")
                    elif (not discovery_send) and prev_send:
                        stop_hello_mode(reason="settings_disable")
                    refresh_hello_button()

                    if close_dialog:
                        dlg.accept()
                        return
                    if prev_lang != next_lang:
                        reopen["flag"] = True
                        dlg.accept()
                        return

                def on_accept():
                    apply_settings(close_dialog=False)
                    try:
                        if callable(settings_close_fn):
                            settings_close_fn()
                        else:
                            dlg.accept()
                    except Exception:
                        try:
                            dlg.accept()
                        except Exception:
                            pass

                def on_apply():
                    apply_settings(close_dialog=False)

                _auto_apply_pending = {"v": False}

                def _run_auto_apply() -> None:
                    _auto_apply_pending["v"] = False
                    on_apply()

                def _schedule_auto_apply(*_args) -> None:
                    if _auto_apply_pending["v"]:
                        return
                    _auto_apply_pending["v"] = True
                    QtCore.QTimer.singleShot(0, _run_auto_apply)

                def on_copy():
                    try:
                        text = log_view.toPlainText().strip()
                        if not text:
                            text = "\n".join(t for t, _lvl in log_buffer)
                        cb = QtWidgets.QApplication.clipboard()
                        if cb is None:
                            return
                        try:
                            cb.setText(text, QtGui.QClipboard.Mode.Clipboard)
                        except Exception:
                            pass
                        # X11 selection clipboard is not supported on Windows and some Qt builds; avoid warnings.
                        if not sys.platform.startswith("win"):
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

                def on_full_reset_profile():
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
                    auto_pacing = False
                    discovery_send = True
                    discovery_reply = True
                    cfg["discovery_hello_runtime_seconds"] = 0
                    cfg["discovery_hello_autostart"] = True
                    cfg["discovery_hello_packet_count"] = 1
                    cfg["discovery_hello_gap_seconds"] = 1
                    cfg["discovery_hello_packet_gap_seconds"] = 1
                    clear_pending_on_switch = True
                    contacts_visibility = "all"
                    _STORAGE.set_runtime_log_enabled(runtime_log_file)
                    try:
                        args.retry_seconds = 10
                        args.max_seconds = 3600
                        args.max_bytes = 200
                        args.rate_seconds = 5
                        args.parallel_sends = 2
                        args.auto_pacing = False
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
                            start_hello_mode(reason="reset", immediate=True)
                            send_discovery_broadcast()
                            log_line(f"{ts_local()} HELLO: enabled (after reset)", "info")
                        except Exception:
                            pass
                    log_line(f"{ts_local()} RESET: full profile reset completed", "warn")
                    QtWidgets.QMessageBox.information(win, "meshTalk", tr("full_reset_done"))
                    dlg.accept()

                def on_full_reset_all():
                    nonlocal current_lang, verbose_log, runtime_log_file
                    nonlocal discovery_send, discovery_reply, clear_pending_on_switch
                    if not self_id:
                        QtWidgets.QMessageBox.information(win, "meshTalk", tr("full_reset_unavailable"))
                        return
                    reply = QtWidgets.QMessageBox.warning(
                        win,
                        "meshTalk",
                        tr("full_reset_all_confirm"),
                        QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                        QtWidgets.QMessageBox.No,
                    )
                    if reply != QtWidgets.QMessageBox.Yes:
                        return
                    import shutil

                    # Clear runtime state first.
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

                    # Delete all persisted node profiles under BASE_DIR.
                    try:
                        for name in os.listdir(BASE_DIR):
                            p = os.path.join(BASE_DIR, name)
                            if os.path.isdir(p) and re.fullmatch(r"[0-9a-fA-F]{8}", name):
                                shutil.rmtree(p, ignore_errors=True)
                    except Exception:
                        pass
                    # Delete legacy shared dir (if any).
                    try:
                        legacy_dir = os.path.join(BASE_DIR, LEGACY_BASE_DIR)
                        if os.path.isdir(legacy_dir):
                            shutil.rmtree(legacy_dir, ignore_errors=True)
                    except Exception:
                        pass
                    # Delete root-level legacy files as well.
                    for name in ("config.json", "state.json", "history.log", "incoming.json", "runtime.log"):
                        try:
                            p = os.path.join(BASE_DIR, name)
                            if os.path.isfile(p):
                                os.remove(p)
                        except Exception:
                            pass
                    try:
                        root_keydir = os.path.join(BASE_DIR, "keyRings")
                        if os.path.isdir(root_keydir):
                            shutil.rmtree(root_keydir, ignore_errors=True)
                    except Exception:
                        pass

                    # Recreate current node profile and defaults.
                    set_data_dir_for_node(self_id)
                    ensure_storage_key()
                    current_lang = "ru"
                    verbose_log = True
                    runtime_log_file = True
                    auto_pacing = False
                    discovery_send = True
                    discovery_reply = True
                    cfg["discovery_hello_runtime_seconds"] = 0
                    cfg["discovery_hello_autostart"] = True
                    cfg["discovery_hello_packet_count"] = 1
                    cfg["discovery_hello_gap_seconds"] = 1
                    cfg["discovery_hello_packet_gap_seconds"] = 1
                    clear_pending_on_switch = True
                    contacts_visibility = "all"
                    _STORAGE.set_runtime_log_enabled(runtime_log_file)
                    try:
                        args.retry_seconds = 10
                        args.max_seconds = 3600
                        args.max_bytes = 200
                        args.rate_seconds = 5
                        args.parallel_sends = 2
                        args.auto_pacing = False
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
                    try:
                        start_hello_mode(reason="reset_all", immediate=True)
                        send_discovery_broadcast()
                    except Exception:
                        pass
                    log_line(f"{ts_local()} RESET: all profiles/settings reset completed", "warn")
                    QtWidgets.QMessageBox.information(win, "meshTalk", tr("full_reset_all_done"))
                    dlg.accept()

                btn_ack.clicked.connect(on_ack_alerts)
                btn_copy.clicked.connect(on_copy)
                btn_clear.clicked.connect(on_clear)
                btn_full_reset_profile.clicked.connect(on_full_reset_profile)
                btn_full_reset_all.clicked.connect(on_full_reset_all)

                # Apply settings immediately after user input.
                for _w in (
                    rb_ru,
                    rb_en,
                    cb_verbose,
                    cb_pkt_trace,
                    cb_runtime_log,
                    cb_discovery_send,
                    cb_discovery_reply,
                    cb_clear_pending,
                    activity_retry_edit,
                    activity_maxdays_edit,
                    activity_backoff_cap_edit,
                    activity_jitter_edit,
                    activity_batch_count_edit,
                    activity_batch_intra_pause_edit,
                    maxbytes_edit,
                    data_port_combo,
                    contacts_visibility_combo,
                    sec_policy,
                    cb_rekey,
                    cmp_choice,
                    cmp_norm,
                    theme_combo,
                    cb_activity_advanced,
                ):
                    try:
                        if isinstance(_w, QtWidgets.QLineEdit):
                            _w.editingFinished.connect(_schedule_auto_apply)
                        elif isinstance(_w, QtWidgets.QComboBox):
                            _w.currentIndexChanged.connect(_schedule_auto_apply)
                        elif isinstance(_w, QtWidgets.QCheckBox):
                            _w.toggled.connect(_schedule_auto_apply)
                        elif isinstance(_w, QtWidgets.QRadioButton):
                            _w.toggled.connect(_schedule_auto_apply)
                    except Exception:
                        pass

                def _close_inplace_settings(*_args):
                    nonlocal settings_panel_widget
                    nonlocal settings_close_fn
                    nonlocal settings_log_view, settings_auto_pacing_cb
                    nonlocal settings_data_port_combo
                    nonlocal settings_status_line
                    nonlocal settings_activity_rate_lbl, settings_activity_parallel_lbl, settings_activity_pps_lbl
                    nonlocal settings_activity_retry_lbl, settings_activity_max_lbl
                    nonlocal settings_activity_active_lbl, settings_activity_probe_min_lbl, settings_activity_probe_max_lbl
                    nonlocal settings_activity_probe_win_lbl, settings_activity_grace_lbl, settings_activity_backoff_lbl
                    nonlocal settings_activity_jitter_lbl
                    nonlocal settings_activity_fast_retries_lbl, settings_activity_fast_delay_lbl, settings_activity_fast_budget_lbl
                    settings_log_view = None
                    settings_data_port_combo = None
                    settings_auto_pacing_cb = None
                    settings_status_line = None
                    settings_activity_rate_lbl = None
                    settings_activity_parallel_lbl = None
                    settings_activity_pps_lbl = None
                    settings_activity_retry_lbl = None
                    settings_activity_max_lbl = None
                    settings_activity_active_lbl = None
                    settings_activity_probe_min_lbl = None
                    settings_activity_probe_max_lbl = None
                    settings_activity_probe_win_lbl = None
                    settings_activity_grace_lbl = None
                    settings_activity_backoff_lbl = None
                    settings_activity_jitter_lbl = None
                    settings_activity_fast_retries_lbl = None
                    settings_activity_fast_delay_lbl = None
                    settings_activity_fast_budget_lbl = None
                    try:
                        right_col.removeWidget(dlg)
                    except Exception:
                        pass
                    try:
                        dlg.hide()
                        dlg.deleteLater()
                    except Exception:
                        pass
                    try:
                        _purge_stale_settings_panels()
                    except Exception:
                        pass
                    settings_panel_widget = None
                    settings_close_fn = None
                    try:
                        list_group.show()
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
                settings_close_fn = _close_inplace_settings
                try:
                    list_group.hide()
                    root_layout.setStretch(0, 0)
                    root_layout.setStretch(1, 1)
                    chat_text.hide()
                    msg_entry.hide()
                    send_btn.hide()
                except Exception:
                    pass
                right_col.insertWidget(2, dlg, 1)
                dlg.show()
                update_status()
                return

        settings_btn.clicked.connect(open_settings)

        def _toggle_hello_mode() -> None:
            if hello_mode_active:
                stop_hello_mode(reason="manual_button")
            else:
                start_hello_mode(reason="manual_button", immediate=True)
            refresh_hello_button()
        hello_btn.clicked.connect(_toggle_hello_mode)
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

        def _hex_rgb(hx: str) -> Tuple[int, int, int]:
            h = str(hx or "").strip().lstrip("#")
            if len(h) != 6:
                return (0, 0, 0)
            return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))

        def _rgba_css(hx: str, alpha: float) -> str:
            r, g, b = _hex_rgb(hx)
            a = max(0.0, min(1.0, float(alpha)))
            return f"rgba({r},{g},{b},{a:.3f})"

        THEME_BASE = {
            # Two main backgrounds: contacts field and chat/bubbles field.
            "ubuntu_style": {
                "contacts_bg": "#2b0a22",
                "chat_bg": "#35102a",
                "contact_alpha": 0.92,
                "bubble_alpha": 0.92,
                "bubble_border": "rgba(255,255,255,0.10)",
            },
            "brutal_man": {
                "contacts_bg": "#15181b",
                "chat_bg": "#101214",
                "contact_alpha": 0.94,
                "bubble_alpha": 0.94,
                "bubble_border": "rgba(255,255,255,0.10)",
            },
            "pretty_girl": {
                # Pantone 2026 Cloud Dancer approximation as base; chat is slightly cooler.
                "contacts_bg": "#f7f5f0",
                "chat_bg": "#f3f0f4",
                "contact_alpha": 0.96,
                "bubble_alpha": 0.96,
                "bubble_border": "rgba(0,0,0,0.12)",
            },
            "spinach": {
                "contacts_bg": "#e6f0df",
                "chat_bg": "#eef6ea",
                "contact_alpha": 0.96,
                "bubble_alpha": 0.96,
                "bubble_border": "rgba(36,66,44,0.12)",
            },
            "froggy": {
                "contacts_bg": "#18271f",
                "chat_bg": "#1d2e24",
                "contact_alpha": 0.94,
                "bubble_alpha": 0.94,
                "bubble_border": "rgba(159,213,141,0.12)",
            },
            "dark_froggy": {
                "contacts_bg": "#18271f",
                "chat_bg": "#1d2e24",
                "contact_alpha": 0.94,
                "bubble_alpha": 0.94,
                "bubble_border": "rgba(159,213,141,0.12)",
            },
        }

        def _theme_base(theme_id: str) -> Dict[str, object]:
            tid = str(theme_id or "ubuntu_style").strip().lower()
            base = THEME_BASE.get(tid) or THEME_BASE["ubuntu_style"]
            return dict(base)

        def color_pair_for_id(seed: str) -> Tuple[str, str]:
            base_bg = str(_theme_base(current_theme).get("contacts_bg") or "#35102a")
            accent = avatar_base_color(seed)
            # Contact list cards: deliberately muted tint.
            bg_hex = mix_hex(base_bg, accent, 0.05)
            # Text color must keep contrast; base differs between light/dark themes.
            base_tx = "#21312a" if str(current_theme or "") in ("pretty_girl", "spinach") else "#e8e0e8"
            tx_hex = mix_hex(base_tx, accent, 0.16)
            return (bg_hex, tx_hex)

        def color_pair_for_message(seed: str) -> Tuple[str, str]:
            base_bg = str(_theme_base(current_theme).get("chat_bg") or "#35102a")
            accent = avatar_base_color(seed)
            bg_hex = mix_hex(base_bg, accent, 0.12)
            base_tx = "#21312a" if str(current_theme or "") in ("pretty_girl", "spinach") else "#eeeeec"
            tx_hex = mix_hex(base_tx, accent, 0.35)
            return (bg_hex, tx_hex)

        avatar_cache: Dict[Tuple[str, int, str], str] = {}

        def avatar_data_uri(seed: str, size: int) -> str:
            try:
                is_light = str(current_theme or "").strip().lower() in ("pretty_girl", "spinach")
            except Exception:
                is_light = False
            theme_kind = "light" if is_light else "dark"
            key = (seed, size, theme_kind)
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

        def append_html(view, text: str, color: str) -> None:
            """
            Append a colored log line to either:
            - QListWidget (main GUI log/chat list rendering), or
            - QTextEdit (Settings -> Log preview window).
            """

            def _esc(s: str) -> str:
                return (
                    str(s)
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace('"', "&quot;")
                    .replace("'", "&#39;")
                )

            if isinstance(view, QtWidgets.QTextEdit):
                try:
                    cursor = view.textCursor()
                    cursor.movePosition(QtGui.QTextCursor.End)
                    cursor.insertHtml(f"<span style='color:{_esc(color)}'>{_esc(text)}</span><br/>")
                    view.setTextCursor(cursor)
                    view.ensureCursorVisible()
                except Exception:
                    try:
                        view.append(str(text))
                    except Exception:
                        pass
                return

            # Default: QListWidget-like.
            row_wrap = QtWidgets.QWidget()
            row_wrap.setStyleSheet("background: transparent; border: none;")
            row_l = QtWidgets.QHBoxLayout(row_wrap)
            row_l.setContentsMargins(4, 1, 4, 1)
            row_l.setSpacing(0)
            lbl = QtWidgets.QLabel(str(text))
            lbl.setWordWrap(True)
            lbl.setStyleSheet(f"color:{color};")
            row_l.addWidget(lbl, 1)
            try:
                row_wrap.setMinimumWidth(max(100, int(view.viewport().width()) - 4))
            except Exception:
                pass
            item = QtWidgets.QListWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)
            item.setData(QtCore.Qt.UserRole, -1)
            try:
                item.setSizeHint(QtCore.QSize(max(100, int(view.viewport().width()) - 4), row_wrap.sizeHint().height()))
            except Exception:
                pass
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
            auto_scroll: bool = True,
        ) -> None:
            del actions  # Action buttons are handled in header/context flow.
            bg, tx = color_pair_for_message(peer_id)
            ts, msg = split_chat_timestamp(text)
            if meta:
                meta_l = meta.lower().strip()
                if (
                    meta_l.startswith("отправлена в ")
                    or meta_l.startswith("отправлено в ")
                    or meta_l.startswith("доставлено в ")
                    or meta_l.startswith("получено в ")
                    or meta_l.startswith("пришло ")
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
            base = _theme_base(current_theme)
            bubble_alpha = float(base.get("bubble_alpha", 0.92) or 0.92)
            bg_rgba = _rgba_css(bg, bubble_alpha)
            bubble.setStyleSheet(
                # No visible border: only background + rounded corners.
                f"QFrame#chatBubble {{ background-color:{bg_rgba}; border:none; border-radius:9px; }}"
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
            # Bubble max width: keep left/right "air" so long messages still look like bubbles.
            # Also prevents huge single-line bubbles from breaking scroll/relayout.
            vpw = max(200, int(view.viewport().width()))
            max_w = max(320, int(vpw * 0.90))
            max_w = min(max_w, max(320, int(vpw - 12)))
            try:
                fm_msg = msg_lbl.fontMetrics()
                msg_lines = [ln for ln in str(msg).splitlines() if ln] or [str(msg)]
                msg_px = max(fm_msg.horizontalAdvance(ln) for ln in msg_lines)
            except Exception:
                msg_px = int(len(msg) * 7)
            try:
                fm_meta = meta_lbl.fontMetrics()
                meta_px = int(fm_meta.horizontalAdvance(str(combined or "")))
            except Exception:
                meta_px = int(len(str(combined or "")) * 6)
            # +70 for avatar column and inner paddings.
            preferred = max(220, int(max(msg_px + 62, meta_px + 18)))
            preferred = min(max_w, preferred)
            bubble.setMinimumWidth(min(220, preferred))
            bubble.setMaximumWidth(preferred)
            bubble.setSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Preferred)
            # Force wrap width so Qt computes correct height and doesn't clip the tail.
            try:
                wrap_w = max(60, int(preferred) - 62)
                msg_lbl.setMaximumWidth(wrap_w)
            except Exception:
                pass
            try:
                meta_max = max(90, preferred - 18)
                meta_lbl.setMaximumWidth(meta_max)
                meta_lbl.setText(combined)
                meta_lbl.setToolTip(combined)
            except Exception:
                pass
            row_l.addWidget(bubble, 0)
            if not outgoing:
                row_l.addStretch(1)

            item = QtWidgets.QListWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable)
            item.setData(QtCore.Qt.UserRole, int(row_index))
            try:
                # QListWidgetItem sizeHint depends on the current width to compute word-wrap height.
                row_wrap.setFixedWidth(max(100, int(view.viewport().width()) - 2))
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
            if auto_scroll:
                # Auto-stick to bottom only if user is already near the bottom or this is outgoing.
                try:
                    sb = view.verticalScrollBar()
                    at_bottom = (sb is None) or (int(sb.value()) >= int(sb.maximum()) - 4)
                except Exception:
                    at_bottom = True
                if outgoing or at_bottom:
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
                                vpw = max(200, int(view.viewport().width()))
                                max_w = max(320, int(vpw * 0.90))
                                max_w = min(max_w, max(320, int(vpw - 12)))
                                bubble.setMaximumWidth(max_w)
                                meta_lbl = bubble.findChild(QtWidgets.QLabel, "chatMeta")
                                msg_lbl = bubble.findChild(QtWidgets.QLabel, "chatMessage")
                                if meta_lbl is not None:
                                    full_meta = str(meta_lbl.property("full_meta") or meta_lbl.toolTip() or meta_lbl.text() or "")
                                else:
                                    full_meta = ""
                                if msg_lbl is not None:
                                    try:
                                        fm_msg = msg_lbl.fontMetrics()
                                        msg_lines = [ln for ln in str(msg_lbl.text()).splitlines() if ln] or [str(msg_lbl.text())]
                                        msg_px = max(fm_msg.horizontalAdvance(ln) for ln in msg_lines)
                                    except Exception:
                                        msg_px = int(len(str(msg_lbl.text())) * 7)
                                    try:
                                        fm_meta = meta_lbl.fontMetrics() if meta_lbl is not None else None
                                        meta_px = int(fm_meta.horizontalAdvance(full_meta)) if fm_meta is not None else int(len(full_meta) * 6)
                                    except Exception:
                                        meta_px = int(len(full_meta) * 6)
                                    preferred = min(max_w, max(220, int(max(msg_px + 62, meta_px + 18))))
                                    bubble.setMaximumWidth(preferred)
                                    try:
                                        wrap_w = max(60, int(preferred) - 62)
                                        msg_lbl.setMaximumWidth(wrap_w)
                                    except Exception:
                                        pass
                                    if meta_lbl is not None:
                                        meta_max = max(90, preferred - 18)
                                        meta_lbl.setMaximumWidth(meta_max)
                                        meta_lbl.setText(full_meta)
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

        def _contact_status_prefix(status_code: Optional[str]) -> Optional[str]:
            code = str(status_code or "").strip().lower()
            if code.startswith("app_"):
                return "meshTalk"
            if code.startswith("mesh_"):
                return "Meshtastic"
            return None

        def _format_contact_second_line(
            long_name: str,
            short_name: str,
            *,
            status_code: Optional[str] = None,
        ) -> str:
            long_clean = str(long_name or "").strip()
            short_clean = str(short_name or "").strip()
            prefix = _contact_status_prefix(status_code)
            generic_tail = long_clean
            if long_clean:
                m = re.match(r"^(Meshtastic|meshTalk|Static)\s+(.*)$", long_clean, re.IGNORECASE)
                if m:
                    generic_tail = str(m.group(2) or "").strip()
                    long_clean = f"{prefix} {generic_tail}".strip() if prefix else long_clean
            elif prefix and short_clean:
                long_clean = prefix
            second = long_clean
            if short_clean:
                second = f"{second} [{short_clean}]" if second else f"[{short_clean}]"
            return second

        def dialog_title(dialog_id: str, *, status_code: Optional[str] = None) -> str:
            if dialog_id.startswith("group:"):
                return f"{dialog_id[6:]}"
            wire = norm_id_for_wire(dialog_id)
            long_name, short_name = _peer_name_parts(dialog_id)
            if long_name or short_name:
                second = _format_contact_second_line(long_name, short_name, status_code=status_code)
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
            prev_val = 0
            prev_max = 0
            had_items = False
            try:
                sb_prev = chat_text.verticalScrollBar()
                had_items = bool(chat_text.count() > 0)
                if sb_prev is not None:
                    prev_val = int(sb_prev.value())
                    prev_max = int(sb_prev.maximum())
            except Exception:
                prev_val = 0
                prev_max = 0
                had_items = False
            chat_text.clear()
            if not dialog_id:
                return
            follow_bottom = (not had_items) or (int(prev_val) >= int(prev_max) - 4)

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
                    if direction == "day":
                        append_html(chat_text, text, "#8a7f8b")
                        continue
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
                    append_chat_entry(
                        chat_text,
                        text,
                        peer_id,
                        direction == "out",
                        idx,
                        meta=meta,
                        actions=actions,
                        auto_scroll=False,
                    )
                else:
                    line = str(entry)
                    append_html(chat_text, line, "#66d9ef")
            relayout_chat_items(chat_text)
            try:
                sb_now = chat_text.verticalScrollBar()
                if sb_now is not None:
                    if follow_bottom:
                        sb_now.setValue(int(sb_now.maximum()))
                    else:
                        if prev_max > 0:
                            ratio = float(prev_val) / float(prev_max)
                            target = int(round(ratio * float(sb_now.maximum())))
                        else:
                            target = int(prev_val)
                        target = max(int(sb_now.minimum()), min(int(sb_now.maximum()), int(target)))
                        sb_now.setValue(int(target))
            except Exception:
                pass

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

        def _is_entry_cancelable(entry: Dict[str, object]) -> bool:
            if str(entry.get("dir", "")) != "out":
                return False
            meta_data = entry.get("meta_data")
            if not isinstance(meta_data, dict):
                return False
            if meta_data.get("delivered_at_ts") is not None:
                return False
            if meta_data.get("status") in ("timeout", "send_blocked", "decode_error", "canceled"):
                return False
            packets_raw = meta_data.get("packets")
            if isinstance(packets_raw, (tuple, list)) and len(packets_raw) >= 2:
                try:
                    done_now = int(packets_raw[0])
                    total_now = int(packets_raw[1])
                    return done_now < total_now
                except Exception:
                    pass
            try:
                return float(meta_data.get("sent_at_ts", 0.0) or 0.0) > 0.0
            except Exception:
                return True

        def _cancel_pending_message(dialog_id: str, entry: Dict[str, object]) -> bool:
            group_id = str(entry.get("msg_id", "") or "").strip()
            if not group_id:
                return False
            removed = 0
            attempts_max = 0
            total_max = 0
            with pending_lock:
                peer_items = list(pending_by_peer.items())
                for peer_norm, items in peer_items:
                    if not isinstance(items, dict):
                        continue
                    ids_to_drop: List[str] = []
                    for rec_id, rec in items.items():
                        if not isinstance(rec, dict):
                            continue
                        rec_group = str(rec.get("group", "") or "")
                        if rec_group == group_id or str(rec.get("id", "") or "") == group_id:
                            ids_to_drop.append(str(rec_id))
                            removed += 1
                            try:
                                attempts_max = max(attempts_max, int(rec.get("attempts", 0) or 0))
                            except Exception:
                                pass
                            try:
                                total_max = max(total_max, int(rec.get("total", 0) or 0))
                            except Exception:
                                pass
                    for rec_id in ids_to_drop:
                        try:
                            items.pop(rec_id, None)
                        except Exception:
                            pass
                    if not items:
                        pending_by_peer.pop(peer_norm, None)
                if removed > 0:
                    save_state(pending_by_peer)
            if removed <= 0:
                return False
            reason = "canceled"
            update_sent_failed(dialog_id, group_id, reason, max(1, attempts_max), max(1, total_max))
            log_line(f"{ts_local()} QUEUE: canceled group={group_id} parts={removed}", "warn")
            return True

        def _show_chat_default_menu(pos: "QtCore.QPoint") -> None:
            _ = pos

        def _prepare_popup_menu(menu: "QtWidgets.QMenu") -> "QtWidgets.QMenu":
            try:
                menu.setAttribute(QtCore.Qt.WA_StyledBackground, True)
            except Exception:
                pass
            try:
                menu.setAttribute(QtCore.Qt.WA_TranslucentBackground, False)
            except Exception:
                pass
            try:
                menu.setAutoFillBackground(True)
            except Exception:
                pass
            try:
                menu.setWindowOpacity(1.0)
            except Exception:
                pass
            return menu

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
            menu = _prepare_popup_menu(QtWidgets.QMenu(win))
            act_copy = menu.addAction(tr("msg_ctx_copy"))
            act_cancel = None
            if _is_entry_cancelable(entry):
                act_cancel = menu.addAction(tr("msg_ctx_cancel_send"))
            picked = menu.exec(chat_text.viewport().mapToGlobal(pos))
            if picked == act_copy:
                _copy_message_entry(entry)
            elif act_cancel is not None and picked == act_cancel:
                _cancel_pending_message(dialog_id, entry)

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
            def _dialog_sort_ts(dialog_id: str, rec: Dict[str, object]) -> float:
                try:
                    return float(rec.get("last_rx_ts", 0.0) or 0.0)
                except Exception:
                    return 0.0

            ordered = sorted(
                dialogs.items(),
                key=lambda kv: _dialog_sort_ts(str(kv[0]), dict(kv[1] if isinstance(kv[1], dict) else {})),
                reverse=True,
            )
            list_index.clear()
            filter_text = search_field.text().strip().lower()
            known = (set(known_peers.keys()) | set(peer_states.keys())) - set(hidden_contacts)
            known.discard(self_id)
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
                if item_id == self_id:
                    return
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
                try:
                    base = _theme_base(current_theme)
                    ca = float(base.get("contact_alpha", 0.92) or 0.92)
                    c = QtGui.QColor(bg_hex)
                    c.setAlphaF(max(0.0, min(1.0, ca)))
                    item.setBackground(c)
                except Exception:
                    item.setBackground(QtGui.QColor(bg_hex))
                item.setForeground(QtGui.QColor(tx_hex))
                item.setIcon(make_avatar(item_id))
                unread = int(dialogs.get(item_id, {}).get("unread", 0) or 0)
                status_code: Optional[str] = None
                status_color: Optional[str] = None
                app_recent = False
                app_seen_any = False  # any app activity ever recorded
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
                    # For Meshtastic-only peers (no PeerState yet), derive device presence from node DB cache
                    # (lastHeard) or persisted peer_meta.
                    if device_ts <= 0.0:
                        try:
                            meta = peer_meta.get(item_id, {})
                            if isinstance(meta, dict):
                                ds = meta.get("device_seen_ts")
                                if isinstance(ds, (int, float)) and float(ds) > 0.0:
                                    device_ts = float(ds)
                        except Exception:
                            pass
                    if device_ts <= 0.0:
                        try:
                            with peer_names_lock:
                                rec = peer_names.get(item_id) or peer_names.get(str(item_id).lower()) or {}
                            lh = rec.get("last_heard_ts") if isinstance(rec, dict) else None
                            if isinstance(lh, (int, float)) and float(lh) > 0.0:
                                device_ts = float(lh)
                                if st is not None and float(getattr(st, "device_seen_ts", 0.0) or 0.0) <= 0.0:
                                    st.device_seen_ts = float(lh)
                        except Exception:
                            pass
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
                    try:
                        keys_ok = peer_direct_meshtalk_ready(item_id, now_ts=now_ts)
                    except Exception:
                        keys_ok = False
                    # Smooth fade: when peer just stops talking (no explicit app-offline signal),
                    # gradually darken the square from online -> offline across the stale window.
                    def _fade_ratio(age_s: float) -> float:
                        # Log-style fade:
                        # - keep "online" color until 1 hour
                        # - at 1 hour: immediate dim to 1/3
                        # - then smoothly (moderately) fade to dark until CONTACT_STALE_SECONDS
                        try:
                            a = float(age_s)
                        except Exception:
                            a = 0.0
                        start_s = 3600.0  # 1 hour hard step
                        end_s = float(CONTACT_STALE_SECONDS)
                        if a <= start_s:
                            return 0.0
                        if a >= end_s:
                            return 1.0
                        span = max(1.0, end_s - start_s)
                        x = max(0.0, min(1.0, (a - start_s) / span))
                        # f in [0..1], logarithmic-ish easing.
                        k = 9.0
                        try:
                            f = math.log1p(k * x) / math.log1p(k)
                        except Exception:
                            f = x
                        return (1.0 / 3.0) + ((2.0 / 3.0) * max(0.0, min(1.0, f)))

                    explicit_offline = False
                    if st:
                        try:
                            offline_ts = float(getattr(st, "app_offline_ts", 0.0) or 0.0)
                            if offline_ts > 0.0 and float(seen_ts) <= offline_ts:
                                explicit_offline = True
                        except Exception:
                            explicit_offline = False

                    # Base palette for the small status square.
                    APP_ON = "#2bbf66"
                    APP_OFF = "#0e2d1a"
                    MESH_ON = "#d9b233"
                    MESH_OFF = "#2f2206"
                    # Contact indicator policy:
                    # - show green only for "fresh" meshTalk app activity (<= CONTACT_STALE_SECONDS) and valid keys
                    # - otherwise, fall back to Meshtastic device presence (yellow) if available
                    if app_seen_any and keys_ok and app_seen_fresh:
                        if app_recent:
                            status_code = "app_online"
                            status_color = APP_ON
                        else:
                            status_code = "app_offline"
                            if explicit_offline:
                                status_color = APP_OFF
                            else:
                                status_color = mix_hex(APP_ON, APP_OFF, _fade_ratio(float(now_ts - float(seen_ts or 0.0))))
                    else:
                        if device_recent:
                            status_code = "mesh_online"
                            status_color = MESH_ON
                        elif device_seen_fresh:
                            status_code = "mesh_offline"
                            status_color = mix_hex(MESH_ON, MESH_OFF, _fade_ratio(float(now_ts - float(device_ts or 0.0))))
                        else:
                            status_code = None
                            status_color = None
                    if visibility_mode == "online" and status_code not in ("app_online", "mesh_online"):
                        return
                    if visibility_mode == "app" and status_code not in ("app_online", "app_offline"):
                        return
                    if visibility_mode == "device" and status_code not in ("mesh_online", "mesh_offline"):
                        return
                    item.setText(dialog_title(item_id, status_code=status_code))
                item.setData(
                    QtCore.Qt.UserRole,
                    {
                        "id": item_id,
                        "pinned": item_id in pinned_dialogs,
                        "unread": unread,
                        "last_rx_ts": float(dialogs.get(item_id, {}).get("last_rx_ts", 0.0) or 0.0),
                        "status_code": status_code,
                        "status_color": status_color or "",
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

            def _peer_seen_ts(peer_id: str) -> float:
                st = peer_states.get(peer_id)
                vals: list[float] = []
                try:
                    vals.append(float(getattr(st, "last_seen_ts", 0.0) or 0.0))
                except Exception:
                    pass
                try:
                    vals.append(float(getattr(st, "device_seen_ts", 0.0) or 0.0))
                except Exception:
                    pass
                try:
                    m = peer_meta.get(peer_id, {})
                    if isinstance(m, dict):
                        vals.append(float(m.get("last_seen_ts", 0.0) or 0.0))
                        vals.append(float(m.get("device_seen_ts", 0.0) or 0.0))
                except Exception:
                    pass
                return max(vals) if vals else 0.0

            for peer in sorted(known, key=lambda p: (_peer_seen_ts(str(p)), str(p)), reverse=True):
                if peer not in seen:
                    add_item(peer, "")
            def _group_sort_ts(name: str) -> float:
                rec = dialogs.get(f"group:{name}", {})
                if not isinstance(rec, dict):
                    return 0.0
                try:
                    return float(rec.get("last_rx_ts", 0.0) or 0.0)
                except Exception:
                    return 0.0

            for g in sorted(groups_all, key=lambda name: (_group_sort_ts(str(name)), str(name)), reverse=True):
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
            # Initiate key exchange when user explicitly opens a dialog.
            # Do not depend on peer_used_meshtalk(): on a fresh peer we haven't pinned/confirmed anything yet.
            if peer_norm != self_id and st and not st.key_ready and not bool(getattr(st, "pinned_mismatch", False)):
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
                st.await_key_confirm_attempts = 0
                st.next_key_req_ts = 0.0
            send_key_request(peer_id, require_confirm=True, reason="manual_request_key")

        def import_peer_public_key(peer_id: str) -> None:
            if not peer_id or peer_id.startswith("group:"):
                return
            if not re.fullmatch(r"[0-9a-fA-F]{8}", peer_id):
                log_line(f"KEY: invalid peer id '{peer_id}'", "warn")
                return
            text, ok = QtWidgets.QInputDialog.getMultiLineText(
                win,
                tr("key_import_pub_title"),
                tr("key_import_pub_prompt").format(peer=norm_id_for_wire(peer_id)),
                "",
            )
            if not ok:
                return
            raw_input = str(text or "").strip()
            if not raw_input:
                return
            try:
                raw_compact = "".join(raw_input.split())
                pub_raw: bytes
                if re.fullmatch(r"[0-9a-fA-F]{64}", raw_compact or ""):
                    pub_raw = bytes.fromhex(raw_compact)
                else:
                    pub_raw = b64d(raw_compact)
                if len(pub_raw) != 32:
                    raise ValueError("invalid public key length")
                # Validate X25519 public key bytes.
                x25519.X25519PublicKey.from_public_bytes(pub_raw)
                store_peer_pub(peer_id, pub_raw)
                st = get_peer_state(peer_id)
                if st:
                    st.force_key_req = True
                    st.await_key_confirm = True
                    st.await_key_confirm_attempts = 0
                    st.next_key_req_ts = 0.0
                send_key_request(peer_id, require_confirm=True, reason="manual_import_pub")
                refresh_list()
                QtWidgets.QMessageBox.information(
                    win,
                    "meshTalk",
                    tr("key_import_pub_done").format(peer=norm_id_for_wire(peer_id)),
                )
            except Exception:
                QtWidgets.QMessageBox.warning(
                    win,
                    "meshTalk",
                    tr("key_import_pub_failed").format(peer=norm_id_for_wire(peer_id)),
                )

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
                st.await_key_confirm_attempts = 0
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
                st2.await_key_confirm_attempts = 0
                st2.next_key_req_ts = 0.0
            send_key_request(peer_id, require_confirm=True, reason="replace_pinned_key")
            log_line(f"{ts_local()} KEY: pinned key replaced for {peer_id}, confirmation requested", "info")

        trace_inflight: set[str] = set()
        trace_queue: list[str] = []
        trace_lock = threading.Lock()

        def _start_trace_route(peer_id: str) -> None:
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

            def _worker(peer_norm: str, msg_id: str, started_at_ts: float, meta_seed: Dict[str, object]) -> None:
                try:
                    iface = interface
                    if not radio_ready or iface is None:
                        delivered_at_ts = time.time()
                        ui_emit("log", f"{ts_local()} TRACE: start {peer_norm} (radio not connected)")
                        ui_emit(
                            "trace_done",
                            (
                                peer_norm,
                                msg_id,
                                {
                                    **meta_seed,
                                    "delivery": max(0.0, float(delivered_at_ts - started_at_ts)),
                                    "attempts": float(meta_seed.get("attempts", 0.0) or 0.0),
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
                    base_timeout = max(5.0, min(60.0, float(base_timeout)))
                    timeout_s = base_timeout * float(max(1, wait_factor))
                    try:
                        max_total_s = float(getattr(args, "max_seconds", 600) or 600)
                    except Exception:
                        max_total_s = 600.0
                    max_total_s = min(600.0, max(10.0, float(max_total_s)))
                    timeout_s = max(2.0, min(float(timeout_s), float(max_total_s), 60.0))
                    ui_emit(
                        "log",
                        f"{ts_local()} TRACE: params {peer_norm} timeout_s={timeout_s:.1f} max_total_s={max_total_s:.1f} base_timeout={base_timeout:.1f} nodes={nodes_len}",
                    )

                    attempt = 0
                    next_retry_at = started_at_ts
                    while not done.is_set():
                        now = time.time()
                        if (now - started_at_ts) >= max_total_s:
                            break
                        if now < next_retry_at:
                            done.wait(timeout=min(0.2, max(0.0, next_retry_at - now)))
                            continue
                        attempt += 1
                        ui_emit("trace_update", (peer_norm, msg_id, float(attempt)))
                        ui_emit("log", f"{ts_local()} TRACE: attempt={attempt} {peer_norm}")
                        req = mesh_pb2.RouteDiscovery()
                        send_err: list[BaseException] = []
                        send_done = threading.Event()

                        def _send_req() -> None:
                            try:
                                ch_idx = int(args.channel if args.channel is not None else 0)
                                send_traceroute_request(
                                    interface=iface,
                                    req=req,
                                    destination_id=dest,
                                    traceroute_port_num=portnums_pb2.PortNum.TRACEROUTE_APP,
                                    on_response=_on_resp,
                                    channel_index=ch_idx,
                                    hop_limit=hop_limit,
                                )
                                try:
                                    activity_record("out", "srv", 1, now=time.time(), bytes_count=0, subkind="trace")
                                except Exception:
                                    pass
                            except BaseException as ex:
                                send_err.append(ex)
                            finally:
                                send_done.set()

                        t0 = time.time()
                        threading.Thread(target=_send_req, daemon=True).start()
                        if not send_done.wait(timeout=5.0):
                            ui_emit("log", f"{ts_local()} TRACE: sendData blocked >5s, abort {peer_norm}")
                            with result_lock:
                                result["status"] = "send_blocked"
                                result["text"] = tr("trace_send_blocked")
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
                        if status == "send_blocked":
                            text = tr("trace_send_blocked")
                        else:
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
                        **meta_seed,
                        "delivery": max(0.0, float(delivered_at_ts - started_at_ts)),
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
                    ui_emit("trace_done", (peer_norm, msg_id, meta_data_final, resp_text))
                finally:
                    next_peer: Optional[str] = None
                    with trace_lock:
                        trace_inflight.discard(peer_norm)
                        if trace_queue:
                            next_peer = trace_queue.pop(0)
                            trace_inflight.add(next_peer)
                    if next_peer:
                        ui_emit("log", f"{ts_local()} TRACE: dequeued and starting {next_peer}")
                        _start_trace_route(next_peer)

            threading.Thread(target=_worker, args=(peer_id, trace_id, sent_at_ts, meta_data_out), daemon=True).start()

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
                if peer_id in trace_queue:
                    log_line(f"{ts_local()} TRACE: already queued for {peer_id}", "warn")
                    return
                if trace_inflight:
                    trace_queue.append(peer_id)
                    active_peer = next(iter(trace_inflight))
                    log_line(f"{ts_local()} TRACE: queued {peer_id} after active trace {active_peer} pos={len(trace_queue)}", "info")
                    return
                trace_inflight.add(peer_id)
            _start_trace_route(peer_id)

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
            def _day_separator_text(day_key: str) -> str:
                try:
                    t_struct = time.strptime(str(day_key), "%Y-%m-%d")
                    return f"--- {time.strftime('%d.%m.%Y', t_struct)} ---"
                except Exception:
                    return f"--- {str(day_key or '').strip()} ---"

            def _ensure_day_separator(day_key: str, persist: bool) -> None:
                if not dialog_id or not day_key:
                    return
                marker_id = f"day:{day_key}"
                marker_text = _day_separator_text(day_key)
                hist = chat_history.setdefault(dialog_id, [])
                # Insert date separator only once per day for a dialog.
                for rec in hist:
                    if isinstance(rec, dict) and str(rec.get("msg_id", "") or "") == marker_id:
                        return
                marker_entry = {"text": marker_text, "dir": "day", "msg_id": marker_id}
                hist.append(marker_entry)
                if current_dialog == dialog_id:
                    append_html(chat_text, marker_text, "#8a7f8b")
                if persist:
                    append_history("day", dialog_id, marker_id, marker_text)

            if not replace_msg_id:
                _ensure_day_separator(time.strftime("%Y-%m-%d", time.localtime()), persist=True)
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
                    if history_has_msg(chat_history, peer_norm, group_id):
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
                if history_has_msg(chat_history, peer_norm, group_id):
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
                    # Do not show generic "MC" placeholder in message status.
                    # Display compression only when exact algorithm is known.
                    if str(compression_name or "").strip().upper() == "MC":
                        compression_name = None
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
            append_log_to_view(view, text, level, qtgui=QtGui)

        def log_line(text: str, level: str = "info") -> None:
            nonlocal errors_need_ack, unseen_error_count, unseen_warn_count
            nonlocal last_error_summary, last_warn_summary, last_error_ts, last_warn_ts
            try:
                # Avoid touching Qt widgets from non-GUI threads.
                if QtCore.QThread.currentThread() != app.thread():
                    ui_emit("log", (str(text), str(level or "info")))
                    return
            except Exception:
                pass
            text, body = normalize_log_text_line(text, fallback_ts=ts_local())
            # Respect "Detailed events" toggle: hide very chatty diagnostics.
            if should_skip_verbose_log(body, bool(verbose_log)):
                return
            now = time.time()
            if not hasattr(log_line, "_last"):
                log_line._last = {"body": "", "ts": 0.0}
            lvl = classify_log_level(text, level)
            # Suppress immediate duplicate lines (print + ui_emit of same event),
            # but do NOT suppress security/errors/warnings where repetition is meaningful.
            if should_suppress_duplicate_log(body, lvl, now, log_line._last):
                return
            log_line._last = {"body": body, "ts": now}
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
                # Keep it short and avoid duplicate timestamps in UI.
                return f"пришло {hhmm}" if is_ru else f"received at {hhmm}"
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
            update_outgoing_delivery_state(
                chat_history=chat_history,
                dialog_id=dialog_id,
                msg_id=msg_id,
                delivery=delivery,
                attempts=attempts,
                forward_hops=forward_hops,
                ack_hops=ack_hops,
                packets=packets,
                format_meta_fn=format_meta,
                normalize_compression_name_fn=normalize_compression_name,
                update_dialog_fn=update_dialog,
                render_chat_fn=render_chat,
                refresh_list_fn=refresh_list,
                append_history_fn=append_history,
                current_dialog=current_dialog,
            )

        def update_sent_failed(
            dialog_id: str,
            msg_id: str,
            reason: str,
            attempts: int,
            total: int,
        ) -> None:
            update_outgoing_failed_state(
                chat_history=chat_history,
                dialog_id=dialog_id,
                msg_id=msg_id,
                reason=reason,
                attempts=attempts,
                total=total,
                format_meta_fn=format_meta,
                normalize_compression_name_fn=normalize_compression_name,
                update_dialog_fn=update_dialog,
                render_chat_fn=render_chat,
                refresh_list_fn=refresh_list,
                current_dialog=current_dialog,
            )

        def _split_text_by_utf8_limit(text: str, max_bytes: int) -> list[str]:
            src = str(text or "")
            if not src:
                return [""]
            lim = max(1, int(max_bytes))
            out: list[str] = []
            i = 0
            n = len(src)
            while i < n:
                # Fast path: remaining tail fits.
                tail = src[i:]
                if len(tail.encode("utf-8", errors="replace")) <= lim:
                    out.append(tail)
                    break
                lo = i + 1
                hi = n
                best = i
                # Binary search maximal char boundary that fits into lim bytes.
                while lo <= hi:
                    mid = (lo + hi) // 2
                    part = src[i:mid]
                    if len(part.encode("utf-8", errors="replace")) <= lim:
                        best = mid
                        lo = mid + 1
                    else:
                        hi = mid - 1
                if best <= i:
                    # Safety fallback (should be unreachable for UTF-8 text).
                    best = min(i + 1, n)
                out.append(src[i:best])
                i = best
            return out

        def send_plain_meshtastic_text(peer_norm: str, text: str) -> bool:
            peer_id = norm_id_for_filename(peer_norm)
            if not peer_id or not radio_ready or interface is None:
                return False
            max_plain_local = max(1, int(getattr(args, "max_bytes", 200) or 200) - int(PAYLOAD_OVERHEAD))
            chunks: list[str]
            try:
                text_bytes = len(str(text or "").encode("utf-8", errors="replace"))
            except Exception:
                text_bytes = 0
            if text_bytes > max_plain_local:
                chunks = _split_text_by_utf8_limit(text, max_plain_local)
                log_line(
                    f"{ts_local()} SENDSTD: chunking -> {peer_id} bytes={text_bytes} parts={len(chunks)} max_plain={max_plain_local}",
                    "info",
                )
            else:
                chunks = [str(text or "")]
            last_pkt = None
            sent_chunks = 0
            for idx, chunk in enumerate(chunks, start=1):
                try:
                    pkt = interface.sendText(
                        chunk,
                        destinationId=wire_id_from_norm(peer_id),
                        wantAck=False,
                        channelIndex=(args.channel if args.channel is not None else 0),
                    )
                except Exception as ex:
                    label = f" part={idx}/{len(chunks)}" if len(chunks) > 1 else ""
                    log_line(f"{ts_local()} SENDSTD: failed -> {peer_id}{label} ({type(ex).__name__}: {ex})", "warn")
                    return False
                if bool(packet_trace_log):
                    try:
                        bc_dbg = len(str(chunk or "").encode("utf-8", errors="replace"))
                    except Exception:
                        bc_dbg = 0
                    suffix = f" part={idx}/{len(chunks)}" if len(chunks) > 1 else ""
                    log_line(f"{ts_local()} PKT: tx std to={peer_id} bytes={bc_dbg}{suffix}", "info")
                try:
                    bc = len(str(chunk or "").encode("utf-8", errors="replace"))
                except Exception:
                    bc = 0
                sent_chunks += 1
                activity_record("out", "std", 1, bytes_count=bc)
                last_pkt = pkt
            msg_id = f"mtxt:{os.urandom(4).hex()}"
            try:
                if isinstance(last_pkt, dict):
                    pid = last_pkt.get("id")
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
            if sent_chunks > 1:
                preview = f"[chunked {sent_chunks}x] {preview}"
            log_line(
                f"{ts_local()} SENDSTD: {msg_id} -> {peer_id} port=TEXT_MESSAGE_APP text={preview!r}",
                "info",
            )
            try:
                routing_ctl.observe_local_send_attempt(
                    peer_id,
                    "meshtastic_text",
                    now=time.time(),
                )
            except Exception:
                pass
            return True

        def send_plain_meshtastic_broadcast(text: str) -> bool:
            if not radio_ready or interface is None:
                return False
            max_plain_local = max(1, int(getattr(args, "max_bytes", 200) or 200) - int(PAYLOAD_OVERHEAD))
            chunks: list[str]
            try:
                text_bytes = len(str(text or "").encode("utf-8", errors="replace"))
            except Exception:
                text_bytes = 0
            if text_bytes > max_plain_local:
                chunks = _split_text_by_utf8_limit(text, max_plain_local)
                log_line(
                    f"{ts_local()} SENDSTD: chunking -> Primary bytes={text_bytes} parts={len(chunks)} max_plain={max_plain_local}",
                    "info",
                )
            else:
                chunks = [str(text or "")]
            last_pkt = None
            sent_chunks = 0
            for idx, chunk in enumerate(chunks, start=1):
                try:
                    pkt = interface.sendText(
                        chunk,
                        destinationId=meshtastic.BROADCAST_ADDR,
                        wantAck=False,
                        channelIndex=(args.channel if args.channel is not None else 0),
                    )
                except Exception as ex:
                    label = f" part={idx}/{len(chunks)}" if len(chunks) > 1 else ""
                    log_line(f"{ts_local()} SENDSTD: failed -> Primary{label} ({type(ex).__name__}: {ex})", "warn")
                    try:
                        routing_ctl.observe_tx_result(
                            "group:primary",
                            "meshtastic_text",
                            now=time.time(),
                            success=False,
                            timeout=True,
                            rtt_s=None,
                            attempts=1,
                            hops=None,
                            micro_retries=0,
                        )
                    except Exception:
                        pass
                    return False
                if bool(packet_trace_log):
                    try:
                        bc_dbg = len(str(chunk or "").encode("utf-8", errors="replace"))
                    except Exception:
                        bc_dbg = 0
                    suffix = f" part={idx}/{len(chunks)}" if len(chunks) > 1 else ""
                    log_line(f"{ts_local()} PKT: tx std to=Primary bytes={bc_dbg}{suffix}", "info")
                try:
                    bc = len(str(chunk or "").encode("utf-8", errors="replace"))
                except Exception:
                    bc = 0
                sent_chunks += 1
                activity_record("out", "std", 1, bytes_count=bc)
                last_pkt = pkt
            msg_id = f"mtxt:{os.urandom(4).hex()}"
            try:
                if isinstance(last_pkt, dict):
                    pid = last_pkt.get("id")
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
            if sent_chunks > 1:
                preview = f"[chunked {sent_chunks}x] {preview}"
            log_line(
                f"{ts_local()} SENDSTD: {msg_id} -> Primary port=TEXT_MESSAGE_APP text={preview!r}",
                "info",
            )
            try:
                routing_ctl.observe_tx_result(
                    "group:primary",
                    "meshtastic_text",
                    now=time.time(),
                    success=True,
                    timeout=False,
                    rtt_s=None,
                    attempts=1,
                    hops=None,
                    micro_retries=0,
                )
            except Exception:
                pass
            return True

        def select_delivery_route(peer_norm: str, purpose: str = "unicast") -> tuple[str, float, str, list[tuple[str, float]]]:
            pnorm = norm_id_for_filename(peer_norm)
            candidates: list[str] = []
            now_sel = time.time()
            # Route selection must follow the current peer state, not a score tie-break.
            # If the contact is currently considered meshTalk-capable/recent, we use
            # the meshTalk protocol path only. Plain Meshtastic text is a fallback
            # only for peers that are not in meshTalk state.
            direct_ready = False
            try:
                direct_ready = peer_direct_meshtalk_ready(pnorm, now_ts=now_sel)
            except Exception:
                direct_ready = False
            if direct_ready:
                candidates.append("meshTalk")
            else:
                candidates.append("meshtastic_text")
                guard_reason = "unknown"
                try:
                    st_guard = get_peer_state(pnorm)
                except Exception:
                    st_guard = None
                if not st_guard:
                    guard_reason = "no_peer_state"
                else:
                    try:
                        if bool(getattr(st_guard, "pinned_mismatch", False)):
                            guard_reason = "pinned_mismatch"
                        elif not bool(getattr(st_guard, "key_ready", False)):
                            guard_reason = "no_key_session"
                        else:
                            seen_ts = float(getattr(st_guard, "last_seen_ts", 0.0) or 0.0)
                            offline_ts = float(getattr(st_guard, "app_offline_ts", 0.0) or 0.0)
                            if seen_ts <= 0.0:
                                guard_reason = "no_app_seen"
                            elif (now_sel - seen_ts) > float(CONTACT_STALE_SECONDS):
                                guard_reason = "app_stale"
                            elif offline_ts > 0.0 and (now_sel - offline_ts) <= float(CONTACT_STALE_SECONDS) and seen_ts <= offline_ts:
                                guard_reason = "app_offline"
                            else:
                                guard_reason = "not_direct_ready"
                    except Exception:
                        guard_reason = "state_error"
                log_line(
                    f"{ts_local()} ROUTE_GUARD: peer={pnorm} direct_meshtalk_ready=no reason={guard_reason}",
                    "info",
                )
            qd = 0
            try:
                with pending_lock:
                    qd = int(len(pending_by_peer.get(pnorm, {})))
            except Exception:
                qd = 0
            dec = routing_ctl.select_unicast_route(pnorm, candidates, queue_depth=int(qd), now=now_sel)

            def _best_relay_via_for_peer(peer_id_norm: str) -> str:
                try:
                    reachability_map = getattr(relay_state, "reachability", {}) or {}
                    slot_now = current_epoch_slot(now=now_sel)
                    token_candidates = [
                        _relay_token_for_peer(peer_id_norm, slot_now),
                        _relay_token_for_peer(peer_id_norm, max(0, int(slot_now) - 1)),
                    ]
                    for token in token_candidates:
                        rows = list(reachability_map.get(token) or [])
                        if rows:
                            return str(getattr(rows[0], "via_peer", "") or "").strip()
                except Exception:
                    pass
                return ""

            route_id_now = str(dec.route_id or "meshtastic_text")
            via_peer_now = ""
            if route_id_now == "meshTalk" and not direct_ready:
                via_peer_now = _best_relay_via_for_peer(pnorm)
            if route_id_now == "meshTalk":
                path_label = "direct" if direct_ready else (f"via {via_peer_now}" if via_peer_now else "meshTalk")
            else:
                path_label = route_id_now
            route_sig = (path_label, via_peer_now, route_id_now)
            prev_sig = route_selection_last_by_peer.get(pnorm)
            if prev_sig != route_sig:
                route_selection_last_by_peer[pnorm] = route_sig
                try:
                    kbest_txt = ", ".join(f"{str(rid)}:{float(score):.2f}" for rid, score in list(dec.k_best or [])[:3])
                except Exception:
                    kbest_txt = ""
                if prev_sig is None:
                    log_line(
                        f"{ts_local()} ROUTE_SWITCH: peer={pnorm} init={path_label} route={route_id_now} reason={str(dec.reason)}"
                        + (f" kbest=[{kbest_txt}]" if kbest_txt else ""),
                        "info",
                    )
                else:
                    log_line(
                        f"{ts_local()} ROUTE_SWITCH: peer={pnorm} {prev_sig[0]} -> {path_label} route={route_id_now} reason={str(dec.reason)}"
                        + (f" kbest=[{kbest_txt}]" if kbest_txt else ""),
                        "info",
                    )
            return (str(dec.route_id or "meshtastic_text"), float(dec.score), str(dec.reason), list(dec.k_best))

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
                peers_group = sorted(groups.get(name, set()))
                mt_targets = set(routing_ctl.choose_group_targets(peers_group, now=time.time()))
                for peer_norm in peers_group:
                    route_id, route_score, route_reason, _k_best = select_delivery_route(peer_norm, purpose="group")
                    # Group/broadcast policy: allow meshTalk only for top scored fanout subset.
                    if route_id == "meshTalk" and norm_id_for_filename(peer_norm) not in mt_targets:
                        route_id = "meshtastic_text"
                        route_reason = "group_fanout_cap"
                    if route_id == "meshTalk":
                        log_line(
                            f"{ts_local()} ROUTE: {peer_norm} -> meshTalk score={route_score:.3f} reason={route_reason}",
                            "info",
                        )
                        if queue_message(
                            peer_norm,
                            text,
                            route_id="meshTalk",
                            route_score=float(route_score),
                            route_reason=str(route_reason),
                        ) is not None:
                            queued_ok += 1
                    else:
                        log_line(
                            f"{ts_local()} ROUTE: {peer_norm} -> meshtastic_text score={route_score:.3f} reason={route_reason}",
                            "info",
                        )
                        if send_plain_meshtastic_text(peer_norm, text):
                            queued_ok += 1
                if queued_ok <= 0:
                    QtWidgets.QMessageBox.information(win, "meshTalk", tr("group_send_none"))
                    return
                chat_line(current_dialog, text, "#fd971f", outgoing=True, meta=format_meta(None, 0, None, None, None))
                append_history("sent", current_dialog, os.urandom(8).hex(), text)
                return
            route_id_d, route_score_d, route_reason_d, _k_best_d = select_delivery_route(current_dialog, purpose="unicast")
            if route_id_d != "meshTalk":
                log_line(
                    f"{ts_local()} ROUTE: {current_dialog} -> meshtastic_text score={route_score_d:.3f} reason={route_reason_d}",
                    "info",
                )
                if not send_plain_meshtastic_text(current_dialog, text):
                    QtWidgets.QMessageBox.warning(win, "meshTalk", "Meshtastic text send failed.")
                return
            log_line(
                f"{ts_local()} ROUTE: {current_dialog} -> meshTalk score={route_score_d:.3f} reason={route_reason_d}",
                "info",
            )
            res = queue_message(
                current_dialog,
                text,
                route_id="meshTalk",
                route_score=float(route_score_d),
                route_reason=str(route_reason_d),
            )
            if res is None:
                # k-best fallback: if queueing MT path failed, try plain text route.
                try:
                    fb_routes = [rid for (rid, _s) in _k_best_d]
                except Exception:
                    fb_routes = []
                if "meshtastic_text" in fb_routes:
                    log_line(f"{ts_local()} ROUTE: {current_dialog} fallback -> meshtastic_text", "warn")
                    if not send_plain_meshtastic_text(current_dialog, text):
                        QtWidgets.QMessageBox.warning(win, "meshTalk", "Meshtastic text send failed.")
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

        def _build_runtime_status_line() -> str:
            now = time.time()
            peers_known = len(known_peers)
            peers_tracked = len(tracked_peers)
            pending_count = sum(len(v) for v in pending_by_peer.values())
            last_act = max(0, int(now - last_activity_ts))
            last_key = "-" if last_key_sent_ts <= 0 else f"{int(now - last_key_sent_ts)}s ago"
            selected = current_dialog or "-"
            return (
                f"Port: {args.port} | meshTalk portNum: {data_port_label} | Self: {self_id} | "
                f"Peers: known {peers_known}, tracked {peers_tracked}, pending {pending_count} | "
                f"Selected: {selected} | Last activity: {last_act}s ago | Last key request: {last_key}"
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
            refresh_hello_button()
            try:
                line = _build_runtime_status_line()
                if settings_status_line is not None:
                    settings_status_line.setText(line)
            except Exception:
                pass

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
            line = _build_runtime_status_line()
            l1.setText(line)
            l2.setText("")
            l3.setText("")

        def load_history() -> None:
            if not os.path.isfile(HISTORY_FILE):
                return
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()[-2000:]
            except Exception:
                return

            def _day_separator_text(day_key: str) -> str:
                try:
                    t_struct = time.strptime(str(day_key), "%Y-%m-%d")
                    return f"--- {time.strftime('%d.%m.%Y', t_struct)} ---"
                except Exception:
                    return f"--- {str(day_key or '').strip()} ---"

            seen_ids: set[tuple[str, str, str, str]] = set()
            last_day_by_dialog: Dict[str, str] = {}
            for line in lines:
                parsed = parse_history_record_line(line)
                if parsed is None:
                    continue
                ts_part, direction, peer_id, msg_id, text, meta_data = parsed
                peer_norm = norm_id_for_filename(peer_id)
                dialog_id = peer_id if peer_id.startswith("group:") else peer_norm
                day_key = ts_part.split(" ")[0] if " " in ts_part else ""
                if direction == "day":
                    marker_id = str(msg_id or (f"day:{day_key}" if day_key else "day:unknown"))
                    marker_text = str(text or "").strip() or _day_separator_text(day_key)
                    if not history_has_msg(chat_history, dialog_id, marker_id):
                        chat_history.setdefault(dialog_id, []).append({"text": marker_text, "dir": "day", "msg_id": marker_id})
                    if day_key:
                        last_day_by_dialog[dialog_id] = day_key
                    continue
                if direction not in ("recv", "sent"):
                    continue
                key = (peer_norm, msg_id, direction, text)
                if msg_id and key in seen_ids:
                    continue
                if msg_id:
                    seen_ids.add(key)
                if peer_id.startswith("group:") and peer_id[6:] not in groups and peer_id.lower() != "group:primary":
                    continue
                if day_key and last_day_by_dialog.get(dialog_id, "") != day_key:
                    marker_id = f"day:{day_key}"
                    if not history_has_msg(chat_history, dialog_id, marker_id):
                        chat_history.setdefault(dialog_id, []).append(
                            {"text": _day_separator_text(day_key), "dir": "day", "msg_id": marker_id}
                        )
                    last_day_by_dialog[dialog_id] = day_key
                time_only = ts_part.split(" ")[1][:5] if " " in ts_part else ts_part[:5]
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
            nonlocal data_portnum, data_port_label
            nonlocal current_dialog, dialogs, chat_history, list_index
            nonlocal discovery_send, discovery_reply
            nonlocal hello_mode_active, hello_mode_until_ts
            nonlocal incoming_state
            nonlocal interface, self_id, self_id_raw, radio_ready, known_peers, peer_states, peer_names
            nonlocal initial_port_arg
            nonlocal clear_pending_on_switch, last_loaded_profile
            nonlocal peer_meta_dirty
            nonlocal relay_last_adv_ts
            nonlocal transport_state_last_by_peer, route_selection_last_by_peer
            if initializing:
                now = time.time()
                if (now - last_init_label_ts) >= 0.5:
                    init_step = (init_step + 1) % 3
                    dots = "." * (init_step + 1)
                    chat_label.setText(f"Initializing{dots}")
                    last_init_label_ts = now
            try:
                now_tick = time.time()
                if radio_ready and self_id and (now_tick - float(relay_last_adv_ts)) >= 60.0:
                    relay_last_adv_ts = now_tick
                    announce_self_relay_token(now_tick)
            except Exception:
                pass
            while True:
                try:
                    evt, payload = ui_events.get_nowait()
                except queue.Empty:
                    break
                if evt == "names_update":
                    refresh_list()
                if evt == "peer_update":
                    peer_norm = str(payload) if isinstance(payload, str) else None
                    update_peer_meta(peer_norm)
                    if peer_norm and key_conflict_peer == peer_norm:
                        try:
                            st_conf = peer_states.get(peer_norm)
                            if not bool(getattr(st_conf, "pinned_mismatch", False)):
                                _clear_key_conflict_header()
                        except Exception:
                            pass
                    if peer_norm:
                        try:
                            _state, _reason = peer_transport_state(peer_norm, now_ts=time.time())
                            _prev = transport_state_last_by_peer.get(peer_norm)
                            if _prev != (_state, _reason):
                                transport_state_last_by_peer[peer_norm] = (_state, _reason)
                                ui_emit(
                                    "log",
                                    f"{ts_local()} TRANSPORT: peer={peer_norm} state={_state} reason={_reason}",
                                )
                        except Exception:
                            pass
                    refresh_list()
                elif evt == "config_reload":
                    try:
                        cfg_new = payload if isinstance(payload, dict) else {}
                        cfg.clear()
                        cfg.update(cfg_new)
                        cfg["mesh_packet_portnum"] = normalize_mesh_packet_port_value(
                            cfg.get("mesh_packet_portnum", DEFAULT_MESHTALK_PACKET_PORT)
                        )
                        cfg.setdefault("activity_timing_mode", "manual")
                        cfg["activity_intra_batch_gap_ms"] = int(cfg.get("activity_intra_batch_gap_ms", 0) or 0)
                        cfg["discovery_hello_packet_count"] = int(cfg.get("discovery_hello_packet_count", 1) or 1)
                        cfg["discovery_hello_gap_seconds"] = int(cfg.get("discovery_hello_gap_seconds", 1) or 1)
                        cfg["discovery_hello_packet_gap_seconds"] = int(cfg.get("discovery_hello_packet_gap_seconds", 1) or 1)
                        cfg["discovery_hello_runtime_seconds"] = int(cfg.get("discovery_hello_runtime_seconds", 0) or 0)
                        cfg["discovery_hello_autostart"] = bool(cfg.get("discovery_hello_autostart", True))
                        data_portnum, data_port_label = resolve_mesh_packet_port(cfg.get("mesh_packet_portnum"))
                        cfg["activity_controller_model"] = normalize_activity_controller_model(
                            cfg.get("activity_controller_model", ACTIVITY_CONTROLLER_DEFAULT)
                        )
                        ensure_routing_defaults(cfg)
                        if migrate_legacy_manual_activity_defaults(cfg):
                            try:
                                save_config(cfg)
                            except Exception:
                                pass
                        routing_ctl.update_config(cfg)
                        cfg["port"] = args.port
                        current_lang = str(cfg.get("lang", current_lang)).lower()
                        if current_lang not in ("ru", "en"):
                            current_lang = "ru"
                        verbose_log = bool(cfg.get("log_verbose", verbose_log))
                        runtime_log_file = bool(cfg.get("runtime_log_file", runtime_log_file))
                        _STORAGE.set_runtime_log_enabled(runtime_log_file)
                        auto_pacing = False
                        try:
                            args.auto_pacing = False
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
                        contacts_visibility = normalize_contacts_visibility(
                            cfg.get("contacts_visibility", contacts_visibility),
                            default=contacts_visibility or "all",
                        )
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
                                int(cfg.get("parallel_sends", getattr(args, "parallel_sends", 2))),
                            )
                        except Exception:
                            args.parallel_sends = 2
                        ui_emit(
                            "log",
                            f"{ts_local()} ACTIVITY: timing={cfg.get('activity_timing_mode', 'manual')} "
                            f"retry={int(args.retry_seconds)}s rate={int(args.rate_seconds)}s "
                            f"parallel={int(args.parallel_sends)}",
                        )
                        pinned_dialogs = set(cfg.get("pinned_dialogs", []))
                        hidden_contacts = set(cfg.get("hidden_contacts", []))
                        peer_meta_dirty = False
                        transport_state_last_by_peer.clear()
                        route_selection_last_by_peer.clear()
                        peer_meta.clear()
                        peer_meta.update(parse_peer_meta_records(cfg.get("peer_meta", {}), norm_id_for_filename))
                        sync_peer_meta_to_states(peer_meta, peer_states)
                        groups.clear()
                        groups.update(parse_groups_config(cfg.get("groups", {})))
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
                    except Exception as ex:
                        trace_suppressed("ui.config_reload", ex)
                elif evt == "pacing_update":
                    if isinstance(payload, (tuple, list)) and len(payload) >= 2:
                        try:
                            new_rate = max(1, int(payload[0]))
                            new_parallel = max(1, int(payload[1]))
                            cfg["rate_seconds"] = new_rate
                            cfg["parallel_sends"] = new_parallel
                            # If Settings dialog is open, reflect the tuned values live.
                            try:
                                # Activity tab live labels (if settings is open).
                                try:
                                    if settings_activity_rate_lbl is not None:
                                        settings_activity_rate_lbl.setText(f"{int(new_rate)}s")
                                    if settings_activity_parallel_lbl is not None:
                                        settings_activity_parallel_lbl.setText(str(int(new_parallel)))
                                    if settings_activity_pps_lbl is not None:
                                        settings_activity_pps_lbl.setText(f"{(float(new_parallel) / float(max(1, int(new_rate)))):.3f} pkt/s")
                                except Exception:
                                    pass
                            except Exception:
                                pass
                            now_save = time.time()
                            if auto_pacing and ((now_save - last_pacing_save_ts) >= 60.0):
                                last_pacing_save_ts = now_save
                                save_gui_config()
                        except Exception:
                            pass
                elif evt == "trace_update":
                    trace_update = parse_trace_update_payload(payload)
                    if trace_update is not None:
                        peer_norm, trace_id, attempts_val = trace_update
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
                        if not handle_trace_done_ui(
                            peer_norm=peer_norm,
                            trace_id=trace_id,
                            meta_data=meta_data,
                            resp_text=resp_text,
                            chat_history=chat_history,
                            history_has_msg=history_has_msg,
                            format_meta=format_meta,
                            chat_line=chat_line,
                            append_history=append_history,
                            tr=tr,
                            as_optional_float=as_optional_float,
                            now_ts=time.time(),
                        ):
                            continue
                elif evt == "trace_result":
                    # Legacy event shape (older builds); keep best-effort behavior.
                    if isinstance(payload, (tuple, list)) and len(payload) >= 2:
                        peer_norm = str(payload[0] or "")
                        text = str(payload[1] or "")
                        if peer_norm and text:
                            chat_line(peer_norm, text, "#66d9ef", outgoing=False)
                elif evt == "recv":
                    recv_payload = parse_recv_payload(payload)
                    if recv_payload is None:
                        continue
                    from_id = recv_payload["from_id"]
                    text = recv_payload["text"]
                    fwd_hops = recv_payload["fwd_hops"]
                    delivery = recv_payload["delivery"]
                    group_id = recv_payload["group_id"]
                    part = recv_payload["part"]
                    total = recv_payload["total"]
                    attempt_in = recv_payload["attempt_in"]
                    chunk_b64 = recv_payload["chunk_b64"]
                    compression_flag = recv_payload["compression_flag"]
                    legacy_codec = recv_payload["legacy_codec"]
                    payload_cmp = recv_payload["payload_cmp"]
                    compact_wire = recv_payload["compact_wire"]
                    peer_norm = norm_id_for_filename(from_id)
                    update_peer_meta(peer_norm)
                    if peer_norm:
                        recv_now_ts = time.time()
                        recv_result = ingest_incoming_ui_fragment(
                            incoming_state=incoming_state,
                            peer_norm=peer_norm,
                            group_id=str(group_id),
                            total=int(total),
                            delivery=delivery,
                            fwd_hops=fwd_hops,
                            attempt_in=attempt_in,
                            compact_wire=bool(compact_wire),
                            compression_flag=int(compression_flag or 0),
                            legacy_codec=legacy_codec,
                            payload_cmp=payload_cmp,
                            chunk_b64=chunk_b64,
                            text=text,
                            part=int(part),
                            recv_now_ts=recv_now_ts,
                            effective_payload_cmp_label=effective_payload_cmp_label,
                            merge_compact_compression=merge_compact_compression,
                            assemble_incoming_text=assemble_incoming_text,
                            infer_compact_cmp_label_from_joined_parts=infer_compact_cmp_label_from_joined_parts,
                            normalize_compression_name=normalize_compression_name,
                            infer_compact_norm_from_joined_parts=infer_compact_norm_from_joined_parts,
                            compression_efficiency_pct=compression_efficiency_pct,
                            b64d=b64d,
                        )
                        save_incoming_state(incoming_state)
                        rec = recv_result["record"]
                        key = recv_result["key"]
                        full = recv_result["full_text"]
                        decode_ok = bool(recv_result["decode_ok"])
                        avg_hops = recv_result["avg_hops"]
                        avg_attempts = recv_result["avg_attempts"]
                        done_now = bool(recv_result["done_now"])
                        status = recv_result["status"]
                        compression_name = recv_result["compression_name"]
                        compression_eff_pct = recv_result["compression_eff_pct"]
                        compression_norm = recv_result["compression_norm"]
                        rec_received_ts = recv_result["received_at_ts"]
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
                    recv_plain = parse_recv_plain_payload(payload)
                    if recv_plain is not None:
                        peer_norm, text_plain, msg_id_plain, dialog_id_plain = recv_plain
                        peer_norm = norm_id_for_filename(peer_norm)
                        if not peer_norm:
                            continue
                        handle_recv_plain_ui(
                            peer_norm=peer_norm,
                            text_plain=text_plain,
                            msg_id_plain=msg_id_plain,
                            dialog_id_plain=dialog_id_plain,
                            chat_history=chat_history,
                            history_has_msg=history_has_msg,
                            update_peer_meta=update_peer_meta,
                            chat_line=chat_line,
                            append_history=append_history,
                            log_line=log_line,
                            format_plain_transport_meta=format_plain_transport_meta,
                            now_ts=time.time(),
                            ts_local=ts_local,
                        )
                elif evt == "queued":
                    queued_payload = parse_queued_payload(payload)
                    if queued_payload is not None:
                        peer_norm, queued_id, nbytes, parts, cmp_label = queued_payload
                        if queued_id is not None and nbytes is not None and parts is not None and cmp_label is not None:
                            group_id = queued_id
                            log_line(f"QUEUE -> {peer_norm}: id={group_id} parts={parts} bytes={nbytes} cmp={cmp_label}", "info")
                        elif queued_id is not None:
                            # Legacy payload: never log message text.
                            text_legacy = queued_id
                            log_line(
                                f"QUEUE -> {peer_norm}: (redacted) bytes={len(text_legacy.encode('utf-8'))}",
                                "info",
                            )
                elif evt == "ack":
                    if not hasattr(process_ui_events, "_outgoing"):
                        process_ui_events._outgoing = {}
                    ack_update = update_outgoing_ack_tracker(
                        process_ui_events._outgoing,
                        payload,
                    )
                    if ack_update is None:
                        continue
                    peer_norm, group_id, delivery, avg_attempts, avg_fwd, avg_ack, packets = ack_update
                    update_peer_meta(peer_norm)
                    update_sent_delivery(
                        peer_norm,
                        str(group_id),
                        float(delivery),
                        avg_attempts,
                        avg_fwd,
                        avg_ack,
                        packets,
                    )
                elif evt == "failed":
                    peer_norm, group_id, reason, attempts, total = payload
                    update_peer_meta(str(peer_norm) if isinstance(peer_norm, str) else None)
                    update_sent_failed(str(peer_norm), str(group_id), str(reason), int(attempts), int(total))
                elif evt == "log":
                    if isinstance(payload, (tuple, list)) and len(payload) >= 2:
                        log_line(str(payload[0]), str(payload[1] or "info"))
                    else:
                        log_line(str(payload), "info")
                elif evt == "hello_state":
                    if isinstance(payload, dict):
                        try:
                            hello_mode_until_ts = float(payload.get("until_ts", hello_mode_until_ts) or 0.0)
                        except Exception:
                            pass
                        try:
                            hello_mode_active = bool(payload.get("active", hello_mode_active))
                        except Exception:
                            pass
                    refresh_hello_button()
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
                            try:
                                st_conf = peer_states.get(peer_norm)
                                if st_conf is not None and not bool(getattr(st_conf, "pinned_mismatch", False)):
                                    # The conflict was already resolved (auto-accept/manual accept)
                                    # before the queued UI event was processed.
                                    continue
                            except Exception:
                                pass
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
                    transport_state_last_by_peer.clear()
                    route_selection_last_by_peer.clear()
                    with pending_lock:
                        clear_runtime_collections(
                            known_peers=known_peers,
                            peer_states=peer_states,
                            key_response_last_ts=key_response_last_ts,
                            key_conflict_ignored=key_conflict_ignored,
                            key_conflict_hidden_log_ts=key_conflict_hidden_log_ts,
                            incoming_state=incoming_state,
                            pending_by_peer=pending_by_peer,
                            dialogs=dialogs,
                            chat_history=chat_history,
                            list_index=list_index,
                        )
                    with peer_names_lock:
                        peer_names.clear()
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
            menu = _prepare_popup_menu(QtWidgets.QMenu(win))
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
                add_action(tr("key_import_pub"), lambda: import_peer_public_key(current_id))
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
                        log_line(f"{ts_local()} HELLO: burst", "discovery")
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
                if str(msg).startswith("Another instance is already running"):
                    ui_emit("log", f"{ts_local()} APP: {msg}")
                    radio_loop_running = False
                    return
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
                send_app_offline_broadcast(nowait=True)
            except Exception:
                pass

        app.aboutToQuit.connect(_on_app_about_to_quit)

        win.show()
        try:
            return app.exec()
        except KeyboardInterrupt:
            try:
                app.quit()
            except Exception:
                pass
            return 0
        finally:
            if prev_sigint_handler is not None:
                try:
                    signal.signal(signal.SIGINT, prev_sigint_handler)
                except Exception:
                    pass

    rc = run_gui_qt()
    if rc >= 0:
        return rc
    print("ERROR: Qt GUI is required (install PySide6). RU: нужен Qt GUI (установите PySide6).")
    return 2


if __name__ == "__main__":
    sys.exit(main())
