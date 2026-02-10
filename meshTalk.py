#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""
Reliable point-to-point messaging over Meshtastic with end-to-end encryption.
RU: Надёжная двусторонняя доставка поверх Meshtastic с E2EE.
"""

from __future__ import annotations

import argparse
import base64
import os
import queue
import sys
import threading
import time
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
from meshtalk.storage import (
    Storage,
    decode_history_meta_token,
    encode_history_meta_token,
    harden_dir,
    harden_file,
    maybe_set_private_umask,
    parse_history_record_line,
)
from message_text_compression import (
    MODE_BZ2,
    MODE_DEFLATE,
    MODE_BYTE_DICT,
    MODE_FIXED_BITS,
    MODE_LZMA,
    MODE_NLTK,
    MODE_SPACY,
    MODE_TENSORFLOW,
    MODE_ZLIB,
    compress_text,
    mode_name,
)


VERSION = "0.3.2"
DEFAULT_PORTNUM = portnums_pb2.PortNum.PRIVATE_APP
PAYLOAD_OVERHEAD = 1 + 1 + 8 + 12 + 16  # ver + type + msg_id + nonce + tag
KEY_REQ_PREFIX = b"KR1|"
KEY_RESP_PREFIX = b"KR2|"
MSG_V2_PREFIX = b"M2"
MSG_V2_HEADER_LEN = 16  # prefix(2) + ts(4) + group(4) + part(2) + total(2) + attempt(1) + meta(1)
MAX_PENDING_PER_PEER = 128
RETRY_BACKOFF_MAX_SECONDS = 300.0
RETRY_JITTER_RATIO = 0.25
KEY_RESPONSE_MIN_INTERVAL_SECONDS = 300.0
KEY_RESPONSE_RETRY_INTERVAL_SECONDS = 5.0
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
    int(MODE_DEFLATE),
    int(MODE_ZLIB),
    int(MODE_BZ2),
    int(MODE_LZMA),
    int(MODE_NLTK),
    int(MODE_SPACY),
    int(MODE_TENSORFLOW),
)
LEGACY_COMPRESSION_MODES = tuple(COMPRESSION_MODES)
AUTO_MIN_GAIN_BYTES = 2


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
    return nid


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


class PeerState:
    def __init__(self, peer_id_norm: str, aes: Optional[AESGCM] = None) -> None:
        self.peer_id_norm = peer_id_norm
        self.aes = aes
        self.last_seen_ts = 0.0
        # Set only after confirmed two-way key exchange (peer has our pub and we have peer pub).
        self.key_confirmed_ts = 0.0
        self.compression_capable = False
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
        self.next_key_refresh_ts = 0.0
        self.await_key_confirm = False

    @property
    def key_ready(self) -> bool:
        return self.aes is not None


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
        supported_modes=set(COMPRESSION_MODES),
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


    args = ap.parse_args()
    initial_port_arg = args.port

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
    incoming_state: Dict[str, Dict[str, object]] = {}

    def update_peer_names_from_nodes(peer_norm: Optional[str] = None) -> None:
        try:
            if interface is None:
                return
            nodes = getattr(interface, "nodes", None)
            if not isinstance(nodes, dict):
                return
            for node in nodes.values():
                if not isinstance(node, dict):
                    continue
                user = node.get("user") if isinstance(node.get("user"), dict) else {}
                nid = user.get("id") or node.get("id")
                if not isinstance(nid, str) or not nid:
                    continue
                norm = norm_id_for_filename(nid)
                if peer_norm and norm != peer_norm:
                    continue
                long_name = user.get("longName") or user.get("longname") or node.get("longName")
                short_name = user.get("shortName") or user.get("shortname") or node.get("shortName")
                if long_name or short_name:
                    peer_names[norm] = {
                        "long": str(long_name or ""),
                        "short": str(short_name or ""),
                    }
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
        peer_id_norm = self_id
        set_data_dir_for_node(self_id)
        migrate_data_dir(os.path.join(LEGACY_BASE_DIR, self_id), DATA_DIR)
        migrate_data_dir(LEGACY_BASE_DIR, DATA_DIR)
        ensure_storage_key()
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
                st.compression_modes = set(COMPRESSION_MODES)
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
        return path

    def on_receive(packet, interface=None):
        nonlocal last_activity_ts
        decoded = packet.get("decoded") or {}
        portnum = decoded.get("portnum")
        if isinstance(portnum, str):
            if portnum != "PRIVATE_APP":
                return
        elif isinstance(portnum, int):
            if portnum != int(DEFAULT_PORTNUM):
                return
        payload = parse_payload(decoded.get("payload"))
        if not payload:
            return

        # Peer presence signal: any packet on our port counts as "seen".
        try:
            now_seen = time.time()
            from_id_seen = packet.get("fromId")
            peer_norm_seen = norm_id_for_filename(from_id_seen) if from_id_seen else None
            if peer_norm_seen:
                st_seen = get_peer_state(peer_norm_seen)
                if st_seen:
                    st_seen.last_seen_ts = now_seen
        except Exception:
            pass

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
                store_peer_pub(peer_id, pub_raw)
            except PeerKeyPinnedError as ex:
                ui_emit(
                    "log",
                    f"{ts_local()} KEY: pinned key mismatch for {peer_id} old={ex.old_fp} new={ex.new_fp}. Use 'Reset key' to accept new.",
                )
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
                ui_emit("log", f"{ts_local()} KEYOK: exchange complete with {peer_id}. Confirmed.")
                st.force_key_req = False
                st.await_key_confirm = False
                st.next_key_req_ts = float("inf")
            if kind == "req":
                ui_emit("log", f"{ts_local()} KEY: request from {peer_id}")
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
                        f"{ts_local()} KEY: request from {peer_id} suppressed (recent response, wait {left_s}s).",
                    )
                else:
                    modes_bytes = ",".join(str(m) for m in sorted(COMPRESSION_MODES)).encode("ascii")
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
                    ui_emit("log", f"{ts_local()} KEY: received request from {peer_id}, sent our public key.")
                if st and not is_broadcast:
                    st.await_key_confirm = True
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
                        send_key_request(peer_norm)
                        st.next_key_req_ts = now + max(1.0, float(args.retry_seconds))
                        ui_emit("log", f"{ts_local()} KEY: request (no key) -> {from_id}")
                        ui_emit("peer_update", peer_norm)
            return

        status, msg_type, msg_id, pt, rx_compression = try_unpack_message(
            payload, st.aes, bind_aad_type=bool(getattr(st, "aad_type_bound", False))
        )
        if status == "decrypt_fail":
            now = time.time()
            if (st.last_decrypt_fail_ts <= 0.0) or ((now - st.last_decrypt_fail_ts) > 30.0):
                st.decrypt_fail_count = 0
            st.decrypt_fail_count += 1
            st.last_decrypt_fail_ts = now
            ui_emit(
                "log",
                f"{ts_local()} KEY: decrypt failed for {from_id} (possible stale key).",
            )
            if peer_norm:
                st.force_key_req = True
                if st.decrypt_fail_count >= 2:
                    # Suspend old key without deleting; wait for fresh exchange
                    st.aes = None
                    st.next_key_req_ts = 0.0
                if now >= st.next_key_req_ts:
                    send_key_request(peer_norm)
                    st.next_key_req_ts = now + max(1.0, float(args.retry_seconds))
                ui_emit("peer_update", peer_norm)
            return
        if status != "ok" or msg_type is None or msg_id is None:
            return
        msg_hex = msg_id.hex()
        st.decrypt_fail_count = 0
        if st.await_key_confirm:
            st.await_key_confirm = False
            st.force_key_req = False
            st.next_key_req_ts = float("inf")
            st.last_key_ok_ts = time.time()
            st.key_confirmed_ts = st.last_key_ok_ts
            if from_id:
                ui_emit("log", f"{ts_local()} KEYOK: confirmed by encrypted traffic from {from_id}.")

        def build_ack_text(hops: Optional[int]) -> bytes:
            parts = ["ACK", "mc=1", f"mc_modes={','.join(str(m) for m in COMPRESSION_MODES)}"]
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
                        parsed_modes = {m for m in parsed_modes if m in COMPRESSION_MODES}
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
                    f"{ts_local()} ACK: {msg_hex} rtt={rtt:.2f}s avg={st.rtt_avg:.2f}s attempts={attempts}",
                )
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
                            st.aes,
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
                        "mc_nltk": MODE_NLTK,
                        "mc_spacy": MODE_SPACY,
                        "mc_tensorflow": MODE_TENSORFLOW,
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
                                st.aes,
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
            ui_emit("log", f"{ts_local()} RECV: {msg_hex} cmp={log_cmp}")
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
                    st.aes,
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
        pub.subscribe(on_receive, "meshtastic.receive.data")

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
            send_key_request(peer_norm)

    def send_key_request(peer_norm: str, require_confirm: bool = True) -> None:
        nonlocal last_activity_ts, last_key_sent_ts
        if not radio_ready or interface is None:
            return
        if peer_norm == self_id:
            return
        st = get_peer_state(peer_norm)
        now = time.time()
        if st and (now - st.last_key_req_ts) < 5.0:
            return
        dest_id = wire_id_from_norm(peer_norm)
        modes_bytes = ",".join(str(m) for m in sorted(COMPRESSION_MODES)).encode("ascii")
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
            st.next_key_refresh_ts = last_activity_ts + 3600.0 + random.uniform(0, 600)
            if require_confirm:
                st.await_key_confirm = True
                st.next_key_req_ts = last_activity_ts + max(1.0, float(args.retry_seconds))
        ui_emit("log", f"{ts_local()} KEY: request sent to {dest_id}")

    def send_discovery_broadcast() -> None:
        if not radio_ready or interface is None:
            return
        modes_bytes = ",".join(str(m) for m in sorted(COMPRESSION_MODES)).encode("ascii")
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
        return ((float(plain) - float(packed)) / float(plain)) * 100.0

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
            "mc_nltk": "NLTK",
            "mc_spacy": "SPACY",
            "mc_tensorflow": "TENSORFLOW",
            "mc_unknown": "MC",
            "deflate": "DEFLATE",
            "zlib": "ZLIB",
            "bz2": "BZ2",
            "lzma": "LZMA",
            "nltk": "NLTK",
            "spacy": "SPACY",
            "tensorflow": "TENSORFLOW",
        }
        return aliases.get(low, name)

    def queue_message(peer_norm: str, text: str) -> Optional[tuple[str, int, Optional[str], Optional[float]]]:
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
        cmp_eff_pct: Optional[float] = None
        peer_supports_mc = bool(st.compression_capable)
        peer_supports_msg_v2 = bool(
            (getattr(st, "peer_msg_versions", None) is None)
            or (2 in set(getattr(st, "peer_msg_versions", {1})))
        )
        peer_supported_modes = sorted(
            {int(m) for m in getattr(st, "compression_modes", set()) if int(m) in COMPRESSION_MODES}
        )
        if not peer_supported_modes:
            peer_supported_modes = list(LEGACY_COMPRESSION_MODES)
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
        if peer_supports_mc and peer_supports_msg_v2 and (not plain_fits_one_packet):
            best_blob: Optional[bytes] = None
            best_mode: Optional[int] = None
            mode_order = list(peer_supported_modes)
            for mode_try in mode_order:
                if best_mode is not None and mode_try == best_mode:
                    continue
                try:
                    candidate = compress_text(text, mode=mode_try, preserve_case=True)
                except Exception:
                    continue
                if (best_blob is None) or (len(candidate) < len(best_blob)):
                    best_blob = candidate
                    best_mode = mode_try
            if best_blob is not None and len(best_blob) < (len(text_bytes) - int(AUTO_MIN_GAIN_BYTES)):
                payload_blob = best_blob
                use_compact_wire = True
                compression_flag = 1
                cmp_label = mode_name(int(best_mode))
                cmp_eff_pct = compression_efficiency_pct(len(text_bytes), len(best_blob))
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
        last_activity_ts = time.time()
        if st.key_ready:
            print(f"QUEUE: {group_id} parts={total} bytes={len(text_bytes)} cmp={cmp_label}")
        else:
            print(f"WAITING KEY: queued for {peer_norm} id={group_id}")
        ui_emit("queued", (peer_norm, group_id, len(text_bytes), int(total), str(cmp_label)))
        tracked_peers.add(peer_norm)
        return (group_id, total, normalize_compression_name(cmp_label), cmp_eff_pct)

    send_window_start_ts = 0.0
    send_window_count = 0
    send_rr_offset = 0

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
                        send_key_request(peer_norm)
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
                ui_emit("log", f"{ts_local()} SEND: {rec['id']} attempt={rec['attempts']} cmp={cmp_name} -> {peer_norm}")
                return

    # If we just generated our keys or peer key is missing, request exchange immediately.
    if peer_id_norm:
        st = get_peer_state(peer_id_norm)
        if generated_now or (st is not None and not st.key_ready):
            print(f"{ts_local()} KEY: startup request to {wire_id_from_norm(peer_id_norm)}")
            send_key_request(peer_id_norm)
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
        while True:
            send_due()
            now = time.time()
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
                        send_key_request(peer_norm, require_confirm=True)
                        continue
                    if st.next_key_refresh_ts <= 0.0:
                        st.next_key_refresh_ts = now + 3600.0 + random.uniform(0, 600)
                    if now >= st.next_key_refresh_ts:
                        send_key_request(peer_norm, require_confirm=False)
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
            if radio_ready and (now - last_health_ts) >= 300.0:
                last_health_ts = now
                with pending_lock:
                    pending_count = sum(len(v) for v in pending_by_peer.values())
                peers_snapshot, avg_rtt = snapshot_runtime_state(peer_states, known_peers, tracked_peers)
                ui_emit(
                    "log",
                    f"{ts_local()} HEALTH: peers={len(peers_snapshot)} tracked={len(tracked_peers)} pending={pending_count} avg_rtt={avg_rtt:.2f}s",
                )
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
        enc_status = "ACTIVE" if st and st.key_ready else "WAITING KEY"
        print(f"Encryption: {enc_status}")
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
                "peer_delete": "Delete contact",
                "peer_delete_confirm": "Delete contact '{name}'?",
                "clear_history": "Clear history",
                "clear_history_confirm": "Clear chat history with '{name}'?",
                "group_add": "Add selected to group",
                "actions": "Actions",
                "key_request": "Request key",
                "key_reset": "Reset key",
                "settings_runtime": "Runtime settings",
                "settings_restart": "Port/retry/limits apply after reconnect or restart",
                "port": "Port",
                "channel": "Channel",
                "retry": "Retry seconds",
                "max_seconds": "Max seconds",
                "max_bytes": "Max bytes",
                "rate": "Rate seconds",
                "parallel_sends": "Parallel packets",
                "discovery": "Discovery",
                "discovery_send": "Send broadcast discovery",
                "discovery_reply": "Reply to broadcast discovery",
                "clear_pending_on_switch": "Clear pending when profile switches",
                "full_reset": "Full reset",
                "full_reset_confirm": "Delete all profile settings, history, pending state and keys for '{name}'?\n\nThis action cannot be undone.",
                "full_reset_done": "Profile data and keys were reset.",
                "full_reset_unavailable": "Full reset is available after node/profile initialization.",
                "copy_log": "Copy log",
                "clear_log": "Clear log",
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
                "last_seen": "Last seen",
                "peer_delete": "Удалить собеседника",
                "peer_delete_confirm": "Удалить собеседника '{name}'?",
                "clear_history": "Очистить историю",
                "clear_history_confirm": "Очистить историю чата с '{name}'?",
                "group_add": "Добавить выделенных в группу",
                "actions": "Действия",
                "key_request": "Запросить ключ",
                "key_reset": "Сбросить ключ",
                "settings_runtime": "Параметры запуска",
                "settings_restart": "Порт/повтор/лимиты применяются после переподключения или перезапуска",
                "port": "Порт",
                "channel": "Канал",
                "retry": "Повтор, сек",
                "max_seconds": "Макс ожидание, сек",
                "max_bytes": "Макс байт",
                "rate": "Мин интервал, сек",
                "parallel_sends": "Параллельно, пакетов",
                "discovery": "Обнаружение",
                "discovery_send": "Отправлять broadcast discovery",
                "discovery_reply": "Отвечать на broadcast discovery",
                "clear_pending_on_switch": "Очищать очередь при смене профиля",
                "full_reset": "Полный сброс",
                "full_reset_confirm": "Удалить все настройки профиля, историю, очередь и ключи для '{name}'?\n\nДействие необратимо.",
                "full_reset_done": "Данные профиля и ключи сброшены.",
                "full_reset_unavailable": "Полный сброс доступен после инициализации ноды/профиля.",
                "copy_log": "Копировать лог",
                "clear_log": "Очистить лог",
                "about_author": "Автор",
                "about_callsign": "Позывной",
                "about_telegram": "Telegram",
                "about_vision": "Видение: только гражданское/любительское/исследовательское изучение mesh-месседжинга",
                "about_author_position": "Позиция автора: военное и любое незаконное использование прямо запрещено",
                "about_disclaimer": "Отказ от ответственности: ПО «как есть», без гарантий; автор не отвечает за ущерб",
            },
        }
        cfg: Dict[str, object] = {}
        log_startup = []
        for line in startup_events:
            log_startup.append(line)
        current_lang = str(cfg.get("lang", "ru")).lower()
        verbose_log = bool(cfg.get("log_verbose", True))
        runtime_log_file = bool(cfg.get("runtime_log_file", True))
        pinned_dialogs = set(cfg.get("pinned_dialogs", []))
        hidden_contacts = set(cfg.get("hidden_contacts", []))
        groups_cfg = cfg.get("groups", {}) if isinstance(cfg.get("groups", {}), dict) else {}
        clear_pending_on_switch = bool(cfg.get("clear_pending_on_switch", True))
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
        items_list = QtWidgets.QListWidget()
        set_mono(items_list)
        items_list.setIconSize(QtCore.QSize(36, 36))
        items_list.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
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
        chat_label.setAlignment(QtCore.Qt.AlignCenter)
        chat_label.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        chat_label.setTextInteractionFlags(QtCore.Qt.NoTextInteraction)
        chat_label.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        settings_spacer = QtWidgets.QSpacerItem(10, 10, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        settings_btn = QtWidgets.QPushButton(tr("settings"))
        settings_btn.setFixedHeight(32)
        header_layout.addWidget(chat_label, 1)
        header_layout.addItem(settings_spacer)
        header_layout.addWidget(settings_btn, 0)
        header_bar.setFixedHeight(32)
        settings_row.addWidget(header_bar, 1)
        right_col.addLayout(settings_row, 0)
        chat_text = QtWidgets.QTextEdit()
        chat_text.setReadOnly(True)
        set_mono(chat_text)
        chat_text.setContentsMargins(0, 0, 0, 0)
        chat_text.setViewportMargins(0, 0, 0, 0)
        chat_text.document().setDocumentMargin(0)
        chat_text.setFrameShape(QtWidgets.QFrame.NoFrame)
        right_col.addWidget(chat_text, 4)

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

        msg_entry.textChanged.connect(adjust_input_height)
        win.resizeEvent = (lambda e, _orig=win.resizeEvent: (_orig(e), adjust_input_height()))

        class ContactDelegate(QtWidgets.QStyledItemDelegate):
            def paint(self, painter: QtGui.QPainter, option: QtWidgets.QStyleOptionViewItem, index: QtCore.QModelIndex) -> None:
                super().paint(painter, option, index)
                data = index.data(QtCore.Qt.UserRole)
                if not isinstance(data, dict):
                    return
                lock_state = data.get("lock")
                unread = int(data.get("unread", 0) or 0)
                rect = option.rect
                pad = 4
                selected = bool(option.state & QtWidgets.QStyle.State_Selected)
                painter.save()
                if unread > 0:
                    dot = 8
                    dot_x = rect.right() - dot - pad - 2
                    dot_y = rect.top() + pad + 2
                    painter.setPen(QtCore.Qt.NoPen)
                    painter.setBrush(QtGui.QColor("#ff9800"))
                    painter.drawEllipse(QtCore.QRect(dot_x, dot_y, dot, dot))
                fg = QtGui.QColor("#2b0a22") if selected else QtGui.QColor("#8a7f8b")
                painter.setPen(fg)
                font = painter.font()
                font.setPointSize(8)
                painter.setFont(font)
                fm = QtGui.QFontMetrics(font)
                line_h = int(max(10, fm.height()))
                y = rect.bottom() - pad - line_h
                try:
                    key_h = int(data.get("key_h")) if data.get("key_h") is not None else None
                except Exception:
                    key_h = None
                try:
                    seen_h = int(data.get("seen_h")) if data.get("seen_h") is not None else None
                except Exception:
                    seen_h = None
                if lock_state == "ok" and key_h is not None:
                    lock_text = f"🔒 {key_h} h"
                    painter.drawText(
                        QtCore.QRect(rect.left() + pad, y, rect.width() - pad * 2, line_h),
                        int(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter),
                        lock_text,
                    )
                    y -= line_h
                seen_text = f"{tr('last_seen')}: {seen_h} h" if seen_h is not None else f"{tr('last_seen')}: -"
                painter.drawText(
                    QtCore.QRect(rect.left() + pad, y, rect.width() - pad * 2, line_h),
                    int(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter),
                    seen_text,
                )
                painter.restore()

        items_list.setItemDelegate(ContactDelegate(items_list))

        # Ubuntu terminal-like theme (flat, no frames)
        win.setStyleSheet(
            """
            QWidget { background: #300a24; color: #eeeeec; }
            QGroupBox { border: 0; margin-top: 0; font-weight: 600; }
            QGroupBox::title { subcontrol-origin: margin; left: 4px; color: #cfcfcf; }
            QGroupBox#listGroup::title { height: 0px; }
            QGroupBox#listGroup { margin-top: 0px; }
            QListWidget { background: #2b0a22; border: 1px solid #3c0f2e; padding: 0px; }
            QTextEdit { background: #2b0a22; border: 1px solid #3c0f2e; padding: 0px; }
            QLineEdit { background: #2b0a22; border: 1px solid #6f4a7a; padding: 6px; }
            QPushButton { background: #5c3566; border: 1px solid #6f4a7a; padding: 6px 10px; }
            QPushButton:hover { background: #6f4a7a; }
            QMenu { background: #2b0a22; border: 1px solid #6f4a7a; padding: 2px; }
            QMenu::item { padding: 6px 14px; color: #eeeeec; }
            QMenu::item:selected { background: #ff9800; color: #2b0a22; }
            QLabel#muted { color: #c0b7c2; }
            QLabel#hint { color: #bcaec0; font-size: 10px; }
            QLabel#section { color: #c0b7c2; font-size: 13px; font-weight: 400; }
            QWidget#headerBar { background: #c24f00; }
            QWidget#headerBar QLabel { background: transparent; font-weight: 600; color: #2b0a22; }
            QWidget#headerBar[mtStatus="ok"] { background: #0b3d1f; }
            QWidget#headerBar[mtStatus="ok"] QLabel { color: #eaffea; }
            QWidget#headerBar[mtStatus="error"] { background: #6b1d1d; }
            QWidget#headerBar[mtStatus="error"] QLabel { color: #ffecec; }
            QListWidget::item { padding: 8px 0px; }
            QListWidget::item:selected { background: #ff9800; color: #2b0a22; }
            QListWidget::item:selected:!active { background: #ff9800; color: #2b0a22; }
            """
        )

        header_status = "init"
        errors_need_ack = False
        header_bar.setProperty("mtStatus", header_status)

        def set_header_status(status: str) -> None:
            nonlocal header_status
            st = str(status or "init").strip().lower()
            if st not in ("init", "ok", "error"):
                st = "init"
            if st == header_status:
                return
            header_status = st
            header_bar.setProperty("mtStatus", st)
            try:
                header_bar.style().unpolish(header_bar)
                header_bar.style().polish(header_bar)
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
                    "peer_meta": peer_meta,
                }
            )

        def apply_language() -> None:
            list_group.setTitle("")
            chat_label.setText(self_title())
            msg_entry.setPlaceholderText(tr("message"))
            settings_btn.setText(tr("settings"))
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
            if float(getattr(st, "key_confirmed_ts", 0.0) or 0.0) > 0.0:
                prev = float(rec.get("key_confirmed_ts", 0.0) or 0.0)
                if float(st.key_confirmed_ts) > (prev + 1.0):
                    rec["key_confirmed_ts"] = float(st.key_confirmed_ts)
                    changed = True
            if changed:
                peer_meta[peer_norm] = rec
                peer_meta_dirty = True

        settings_log_view: Optional["QtWidgets.QTextEdit"] = None

        def open_settings() -> None:
            nonlocal current_lang
            nonlocal verbose_log
            nonlocal runtime_log_file
            nonlocal discovery_send, discovery_reply
            nonlocal clear_pending_on_switch
            nonlocal errors_need_ack
            errors_need_ack = False
            update_status()
            dlg = QtWidgets.QDialog(win)
            dlg.setWindowTitle(tr("settings_title"))
            dlg.resize(700, 560)
            layout = QtWidgets.QVBoxLayout(dlg)
            top_row = QtWidgets.QHBoxLayout()
            top_row.setContentsMargins(0, 0, 0, 0)
            top_row.setSpacing(14)
            left_panel = QtWidgets.QVBoxLayout()
            left_panel.setContentsMargins(0, 0, 0, 0)
            left_panel.setSpacing(6)
            right_panel = QtWidgets.QVBoxLayout()
            right_panel.setContentsMargins(0, 0, 0, 0)
            right_panel.setSpacing(6)
            runtime_title = QtWidgets.QLabel(tr("settings_runtime"))
            runtime_title.setObjectName("muted")
            runtime_title.setStyleSheet("font-weight:600;")
            left_panel.addWidget(runtime_title)
            runtime_group = QtWidgets.QGroupBox("")
            runtime_layout = QtWidgets.QFormLayout(runtime_group)
            runtime_layout.setLabelAlignment(QtCore.Qt.AlignLeft)
            runtime_layout.setFormAlignment(QtCore.Qt.AlignTop)
            runtime_layout.setVerticalSpacing(8)
            runtime_layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.FieldsStayAtSizeHint)

            def compact_field(widget, width: int = 240):
                widget.setMinimumWidth(150)
                widget.setMaximumWidth(width)
                widget.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
                return widget

            def int_text(value, fallback: int) -> str:
                try:
                    return str(int(float(value)))
                except Exception:
                    return str(int(fallback))

            port_edit = QtWidgets.QLineEdit(str(cfg.get("port", args.port)))
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
            compact_field(port_edit)
            compact_field(retry_edit)
            compact_field(maxsec_edit)
            compact_field(maxbytes_edit)
            compact_field(rate_edit)
            compact_field(parallel_edit, width=120)
            int_validator = QtGui.QIntValidator(0, 999999, dlg)
            parallel_validator = QtGui.QIntValidator(1, 128, dlg)
            retry_edit.setValidator(int_validator)
            maxsec_edit.setValidator(int_validator)
            maxbytes_edit.setValidator(int_validator)
            rate_edit.setValidator(int_validator)
            parallel_edit.setValidator(parallel_validator)
            runtime_layout.addRow(tr("port"), port_edit)
            runtime_layout.addRow(tr("retry"), retry_edit)
            runtime_layout.addRow(tr("max_seconds"), maxsec_edit)
            runtime_layout.addRow(tr("max_bytes"), maxbytes_edit)
            runtime_layout.addRow(tr("rate"), rate_edit)
            runtime_layout.addRow(tr("parallel_sends"), parallel_edit)
            left_panel.addWidget(runtime_group)
            restart_label = QtWidgets.QLabel(tr("settings_restart"))
            restart_label.setObjectName("hint")
            restart_label.setWordWrap(True)
            left_panel.addWidget(restart_label)
            lang_label = QtWidgets.QLabel(tr("language"))
            right_panel.addWidget(lang_label)
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
            right_panel.addLayout(lang_row)
            log_label = QtWidgets.QLabel(tr("log") + " (events)")
            log_label.setObjectName("muted")
            right_panel.addWidget(log_label)
            cb_verbose = QtWidgets.QCheckBox(tr("verbose_events"))
            cb_verbose.setChecked(verbose_log)
            right_panel.addWidget(cb_verbose)
            cb_runtime_log = QtWidgets.QCheckBox(tr("runtime_log_file"))
            cb_runtime_log.setChecked(runtime_log_file)
            right_panel.addWidget(cb_runtime_log)
            discovery_label = QtWidgets.QLabel(tr("discovery"))
            discovery_label.setObjectName("muted")
            right_panel.addWidget(discovery_label)
            cb_discovery_send = QtWidgets.QCheckBox(tr("discovery_send"))
            cb_discovery_send.setChecked(discovery_send)
            right_panel.addWidget(cb_discovery_send)
            cb_discovery_reply = QtWidgets.QCheckBox(tr("discovery_reply"))
            cb_discovery_reply.setChecked(discovery_reply)
            right_panel.addWidget(cb_discovery_reply)
            cb_clear_pending = QtWidgets.QCheckBox(tr("clear_pending_on_switch"))
            cb_clear_pending.setChecked(clear_pending_on_switch)
            right_panel.addWidget(cb_clear_pending)

            top_row.addLayout(left_panel, 1)
            top_row.addLayout(right_panel, 1)
            layout.addLayout(top_row)
            log_view = QtWidgets.QTextEdit()
            log_view.setReadOnly(True)
            set_mono(log_view, 10)
            layout.addWidget(log_view, 2)
            nonlocal settings_log_view
            settings_log_view = log_view
            copy_row = QtWidgets.QHBoxLayout()
            copy_row.setContentsMargins(0, 0, 0, 0)
            copy_row.addStretch(1)
            btn_clear = QtWidgets.QPushButton(tr("clear_log"))
            btn_copy = QtWidgets.QPushButton(tr("copy_log"))
            copy_row.addWidget(btn_clear)
            copy_row.addWidget(btn_copy)
            layout.addLayout(copy_row)
            author_label = QtWidgets.QLabel(
                f"meshTalk v{VERSION}\n"
                f"{tr('about_author')}: Anton Vologzhanin\n"
                f"{tr('about_callsign')}: R3VAF\n"
                f"{tr('about_telegram')}: @peerat33\n"
                f"{tr('about_vision')}\n"
                f"{tr('about_author_position')}\n"
                f"{tr('about_disclaimer')}"
            )
            author_label.setObjectName("muted")
            layout.addWidget(author_label)
            danger_row = QtWidgets.QHBoxLayout()
            danger_row.setContentsMargins(0, 0, 0, 0)
            danger_row.addStretch(1)
            btn_full_reset = QtWidgets.QPushButton(tr("full_reset"))
            btn_full_reset.setStyleSheet(
                "QPushButton { background:#8f1d1d; border:1px solid #c85a5a; color:#ffecec; font-weight:600; }"
                "QPushButton:hover { background:#a82424; }"
            )
            danger_row.addWidget(btn_full_reset)
            layout.addLayout(danger_row)
            buttons = QtWidgets.QDialogButtonBox(
                QtWidgets.QDialogButtonBox.Ok
                | QtWidgets.QDialogButtonBox.Cancel
                | QtWidgets.QDialogButtonBox.Apply
            )
            layout.addWidget(buttons)
            for text, level in log_buffer[-500:]:
                log_append_view(log_view, text, level)

            def parse_int_field(edit: QtWidgets.QLineEdit, default: int) -> int:
                try:
                    raw = edit.text().strip()
                    return int(raw) if raw else int(default)
                except Exception:
                    return int(default)

            def apply_settings(close_dialog: bool) -> None:
                nonlocal verbose_log, runtime_log_file, discovery_send, discovery_reply, clear_pending_on_switch
                verbose_log = cb_verbose.isChecked()
                runtime_log_file = cb_runtime_log.isChecked()
                _STORAGE.set_runtime_log_enabled(runtime_log_file)
                prev_send = discovery_send
                discovery_send = cb_discovery_send.isChecked()
                discovery_reply = cb_discovery_reply.isChecked()
                clear_pending_on_switch = cb_clear_pending.isChecked()
                set_language("ru" if rb_ru.isChecked() else "en", persist=True)
                cfg["port"] = port_edit.text().strip() or "auto"
                cfg["retry_seconds"] = parse_int_field(retry_edit, 30)
                cfg["max_seconds"] = parse_int_field(maxsec_edit, 3600)
                cfg["max_bytes"] = parse_int_field(maxbytes_edit, 200)
                cfg["rate_seconds"] = parse_int_field(rate_edit, 30)
                cfg["parallel_sends"] = max(1, parse_int_field(parallel_edit, 1))
                cfg["discovery_enabled"] = bool(discovery_send and discovery_reply)
                cfg["discovery_send"] = discovery_send
                cfg["discovery_reply"] = discovery_reply
                cfg["runtime_log_file"] = runtime_log_file
                cfg["clear_pending_on_switch"] = clear_pending_on_switch
                save_gui_config()
                if discovery_send and not prev_send:
                    reset_discovery_schedule()
                    ui_emit("log", f"{ts_local()} DISCOVERY: enabled (burst)")
                if close_dialog:
                    dlg.accept()

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
                tracked_peers.clear()
                known_peers.clear()
                peer_states.clear()
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
                # New storage key for encrypted history/state at rest.
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
                runtime_log_file = False
                discovery_send = False
                discovery_reply = False
                clear_pending_on_switch = True
                _STORAGE.set_runtime_log_enabled(runtime_log_file)
                try:
                    args.retry_seconds = 30
                    args.max_seconds = 3600
                    args.max_bytes = 200
                    args.rate_seconds = 30
                    args.parallel_sends = 1
                except Exception:
                    pass
                # Recreate local keypair for current profile.
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
                log_line(f"{ts_local()} RESET: full profile reset completed", "warn")
                QtWidgets.QMessageBox.information(win, "meshTalk", tr("full_reset_done"))
                dlg.accept()
            buttons.accepted.connect(on_accept)
            buttons.rejected.connect(dlg.reject)
            btn_apply = buttons.button(QtWidgets.QDialogButtonBox.Apply)
            if btn_apply is not None:
                btn_apply.clicked.connect(on_apply)
            btn_copy.clicked.connect(on_copy)
            btn_clear.clicked.connect(on_clear)
            btn_full_reset.clicked.connect(on_full_reset)
            dlg.exec()
            settings_log_view = None

        settings_btn.clicked.connect(open_settings)
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
            return (
                s.replace("&", "&amp;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;")
            )

        def make_avatar_pixmap(seed: str, size: int) -> QtGui.QPixmap:
            palette = [
                "#ff6b6b", "#ffa94d", "#ffd43b", "#a9e34b",
                "#4cd4b0", "#38d9a9", "#63e6be", "#4dabf7",
                "#74c0fc", "#9775fa", "#b197fc", "#f783ac",
                "#ff8787", "#ffc078", "#8ce99a", "#5c7cfa",
            ]
            h = hashlib.sha256(seed.encode("utf-8")).digest()
            pm = QtGui.QPixmap(size, size)
            pm.fill(QtCore.Qt.transparent)
            painter = QtGui.QPainter(pm)
            painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
            idx0 = h[0] % len(palette)
            idx1 = (idx0 + 3 + (h[1] % 6)) % len(palette)
            idx2 = (idx1 + 5 + (h[2] % 5)) % len(palette)
            idx3 = (idx2 + 7 + (h[3] % 4)) % len(palette)
            colors = [
                QtGui.QColor(palette[idx0]),
                QtGui.QColor(palette[idx1]),
                QtGui.QColor(palette[idx2]),
                QtGui.QColor(palette[idx3]),
            ]
            rotate = h[7] % 4
            colors = colors[rotate:] + colors[:rotate]
            def solid_brush(c: QtGui.QColor) -> QtGui.QBrush:
                # PySide6 compatibility: avoid QBrush(QColor) ctor path on older builds.
                b = QtGui.QBrush()
                b.setStyle(QtCore.Qt.SolidPattern)
                b.setColor(c)
                return b
            painter.setBrush(solid_brush(colors[0]))
            painter.setPen(QtCore.Qt.NoPen)
            painter.drawEllipse(0, 0, size, size)
            cx = size / 2.0
            cy = size / 2.0
            r = size / 2.0 - 2.0
            base_angle = (h[4] % 360) * math.pi / 180.0
            weights = [1 + (h[8 + i] % 7) for i in range(4)]
            total = float(sum(weights))
            angle = base_angle
            for i in range(4):
                span = (weights[i] / total) * (2.0 * math.pi)
                angle0 = angle
                angle1 = angle + span
                p0 = QtCore.QPointF(cx + r * math.cos(angle0), cy + r * math.sin(angle0))
                p1 = QtCore.QPointF(cx + r * math.cos(angle1), cy + r * math.sin(angle1))
                poly = QtGui.QPolygonF([QtCore.QPointF(cx, cy), p0, p1])
                painter.setBrush(solid_brush(colors[i]))
                painter.drawPolygon(poly)
                angle += span
            ring = QtGui.QPen(QtGui.QColor(255, 255, 255, 60), 1)
            painter.setPen(ring)
            painter.setBrush(QtCore.Qt.NoBrush)
            painter.drawEllipse(1, 1, size - 2, size - 2)
            painter.end()
            return pm

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
            # Blend toward base background, keep a subtle hint of avatar color
            bg_hex = mix_hex(base_bg, accent, 0.12)
            # Text is a lighter blend toward accent
            tx_hex = mix_hex("#eeeeec", accent, 0.35)
            return (bg_hex, tx_hex)

        def color_pair_for_message(seed: str) -> Tuple[str, str]:
            return color_pair_for_id(seed)

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

        def append_html(view: QtWidgets.QTextEdit, text: str, color: str) -> None:
            view.moveCursor(QtGui.QTextCursor.End)
            view.insertHtml(f"<span style='color:{color}'>" + html_escape(text) + "</span><br>")
            view.moveCursor(QtGui.QTextCursor.End)

        def append_chat_entry(
            view: QtWidgets.QTextEdit,
            text: str,
            peer_id: str,
            outgoing: bool,
            row_index: int,
            meta: str = "",
        ) -> None:
            icon = avatar_data_uri(peer_id, 36)
            bg, tx = color_pair_for_message(peer_id)
            if " " in text and len(text) >= 6:
                ts = text[:5]
                msg = text[6:]
            else:
                ts = ""
                msg = text
            ts_html = ""
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
            m_old = re.search(r"\bp(\d+)/(\d+)\b", combined_l)
            if m_old:
                try:
                    if int(m_old.group(1)) < int(m_old.group(2)):
                        pending = True
                except Exception:
                    pass
            m_parts = re.search(r"(?:\bparts\b|\bчасти\b|\bчастей\b)\s+(\d+)\s*/\s*(\d+)", combined_l)
            if m_parts:
                try:
                    if int(m_parts.group(1)) < int(m_parts.group(2)):
                        pending = True
                except Exception:
                    pass
            ts_html = html_escape(combined)
            failed = (
                ("failed (" in combined_l)
                or ("ошибка (" in combined_l)
            )
            text_color = tx
            tag_color = tx
            ts_color = "#ff5a5f" if failed else ("#ff9800" if pending else "#8a7f8b")
            tag = short_tag(peer_id)
            tag_html = html_escape(tag) if tag else "&nbsp;"
            msg_align = "left"
            avatar_cell = (
                f"<td width='46' align='center' valign='top' style='padding:0;' rowspan='2'>"
                f"<div style='display:flex;flex-direction:column;align-items:center;gap:2px;'>"
                f"<img src='{icon}' width='36' height='36'>"
                f"<div style='color:{tag_color};font-size:13px;font-weight:600;line-height:1.0;text-align:center;'>{tag_html}</div>"
                f"</div>"
                f"</td>"
            )
            msg_text_cell = (
                f"<td width='100%' align='{msg_align}' valign='top' style='padding:4px 8px 0 4px;color:{text_color};text-align:{msg_align};line-height:1.25;margin:0;height:100%;'>"
                f"{html_escape(msg)}"
                f"</td>"
            )
            ts_cell = (
                f"<td width='100%' align='right' valign='bottom' style='padding:0 6px 1px 0;color:{ts_color};font-size:10px;line-height:1.0;margin:0;text-align:right;'>"
                f"{ts_html}"
                f"</td>"
            )
            bubble_align = "right" if outgoing else "left"
            bubble_pad = "padding-left:40px;padding-right:0;" if outgoing else "padding-right:40px;padding-left:0;"
            row = (
                f"<table width='100%' style='margin:0;padding:0;border-collapse:collapse;' cellpadding='0' cellspacing='0'>"
                f"<tr><td style='padding:0 0 2px 0;{bubble_pad}'>"
                f"<table width='100%' align='{bubble_align}' cellpadding='0' cellspacing='0' style='border-collapse:collapse;'>"
                f"<tr><td style='background:{bg};padding:6px 0;'>"
                f"<table width='100%' cellpadding='0' cellspacing='0' style='margin:0;padding:0;border-collapse:collapse;height:100%;'>"
                f"<tr>{avatar_cell}{msg_text_cell}</tr>"
                f"<tr>{ts_cell}</tr>"
                f"</table>"
                f"</td></tr></table>"
                f"</td></tr></table>"
            )
            view.moveCursor(QtGui.QTextCursor.End)
            view.insertHtml(row)
            view.moveCursor(QtGui.QTextCursor.End)

        def dialog_title(dialog_id: str) -> str:
            if dialog_id.startswith("group:"):
                return f"{dialog_id[6:]}"
            wire = norm_id_for_wire(dialog_id)
            name = peer_names.get(dialog_id, {})
            long_name = str(name.get("long", "")).strip()
            short_name = str(name.get("short", "")).strip()
            if long_name or short_name:
                second = long_name
                if short_name:
                    second = f"{second} [{short_name}]" if second else f"[{short_name}]"
                return f"{wire}\n{second}"
            return wire

        def short_tag(peer_id: str) -> str:
            name = peer_names.get(peer_id, {})
            short_name = str(name.get("short", "")).strip()
            if short_name:
                return f"{short_name}"
            return ""

        def self_title() -> str:
            if not radio_ready:
                return "Waiting for radio..."
            wire = norm_id_for_wire(self_id)
            name = peer_names.get(self_id, {})
            long_name = str(name.get("long", "")).strip()
            short_name = str(name.get("short", "")).strip()
            second = ""
            if long_name or short_name:
                second = long_name
                if short_name:
                    second = f"{second}[{short_name}]" if second else f"[{short_name}]"
            pub_full = b64e(pub_self_raw) if pub_self_raw else "-----"
            pub_mask = f"{pub_full[:5]}****{pub_full[-5:]}" if len(pub_full) > 10 else pub_full
            return f"Client ID: {wire} {second} pub: {pub_mask}".strip()

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
                        )
                        entry["meta"] = meta
                    append_chat_entry(chat_text, text, peer_id, direction == "out", idx, meta=meta)
                else:
                    line = str(entry)
                    append_html(chat_text, line, "#66d9ef")

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
            items_list.clear()
            now_ts = time.time()
            ordered = sorted(
                dialogs.items(),
                key=lambda kv: float(kv[1].get("last_rx_ts", kv[1].get("last_ts", 0.0))),
                reverse=True,
            )
            list_index.clear()
            filter_text = search_field.text().strip().lower()
            known = (set(known_peers.keys()) | set(peer_states.keys())) - set(hidden_contacts)
            groups_all = set(groups.keys())
            seen = set()

            def make_avatar(seed: str) -> QtGui.QIcon:
                return QtGui.QIcon(make_avatar_pixmap(seed, 36))

            def add_header(title: str) -> None:
                item = QtWidgets.QListWidgetItem(title)
                item.setFlags(QtCore.Qt.ItemIsEnabled)
                item.setForeground(QtGui.QColor("#c0b7c2"))
                font = QtGui.QFont("Ubuntu Mono", 13)
                font.setBold(False)
                item.setFont(font)
                items_list.addItem(item)
                list_index.append(None)

            def lock_state_for_item(item_id: str) -> Optional[str]:
                if item_id.startswith("group:"):
                    return None
                st = get_peer_state(item_id)
                if not st or not st.key_ready:
                    return None
                # Apply persisted peer metadata (if any) to in-memory state for UI purposes.
                meta = peer_meta.get(item_id, {})
                if isinstance(meta, dict):
                    try:
                        ls = meta.get("last_seen_ts")
                        if float(getattr(st, "last_seen_ts", 0.0) or 0.0) <= 0.0 and isinstance(ls, (int, float)) and float(ls) > 0.0:
                            st.last_seen_ts = float(ls)
                    except Exception:
                        pass
                    try:
                        kc = meta.get("key_confirmed_ts")
                        if float(getattr(st, "key_confirmed_ts", 0.0) or 0.0) <= 0.0 and isinstance(kc, (int, float)) and float(kc) > 0.0:
                            st.key_confirmed_ts = float(kc)
                    except Exception:
                        pass
                # Show lock only after confirmed two-way exchange.
                if bool(getattr(st, "await_key_confirm", False)):
                    return None
                if float(getattr(st, "key_confirmed_ts", 0.0) or 0.0) > 0.0:
                    return "ok"
                return None

            def add_item(item_id: str, last_text: str = "") -> None:
                title = dialog_title(item_id)
                if filter_text and filter_text not in title.lower():
                    return
                item = QtWidgets.QListWidgetItem(title)
                size = item.sizeHint()
                base_h = max(64, int(size.height()) + 24)
                item.setSizeHint(QtCore.QSize(size.width(), base_h))
                if item_id.startswith("group:"):
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                bg_hex, tx_hex = color_pair_for_id(item_id)
                item.setBackground(QtGui.QColor(bg_hex))
                item.setForeground(QtGui.QColor(tx_hex))
                item.setIcon(make_avatar(item_id))
                unread = int(dialogs.get(item_id, {}).get("unread", 0) or 0)
                lock_state = lock_state_for_item(item_id)
                seen_h = None
                key_h = None
                if not item_id.startswith("group:"):
                    st = peer_states.get(item_id)
                    if st:
                        try:
                            seen_ts = float(getattr(st, "last_seen_ts", 0.0) or 0.0)
                        except Exception:
                            seen_ts = 0.0
                        if seen_ts > 0.0:
                            seen_h = int(max(0.0, (float(now_ts) - float(seen_ts)) // 3600.0))
                        if lock_state == "ok":
                            try:
                                key_ts = float(getattr(st, "key_confirmed_ts", 0.0) or 0.0)
                            except Exception:
                                key_ts = 0.0
                            if key_ts > 0.0:
                                key_h = int(max(0.0, (float(now_ts) - float(key_ts)) // 3600.0))
                item.setData(
                    QtCore.Qt.UserRole,
                    {
                        "id": item_id,
                        "pinned": item_id in pinned_dialogs,
                        "unread": unread,
                        "lock": lock_state,
                        "seen_h": seen_h,
                        "key_h": key_h,
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
            update_status()
            chat_label.setText(self_title())
            # Keep current dialog visibly highlighted after list rebuild.
            if current_dialog and current_dialog in list_index:
                try:
                    items_list.setCurrentRow(list_index.index(current_dialog))
                except Exception:
                    pass

        def set_language(lang: str, persist: bool = False) -> None:
            nonlocal current_lang
            if lang not in ("ru", "en"):
                lang = "ru"
            current_lang = lang
            if persist:
                save_gui_config()
            apply_language()
            refresh_list()
            render_chat(current_dialog)
            app.processEvents()
            for w in win.findChildren(QtWidgets.QWidget):
                w.update()
                w.repaint()
            win.update()
            win.repaint()
            app.processEvents()
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
            if peer_norm != self_id and st and not st.key_ready:
                st.force_key_req = True
                st.next_key_req_ts = 0.0
                send_key_request(peer_norm)
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
            if not os.path.isfile(HISTORY_FILE):
                return
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception:
                return
            out: list[str] = []
            for line in lines:
                raw = line.rstrip("\n")
                parts = raw.split(" | ", 3)
                if len(parts) < 4:
                    out.append(line)
                    continue
                ts_part, direction, peer_raw, rest = parts
                if peer_raw != old_dialog_id:
                    out.append(line)
                    continue
                if new_dialog_id is None:
                    continue
                out.append(f"{ts_part} | {direction} | {new_dialog_id} | {rest}\n")
            try:
                with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                    f.writelines(out)
            except Exception:
                return

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
            # Purge history file lines for this peer
            def purge_history(peer_norm: str) -> None:
                if not os.path.isfile(HISTORY_FILE):
                    return
                try:
                    with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                except Exception:
                    return
                keep: list[str] = []
                for line in lines:
                    parts = line.rstrip("\n").split(" | ")
                    if len(parts) < 5:
                        keep.append(line)
                        continue
                    peer_raw = parts[2]
                    peer_norm_line = norm_id_for_filename(peer_raw)
                    if peer_norm_line == peer_norm:
                        continue
                    keep.append(line)
                try:
                    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                        f.writelines(keep)
                except Exception:
                    pass

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
            purge_history(peer_id)
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
            send_key_request(peer_id)

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
                st.force_key_req = True
                st.next_key_req_ts = 0.0
            send_key_request(peer_id)
            log_line(f"{ts_local()} KEY: reset for {peer_id}", "warn")

        def chat_line(
            dialog_id: str,
            text: str,
            color: str,
            outgoing: bool = False,
            msg_id: Optional[str] = None,
            meta: str = "",
            meta_data: Optional[Dict[str, object]] = None,
            replace_msg_id: Optional[str] = None,
        ) -> None:
            ts = time.strftime("%H:%M", time.localtime())
            line = f"{ts} {text}"
            history = chat_history.setdefault(dialog_id, [])
            if replace_msg_id:
                for i in range(len(history) - 1, -1, -1):
                    entry = history[i]
                    if isinstance(entry, dict) and entry.get("msg_id") == replace_msg_id:
                        entry["text"] = line
                        if meta:
                            entry["meta"] = meta
                        if meta_data is not None:
                            entry["meta_data"] = dict(meta_data)
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
                append_chat_entry(chat_text, line, peer_id, outgoing, idx, meta=meta)
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
                compression_name = normalize_compression_name(cmp_raw)
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
            if level == "error":
                color = "#f92672"
            elif level == "keyok":
                color = "#ad7fa8"
            elif level == "key":
                color = "#6fdc6f"
            elif level == "warn":
                color = "#fd971f"
            else:
                color = "#8a7f8b"
            append_html(view, text, color)

        def log_line(text: str, level: str = "info") -> None:
            nonlocal errors_need_ack
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
                if ("pinned key mismatch" in low) or ("reject invalid public key" in low):
                    lvl = "error"
                elif ("error" in low) or ("exception" in low) or ("traceback" in low):
                    # Keep it simple: treat traceback/exception/error keywords as errors.
                    lvl = "error"
                elif "keyok:" in low:
                    lvl = "keyok"
                elif "key:" in low:
                    lvl = "key"
            if lvl == "error" and settings_log_view is None:
                errors_need_ack = True
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
            )

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
                queued_ok = 0
                for peer_norm in sorted(groups.get(name, set())):
                    if queue_message(peer_norm, text) is not None:
                        queued_ok += 1
                if queued_ok <= 0:
                    QtWidgets.QMessageBox.information(win, "meshTalk", tr("group_send_none"))
                    return
                chat_line(current_dialog, text, "#fd971f", outgoing=True, meta=format_meta(None, 0, None, None, None))
                append_history("sent", current_dialog, os.urandom(8).hex(), text)
                return
            res = queue_message(current_dialog, text)
            if res is None:
                return
            group_id, total, cmp_name, cmp_eff_pct = res
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
                },
            )

        def update_status() -> None:
            if errors_need_ack:
                set_header_status("error")
            elif radio_ready and not initializing:
                set_header_status("ok")
            else:
                set_header_status("init")

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
                if peer_id.startswith("group:") and peer_id[6:] not in groups:
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
            nonlocal current_lang, verbose_log, runtime_log_file, pinned_dialogs, hidden_contacts, groups
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
                        compression_name = normalize_compression_name(cmp_raw)
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
                elif evt == "self_update":
                    chat_label.setText(self_title())
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
                    peer_names.clear()
                    key_response_last_ts.clear()
                    incoming_state.clear()
                    with pending_lock:
                        pending_by_peer.clear()
                    dialogs.clear()
                    chat_history.clear()
                    list_index.clear()
                    current_dialog = None
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
                add_action(tr("group_rename"), lambda: rename_group(current_id))
                add_action(tr("group_delete"), lambda: delete_group(current_id))
            else:
                if groups:
                    def add_to_group() -> None:
                        gname, ok = QtWidgets.QInputDialog.getItem(win, "meshTalk", tr("group_add"), sorted(groups.keys()), 0, False)
                        if ok and gname:
                            add_peers_to_group_by_name([current_id], str(gname))
                    add_action(tr("group_add"), add_to_group)
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
                    initializing = False
                    refresh_list()
                    chat_label.setText(self_title())
                    radio_loop_running = False
                    return
                chat_label.setText(msg)
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

        win.show()
        return app.exec()

    rc = run_gui_qt()
    if rc >= 0:
        return rc
    print("ERROR: Qt GUI is required (install PySide6). RU: нужен Qt GUI (установите PySide6).")
    return 2


if __name__ == "__main__":
    sys.exit(main())
