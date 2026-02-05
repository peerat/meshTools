#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
from typing import Dict, Optional, Tuple

from meshtastic.serial_interface import SerialInterface
from pubsub import pub
from meshtastic import portnums_pb2
from serial.tools import list_ports

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


VERSION = "0.2.0"
PROTO_VERSION = 1
TYPE_MSG = 1
TYPE_ACK = 2
DEFAULT_PORTNUM = portnums_pb2.PortNum.PRIVATE_APP
PAYLOAD_OVERHEAD = 1 + 1 + 8 + 12 + 16  # ver + type + msg_id + nonce + tag
KEY_REQ_PREFIX = b"KR1|"
KEY_RESP_PREFIX = b"KR2|"
DATA_DIR = "meshTalk"
STATE_FILE = os.path.join(DATA_DIR, "state.json")
HISTORY_FILE = os.path.join(DATA_DIR, "history.log")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")


def ts_local() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def ensure_data_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)


def load_state(default_peer: Optional[str] = None) -> Dict[str, Dict[str, Dict[str, object]]]:
    if not os.path.isfile(STATE_FILE):
        return {}
    try:
        import json
        data = json.loads(open(STATE_FILE, "r", encoding="utf-8").read())
        pending: Dict[str, Dict[str, Dict[str, object]]] = {}
        for item in data.get("pending", []):
            if not isinstance(item, dict):
                continue
            mid = item.get("id")
            if isinstance(mid, str) and mid:
                peer = item.get("peer")
                if not isinstance(peer, str) or not peer:
                    peer = default_peer or "default"
                pending.setdefault(peer, {})[mid] = item
        return pending
    except Exception:
        return {}


def save_state(pending_by_peer: Dict[str, Dict[str, Dict[str, object]]]) -> None:
    import json
    tmp = STATE_FILE + ".tmp"
    flat = []
    for peer_id, items in pending_by_peer.items():
        for rec in items.values():
            if isinstance(rec, dict):
                rec = dict(rec)
                rec.setdefault("peer", peer_id)
                flat.append(rec)
    data = {"pending": flat}
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, STATE_FILE)


def append_history(direction: str, peer_id: str, msg_id: str, text: str, extra: str = "") -> None:
    peer_norm = norm_id_for_filename(peer_id)
    line = f"{ts_local()} | {direction} | {peer_norm} | {msg_id} | {text}"
    if extra:
        line += f" | {extra}"
    with open(HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def load_config() -> Dict[str, object]:
    if not os.path.isfile(CONFIG_FILE):
        return {}
    try:
        import json
        return json.loads(open(CONFIG_FILE, "r", encoding="utf-8").read())
    except Exception:
        return {}


def save_config(cfg: Dict[str, object]) -> None:
    import json
    tmp = CONFIG_FILE + ".tmp"
    os.makedirs(os.path.dirname(CONFIG_FILE) or ".", exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False)
    os.replace(tmp, CONFIG_FILE)


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


def pack_message(msg_type: int, msg_id: bytes, aes: AESGCM, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, msg_id)
    return bytes([PROTO_VERSION, msg_type]) + msg_id + nonce + ct


def try_unpack_message(payload: bytes, aes: AESGCM) -> Tuple[str, Optional[int], Optional[bytes], Optional[bytes]]:
    if len(payload) < (1 + 1 + 8 + 12 + 16):
        return ("nope", None, None, None)
    ver = payload[0]
    if ver != PROTO_VERSION:
        return ("nope", None, None, None)
    msg_type = payload[1]
    if msg_type not in (TYPE_MSG, TYPE_ACK):
        return ("nope", None, None, None)
    msg_id = payload[2:10]
    nonce = payload[10:22]
    ct = payload[22:]
    try:
        pt = aes.decrypt(nonce, ct, msg_id)
    except Exception:
        return ("decrypt_fail", msg_type, msg_id, None)
    return ("ok", msg_type, msg_id, pt)


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
        self.pending: Dict[str, Dict[str, object]] = {}
        self.last_send_ts = 0.0
        self.next_key_req_ts = 0.0
        self.rtt_avg = 0.0
        self.rtt_count = 0
        self.force_key_req = False
        self.decrypt_fail_count = 0
        self.last_decrypt_fail_ts = 0.0

    @property
    def key_ready(self) -> bool:
        return self.aes is not None


def resolve_peer_path(peer_arg: str) -> str:
    # If peer_arg is a bare id (no path separators, no .pub), map to keyRings/<id>.pub
    if not peer_arg:
        return peer_arg
    if ("/" not in peer_arg) and ("\\" not in peer_arg) and (not peer_arg.endswith(".pub")):
        return os.path.join("keyRings", f"{norm_id_for_filename(peer_arg)}.pub")
    return peer_arg


def peer_request_id(args_user: Optional[str]) -> Optional[str]:
    if not args_user:
        return None
    if ("/" in args_user) or ("\\" in args_user) or args_user.endswith(".pub"):
        return None
    return args_user


def parse_key_frame(payload: bytes) -> Optional[Tuple[str, str, bytes]]:
    if payload.startswith(KEY_REQ_PREFIX):
        kind = "req"
        rest = payload[len(KEY_REQ_PREFIX):]
    elif payload.startswith(KEY_RESP_PREFIX):
        kind = "resp"
        rest = payload[len(KEY_RESP_PREFIX):]
    else:
        return None
    try:
        peer_id, pub_b64 = rest.split(b"|", 1)
        peer_id_str = peer_id.decode("utf-8", errors="ignore")
        pub_raw = b64d(pub_b64.decode("ascii"))
        return (kind, peer_id_str, pub_raw)
    except Exception:
        return None


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
    cfg_cli = load_config()
    ap = argparse.ArgumentParser(
        prog="meshTalk.py",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
    )
    ap.add_argument("-h", "--help", action="store_true", help="show this help message and exit. RU: показать помощь и выйти.")
    ap.add_argument("--version", action="store_true", help="print version and exit. RU: вывести версию и выйти.")

    ap.add_argument("--port", default=str(cfg_cli.get("port", "auto")), help="serial port or 'auto' (default: auto). RU: серийный порт или 'auto' (по умолчанию: auto).")
    ap.add_argument("--channel", type=int, default=cfg_cli.get("channel", None), help="Meshtastic channel index (default: main). RU: индекс канала Meshtastic (по умолчанию: основной).")

    # self id is auto-detected from radio

    ap.add_argument("--retry-seconds", type=int, default=cfg_cli.get("retry_seconds", 30), help="retry interval in seconds (default: 30). RU: интервал повторов, сек (по умолчанию: 30).")
    ap.add_argument("--max-seconds", type=int, default=cfg_cli.get("max_seconds", 3600), help="max time to wait for ACK (default: 3600). RU: максимум ожидания ACK, сек (по умолчанию: 3600).")
    ap.add_argument("--max-bytes", type=int, default=cfg_cli.get("max_bytes", 200), help="max payload bytes per packet (default: 200). RU: максимум байт полезной нагрузки (по умолчанию: 200).")
    ap.add_argument("--rate-seconds", type=float, default=cfg_cli.get("rate_seconds", 30.0), help="min seconds between sends (default: 30). RU: минимум секунд между отправками (по умолчанию: 30).")


    args = ap.parse_args()

    if args.help:
        ap.print_help()
        return 0
    if args.version:
        print(VERSION)
        return 0


    startup_events = []

    # Auto-detect port
    if args.port.lower() == "auto":
        detected = detect_serial_port()
        if not detected:
            print("ERROR: no serial ports detected. RU: порты не найдены.")
            return 2
        args.port = detected
        startup_events.append(f"{ts_local()} PORT: auto-detected {args.port}")
    elif args.port == "/dev/ttyUSB0" and sys.platform.startswith("win"):
        detected = detect_serial_port()
        if detected:
            args.port = detected
            startup_events.append(f"{ts_local()} PORT: auto-detected {args.port}")
        else:
            print("ERROR: serial port not found (use --port COMx or --port auto). RU: порт не найден.")
            return 2

    interface = SerialInterface(devPath=args.port)
    startup_events.append(f"{ts_local()} PORT: opened {args.port}")

    self_id_raw = get_self_id(interface)
    if not self_id_raw:
        print("ERROR: cannot detect self id from radio. RU: не могу определить свой id из радио.")
        return 2
    startup_events.append(f"{ts_local()} NODE: self id {self_id_raw}")

    keydir = "keyRings"
    self_id = norm_id_for_filename(self_id_raw)
    priv_path = os.path.join(keydir, f"{self_id}.key")
    pub_path = os.path.join(keydir, f"{self_id}.pub")

    # Ensure key files exist (auto-generate if missing)
    generated_now = False
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
        print(f"KEY: auto-generated keys -> {priv_path}, {pub_path}")
        generated_now = True

    priv = load_priv(priv_path)
    pub_self = load_pub(pub_path)
    pub_self_raw = pub_self.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # GUI-only mode: no CLI validation needed

    peer_id_norm, peer_path = (None, None)
    known_peers = load_known_peers(keydir, self_id)
    peer_names: Dict[str, Dict[str, str]] = {}

    def update_peer_names_from_nodes(peer_norm: Optional[str] = None) -> None:
        try:
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

    update_peer_names_from_nodes()

    ensure_data_dir()
    pending_by_peer: Dict[str, Dict[str, Dict[str, object]]] = load_state(default_peer=peer_id_norm)
    pending_lock = threading.Lock()
    seen_msgs: Dict[str, float] = {}
    seen_lock = threading.Lock()
    peer_states: Dict[str, PeerState] = {}
    tracked_peers = set()
    ui_events: "queue.Queue[Tuple[str, object]]" = queue.Queue()
    gui_enabled = True
    last_activity_ts = time.time()
    last_key_sent_ts = 0.0

    def ui_emit(evt: str, payload: object) -> None:
        if gui_enabled:
            ui_events.put((evt, payload))

    if generated_now:
        ui_emit("log", f"{ts_local()} KEY: auto-generated keys -> {priv_path}, {pub_path}")

    def get_peer_state(peer_norm: Optional[str]) -> Optional[PeerState]:
        if not peer_norm:
            return None
        st = peer_states.get(peer_norm)
        if st is None:
            if peer_norm == self_id:
                aes_local = AESGCM(derive_key(priv, pub_self))
                st = PeerState(peer_norm, aes_local)
                peer_states[peer_norm] = st
                return st
            pub = known_peers.get(peer_norm)
            aes_local = AESGCM(derive_key(priv, pub)) if pub else None
            st = PeerState(peer_norm, aes_local)
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

    def store_peer_pub(peer_id: str, pub_raw: bytes) -> str:
        peer_id_norm = norm_id_for_filename(peer_id)
        path = os.path.join(keydir, f"{peer_id_norm}.pub")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(b64e(pub_raw))
        update_peer_pub(peer_id_norm, pub_raw)
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

        # Key exchange frames are plaintext
        key_frame = parse_key_frame(payload)
        if key_frame:
            kind, peer_id, pub_raw = key_frame
            from_id = packet.get("fromId") or peer_id
            peer_norm = norm_id_for_filename(peer_id)
            update_peer_names_from_nodes(peer_norm)
            store_peer_pub(peer_id, pub_raw)
            last_activity_ts = time.time()
            st = get_peer_state(peer_norm)
            if st and st.key_ready:
                print(f"KEY: exchange complete with {peer_id}. Encryption active.")
                ui_emit("log", f"{ts_local()} KEY: exchange complete with {peer_id}. Encryption active.")
                st.force_key_req = False
                st.next_key_req_ts = float("inf")
            if kind == "req":
                ui_emit("log", f"{ts_local()} KEY: request from {peer_id}")
                resp = KEY_RESP_PREFIX + self_id.encode("utf-8") + b"|" + b64e(pub_self_raw).encode("ascii")
                if from_id:
                    interface.sendData(
                        resp,
                        destinationId=from_id,
                        wantAck=False,
                        portNum=DEFAULT_PORTNUM,
                        channelIndex=(args.channel if args.channel is not None else 0),
                    )
                print(f"KEY: received request from {peer_id}, sent our public key.")
            else:
                ui_emit("log", f"{ts_local()} KEY: response from {peer_id}")
            ui_emit("peer_update", peer_norm)
            return

        from_id = packet.get("fromId")
        peer_norm = norm_id_for_filename(from_id) if from_id else None
        update_peer_names_from_nodes(peer_norm)
        st = get_peer_state(peer_norm)
        if not st or not st.aes:
            return

        status, msg_type, msg_id, pt = try_unpack_message(payload, st.aes)
        if status == "decrypt_fail":
            now = time.time()
            st.decrypt_fail_count += 1
            if (st.last_decrypt_fail_ts <= 0.0) or ((now - st.last_decrypt_fail_ts) > 30.0):
                st.last_decrypt_fail_ts = now
                ui_emit(
                    "log",
                    f"{ts_local()} KEY: decrypt failed for {from_id} (possible stale key). Use Reset key.",
                )
                print(f"KEY: decrypt failed for {from_id} (possible stale key).")
            return
        if status != "ok" or msg_type is None or msg_id is None:
            return
        msg_hex = msg_id.hex()

        if msg_type == TYPE_ACK:
            now = time.time()
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
                rtt = max(0.0, now - float(last_send))
                st.rtt_count += 1
                st.rtt_avg = st.rtt_avg + (rtt - st.rtt_avg) / float(st.rtt_count)
                print(f"ACK: {msg_hex} rtt={rtt:.2f}s avg={st.rtt_avg:.2f}s attempts={attempts}")
                append_history("sent", str(from_id), msg_hex, str(rec.get("text", "")), f"rtt={rtt:.2f}s attempts={attempts}")
                ui_emit("log", f"{ts_local()} ACK: {msg_hex} rtt={rtt:.2f}s attempts={attempts}")
            return

        if msg_type == TYPE_MSG:
            msg_key = f"{peer_norm}:{msg_hex}"
            with seen_lock:
                last = seen_msgs.get(msg_key)
                now = time.time()
                if last and (now - last) < 3600:
                    # Duplicate, still ACK but no re-print.
                    if from_id:
                        ack_payload = pack_message(TYPE_ACK, msg_id, st.aes, b"ACK")
                        interface.sendData(
                            ack_payload,
                            destinationId=from_id,
                            wantAck=False,
                            portNum=DEFAULT_PORTNUM,
                            channelIndex=(args.channel if args.channel is not None else 0),
                        )
                    return
                seen_msgs[msg_key] = now
            try:
                text = pt.decode("utf-8", errors="replace")
            except Exception:
                text = repr(pt)
            print(f"RECV from {from_id}: {text}")
            append_history("recv", str(from_id), msg_hex, text)
            last_activity_ts = time.time()
            if peer_norm:
                ui_emit("recv", (peer_norm, text))
            if from_id:
                ack_payload = pack_message(TYPE_ACK, msg_id, st.aes, b"ACK")
                interface.sendData(
                    ack_payload,
                    destinationId=from_id,
                    wantAck=False,
                    portNum=DEFAULT_PORTNUM,
                    channelIndex=(args.channel if args.channel is not None else 0),
                )
            return

    print(f"meshTalk.py v{VERSION}")
    print(f"Port: {args.port} (Windows: COM3 or auto)")
    print("Listening: ON")
    max_plain = max(0, int(args.max_bytes) - PAYLOAD_OVERHEAD)
    print(f"Max plaintext bytes: {max_plain} (payload limit {args.max_bytes}, overhead {PAYLOAD_OVERHEAD})")
    print(f"Rate limit: {args.rate_seconds}s, retry: {args.retry_seconds}s, max: {args.max_seconds}s")

    pub.subscribe(on_receive, "meshtastic.receive.data")

    def regenerate_keys() -> None:
        nonlocal priv, pub_self, pub_self_raw
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
        priv = load_priv(priv_path)
        pub_self = load_pub(pub_path)
        pub_self_raw = pub_self.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        for st in peer_states.values():
            st.aes = None
            st.rtt_avg = 0.0
            st.rtt_count = 0
            st.next_key_req_ts = 0.0
        print("KEY: regenerated, waiting for exchange.")
        ui_emit("log", f"{ts_local()} KEY: regenerated, waiting for exchange.")
        for peer_norm in list(tracked_peers):
            send_key_request(peer_norm)

    def send_key_request(peer_norm: str) -> None:
        nonlocal last_activity_ts, last_key_sent_ts
        if peer_norm == self_id:
            return
        dest_id = wire_id_from_norm(peer_norm)
        req = KEY_REQ_PREFIX + self_id.encode("utf-8") + b"|" + b64e(pub_self_raw).encode("ascii")
        interface.sendData(
            req,
            destinationId=dest_id,
            wantAck=False,
            portNum=DEFAULT_PORTNUM,
            channelIndex=(args.channel if args.channel is not None else 0),
        )
        print(f"{ts_local()} KEY: request sent to {dest_id}")
        last_activity_ts = time.time()
        last_key_sent_ts = last_activity_ts
        ui_emit("log", f"{ts_local()} KEY: request sent to {dest_id}")

    def queue_message(peer_norm: str, text: str) -> None:
        nonlocal last_activity_ts
        peer_norm = norm_id_for_filename(peer_norm)
        st = get_peer_state(peer_norm)
        if not st:
            return
        st.force_key_req = True
        mid = os.urandom(8).hex()
        rec = {
            "id": mid,
            "text": text,
            "created": time.time(),
            "attempts": 0,
            "last_send": 0.0,
            "peer": peer_norm,
        }
        with pending_lock:
            pending_by_peer.setdefault(peer_norm, {})[mid] = rec
            save_state(pending_by_peer)
        append_history("queue", peer_norm, mid, text)
        last_activity_ts = time.time()
        if st.key_ready:
            print(f"QUEUE: {mid} bytes={len(text.encode('utf-8'))}")
        else:
            print(f"WAITING KEY: queued for {peer_norm} id={mid}")
        ui_emit("queued", (peer_norm, text))
        tracked_peers.add(peer_norm)

    global_last_send_ts = 0.0

    def send_due() -> None:
        nonlocal global_last_send_ts
        now = time.time()
        if (now - global_last_send_ts) < float(args.rate_seconds):
            return
        with pending_lock:
            peer_list = set(pending_by_peer.keys())
        peer_list |= set(tracked_peers)

        for peer_norm in sorted(peer_list):
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
                    continue

                last_send = float(rec.get("last_send", 0.0))
                if (now - last_send) < float(args.retry_seconds):
                    continue

                text = str(rec.get("text", ""))
                pt = text.encode("utf-8")
                if len(pt) > max_plain:
                    with pending_lock:
                        pending_by_peer.get(peer_norm, {}).pop(rec["id"], None)
                        if not pending_by_peer.get(peer_norm):
                            pending_by_peer.pop(peer_norm, None)
                        save_state(pending_by_peer)
                    print(f"DROP: {rec['id']} too long")
                    append_history("drop", peer_norm, rec["id"], text, "too_long")
                    ui_emit("log", f"{ts_local()} DROP: {rec['id']} too long for {peer_norm}")
                    return

                if not st.aes:
                    return

                payload = pack_message(TYPE_MSG, bytes.fromhex(rec["id"]), st.aes, pt)
                if len(payload) > args.max_bytes:
                    with pending_lock:
                        pending_by_peer.get(peer_norm, {}).pop(rec["id"], None)
                        if not pending_by_peer.get(peer_norm):
                            pending_by_peer.pop(peer_norm, None)
                        save_state(pending_by_peer)
                    print(f"DROP: {rec['id']} payload too big")
                    append_history("drop", peer_norm, rec["id"], text, "payload_too_big")
                    ui_emit("log", f"{ts_local()} DROP: {rec['id']} payload too big for {peer_norm}")
                    return

                interface.sendData(
                    payload,
                    destinationId=wire_id_from_norm(peer_norm),
                    wantAck=False,
                    portNum=DEFAULT_PORTNUM,
                    channelIndex=(args.channel if args.channel is not None else 0),
                )
                rec["attempts"] = int(rec.get("attempts", 0)) + 1
                rec["last_send"] = now
                with pending_lock:
                    pending_by_peer.setdefault(peer_norm, {})[rec["id"]] = rec
                    save_state(pending_by_peer)
                global_last_send_ts = now
                print(f"SEND: {rec['id']} attempt={rec['attempts']}")
                append_history("send", peer_norm, rec["id"], text, f"attempt={rec['attempts']}")
                ui_emit("log", f"{ts_local()} SEND: {rec['id']} attempt={rec['attempts']} -> {peer_norm}")
                return

    # If we just generated our keys or peer key is missing, request exchange immediately.
    if peer_id_norm:
        st = get_peer_state(peer_id_norm)
        if generated_now or (st is not None and not st.key_ready):
            print(f"{ts_local()} KEY: startup request to {wire_id_from_norm(peer_id_norm)}")
            send_key_request(peer_id_norm)
            if st:
                st.next_key_req_ts = time.time() + max(1.0, float(args.retry_seconds))

    def sender_loop() -> None:
        while True:
            send_due()
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
                "select_peers": "Select peers from Contacts first.",
                "log": "Log",
                "verbose_events": "Verbose events",
                "pin": "Pin",
                "unpin": "Unpin",
                "group_rename": "Rename group",
                "group_delete": "Delete group",
                "group_delete_confirm": "Delete group '{name}'?",
                "group_exists": "Group already exists.",
                "group_rename_failed": "Group not found.",
                "pinned": "Pinned",
                "recent": "Contact list",
                "peer_delete": "Delete contact",
                "peer_delete_confirm": "Delete contact '{name}'?",
                "group_add": "Add selected to group",
                "actions": "Actions",
                "key_request": "Request key",
                "key_reset": "Reset key",
                "settings_runtime": "Runtime settings",
                "settings_restart": "Applies after restart",
                "port": "Port",
                "channel": "Channel",
                "retry": "Retry seconds",
                "max_seconds": "Max seconds",
                "max_bytes": "Max bytes",
                "rate": "Rate seconds",
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
                "select_peers": "Сначала выберите контакты.",
                "log": "Лог",
                "verbose_events": "Подробные события",
                "pin": "Закрепить",
                "unpin": "Открепить",
                "group_rename": "Переименовать группу",
                "group_delete": "Удалить группу",
                "group_delete_confirm": "Удалить группу '{name}'?",
                "group_exists": "Группа уже существует.",
                "group_rename_failed": "Группа не найдена.",
                "pinned": "Закреплённые",
                "recent": "Список контактов",
                "peer_delete": "Удалить собеседника",
                "peer_delete_confirm": "Удалить собеседника '{name}'?",
                "group_add": "Добавить выделенных в группу",
                "actions": "Действия",
                "key_request": "Запросить ключ",
                "key_reset": "Сбросить ключ",
                "settings_runtime": "Параметры запуска",
                "settings_restart": "Применятся после перезапуска",
                "port": "Порт",
                "channel": "Канал",
                "retry": "Повтор, сек",
                "max_seconds": "Макс ожидание, сек",
                "max_bytes": "Макс байт",
                "rate": "Мин интервал, сек",
            },
        }
        cfg = load_config()
        log_startup = []
        log_startup.append(f"{ts_local()} CFG: loaded config")
        for line in startup_events:
            log_startup.append(line)
        current_lang = str(cfg.get("lang", "ru")).lower()
        verbose_log = bool(cfg.get("log_verbose", True))
        pinned_dialogs = set(cfg.get("pinned_dialogs", []))
        hidden_contacts = set(cfg.get("hidden_contacts", []))
        groups_cfg = cfg.get("groups", {}) if isinstance(cfg.get("groups", {}), dict) else {}
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
        chat_label = QtWidgets.QLabel("")
        chat_label.setObjectName("section")
        set_mono(chat_label, 13)
        chat_label.setFixedHeight(32)
        chat_label.setAlignment(QtCore.Qt.AlignCenter)
        chat_label.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        settings_spacer = QtWidgets.QSpacerItem(10, 10, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        settings_btn = QtWidgets.QPushButton(tr("settings"))
        settings_btn.setFixedHeight(32)
        settings_row.addWidget(chat_label, 0)
        settings_row.addItem(settings_spacer)
        settings_row.addWidget(settings_btn)
        right_col.addLayout(settings_row, 0)
        chat_text = QtWidgets.QTextEdit()
        chat_text.setReadOnly(True)
        set_mono(chat_text)
        right_col.addWidget(chat_text, 4)

        msg_entry = QtWidgets.QLineEdit()
        set_mono(msg_entry)
        msg_entry.setPlaceholderText(tr("message"))
        send_btn = QtWidgets.QPushButton(tr("send"))
        msg_row = QtWidgets.QHBoxLayout()
        msg_row.setContentsMargins(0, 0, 0, 0)
        msg_row.setSpacing(0)
        msg_row.addWidget(msg_entry, 1)
        msg_row.addWidget(send_btn)
        right_col.addLayout(msg_row, 0)

        # Ubuntu terminal-like theme (flat, no frames)
        win.setStyleSheet(
            """
            QWidget { background: #300a24; color: #eeeeec; }
            QGroupBox { border: 0; margin-top: 0; font-weight: 600; }
            QGroupBox::title { subcontrol-origin: margin; left: 4px; color: #cfcfcf; }
            QGroupBox#listGroup::title { height: 0px; }
            QGroupBox#listGroup { margin-top: 0px; }
            QListWidget { background: #2b0a22; border: 1px solid #3c0f2e; padding: 6px; }
            QTextEdit { background: #35102a; border: 1px solid #3c0f2e; padding: 6px; }
            QLineEdit { background: #2b0a22; border: 1px solid #6f4a7a; padding: 6px; }
            QPushButton { background: #5c3566; border: 1px solid #6f4a7a; padding: 6px 10px; }
            QPushButton:hover { background: #6f4a7a; }
            QLabel#muted { color: #c0b7c2; }
            QLabel#section { color: #c0b7c2; font-size: 13px; font-weight: 400; }
            QListWidget::item { padding: 4px 6px; }
            QListWidget::item:selected { background: #3a0f2c; }
            """
        )

        groups: Dict[str, set] = {k: set(v) for k, v in groups_cfg.items() if isinstance(k, str) and isinstance(v, list)}
        dialogs: Dict[str, Dict[str, object]] = {}
        chat_history: Dict[str, list] = {}
        list_index: list[Optional[str]] = []
        current_dialog: Optional[str] = None

        def save_gui_config() -> None:
            save_config(
                {
                    "lang": current_lang,
                    "log_verbose": verbose_log,
                    "pinned_dialogs": sorted(pinned_dialogs),
                    "hidden_contacts": sorted(hidden_contacts),
                    "groups": {k: sorted(list(v)) for k, v in groups.items()},
                    "port": cfg.get("port", args.port),
                    "channel": cfg.get("channel", args.channel),
                    "retry_seconds": cfg.get("retry_seconds", args.retry_seconds),
                    "max_seconds": cfg.get("max_seconds", args.max_seconds),
                    "max_bytes": cfg.get("max_bytes", args.max_bytes),
                    "rate_seconds": cfg.get("rate_seconds", args.rate_seconds),
                }
            )

        def apply_language() -> None:
            list_group.setTitle("")
            chat_label.setText(self_title())
            msg_entry.setPlaceholderText(tr("message"))
            settings_btn.setText(tr("settings"))
            send_btn.setText(tr("send"))
            search_field.setPlaceholderText(tr("search"))

        settings_log_view: Optional["QtWidgets.QTextEdit"] = None

        def open_settings() -> None:
            nonlocal current_lang
            nonlocal verbose_log
            dlg = QtWidgets.QDialog(win)
            dlg.setWindowTitle(tr("settings_title"))
            dlg.resize(700, 560)
            layout = QtWidgets.QVBoxLayout(dlg)
            runtime_title = QtWidgets.QLabel(tr("settings_runtime"))
            runtime_title.setObjectName("muted")
            runtime_title.setStyleSheet("font-weight:600;")
            layout.addWidget(runtime_title)
            runtime_group = QtWidgets.QGroupBox("")
            runtime_layout = QtWidgets.QFormLayout(runtime_group)
            runtime_layout.setLabelAlignment(QtCore.Qt.AlignLeft)
            runtime_layout.setFormAlignment(QtCore.Qt.AlignTop)
            runtime_layout.setVerticalSpacing(8)
            port_edit = QtWidgets.QLineEdit(str(cfg.get("port", args.port)))
            channel_default = 0 if args.channel is None else args.channel
            channel_edit = QtWidgets.QLineEdit(str(cfg.get("channel", channel_default)))
            retry_edit = QtWidgets.QLineEdit(str(cfg.get("retry_seconds", args.retry_seconds)))
            maxsec_edit = QtWidgets.QLineEdit(str(cfg.get("max_seconds", args.max_seconds)))
            maxbytes_edit = QtWidgets.QLineEdit(str(cfg.get("max_bytes", args.max_bytes)))
            rate_edit = QtWidgets.QLineEdit(str(cfg.get("rate_seconds", args.rate_seconds)))
            runtime_layout.addRow(tr("port"), port_edit)
            runtime_layout.addRow(tr("channel"), channel_edit)
            runtime_layout.addRow(tr("retry"), retry_edit)
            runtime_layout.addRow(tr("max_seconds"), maxsec_edit)
            runtime_layout.addRow(tr("max_bytes"), maxbytes_edit)
            runtime_layout.addRow(tr("rate"), rate_edit)
            layout.addWidget(runtime_group)
            restart_label = QtWidgets.QLabel(tr("settings_restart"))
            restart_label.setObjectName("muted")
            layout.addWidget(restart_label)
            lang_label = QtWidgets.QLabel(tr("language"))
            layout.addWidget(lang_label)
            rb_ru = QtWidgets.QRadioButton(tr("lang_ru"))
            rb_en = QtWidgets.QRadioButton(tr("lang_en"))
            if current_lang == "en":
                rb_en.setChecked(True)
            else:
                rb_ru.setChecked(True)
            layout.addWidget(rb_ru)
            layout.addWidget(rb_en)
            log_label = QtWidgets.QLabel(tr("log") + " (events)")
            log_label.setObjectName("muted")
            layout.addWidget(log_label)
            cb_verbose = QtWidgets.QCheckBox(tr("verbose_events"))
            cb_verbose.setChecked(verbose_log)
            layout.addWidget(cb_verbose)
            log_view = QtWidgets.QTextEdit()
            log_view.setReadOnly(True)
            set_mono(log_view, 10)
            layout.addWidget(log_view, 2)
            nonlocal settings_log_view
            settings_log_view = log_view
            buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
            layout.addWidget(buttons)
            for text, level in log_buffer[-500:]:
                log_append_view(log_view, text, level)
            def on_accept():
                verbose_log = cb_verbose.isChecked()
                set_language("ru" if rb_ru.isChecked() else "en", persist=True)
                cfg["port"] = port_edit.text().strip() or "auto"
                cfg["channel"] = int(channel_edit.text().strip()) if channel_edit.text().strip() else 0
                cfg["retry_seconds"] = int(retry_edit.text().strip()) if retry_edit.text().strip() else 30
                cfg["max_seconds"] = int(maxsec_edit.text().strip()) if maxsec_edit.text().strip() else 3600
                cfg["max_bytes"] = int(maxbytes_edit.text().strip()) if maxbytes_edit.text().strip() else 200
                cfg["rate_seconds"] = float(rate_edit.text().strip()) if rate_edit.text().strip() else 30.0
                save_gui_config()
                dlg.accept()
            buttons.accepted.connect(on_accept)
            buttons.rejected.connect(dlg.reject)
            dlg.exec()
            settings_log_view = None

        settings_btn.clicked.connect(open_settings)

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
            painter.setBrush(QtGui.QBrush(colors[0]))
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
                painter.setBrush(QtGui.QBrush(colors[i]))
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
        ) -> None:
            icon = avatar_data_uri(peer_id, 36)
            align = "right" if outgoing else "left"
            bg, tx = color_pair_for_id(peer_id)
            if " " in text and len(text) >= 6:
                ts = text[:5]
                msg = text[6:]
            else:
                ts = ""
                msg = text
            tag = short_tag(peer_id)
            row = (
                f"<table width='100%' style='background:{bg};' cellpadding='0' cellspacing='0'><tr>"
                f"<td width='40' align='left' valign='middle' style='padding:4px 0;'>"
                f"<img src='{icon}' width='36' height='36'></td>"
                f"<td align='left' valign='middle' style='padding:4px 0;'>"
                f"<div style='color:{tx}'>{html_escape(tag + msg)}</div>"
                f"<div style='color:#8a7f8b;font-size:10px;text-align:right'>{html_escape(ts)}</div>"
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
                return f"[{short_name}] "
            return ""

        def self_title() -> str:
            wire = norm_id_for_wire(self_id)
            name = peer_names.get(self_id, {})
            long_name = str(name.get("long", "")).strip()
            short_name = str(name.get("short", "")).strip()
            if long_name or short_name:
                second = long_name
                if short_name:
                    second = f"{second} [{short_name}]" if second else f"[{short_name}]"
                return f"{wire} {second}"
            return wire

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
            for idx, entry in enumerate(chat_history.get(dialog_id, [])):
                if isinstance(entry, dict):
                    text = str(entry.get("text", ""))
                    direction = str(entry.get("dir", "in"))
                    peer_id = self_id if direction == "out" else dialog_id
                    append_chat_entry(chat_text, text, peer_id, direction == "out", idx)
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

            def add_item(item_id: str, last_text: str = "") -> None:
                title = dialog_title(item_id)
                if filter_text and filter_text not in title.lower():
                    return
                item = QtWidgets.QListWidgetItem(title)
                if "\n" in title:
                    size = item.sizeHint()
                    item.setSizeHint(QtCore.QSize(size.width(), int(size.height() * 1.8)))
                if item_id.startswith("group:"):
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                bg_hex, tx_hex = color_pair_for_id(item_id)
                item.setBackground(QtGui.QColor(bg_hex))
                item.setForeground(QtGui.QColor(tx_hex))
                item.setIcon(make_avatar(item_id))
                unread = int(dialogs.get(item_id, {}).get("unread", 0) or 0)
                item.setData(QtCore.Qt.UserRole, {"id": item_id, "pinned": item_id in pinned_dialogs, "unread": unread})
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

        def set_language(lang: str, persist: bool = False) -> None:
            nonlocal current_lang
            if lang not in ("ru", "en"):
                lang = "ru"
            current_lang = lang
            if persist:
                save_gui_config()
            apply_language()
            refresh_list()
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

        def chat_line(dialog_id: str, text: str, color: str, outgoing: bool = False) -> None:
            ts = time.strftime("%H:%M", time.localtime())
            line = f"{ts} {text}"
            chat_history.setdefault(dialog_id, []).append({"text": line, "dir": "out" if outgoing else "in"})
            update_dialog(dialog_id, line, recv=not outgoing)
            if not outgoing and current_dialog != dialog_id:
                rec = dialogs.get(dialog_id) or {}
                rec["unread"] = int(rec.get("unread", 0) or 0) + 1
                dialogs[dialog_id] = rec
            refresh_list()
            if current_dialog == dialog_id:
                peer_id = self_id if outgoing else dialog_id
                idx = len(chat_history.get(dialog_id, [])) - 1
                append_chat_entry(chat_text, line, peer_id, outgoing, idx)
            update_status()

        log_buffer: list[tuple[str, str]] = []
        for line in log_startup:
            log_buffer.append((line, "info"))

        def log_append_view(view: QtWidgets.QTextEdit, text: str, level: str) -> None:
            color = "#9ecbff" if level == "info" else "#e6db74"
            if level == "error":
                color = "#f92672"
            append_html(view, text, color)

        def log_line(text: str, level: str = "info") -> None:
            log_buffer.append((text, level))
            if settings_log_view is not None:
                log_append_view(settings_log_view, text, level)
            update_status()

        def send_message() -> None:
            text = msg_entry.text().strip()
            if not text:
                return
            msg_entry.clear()
            if not current_dialog:
                QtWidgets.QMessageBox.information(win, "meshTalk", tr("select_dialog"))
                return
            if current_dialog.startswith("group:"):
                name = current_dialog[6:]
                for peer_norm in sorted(groups.get(name, set())):
                    queue_message(peer_norm, text)
                chat_line(current_dialog, text, "#fd971f", outgoing=True)
                append_history("send", current_dialog, str(int(time.time() * 1000)), text)
                return
            queue_message(current_dialog, text)
            chat_line(current_dialog, text, "#a6e22e", outgoing=True)

        def update_status() -> None:
            # Status is shown in Settings dialog; no-op placeholder for compatibility.
            return

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
            for line in lines:
                parts = line.rstrip("\n").split(" | ")
                if len(parts) < 5:
                    continue
                direction = parts[1]
                peer_id = parts[2]
                peer_norm = norm_id_for_filename(peer_id)
                if peer_id.startswith("group:") and peer_id[6:] not in groups:
                    continue
                text = parts[4]
                ts_part = parts[0]
                time_only = ts_part.split(" ")[1][:5] if " " in ts_part else ts_part[:5]
                dialog_id = peer_id if peer_id.startswith("group:") else peer_norm
                dir_flag = "out" if direction in ("send", "sent") else "in"
                chat_history.setdefault(dialog_id, []).append({"text": f"{time_only} {text}", "dir": dir_flag})
                update_dialog(dialog_id, text, recv=(dir_flag == "in"))

        def process_ui_events() -> None:
            while True:
                try:
                    evt, payload = ui_events.get_nowait()
                except queue.Empty:
                    break
                if evt == "peer_update":
                    refresh_list()
                elif evt == "recv":
                    from_id, text = payload
                    peer_norm = norm_id_for_filename(from_id)
                    if peer_norm:
                        chat_line(peer_norm, text, "#66d9ef")
                elif evt == "queued":
                    peer_norm, text = payload
                    log_line(f"QUEUE -> {peer_norm}: {text}", "info")
                elif evt == "log":
                    log_line(str(payload), "warn")
            update_status()

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
                add_action(tr("key_reset"), lambda: reset_peer_key(current_id))
                add_action(tr("peer_delete"), lambda: delete_peer(current_id))

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
        msg_entry.returnPressed.connect(send_message)

        load_history()
        refresh_list()
        log_line(f"{ts_local()} GUI: started | port={args.port} | self={self_id}", "info")
        log_line(f"{ts_local()} RADIO: listening ON", "info")
        update_status()

        timer = QtCore.QTimer()
        timer.timeout.connect(process_ui_events)
        timer.start(200)

        win.show()
        return app.exec()

    def run_gui_tk() -> int:
        print("ERROR: Tkinter GUI is disabled. RU: Tkinter GUI отключён.")
        return 2

    rc = run_gui_qt()
    if rc >= 0:
        return rc
    print("ERROR: Qt GUI is required (install PySide6). RU: нужен Qt GUI (установите PySide6).")
    return 2


if __name__ == "__main__":
    sys.exit(main())
