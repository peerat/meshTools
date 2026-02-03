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
import sys
import threading
import time
from typing import Dict, Optional, Tuple

from meshtastic.serial_interface import SerialInterface
from pubsub import pub
from meshtastic import portnums_pb2
from serial.tools import list_ports

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


VERSION = "0.1.0"
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


def ts_local() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def ensure_data_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)


def load_state() -> Dict[str, Dict[str, object]]:
    if not os.path.isfile(STATE_FILE):
        return {}
    try:
        import json
        data = json.loads(open(STATE_FILE, "r", encoding="utf-8").read())
        pending = {}
        for item in data.get("pending", []):
            if not isinstance(item, dict):
                continue
            mid = item.get("id")
            if isinstance(mid, str) and mid:
                pending[mid] = item
        return pending
    except Exception:
        return {}


def save_state(pending: Dict[str, Dict[str, object]]) -> None:
    import json
    tmp = STATE_FILE + ".tmp"
    data = {"pending": list(pending.values())}
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, STATE_FILE)


def append_history(direction: str, peer_id: str, msg_id: str, text: str, extra: str = "") -> None:
    line = f"{ts_local()} | {direction} | {peer_id} | {msg_id} | {text}"
    if extra:
        line += f" | {extra}"
    with open(HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


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


def unpack_message(payload: bytes, aes: AESGCM) -> Optional[Tuple[int, bytes, bytes]]:
    if len(payload) < (1 + 1 + 8 + 12 + 16):
        return None
    ver = payload[0]
    if ver != PROTO_VERSION:
        return None
    msg_type = payload[1]
    msg_id = payload[2:10]
    nonce = payload[10:22]
    ct = payload[22:]
    try:
        pt = aes.decrypt(nonce, ct, msg_id)
    except Exception:
        return None
    return (msg_type, msg_id, pt)


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
    ap = argparse.ArgumentParser(
        prog="meshTalk.py",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
    )
    ap.add_argument("-h", "--help", action="store_true", help="show this help message and exit. RU: показать помощь и выйти.")
    ap.add_argument("--version", action="store_true", help="print version and exit. RU: вывести версию и выйти.")

    ap.add_argument("--port", default="auto", help="serial port or 'auto' (default: auto). RU: серийный порт или 'auto' (по умолчанию: auto).")
    ap.add_argument("--channel", type=int, default=None, help="Meshtastic channel index (default: main). RU: индекс канала Meshtastic (по умолчанию: основной).")

    ap.add_argument("--user", default=None, help="peer node ID or key file (id or keyRings/<id>.pub). RU: узел собеседника (id или keyRings/<id>.pub).")

    # self id is auto-detected from radio

    ap.add_argument("--retry-seconds", type=int, default=30, help="retry interval in seconds (default: 30). RU: интервал повторов, сек (по умолчанию: 30).")
    ap.add_argument("--max-seconds", type=int, default=3600, help="max time to wait for ACK (default: 3600). RU: максимум ожидания ACK, сек (по умолчанию: 3600).")
    ap.add_argument("--max-bytes", type=int, default=200, help="max payload bytes per packet (default: 200). RU: максимум байт полезной нагрузки (по умолчанию: 200).")
    ap.add_argument("--rate-seconds", type=float, default=30.0, help="min seconds between sends (default: 30). RU: минимум секунд между отправками (по умолчанию: 30).")


    args = ap.parse_args()

    if args.help:
        ap.print_help()
        return 0
    if args.version:
        print(VERSION)
        return 0


    # Auto-detect port
    if args.port.lower() == "auto":
        detected = detect_serial_port()
        if not detected:
            print("ERROR: no serial ports detected. RU: порты не найдены.")
            return 2
        args.port = detected
    elif args.port == "/dev/ttyUSB0" and sys.platform.startswith("win"):
        detected = detect_serial_port()
        if detected:
            args.port = detected
        else:
            print("ERROR: serial port not found (use --port COMx or --port auto). RU: порт не найден.")
            return 2

    interface = SerialInterface(devPath=args.port)

    self_id_raw = get_self_id(interface)
    if not self_id_raw:
        print("ERROR: cannot detect self id from radio. RU: не могу определить свой id из радио.")
        return 2

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

    if not args.user:
        print("ERROR: --user is required (id or key file). RU: нужен --user (id или ключ).")
        return 2
    peer_path = resolve_peer_path(args.user)

    peer_pub: Optional[x25519.X25519PublicKey] = None
    aes: Optional[AESGCM] = None
    if os.path.isfile(peer_path):
        peer_pub = load_pub(peer_path)
        aes = AESGCM(derive_key(priv, peer_pub))

    ensure_data_dir()
    pending: Dict[str, Dict[str, object]] = load_state()
    pending_lock = threading.Lock()
    seen_msgs: Dict[str, float] = {}
    seen_lock = threading.Lock()
    key_ready = threading.Event()
    if aes:
        key_ready.set()
    rtt_avg = 0.0
    rtt_count = 0
    last_send_ts = 0.0
    next_key_req_ts = 0.0

    def store_peer_pub(peer_id: str, pub_raw: bytes) -> str:
        peer_id_norm = norm_id_for_filename(peer_id)
        path = os.path.join(keydir, f"{peer_id_norm}.pub")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(b64e(pub_raw))
        return path

    def on_receive(packet, interface=None):
        nonlocal aes, rtt_avg, rtt_count
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
            if kind == "req":
                # Save peer pub and respond with our pub
                store_peer_pub(peer_id, pub_raw)
                try:
                    peer_pub_local = x25519.X25519PublicKey.from_public_bytes(pub_raw)
                    aes = AESGCM(derive_key(priv, peer_pub_local))
                    key_ready.set()
                    print(f"KEY: exchange complete with {peer_id}. Encryption active.")
                except Exception:
                    pass
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
                store_peer_pub(peer_id, pub_raw)
                try:
                    peer_pub_local = x25519.X25519PublicKey.from_public_bytes(pub_raw)
                    aes = AESGCM(derive_key(priv, peer_pub_local))
                    key_ready.set()
                    print(f"KEY: exchange complete with {peer_id}. Encryption active.")
                except Exception:
                    pass
            return

        if not aes:
            return

        res = unpack_message(payload, aes)
        if not res:
            return

        msg_type, msg_id, pt = res
        from_id = packet.get("fromId")
        msg_hex = msg_id.hex()

        if msg_type == TYPE_ACK:
            now = time.time()
            with pending_lock:
                rec = pending.pop(msg_hex, None)
                if rec is not None:
                    save_state(pending)
            if rec is not None:
                last_send = rec.get("last_send", 0.0) or 0.0
                attempts = rec.get("attempts", 0) or 0
                rtt = max(0.0, now - float(last_send))
                rtt_count += 1
                rtt_avg = rtt_avg + (rtt - rtt_avg) / float(rtt_count)
                print(f"ACK: {msg_hex} rtt={rtt:.2f}s avg={rtt_avg:.2f}s attempts={attempts}")
                append_history("sent", str(from_id), msg_hex, str(rec.get("text", "")), f"rtt={rtt:.2f}s attempts={attempts}")
            return

        if msg_type == TYPE_MSG:
            msg_key = msg_id.hex()
            with seen_lock:
                last = seen_msgs.get(msg_key)
                now = time.time()
                if last and (now - last) < 3600:
                    # Duplicate, still ACK but no re-print.
                    if from_id:
                        ack_payload = pack_message(TYPE_ACK, msg_id, aes, b"ACK")
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
            if from_id:
                ack_payload = pack_message(TYPE_ACK, msg_id, aes, b"ACK")
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
    print(f"Encryption: {'ACTIVE' if aes else 'WAITING KEY'}")
    print("Type message and press Enter. /keys to rotate keys.")
    if pending:
        print(f"PENDING: {len(pending)} message(s) in queue")

    pub.subscribe(on_receive, "meshtastic.receive.data")

    def regenerate_keys() -> None:
        nonlocal priv, pub_self, pub_self_raw, aes, rtt_avg, rtt_count
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
        aes = None
        key_ready.clear()
        rtt_avg = 0.0
        rtt_count = 0
        print("KEY: regenerated, waiting for exchange.")
        send_key_request(args.user)

    def send_key_request(dest_id: str) -> None:
        dest_id = norm_id_for_wire(dest_id)
        req = KEY_REQ_PREFIX + self_id.encode("utf-8") + b"|" + b64e(pub_self_raw).encode("ascii")
        interface.sendData(
            req,
            destinationId=dest_id,
            wantAck=False,
            portNum=DEFAULT_PORTNUM,
            channelIndex=(args.channel if args.channel is not None else 0),
        )
        print(f"KEY: request sent to {dest_id}")

    def queue_message(text: str) -> None:
        mid = os.urandom(8).hex()
        rec = {
            "id": mid,
            "text": text,
            "created": time.time(),
            "attempts": 0,
            "last_send": 0.0,
        }
        with pending_lock:
            pending[mid] = rec
            save_state(pending)
        append_history("queue", args.user, mid, text)
        print(f"QUEUE: {mid} bytes={len(text.encode('utf-8'))}")

    def send_due() -> None:
        nonlocal last_send_ts, next_key_req_ts
        now = time.time()
        dest_id = norm_id_for_wire(args.user)

        # Key exchange
        if not key_ready.is_set():
            if now >= next_key_req_ts:
                print(f"KEY: request -> {dest_id}")
                send_key_request(dest_id)
                next_key_req_ts = now + max(1.0, float(args.retry_seconds))
            return

        # Rate limit
        if (now - last_send_ts) < float(args.rate_seconds):
            return

        with pending_lock:
            items = list(pending.values())

        if not items:
            return

        # Oldest first
        items.sort(key=lambda r: float(r.get("created", 0.0)))
        for rec in items:
            created = float(rec.get("created", 0.0))
            if (now - created) > float(args.max_seconds):
                with pending_lock:
                    pending.pop(rec["id"], None)
                    save_state(pending)
                print(f"DROP: {rec['id']} timeout")
                append_history("drop", args.user, rec["id"], str(rec.get("text", "")), "timeout")
                continue

            last_send = float(rec.get("last_send", 0.0))
            if (now - last_send) < float(args.retry_seconds):
                continue

            text = str(rec.get("text", ""))
            pt = text.encode("utf-8")
            if len(pt) > max_plain:
                with pending_lock:
                    pending.pop(rec["id"], None)
                    save_state(pending)
                print(f"DROP: {rec['id']} too long")
                append_history("drop", args.user, rec["id"], text, "too_long")
                return

            if not aes:
                return

            payload = pack_message(TYPE_MSG, bytes.fromhex(rec["id"]), aes, pt)
            if len(payload) > args.max_bytes:
                with pending_lock:
                    pending.pop(rec["id"], None)
                    save_state(pending)
                print(f"DROP: {rec['id']} payload too big")
                append_history("drop", args.user, rec["id"], text, "payload_too_big")
                return

            interface.sendData(
                payload,
                destinationId=dest_id,
                wantAck=False,
                portNum=DEFAULT_PORTNUM,
                channelIndex=(args.channel if args.channel is not None else 0),
            )
            rec["attempts"] = int(rec.get("attempts", 0)) + 1
            rec["last_send"] = now
            with pending_lock:
                pending[rec["id"]] = rec
                save_state(pending)
            last_send_ts = now
            print(f"SEND: {rec['id']} attempt={rec['attempts']}")
            append_history("send", args.user, rec["id"], text, f"attempt={rec['attempts']}")
            return

    # If we just generated our keys or peer key is missing, request exchange immediately.
    if (generated_now or not aes):
        req_id = peer_request_id(args.user)
        if req_id:
            print(f"KEY: startup request to {norm_id_for_wire(req_id)}")
            send_key_request(req_id)

    def sender_loop() -> None:
        while True:
            send_due()
            time.sleep(0.2)

    threading.Thread(target=sender_loop, daemon=True).start()

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
            queue_message(line)
    except KeyboardInterrupt:
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
