#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import sys
import threading
import time
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from meshtalk.utils import (
    HISTORY_TEXT_ENC_PREFIX,
    HISTORY_TEXT_PREFIX,
    encode_history_text,
    parse_history_line,
    set_history_encryption_key,
)


HISTORY_META_PREFIX = "meta64:"
HISTORY_META_MAX_BYTES = 8192
STORAGE_BACKEND_FILE = "file"
STORAGE_BACKEND_KEYRING = "keyring"
STORAGE_BACKEND_AUTO = "auto"
_WIN_ACL_DONE: set[str] = set()
_WIN_ACL_LOCK = threading.Lock()


def _win_acl_enabled() -> bool:
    raw = str(os.environ.get("MESHTALK_WIN_ACL", "1") or "1").strip().lower()
    return raw not in ("0", "off", "false", "no")


def maybe_set_private_umask() -> None:
    # Best-effort: make newly created files private on POSIX.
    if sys.platform.startswith("win"):
        return
    try:
        os.umask(0o077)
    except Exception:
        pass


def harden_dir(path: str) -> None:
    if not path:
        return
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        return
    if sys.platform.startswith("win"):
        if not _win_acl_enabled():
            return
        _harden_windows_acl(path)
        return
    try:
        os.chmod(path, 0o700)
    except Exception:
        pass


def harden_file(path: str) -> None:
    if not path:
        return
    if sys.platform.startswith("win"):
        if not _win_acl_enabled():
            return
        _harden_windows_acl(path)
        return
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def _harden_windows_acl(path: str) -> None:
    if not path or (not sys.platform.startswith("win")):
        return
    try:
        abs_path = os.path.abspath(path)
    except Exception:
        abs_path = str(path)
    try:
        with _WIN_ACL_LOCK:
            if abs_path in _WIN_ACL_DONE:
                return
    except Exception:
        pass
    user = str(os.environ.get("USERNAME", "") or "").strip()
    if not user:
        return
    try:
        creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0) or 0)
        startupinfo = None
        if hasattr(subprocess, "STARTUPINFO") and hasattr(subprocess, "STARTF_USESHOWWINDOW"):
            try:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            except Exception:
                startupinfo = None
        subprocess.run(
            [
                "icacls",
                abs_path,
                "/inheritance:r",
                "/grant:r",
                f"{user}:F",
                "SYSTEM:F",
                "Administrators:F",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            startupinfo=startupinfo,
            creationflags=creationflags,
        )
        try:
            with _WIN_ACL_LOCK:
                _WIN_ACL_DONE.add(abs_path)
        except Exception:
            pass
    except Exception:
        pass


def _storage_backend_mode() -> str:
    raw = str(os.environ.get("MESHTALK_STORAGE_BACKEND", STORAGE_BACKEND_FILE) or STORAGE_BACKEND_FILE).strip().lower()
    if raw in (STORAGE_BACKEND_FILE, STORAGE_BACKEND_KEYRING, STORAGE_BACKEND_AUTO):
        return raw
    return STORAGE_BACKEND_FILE


def _keyring_slot(keydir: str) -> str:
    full = os.path.abspath(str(keydir or ""))
    digest = hashlib.sha256(full.encode("utf-8", errors="replace")).hexdigest()[:24]
    return f"profile:{digest}"


def _keyring_load_storage_key(keydir: str) -> Optional[bytes]:
    try:
        import keyring  # type: ignore
    except Exception:
        return None
    try:
        token = keyring.get_password("meshTalk.storage", _keyring_slot(keydir))
    except Exception:
        return None
    if not token:
        return None
    try:
        raw = base64.b64decode(str(token).encode("ascii"), validate=True)
        if len(raw) == 32:
            return raw
    except Exception:
        return None
    return None


def _keyring_store_storage_key(keydir: str, raw_key: bytes) -> bool:
    try:
        import keyring  # type: ignore
    except Exception:
        return False
    try:
        keyring.set_password(
            "meshTalk.storage",
            _keyring_slot(keydir),
            base64.b64encode(bytes(raw_key)).decode("ascii"),
        )
        return True
    except Exception:
        return False


def _storage_encrypt_str(value: object, key: Optional[bytes], aad: bytes) -> object:
    if value is None:
        return value
    if not key:
        raise ValueError("storage key is not available")
    text = str(value)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, text.encode("utf-8"), aad)
    return HISTORY_TEXT_ENC_PREFIX + base64.b64encode(nonce + ct).decode("ascii")


def _storage_decrypt_str(value: object, key: Optional[bytes], aad: bytes) -> object:
    if not isinstance(value, str):
        return value
    if not value.startswith(HISTORY_TEXT_ENC_PREFIX):
        return value
    if not key:
        return ""
    payload = value[len(HISTORY_TEXT_ENC_PREFIX):]
    try:
        raw = base64.b64decode(payload.encode("ascii"), validate=True)
        if len(raw) < (12 + 16):
            return ""
        nonce = raw[:12]
        ct = raw[12:]
        pt = AESGCM(key).decrypt(nonce, ct, aad)
        return pt.decode("utf-8", errors="replace")
    except Exception:
        return ""


def encode_history_meta_token(meta_data: Optional[Dict[str, object]]) -> str:
    if not isinstance(meta_data, dict) or not meta_data:
        return ""
    try:
        import json

        raw = json.dumps(meta_data, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(raw) > int(HISTORY_META_MAX_BYTES):
            return ""
        return HISTORY_META_PREFIX + base64.b64encode(raw).decode("ascii")
    except Exception:
        return ""


def decode_history_meta_token(token: str) -> Optional[Dict[str, object]]:
    if not isinstance(token, str):
        return None
    payload = token.strip()
    if not payload.startswith(HISTORY_META_PREFIX):
        return None
    payload = payload[len(HISTORY_META_PREFIX):].strip()
    if not payload:
        return None
    try:
        raw = base64.b64decode(payload.encode("ascii"), validate=True)
        if len(raw) > int(HISTORY_META_MAX_BYTES):
            return None
        import json

        data = json.loads(raw.decode("utf-8", errors="replace"))
        if isinstance(data, dict):
            return data
    except Exception:
        return None
    return None


def parse_history_record_line(
    line: str,
) -> Optional[Tuple[str, str, str, str, str, Optional[Dict[str, object]]]]:
    if not isinstance(line, str):
        return None
    parts = line.rstrip("\n").split(" | ")
    if len(parts) < 5:
        return None
    base_line = " | ".join(parts[:5])
    parsed = parse_history_line(base_line, strict_encoded=True)
    if parsed is None:
        # Backward compatibility: legacy history rows could store plain text
        # without b64/enc prefix. Keep strict behavior for malformed b64 payloads.
        text_wire = str(parts[4] or "")
        if text_wire.startswith(HISTORY_TEXT_PREFIX) or text_wire.startswith(HISTORY_TEXT_ENC_PREFIX):
            return None
        # Parse full legacy line first to preserve plain text that may contain
        # " | " separators.
        parsed = parse_history_line(line.rstrip("\n"), strict_encoded=False)
        if parsed is None:
            parsed = parse_history_line(base_line, strict_encoded=False)
    if parsed is None:
        return None
    meta_data: Optional[Dict[str, object]] = None
    for token in parts[5:]:
        decoded = decode_history_meta_token(token)
        if isinstance(decoded, dict):
            meta_data = decoded
            break
    ts_part, direction, peer_id, msg_id, text = parsed
    return (ts_part, direction, peer_id, msg_id, text, meta_data)


class Storage:
    def __init__(
        self,
        config_file: str,
        state_file: str,
        history_file: str,
        incoming_file: str,
        runtime_log_file: str,
        keydir: str,
    ) -> None:
        self.config_file = config_file
        self.state_file = state_file
        self.history_file = history_file
        self.incoming_file = incoming_file
        self.runtime_log_file = runtime_log_file
        self.keydir = keydir
        self.storage_key_file = os.path.join(keydir, "storage.key") if keydir else ""
        self.storage_key: Optional[bytes] = None
        self.runtime_log_enabled = False
        self._runtime_log_lock = threading.Lock()
        self._history_lock = threading.Lock()

    def set_paths(
        self,
        config_file: str,
        state_file: str,
        history_file: str,
        incoming_file: str,
        runtime_log_file: str,
        keydir: str,
    ) -> None:
        self.config_file = config_file
        self.state_file = state_file
        self.history_file = history_file
        self.incoming_file = incoming_file
        self.runtime_log_file = runtime_log_file
        self.keydir = keydir
        self.storage_key_file = os.path.join(keydir, "storage.key") if keydir else ""
        self.storage_key = None
        set_history_encryption_key(None)

    def set_runtime_log_enabled(self, enabled: bool) -> None:
        self.runtime_log_enabled = bool(enabled)

    def ensure_storage_key(self) -> Optional[bytes]:
        if self.storage_key:
            return self.storage_key
        mode = _storage_backend_mode()
        keydir_here = str(self.keydir or "")
        if mode in (STORAGE_BACKEND_KEYRING, STORAGE_BACKEND_AUTO) and keydir_here:
            kr_raw = _keyring_load_storage_key(keydir_here)
            if isinstance(kr_raw, (bytes, bytearray)) and len(bytes(kr_raw)) == 32:
                self.storage_key = bytes(kr_raw)
                set_history_encryption_key(self.storage_key)
                return self.storage_key
            if mode == STORAGE_BACKEND_KEYRING:
                try:
                    raw_new = os.urandom(32)
                    if _keyring_store_storage_key(keydir_here, raw_new):
                        self.storage_key = raw_new
                        set_history_encryption_key(raw_new)
                        return self.storage_key
                except Exception:
                    pass
                return None
        if not self.storage_key_file:
            return None
        harden_dir(os.path.dirname(self.storage_key_file) or ".")
        # Load existing key
        try:
            if os.path.isfile(self.storage_key_file):
                with open(self.storage_key_file, "r", encoding="utf-8") as f:
                    raw_b64 = f.read().strip()
                raw = base64.b64decode(
                    raw_b64.encode("ascii"),
                    validate=True,
                )
                if len(raw) == 32:
                    self.storage_key = raw
                    set_history_encryption_key(raw)
                    harden_file(self.storage_key_file)
                    if keydir_here:
                        _keyring_store_storage_key(keydir_here, raw)
                    return self.storage_key
        except Exception:
            pass
        # Create new key
        try:
            raw = os.urandom(32)
            if mode == STORAGE_BACKEND_AUTO and keydir_here:
                if _keyring_store_storage_key(keydir_here, raw):
                    self.storage_key = raw
                    set_history_encryption_key(raw)
                    return self.storage_key
            tmp = self.storage_key_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(base64.b64encode(raw).decode("ascii"))
            os.replace(tmp, self.storage_key_file)
            harden_file(self.storage_key_file)
            self.storage_key = raw
            set_history_encryption_key(raw)
            return self.storage_key
        except Exception:
            return None

    def append_runtime_log(self, line: str) -> None:
        if not line:
            return
        if not self.runtime_log_enabled:
            return
        try:
            harden_dir(os.path.dirname(self.runtime_log_file) or ".")
            with self._runtime_log_lock:
                with open(self.runtime_log_file, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            harden_file(self.runtime_log_file)
        except Exception:
            pass

    def clear_runtime_log(self) -> None:
        try:
            harden_dir(os.path.dirname(self.runtime_log_file) or ".")
            with self._runtime_log_lock:
                with open(self.runtime_log_file, "w", encoding="utf-8") as f:
                    f.write("")
            harden_file(self.runtime_log_file)
        except Exception:
            pass

    def append_history(
        self,
        direction: str,
        peer_id: str,
        msg_id: str,
        text: str,
        extra: str = "",
        meta_data: Optional[Dict[str, object]] = None,
        peer_norm_fn=None,
    ) -> None:
        if peer_norm_fn:
            peer_norm = peer_norm_fn(peer_id)
        else:
            peer_norm = str(peer_id or "")
        key_ok = self.ensure_storage_key()
        if not key_ok:
            # Fail closed: avoid writing plaintext history when storage key is unavailable.
            return
        aad = f"{direction}|{peer_norm}|{msg_id}".encode("utf-8", errors="replace")
        try:
            enc_text = encode_history_text(text, aad=aad)
        except Exception:
            return
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} | {direction} | {peer_norm} | {msg_id} | {enc_text}"
        extras: list[str] = []
        extra_text = str(extra).strip()
        if extra_text:
            extras.append(extra_text)
        meta_token = encode_history_meta_token(meta_data)
        if meta_token:
            extras.append(meta_token)
        if extras:
            line += " | " + " | ".join(extras)
        harden_dir(os.path.dirname(self.history_file) or ".")
        with self._history_lock:
            with open(self.history_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        harden_file(self.history_file)

    def purge_history_peer(
        self,
        peer_id: str,
        peer_norm_fn=None,
    ) -> None:
        """Remove history lines for a given peer id.

        This is protected by the same history lock as append_history() to avoid
        concurrent read/modify/write races that could drop recent appends.
        """
        if not peer_id:
            return
        if peer_norm_fn:
            target = peer_norm_fn(peer_id)
        else:
            target = str(peer_id or "")
        if not target:
            return
        if not os.path.isfile(self.history_file):
            return
        try:
            with self._history_lock:
                try:
                    with open(self.history_file, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                except Exception:
                    return
                keep: list[str] = []
                for line in lines:
                    parts = line.rstrip("\n").split(" | ")
                    if len(parts) < 3:
                        keep.append(line)
                        continue
                    peer_raw = parts[2]
                    peer_norm_line = peer_norm_fn(peer_raw) if peer_norm_fn else str(peer_raw or "")
                    if peer_norm_line == target:
                        continue
                    keep.append(line)
                tmp = self.history_file + ".tmp"
                harden_dir(os.path.dirname(self.history_file) or ".")
                with open(tmp, "w", encoding="utf-8") as f:
                    f.writelines(keep)
                os.replace(tmp, self.history_file)
            harden_file(self.history_file)
        except Exception:
            pass

    def rewrite_history_peer_field(self, old_peer_id: str, new_peer_id: Optional[str]) -> None:
        """Rewrite the peer_id field in history.log (exact match).

        Used for renaming group dialogs. When new_peer_id is None, matching lines are removed.
        """
        if not old_peer_id:
            return
        if not os.path.isfile(self.history_file):
            return
        try:
            with self._history_lock:
                try:
                    with open(self.history_file, "r", encoding="utf-8") as f:
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
                    if peer_raw != old_peer_id:
                        out.append(line)
                        continue
                    if new_peer_id is None:
                        continue
                    out.append(f"{ts_part} | {direction} | {new_peer_id} | {rest}\n")
                tmp = self.history_file + ".tmp"
                harden_dir(os.path.dirname(self.history_file) or ".")
                with open(tmp, "w", encoding="utf-8") as f:
                    f.writelines(out)
                os.replace(tmp, self.history_file)
            harden_file(self.history_file)
        except Exception:
            pass

    def load_config(self) -> Dict[str, object]:
        if not os.path.isfile(self.config_file):
            return {}
        try:
            import json

            return json.loads(open(self.config_file, "r", encoding="utf-8").read())
        except Exception:
            return {}

    def save_config(self, cfg: Dict[str, object]) -> None:
        import json

        tmp = self.config_file + ".tmp"
        harden_dir(os.path.dirname(self.config_file) or ".")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False)
        os.replace(tmp, self.config_file)
        harden_file(self.config_file)

    def load_state(self, default_peer: Optional[str] = None) -> Dict[str, Dict[str, Dict[str, object]]]:
        if not os.path.isfile(self.state_file):
            return {}
        try:
            import json

            data = json.loads(open(self.state_file, "r", encoding="utf-8").read())
            pending: Dict[str, Dict[str, Dict[str, object]]] = {}
            for item in data.get("pending", []):
                if not isinstance(item, dict):
                    continue
                mid = item.get("id")
                if isinstance(mid, str) and mid:
                    peer = item.get("peer")
                    if not isinstance(peer, str) or not peer:
                        peer = default_peer or "default"
                    rec = dict(item)
                    rec["peer"] = peer
                    aad_base = f"state|{peer}|{mid}".encode("utf-8", errors="replace")
                    locked = False
                    for field in ("text", "chunk_text", "chunk_b64"):
                        val = rec.get(field)
                        if isinstance(val, str) and val.startswith(HISTORY_TEXT_ENC_PREFIX):
                            dec = _storage_decrypt_str(val, self.storage_key, aad_base + b"|" + field.encode("ascii"))
                            if not isinstance(dec, str) or dec == "":
                                locked = True
                                break
                            rec[field] = dec
                    if locked:
                        continue
                    pending.setdefault(peer, {})[mid] = rec
            return pending
        except Exception:
            return {}

    def save_state(self, pending_by_peer: Dict[str, Dict[str, Dict[str, object]]]) -> None:
        import json

        storage_key = self.ensure_storage_key()
        if not storage_key:
            return
        tmp = self.state_file + ".tmp"
        harden_dir(os.path.dirname(self.state_file) or ".")
        flat = []
        for peer_id, items in pending_by_peer.items():
            for rec in items.values():
                if isinstance(rec, dict):
                    out = dict(rec)
                    out.setdefault("peer", peer_id)
                    mid = out.get("id")
                    peer = out.get("peer")
                    if isinstance(mid, str) and mid and isinstance(peer, str) and peer:
                        aad_base = f"state|{peer}|{mid}".encode("utf-8", errors="replace")
                        for field in ("text", "chunk_text", "chunk_b64"):
                            if field in out and out.get(field) is not None:
                                out[field] = _storage_encrypt_str(
                                    out.get(field),
                                    storage_key,
                                    aad_base + b"|" + field.encode("ascii"),
                                )
                    flat.append(out)
        data = {"pending": flat}
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, self.state_file)
        harden_file(self.state_file)

    def load_incoming_state(self) -> Dict[str, Dict[str, object]]:
        if not os.path.isfile(self.incoming_file):
            return {}
        try:
            import json

            data = json.loads(open(self.incoming_file, "r", encoding="utf-8").read())
            incoming: Dict[str, Dict[str, object]] = {}
            for item in data.get("incoming", []):
                if not isinstance(item, dict):
                    continue
                peer = item.get("peer")
                group_id = item.get("group_id")
                total = item.get("total")
                parts = item.get("parts") or {}
                if not isinstance(peer, str) or not peer or not isinstance(group_id, str) or not group_id:
                    continue
                if not isinstance(total, int) or total <= 0:
                    continue
                if not isinstance(parts, dict):
                    continue
                parts_int: Dict[int, str] = {}
                aad_base = f"incoming|{peer}|{group_id}".encode("utf-8", errors="replace")
                for k, v in parts.items():
                    try:
                        ki = int(k)
                    except Exception:
                        continue
                    v_str = str(v)
                    if v_str.startswith(HISTORY_TEXT_ENC_PREFIX):
                        dec = _storage_decrypt_str(v_str, self.storage_key, aad_base + b"|" + str(ki).encode("ascii"))
                        if isinstance(dec, str) and dec:
                            parts_int[ki] = dec
                    else:
                        parts_int[ki] = v_str
                key = f"{peer}:{group_id}"
                incoming[key] = {
                    "peer": peer,
                    "group_id": group_id,
                    "total": total,
                    "parts": parts_int,
                    "delivery": item.get("delivery"),
                    "hops_sum": float(item.get("hops_sum", 0.0)),
                    "hops_n": int(item.get("hops_n", 0)),
                    "attempts_sum": float(item.get("attempts_sum", 0.0)),
                    "attempts_n": int(item.get("attempts_n", 0)),
                    "compact": bool(item.get("compact", False)),
                    "compression": int(item.get("compression", 0) or 0),
                    "legacy_codec": (str(item.get("legacy_codec")) if item.get("legacy_codec") else None),
                    "payload_cmp": (str(item.get("payload_cmp")) if item.get("payload_cmp") else "none"),
                    "received_at_ts": float(item.get("received_at_ts", 0.0) or 0.0),
                    "incoming_started_ts": float(item.get("incoming_started_ts", 0.0) or 0.0),
                }
            return incoming
        except Exception:
            return {}

    def save_incoming_state(self, incoming: Dict[str, Dict[str, object]]) -> None:
        import json

        storage_key = self.ensure_storage_key()
        if not storage_key:
            return
        tmp = self.incoming_file + ".tmp"
        harden_dir(os.path.dirname(self.incoming_file) or ".")
        flat = []
        for rec in incoming.values():
            if not isinstance(rec, dict):
                continue
            peer = rec.get("peer")
            group_id = rec.get("group_id")
            total = rec.get("total")
            parts = rec.get("parts") or {}
            if not isinstance(peer, str) or not peer or not isinstance(group_id, str) or not group_id:
                continue
            if not isinstance(total, int) or total <= 0:
                continue
            if not isinstance(parts, dict):
                continue
            parts_str: Dict[str, str] = {}
            aad_base = f"incoming|{peer}|{group_id}".encode("utf-8", errors="replace")
            for k, v in parts.items():
                part_idx = str(k)
                parts_str[part_idx] = str(
                    _storage_encrypt_str(
                        str(v),
                        storage_key,
                        aad_base + b"|" + part_idx.encode("ascii", errors="replace"),
                    )
                )
            flat.append(
                {
                    "peer": peer,
                    "group_id": group_id,
                    "total": total,
                    "parts": parts_str,
                    "delivery": rec.get("delivery"),
                    "hops_sum": float(rec.get("hops_sum", 0.0)),
                    "hops_n": int(rec.get("hops_n", 0)),
                    "attempts_sum": float(rec.get("attempts_sum", 0.0)),
                    "attempts_n": int(rec.get("attempts_n", 0)),
                    "compact": bool(rec.get("compact", False)),
                    "compression": int(rec.get("compression", 0) or 0),
                    "legacy_codec": (str(rec.get("legacy_codec")) if rec.get("legacy_codec") else None),
                    "payload_cmp": (str(rec.get("payload_cmp")) if rec.get("payload_cmp") else "none"),
                    "received_at_ts": float(rec.get("received_at_ts", 0.0) or 0.0),
                    "incoming_started_ts": float(rec.get("incoming_started_ts", 0.0) or 0.0),
                }
            )
        data = {"incoming": flat}
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, self.incoming_file)
        harden_file(self.incoming_file)
