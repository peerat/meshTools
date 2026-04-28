#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""
Protocol v2 (MT2) plaintext handshake handling.

This module owns:
- HELLO (broadcast presence beacons, minimal plaintext)
- KR1/KR2 (unicast X25519 public key exchange)

It intentionally does NOT touch Qt and does not import Meshtastic. The caller provides:
- a packet dict (from meshtastic) for metadata like fromId/rssi/snr/hopStart/hopLimit
- callbacks for state/storage updates and sending a KR2 response
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from meshtalk.mt2_frames import build_kr2_frame, parse_mt2_frame
from meshtalk.protocol import PeerKeyPinnedError, b64e, pub_fingerprint


KEY_FRAME_REPLAY_WINDOW_SECONDS = 10.0 * 60.0
GLOBAL_KEY_RESPONSE_MIN_GAP_SECONDS = 1.0
NEW_PEER_RATE_WINDOW_SECONDS = 60.0
NEW_PEER_RATE_MAX_PER_WINDOW = 24
KEY_FRAME_RECENT_CACHE_LIMIT = 16
KEY_ROTATION_OSCILLATION_WINDOW_SECONDS = 30.0 * 60.0
KEY_REQUEST_LOG_DEBOUNCE_SECONDS = 2.0


def _valid_peer_id_norm(peer_norm: str) -> bool:
    # Defensive: peer_norm comes from the wire; only allow 8 hex chars.
    try:
        s = str(peer_norm or "")
    except Exception:
        return False
    if len(s) != 8:
        return False
    for ch in s:
        if ch not in "0123456789abcdefABCDEF":
            return False
    return True


def calc_hops(packet: Dict[str, Any]) -> Optional[int]:
    try:
        hop_start = packet.get("hopStart")
        hop_limit = packet.get("hopLimit")
        if isinstance(hop_start, int) and isinstance(hop_limit, int):
            return max(0, int(hop_start) - int(hop_limit))
    except Exception:
        pass
    return None


def is_broadcast_to(to_id: object) -> bool:
    # Meshtastic uses "^all" in dicts, but callers may also pass numeric addr (0xFFFFFFFF).
    try:
        if isinstance(to_id, str) and to_id.strip() == "^all":
            return True
    except Exception:
        pass
    try:
        if isinstance(to_id, int) and int(to_id) == 0xFFFFFFFF:
            return True
    except Exception:
        pass
    return False


def _known_peer(ctx: "HandshakeContext", peer_norm: str) -> bool:
    if not peer_norm:
        return True
    try:
        if os.path.isfile(os.path.join(str(ctx.keydir or ""), f"{peer_norm}.pub")):
            return True
    except Exception:
        pass
    try:
        rec = ctx.peer_meta.get(peer_norm)
        if isinstance(rec, dict):
            return True
    except Exception:
        pass
    return False


def _allow_new_peer_intake(ctx: "HandshakeContext", peer_norm: str, now: float) -> bool:
    if _known_peer(ctx, peer_norm):
        return True
    try:
        sec = ctx.peer_meta.setdefault("__security__", {})
        if not isinstance(sec, dict):
            return True
        events_raw = sec.get("new_peer_events")
        events = [float(ts) for ts in (events_raw or []) if isinstance(ts, (int, float))]
        cutoff = float(now) - float(NEW_PEER_RATE_WINDOW_SECONDS)
        events = [ts for ts in events if ts >= cutoff]
        if len(events) >= int(NEW_PEER_RATE_MAX_PER_WINDOW):
            sec["new_peer_events"] = events
            return False
        events.append(float(now))
        sec["new_peer_events"] = events
    except Exception:
        return True
    return True


def _remember_recent_key_frame(ctx: "HandshakeContext", peer_norm: str, sig: str, now: float) -> bool:
    if not sig:
        return False
    try:
        meta_rec = ctx.peer_meta.setdefault(peer_norm, {})
        if not isinstance(meta_rec, dict):
            return False
        cache_raw = meta_rec.get("recent_key_frame_sigs")
        cache: Dict[str, float]
        if isinstance(cache_raw, dict):
            cache = {
                str(k): float(v)
                for k, v in cache_raw.items()
                if isinstance(k, str) and isinstance(v, (int, float))
            }
        else:
            cache = {}
        cutoff = float(now) - float(KEY_FRAME_REPLAY_WINDOW_SECONDS)
        cache = {k: ts for k, ts in cache.items() if ts >= cutoff}
        prev_ts = cache.get(sig)
        if isinstance(prev_ts, (int, float)) and (float(now) - float(prev_ts)) < float(KEY_FRAME_REPLAY_WINDOW_SECONDS):
            meta_rec["recent_key_frame_sigs"] = cache
            return True
        cache[sig] = float(now)
        if len(cache) > int(KEY_FRAME_RECENT_CACHE_LIMIT):
            ordered = sorted(cache.items(), key=lambda item: float(item[1]), reverse=True)[: int(KEY_FRAME_RECENT_CACHE_LIMIT)]
            cache = {k: ts for k, ts in ordered}
        meta_rec["recent_key_frame_sigs"] = cache
    except Exception:
        return False
    return False


def _is_rotation_oscillation(ctx: "HandshakeContext", peer_norm: str, old_fp: str, new_fp: str, now: float) -> bool:
    try:
        meta_rec = ctx.peer_meta.setdefault(peer_norm, {})
        if not isinstance(meta_rec, dict):
            return False
        prev_old = str(meta_rec.get("last_auto_rotation_old_fp", "") or "")
        prev_new = str(meta_rec.get("last_auto_rotation_new_fp", "") or "")
        prev_ts = float(meta_rec.get("last_auto_rotation_ts", 0.0) or 0.0)
        if (float(now) - prev_ts) > float(KEY_ROTATION_OSCILLATION_WINDOW_SECONDS):
            return False
        if prev_old == str(new_fp or "") and prev_new == str(old_fp or ""):
            return True
    except Exception:
        return False
    return False


def _remember_auto_rotation(ctx: "HandshakeContext", peer_norm: str, old_fp: str, new_fp: str, now: float) -> None:
    try:
        meta_rec = ctx.peer_meta.setdefault(peer_norm, {})
        if not isinstance(meta_rec, dict):
            return
        meta_rec["last_auto_rotation_old_fp"] = str(old_fp or "")
        meta_rec["last_auto_rotation_new_fp"] = str(new_fp or "")
        meta_rec["last_auto_rotation_ts"] = float(now)
    except Exception:
        pass


def _pinned_pub_matches(ctx: "HandshakeContext", peer_norm: str, pub_raw: Optional[bytes]) -> bool:
    try:
        if pub_raw is None:
            return False
        pub = bytes(pub_raw)
        if len(pub) != 32:
            return False
        pub_path = os.path.join(str(ctx.keydir or ""), f"{peer_norm}.pub")
        if not os.path.isfile(pub_path):
            return False
        with open(pub_path, "rb") as f:
            pinned = f.read()
        return bytes(pinned) == pub
    except Exception:
        return False


def _should_skip_same_key_req_refresh(ctx: "HandshakeContext", peer_norm: str, now: float, window_s: float) -> bool:
    try:
        if float(window_s) <= 0.0:
            return False
        meta_rec = ctx.peer_meta.setdefault(peer_norm, {})
        if not isinstance(meta_rec, dict):
            return False
        prev_ts = float(meta_rec.get("last_same_key_req_refresh_ts", 0.0) or 0.0)
        if prev_ts > 0.0 and (float(now) - prev_ts) < float(window_s):
            return True
        meta_rec["last_same_key_req_refresh_ts"] = float(now)
    except Exception:
        return False
    return False


def _should_emit_key_request_log(ctx: "HandshakeContext", peer_norm: str, now: float) -> bool:
    try:
        meta_rec = ctx.peer_meta.setdefault(peer_norm, {})
        if not isinstance(meta_rec, dict):
            return True
        prev_ts = float(meta_rec.get("last_key_req_log_ts", 0.0) or 0.0)
        if prev_ts > 0.0 and (float(now) - prev_ts) < float(KEY_REQUEST_LOG_DEBOUNCE_SECONDS):
            return False
        meta_rec["last_key_req_log_ts"] = float(now)
    except Exception:
        return True
    return True


@dataclass
class HandshakeContext:
    # identity
    self_id: str
    pub_self_raw: bytes
    keydir: str

    # policy / timers
    key_response_min_interval_s: float
    key_response_retry_interval_s: float
    packet_trace: bool

    # shared mutable stores owned by meshTalk.py
    peer_meta: Dict[str, Dict[str, object]]
    key_response_last_ts: Dict[str, float]

    # callbacks
    norm_peer_id: Callable[[Optional[str]], Optional[str]]
    wire_id_from_norm: Callable[[str], str]
    ts_local: Callable[[], str]
    ui_emit: Callable[[str, object], None]
    activity_record: Callable[..., None]

    get_peer_state: Callable[[Optional[str]], Any]
    ensure_peer_state: Callable[[str], Any]
    update_peer_names_from_nodes: Callable[[Optional[str]], None]

    store_peer_pub: Callable[[str, bytes], None]
    force_store_peer_pub: Callable[[str, bytes], None]
    update_peer_pub: Callable[[str, bytes], None]
    should_auto_accept_first_peer_key: Callable[[str, Any], Tuple[bool, str]]
    should_auto_accept_peer_key_rotation: Callable[[str, Any], Tuple[bool, str]]

    send_kr2: Callable[[str, bytes], bool]
    on_key_conflict: Callable[[str, str, str], None]
    on_key_confirmed: Callable[[str, Any, str], None]


def handle_mt2_plaintext(packet: Dict[str, Any], payload: bytes, now: float, ctx: HandshakeContext) -> bool:
    """
    Returns True if payload is an MT2 plaintext frame and was handled.
    """
    mt2 = parse_mt2_frame(payload)
    if not mt2:
        return False
    kind, pub_raw, _nonce = mt2
    from_id_raw = packet.get("fromId")
    peer_norm = ctx.norm_peer_id(from_id_raw) if from_id_raw else None

    if kind == "hello":
        # Presence beacon only (no key, no caps).
        if peer_norm and _valid_peer_id_norm(peer_norm) and peer_norm != ctx.self_id:
            if not _allow_new_peer_intake(ctx, peer_norm, now):
                try:
                    sec = ctx.peer_meta.setdefault("__security__", {})
                    if isinstance(sec, dict):
                        last_drop = float(sec.get("new_peer_drop_log_ts", 0.0) or 0.0)
                        if (now - last_drop) >= 10.0:
                            sec["new_peer_drop_log_ts"] = float(now)
                            ctx.ui_emit(
                                "log",
                                f"{ctx.ts_local()} KEY: new-peer intake throttled (HELLO) peer={peer_norm}",
                            )
                except Exception:
                    pass
                return True
            st = ctx.ensure_peer_state(peer_norm)
            try:
                st.last_seen_ts = float(now)
                st.app_offline_ts = 0.0
            except Exception:
                pass
            # If the peer is visible (HELLO received) but no public key is known yet,
            # emit a one-time hint so users understand how to start the key exchange.
            has_pub = False
            try:
                pub_path = os.path.join(str(ctx.keydir or ""), f"{peer_norm}.pub")
                has_pub = bool(os.path.isfile(pub_path))
            except Exception:
                has_pub = False
            try:
                key_ready = bool(getattr(st, "key_ready", False))
            except Exception:
                key_ready = False
            try:
                last_hint = float(getattr(st, "last_key_hint_ts", 0.0) or 0.0)
            except Exception:
                last_hint = 0.0
            if (not has_pub) and (not key_ready) and ((now - last_hint) > 600.0):
                try:
                    st.last_key_hint_ts = float(now)
                except Exception:
                    pass
                ctx.ui_emit(
                    "log",
                    f"{ctx.ts_local()} KEY: hint peer={peer_norm} -> menu: Send and request public key / меню: Отправить и запросить public key",
                )
            # Throttle hello-rx logs per peer (avoid spam), unless packet trace is enabled.
            try:
                last_hello = float(getattr(st, "last_hello_rx_ts", 0.0) or 0.0)
            except Exception:
                last_hello = 0.0
            # Defensive: local clock changes (VM suspend/resume, manual time set) can move time backwards.
            # If we detect "future" timestamps, reset throttling so hello-rx logs don't get muted for hours.
            try:
                if last_hello > 0.0 and (last_hello - float(now)) > 5.0:
                    last_hello = 0.0
            except Exception:
                pass
            if bool(ctx.packet_trace) or ((now - last_hello) >= 60.0):
                try:
                    st.last_hello_rx_ts = float(now)
                except Exception:
                    pass
                parts = [f"peer={peer_norm}"]
                try:
                    rx_rssi = packet.get("rxRssi")
                    rx_snr = packet.get("rxSnr")
                    hops = calc_hops(packet)
                    if isinstance(rx_rssi, (int, float)):
                        parts.append(f"rssi={float(rx_rssi):.0f}")
                    if isinstance(rx_snr, (int, float)):
                        parts.append(f"snr={float(rx_snr):.1f}")
                    if hops is not None:
                        parts.append(f"hops={int(hops)}")
                except Exception:
                    pass
                ctx.ui_emit("log", f"{ctx.ts_local()} DISCOVERY: hello rx " + " ".join(parts))

            try:
                rec = ctx.peer_meta.setdefault(peer_norm, {})
                if isinstance(rec, dict):
                    rec["last_seen_ts"] = float(now)
                    rec["app_offline_ts"] = 0.0
            except Exception:
                pass
            ctx.ui_emit("peer_update", peer_norm)
        try:
            ctx.activity_record("in", "srv", 1, now=now, bytes_count=len(payload), subkind="disc")
        except Exception:
            pass
        return True

    # KR1/KR2 must be unicast; do not accept broadcast key frames.
    to_id = packet.get("toId") or packet.get("to")
    if is_broadcast_to(to_id):
        try:
            ctx.activity_record("in", "srv", 1, now=now, bytes_count=len(payload), subkind="key")
        except Exception:
            pass
        ctx.ui_emit("log", f"{ctx.ts_local()} KEY: ignored broadcast key frame from {from_id_raw or '?'}")
        return True

    if not peer_norm:
        try:
            ctx.activity_record("in", "srv", 1, now=now, bytes_count=len(payload), subkind="key")
        except Exception:
            pass
        ctx.ui_emit("log", f"{ctx.ts_local()} KEY: reject key frame (missing fromId).")
        return True
    if not _valid_peer_id_norm(peer_norm):
        try:
            ctx.activity_record("in", "srv", 1, now=now, bytes_count=len(payload), subkind="key")
        except Exception:
            pass
        ctx.ui_emit("log", f"{ctx.ts_local()} KEY: reject key frame (invalid fromId={from_id_raw!r}).")
        return True
    if peer_norm == ctx.self_id:
        try:
            ctx.activity_record("in", "srv", 1, now=now, bytes_count=len(payload), subkind="key")
        except Exception:
            pass
        ctx.ui_emit("log", f"{ctx.ts_local()} KEY: ignored key frame with self-id from={from_id_raw!r}.")
        return True

    ctx.update_peer_names_from_nodes(peer_norm)
    if not _allow_new_peer_intake(ctx, peer_norm, now):
        try:
            sec = ctx.peer_meta.setdefault("__security__", {})
            if isinstance(sec, dict):
                last_drop = float(sec.get("new_peer_drop_log_ts", 0.0) or 0.0)
                if (now - last_drop) >= 10.0:
                    sec["new_peer_drop_log_ts"] = float(now)
                    ctx.ui_emit(
                        "log",
                        f"{ctx.ts_local()} KEY: new-peer intake throttled (KR) peer={peer_norm}",
                    )
        except Exception:
            pass
        return True
    try:
        ctx.activity_record("in", "srv", 1, now=now, bytes_count=len(payload), subkind="key")
    except Exception:
        pass

    st = ctx.get_peer_state(peer_norm)
    if st is not None:
        try:
            st.last_seen_ts = float(now)
            st.app_offline_ts = 0.0
        except Exception:
            pass

    # Basic anti-replay for plaintext key frames: ignore repeated key-frame signatures for the
    # same peer within a bounded window. Keep a small recent cache, not just the last frame,
    # because duplicate deliveries can be interleaved with other events.
    try:
        nonce_hex = bytes(_nonce or b"").hex() if isinstance(_nonce, (bytes, bytearray)) else ""
    except Exception:
        nonce_hex = ""
    if nonce_hex:
        try:
            sig = f"{kind}:{nonce_hex}"
            if _remember_recent_key_frame(ctx, peer_norm, sig, now):
                ctx.ui_emit(
                    "log",
                    f"{ctx.ts_local()} KEY: duplicate key frame suppressed peer={peer_norm} kind={kind}",
                )
                return True
        except Exception:
            pass

    try:
        has_pinned_pub = bool(os.path.isfile(os.path.join(str(ctx.keydir or ""), f"{peer_norm}.pub")))
    except Exception:
        has_pinned_pub = False

    skip_key_refresh = False
    if kind == "req" and has_pinned_pub:
        try:
            st_ready = bool(st and bool(getattr(st, "key_ready", False)))
        except Exception:
            st_ready = False
        if st_ready and _pinned_pub_matches(ctx, peer_norm, pub_raw):
            if _should_skip_same_key_req_refresh(ctx, peer_norm, now, float(ctx.key_response_min_interval_s)):
                skip_key_refresh = True
                ctx.ui_emit(
                    "log",
                    f"{ctx.ts_local()} KEY: request refresh skipped peer={peer_norm} reason=recent_same_key",
                )

    # First-seen key handling is policy-driven:
    # - AUTO / ALWAYS: TOFU, accept first observed key automatically
    # - STRICT: require explicit user accept before persisting trust anchor
    first_seen_auto_accepted = False
    if (not skip_key_refresh) and (not has_pinned_pub):
        try:
            if pub_raw is None:
                raise ValueError("missing pubkey")
            new_pub = bytes(pub_raw)
            if len(new_pub) != 32:
                raise ValueError("invalid pubkey length")
            new_fp = pub_fingerprint(new_pub)
            auto_ok, auto_why = ctx.should_auto_accept_first_peer_key(peer_norm, st)
            try:
                ctx.ui_emit(
                    "log",
                    f"{ctx.ts_local()} KEY: trust_state peer={peer_norm} state=first_seen action={'auto_accept' if auto_ok else 'manual_accept'} {auto_why}",
                )
            except Exception:
                pass
            if auto_ok:
                try:
                    ctx.store_peer_pub(peer_norm, new_pub)
                    st_auto = ctx.get_peer_state(peer_norm)
                    if st_auto is not None:
                        try:
                            st_auto.pinned_mismatch = False
                            st_auto.pinned_old_fp = ""
                            st_auto.pinned_new_fp = ""
                            st_auto.pinned_new_pub_b64 = ""
                        except Exception:
                            pass
                    first_seen_auto_accepted = True
                    ctx.ui_emit(
                        "log",
                        f"{ctx.ts_local()} KEY: first key auto-accepted peer={peer_norm} fp={new_fp} {auto_why}",
                    )
                except Exception as e:
                    ctx.ui_emit(
                        "log",
                        f"{ctx.ts_local()} KEY: first key auto-accept failed peer={peer_norm} fp={new_fp} error={type(e).__name__}; manual accept required",
                    )
                    auto_ok = False
            if auto_ok:
                # Continue into normal update/send KR2 flow below.
                pass
            else:
                st_new = ctx.get_peer_state(peer_norm)
                if st_new is not None:
                    try:
                        st_new.pinned_mismatch = True
                        st_new.pinned_old_fp = "none"
                        st_new.pinned_new_fp = str(new_fp or "")
                        st_new.pinned_new_pub_b64 = b64e(new_pub)
                        st_new.force_key_req = False
                        st_new.await_key_confirm = False
                        st_new.await_key_confirm_attempts = 0
                        st_new.next_key_req_ts = float("inf")
                        st_new.aes = None
                    except Exception:
                        pass
                ctx.ui_emit(
                    "log",
                    f"{ctx.ts_local()} KEY: first key pending manual accept peer={peer_norm} fp={new_fp}",
                )
                try:
                    ctx.on_key_conflict(peer_norm, "none", str(new_fp or ""))
                except Exception:
                    pass
                ctx.ui_emit("peer_update", peer_norm)
                return True
        except Exception:
            ctx.ui_emit("log", f"{ctx.ts_local()} KEY: reject invalid public key from {peer_norm}.")
            return True

    # Store/TOFU pin peer key (already trusted peer with pinned file).
    if (not skip_key_refresh) and (not first_seen_auto_accepted):
        try:
            if pub_raw is None:
                raise ValueError("missing pubkey")
            ctx.store_peer_pub(peer_norm, bytes(pub_raw))
            try:
                ctx.ui_emit(
                    "log",
                    f"{ctx.ts_local()} KEY: trust_state peer={peer_norm} state=known_ok action=update_runtime",
                )
            except Exception:
                pass
        except PeerKeyPinnedError as ex:
            auto_ok, auto_why = ctx.should_auto_accept_peer_key_rotation(peer_norm, st)
            if auto_ok and _is_rotation_oscillation(ctx, peer_norm, str(ex.old_fp or ""), str(ex.new_fp or ""), now):
                auto_ok = False
                auto_why = "policy=auto reason=rotation_oscillation action=manual_accept"
            try:
                ctx.ui_emit(
                    "log",
                    f"{ctx.ts_local()} KEY: trust_state peer={peer_norm} state=pinned_rotation action={'auto_accept' if auto_ok else 'manual_accept'} old={ex.old_fp} new={ex.new_fp} {auto_why}",
                )
            except Exception:
                pass
            if auto_ok:
                try:
                    # Accept rotation by writing a new pinned key.
                    # Important: do not delete the old key first, so a write failure
                    # cannot leave the peer unpinned.
                    if not _valid_peer_id_norm(peer_norm):
                        raise ValueError("invalid peer id")
                    ctx.force_store_peer_pub(peer_norm, bytes(pub_raw))
                    st_auto = ctx.get_peer_state(peer_norm)
                    if st_auto is not None:
                        try:
                            st_auto.pinned_mismatch = False
                            st_auto.pinned_old_fp = ""
                            st_auto.pinned_new_fp = ""
                            st_auto.pinned_new_pub_b64 = ""
                        except Exception:
                            pass
                    _remember_auto_rotation(ctx, peer_norm, str(ex.old_fp or ""), str(ex.new_fp or ""), now)
                    ctx.ui_emit(
                        "log",
                        f"{ctx.ts_local()} KEY: pinned key mismatch peer={peer_norm} old={ex.old_fp} new={ex.new_fp} action=auto_accept {auto_why}",
                    )
                except Exception as e:
                    ctx.ui_emit(
                        "log",
                        f"{ctx.ts_local()} KEY: pinned key mismatch peer={peer_norm} old={ex.old_fp} new={ex.new_fp} action=reset_key_required auto_accept_failed={type(e).__name__}",
                    )
                    auto_ok = False
            if not auto_ok:
                if st is not None:
                    try:
                        st.pinned_mismatch = True
                        st.pinned_old_fp = str(ex.old_fp or "")
                        st.pinned_new_fp = str(ex.new_fp or "")
                        st.pinned_new_pub_b64 = b64e(bytes(pub_raw))
                        st.force_key_req = False
                        st.await_key_confirm = False
                        st.await_key_confirm_attempts = 0
                        st.next_key_req_ts = float("inf")
                        st.aes = None
                    except Exception:
                        pass
                ctx.ui_emit(
                    "log",
                    f"{ctx.ts_local()} KEY: pinned key mismatch peer={peer_norm} old={ex.old_fp} new={ex.new_fp} action=reset_key_required {auto_why}",
                )
                try:
                    ctx.on_key_conflict(peer_norm, str(ex.old_fp or ""), str(ex.new_fp or ""))
                except Exception:
                    pass
                return True
        except Exception:
            ctx.ui_emit("log", f"{ctx.ts_local()} KEY: reject invalid public key from {peer_norm}.")
            return True

    # Update runtime key material (AES key for encrypted packets).
    if not skip_key_refresh:
        try:
            ctx.update_peer_pub(peer_norm, bytes(pub_raw))
        except Exception:
            pass
        st_fix = ctx.get_peer_state(peer_norm)
        if st_fix is not None:
            try:
                st_fix.pinned_mismatch = False
                st_fix.pinned_old_fp = ""
                st_fix.pinned_new_fp = ""
                st_fix.pinned_new_pub_b64 = ""
            except Exception:
                pass

    st2 = ctx.get_peer_state(peer_norm)
    if kind == "req":
        if _should_emit_key_request_log(ctx, peer_norm, now):
            ctx.ui_emit("log", f"{ctx.ts_local()} KEY: request from {peer_norm} initiator=remote event=req frame=KR1")
        last_resp = float(ctx.key_response_last_ts.get(peer_norm, 0.0) or 0.0)
        last_resp_global = float(ctx.key_response_last_ts.get("__global__", 0.0) or 0.0)
        retrying_confirm = bool(st2 and bool(getattr(st2, "await_key_confirm", False)))
        min_reply_interval = float(ctx.key_response_retry_interval_s) if retrying_confirm else float(ctx.key_response_min_interval_s)
        if (now - last_resp_global) < float(GLOBAL_KEY_RESPONSE_MIN_GAP_SECONDS):
            left_s = int(max(0.0, float(GLOBAL_KEY_RESPONSE_MIN_GAP_SECONDS) - (now - last_resp_global)))
            ctx.ui_emit(
                "log",
                f"{ctx.ts_local()} KEY: response suppressed peer={peer_norm} initiator=remote reason=global_throttle wait={left_s}s",
            )
        elif (now - last_resp) < min_reply_interval:
            left_s = int(max(0.0, min_reply_interval - (now - last_resp)))
            ctx.ui_emit(
                "log",
                f"{ctx.ts_local()} KEY: response suppressed peer={peer_norm} initiator=remote reason=recent_response wait={left_s}s",
            )
        else:
            nonce4 = os.urandom(4)
            resp = build_kr2_frame(bytes(ctx.pub_self_raw), bytes(nonce4))
            ok = False
            try:
                ok = bool(ctx.send_kr2(peer_norm, resp))
            except Exception:
                ok = False
            if ok:
                ctx.key_response_last_ts[peer_norm] = float(now)
                ctx.key_response_last_ts["__global__"] = float(now)
                # Mark successful remote-initiated exchange as confirmed too.
                # Without this, responder peers remain "unconfirmed" and key-rotation
                # policy can be weaker than intended.
                if st2 and bool(getattr(st2, "key_ready", False)):
                    try:
                        st2.last_key_ok_ts = float(now)
                        st2.key_confirmed_ts = float(now)
                        st2.await_key_confirm = False
                        st2.await_key_confirm_attempts = 0
                        st2.force_key_req = False
                        st2.next_key_req_ts = float("inf")
                    except Exception:
                        pass
                    try:
                        ctx.on_key_confirmed(peer_norm, st2, "req_reply")
                    except Exception:
                        pass
                try:
                    ctx.activity_record("out", "srv", 1, now=now, bytes_count=len(resp), subkind="key")
                except Exception:
                    pass
                ctx.ui_emit(
                    "log",
                    f"{ctx.ts_local()} KEY: response sent to {peer_norm} initiator=remote event=req_reply frame=KR2 plaintext x25519(32b)->aes-256-gcm",
                )
        ctx.ui_emit("peer_update", peer_norm)
        return True

    # kind == "resp"
    ctx.ui_emit("log", f"{ctx.ts_local()} KEY: response from {peer_norm} initiator=remote event=resp frame=KR2")
    if st2 and bool(getattr(st2, "key_ready", False)):
        try:
            st2.last_key_ok_ts = float(now)
        except Exception:
            pass
        if bool(getattr(st2, "await_key_confirm", False)):
            try:
                st2.key_confirmed_ts = float(now)
                st2.await_key_confirm = False
                st2.await_key_confirm_attempts = 0
                st2.force_key_req = False
                st2.next_key_req_ts = float("inf")
            except Exception:
                pass
            ctx.ui_emit(
                "log",
                f"{ctx.ts_local()} KEYOK: confirmed_by=resp peer={peer_norm} initiator=remote aes-256-gcm",
            )
            # CAPS exchange is inside MT-WIRE; caller owns those functions.
            try:
                ctx.on_key_confirmed(peer_norm, st2, "resp")
            except Exception:
                pass
    ctx.ui_emit("peer_update", peer_norm)
    return True
