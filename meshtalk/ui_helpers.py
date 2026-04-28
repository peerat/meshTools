#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


def build_gui_config_payload(
    *,
    current_lang: str,
    verbose_log: bool,
    runtime_log_file: bool,
    auto_pacing: bool,
    pinned_dialogs: set[str],
    hidden_contacts: set[str],
    groups: Dict[str, set],
    cfg: Dict[str, Any],
    args: Any,
    data_port_label: str,
    normalize_activity_controller_model_fn: Any,
    activity_controller_default: str,
    msg_retry_active_window_seconds: float,
    msg_retry_muted_interval_seconds: float,
    msg_retry_probe_window_seconds: float,
    peer_responsive_grace_seconds: float,
    retry_backoff_max_seconds: float,
    retry_jitter_ratio: float,
    discovery_send: bool,
    discovery_reply: bool,
    clear_pending_on_switch: bool,
    contacts_visibility: str,
    current_theme: str,
    peer_meta: Dict[str, Any],
) -> Dict[str, Any]:
    return {
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
        "mesh_packet_portnum": cfg.get("mesh_packet_portnum", data_port_label),
        "activity_intra_batch_gap_ms": cfg.get("activity_intra_batch_gap_ms", 0),
        "discovery_hello_burst_count": cfg.get("discovery_hello_burst_count", 1),
        "discovery_hello_packet_count": cfg.get("discovery_hello_packet_count", 1),
        "discovery_hello_gap_seconds": cfg.get("discovery_hello_gap_seconds", 1),
        "discovery_hello_packet_gap_seconds": cfg.get("discovery_hello_packet_gap_seconds", 1),
        "discovery_hello_interval_seconds": cfg.get("discovery_hello_interval_seconds", 60),
        "discovery_hello_runtime_seconds": cfg.get("discovery_hello_runtime_seconds", 300),
        "discovery_hello_autostart": bool(cfg.get("discovery_hello_autostart", True)),
        "rate_seconds": cfg.get("rate_seconds", args.rate_seconds),
        "parallel_sends": cfg.get("parallel_sends", getattr(args, "parallel_sends", 1)),
        "activity_timing_mode": str(cfg.get("activity_timing_mode", "manual") or "manual"),
        "activity_profile": cfg.get("activity_profile", "low"),
        "activity_aggressiveness": cfg.get("activity_aggressiveness", 20),
        "activity_controller_model": normalize_activity_controller_model_fn(
            cfg.get("activity_controller_model", activity_controller_default)
        ),
        "activity_active_window_seconds": cfg.get("activity_active_window_seconds", msg_retry_active_window_seconds),
        "activity_probe_interval_min_seconds": cfg.get("activity_probe_interval_min_seconds", 10 * 60),
        "activity_probe_interval_max_seconds": cfg.get("activity_probe_interval_max_seconds", msg_retry_muted_interval_seconds),
        "activity_probe_window_max_seconds": cfg.get("activity_probe_window_max_seconds", msg_retry_probe_window_seconds),
        "activity_peer_responsive_grace_seconds": cfg.get(
            "activity_peer_responsive_grace_seconds", peer_responsive_grace_seconds
        ),
        "activity_retry_backoff_max_seconds": cfg.get("activity_retry_backoff_max_seconds", retry_backoff_max_seconds),
        "activity_retry_jitter_ratio": cfg.get("activity_retry_jitter_ratio", retry_jitter_ratio),
        "activity_fast_retries": cfg.get("activity_fast_retries", 0),
        "activity_fast_retry_min_ms": cfg.get("activity_fast_retry_min_ms", 350),
        "activity_fast_retry_max_ms": cfg.get("activity_fast_retry_max_ms", 850),
        "activity_fast_budget_per_second": cfg.get("activity_fast_budget_per_second", 2),
        "activity_ledbat_target_delay_seconds": cfg.get("activity_ledbat_target_delay_seconds", 2.0),
        "activity_ledbat_gain": cfg.get("activity_ledbat_gain", 0.7),
        "activity_quic_max_ack_delay_seconds": cfg.get("activity_quic_max_ack_delay_seconds", 1.0),
        "activity_quic_timer_granularity_seconds": cfg.get("activity_quic_timer_granularity_seconds", 0.01),
        "routing_score_w_delivery": cfg.get("routing_score_w_delivery", 1.30),
        "routing_score_w_timeout": cfg.get("routing_score_w_timeout", 1.05),
        "routing_score_w_rtt": cfg.get("routing_score_w_rtt", 0.35),
        "routing_score_w_hops": cfg.get("routing_score_w_hops", 0.25),
        "routing_score_w_retry": cfg.get("routing_score_w_retry", 0.40),
        "routing_score_w_micro": cfg.get("routing_score_w_micro", 0.20),
        "routing_score_w_congestion": cfg.get("routing_score_w_congestion", 0.50),
        "routing_score_w_snr_bonus": cfg.get("routing_score_w_snr_bonus", 0.08),
        "routing_ema_alpha": cfg.get("routing_ema_alpha", 0.22),
        "routing_decay_half_life_seconds": cfg.get("routing_decay_half_life_seconds", 1200.0),
        "routing_min_samples": cfg.get("routing_min_samples", 6),
        "routing_route_ttl_seconds": cfg.get("routing_route_ttl_seconds", 1800.0),
        "routing_hysteresis_rel": cfg.get("routing_hysteresis_rel", 0.12),
        "routing_hysteresis_abs": cfg.get("routing_hysteresis_abs", 0.04),
        "routing_sticky_hold_seconds": cfg.get("routing_sticky_hold_seconds", 45.0),
        "routing_failover_timeout_ema": cfg.get("routing_failover_timeout_ema", 0.55),
        "routing_failover_delivery_ema": cfg.get("routing_failover_delivery_ema", 0.25),
        "routing_failover_rtt_seconds": cfg.get("routing_failover_rtt_seconds", 25.0),
        "routing_group_fanout_cap": cfg.get("routing_group_fanout_cap", 8),
        "routing_group_min_score": cfg.get("routing_group_min_score", -0.20),
        "routing_control_rate_per_second": cfg.get("routing_control_rate_per_second", 0.20),
        "routing_control_burst": cfg.get("routing_control_burst", 3.0),
        "routing_control_min_interval_seconds": cfg.get("routing_control_min_interval_seconds", 2.0),
        "discovery_enabled": bool(discovery_send and discovery_reply),
        "discovery_send": discovery_send,
        "discovery_reply": discovery_reply,
        "clear_pending_on_switch": clear_pending_on_switch,
        "contacts_visibility": contacts_visibility,
        "ui_theme": current_theme,
        "peer_meta": peer_meta,
    }


def split_chat_timestamp(text: str, fallback_ts: Optional[str] = None) -> Tuple[str, str]:
    src = str(text or "")
    if " " in src and len(src) >= 6:
        return src[:5], src[6:]
    return str(fallback_ts or ""), src


def strip_parenthesized_prefix(text: str) -> str:
    msg = str(text or "")
    if msg.startswith("("):
        end = msg.find(") ")
        if end != -1:
            return msg[end + 2 :]
    return msg
