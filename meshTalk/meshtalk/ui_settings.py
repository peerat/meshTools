from __future__ import annotations

from typing import Dict


_VALID_CONTACTS_VISIBILITY = {"all", "online", "app", "device"}


def clamp_float(value: float, low: float, high: float) -> float:
    return max(float(low), min(float(high), float(value)))


def compute_activity_preset(profile: str, aggressiveness: int) -> Dict[str, float]:
    s = clamp_float(float(aggressiveness), 0.0, 100.0) / 100.0
    profile = str(profile or "low").strip().lower()
    if profile == "fast":
        active = 300.0 + 600.0 * s
        probe_min = 600.0 - 540.0 * s
        probe_max = 3600.0 - 3300.0 * s
        probe_win = 120.0 + 480.0 * s
        grace = 180.0 + 420.0 * s
        backoff_cap = 300.0 - 240.0 * s
        jitter = 0.20
        fast_retries = 1 + (1 if s >= 0.80 else 0)
        fast_min_ms = 220.0 - 70.0 * s
        fast_max_ms = 700.0 - 200.0 * s
        fast_budget = 3
    elif profile == "bal":
        active = 120.0 + 480.0 * s
        probe_min = 1800.0 - 1680.0 * s
        probe_max = 14400.0 - 12600.0 * s
        probe_win = 60.0 + 240.0 * s
        grace = 120.0 + 180.0 * s
        backoff_cap = 600.0 - 420.0 * s
        jitter = 0.25
        fast_retries = 1 if s >= 0.55 else 0
        fast_min_ms = 280.0 - 60.0 * s
        fast_max_ms = 850.0 - 150.0 * s
        fast_budget = 2
    else:
        active = 60.0 + 120.0 * s
        probe_min = 3600.0 - 3000.0 * s
        probe_max = 43200.0 - 36000.0 * s
        probe_win = 30.0 + 90.0 * s
        grace = 120.0 + 120.0 * s
        backoff_cap = 600.0 - 300.0 * s
        jitter = 0.25
        fast_retries = 0
        fast_min_ms = 350.0
        fast_max_ms = 900.0
        fast_budget = 1
    probe_min = clamp_float(probe_min, 60.0, 12 * 3600.0)
    probe_max = clamp_float(probe_max, probe_min, 7 * 86400.0)
    probe_win = clamp_float(probe_win, 10.0, 30 * 60.0)
    active = clamp_float(active, 10.0, 60 * 60.0)
    grace = clamp_float(grace, 10.0, 3600.0)
    backoff_cap = clamp_float(backoff_cap, 30.0, 3600.0)
    jitter = clamp_float(jitter, 0.0, 1.0)
    fast_retries = int(max(0, min(3, int(fast_retries))))
    fast_min_ms = clamp_float(float(fast_min_ms), 50.0, 5000.0)
    fast_max_ms = clamp_float(float(fast_max_ms), float(fast_min_ms), 8000.0)
    fast_budget = int(max(0, min(10, int(fast_budget))))
    return {
        "activity_active_window_seconds": float(active),
        "activity_probe_interval_min_seconds": float(probe_min),
        "activity_probe_interval_max_seconds": float(probe_max),
        "activity_probe_window_max_seconds": float(probe_win),
        "activity_peer_responsive_grace_seconds": float(grace),
        "activity_retry_backoff_max_seconds": float(backoff_cap),
        "activity_retry_jitter_ratio": float(jitter),
        "activity_fast_retries": float(fast_retries),
        "activity_fast_retry_min_ms": float(fast_min_ms),
        "activity_fast_retry_max_ms": float(fast_max_ms),
        "activity_fast_budget_per_second": float(fast_budget),
    }


def parse_int_text(raw: object, default: int) -> int:
    try:
        text = str(raw or "").strip()
        return int(text) if text else int(default)
    except Exception:
        return int(default)


def parse_float_text(raw: object, default: float) -> float:
    try:
        text = str(raw or "").strip().replace(",", ".")
        return float(text) if text else float(default)
    except Exception:
        return float(default)


def normalize_contacts_visibility(value: object, default: str = "all") -> str:
    normalized = str(value or default).strip().lower()
    if normalized not in _VALID_CONTACTS_VISIBILITY:
        return str(default).strip().lower() or "all"
    return normalized


def build_activity_runtime_settings(
    *,
    retry_text: object,
    max_days_text: object,
    max_bytes_text: object,
    batch_count_text: object,
    intra_gap_text: object,
    backoff_cap_text: object,
    jitter_text: object,
    show_advanced: bool,
    parallel_default: int,
    intra_gap_default: int,
    backoff_default: int,
    jitter_ratio_default: float,
) -> Dict[str, object]:
    unified_interval_s = max(0, parse_int_text(retry_text, 30))
    jitter_default_pct = int(round(float(jitter_ratio_default) * 100.0))
    jitter_pct = max(0, min(100, parse_int_text(jitter_text, jitter_default_pct)))
    return {
        "retry_seconds": int(unified_interval_s),
        "max_seconds": max(1, parse_int_text(max_days_text, 1)) * 86400,
        "max_bytes": parse_int_text(max_bytes_text, 200),
        "rate_seconds": int(unified_interval_s),
        "parallel_sends": max(1, parse_int_text(batch_count_text, parallel_default)),
        "activity_intra_batch_gap_ms": max(0, parse_int_text(intra_gap_text, intra_gap_default)),
        "activity_show_advanced": bool(show_advanced),
        "activity_retry_backoff_max_seconds": float(max(1, parse_int_text(backoff_cap_text, backoff_default))),
        "activity_retry_jitter_ratio": float(jitter_pct) / 100.0,
    }
