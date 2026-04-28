#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any


LOG_PALETTE = {
    "error": "#f92672",
    "warn": "#fd971f",
    "key": "#ffd75f",
    "keyok": "#ffd75f",
    "caps": "#ffd75f",
    "trace": "#66d9ef",
    "pace": "#a6e22e",
    "health": "#6be5b5",
    "discovery": "#b894ff",
    "radio": "#74b2ff",
    "gui": "#e0e0e0",
    "queue": "#c3b38a",
    "route": "#c3b38a",
    "send": "#c6f08c",
    "recv": "#66d9ef",
    "ack": "#66d9ef",
    "compress": "#f4a3d7",
    "norm": "#f4a3d7",
    "pkt": "#9ec4ff",
    "ctrl": "#a6e22e",
}


def classify_log_level(text: str, level: str = "info") -> str:
    lvl = str(level or "info").strip().lower()
    low = str(text or "").lower()
    if lvl != "info":
        return lvl
    if "trace:" in low and "traceback" not in low:
        lvl = "trace"
    elif "pace:" in low:
        lvl = "pace"
    elif "health:" in low:
        lvl = "health"
    elif ("discovery:" in low) or ("hello:" in low):
        lvl = "discovery"
    elif "radio:" in low:
        lvl = "radio"
    elif "gui:" in low:
        lvl = "gui"
    elif "queue:" in low:
        lvl = "queue"
    elif "route2:" in low or "route:" in low:
        lvl = "route"
    elif "send:" in low or "sendstd:" in low:
        lvl = "send"
    elif "ack:" in low:
        lvl = "ack"
    elif "recv:" in low:
        lvl = "recv"
    elif "compstat:" in low or "compress:" in low:
        lvl = "compress"
    elif "norm:" in low:
        lvl = "norm"
    elif "pkt:" in low:
        lvl = "pkt"
    elif "ctrl:" in low:
        lvl = "ctrl"
    if "pinned key mismatch" in low:
        if "action=auto_accept" in low:
            lvl = "key"
        else:
            lvl = "error"
    elif "reject invalid public key" in low:
        lvl = "error"
    elif ("exception" in low) or ("traceback" in low):
        lvl = "error"
    elif low.startswith("error:"):
        lvl = "error"
    elif low.startswith("warn:"):
        lvl = "warn"
    elif "keyok:" in low:
        lvl = "keyok"
    elif "caps:" in low:
        lvl = "caps"
    elif ("key:" in low) or ("crypto:" in low):
        lvl = "key"
    return lvl


def should_skip_verbose_log(body: str, verbose_log: bool) -> bool:
    if bool(verbose_log):
        return False
    body_low = str(body or "").lower().strip()
    return body_low.startswith(("norm:", "compress:", "compstat:", "metrics:"))


def should_suppress_duplicate_log(body: str, level: str, now: float, last_state: dict[str, Any]) -> bool:
    lvl = str(level or "info").strip().lower()
    if lvl in ("warn", "error", "key", "keyok", "caps", "trace"):
        return False
    if body and body == str(last_state.get("body", "")) and (now - float(last_state.get("ts", 0.0) or 0.0)) < 0.6:
        return True
    return False


def append_log_to_view(view: Any, text: str, level: str, *, qtgui: Any) -> None:
    color = LOG_PALETTE.get(str(level or "info").strip().lower(), "#e0e0e0")
    try:
        view.moveCursor(qtgui.QTextCursor.End)
        view.setTextColor(qtgui.QColor(color))
        view.append(str(text).rstrip("\n"))
        view.ensureCursorVisible()
    except Exception:
        try:
            view.append(str(text))
        except Exception:
            pass
