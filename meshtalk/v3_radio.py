#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import threading

from typing import Any, Callable


_RADIO_SEND_LOCK = threading.Lock()


def send_packet(
    *,
    interface: Any,
    payload: bytes,
    destination_id: str,
    port_num: int,
    channel_index: int,
    trace_context: str,
    trace_suppressed_fn: Callable[[str, Exception], None],
    ui_emit_fn: Callable[[str, Any], None],
    log_packet_trace: bool,
    log_line: str,
) -> bool:
    try:
        with _RADIO_SEND_LOCK:
            interface.sendData(
                payload,
                destinationId=destination_id,
                wantAck=False,
                portNum=port_num,
                channelIndex=channel_index,
            )
    except Exception as ex:
        trace_suppressed_fn(trace_context, ex)
        ui_emit_fn("radio_lost", None)
        return False
    if log_packet_trace:
        try:
            ui_emit_fn("log", log_line)
        except Exception:
            pass
    return True


def try_send_packet_nowait(
    *,
    interface: Any,
    payload: bytes,
    destination_id: str,
    port_num: int,
    channel_index: int,
    trace_context: str,
    trace_suppressed_fn: Callable[[str, Exception], None],
    ui_emit_fn: Callable[[str, Any], None],
    log_packet_trace: bool,
    log_line: str,
) -> bool:
    try:
        acquired = _RADIO_SEND_LOCK.acquire(blocking=False)
    except Exception:
        acquired = False
    if not acquired:
        return False
    try:
        interface.sendData(
            payload,
            destinationId=destination_id,
            wantAck=False,
            portNum=port_num,
            channelIndex=channel_index,
        )
    except Exception as ex:
        trace_suppressed_fn(trace_context, ex)
        ui_emit_fn("radio_lost", None)
        return False
    finally:
        try:
            _RADIO_SEND_LOCK.release()
        except Exception:
            pass
    if log_packet_trace:
        try:
            ui_emit_fn("log", log_line)
        except Exception:
            pass
    return True


def send_wire_payload(
    *,
    interface: Any,
    payload: bytes,
    destination_id: str,
    port_num: int,
    channel_index: int,
    trace_context: str,
    trace_suppressed_fn: Callable[[str, Exception], None],
    ui_emit_fn: Callable[[str, Any], None],
    log_packet_trace: bool,
    log_line: str,
) -> bool:
    return send_packet(
        interface=interface,
        payload=payload,
        destination_id=destination_id,
        port_num=port_num,
        channel_index=channel_index,
        trace_context=trace_context,
        trace_suppressed_fn=trace_suppressed_fn,
        ui_emit_fn=ui_emit_fn,
        log_packet_trace=log_packet_trace,
        log_line=log_line,
    )


def send_traceroute_request(
    *,
    interface: Any,
    req: Any,
    destination_id: str,
    traceroute_port_num: int,
    on_response: Callable[..., Any],
    channel_index: int,
    hop_limit: int,
) -> None:
    try:
        with _RADIO_SEND_LOCK:
            interface.sendData(
                req,
                destinationId=destination_id,
                portNum=traceroute_port_num,
                wantResponse=True,
                onResponse=on_response,
                channelIndex=channel_index,
                hopLimit=hop_limit,
            )
    except TypeError:
        try:
            with _RADIO_SEND_LOCK:
                interface.sendData(
                    req,
                    destinationId=destination_id,
                    portNum=traceroute_port_num,
                    wantResponse=True,
                    onResponse=on_response,
                    channelIndex=channel_index,
                )
        except TypeError:
            with _RADIO_SEND_LOCK:
                interface.sendData(
                    req,
                    destinationId=destination_id,
                    portNum=traceroute_port_num,
                    wantResponse=True,
                    onResponse=on_response,
                )
