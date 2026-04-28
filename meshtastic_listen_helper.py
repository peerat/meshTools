#!/usr/bin/env python3

import argparse
import datetime as dt
import json
import logging
import signal
import sys
import time
from typing import Any

import meshtastic.serial_interface
from pubsub import pub


STOP = False
IFACE = None


def iso_utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _sig_handler(_signum, _frame) -> None:
    global STOP
    STOP = True
    if IFACE is not None:
        try:
            IFACE.close()
        except Exception:
            pass


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key == "raw":
                continue
            out[key] = _sanitize(item)
        return out
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize(item) for item in value]
    if isinstance(value, bytes):
        return {"encoding": "hex", "data": value.hex()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def on_receive(packet, interface) -> None:  # pylint: disable=unused-argument
    _emit(
        {
            "kind": "packet",
            "ts_utc": iso_utc_now(),
            "packet": _sanitize(packet),
        }
    )


def on_node_updated(node, interface) -> None:  # pylint: disable=unused-argument
    _emit(
        {
            "kind": "node",
            "ts_utc": iso_utc_now(),
            "node": _sanitize(node),
        }
    )


def main() -> int:
    global IFACE

    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=None)
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)
    logging.basicConfig(level=logging.WARNING)

    pub.subscribe(on_receive, "meshtastic.receive")
    pub.subscribe(on_node_updated, "meshtastic.node.updated")

    try:
        IFACE = meshtastic.serial_interface.SerialInterface(
            devPath=args.port,
            noNodes=False,
            timeout=args.timeout,
        )
    except Exception as ex:
        print(f"listen helper failed: {ex}", file=sys.stderr, flush=True)
        return 2

    try:
        while not STOP:
            time.sleep(0.2)
    finally:
        if IFACE is not None:
            try:
                IFACE.close()
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
