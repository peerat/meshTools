#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
node_db_update.py

One-shot Meshtastic node database updater with cumulative JSON storage.

Features:
- Captures channel utilization and TX air utilization from --nodes output
- Stores complete --info output in database
- Maintains per-node raw snapshots from parsed --nodes data
- Tracks changes in node properties over time
- Reports new nodes and property changes

Usage:
    python node_db_update.py --port /dev/ttyUSB0 --db nodeDb.txt
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple


# ==============================================================================
# Utility Functions
# ==============================================================================

def iso_now() -> str:
    """Return current UTC time in ISO format."""
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def run_cmd(cmd: List[str], timeout: int) -> Tuple[int, str, str]:
    """
    Execute command and return (returncode, stdout, stderr).
    
    Args:
        cmd: Command and arguments as list
        timeout: Maximum execution time in seconds
        
    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def atomic_write_text(path: str, data: str) -> None:
    """
    Atomically write text data to file using temp file and rename.
    
    Args:
        path: Destination file path
        data: Text content to write
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    
    fd, tmp_path = tempfile.mkstemp(
        prefix=".tmp_nodeDb_",
        dir=directory,
        text=True
    )
    
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def safe_float(value: Any) -> Optional[float]:
    """Safely convert value to float, return None on error."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def safe_int(value: Any) -> Optional[int]:
    """Safely convert value to int, return None on error."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def try_parse_json(stdout: str) -> Optional[Any]:
    """
    Attempt to parse JSON from command output.
    
    Strips common preface lines like "Connected to radio" before parsing.
    
    Args:
        stdout: Raw command output
        
    Returns:
        Parsed JSON object or None if parsing fails
    """
    text = stdout.strip()
    if not text:
        return None
    
    # Remove known preface lines
    lines = [
        line for line in text.splitlines()
        if line.strip() and line.strip() != "Connected to radio"
    ]
    
    cleaned = "\n".join(lines).strip()
    if not cleaned:
        return None
    
    try:
        return json.loads(cleaned)
    except (json.JSONDecodeError, ValueError):
        return None


# ==============================================================================
# ASCII Table Parsing
# ==============================================================================

BOX_ROW_RE = re.compile(r"^\s*│")
DATA_ROW_START_RE = re.compile(r"^\s*│\s*\d+\s*│")


def split_box_row(line: str) -> List[str]:
    """Split ASCII table row by │ delimiter and strip whitespace."""
    parts = [part.strip() for part in line.strip().strip("│").split("│")]
    return parts


def parse_nodes_table(stdout: str) -> List[Dict[str, Any]]:
    """
    Parse ASCII box-drawing table from --nodes output.
    
    Returns list of row dicts with column headers as keys, plus special
    "__cols__" key containing the column names in order.
    
    Args:
        stdout: Raw --nodes command output
        
    Returns:
        List of parsed row dictionaries
    """
    lines = [ln.rstrip("\n") for ln in stdout.splitlines() if ln.strip()]
    header_cols: Optional[List[str]] = None
    rows: List[Dict[str, Any]] = []
    
    for line in lines:
        if not BOX_ROW_RE.match(line):
            continue
        
        # Detect header row
        if header_cols is None:
            if "│" in line and "User" in line and "ID" in line and "Hardware" in line:
                header_cols = split_box_row(line)
            continue
        
        # Parse data rows (start with │ <number> │)
        if not DATA_ROW_START_RE.match(line):
            continue
        
        parts = split_box_row(line)
        
        # Trim to header length
        if len(parts) >= len(header_cols):
            parts = parts[:len(header_cols)]
        
        # Validate row length
        if len(parts) != len(header_cols):
            continue
        
        row = dict(zip(header_cols, parts))
        row["__cols__"] = header_cols
        rows.append(row)
    
    return rows


# ==============================================================================
# Column Matching and Value Parsing
# ==============================================================================

def _normalize_column_name(name: str) -> str:
    """
    Normalize column header for fuzzy matching.
    
    - Convert to lowercase
    - Remove punctuation (%, ., commas)
    - Collapse whitespace
    
    Args:
        name: Raw column header
        
    Returns:
        Normalized column name
    """
    normalized = name.strip().lower()
    normalized = normalized.replace("%", "")
    normalized = re.sub(r"[^\w\s]", " ", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _get_column_value(row: Dict[str, Any], candidates: List[str]) -> Optional[str]:
    """
    Get column value using fuzzy matching on header names.
    
    Tries exact normalized match first, then substring match.
    Returns None for empty/N/A values.
    
    Args:
        row: Parsed table row dictionary
        candidates: List of possible normalized column names
        
    Returns:
        Column value or None
    """
    # Try exact normalized match
    for key in row.keys():
        if key == "__cols__":
            continue
        
        normalized_key = _normalize_column_name(key)
        for candidate in candidates:
            if normalized_key == candidate:
                value = row.get(key)
                if value is None:
                    continue
                
                value_str = str(value).strip()
                return value_str if value_str and value_str != "N/A" else None
    
    # Fallback: substring match
    for key in row.keys():
        if key == "__cols__":
            continue
        
        normalized_key = _normalize_column_name(key)
        for candidate in candidates:
            if candidate in normalized_key:
                value = row.get(key)
                if value is None:
                    continue
                
                value_str = str(value).strip()
                return value_str if value_str and value_str != "N/A" else None
    
    return None


def _parse_percentage(value: Optional[str]) -> Optional[float]:
    """Parse percentage string (e.g., '45.2%') to float."""
    if not value:
        return None
    cleaned = value.replace("%", "").strip()
    return safe_float(cleaned)


def _parse_degrees(value: Optional[str]) -> Optional[float]:
    """Parse degree string (e.g., '45.2°') to float."""
    if not value:
        return None
    cleaned = value.replace("°", "").strip()
    return safe_float(cleaned)


def _parse_altitude_meters(value: Optional[str]) -> Optional[float]:
    """Parse altitude string (e.g., '123m') to float."""
    if not value:
        return None
    cleaned = value.lower().replace("m", "").strip()
    return safe_float(cleaned)


def _parse_decibels(value: Optional[str]) -> Optional[float]:
    """Parse decibel string (e.g., '10dB') to float."""
    if not value:
        return None
    cleaned = value.replace("dB", "").replace("db", "").strip()
    return safe_float(cleaned)


def _parse_battery(value: Optional[str]) -> Dict[str, Any]:
    """
    Parse battery status.
    
    Returns dict with 'state' and 'percent' keys.
    Handles 'Powered', percentage values, and text states.
    
    Args:
        value: Battery status string
        
    Returns:
        Dictionary with state and percent fields
    """
    if not value:
        return {"state": None, "percent": None}
    
    value_lower = value.strip().lower()
    
    # Handle "Powered" state
    if value_lower == "powered":
        return {"state": "Powered", "percent": None}
    
    # Handle percentage
    if value.strip().endswith("%"):
        return {"state": None, "percent": _parse_percentage(value)}
    
    # Handle other states
    return {"state": value.strip(), "percent": None}


# ==============================================================================
# Node Data Normalization
# ==============================================================================

def normalize_node_from_table_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize node data from parsed ASCII table row.
    
    Uses robust column matching to handle variations in column headers
    across different meshtastic CLI versions.
    
    Args:
        row: Parsed table row dictionary
        
    Returns:
        Normalized node dictionary with standardized keys
    """
    # Extract node ID
    node_id = _get_column_value(row, ["id"])
    if not node_id or not node_id.startswith("!"):
        return {}
    
    # Extract core fields
    user = _get_column_value(row, ["user"])
    aka = _get_column_value(row, ["aka"])
    hardware = _get_column_value(row, ["hardware"])
    pubkey = _get_column_value(row, ["pubkey"])
    role = _get_column_value(row, ["role"])
    
    # Extract position data
    lat_str = _get_column_value(row, ["latitude", "lat"])
    lon_str = _get_column_value(row, ["longitude", "lon"])
    alt_str = _get_column_value(row, ["altitude", "alt", "alt m", "altitude m"])
    
    # Extract telemetry
    battery_str = _get_column_value(row, ["battery", "batt"])
    channel_util_str = _get_column_value(row, [
        "channel util", "channel utilization", "chan util", "ch util"
    ])
    tx_air_str = _get_column_value(row, [
        "tx air util", "tx air utilization", "air util", "tx air"
    ])
    snr_str = _get_column_value(row, ["snr"])
    hops_str = _get_column_value(row, ["hops"])
    channel_str = _get_column_value(row, ["channel", "channel index", "ch index"])
    
    # Extract timestamps
    last_heard = _get_column_value(row, ["lastheard", "last heard"])
    since = _get_column_value(row, ["since"])
    
    # Build normalized node data
    node_data: Dict[str, Any] = {
        "id": node_id,
        "user": user,
        "aka": aka,
        "hardware": hardware,
        "pubkey": pubkey,
        "role": role,
        "position": {
            "lat": _parse_degrees(lat_str),
            "lon": _parse_degrees(lon_str),
            "alt_m": _parse_altitude_meters(alt_str),
        },
        "battery": _parse_battery(battery_str),
        "channel_util_pct": _parse_percentage(channel_util_str),
        "tx_air_util_pct": _parse_percentage(tx_air_str),
        "snr_db": _parse_decibels(snr_str),
        "hops": safe_int(hops_str) if hops_str else None,
        "channel_index": safe_int(channel_str) if channel_str else None,
        "last_heard": last_heard,
        "since": since,
        # Preserve raw row data
        "raw_nodes_row": {k: v for k, v in row.items() if k != "__cols__"},
    }
    
    return node_data


# ==============================================================================
# Info Command Parsing
# ==============================================================================

def parse_info_output(stdout: str) -> Dict[str, Any]:
    """
    Parse meshtastic --info output.
    
    Attempts JSON parsing first, falls back to raw text.
    
    Args:
        stdout: Raw --info command output
        
    Returns:
        Dictionary with 'json' or 'raw_text' key
    """
    parsed_json = try_parse_json(stdout)
    
    if isinstance(parsed_json, (dict, list)):
        return {"json": parsed_json}
    
    # Fallback to raw text
    text_lines = [
        line for line in stdout.splitlines()
        if line.strip() and line.strip() != "Connected to radio"
    ]
    text = "\n".join(text_lines)
    
    return {"raw_text": text}


# ==============================================================================
# Output Formatting
# ==============================================================================

def _format_cell(value: Any) -> str:
    if value is None:
        return "-"
    return str(value)


def format_table(headers: List[str], rows: List[List[Any]]) -> List[str]:
    widths = [len(header) for header in headers]
    for row in rows:
        for idx, value in enumerate(row):
            widths[idx] = max(widths[idx], len(_format_cell(value)))
    lines = []
    header_line = "  " + "  ".join(
        header.ljust(widths[idx]) for idx, header in enumerate(headers)
    )
    separator_line = "  " + "  ".join("-" * width for width in widths)
    lines.append(header_line)
    lines.append(separator_line)
    for row in rows:
        line = "  " + "  ".join(
            _format_cell(value).ljust(widths[idx]) for idx, value in enumerate(row)
        )
        lines.append(line)
    return lines


# ==============================================================================
# Database Operations
# ==============================================================================

# Fields to track for changes
TRACKED_FIELDS = [
    ("user", "user"),
    ("aka", "aka"),
    ("hardware", "hardware"),
    ("pubkey", "pubkey"),
    ("role", "role"),
    ("position.lat", "position.lat"),
    ("position.lon", "position.lon"),
    ("position.alt_m", "position.alt_m"),
    ("battery.state", "battery.state"),
    ("battery.percent", "battery.percent"),
    ("snr_db", "snr_db"),
]


def deep_get(data: Dict[str, Any], path: str) -> Any:
    """
    Get value from nested dictionary using dot notation path.
    
    Args:
        data: Source dictionary
        path: Dot-separated path (e.g., 'position.lat')
        
    Returns:
        Value at path or None if not found
    """
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def deep_set(data: Dict[str, Any], path: str, value: Any) -> None:
    """
    Set value in nested dictionary using dot notation path.
    
    Creates intermediate dictionaries as needed.
    
    Args:
        data: Target dictionary
        path: Dot-separated path (e.g., 'position.lat')
        value: Value to set
    """
    parts = path.split(".")
    current: Any = data
    
    # Navigate to parent
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]
    
    # Set value
    current[parts[-1]] = value


def load_database(path: str) -> Dict[str, Any]:
    """
    Load database from JSON file.
    
    Creates new database if file doesn't exist or is corrupt.
    Backs up corrupt files before replacing.
    
    Args:
        path: Database file path
        
    Returns:
        Database dictionary
    """
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return {
            "meta": {
                "created_utc": iso_now(),
                "updated_utc": None
            },
            "nodes": {}
        }
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        # Backup corrupt file
        backup_path = f"{path}.corrupt_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.replace(path, backup_path)
        
        return {
            "meta": {
                "created_utc": iso_now(),
                "updated_utc": None,
                "recovered_from": backup_path
            },
            "nodes": {}
        }


def ensure_node_record(node_id: str, db_nodes: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure node record exists in database, create if needed.
    
    Args:
        node_id: Node identifier
        db_nodes: Database nodes dictionary
        
    Returns:
        Node record dictionary
    """
    if node_id not in db_nodes:
        db_nodes[node_id] = {
            "id": node_id,
            "first_seen_utc": iso_now(),
            "last_seen_utc": None,
            "current": {},
            "history": [],  # [{ts_utc, changes: {field: {from, to}}}]
        }
    
    return db_nodes[node_id]


def apply_node_update(
    node_record: Dict[str, Any],
    new_data: Dict[str, Any],
    timestamp_utc: str
) -> Dict[str, Any]:
    """
    Apply updates to node record and track changes.
    
    Compares new data against current state, records changes in history,
    and updates current state.
    
    Args:
        node_record: Existing node record
        new_data: New node data from scan
        timestamp_utc: Update timestamp
        
    Returns:
        Dictionary of changes: {field: {from, to}}
    """
    current = node_record.get("current", {})
    changes: Dict[str, Any] = {}
    
    # Check tracked fields for changes
    for field_path, source_path in TRACKED_FIELDS:
        new_value = deep_get(new_data, source_path)
        old_value = deep_get(current, field_path)
        
        # Handle numeric jitter for floats
        if isinstance(new_value, float) and isinstance(old_value, float):
            if abs(new_value - old_value) < 1e-6:
                continue
        
        # Record change if values differ
        if new_value != old_value and not (new_value is None and old_value is None):
            changes[field_path] = {
                "from": old_value,
                "to": new_value
            }
            deep_set(current, field_path, new_value)
    
    # Always update telemetry fields
    for key in ("last_heard", "since"):
        value = new_data.get(key)
        if value is not None:
            current[key] = value
    
    # Preserve raw row snapshot
    raw_row = new_data.get("raw_nodes_row")
    if isinstance(raw_row, dict):
        current["raw_nodes_row"] = raw_row
    
    # Update record
    node_record["current"] = current
    node_record["last_seen_utc"] = timestamp_utc
    
    # Add to history if changes occurred
    if changes:
        node_record["history"].append({
            "ts_utc": timestamp_utc,
            "changes": changes
        })
    
    return changes


# ==============================================================================
# Main Function
# ==============================================================================

def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="One-shot Meshtastic node database updater"
    )
    parser.add_argument(
        "--port",
        default="/dev/ttyUSB0",
        help="Serial port (default: /dev/ttyUSB0)"
    )
    parser.add_argument(
        "--db",
        default="nodeDb.txt",
        help="Database file path (default: nodeDb.txt)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=40,
        help="Command timeout in seconds (default: 40)"
    )
    parser.add_argument(
        "--meshtastic-bin",
        default="meshtastic",
        help="Meshtastic CLI binary name or path"
    )
    parser.add_argument(
        "--channel",
        type=int,
        default=None,
        help="Optional channel index to query"
    )
    
    args = parser.parse_args()
    timestamp = iso_now()
    
    # Load database
    db = load_database(args.db)
    db.setdefault("meta", {})
    db.setdefault("nodes", {})
    db["meta"]["updated_utc"] = timestamp
    db["meta"]["last_port"] = args.port
    
    # Build base command
    base_cmd = [args.meshtastic_bin, "--port", args.port]
    if args.channel is not None:
        base_cmd += ["--ch-index", str(args.channel)]
    
    # ===== Fetch nodes data =====
    nodes_json = None
    nodes_stdout = ""
    nodes_stderr = ""
    
    # Try different JSON output flags
    for json_flag in (["--format", "json"], ["--json"], []):
        cmd = base_cmd + ["--nodes"] + json_flag
        returncode, stdout, stderr = run_cmd(cmd, timeout=args.timeout)
        
        if returncode != 0:
            nodes_stdout, nodes_stderr = stdout, stderr
            continue
        
        parsed = try_parse_json(stdout)
        if parsed is not None:
            nodes_json = parsed
            nodes_stdout, nodes_stderr = stdout, stderr
            break
        
        nodes_stdout, nodes_stderr = stdout, stderr
        if not json_flag:  # Last attempt
            break
    
    # Check for command failure
    if not nodes_stdout.strip() and nodes_stderr.strip():
        print("[ERROR] meshtastic --nodes returned no output.", file=sys.stderr)
        print(nodes_stderr.strip(), file=sys.stderr)
        return 2
    
    # ===== Normalize nodes data =====
    normalized_nodes: List[Dict[str, Any]] = []
    
    if isinstance(nodes_json, list):
        # Parse JSON format
        for item in nodes_json:
            if not isinstance(item, dict):
                continue
            
            node_id = item.get("id") or item.get("ID") or item.get("nodeId")
            if not node_id or not isinstance(node_id, str) or not node_id.startswith("!"):
                continue
            
            normalized_nodes.append({
                "id": node_id,
                "user": item.get("user") or item.get("longName") or item.get("User"),
                "aka": item.get("aka") or item.get("shortName") or item.get("AKA"),
                "hardware": item.get("hardware") or item.get("hwModel") or item.get("Hardware"),
                "pubkey": item.get("pubkey") or item.get("publicKey") or item.get("Pubkey"),
                "role": item.get("role") or item.get("Role"),
                "position": {
                    "lat": safe_float(item.get("latitude") or item.get("lat")),
                    "lon": safe_float(item.get("longitude") or item.get("lon")),
                    "alt_m": safe_float(item.get("altitude") or item.get("alt_m") or item.get("alt")),
                },
                "battery": {
                    "state": item.get("batteryState"),
                    "percent": safe_float(
                        item.get("batteryLevel") or item.get("batteryPercent") or item.get("battery")
                    ),
                },
                "channel_util_pct": safe_float(
                    item.get("channelUtil") or item.get("channel_util") or item.get("channelUtilization")
                ),
                "tx_air_util_pct": safe_float(
                    item.get("txAirUtil") or item.get("tx_air_util") or item.get("txAirUtilization")
                ),
                "snr_db": safe_float(item.get("snr") or item.get("SNR")),
                "hops": safe_int(item.get("hops") or item.get("Hops")),
                "channel_index": safe_int(item.get("channel") or item.get("Channel")),
                "last_heard": item.get("lastHeard") or item.get("LastHeard"),
                "since": item.get("since") or item.get("Since"),
                "raw_nodes_row": item,
            })
    else:
        # Parse ASCII table format
        table_rows = parse_nodes_table(nodes_stdout)
        for row in table_rows:
            normalized = normalize_node_from_table_row(row)
            if normalized.get("id"):
                normalized_nodes.append(normalized)
    
    # ===== Fetch info data =====
    info_returncode, info_stdout, info_stderr = run_cmd(
        base_cmd + ["--info"],
        timeout=args.timeout
    )
    
    info_output = info_stdout if info_returncode == 0 else (info_stdout + "\n" + info_stderr)
    info_data = parse_info_output(info_output)
    
    db["meta"]["last_info"] = {
        "ts_utc": timestamp,
        "info": info_data
    }
    
    # ===== Update database =====
    db_nodes = db["nodes"]
    new_nodes: List[str] = []
    changed_nodes: List[Tuple[str, Dict[str, Any]]] = []
    
    # Change counters
    rename_count = 0
    aka_count = 0
    role_count = 0
    hardware_count = 0
    pubkey_count = 0
    
    seen_node_ids = set()
    
    for node_data in normalized_nodes:
        node_id = node_data["id"]
        seen_node_ids.add(node_id)
        
        is_new = node_id not in db_nodes
        record = ensure_node_record(node_id, db_nodes)
        changes = apply_node_update(record, node_data, timestamp)
        
        if is_new:
            new_nodes.append(node_id)
        
        if changes:
            changed_nodes.append((node_id, changes))
            
            # Count specific change types
            if "user" in changes:
                rename_count += 1
            if "aka" in changes:
                aka_count += 1
            if "role" in changes:
                role_count += 1
            if "hardware" in changes:
                hardware_count += 1
            if "pubkey" in changes:
                pubkey_count += 1
    
    # Record run statistics
    db["meta"]["last_run_stats"] = {
        "ts_utc": timestamp,
        "nodes_seen": len(seen_node_ids),
        "new_nodes": len(new_nodes),
        "nodes_changed": len(changed_nodes),
    }
    
    # ===== Save database =====
    db_json = json.dumps(db, ensure_ascii=False, indent=2, sort_keys=True)
    atomic_write_text(args.db, db_json)
    
    # ===== Report results =====
    print(f"[OK] Database updated: {args.db}")
    print(f"     Seen: {len(seen_node_ids)} | New: {len(new_nodes)} | Changed: {len(changed_nodes)}")
    
    # Report new nodes
    if new_nodes:
        print("\n[NEW NODES]")
        new_rows: List[List[Any]] = []
        for idx, node_id in enumerate(sorted(new_nodes), 1):
            record = db_nodes[node_id]
            current = record.get("current", {})
            new_rows.append([
                idx,
                node_id,
                current.get("user"),
                current.get("aka"),
                current.get("hardware"),
                current.get("role"),
                record.get("last_seen_utc"),
                current.get("last_heard"),
                current.get("since"),
            ])
        for line in format_table(
            ["#", "ID", "User", "AKA", "HW", "Role", "Last Seen (UTC)", "Last Heard", "Since"],
            new_rows,
        ):
            print(line)

    # Report changes
    if changed_nodes:
        print("\n[CHANGES]")
        for node_id, changes in changed_nodes:
            current = db_nodes[node_id]["current"]
            name = current.get("user")
            aka = current.get("aka")
            last_seen = db_nodes[node_id].get("last_seen_utc")
            last_heard = current.get("last_heard")
            
            header = f"  * {node_id}"
            if name or aka:
                header += f" ({name or ''}{' / ' if (name and aka) else ''}{aka or ''})"
            print(f"{header}  last_seen_utc={last_seen!r}  last_heard={last_heard!r}")
            
            change_rows: List[List[Any]] = []
            for field, change_info in changes.items():
                change_rows.append([
                    field,
                    change_info.get("from"),
                    change_info.get("to"),
                ])
            for line in format_table(["Field", "From", "To"], change_rows):
                print(line)
        
        print("\n[CHANGE COUNTS]")
        print(f"  User renamed:       {rename_count}")
        print(f"  AKA changed:        {aka_count}")
        print(f"  Role changed:       {role_count}")
        print(f"  Hardware changed:   {hardware_count}")
        print(f"  Pubkey changed:     {pubkey_count}")
    
    print("\n[NODES]")
    node_rows: List[List[Any]] = []
    sorted_nodes = sorted(
        db_nodes.items(),
        key=lambda item: item[1].get("first_seen_utc") or "",
        reverse=True,
    )
    for idx, (node_id, record) in enumerate(sorted_nodes, 1):
        current = record.get("current", {})
        node_rows.append([
            idx,
            node_id,
            current.get("user"),
            current.get("aka"),
            record.get("last_seen_utc"),
            current.get("last_heard"),
            current.get("since"),
        ])
    for line in format_table(
        ["#", "ID", "User", "AKA", "Last Seen (UTC)", "Last Heard", "Since"],
        node_rows,
    ):
        print(line)
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
