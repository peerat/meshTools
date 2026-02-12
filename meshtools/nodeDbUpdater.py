#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""
node_db_update.py

One-shot Meshtastic node DB updater with a cumulative JSON store.
RU: Одноразовый обновитель базы узлов Meshtastic с накопительным JSON‑хранилищем.

Features:
- Captures channel utilization and TX air utilization from --nodes output
- Stores full --info output in the DB
- Keeps a raw snapshot per node from --nodes parsing
- Tracks node property changes over time
- Prints new nodes and changed fields
RU:
- Снимает channel utilization и TX air utilization из вывода --nodes
- Сохраняет полный вывод --info в базе
- Хранит сырой снимок по каждому узлу из парсинга --nodes
- Отслеживает изменения свойств узлов со временем
- Печатает новые узлы и изменения свойств

Usage:
    python node_db_update.py --port /dev/ttyUSB0 --db nodeDb.txt
RU:
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
# Helper functions
# RU: Вспомогательные функции
# ==============================================================================

def iso_now() -> str:
    """Return current UTC time in ISO format. RU: Вернуть текущее время UTC в формате ISO."""
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def run_cmd(cmd: List[str], timeout: int) -> Tuple[int, str, str]:
    """
    Run a command and return (returncode, stdout, stderr).
    RU: Выполнить команду и вернуть (returncode, stdout, stderr).

    Args:
        cmd: Command and args list. RU: Команда и аргументы списком.
        timeout: Max runtime seconds. RU: Максимальное время выполнения в секундах.

    Returns:
        Tuple (return_code, stdout, stderr). RU: Кортеж (return_code, stdout, stderr).
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
    Atomically write text to file via temp file + rename.
    RU: Атомарно записать текст в файл через временный файл и переименование.

    Args:
        path: Target path. RU: Путь назначения.
        data: Text to write. RU: Текст для записи.
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
    """Безопасно преобразовать значение в float, при ошибке вернуть None."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def safe_int(value: Any) -> Optional[int]:
    """Безопасно преобразовать значение в int, при ошибке вернуть None."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def try_parse_json(stdout: str) -> Optional[Any]:
    """
    Попытаться распарсить JSON из вывода команды.

    Перед парсингом удаляет типовые префиксы вроде "Connected to radio".

    Аргументы:
        stdout: Сырой вывод команды

    Возвращает:
        Распарсенный JSON-объект или None при ошибке
    """
    text = stdout.strip()
    if not text:
        return None
    
    # Remove known prefix lines.
    # RU: Удаляем известные префиксные строки
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
# ASCII table parsing
# RU: Парсинг ASCII-таблицы
# ==============================================================================

BOX_ROW_RE = re.compile(r"^\s*│")
DATA_ROW_START_RE = re.compile(r"^\s*│\s*\d+\s*│")


def split_box_row(line: str) -> List[str]:
    """Split ASCII table row by │ and trim spaces. RU: Разбить строку ASCII-таблицы по разделителю │ и обрезать пробелы."""
    parts = [part.strip() for part in line.strip().strip("│").split("│")]
    return parts


def parse_nodes_table(stdout: str) -> List[Dict[str, Any]]:
    """
    Parse ASCII table from --nodes output.
    RU: Парсинг ASCII-таблицы из вывода --nodes.

    Returns list of row dicts keyed by column headers + "__cols__" key.
    RU: Возвращает список строк-словарей с ключами по заголовкам колонок, плюс "__cols__".

    Args:
        stdout: Raw --nodes output. RU: Сырой вывод команды --nodes.

    Returns:
        List of row dicts. RU: Список словарей строк.
    """
    lines = [ln.rstrip("\n") for ln in stdout.splitlines() if ln.strip()]
    header_cols: Optional[List[str]] = None
    rows: List[Dict[str, Any]] = []
    
    for line in lines:
        if not BOX_ROW_RE.match(line):
            continue
        
        # Find header. RU: Находим заголовок.
        if header_cols is None:
            if "│" in line and "User" in line and "ID" in line and "Hardware" in line:
                header_cols = split_box_row(line)
            continue
        
        # Parse data rows (start with │ <number> │). RU: Парсим строки данных (начинаются с │ <число> │).
        if not DATA_ROW_START_RE.match(line):
            continue
        
        parts = split_box_row(line)
        
        # Trim to header length. RU: Обрезаем до длины заголовка.
        if len(parts) >= len(header_cols):
            parts = parts[:len(header_cols)]
        
        # Validate row length. RU: Проверяем длину строки.
        if len(parts) != len(header_cols):
            continue
        
        row = dict(zip(header_cols, parts))
        row["__cols__"] = header_cols
        rows.append(row)
    
    return rows


# ==============================================================================
# Column mapping and parsing values
# RU: Сопоставление колонок и парсинг значений
# ==============================================================================

def _normalize_column_name(name: str) -> str:
    """
    Нормализовать заголовок колонки для нечёткого сопоставления.

    - Привести к нижнему регистру
    - Удалить пунктуацию (%, ., запятые)
    - Схлопнуть пробелы

    Аргументы:
        name: Исходный заголовок колонки

    Возвращает:
        Нормализованное имя колонки
    """
    normalized = name.strip().lower()
    normalized = normalized.replace("%", "")
    normalized = re.sub(r"[^\w\s]", " ", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _get_column_value(row: Dict[str, Any], candidates: List[str]) -> Optional[str]:
    """
    Получить значение колонки по нечёткому совпадению заголовков.

    Сначала пробует точное совпадение нормализованных имён, затем подстроку.
    Возвращает None для пустых/N/A значений.

    Аргументы:
        row: Словарь строки таблицы
        candidates: Список возможных нормализованных имён колонок

    Возвращает:
        Значение колонки или None
    """
    # Try exact match for normalized name.
    # RU: Пробуем точное совпадение нормализованного имени
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
    
    # Fallback: substring match.
    # RU: Запасной вариант: совпадение по подстроке
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
    """Парсинг строки процента (например, '45.2%') в float."""
    if not value:
        return None
    cleaned = value.replace("%", "").strip()
    return safe_float(cleaned)


def _parse_degrees(value: Optional[str]) -> Optional[float]:
    """Parse degrees string (e.g. '45.2°') to float. RU: Парсинг строки градусов (например, '45.2°') в float."""
    if not value:
        return None
    cleaned = value.replace("°", "").strip()
    return safe_float(cleaned)


def _parse_altitude_meters(value: Optional[str]) -> Optional[float]:
    """Parse altitude (e.g. '123m') to float. RU: Парсинг высоты (например, '123m') в float."""
    if not value:
        return None
    cleaned = value.lower().replace("m", "").strip()
    return safe_float(cleaned)


def _parse_decibels(value: Optional[str]) -> Optional[float]:
    """Parse decibels (e.g. '10dB') to float. RU: Парсинг децибел (например, '10dB') в float."""
    if not value:
        return None
    cleaned = value.replace("dB", "").replace("db", "").strip()
    return safe_float(cleaned)


def detect_device_not_found(text: str) -> bool:
    s = (text or "").lower()
    if not s:
        return False
    if "file not found error" in s:
        return True
    if "serial device" in s and "not found" in s:
        return True
    if "no such file or directory" in s and ("/dev/" in s or "tty" in s):
        return True
    if "device at" in s and "was not found" in s:
        return True
    return False


def _parse_battery(value: Optional[str]) -> Dict[str, Any]:
    """
    Parse battery state.
    RU: Парсинг состояния батареи.

    Returns dict with 'state' and 'percent'.
    RU: Возвращает словарь с ключами 'state' и 'percent'.
    Handles 'Powered', percent values, and text states.
    RU: Обрабатывает 'Powered', процентные значения и текстовые состояния.

    Args:
        value: Battery state string. RU: Строка состояния батареи.

    Returns:
        Dict with state and percent. RU: Словарь с полями state и percent.
    """
    if not value:
        return {"state": None, "percent": None}
    
    value_lower = value.strip().lower()
    
    # "Powered" state
    # RU: Состояние "Powered"
    if value_lower == "powered":
        return {"state": "Powered", "percent": None}
    
    # Percent value
    # RU: Процент
    if value.strip().endswith("%"):
        return {"state": None, "percent": _parse_percentage(value)}
    
    # Other states
    # RU: Остальные состояния
    return {"state": value.strip(), "percent": None}


# ==============================================================================
# Node data normalization
# RU: Нормализация данных узла
# ==============================================================================

def normalize_node_from_table_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Нормализация данных узла из строки ASCII-таблицы.

    Использует устойчивое сопоставление колонок, чтобы учесть вариации заголовков
    между разными версиями meshtastic CLI.

    Аргументы:
        row: Словарь строки таблицы

    Возвращает:
        Нормализованный словарь узла со стандартными ключами
    """
    # Extract node ID.
    # RU: Извлекаем ID узла
    node_id = _get_column_value(row, ["id"])
    if not node_id or not node_id.startswith("!"):
        return {}
    
    # Extract main fields.
    # RU: Извлекаем основные поля
    user = _get_column_value(row, ["user"])
    aka = _get_column_value(row, ["aka"])
    hardware = _get_column_value(row, ["hardware"])
    pubkey = _get_column_value(row, ["pubkey"])
    role = _get_column_value(row, ["role"])
    
    # Extract coordinates.
    # RU: Извлекаем координаты
    lat_str = _get_column_value(row, ["latitude", "lat"])
    lon_str = _get_column_value(row, ["longitude", "lon"])
    alt_str = _get_column_value(row, ["altitude", "alt", "alt m", "altitude m"])
    
    # Extract telemetry.
    # RU: Извлекаем телеметрию
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
    
    # Extract timestamps.
    # RU: Извлекаем временные метки
    last_heard = _get_column_value(row, ["lastheard", "last heard"])
    since = _get_column_value(row, ["since"])
    
    # Build normalized node data.
    # RU: Собираем нормализованные данные узла.
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
        # Keep raw row data.
        # RU: Сохраняем исходные данные строки.
        "raw_nodes_row": {k: v for k, v in row.items() if k != "__cols__"},
    }
    
    return node_data


# ==============================================================================
# --info parsing
# RU: Парсинг команды Info
# ==============================================================================

def parse_info_output(stdout: str) -> Dict[str, Any]:
    """
    Parse meshtastic --info output.
    RU: Парсинг вывода meshtastic --info.

    Tries JSON first, then raw text.
    RU: Сначала пытается JSON, при неудаче — сырой текст.

    Args:
        stdout: Raw --info output. RU: Сырой вывод команды --info.

    Returns:
        Dict with 'json' or 'raw_text'. RU: Словарь с ключом 'json' или 'raw_text'.
    """
    parsed_json = try_parse_json(stdout)
    
    if isinstance(parsed_json, (dict, list)):
        return {"json": parsed_json}
    
    # Fallback: raw text. RU: Запасной вариант: сырой текст.
    text_lines = [
        line for line in stdout.splitlines()
        if line.strip() and line.strip() != "Connected to radio"
    ]
    text = "\n".join(text_lines)
    
    return {"raw_text": text}


# ==============================================================================
# Output formatting
# RU: Форматирование вывода
# ==============================================================================

def _format_cell(value: Any) -> str:
    if value is None:
        return "-"
    return str(value)


def _display_width(s: str) -> int:
    import unicodedata
    width = 0
    for ch in s:
        if ch == "\t":
            width += 4
            continue
        # Combining marks do not add width. RU: Комбинируемые символы ширины не добавляют.
        if unicodedata.combining(ch):
            continue
        eaw = unicodedata.east_asian_width(ch)
        if eaw in ("W", "F"):
            width += 2
        else:
            width += 1
    return width


def _ljust_display(s: str, width: int) -> str:
    pad = width - _display_width(s)
    if pad <= 0:
        return s
    return s + (" " * pad)


def format_table(headers: List[str], rows: List[List[Any]]) -> List[str]:
    widths = [_display_width(header) for header in headers]
    for row in rows:
        for idx, value in enumerate(row):
            widths[idx] = max(widths[idx], _display_width(_format_cell(value)))
    lines = []
    header_line = "  " + "  ".join(
        _ljust_display(header, widths[idx]) for idx, header in enumerate(headers)
    )
    separator_line = "  " + "  ".join("-" * width for width in widths)
    lines.append(header_line)
    lines.append(separator_line)
    for row in rows:
        line = "  " + "  ".join(
            _ljust_display(_format_cell(value), widths[idx]) for idx, value in enumerate(row)
        )
        lines.append(line)
    return lines


def format_ts_display(value: Any) -> Any:
    """
    Привести время к виду "YYYY-MM-DD HH:MM:SS" для вывода.
    Убирает суффиксы временной зоны типа "+00:00".
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return dt.datetime.fromtimestamp(float(value), tz=dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return s
        try:
            s_norm = s.replace("Z", "+00:00")
            dt_obj = dt.datetime.fromisoformat(s_norm)
            if dt_obj.tzinfo is not None:
                dt_obj = dt_obj.astimezone(dt.timezone.utc).replace(tzinfo=None)
            return dt_obj.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            if s.endswith("+00:00"):
                s = s[:-6]
            return s.replace("T", " ")
    return value


def parse_ts_to_epoch(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return float(value)
        except Exception:
            return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            s_norm = s.replace("Z", "+00:00")
            dt_obj = dt.datetime.fromisoformat(s_norm)
            if dt_obj.tzinfo is None:
                dt_obj = dt_obj.replace(tzinfo=dt.timezone.utc)
            return dt_obj.timestamp()
        except Exception:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
                try:
                    dt_obj = dt.datetime.strptime(s, fmt).replace(tzinfo=dt.timezone.utc)
                    return dt_obj.timestamp()
                except Exception:
                    continue
    return None


# ==============================================================================
# DB operations
# RU: Операции с базой данных
# ==============================================================================

# Fields to track changes
# RU: Поля для отслеживания изменений
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
    Получить значение из вложенного словаря по пути в нотации с точками.

    Аргументы:
        data: Исходный словарь
        path: Путь с точками (например, 'position.lat')

    Возвращает:
        Значение по пути или None, если не найдено
    """
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def deep_set(data: Dict[str, Any], path: str, value: Any) -> None:
    """
    Установить значение во вложенном словаре по пути в нотации с точками.

    При необходимости создаёт промежуточные словари.

    Аргументы:
        data: Целевой словарь
        path: Путь с точками (например, 'position.lat')
        value: Значение для установки
    """
    parts = path.split(".")
    current: Any = data
    
    # Move to parent.
    # RU: Переходим к родителю
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]
    
    # Set value.
    # RU: Устанавливаем значение
    current[parts[-1]] = value


def load_database(path: str) -> Dict[str, Any]:
    """
    Загрузить базу из JSON-файла.

    Создаёт новую базу, если файла нет или он повреждён.
    Делает бэкап повреждённого файла перед заменой.

    Аргументы:
        path: Путь к файлу базы

    Возвращает:
        Словарь базы
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
        # Backup corrupted file.
        # RU: Бэкап повреждённого файла
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
    Убедиться, что запись узла есть в базе, при необходимости создать.

    Аргументы:
        node_id: Идентификатор узла
        db_nodes: Словарь узлов базы

    Возвращает:
        Словарь записи узла
    """
    if node_id not in db_nodes:
        db_nodes[node_id] = {
            "id": node_id,
            "first_seen_utc": iso_now(),
            "last_seen_utc": None,
            "current": {},
            "history": [],  # history format: [{ts_utc, changes: {field: {from, to}}}] RU: формат истории: [{ts_utc, changes: {field: {from, to}}}]
        }
    
    return db_nodes[node_id]


def apply_node_update(
    node_record: Dict[str, Any],
    new_data: Dict[str, Any],
    timestamp_utc: str
) -> Dict[str, Any]:
    """
    Применить обновления к записи узла и отследить изменения.

    Сравнивает новые данные с текущим состоянием, пишет изменения в историю
    и обновляет текущее состояние.

    Аргументы:
        node_record: Существующая запись узла
        new_data: Новые данные сканирования
        timestamp_utc: Временная метка обновления

    Возвращает:
        Словарь изменений: {field: {from, to}}
    """
    current = node_record.get("current", {})
    changes: Dict[str, Any] = {}
    
    # Check tracked fields for changes.
    # RU: Проверяем отслеживаемые поля на изменения
    for field_path, source_path in TRACKED_FIELDS:
        new_value = deep_get(new_data, source_path)
        old_value = deep_get(current, field_path)
        
        # Ignore minor float noise.
        # RU: Учитываем числовой шум для float
        if isinstance(new_value, float) and isinstance(old_value, float):
            if abs(new_value - old_value) < 1e-6:
                continue
        
        # Record change when values differ.
        # RU: Фиксируем изменение при различии значений
        if new_value != old_value and not (new_value is None and old_value is None):
            changes[field_path] = {
                "from": old_value,
                "to": new_value
            }
            deep_set(current, field_path, new_value)
    
    # Always update telemetry.
    # RU: Всегда обновляем телеметрию
    for key in ("last_heard", "since"):
        value = new_data.get(key)
        if value is not None:
            current[key] = value
    
    # Store raw row snapshot.
    # RU: Сохраняем сырой снимок строки
    raw_row = new_data.get("raw_nodes_row")
    if isinstance(raw_row, dict):
        current["raw_nodes_row"] = raw_row
    
    # Update record.
    # RU: Обновляем запись
    node_record["current"] = current
    # Align last_seen_utc to last_heard when available.
    # RU: last_seen_utc при наличии выравниваем по last_heard
    last_heard = new_data.get("last_heard")
    if isinstance(last_heard, str) and last_heard.strip():
        node_record["last_seen_utc"] = last_heard.strip()
    elif isinstance(last_heard, (int, float)):
        try:
            node_record["last_seen_utc"] = dt.datetime.fromtimestamp(
                float(last_heard), tz=dt.timezone.utc
            ).isoformat(timespec="seconds")
        except Exception:
            node_record["last_seen_utc"] = timestamp_utc
    else:
        node_record["last_seen_utc"] = timestamp_utc
    
    # Append history if changed.
    # RU: Добавляем в историю, если были изменения
    if changes:
        node_record["history"].append({
            "ts_utc": timestamp_utc,
            "changes": changes
        })
    
    return changes


# ==============================================================================
# Main function
# RU: Основная функция
# ==============================================================================

def main() -> int:
    """Main entry point. RU: Основная точка входа."""
    parser = argparse.ArgumentParser(
        description="One-shot Meshtastic node DB updater. RU: Одноразовый обновитель базы узлов Meshtastic.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python nodeDbUpdater.py --port /dev/ttyUSB0 --db nodeDb.txt\n"
            "  python nodeDbUpdater.py --regenerate\n"
            "  python nodeDbUpdater.py --prune-days 30\n"
            "\n"
            "RU: Примеры:\n"
            "  python nodeDbUpdater.py --port /dev/ttyUSB0 --db nodeDb.txt\n"
            "  python nodeDbUpdater.py --regenerate\n"
            "  python nodeDbUpdater.py --prune-days 30\n"
        ),
    )
    parser.add_argument(
        "--port",
        default="/dev/ttyUSB0",
        help="Serial port (default: /dev/ttyUSB0, Windows: COM3). RU: Серийный порт (по умолчанию: /dev/ttyUSB0, Windows: COM3)."
    )
    parser.add_argument(
        "--db",
        default="nodeDb.txt",
        help="DB file path (default: nodeDb.txt). RU: Путь к файлу базы (по умолчанию: nodeDb.txt)."
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=40,
        help="Command timeout in seconds (default: 40). RU: Таймаут команд в секундах (по умолчанию: 40)."
    )
    parser.add_argument(
        "--meshtastic-bin",
        default="meshtastic",
        help="Meshtastic CLI name/path. RU: Имя/путь до Meshtastic CLI."
    )
    parser.add_argument(
        "--channel",
        type=int,
        default=None,
        help="Optional channel index. RU: Опциональный индекс канала для запроса."
    )
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="Recreate DB from scratch (ignore existing). RU: Пересоздать базу с нуля (игнорировать существующую)."
    )
    parser.add_argument(
        "--prune-days",
        type=int,
        default=None,
        help="Delete nodes not seen for N days. RU: Удалить узлы, не замеченные дольше N дней."
    )
    
    args = parser.parse_args()
    timestamp = iso_now()
    
    # Load DB. RU: Загружаем базу.
    if args.regenerate:
        db = {
            "meta": {
                "created_utc": iso_now(),
                "updated_utc": None
            },
            "nodes": {}
        }
    else:
        db = load_database(args.db)
    db.setdefault("meta", {})
    db.setdefault("nodes", {})
    db["meta"]["updated_utc"] = timestamp
    db["meta"]["last_port"] = args.port
    
    # Build base command. RU: Собираем базовую команду.
    base_cmd = [args.meshtastic_bin, "--port", args.port]
    if args.channel is not None:
        base_cmd += ["--ch-index", str(args.channel)]
    
    # ===== Nodes retrieval =====
    # RU: Получение данных узлов
    nodes_json = None
    nodes_stdout = ""
    nodes_stderr = ""
    
    # Try JSON output flags.
    # RU: Пробуем разные флаги JSON-вывода
    for json_flag in (["--format", "json"], ["--json"], []):
        cmd = base_cmd + ["--nodes"] + json_flag
        returncode, stdout, stderr = run_cmd(cmd, timeout=args.timeout)
        
        if detect_device_not_found((stdout or "") + "\n" + (stderr or "")):
            print(
                f"[ERROR] Device not found on port {args.port}. Check cable/port/drivers (Windows: COM3). "
                f"RU: Устройство не найдено на порту {args.port}. Проверьте кабель/порт/драйверы (Windows: COM3).",
                file=sys.stderr,
            )
            return 2

        if returncode != 0:
            nodes_stdout, nodes_stderr = stdout, stderr
            continue
        
        parsed = try_parse_json(stdout)
        if parsed is not None:
            nodes_json = parsed
            nodes_stdout, nodes_stderr = stdout, stderr
            break
        
        nodes_stdout, nodes_stderr = stdout, stderr
        if not json_flag:  # Last attempt. RU: Последняя попытка
            break
    
    # Check command success. RU: Проверяем, что команда не провалилась.
    if not nodes_stdout.strip() and nodes_stderr.strip():
        print("[ERROR] meshtastic --nodes returned no output.", file=sys.stderr)
        print(nodes_stderr.strip(), file=sys.stderr)
        return 2
    
    # ===== Node normalization =====
    # RU: Нормализация данных узлов
    normalized_nodes: List[Dict[str, Any]] = []
    
    if isinstance(nodes_json, list):
        # Parse JSON format.
        # RU: Парсим JSON-формат
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
        # Parse ASCII table format.
        # RU: Парсим формат ASCII-таблицы
        table_rows = parse_nodes_table(nodes_stdout)
        for row in table_rows:
            normalized = normalize_node_from_table_row(row)
            if normalized.get("id"):
                normalized_nodes.append(normalized)
    
    # ===== Info retrieval =====
    # RU: Получение данных info
    info_returncode, info_stdout, info_stderr = run_cmd(
        base_cmd + ["--info"],
        timeout=args.timeout
    )

    if detect_device_not_found((info_stdout or "") + "\n" + (info_stderr or "")):
        print(
            f"[ERROR] Device not found on port {args.port}. Check cable/port/drivers (Windows: COM3). "
            f"RU: Устройство не найдено на порту {args.port}. Проверьте кабель/порт/драйверы (Windows: COM3).",
            file=sys.stderr,
        )
        return 2
    
    info_output = info_stdout if info_returncode == 0 else (info_stdout + "\n" + info_stderr)
    info_data = parse_info_output(info_output)
    
    db["meta"]["last_info"] = {
        "ts_utc": timestamp,
        "info": info_data
    }
    
    # ===== DB update =====
    # RU: Обновление базы
    db_nodes = db["nodes"]
    new_nodes: List[str] = []
    changed_nodes: List[Tuple[str, Dict[str, Any]]] = []
    
    # Change counters. RU: Счётчики изменений.
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
            
            # Count specific change types.
            # RU: Считаем конкретные типы изменений
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
    
    # Record run stats.
    # RU: Записываем статистику запуска
    db["meta"]["last_run_stats"] = {
        "ts_utc": timestamp,
        "nodes_seen": len(seen_node_ids),
        "new_nodes": len(new_nodes),
        "nodes_changed": len(changed_nodes),
    }

    # Prune old records by last seen time.
    # RU: Удаляем старые записи по времени последнего появления
    pruned_count = 0
    if args.prune_days is not None and args.prune_days >= 0:
        cutoff = dt.datetime.now(dt.timezone.utc).timestamp() - (args.prune_days * 86400)
        to_delete = []
        for node_id, record in db_nodes.items():
            current = record.get("current", {})
            ts = parse_ts_to_epoch(current.get("last_heard"))
            if ts is None:
                ts = parse_ts_to_epoch(record.get("last_seen_utc"))
            if ts is None:
                ts = parse_ts_to_epoch(record.get("first_seen_utc"))
            if ts is not None and ts < cutoff:
                to_delete.append(node_id)
        for node_id in to_delete:
            del db_nodes[node_id]
            pruned_count += 1
    
    # ===== Save DB =====
    # RU: Сохраняем базу
    db_json = json.dumps(db, ensure_ascii=False, indent=2, sort_keys=True)
    atomic_write_text(args.db, db_json)
    
    # ===== Output results =====
    # RU: Выводим результаты
    print(f"[OK] Database updated: {args.db}")
    print(f"     Seen: {len(seen_node_ids)} | New: {len(new_nodes)} | Changed: {len(changed_nodes)}")
    if args.prune_days is not None and args.prune_days >= 0:
        print(f"     Pruned: {pruned_count} (older than {args.prune_days} days)")
    
    # New nodes output. RU: Вывод новых узлов.
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
                format_ts_display(record.get("last_seen_utc")),
                format_ts_display(current.get("last_heard")),
                current.get("since"),
            ])
        for line in format_table(
            ["#", "ID", "User", "AKA", "HW", "Role", "Last Seen (UTC)", "Last Heard", "Since"],
            new_rows,
        ):
            print(line)

    # Changes output. RU: Вывод изменений.
    if changed_nodes:
        print("\n[CHANGES]")
        for node_id, changes in changed_nodes:
            changes_view = {k: v for k, v in changes.items() if k != "snr_db"}
            if not changes_view:
                continue
            current = db_nodes[node_id]["current"]
            name = current.get("user")
            aka = current.get("aka")
            last_seen = db_nodes[node_id].get("last_seen_utc")
            last_heard = current.get("last_heard")
            
            header = f"  * {node_id}"
            if name or aka:
                header += f" ({name or ''}{' / ' if (name and aka) else ''}{aka or ''})"
            print(f"{header}  last_seen_utc={format_ts_display(last_seen)!r}  last_heard={format_ts_display(last_heard)!r}")
            
            change_rows: List[List[Any]] = []
            for field, change_info in changes_view.items():
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
    def _first_seen_key(item: Tuple[str, Dict[str, Any]]) -> str:
        rec = item[1]
        val = rec.get("first_seen_utc")
        return str(val or "")

    sorted_items = sorted(db_nodes.items(), key=_first_seen_key)
    for idx, (node_id, record) in enumerate(sorted_items, 1):
        current = record.get("current", {})
        node_rows.append([
            idx,
            node_id,
            current.get("user"),
            current.get("aka"),
            format_ts_display(record.get("first_seen_utc")),
            format_ts_display(record.get("last_seen_utc")),
        ])
    for line in format_table(
        ["#", "ID", "User", "AKA", "First Seen", "Last Seen"],
        node_rows,
    ):
        print(line)
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
