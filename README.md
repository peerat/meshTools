# meshTools

License: MIT (Open Source)
Author: Anton Vologzhanin (R3VAF)

Small utilities around Meshtastic.

## Contents

- `meshLogger.py` polls traceroute and writes daily logs to `meshLogger/`.
- `meshLogger.py` also writes an SQLite DB (`meshLogger.db`) once per hour using `meshtastic --nodes`.
- `nodeDbUpdater.py` is legacy (text DB); keep only if you still need `nodeDb.txt`.
- `graphGen.py` builds Graphviz (DOT/SVG) and D3.js (HTML/JSON) graphs from logs and node DB in `graphGen/` (SQLite preferred, `nodeDb.txt` fallback).
- `meshTalk.py` provides encrypted, ACK-based point-to-point messaging over Meshtastic (Python API).
- meshTalk UI: unread indicator (orange dot) in contact list.

## Requirements

- Python 3.9+
- Meshtastic CLI in PATH (`meshtastic`)
- `cryptography` package (for `meshTalk.py`)
- Graphviz in PATH (`dot`) for `graphGen.py`

## Windows notes

- Install Meshtastic CLI: `pip install meshtastic` (make sure Scripts is in PATH)
- Install Graphviz and add its `bin` to PATH
- Use COM port (example: `--port COM3`)
- Find real paths on your machine:
  - `where python`
  - `where meshtastic`
  - `where dot`
- Add missing folders to PATH (PowerShell, current user):
  - `setx PATH "$env:PATH;C:\path\to\Python\Scripts;C:\path\to\Graphviz\bin"`
- Via GUI (Windows):
  - Start -> "Environment Variables"
  - Edit `Path` -> New -> paste path -> OK

## Install

```bash
pip install -r requirements.txt
```

Check that tools are in PATH:

```bash
meshtastic --help
dot -V
```

## Quick start

Continuous route logging (Ctrl+C to stop):

```bash
python meshLogger.py --port /dev/ttyUSB0
```

Update node DB (one-shot):

```bash
python nodeDbUpdater.py --port /dev/ttyUSB0 --db nodeDb.txt
```

Hourly DB updates (SQLite) are built into `meshLogger.py`.
Traceroutes and listen-events are stored in SQLite only (no text logs).

Print DB schema:

```bash
python meshLogger.py --db-schema
```

Generate graph from recent logs (Graphviz + D3.js):

```bash
python graphGen.py --root .
```

Reliable P2P messaging (E2EE + ACK):

Interactive chat (stdin -> ACK on each line):

```bash
python meshTalk.py --user 02e591e0
```

Keys are stored in `keyRings/` as `<id>.key` and `<id>.pub` (leading `!` is stripped).
If `keyRings/<id>.key` / `keyRings/<id>.pub` are missing, they are generated automatically.
The script detects your node id from the radio automatically.
If a peer key is missing, a key exchange is requested automatically.
Outgoing messages are queued in `meshTalk/state.json` and logged to `meshTalk/history.log`.
Type `/keys` to rotate your keys (they will be regenerated and exchanged again).

Tip: payload size depends on channel settings (e.g. LongFast). Use `--max-bytes` to tune.

## Windows single-file build (meshTalk.exe)

Use `build_meshTalk.bat`:

```bat
build_meshTalk.bat
```

Output: `dist\meshTalk.exe`

## First run checklist

- `meshtastic --help` works
- `dot -V` works
- `python meshLogger.py --port ...` creates `meshLogger/YYYY-MM-DD !xxxxxxxx.txt`
- `python nodeDbUpdater.py --port ...` creates/updates `nodeDb.txt`

## File layout

```
meshTools/
  meshLogger.py
  nodeDbUpdater.py
  graphGen.py
  meshTalk.py
  meshLogger/   # generated daily traceroute logs
  graphGen/     # generated graphs (dot/svg/html/json)
  meshLogger.db # generated SQLite DB
  nodeDb.txt    # generated node DB (legacy)
  keyRings/     # key files (<id>.key, <id>.pub)
  meshTalk/     # queue and history (state.json, history.log)
```

## Notes

- `nodeDb.txt` may contain sensitive data (keys, coordinates). Keep it private.
- `.gitignore` excludes generated logs and DB.
- `graphGen.py` expects trace files named `YYYY-MM-DD !xxxxxxxx*.txt`.

## Troubleshooting

- `meshtastic` not found: run `pip install meshtastic` and add Scripts to PATH.
- `dot` not found: install Graphviz and add `bin` to PATH.
- No logs: ensure `meshLogger/` has `YYYY-MM-DD !xxxxxxxx*.txt` files.
- Device not found: check port name (Linux `/dev/ttyUSB0`, Windows `COM3`), cable, and drivers.

## graphGen.py (D3.js options)

- `--no-d3` disables HTML/JSON.
- `--d3-top N` limits top-N nodes for filtering (default: 30).
- `--d3-min-neighbors N` filters by neighbor count (default: 0).

---

# meshTools (RU)

Небольшие утилиты вокруг Meshtastic.

## Содержание

- `meshLogger.py` опрашивает traceroute и пишет ежедневные логи в `meshLogger/`.
- `meshLogger.py` также пишет SQLite-базу (`meshLogger.db`) раз в час через `meshtastic --nodes`.
- `nodeDbUpdater.py` — устаревший (текстовый) вариант; нужен только если нужен `nodeDb.txt`.
- `graphGen.py` строит графы Graphviz (DOT/SVG) и D3.js (HTML/JSON) из логов и базы узлов в `graphGen/` (предпочитает SQLite, fallback — `nodeDb.txt`).
- `meshTalk.py` — шифрованный P2P-обмен с ACK поверх Meshtastic (Python API).

## Требования

- Python 3.9+
- Meshtastic CLI в PATH (`meshtastic`)
- Пакет `cryptography` (для `meshTalk.py`)
- Graphviz в PATH (`dot`) для `graphGen.py`

## Примечания для Windows

- Установите Meshtastic CLI: `pip install meshtastic` (убедитесь, что Scripts в PATH)
- Установите Graphviz и добавьте его `bin` в PATH
- Используйте COM-порт (например: `--port COM3`)
- Узнать реальные пути на вашей машине:
  - `where python`
  - `where meshtastic`
  - `where dot`
- Добавить недостающие папки в PATH (PowerShell, текущий пользователь):
  - `setx PATH "$env:PATH;C:\path\to\Python\Scripts;C:\path\to\Graphviz\bin"`
- Через GUI (Windows):
  - Start -> "Environment Variables"
  - Edit `Path` -> New -> вставьте путь -> OK

## Установка

```bash
pip install -r requirements.txt
```

Проверка, что утилиты доступны в PATH:

```bash
meshtastic --help
dot -V
```

## Быстрый старт

Непрерывное логирование маршрутов (Ctrl+C для остановки):

```bash
python meshLogger.py --port /dev/ttyUSB0
```

Обновить базу узлов (однократно):

```bash
python nodeDbUpdater.py --port /dev/ttyUSB0 --db nodeDb.txt
```

Почасовое обновление SQLite-базы встроено в `meshLogger.py`.
Traceroute и события listen сохраняются только в SQLite (без текстовых логов).

Показать схему БД:

```bash
python meshLogger.py --db-schema
```

Сгенерировать граф из свежих логов (Graphviz + D3.js):

```bash
python graphGen.py --root .
```

Надежный P2P-обмен (E2EE + ACK):

Интерактивный чат (stdin -> ACK на каждую строку):

```bash
python meshTalk.py --user 02e591e0
```

Ключи хранятся в `keyRings/` как `<id>.key` и `<id>.pub` (ведущий `!` убирается).
Если `keyRings/<id>.key` / `keyRings/<id>.pub` отсутствуют, они создаются автоматически.
Скрипт автоматически определяет id узла из радио.
Если ключ собеседника отсутствует, автоматически запрашивается обмен ключами.
Исходящие сообщения складываются в `meshTalk/state.json` и логируются в `meshTalk/history.log`.
Команда `/keys` пересоздаёт ваши ключи и запускает новый обмен.

Совет: размер пакета зависит от настроек канала (например LongFast). Подбирайте `--max-bytes`.

## Сборка одного exe (meshTalk.exe) в Windows

Используйте `build_meshTalk.bat`:

```bat
build_meshTalk.bat
```

Результат: `dist\meshTalk.exe`

## Чеклист первого запуска

- `meshtastic --help` работает
- `dot -V` работает
- `python meshLogger.py --port ...` создает `meshLogger/YYYY-MM-DD !xxxxxxxx.txt`
- `python nodeDbUpdater.py --port ...` создает/обновляет `nodeDb.txt`

## Структура файлов

```
meshTools/
  meshLogger.py
  nodeDbUpdater.py
  graphGen.py
  meshTalk.py
  meshLogger/   # сгенерированные ежедневные логи traceroute
  graphGen/     # сгенерированные графы (dot/svg/html/json)
  meshLogger.db # сгенерированная SQLite-база
  nodeDb.txt    # сгенерированная база узлов (legacy)
  keyRings/     # ключи (<id>.key, <id>.pub)
  meshTalk/     # очередь и история (state.json, history.log)
```

## Заметки

- `nodeDb.txt` может содержать чувствительные данные (ключи, координаты). Храните приватно.
- `.gitignore` исключает сгенерированные логи и базу.
- `graphGen.py` ожидает файлы трасс вида `YYYY-MM-DD !xxxxxxxx*.txt`.

## Устранение неполадок

- `meshtastic` не найден: выполните `pip install meshtastic` и добавьте Scripts в PATH.
- `dot` не найден: установите Graphviz и добавьте `bin` в PATH.
- Нет логов: убедитесь, что в `meshLogger/` есть файлы `YYYY-MM-DD !xxxxxxxx*.txt`.
- Устройство не найдено: проверьте порт (Linux `/dev/ttyUSB0`, Windows `COM3`), кабель и драйверы.

## graphGen.py (D3.js опции)

- `--no-d3` выключает HTML/JSON.
- `--d3-top N` ограничивает top-N узлов для фильтрации (по умолчанию 30).
- `--d3-min-neighbors N` фильтрует по числу соседей (по умолчанию 0).
