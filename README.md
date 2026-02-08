# meshTools

Author: Anton Vologzhanin (R3VAF)
Current version: 0.3.1

Small utilities around Meshtastic.

## Project Vision

- Purpose: civilian/hobby/geek use and study of message delivery in mesh networks.
- The project is aimed at experimentation, reliability analysis, and protocol behavior learning.
- Military use is explicitly prohibited.
- Any unlawful use (including terrorist, extremist, criminal activity) is explicitly prohibited.
- Disclaimer: software is provided "AS IS", without warranties of any kind.
- Disclaimer: the author is not liable for any direct or indirect damage caused by use or misuse.

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
Outgoing messages are stored per node profile in `<node_id>/state.json` and `<node_id>/history.log`.
Type `/keys` to rotate your keys (they will be regenerated and exchanged again).

### Text Compression (Optional)

Compression is applied to message payload before encryption and only when it gives size gain.

- Config keys:
  - `compression_enabled` (default: `true`)
  - `compression_mode` (preferred mode, default: `0`)
    - `0` = `BYTE_DICT`
    - `1` = `FIXED_BITS`
    - `2` = `DEFLATE`
    - `3` = `ZLIB`
    - `4` = `BZ2`
    - `5` = `LZMA`
  - `min_gain_bytes` (default: `2`)
- Decision rule: all supported modes are compared; compression is used only if best result is at least `min_gain_bytes` smaller than plain UTF-8.
- External transport protocol is unchanged; compression works inside message payload bytes.
- Peer compatibility guard: compression is enabled per peer only after capability markers are observed (`mc=1`, `mc_modes=...`) from validated peer traffic.
- First message to an unknown peer is sent plain, then compression can activate automatically.

Compressed block format (`compression=1`):

`[MAGIC 2B][VER 1B][MODE 1B][DICT_ID 1B][FLAGS 1B] + DATA + [CRC8 1B]`

- `MAGIC`: `0x4D 0x43` (`"MC"`)
- `VER`: `1`
- `MODE`: `0` (`BYTE_DICT`), `1` (`FIXED_BITS`), `2` (`DEFLATE`), `3` (`ZLIB`), `4` (`BZ2`), `5` (`LZMA`)
- `DICT_ID`: static dictionary id (`2`)
- `FLAGS`: bit0 lowercase_used, bit1 preserve_case, bit2 punct_tokens_enabled
- `CRC8`: checksum over header+data
- Tokenization: words + punctuation tokens from `.,!?-:;()"'`.
- Escape for unknown token:
  - `BYTE_DICT`: `0xFF + varint(len) + raw UTF-8`
  - `FIXED_BITS`: `ESC symbol + varint(len) + raw UTF-8`
- Safety guard: max escaped token length is `64` bytes.
- Text round-trip is exact (case and whitespace are preserved in compressed mode).

Compatibility:

- New client receives both compressed and plain payloads.
- Plain payload path remains UTF-8 (`compression=0`).

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
  <node_id>/    # per-node profile data
               # config.json, state.json, incoming.json, history.log, runtime.log, keyRings/
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

## Видение проекта

- Назначение: гражданское/любительское/гиковское использование и изучение прохождения сообщений в mesh-сетях.
- Проект ориентирован на эксперименты, анализ надежности и изучение поведения протокола.
- Военное применение прямо запрещено.
- Любая незаконная деятельность (включая террористическую, экстремистскую и преступную) прямо запрещена.
- Отказ от ответственности: ПО предоставляется «как есть», без каких-либо гарантий.
- Отказ от ответственности: автор не несет ответственности за любой прямой или косвенный ущерб от использования или неправильного использования.

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
Исходящие сообщения сохраняются в профиле узла: `<node_id>/state.json` и `<node_id>/history.log`.
Команда `/keys` пересоздаёт ваши ключи и запускает новый обмен.

### Сжатие текста (опционально)

Сжатие применяется к payload сообщения до шифрования и только если есть выигрыш по размеру.

- Ключи конфигурации:
  - `compression_enabled` (по умолчанию: `true`)
  - `compression_mode` (предпочитаемый режим, по умолчанию: `0`)
    - `0` = `BYTE_DICT`
    - `1` = `FIXED_BITS`
    - `2` = `DEFLATE`
    - `3` = `ZLIB`
    - `4` = `BZ2`
    - `5` = `LZMA`
  - `min_gain_bytes` (по умолчанию: `2`)
- Правило выбора: сравниваются все поддерживаемые режимы; сжатие включается только если лучший результат минимум на `min_gain_bytes` меньше обычного UTF-8.
- Внешний транспортный протокол не меняется; сжатие работает внутри байтов payload.
- Защита совместимости: сжатие включается для peer только после маркеров возможностей (`mc=1`, `mc_modes=...`) из валидированного трафика этого peer.
- Первое сообщение неизвестному peer уходит как обычный текст; далее сжатие может включиться автоматически.

Формат сжатого блока (`compression=1`):

`[MAGIC 2B][VER 1B][MODE 1B][DICT_ID 1B][FLAGS 1B] + DATA + [CRC8 1B]`

- `MAGIC`: `0x4D 0x43` (`"MC"`)
- `VER`: `1`
- `MODE`: `0` (`BYTE_DICT`), `1` (`FIXED_BITS`), `2` (`DEFLATE`), `3` (`ZLIB`), `4` (`BZ2`), `5` (`LZMA`)
- `DICT_ID`: id статического словаря (`2`)
- `FLAGS`: bit0 lowercase_used, bit1 preserve_case, bit2 punct_tokens_enabled
- `CRC8`: контрольная сумма по header+data
- Токенизация: слова + отдельные токены пунктуации `.,!?-:;()"'`.
- Escape для неизвестного токена:
  - `BYTE_DICT`: `0xFF + varint(len) + raw UTF-8`
  - `FIXED_BITS`: `ESC symbol + varint(len) + raw UTF-8`
- Защита: максимальная длина escape-токена `64` байта.
- Текст восстанавливается без потерь (сохраняются регистр и пробелы).

Совместимость:

- Новый клиент принимает и сжатый, и обычный payload.
- Обычный путь (`compression=0`) остается UTF-8 как раньше.

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
  <node_id>/    # профиль конкретной ноды
               # config.json, state.json, incoming.json, history.log, runtime.log, keyRings/
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
