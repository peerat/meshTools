# meshTools

Author: Anton Vologzhanin (R3VAF)
Current version: 0.3.3

Small utilities around Meshtastic.

## Project Vision

- Purpose: civilian/hobby/geek use and study of data-packet delivery in mesh topologies.
- The project is aimed at experimentation, delivery/latency analysis, and protocol behavior learning.
- Military use is explicitly prohibited.
- Any unlawful use (including terrorist, extremist, criminal activity) is explicitly prohibited.
- Disclaimer: software is provided "AS IS", without warranties of any kind.
- Disclaimer: the author is not liable for any direct or indirect damage caused by use or misuse.

## License

- This project is licensed under Apache License 2.0 (`LICENSE`).
- Attribution requirement: if you redistribute this project or derivative works, keep the `NOTICE` file and preserve attribution to Anton Vologzhanin (R3VAF).
- If you do not want to comply with these terms, do not use or redistribute the code.

## Contents

- `meshTalk.py`: research prototype GUI for best-effort P2P payload exchange (ACK/retry, key exchange, runtime diagnostics).
- `meshLogger.py`: traceroute/events logger + SQLite telemetry DB (`meshLogger.db`).
- `graphGen.py`: Graphviz + D3 map/graph generator from collected logs/DB.
- `nodeDbUpdater.py`: legacy text node DB updater (`nodeDb.txt`).
- `meshtalk/`: internal protocol/storage modules (`protocol.py`, `storage.py`).
- `meshtalk_utils.py`: shared parsing/formatting/runtime helpers.
- `message_text_compression.py`: compression/normalization pipeline for payload text.
- Text references: `meshTalk.txt`, `meshLogger.txt`, `graphGen.txt`, `nodeDbUpdater.txt`, `meshtalk_utils.txt`, `message_text_compression.txt`.

## Key capabilities

- Best-effort delivery over Meshtastic with ACK/retry/backoff and message status tracking.
- Per-peer key exchange flow (KR1/KR2), MT-WIRE AES-256-GCM container, and local at-rest sealing for profile data.
- Adaptive pacing and queue control to reduce traffic noise.
- Traceroute integration in dialogs with route details and diagnostics.
- Compression with automatic mode selection (`DEFLATE`, `ZLIB`, `BZ2`, `LZMA`, `ZSTD`) plus reversible normalization (`Token stream`, `SentencePiece vocab`).
- Runtime observability: colorized event log, health snapshots, compression stats (`COMPRESS`/`COMPSTAT`).

## Requirements

- Python 3.9+
- Meshtastic CLI in PATH (`meshtastic`)
- `cryptography` package (for `meshTalk.py`)
- `PySide6` package (Qt GUI for `meshTalk.py`)
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

Optional NLP-related compression profiles:

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

Best-effort P2P payload exchange (cryptographic primitives + ACK):

Qt GUI app:

```bash
python meshTalk.py
```

`meshTalk.py` uses a direct serial connection to the radio (USB/COM).
Default `--port` is `auto`: on startup the app scans serial ports and picks the best candidate automatically.

In the GUI, use the search box to type a node id (e.g. `02e591e0` or `!02e591e0`) and press Enter to open a dialog.

Keys are stored in `keyRings/` as `<id>.key` and `<id>.pub` (leading `!` is stripped).
If `keyRings/<id>.key` / `keyRings/<id>.pub` are missing, they are generated automatically.
Local at-rest storage key is stored in `keyRings/storage.key` (32 bytes, base64; created automatically).

## Cryptography (where/when)

This project uses cryptographic primitives for payload sealing and local at-rest sealing. It does not claim or guarantee any specific security properties.
On startup the runtime log prints a `CRYPTO:` line with the active primitive set.

- Key exchange frames (MT-KEY v1): `KR1|...` / `KR2|...`
  - Format: plaintext UTF-8/ASCII with `|` separators.
  - Public key: X25519 public key (32 raw bytes, base64 in the frame).
- Transport container (MT-WIRE v1): AES-256-GCM (AEAD)
  - Key derivation: X25519 ECDH + HKDF-SHA256 -> 32-byte AES key (see `meshtalk/protocol.py` and `meshtalk/protocol.txt`).
  - Applied: to all MSG/ACK frames on the Meshtastic `PRIVATE_APP` port.
- Local at-rest sealing (per node profile): AES-256-GCM (AEAD)
  - Key file: `<node_id>/keyRings/storage.key` (32 bytes, base64; local-only).
  - Applied: `history.log`, `state.json`, `incoming.json` sensitive fields (see `meshtalk/storage.py` and `meshtalk/storage.txt`).

### Session rekey (optional)

`meshTalk.py` can periodically refresh per-peer session keys inside the encrypted channel (`session_rekey`).
Control frames are carried inside MT-MSG plaintext (`RK1`/`RK2`/`RK3`) and derive a new per-peer AES key from
HKDF(static_shared || ephemeral_shared). Full details: `meshtalk/protocol.txt`.

## Wire Protocol / Packet Structure

Full, versioned specification: `meshtalk/protocol.txt`.

Quick summary:
- MT-KEY v1 (plaintext): `KR1|...` / `KR2|...`
- MT-WIRE v1 (AES-256-GCM): `[ver=1][type][msg_id(8)][nonce(12)][ct||tag]`
- MT-MSG v2 (inside MSG): binary `M2` framing (16-byte header + chunk)
- MT-ACK (inside ACK): UTF-8 `ACK|...`

## Runtime Log: Event Types and UI Colors

Log lines are colorized in the GUI by event prefix (as a reading aid only):
- `ERROR` (red, `#f92672`): exceptions/tracebacks, decode failures, pinned key mismatch.
- `WARN` (orange, `#fd971f`): non-fatal warnings.
- `KEY` / `CRYPTO` (yellow, `#ffd75f`): key exchange, rekey, crypto diagnostics.
- `KEYOK` (yellow, `#ffd75f`): confirmed key exchange.
- `TRACE` (cyan, `#66d9ef`): traceroute.
- `PACE` (green, `#a6e22e`): adaptive pacing suggestions/changes.
- `HEALTH` (mint, `#6be5b5`): periodic health line.
- `DISCOVERY` (violet, `#b894ff`): discovery/broadcast scheduling.
- `RADIO` (blue, `#74b2ff`): connect/disconnect and low-level radio events.
- `GUI` (light, `#e0e0e0`): GUI lifecycle events.
- `QUEUE` (sand, `#c3b38a`): queue changes/clears.
- `COMPRESS` / `COMPSTAT` (default log color): compression decision and periodic compression/normalization efficiency totals.

The script detects your node id from the radio automatically.
If a peer key is missing, a key exchange is requested automatically.
Outgoing messages are stored per node profile in `<node_id>/state.json` and `<node_id>/history.log`.
Payload text persisted on disk is stored as `enc1:...` (AES-256-GCM AEAD; key in `keyRings/storage.key`).
Type `/keys` to rotate your keys (they will be regenerated and exchanged again).

### Text Compression (Optional)

Compression is applied to payload bytes before MT-WIRE sealing and only when it gives size gain.

- Compression is configurable in Settings (recommended: AUTO).
- Decision rule: all supported modes are compared; compression is used only when the best mode is smaller than plain UTF-8.
- External transport protocol is unchanged; compression works inside message payload bytes.
- Peer compatibility guard: compression is enabled per peer only after capability markers are observed (`mc=1`, `mc_modes=...`) from validated peer traffic.
- First message to an unknown peer is sent plain, then compression can activate automatically.
- Table modes `BYTE_DICT`/`FIXED_BITS` are disabled for new outgoing messages.
- Zstandard mode (`mc_zstd`) is supported (dependency: `zstandard`, see `requirements.txt`). It is used only when the peer advertises it in `mc_modes`.
- Normalization (lossless, before binary codecs): improves compression for short chat-like texts.
  - `OFF`: no normalization.
  - `Token stream (basic, reversible)`: serializes exact tokens (incl. whitespace) before compression.
  - `SentencePiece vocab (reversible)`: greedy tokenization by `meshtalk/sp_vocab.txt` before compression.
    `sentencepiece` is used only to generate/update that vocab file; runtime decode does not depend on it.

Compressed block format (`compression=1`):

`[MAGIC 2B][VER 1B][MODE 1B][DICT_ID 1B][FLAGS 1B] + DATA + [CRC8 1B]`

- `MAGIC`: `0x4D 0x43` (`"MC"`)
- `VER`: `1`
- `MODE`: `2` (`DEFLATE`), `3` (`ZLIB`), `4` (`BZ2`), `5` (`LZMA`), `9` (`ZSTD`) for new outgoing messages.
- Legacy values `0` (`BYTE_DICT`) and `1` (`FIXED_BITS`) are kept only for backward decode compatibility.
- `DICT_ID`: static dictionary id (`2`)
- `FLAGS`: bit0 lowercase_used, bit1 preserve_case, bit2 punct_tokens_enabled, bit4 token_stream_payload
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

### Project files (repository / source-controlled)

- `meshLogger.py` — traceroute/logger utility.
- `nodeDbUpdater.py` — legacy text DB updater.
- `graphGen.py` — Graphviz + D3 generator.
- `meshTalk.py` — research prototype GUI for best-effort P2P payload exchange (ACK/retry + cryptographic primitives).
- `meshtalk/` — internal meshTalk modules:
  - `meshtalk/protocol.py` — wire protocol + cryptographic primitives.
  - `meshtalk/storage.py` — config/state/history/incoming storage + at-rest sealing/hardening.
- `meshtalk_utils.py` — shared helpers/parsers/formatters.
- `message_text_compression.py` — text compression modes/codecs.
- `requirements.txt` — Python dependencies.
- `run_meshTalk.bat` / `build_meshTalk.bat` — Windows run/build scripts.
- `README.md` / `CHANGELOG.md` / `meshTalk.txt` — docs.

### Generated during runtime (not source code)

- `meshLogger/` — generated daily traceroute logs.
- `graphGen/` — generated graph output (`dot/svg/html/json`).
- `meshLogger.db` — generated SQLite DB.
- `nodeDb.txt` — generated node DB (legacy mode).
- `keyRings/` — generated key files (`<id>.key`, `<id>.pub`, peer public keys, `storage.key`).
- `<node_id>/` — per-node runtime profile directory:
  - `config.json`, `state.json`, `incoming.json`, `history.log`, `runtime.log`, `keyRings/`.

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

- Назначение: гражданское/любительское/гиковское использование и изучение доставки пакетов данных в mesh-сетях.
- Проект ориентирован на эксперименты, анализ доставки/задержек и изучение поведения протокола.
- Военное применение прямо запрещено.
- Любая незаконная деятельность (включая террористическую, экстремистскую и преступную) прямо запрещена.
- Отказ от ответственности: ПО предоставляется «как есть», без каких-либо гарантий.
- Отказ от ответственности: автор не несет ответственности за любой прямой или косвенный ущерб от использования или неправильного использования.

## Лицензия

- Проект распространяется под Apache License 2.0 (`LICENSE`).
- Требование атрибуции: при распространении проекта или производных работ сохраняйте файл `NOTICE` и упоминание автора Anton Vologzhanin (R3VAF).
- Если вы не готовы выполнять эти условия, не используйте и не распространяйте код.

## Содержание

- `meshTalk.py`: исследовательский GUI-прототип best-effort P2P-обмена (ACK/повторы, обмен ключами, runtime-диагностика).
- `meshLogger.py`: логгер traceroute/событий + SQLite-телеметрия (`meshLogger.db`).
- `graphGen.py`: генерация карт/графов Graphviz + D3 из логов/БД.
- `nodeDbUpdater.py`: legacy-обновление текстовой базы узлов (`nodeDb.txt`).
- `meshtalk/`: внутренние модули протокола/хранилища (`protocol.py`, `storage.py`).
- `meshtalk_utils.py`: общие утилиты парсинга/форматирования.
- `message_text_compression.py`: пайплайн сжатия/нормализации текста payload.
- Текстовые справки: `meshTalk.txt`, `meshLogger.txt`, `graphGen.txt`, `nodeDbUpdater.txt`, `meshtalk_utils.txt`, `message_text_compression.txt`.

## Ключевые возможности

- Best-effort доставка поверх Meshtastic с ACK/retry/backoff и статусами сообщений.
- По-пировый обмен ключами (KR1/KR2), MT-WIRE AES-256-GCM и локальное запечатывание данных профиля.
- Адаптивный rate/parallel (autopacing) и контроль очередей для снижения шумового трафика.
- Интеграция traceroute в диалогах с выводом маршрута и диагностикой.
- Сжатие с авто-выбором режима (`DEFLATE`, `ZLIB`, `BZ2`, `LZMA`, `ZSTD`) и обратимой нормализацией (`Token stream`, `SentencePiece vocab`).
- Наблюдаемость runtime: цветной лог событий, health-сводки, статистика сжатия (`COMPRESS`/`COMPSTAT`).

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

Опционально для NLP-профилей сжатия:

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

Best-effort P2P-обмен полезной нагрузкой (криптографические примитивы + ACK):

Qt GUI app:

```bash
python meshTalk.py
```

`meshTalk.py` работает через прямое serial-подключение к радио (USB/COM).
Параметр `--port` по умолчанию равен `auto`: при старте приложение сканирует serial-порты и автоматически выбирает наиболее подходящий.

Ключи хранятся в `keyRings/` как `<id>.key` и `<id>.pub` (ведущий `!` убирается).
Если `keyRings/<id>.key` / `keyRings/<id>.pub` отсутствуют, они создаются автоматически.
Локальный ключ хранения на диске хранится в `keyRings/storage.key` (32 байта, base64; создается автоматически).
Скрипт автоматически определяет id узла из радио.
Если ключ собеседника отсутствует, автоматически запрашивается обмен ключами.
Исходящая полезная нагрузка сохраняется в профиле узла: `<node_id>/state.json` и `<node_id>/history.log`.
Текст полезной нагрузки при сохранении на диск хранится как `enc1:...` (AES-256-GCM AEAD; ключ в `keyRings/storage.key`).
Команда `/keys` пересоздаёт ваши ключи и запускает новый обмен.

## Криптография (где/когда)

В проекте используются криптографические примитивы для запечатывания payload и локального запечатывания данных на диске. Проект не обещает и не гарантирует каких-либо конкретных свойств безопасности.

- Обмен ключами (MT-KEY v1): кадры `KR1|...` / `KR2|...`
  - Формат: plaintext UTF-8/ASCII с разделителем `|`.
  - Публичный ключ: X25519 public key (32 raw bytes, base64 внутри кадра).
- Транспортный контейнер (MT-WIRE v1): AES-256-GCM (AEAD)
  - Вычисление ключа: X25519 ECDH + HKDF-SHA256 -> 32-байтный AES key (см. `meshtalk/protocol.py` и `meshtalk/protocol.txt`).
  - Применяется: ко всем MSG/ACK кадрам на порту Meshtastic `PRIVATE_APP`.
- Локальное запечатывание на диске (профиль ноды): AES-256-GCM (AEAD)
  - Файл ключа: `<node_id>/keyRings/storage.key` (32 байта, base64; строго локальный).
  - Применяется: к чувствительным полям в `history.log`, `state.json`, `incoming.json` (см. `meshtalk/storage.py` и `meshtalk/storage.txt`).

### Сжатие текста (опционально)

Сжатие применяется к байтам payload до запечатывания MT-WIRE и только если есть выигрыш по размеру.

- Настройки сжатия настраиваются в Settings (рекомендуется AUTO).
- Правило выбора: сравниваются все поддерживаемые режимы; сжатие включается только если лучший режим меньше обычного UTF-8.
- Внешний транспортный протокол не меняется; сжатие работает внутри байтов payload.
- Защита совместимости: сжатие включается для peer только после маркеров возможностей (`mc=1`, `mc_modes=...`) из валидированного трафика этого peer.
- Первое сообщение неизвестному peer уходит как обычный текст; далее сжатие может включиться автоматически.
- Табличные режимы `BYTE_DICT`/`FIXED_BITS` отключены для новых исходящих сообщений.
- Поддерживается `ZSTD` (`mc_zstd`). Зависимость `zstandard` включена в `requirements.txt`.
- Нормализация (обратимая, перед бинарными кодеками) помогает лучше сжимать короткие чатовые тексты.
  - `OFF`: без нормализации.
  - `Token stream (базовый, обратимый)`: сериализация точных токенов (включая пробелы) перед сжатием.
  - `SentencePiece vocab (обратимый)`: жадная токенизация по `meshtalk/sp_vocab.txt` перед сжатием.
    `sentencepiece` используется только чтобы генерировать/обновлять vocab; на декодирование он не влияет.

Формат сжатого блока (`compression=1`):

`[MAGIC 2B][VER 1B][MODE 1B][DICT_ID 1B][FLAGS 1B] + DATA + [CRC8 1B]`

- `MAGIC`: `0x4D 0x43` (`"MC"`)
- `VER`: `1`
- `MODE`: для новых исходящих используются `2` (`DEFLATE`), `3` (`ZLIB`), `4` (`BZ2`), `5` (`LZMA`), `9` (`ZSTD`).
- Значения `0` (`BYTE_DICT`) и `1` (`FIXED_BITS`) оставлены только для декодирования legacy-сообщений.
- `DICT_ID`: id статического словаря (`2`)
- `FLAGS`: bit0 lowercase_used, bit1 preserve_case, bit2 punct_tokens_enabled, bit4 token_stream_payload
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

### Файлы проекта (в репозитории / исходники)

- `meshLogger.py` — утилита traceroute/logger.
- `nodeDbUpdater.py` — legacy-обновление текстовой БД.
- `graphGen.py` — генерация Graphviz + D3.
- `meshTalk.py` — research prototype GUI для best-effort P2P-обмена полезной нагрузкой (ACK/повторы + криптографические примитивы).
- `meshtalk/` — внутренние модули meshTalk:
  - `meshtalk/protocol.py` — wire-протокол + криптографические примитивы.
  - `meshtalk/storage.py` — хранение config/state/history/incoming + запечатывание на диске.
- `meshtalk_utils.py` — общие утилиты/парсеры/форматтеры.
- `message_text_compression.py` — режимы/кодеки сжатия текста.
- `requirements.txt` — Python-зависимости.
- `run_meshTalk.bat` / `build_meshTalk.bat` — скрипты запуска/сборки для Windows.
- `README.md` / `CHANGELOG.md` / `meshTalk.txt` — документация.

### Генерируется во время работы (не исходники)

- `meshLogger/` — сгенерированные ежедневные логи traceroute.
- `graphGen/` — сгенерированные файлы графов (`dot/svg/html/json`).
- `meshLogger.db` — сгенерированная SQLite-база.
- `nodeDb.txt` — сгенерированная база узлов (legacy-режим).
- `keyRings/` — сгенерированные ключи (`<id>.key`, `<id>.pub`, публичные ключи пиров, `storage.key`).
- `<node_id>/` — runtime-профиль конкретной ноды:
  - `config.json`, `state.json`, `incoming.json`, `history.log`, `runtime.log`, `keyRings/`.

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
