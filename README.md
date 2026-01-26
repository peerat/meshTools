# meshTools

Набор утилит для работы с Meshtastic: логирование трасс, обновление базы узлов
и генерация графов сети в Graphviz.

## Состав

- `meshLogger.py` — сбор и логирование данных из Meshtastic CLI.
- `nodeDbUpdater.py` — одноразовое обновление базы узлов с сохранением истории.
- `graphGen.py` — генерация графов (DOT/SVG/JPG) из трасс.

## Требования

- Python 3.9+.
- Для генерации изображений: Graphviz (`dot`).
- Доступ к Meshtastic CLI в `PATH` для скриптов, работающих с радио.

## Быстрый старт

```bash
# Клонировать и перейти в каталог
cd /workspace/meshTools
```

## Запуск

### 1) Логирование трасс (`meshLogger.py`)

```bash
python3 meshLogger.py --help
```

Ожидается, что скрипт запускается в каталоге проекта. Логи по умолчанию
сохраняются в `./meshLogger` (см. вывод `--help`).

#### Полный help для `meshLogger.py`

```text
usage: meshLogger.py [options]

Meshtastic route logger.
Periodically performs "meshtastic --traceroute" to selected mesh nodes and logs raw routes to a daily file:
  meshTools/YYYY-MM-DD !selfid.txt

Terminal output:
  3 lines per node:
    1) request line
    2) if ok: route towards ("> ..."), else: "<name>[<short>] is no response..."
    3) if ok: route back ("< ...")

Node IDs and Bash:
  Bash treats '!' as history expansion ("event not found").
  This logger accepts node IDs BOTH ways:
    - with bang:  !aca96d48
    - without:    aca96d48   (recommended; no quoting needed)

options:
  -h, --help
        Show this help message and exit

  --port PORT
        Serial port for Meshtastic device.
        Default: /dev/ttyUSB0

  --hours HOURS
        Consider nodes active if they were heard within the last HOURS (by lastHeard).
        Used to build polling list from "meshtastic --info".
        Default: 24

  --timeout SECONDS
        Timeout for single "meshtastic --traceroute" command.
        If exceeded, the request is treated as "no response".
        Default: 30

  --pause SECONDS
        Pause between traceroute requests (after both success and fail).
        Default: 30

  --minhops N
        Poll only nodes with hopsAway >= N (from "meshtastic --info").
        Nodes without hopsAway are excluded when hop filtering is used.
        Default: not set

  --maxhops N
        Poll only nodes with hopsAway <= N (from "meshtastic --info").
        Default: not set

  --once
        Do exactly one full pass over the selected nodes and exit.
        Default: off (continuous loop)

  --node NODEID
        Poll only one specific node.
        NODEID can be "!xxxxxxxx" or "xxxxxxxx".
        Example:
          --node aca96d48

  --id-list FILE
        Poll only node IDs found inside FILE.
        The file may contain ANY text; we extract all patterns like "!xxxxxxxx".
        This filter is applied on top of --hours selection.
        Example:
          --id-list nodes.txt

  --quiet
        Less terminal output (do not print the initial numbered node list).

  --version
        Print program version and exit
```

### 2) Обновление базы узлов (`nodeDbUpdater.py`)

```bash
# Пример: обновление базы из подключённого устройства
python3 nodeDbUpdater.py --port /dev/ttyUSB0 --db nodeDb.txt
```

Файл БД можно хранить в корне проекта или в домашнем каталоге. Скрипт
пишет данные атомарно.

#### Полный help для `nodeDbUpdater.py`

```text
usage: nodeDbUpdater.py [--port PORT] [--db DB] [--timeout SECONDS]
                        [--meshtastic-bin MESHTASTIC_BIN] [--channel CHANNEL]

One-shot Meshtastic node database updater

options:
  --port PORT
        Serial port (default: /dev/ttyUSB0)

  --db DB
        Database file path (default: nodeDb.txt)

  --timeout SECONDS
        Command timeout in seconds (default: 40)

  --meshtastic-bin MESHTASTIC_BIN
        Meshtastic CLI binary name or path

  --channel CHANNEL
        Optional channel index to query
```

### 3) Генерация графов (`graphGen.py`)

```bash
python3 graphGen.py --help
```

Важно: `graphGen.py` ищет трассы в `./meshLogger` и сохраняет результаты
в `./graphGen`. Эти пути фиксированы в коде.

Пример (после накопления логов):

```bash
python3 graphGen.py
```

#### Полный help для `graphGen.py`

```text
usage: graphGen.py [--root ROOT] [--min-edge MIN_EDGE]
                   [--rankdir {LR,TB,RL,BT}] [--dpi DPI]
                   [--include-unknown] [--top TOP]
                   [--datetime DATETIME]
                   [--minwidthline MINWIDTHLINE]
                   [--maxwidthline MAXWIDTHLINE]
                   [--version]

graphGen.py: build Meshtastic graph (DOT+SVG+JPG) from trace files.

options:
  --root ROOT
        Directory with input files (default: current).

  --min-edge MIN_EDGE
        Minimum confirmations to keep a directed link (default: 3).

  --rankdir {LR,TB,RL,BT}
        Graphviz rankdir (default: LR).

  --dpi DPI
        JPG DPI (default: 75).

  --include-unknown
        Include Unknown node (!ffffffff) and all edges adjacent to it (default: excluded).

  --top TOP
        Top N lines in summary lists (default: 15).

  --datetime DATETIME
        Date/time window filter STRICTLY by timestamps at the BEGINNING of EACH TRACE LINE inside the files
        (NOT filename, NOT mtime). Examples: '2026-01-22', '2026-01-22 - 2026-01-23',
        '2026-01-22 23:33 - 2026-01-22 23:40', '2026-01-22 23:33:08 - 2026-01-22 23:33:20'.

  --minwidthline MINWIDTHLINE
        Min edge penwidth in relative scaling (default: 1.0).

  --maxwidthline MAXWIDTHLINE
        Max edge penwidth in relative scaling (default: 30.0).

  --version
        Show program version and exit
```

## Структура данных и путей

По умолчанию (фиксированные пути в коде):

- Логи трасс: `./meshLogger`
- Выходные графы: `./graphGen`
- Поиск базы узлов: текущий каталог, каталог скрипта, домашний каталог

## Примечания

- Если `dot` не найден, генерация изображений будет недоступна.
- Для корректной работы с радио убедитесь, что Meshtastic CLI установлен
  и доступен в `PATH`.
