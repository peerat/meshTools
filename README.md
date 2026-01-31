# meshTools

Small utilities around Meshtastic.  
RU: Небольшие утилиты вокруг Meshtastic.

- `meshLogger.py` polls traceroute and writes daily logs to `meshLogger/`.  
  RU: `meshLogger.py` опрашивает traceroute и пишет ежедневные логи в `meshLogger/`.
- `nodeDbUpdater.py` updates `nodeDb.txt` from `meshtastic --nodes` and `--info`.  
  RU: `nodeDbUpdater.py` обновляет `nodeDb.txt` из `meshtastic --nodes` и `--info`.
- `graphGen.py` builds Graphviz (DOT/SVG) and D3.js (HTML/JSON) graphs from logs and node DB in `graphGen/`.  
  RU: `graphGen.py` строит графы Graphviz (DOT/SVG) и D3.js (HTML/JSON) из логов и базы узлов в `graphGen/`.

## Requirements

- Python 3.9+  
  RU: Python 3.9+
- Meshtastic CLI in PATH (`meshtastic`)  
  RU: Meshtastic CLI в PATH (`meshtastic`)
- Graphviz in PATH (`dot`) for `graphGen.py`  
  RU: Graphviz в PATH (`dot`) для `graphGen.py`

## Windows notes

- Install Meshtastic CLI: `pip install meshtastic` (make sure Scripts is in PATH)  
  RU: Установите Meshtastic CLI: `pip install meshtastic` (убедитесь, что Scripts в PATH)
- Install Graphviz and add its `bin` to PATH  
  RU: Установите Graphviz и добавьте его `bin` в PATH
- Use COM port (example: `--port COM3`)  
  RU: Используйте COM‑порт (например: `--port COM3`)
- Find real paths on your machine:  
  RU: Узнать реальные пути на вашей машине:
  - `where python`
  - `where meshtastic`
  - `where dot`
- Add missing folders to PATH (PowerShell, current user):  
  RU: Добавить недостающие папки в PATH (PowerShell, текущий пользователь):
  - `setx PATH "$env:PATH;C:\path\to\Python\Scripts;C:\path\to\Graphviz\bin"`
- Via GUI (Windows):  
  RU: Через GUI (Windows):
  - Start → “Environment Variables”
  - Edit `Path` → New → paste path → OK

## Install

```bash
pip install -r requirements.txt
```

Check that tools are in PATH:  
RU: Проверка, что утилиты доступны в PATH:

```bash
meshtastic --help
dot -V
```

## Quick start

Continuous route logging (Ctrl+C to stop):  
RU: Непрерывное логирование маршрутов (Ctrl+C для остановки):

```bash
python meshLogger.py --port /dev/ttyUSB0
```

Update node DB (one-shot):  
RU: Обновить базу узлов (однократно):

```bash
python nodeDbUpdater.py --port /dev/ttyUSB0 --db nodeDb.txt
```

Generate graph from recent logs (Graphviz + D3.js):  
RU: Сгенерировать граф из свежих логов (Graphviz + D3.js):

```bash
python graphGen.py --root .
```

## First run checklist

- `meshtastic --help` works  
  RU: `meshtastic --help` работает
- `dot -V` works  
  RU: `dot -V` работает
- `python meshLogger.py --port ...` creates `meshLogger/YYYY-MM-DD !xxxxxxxx.txt`  
  RU: `python meshLogger.py --port ...` создаёт `meshLogger/YYYY-MM-DD !xxxxxxxx.txt`
- `python nodeDbUpdater.py --port ...` creates/updates `nodeDb.txt`  
  RU: `python nodeDbUpdater.py --port ...` создаёт/обновляет `nodeDb.txt`

## File layout

```
meshTools/
  meshLogger.py
  nodeDbUpdater.py
  graphGen.py
  meshLogger/   # generated daily traceroute logs
  graphGen/     # generated graphs (dot/svg/html/json)
  nodeDb.txt    # generated node DB
```

RU:
```
meshTools/
  meshLogger.py
  nodeDbUpdater.py
  graphGen.py
  meshLogger/   # сгенерированные ежедневные логи traceroute
  graphGen/     # сгенерированные графы (dot/svg/html/json)
  nodeDb.txt    # сгенерированная база узлов
```

## Notes

- `nodeDb.txt` may contain sensitive data (keys, coordinates). Keep it private.  
  RU: `nodeDb.txt` может содержать чувствительные данные (ключи, координаты). Храните приватно.
- `.gitignore` excludes generated logs and DB.  
  RU: `.gitignore` исключает сгенерированные логи и базу.
- `graphGen.py` expects trace files named `YYYY-MM-DD !xxxxxxxx*.txt`.  
  RU: `graphGen.py` ожидает файлы трасс вида `YYYY-MM-DD !xxxxxxxx*.txt`.

## Troubleshooting

- `meshtastic` not found: run `pip install meshtastic` and add Scripts to PATH.  
  RU: `meshtastic` не найден: выполните `pip install meshtastic` и добавьте Scripts в PATH.
- `dot` not found: install Graphviz and add `bin` to PATH.  
  RU: `dot` не найден: установите Graphviz и добавьте `bin` в PATH.
- No logs: ensure `meshLogger/` has `YYYY-MM-DD !xxxxxxxx*.txt` files.  
  RU: Нет логов: убедитесь, что в `meshLogger/` есть файлы `YYYY-MM-DD !xxxxxxxx*.txt`.
- Device not found: check port name (Linux `/dev/ttyUSB0`, Windows `COM3`), cable, and drivers.  
  RU: Устройство не найдено: проверьте порт (Linux `/dev/ttyUSB0`, Windows `COM3`), кабель и драйверы.

## graphGen.py (D3.js options)

- `--no-d3` disables HTML/JSON.  
  RU: `--no-d3` выключает HTML/JSON.
- `--d3-top N` limits top‑N nodes for filtering (default: 30).  
  RU: `--d3-top N` ограничивает top‑N узлов для фильтрации (по умолчанию 30).
- `--d3-min-neighbors N` filters by neighbor count (default: 0).  
  RU: `--d3-min-neighbors N` фильтрует по числу соседей (по умолчанию 0).
