# meshTools

Небольшие утилиты вокруг Meshtastic:
- `meshLogger.py` опрашивает traceroute и пишет ежедневные логи в `meshLogger/`.
- `nodeDbUpdater.py` обновляет `nodeDb.txt` из `meshtastic --nodes` и `--info`.
- `graphGen.py` строит графы DOT/SVG/JPG из логов и базы узлов в `graphGen/`.

## Требования
- Python 3.9+
- Meshtastic CLI в PATH (`meshtastic`)
- Graphviz в PATH (`dot`) для `graphGen.py`

## Заметки для Windows
- Установите Meshtastic CLI: `pip install meshtastic` (убедитесь, что Scripts в PATH)
- Установите Graphviz и добавьте его `bin` в PATH
- Используйте COM-порт (пример: `--port COM3`)
- Узнать реальные пути на вашей машине:
  - `where python`
  - `where meshtastic`
  - `where dot`
- Добавить недостающие папки в PATH (PowerShell, для текущего пользователя):
  - `setx PATH "$env:PATH;C:\path\to\Python\Scripts;C:\path\to\Graphviz\bin"`
- Через GUI (Windows):
  - Пуск → «Изменение системных переменных среды»
  - Переменные среды… → выбрать `Path` → Изменить → Создать → вставить путь → OK

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

Сгенерировать граф из свежих логов:
```bash
python graphGen.py --root .
```

## Чек-лист первого запуска
- `meshtastic --help` работает
- `dot -V` работает
- `python meshLogger.py --port ...` создаёт `meshLogger/YYYY-MM-DD !xxxxxxxx.txt`
- `python nodeDbUpdater.py --port ...` создаёт/обновляет `nodeDb.txt`

## Структура файлов
```
meshTools/
  meshLogger.py
  nodeDbUpdater.py
  graphGen.py
  meshLogger/   # сгенерированные ежедневные логи traceroute
  graphGen/     # сгенерированные графы
  nodeDb.txt    # сгенерированная база узлов
```

## Примечания
- `nodeDb.txt` может содержать чувствительные данные (учётные данные, ключи, координаты). Храните приватно.
- `.gitignore` настроен на исключение сгенерированных логов и базы.
- `graphGen.py` ожидает файлы трасс вида `YYYY-MM-DD !xxxxxxxx*.txt`.

## Диагностика
- `meshtastic` не найден: выполните `pip install meshtastic` и добавьте Scripts в PATH.
- `dot` не найден: установите Graphviz и добавьте `bin` в PATH.
- Нет логов: убедитесь, что в `meshLogger/` есть файлы `YYYY-MM-DD !xxxxxxxx*.txt`.
