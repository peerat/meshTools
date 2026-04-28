# meshTools

Utilities for collecting Meshtastic node data, storing it in SQLite, and generating topology graphs.

## Components

- `meshLogger.py`: polls Meshtastic nodes, stores node samples, traceroutes, and listen events in `meshLogger.db`.
- `nodeDbUpdater.py`: one-shot updater that refreshes the legacy `nodeDb.txt` snapshot.
- `graphGen.py`: builds Graphviz and D3 topology reports from `meshLogger.db` or legacy trace files.
- `sqlite_utils.py`: shared SQLite/time helpers used by the runtime scripts.

## Requirements

- `python3` 3.12+
- Meshtastic CLI in `PATH` as `meshtastic`
- Graphviz `dot` in `PATH` for `graphGen.py`
- USB/serial access to a Meshtastic radio for live collection

## Typical usage

Collect one polling cycle:

```bash
python3 meshLogger.py --once --db meshLogger.db
```

Collect continuously:

```bash
python3 meshLogger.py --port /dev/ttyUSB0 --db meshLogger.db
```

Refresh the legacy node snapshot:

```bash
python3 nodeDbUpdater.py --port /dev/ttyUSB0 --db nodeDb.txt
```

Generate graph artifacts:

```bash
python3 graphGen.py --root .
```

Show database schema or version without touching the radio:

```bash
python3 meshLogger.py --db-schema
python3 meshLogger.py --version
```

## Runtime artifacts

These files are generated during normal operation and should usually stay out of version control:

- `meshLogger.db`
- `nodeDb.txt`
- `graphGen/`
- `__pycache__/`

## Development checks

Syntax check:

```bash
python3 -m py_compile graphGen.py meshLogger.py nodeDbUpdater.py sqlite_utils.py
```

Unit tests:

```bash
python3 -m unittest discover -s tests
```

## Windows EXE build

Manual build on Windows:

```bat
py -m pip install pyinstaller meshtastic
build_tune_exe.bat
```

Automatic build in GitHub Actions:

- workflow: `.github/workflows/build-windows-tune.yml`
- trigger it from `Actions -> Build Windows Tune EXE -> Run workflow`
- download artifact `meshLoggerTune-windows`
- resulting file inside the artifact: `dist/meshLoggerTune.exe`

## Notes

- New traceroute rows are stored with UTC ISO timestamps plus an indexed `ts_epoch` column for efficient time-window queries.
- Generated HTML reports embed graph data through a JSON script tag with escaping to avoid script injection from node names.
