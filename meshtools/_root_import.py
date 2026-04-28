"""Load root-level meshTools modules from the parent project checkout."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path


def load_root_module(name: str):
    root_dir = Path(__file__).resolve().parents[2]
    root_str = str(root_dir)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    return importlib.import_module(name)
