"""Compatibility alias for the root-level graphGen module."""

from __future__ import annotations

import sys

from ._root_import import load_root_module

_module = load_root_module("graphGen")
sys.modules[__name__] = _module
