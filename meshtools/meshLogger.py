"""Compatibility alias for the root-level meshLogger module."""

from __future__ import annotations

import sys

from ._root_import import load_root_module

_module = load_root_module("meshLogger")
sys.modules[__name__] = _module
