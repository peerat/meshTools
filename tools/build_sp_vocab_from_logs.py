#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""
Build meshtalk/sp_vocab.txt from local runtime/history logs.

This is a convenience wrapper:
- collects corpus files (runtime.log, */runtime.log, */history.log)
- runs tools/build_sentencepiece_vocab.py
- normalizes output with tools/normalize_sp_vocab.py

Runtime decode path does NOT depend on sentencepiece.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "meshtalk" / "sp_vocab.txt"))
    ap.add_argument("--vocab_size", type=int, default=1200)
    args = ap.parse_args()

    corpus: list[str] = []
    for p in [
        ROOT / "runtime.log",
        *ROOT.glob("*/runtime.log"),
        *ROOT.glob("*/history.log"),
    ]:
        if p.is_file() and p.stat().st_size > 0:
            corpus.append(str(p))

    if not corpus:
        print("No corpus logs found.", file=sys.stderr)
        return 2

    cmd = [
        sys.executable,
        str(ROOT / "tools" / "build_sentencepiece_vocab.py"),
        "--out",
        str(args.out),
        "--vocab_size",
        str(int(args.vocab_size)),
        "--merge-existing",
        *corpus,
    ]
    subprocess.check_call(cmd)
    subprocess.check_call([sys.executable, str(ROOT / "tools" / "normalize_sp_vocab.py")])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

