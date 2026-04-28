#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""
Normalize meshtalk/sp_vocab.txt:
- keep the initial comment header block
- parse tokens (supports the same escapes as runtime: \\s, \\t, \\n, \\\\)
- de-dupe
- drop 1-char tokens (they are ignored by trie anyway)
- sort lexicographically (escaped form) for stable diffs
"""

from __future__ import annotations

from pathlib import Path


def _unescape(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 1 >= len(s):
            out.append("\\")
            break
        nxt = s[i + 1]
        if nxt == "s":
            out.append(" ")
            i += 2
        elif nxt == "t":
            out.append("\t")
            i += 2
        elif nxt == "n":
            out.append("\n")
            i += 2
        elif nxt == "\\":
            out.append("\\")
            i += 2
        else:
            out.append("\\")
            out.append(nxt)
            i += 2
    return "".join(out)


def _escape(s: str) -> str:
    out = []
    for ch in s:
        if ch == " ":
            out.append("\\s")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\\":
            out.append("\\\\")
        else:
            out.append(ch)
    return "".join(out)

def _keep_token(tok: str) -> bool:
    # Keep tokens that contain at least one letter (RU/EN/etc).
    if any(ch.isalpha() for ch in tok):
        return True
    # Keep a tiny allowlist of non-letter tokens that help with URLs/paths.
    if "://" in tok:
        return True
    if tok.startswith(".") and any(ch.isalpha() for ch in tok[1:]):
        return True
    if tok.startswith("www."):
        return True
    return False


def main() -> int:
    path = Path(__file__).resolve().parents[1] / "meshtalk" / "sp_vocab.txt"
    raw = path.read_text(encoding="utf-8").splitlines()

    header: list[str] = []
    tokens: set[str] = set()

    in_header = True
    for line in raw:
        if in_header and (not line or line.lstrip().startswith("#")):
            header.append(line)
            continue
        in_header = False
        if not line:
            continue
        if line.lstrip().startswith("#"):
            continue
        tok = _unescape(line.rstrip("\n"))
        if not tok:
            continue
        if len(tok) < 2:
            continue
        if len(tok) > 64:
            continue
        if not _keep_token(tok):
            continue
        tokens.add(tok)

    out_lines = list(header)
    if out_lines and out_lines[-1] != "":
        out_lines.append("")

    escaped_sorted = sorted((_escape(t) for t in tokens), key=lambda x: (x.lower(), x))
    out_lines.extend(escaped_sorted)
    out_lines.append("")

    path.write_text("\n".join(out_lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
