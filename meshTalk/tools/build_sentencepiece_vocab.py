#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""
Build a reversible vocab list for meshTalk token-stream normalization from a text corpus.

This script requires `sentencepiece` *only for building* the vocab.
Runtime decode path does NOT depend on sentencepiece.

Usage:
  python tools/build_sentencepiece_vocab.py --out meshtalk/sp_vocab.txt corpus1.txt corpus2.txt
  python tools/build_sentencepiece_vocab.py --out meshtalk/sp_vocab.txt --merge-existing corpus*.log
"""

from __future__ import annotations

import argparse
import os
import tempfile
from typing import Iterable, List, Set


def _escape_token(s: str) -> str:
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


def _read_corpus(paths: List[str]) -> str:
    parts: List[str] = []
    for p in paths:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            parts.append(f.read())
    return "\n".join(parts)


def _extract_pieces(vocab_path: str) -> List[str]:
    # sentencepiece .vocab file: "piece<TAB>score"
    pieces: List[str] = []
    with open(vocab_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            piece = line.split("\t", 1)[0]
            if not piece:
                continue
            # Ignore special tokens.
            if piece.startswith("<") and piece.endswith(">"):
                continue
            pieces.append(piece)
    return pieces


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="Output vocab file (e.g. meshtalk/sp_vocab.txt)")
    ap.add_argument("--vocab_size", type=int, default=800, help="SentencePiece vocab size")
    ap.add_argument(
        "--merge-existing",
        action="store_true",
        help="Merge generated tokens with existing output file (if it exists).",
    )
    ap.add_argument("corpus", nargs="+", help="Input text files")
    args = ap.parse_args()

    try:
        import sentencepiece as spm  # type: ignore
    except Exception as ex:
        raise SystemExit(f"sentencepiece is required to build vocab: {ex}")

    corpus_text = _read_corpus(args.corpus)
    if not corpus_text.strip():
        raise SystemExit("empty corpus")

    out_path = str(args.out)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="meshtalk_spm_") as td:
        corpus_path = os.path.join(td, "corpus.txt")
        model_prefix = os.path.join(td, "spm")
        with open(corpus_path, "w", encoding="utf-8") as f:
            f.write(corpus_text)

        spm.SentencePieceTrainer.Train(
            input=corpus_path,
            model_prefix=model_prefix,
            vocab_size=int(args.vocab_size),
            model_type="bpe",
            character_coverage=1.0,
            normalization_rule_name="nmt_nfkc",
            bos_id=-1,
            eos_id=-1,
        )

        vocab_file = model_prefix + ".vocab"
        raw_pieces = _extract_pieces(vocab_file)

        # SentencePiece uses U+2581 "▁" as whitespace marker in pieces.
        # For reversible substring tokenization we convert leading markers to spaces,
        # and also include a no-leading-space variant.
        tokens: Set[str] = set()
        for p in raw_pieces:
            if not p or len(p) < 2:
                continue
            # Convert all markers to spaces (best-effort).
            p2 = p.replace("▁", " ")
            if p2.strip() == "":
                continue
            if len(p2) > 64:
                continue
            tokens.add(p2)
            # Add variant without leading spaces to help matching at string start.
            tokens.add(p2.lstrip(" "))

        # Deterministic order: longer first.
        ordered = sorted(tokens, key=lambda x: (-len(x), x))

        merged: Set[str] = set(ordered)
        if bool(args.merge_existing) and os.path.isfile(out_path):
            try:
                for line in open(out_path, "r", encoding="utf-8", errors="ignore"):
                    line = line.rstrip("\n")
                    if not line or line.lstrip().startswith("#"):
                        continue
                    # Best-effort unescape: reuse same encoding rules as normalize_sp_vocab.py
                    # to keep behavior consistent.
                    piece = line.replace("\\s", " ").replace("\\t", "\t").replace("\\n", "\n").replace("\\\\", "\\")
                    if piece and len(piece) >= 2:
                        merged.add(piece)
            except Exception:
                pass

        ordered2 = sorted(merged, key=lambda x: (-len(x), x))
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(
                "# Auto-generated vocab for reversible token-stream normalization.\n"
                "# Tokens are literal substrings. Escapes: \\\\s space, \\\\t tab, \\\\n newline, \\\\\\\\ backslash.\n"
            )
            for t in ordered2:
                if not t or len(t) < 2:
                    continue
                if len(t) > 64:
                    continue
                f.write(_escape_token(t) + "\n")

    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
