#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import datetime as _dt
import re
from pathlib import Path

import importlib.metadata as md


ROOT = Path(__file__).resolve().parents[1]


def _read_requirements(path: Path) -> list[str]:
    out: list[str] = []
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip environment markers / extras.
        line = re.split(r"\s*;\s*", line, maxsplit=1)[0].strip()
        line = re.split(r"\s+", line, maxsplit=1)[0].strip()
        if not line:
            continue
        # Strip pins (==) and ranges.
        name = re.split(r"[<>=!~]", line, maxsplit=1)[0].strip()
        if name:
            out.append(name)
    return out


def _meta_str(meta, key: str) -> str:
    try:
        v = meta.get(key) or ""
        return str(v).strip()
    except Exception:
        return ""


def main() -> int:
    reqs = []
    reqs += _read_requirements(ROOT / "requirements.txt")
    # requirements-ml.txt was removed; keep a single source of truth in requirements.txt
    # De-dupe while keeping stable ordering.
    seen = set()
    pkgs: list[str] = []
    for r in reqs:
        k = r.lower()
        if k in seen:
            continue
        seen.add(k)
        pkgs.append(r)

    lines: list[str] = []
    lines.append("# Third-Party Licenses (Local Environment Report)")
    lines.append("")
    lines.append(
        f"Generated: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (local machine)."
    )
    lines.append("")
    lines.append(
        "This file lists licenses for Python dependencies *as installed in the current environment*.\n"
        "It is a best-effort inventory and not legal advice. Always verify upstream license texts."
    )
    lines.append("")
    lines.append("| Package | Installed | Version | License (metadata) | License classifiers |")
    lines.append("|---|---:|---:|---|---|")

    for name in pkgs:
        try:
            dist = md.distribution(name)
            meta = dist.metadata
            ver = dist.version or ""
            lic = _meta_str(meta, "License") or "missing"
            classifiers = list(meta.get_all("Classifier") or [])
            lic_cls = [c for c in classifiers if c.startswith("License ::")]
            lic_cls_s = "<br>".join(lic_cls[:4]) if lic_cls else ""
            lines.append(f"| `{name}` | yes | `{ver}` | {lic} | {lic_cls_s} |")
        except Exception:
            lines.append(f"| `{name}` | no |  |  |  |")

    (ROOT / "THIRD_PARTY_LICENSES.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
