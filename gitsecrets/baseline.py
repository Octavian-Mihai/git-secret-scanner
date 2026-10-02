"""Baselines: accept today's findings, report only new ones."""
from __future__ import annotations

import json
from collections.abc import Iterable

from .detector import Finding

DEFAULT_NAME = ".gitsecrets-baseline.json"


def write(path: str, findings: Iterable[Finding]) -> int:
    entries = {f.fingerprint: {"rule": f.rule, "path": f.path} for f in findings}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "fingerprints": entries}, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return len(entries)


def load(path: str) -> set[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            return set(json.load(fh)["fingerprints"])
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as e:
        raise RuntimeError(f"cannot read baseline {path}: {e}") from e


def filter_new(findings: list[Finding], known: set[str]) -> tuple[list[Finding], int]:
    new = [f for f in findings if f.fingerprint not in known]
    return new, len(findings) - len(new)
