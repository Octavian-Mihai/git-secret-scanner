"""Shared types: Finding and PathFilter."""
from __future__ import annotations

import fnmatch
import hashlib
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass
class Finding:
    rule: str
    description: str
    secret: str
    path: str
    line: int
    commit: str | None = None
    author: str | None = None
    date: str | None = None
    entropy: float = 0.0
    verified: bool | None = None  # None = not checked / unknown
    verify_note: str = ""

    @property
    def redacted(self) -> str:
        s = self.secret
        return s[:4] + "*" * min(len(s) - 4, 12) if len(s) > 8 else "*" * len(s)

    @property
    def fingerprint(self) -> str:
        """Stable id for baselines: rule + path + secret (never the line number or commit)."""
        return hashlib.sha256(f"{self.rule}\0{self.path}\0{self.secret}".encode()).hexdigest()[:16]

    def to_dict(self, show_secrets: bool = False) -> dict:
        return {
            "rule": self.rule, "description": self.description,
            "path": self.path, "line": self.line,
            "commit": self.commit, "author": self.author, "date": self.date,
            "secret": self.secret if show_secrets else self.redacted,
            "entropy": round(self.entropy, 3),
            "fingerprint": self.fingerprint,
            "verified": self.verified, "verify_note": self.verify_note,
        }


class PathFilter:
    """Skips lockfiles, binaries, vendored code and user-configured globs."""
    DEFAULT = ["*.lock", "*package-lock.json", "yarn.lock", "pnpm-lock.yaml",
               "poetry.lock", "go.sum", "*.min.js", "*.min.css", "*.map",
               "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.pdf", "*.zip",
               "*.gz", "*node_modules/*", "node_modules/*", "*vendor/*", "vendor/*",
               "*.woff", "*.woff2", "*.ttf", "*.pyc", ".gitsecretsignore",
               ".gitsecrets-baseline.json"]

    def __init__(self, extra: Iterable[str] = ()):
        self.patterns = self.DEFAULT + list(extra)

    def skip(self, path: str) -> bool:
        base = path.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(base, p)
                   for p in self.patterns)


def load_ignore_file(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except OSError:
        return []
