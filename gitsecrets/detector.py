"""Line-level secret detection: regex rules + entropy heuristics."""
import fnmatch
from dataclasses import dataclass
from typing import Iterable, List, Optional

from .entropy import looks_random, shannon
from .rules import ASSIGNMENT, RULES, TOKEN

IGNORE_MARKER = "gitsecrets:ignore"
MAX_LINE = 2000  # skip minified blobs / data lines

PLACEHOLDERS = ("example", "changeme", "placeholder", "your_", "your-", "xxxx",
                "<", "${", "{{", "dummy", "sample", "redacted")


@dataclass
class Finding:
    rule: str
    description: str
    secret: str
    path: str
    line: int
    commit: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    entropy: float = 0.0

    @property
    def redacted(self) -> str:
        s = self.secret
        return s[:4] + "*" * min(len(s) - 4, 12) if len(s) > 8 else "*" * len(s)

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["secret"] = self.redacted
        return d


def _is_placeholder(val: str) -> bool:
    low = val.lower()
    return any(p in low for p in PLACEHOLDERS) or len(set(val)) <= 3


def scan_line(line: str, entropy: bool = True,
              b64_threshold: float = 4.3, hex_threshold: float = 3.0) -> List[tuple]:
    """Return [(rule_id, description, secret, entropy)] for one line."""
    if len(line) > MAX_LINE or IGNORE_MARKER in line:
        return []
    hits, seen = [], set()

    def add(rule, desc, secret):
        if secret not in seen:
            seen.add(secret)
            hits.append((rule, desc, secret, shannon(secret)))

    for rule in RULES:
        for m in rule.regex.finditer(line):
            secret = m.group(rule.group)
            if rule.id == "db-url-password" and _is_placeholder(secret):
                continue
            add(rule.id, rule.description, secret)

    if entropy:
        # 1) secret-looking variable names with a random-looking value
        for m in ASSIGNMENT.finditer(line):
            val = m.group("val")
            if val in seen or _is_placeholder(val):
                continue
            if looks_random(val, b64_threshold - 0.5, hex_threshold - 0.3) \
                    or (shannon(val) >= 3.0 and any(c.isdigit() for c in val) and any(c.isalpha() for c in val)):
                add("generic-secret-assignment",
                    f"High-entropy value assigned to '{m.group('key')}'", val)
        # 2) any standalone high-entropy token
        for m in TOKEN.finditer(line):
            tok = m.group(0)
            if any(tok in x for x in seen) or _is_placeholder(tok) or "/" in tok and tok.count("/") > 2:
                continue
            if looks_random(tok, b64_threshold, hex_threshold):
                add("high-entropy-string", "High-entropy string", tok)
    return hits


class PathFilter:
    """Skips lockfiles, binaries and user-configured globs."""
    DEFAULT = ["*.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
               "poetry.lock", "go.sum", "*.min.js", "*.min.css", "*.map",
               "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.pdf", "*.zip",
               "*.gz", "*.woff", "*.woff2", "*.ttf", "*.pyc", ".gitsecretsignore"]

    def __init__(self, extra: Iterable[str] = ()):
        self.patterns = self.DEFAULT + list(extra)

    def skip(self, path: str) -> bool:
        base = path.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(base, p)
                   for p in self.patterns)


def load_ignore_file(path: str) -> List[str]:
    try:
        with open(path, encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except OSError:
        return []
