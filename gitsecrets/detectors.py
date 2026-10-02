"""Individual detectors and the scan_line orchestrator.

Each detector is a generator `(text, cfg) -> Hit`, so it can be tested alone.
`scan_line` runs them in priority order and drops hits whose secret is already
covered by an earlier (more specific) hit.
"""
from __future__ import annotations

import base64
import re
from collections.abc import Iterator
from typing import NamedTuple

from .config import Config
from .entropy import B64, HEX, looks_random, shannon

IGNORE_MARKER = "gitsecrets:ignore"
MAX_ENTROPY_LINE = 2000    # entropy/base64 detectors skip longer lines (minified blobs)...
MAX_REGEX_LINE = 100_000   # ...but regex rules still run, up to this many characters

PLACEHOLDERS = ("example", "changeme", "placeholder", "your_", "your-", "xxxx",
                "<", "${", "{{", "dummy", "sample", "redacted")

# `password = "..."`-style assignments: value is entropy-checked.
ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<key>[\w.\-]*(?:secret|passw(?:or)?d|passwd|pwd|token|api[_\-]?key|apikey|
        auth|credential|private[_\-]?key|access[_\-]?key)[\w.\-]*)
    \s*[:=]\s*
    (?P<q>['"]?)(?P<val>[^\s'"`,;()\[\]{}]{8,})(?P=q)
    """
)
CODE_REFERENCE = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")  # foo.bar_baz: attribute access, not a value
TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{20,}={0,2}")
B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


class Hit(NamedTuple):
    rule: str
    description: str
    secret: str
    entropy: float


def is_placeholder(val: str) -> bool:
    low = val.lower()
    return any(p in low for p in PLACEHOLDERS) or len(set(val)) <= 3


def detect_regex(text: str, cfg: Config) -> Iterator[Hit]:
    low = text.lower()
    for rule in cfg.rules:
        if rule.keywords and not any(k in low for k in rule.keywords):
            continue
        for m in rule.regex.finditer(text):
            secret = m.group(rule.group)
            ent = shannon(secret)
            if ent < rule.min_entropy or any(a.search(secret) for a in rule.allowlist):
                continue
            yield Hit(rule.id, rule.description, secret, ent)


def detect_assignment(text: str, cfg: Config) -> Iterator[Hit]:
    for m in ASSIGNMENT.finditer(text):
        val = m.group("val")
        if is_placeholder(val) or CODE_REFERENCE.match(val):
            continue
        random_looking = looks_random(val, cfg.b64_threshold - 0.5, cfg.hex_threshold)
        mixed = (len(val) >= 12 and shannon(val) >= 3.0 and any(c.isdigit() for c in val)
                 and any(c.isalpha() for c in val))
        if random_looking or mixed:
            yield Hit("generic-secret-assignment",
                      f"High-entropy value assigned to '{m.group('key')}'", val, shannon(val))


def detect_entropy(text: str, cfg: Config) -> Iterator[Hit]:
    """Context-free high-entropy tokens. Hex is excluded: git SHAs and MD5s are
    indistinguishable from hex keys without context (see detect_assignment)."""
    if "base64," in text:  # data: URIs
        return
    for m in TOKEN.finditer(text):
        tok = m.group(0)
        if (is_placeholder(tok) or tok.startswith(("sha1-", "sha256-", "sha384-", "sha512-"))
                or tok.count("/") > 2 or HEX.match(tok) or not B64.match(tok)
                or not (any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok))):
            continue
        ent = shannon(tok)
        if ent >= cfg.b64_threshold:
            yield Hit("high-entropy-string", "High-entropy string", tok, ent)


def detect_base64(text: str, cfg: Config) -> Iterator[Hit]:
    """Decode base64 blobs and re-run the regex rules on the plaintext."""
    for m in B64_CANDIDATE.finditer(text):
        tok = m.group(0)
        try:
            decoded = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            continue
        if not decoded.replace("\n", "").isprintable():
            continue
        for h in detect_regex(decoded, cfg):
            yield Hit(h.rule + "+base64", h.description + " (base64-encoded)", h.secret, h.entropy)


def scan_line(line: str, cfg: Config) -> list[Hit]:
    if IGNORE_MARKER in line:
        return []
    line = line[:MAX_REGEX_LINE]
    detectors = [detect_regex]
    if len(line) <= MAX_ENTROPY_LINE:
        if cfg.entropy:
            detectors += [detect_assignment, detect_entropy]
        if cfg.decode_base64:
            detectors.append(detect_base64)
    hits: list[Hit] = []
    for detect in detectors:
        for h in detect(line, cfg):
            if any(h.secret in prev.secret for prev in hits):
                continue
            if any(a.search(h.secret) for a in cfg.allow_regexes):
                continue
            hits.append(h)
    return hits
