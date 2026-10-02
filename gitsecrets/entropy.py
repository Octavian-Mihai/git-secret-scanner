"""Shannon entropy helpers."""
from __future__ import annotations

import math
import re
from collections import Counter

HEX = re.compile(r"^[0-9a-fA-F]+$")
B64 = re.compile(r"^[A-Za-z0-9+/=_\-]+$")

# Thresholds in bits/char; hex alphabets cap at 4.0 so need a lower bar.
HEX_THRESHOLD = 3.0
B64_THRESHOLD = 4.2


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def looks_random(s: str, b64_threshold: float = B64_THRESHOLD,
                 hex_threshold: float = HEX_THRESHOLD) -> bool:
    """True if `s` has high enough entropy for its charset to look like a secret."""
    if len(s) < 16:
        return False
    if HEX.match(s):
        return len(s) >= 32 and shannon(s) >= hex_threshold
    if B64.match(s):
        return shannon(s) >= b64_threshold
    return False
