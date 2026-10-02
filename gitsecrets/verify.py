"""Optional liveness checks (--verify).

WARNING: this sends the candidate secret to the provider's API. It is opt-in and
only uses harmless read-only endpoints. Unknown/unsupported rules are left unverified.
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from .detector import Finding

TIMEOUT = 5.0
Opener = Callable[..., Any]


def _call(opener: Opener, req: urllib.request.Request):
    """Return (http_status, body_text); status 0 on network failure."""
    try:
        with opener(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except (urllib.error.URLError, OSError, TimeoutError):
        return 0, ""


def _github(secret: str, opener: Opener):
    req = urllib.request.Request("https://api.github.com/user",
                                 headers={"Authorization": f"Bearer {secret}",
                                          "User-Agent": "gitsecrets"})
    status, _ = _call(opener, req)
    return {200: (True, "token is valid"), 401: (False, "token rejected")}.get(
        status, (None, f"inconclusive (HTTP {status})"))


def _slack(secret: str, opener: Opener):
    req = urllib.request.Request("https://slack.com/api/auth.test", data=b"",
                                 headers={"Authorization": f"Bearer {secret}"})
    status, body = _call(opener, req)
    if status != 200:
        return None, f"inconclusive (HTTP {status})"
    try:
        ok = json.loads(body).get("ok")
    except json.JSONDecodeError:
        return None, "inconclusive (bad response)"
    return (True, "token is valid") if ok else (False, "token rejected")


def _stripe(secret: str, opener: Opener):
    auth = base64.b64encode(f"{secret}:".encode()).decode()
    req = urllib.request.Request("https://api.stripe.com/v1/balance",
                                 headers={"Authorization": f"Basic {auth}"})
    status, _ = _call(opener, req)
    return {200: (True, "key is valid"), 401: (False, "key rejected")}.get(
        status, (None, f"inconclusive (HTTP {status})"))


VERIFIERS: dict[str, Callable] = {
    "github-token": _github, "github-fine-grained-pat": _github,
    "slack-token": _slack, "stripe-key": _stripe,
}


def verify(finding: Finding, opener: Opener | None = None) -> Finding:
    fn = VERIFIERS.get(finding.rule)
    if fn is None:
        finding.verify_note = "no verifier for this rule"
        return finding
    finding.verified, finding.verify_note = fn(finding.secret, opener or urllib.request.urlopen)
    return finding
