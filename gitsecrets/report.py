"""Output formats: text, json (stable schema, see docs/finding.schema.json), sarif."""
from __future__ import annotations

import json
from collections.abc import Sequence

from . import __version__
from .detector import Finding

RED, YEL, GRN, DIM, RST = "\033[31m", "\033[33m", "\033[32m", "\033[2m", "\033[0m"
SCHEMA_VERSION = 1


def render_text(findings: Sequence[Finding], show_secrets: bool = False,
                color: bool = False, suppressed: int = 0) -> str:
    c = (lambda code, s: f"{code}{s}{RST}") if color else (lambda code, s: s)
    out = []
    for f in findings:
        out.append(c(RED, f"[{f.rule}]") + f" {f.description}")
        out.append(f"  file:   {f.path}:{f.line}")
        if f.commit:
            out.append(f"  commit: {f.commit[:10]}  {f.author}  {f.date}")
        out.append(f"  secret: {f.secret if show_secrets else f.redacted}"
                   + c(DIM, f"  (entropy {f.entropy:.2f})"))
        if f.verified is True:
            out.append("  status: " + c(RED, "LIVE") + f" - {f.verify_note}")
        elif f.verified is False:
            out.append("  status: " + c(GRN, "inactive") + f" - {f.verify_note}")
        elif f.verify_note:
            out.append(c(DIM, f"  status: unverified - {f.verify_note}"))
        out.append("")
    summary = (c(YEL, f"{len(findings)} potential secret(s) found") if findings
               else "No secrets found.")
    if suppressed:
        summary += c(DIM, f" ({suppressed} suppressed by baseline)")
    out.append(summary)
    return "\n".join(out)


def render_json(findings: Sequence[Finding], show_secrets: bool = False,
                suppressed: int = 0) -> str:
    return json.dumps({"schema_version": SCHEMA_VERSION, "tool_version": __version__,
                       "suppressed_by_baseline": suppressed,
                       "findings": [f.to_dict(show_secrets) for f in findings]}, indent=2)


def render_sarif(findings: Sequence[Finding]) -> str:
    """SARIF 2.1.0 for GitHub code scanning. Never contains the secret itself."""
    rules = {f.rule: f.description for f in findings}
    results = [{
        "ruleId": f.rule,
        "level": "warning" if f.verified is False else "error",
        "message": {"text": f"{f.description} ({f.redacted})"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.path},
            "region": {"startLine": max(f.line, 1)}}}],
        "partialFingerprints": {"gitsecrets/v1": f.fingerprint},
    } for f in findings]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "gitsecrets", "version": __version__,
            "informationUri": "https://github.com/Octavian-Mihai/git-secret-scanner",
            "rules": [{"id": i, "shortDescription": {"text": d}} for i, d in rules.items()]}},
            "results": results}],
    }, indent=2)
