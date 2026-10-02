"""Regex rules for well-known credential formats."""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    regex: re.Pattern
    group: int = 0  # capture group holding the secret itself


def _r(id, desc, pattern, group=0):
    return Rule(id, desc, re.compile(pattern), group)


RULES = [
    _r("aws-access-key-id", "AWS Access Key ID",
       r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b", 1),
    _r("aws-secret-access-key", "AWS Secret Access Key",
       r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?['\"=:\s]([A-Za-z0-9/+=]{40})\b", 1),
    _r("github-token", "GitHub Token",
       r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b", 1),
    _r("github-fine-grained-pat", "GitHub Fine-Grained PAT",
       r"\b(github_pat_[A-Za-z0-9_]{22,255})\b", 1),
    _r("gitlab-pat", "GitLab Personal Access Token",
       r"\b(glpat-[A-Za-z0-9_\-]{20})\b", 1),
    _r("slack-token", "Slack Token",
       r"\b(xox[abprs]-[A-Za-z0-9-]{10,72})\b", 1),
    _r("slack-webhook", "Slack Webhook URL",
       r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)", 1),
    _r("stripe-key", "Stripe API Key",
       r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,99})\b", 1),
    _r("google-api-key", "Google API Key",
       r"\b(AIza[0-9A-Za-z_\-]{35})\b", 1),
    _r("openai-key", "OpenAI API Key",
       r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})\b", 1),
    _r("anthropic-key", "Anthropic API Key",
       r"\b(sk-ant-[A-Za-z0-9_\-]{32,})\b", 1),
    _r("twilio-key", "Twilio API Key",
       r"\b(SK[0-9a-fA-F]{32})\b", 1),
    _r("sendgrid-key", "SendGrid API Key",
       r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", 1),
    _r("npm-token", "npm Access Token",
       r"\b(npm_[A-Za-z0-9]{36})\b", 1),
    _r("private-key", "Private Key Block",
       r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----)", 1),
    _r("jwt", "JSON Web Token",
       r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b", 1),
    _r("db-url-password", "Password in connection URL",
       r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:([^\s:/@]{6,})@[^\s/]+", 1),
]

# key = value assignments whose name suggests a secret; value is entropy-checked.
ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<key>[\w.\-]*(?:secret|passw(?:or)?d|passwd|pwd|token|api[_\-]?key|apikey|
        auth|credential|private[_\-]?key|access[_\-]?key)[\w.\-]*)
    \s*[:=]\s*
    (?P<q>['"]?)(?P<val>[^\s'"`,;()\[\]{}]{8,})(?P=q)
    """
)

# Generic quoted/standalone candidate tokens for pure-entropy detection.
TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{20,}={0,2}")
