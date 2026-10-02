"""Labelled corpus for measuring detection quality.

Every fake credential is generated at import time from a seeded RNG, so the repo
contains no credential-shaped literals (keeps GitHub push protection and our own
self-scan quiet) and the corpus is reproducible.

POSITIVES: (expected_rule, line)  - a hit with that rule must fire
NEGATIVES: (category, line)       - nothing may fire
The corpus is hand-written and small; it was used to tune the detectors, so
treat the reported numbers as optimistic (see README, "Limitations").
"""
from __future__ import annotations

import base64
import json
import random
import string

rng = random.Random(1337)
B62 = string.ascii_letters + string.digits
UPPER36 = string.ascii_uppercase + "234567"
HEXD = "0123456789abcdef"
URLSAFE = B62 + "-_"


def rand(n: int, alphabet: str = B62) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def rand_edge(n: int, alphabet: str = URLSAFE) -> str:
    """Random string whose first/last chars are alphanumeric (so \\b anchors behave)."""
    return rand(1, B62) + rand(n - 2, alphabet) + rand(1, B62)


def _b64url(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _jwt() -> str:
    return f"{_b64url({'alg': 'HS256', 'typ': 'JWT'})}.{_b64url({'sub': rand(8), 'name': 'x'})}.{rand(43)}"


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


AKID = "AKIA" + rand(16, UPPER36)
POSITIVES: list[tuple[str, str]] = [
    ("aws-access-key-id", f'AWS_ACCESS_KEY_ID = "{AKID}"'),
    ("aws-access-key-id", f"aws_access_key_id: ASIA{rand(16, UPPER36)}"),
    ("aws-access-key-id", f"export AWS_KEY=AKIA{rand(16, UPPER36)}"),
    ("aws-secret-access-key", f"aws_secret_access_key = {rand(40)}"),
    ("aws-secret-access-key", f'AWS_SECRET_ACCESS_KEY: "{rand(40)}"'),
    ("github-token", f'GITHUB_TOKEN = "ghp_{rand(36)}"'),
    ("github-token", f"git clone https://gho_{rand(36)}@github.com/org/repo.git"),
    ("github-fine-grained-pat", f"token: github_pat_{rand(11)}_{rand(48)}"),
    ("gitlab-pat", f"GITLAB_TOKEN=glpat-{rand(20)}"),
    ("slack-token", f'SLACK_BOT_TOKEN = "xoxb-{rand(12, string.digits)}-{rand(13, string.digits)}-{rand(24)}"'),
    ("slack-webhook", f"url = https://hooks.slack.com/services/T{rand(8, UPPER36)}/B{rand(9, UPPER36)}/{rand(24)}"),
    ("stripe-key", f'stripe.api_key = "sk_live_{rand(24)}"'),
    ("stripe-key", f"STRIPE_KEY=rk_test_{rand(24)}"),
    ("google-api-key", f'apiKey: "AIza{rand_edge(35)}"'),
    ("anthropic-key", f'ANTHROPIC_API_KEY = "sk-ant-api03-{rand_edge(80)}"'),
    ("openai-key", f'client = OpenAI(api_key="sk-proj-{rand_edge(48)}")'),
    ("openai-key", f"OPENAI_API_KEY=sk-{rand(48)}"),
    ("twilio-key", f"TWILIO_KEY=SK{rand(32, HEXD)}"),
    ("sendgrid-key", f'SENDGRID = "SG.{rand(22)}.{rand(43)}"'),
    ("npm-token", f"//registry.npmjs.org/:_authToken=npm_{rand(36)}"),
    ("private-key", "-----BEGIN RSA PRIVATE KEY-----"),
    ("private-key", "-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("jwt", f'Authorization: Bearer {_jwt()}'),
    ("db-url-password", f'DATABASE_URL = "postgres://admin:{rand(14)}@db.internal:5432/app"'),
    ("db-url-password", f"mongodb://svc:{rand(18)}@cluster0.example.net/db"),
    ("generic-secret-assignment", f'api_secret = "{rand(32)}"'),
    ("generic-secret-assignment", f"SECRET_KEY={rand(50)}"),
    ("generic-secret-assignment", f"password: {rand(20)}"),
    ("generic-secret-assignment", f'client_secret = "{rand(40)}"'),
    ("generic-secret-assignment", f'api_key = "{rand(32, HEXD)}"'),
    ("high-entropy-string", f'const k = "{rand(40)}";'),
    ("high-entropy-string", f"headers = {{'X-Custom': '{rand(32)}'}}"),
    ("aws-access-key-id+base64", f'blob = "{_b64("AKIA" + rand(16, UPPER36))}"'),
    ("github-token+base64", f'config: {_b64("ghp_" + rand(36))}'),
]

_SHA = rand(40, HEXD)
NEGATIVES: list[tuple[str, str]] = [
    ("git sha", f"git checkout {_SHA}"),
    ("git sha", f'commit = "{_SHA}"'),
    ("md5", f"md5sum: {rand(32, HEXD)}"),
    ("sha256", f"sha256 {rand(64, HEXD)}  release.tar.gz"),
    ("lockfile", f'      "integrity": "sha512-{rand(86, B62 + "+/")}==",'),
    ("lockfile", f"    resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#{rand(40, HEXD)}\""),
    ("uuid", 'id = "123e4567-e89b-12d3-a456-426614174000"'),
    ("uuid", f"request_id: {rand(8, HEXD)}-{rand(4, HEXD)}-{rand(4, HEXD)}-{rand(4, HEXD)}-{rand(12, HEXD)}"),
    ("data uri", f'<img src="data:image/png;base64,{rand(120, B62 + "+/")}">'),
    ("placeholder", 'password = "changeme"'),
    ("placeholder", 'api_key = "your-api-key-here"'),
    ("placeholder", "API_KEY=${API_KEY}"),
    ("placeholder", "secret: <SECRET>"),
    ("placeholder", 'password: "********"'),
    ("placeholder", "AWS_SECRET_ACCESS_KEY={{ aws_secret }}"),
    ("placeholder", 'token = "example_token_value_123"'),
    ("env lookup", 'password = os.environ["DB_PASSWORD"]'),
    ("env lookup", "const token = process.env.GITHUB_TOKEN;"),
    ("env lookup", 'secret = getenv("SECRET_KEY")'),
    ("env lookup", "token = request.headers.get('Authorization')"),
    ("code", "def validate_authentication_token(self, token):"),
    ("code", "self.token = token_provider.get_token()"),
    ("code", "const getUserAuthenticationHandlerFactory = createFactory();"),
    ("code", "class AuthenticationTokenRefreshInterceptor extends Interceptor {"),
    ("code", "auth_token: Optional[str] = None"),
    ("code", "auth = base64.b64encode(raw).decode()"),
    ("code", "secret = config.get_secret_value2()"),
    ("code", "headers['X-Token'] = self.session.token64"),
    ("code", "if (user.passwordResetTokenExpiresAt < Date.now()) {"),
    ("code", "private static final String SECRET_KEY_ALGORITHM = \"HmacSHA256\";"),
    ("code", "return jwt.sign(payload, config.jwtSecret, { expiresIn: '1h' });"),
    ("path", 'import Provider from "../../components/shared/AuthenticationTokenProvider";'),
    ("path", "/usr/local/lib/python3.12/site-packages/some_package/internal/module.py"),
    ("path", "see src/main/java/com/example/security/auth/TokenValidator.java"),
    ("url", "https://example.com/api/v1/users/1234567890/profile/settings"),
    ("url", "https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap"),
    ("css", ".btn-primary-outline-large-rounded-corners-hover-state { color: #ff00aa; }"),
    ("css", "background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);"),
    ("text", "The quick brown fox jumps over the lazy dog while the authentication token is refreshed."),
    ("text", "# TODO: rotate the API key before the 2026 release"),
    ("text", "Set your password in the settings page after the first login."),
    ("test fixture", 'password = "hunter2hunter2"'),
    ("test fixture", 'password = "correct-horse-battery-staple"'),
    ("test fixture", 'token = "test-token"'),
    ("test fixture", 'secret = "secretsecret"'),
    ("test fixture", 'api_key = "abcdefgh"'),
    ("number", "const BIG = 123456789012345678901234567890;"),
    ("number", "timestamp: 1696118400000000000000"),
    ("version", "version = '1.2.3-beta.4+build.20260101.abcdef'"),
    ("ignored", f'API_KEY = "AKIA{rand(16, UPPER36)}"  # gitsecrets:ignore'),
]
