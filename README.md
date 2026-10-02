# gitsecrets

A mini gitleaks in pure Python (no dependencies). Finds API keys and tokens using
**regex rules + Shannon-entropy detection**, scans the **full git history** (including
secrets that were later deleted), and installs as a **pre-commit hook**.

```bash
pip install -e .
gitsecrets tree                  # scan current files
gitsecrets history               # scan every commit on every branch
gitsecrets install-hook          # block commits that add secrets
```

## Demo

```bash
git init demo && cd demo
echo 'AWS_KEY = "AKIA<16 uppercase chars>"' > cfg.py
gitsecrets install-hook
git add cfg.py && git commit -m "oops"   # blocked
```

## How it works

- **Rules** (`rules.py`): AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic,
  Twilio, SendGrid, npm, JWTs, private keys, passwords in URLs.
- **Entropy** (`entropy.py`): flags random-looking strings (base64 > 4.3 bits/char,
  hex > 3.0) and values assigned to secret-sounding names (`api_key`, `password`, ...).
  Placeholders such as `changeme` or `${VAR}` are skipped.
- **History** (`gitscan.py`): streams `git log --all -p`, oldest first, parsing added
  lines; each secret is reported once, at the commit that introduced it.
- **Hook** (`hook.py`): `pre-commit` runs `gitsecrets staged`; exit code 1 blocks the commit.

## False positives

Add `gitsecrets:ignore` to a line, list globs in `.gitsecretsignore`, or pass `--ignore GLOB`.
Tune with `--b64-threshold` / `--hex-threshold`, or use `--no-entropy`.
Output is redacted unless `--show-secrets`; `--json` for CI. Exit codes: 0 clean, 1 findings, 2 error.

## Tests

```bash
python -m unittest discover tests
```
