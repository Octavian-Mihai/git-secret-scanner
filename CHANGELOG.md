# Changelog

## 0.2.0
### Added
- **Baselines**: `gitsecrets baseline` records current findings; later scans report only new ones (`.gitsecrets-baseline.json`, fingerprints ignore line numbers and commits).
- **Verification** (`--verify`, opt-in): checks GitHub, Slack and Stripe secrets against the provider's API.
- **TOML rules**: built-in rules live in `gitsecrets/rules.toml`; users add/disable rules and tune entropy in `.gitsecrets.toml`. Rules support `keywords`, `min_entropy` and `allowlist`.
- **Base64 decoding**: encoded secrets are decoded and re-scanned (`<rule>+base64`).
- **Output**: `--format sarif` (GitHub code scanning), versioned JSON schema (`docs/finding.schema.json`), `-o/--output`, `--exit-zero`.
- **Parallel history scan** (`-j`), progress indicator, keyword prefilter.
- pre-commit framework hook (`.pre-commit-hooks.yaml`) and a GitHub Action (`action.yml`).
- Labelled benchmark corpus + `python -m benchmarks.evaluate` (precision/recall, entropy-threshold sweep).
- CI: tests on Python 3.11-3.13 (Linux, macOS), ruff, mypy, self-scan.

### Changed
- Global options (`-C`, `--json`, ...) now work before *and* after the subcommand.
- Default base64 entropy threshold 4.3 -> 4.2 (chosen from the benchmark sweep).
- Context-free hex strings (git SHAs, MD5s) are no longer flagged; hex needs a secret-looking variable name.
- `node_modules/` and `vendor/` are skipped by default.
- Requires Python >= 3.11 (for `tomllib`).

### Fixed
- Added lines that start with `++` were misread as file headers in history scans.
- File names containing spaces/quotes in history scans.
- Renamed-and-modified files are now scanned.
- Very long lines no longer bypass the regex rules.
- Anthropic keys were reported as OpenAI keys.
- Unclosed subprocess pipes; uncaught error for a nonexistent `-C` path.

## 0.1.0
- Initial release: regex + entropy scanner, history scan, pre-commit hook.
