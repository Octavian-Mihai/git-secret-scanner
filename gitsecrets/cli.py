"""Command-line interface."""
from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from typing import Any

from . import __version__, baseline, hook
from .config import load_config
from .detector import load_ignore_file
from .gitscan import repo_root, scan_history, scan_staged, scan_tree
from .report import render_json, render_sarif, render_text
from .verify import verify

SUPPRESS = argparse.SUPPRESS
# Applied after parsing. (parser.set_defaults would mutate the option actions shared with the
# subparsers and clobber values given before the subcommand.)
DEFAULTS: dict[str, Any] = dict(cwd=".", config=None, format="text", output=None, show_secrets=False,
                no_entropy=False, no_base64=False, b64_threshold=None, hex_threshold=None,
                ignore=[], baseline=None, no_baseline=False, verify=False, exit_zero=False)


def _common() -> argparse.ArgumentParser:
    """Options accepted both before and after the subcommand."""
    c = argparse.ArgumentParser(add_help=False)
    c.add_argument("-C", dest="cwd", default=SUPPRESS, help="run as if started in this directory")
    c.add_argument("--config", default=SUPPRESS, help="config file (default: .gitsecrets.toml in the repo)")
    c.add_argument("--format", choices=["text", "json", "sarif"], default=SUPPRESS)
    c.add_argument("--json", dest="format", action="store_const", const="json", default=SUPPRESS,
                   help="shorthand for --format json")
    c.add_argument("-o", "--output", default=SUPPRESS, help="write the report to a file")
    c.add_argument("--show-secrets", action="store_true", default=SUPPRESS, help="print secrets unredacted")
    c.add_argument("--no-entropy", action="store_true", default=SUPPRESS, help="regex rules only")
    c.add_argument("--no-base64", action="store_true", default=SUPPRESS, help="don't decode base64 blobs")
    c.add_argument("--b64-threshold", type=float, default=SUPPRESS, help="base64 entropy cutoff (bits/char)")
    c.add_argument("--hex-threshold", type=float, default=SUPPRESS, help="hex entropy cutoff (bits/char)")
    c.add_argument("--ignore", action="append", default=SUPPRESS, metavar="GLOB", help="extra path glob to skip")
    c.add_argument("--baseline", default=SUPPRESS, help=f"baseline file (default: {baseline.DEFAULT_NAME} if present)")
    c.add_argument("--no-baseline", action="store_true", default=SUPPRESS, help="ignore any baseline file")
    c.add_argument("--verify", action="store_true", default=SUPPRESS,
                   help="check supported secrets against the provider's API (SENDS the secret to GitHub/Slack/Stripe)")
    c.add_argument("--exit-zero", action="store_true", default=SUPPRESS, help="always exit 0 (e.g. for SARIF upload steps)")
    return c


def build_parser() -> argparse.ArgumentParser:
    common = _common()
    p = argparse.ArgumentParser(prog="gitsecrets", parents=[common],
                                description="Find API keys and tokens in files, git history, and staged changes.")
    p.add_argument("--version", action="version", version=f"gitsecrets {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("history", parents=[common], help="scan every commit on every branch")
    h.add_argument("revs", nargs="*", help="rev-list args (default: --all)")
    h.add_argument("-j", "--jobs", type=int, default=None, help="parallel workers (default: CPU count, max 8)")
    sub.add_parser("staged", parents=[common], help="scan staged changes (used by the hook)")
    sub.add_parser("tree", parents=[common], help="scan current working files")
    b = sub.add_parser("baseline", parents=[common], help="record current findings so only new ones are reported")
    b.add_argument("--source", choices=["history", "tree"], default="history")
    b.add_argument("-j", "--jobs", type=int, default=None)
    i = sub.add_parser("install-hook", parents=[common], help="install pre-commit hook")
    i.add_argument("--force", action="store_true")
    sub.add_parser("uninstall-hook", parents=[common], help="remove pre-commit hook")
    return p


def _progress(done: int, total: int) -> None:
    end = "\n" if done == total else ""
    print(f"\rscanned {done}/{total} commits", end=end, file=sys.stderr, flush=True)


def _tree_root(cwd: str) -> str:
    try:
        return repo_root(cwd)
    except RuntimeError:
        return os.path.abspath(cwd)


def _run(a: argparse.Namespace) -> int:
    root = _tree_root(a.cwd) if a.cmd == "tree" else repo_root(a.cwd)
    if a.cmd == "install-hook":
        print(f"Installed {hook.install(root, a.force)}")
        return 0
    if a.cmd == "uninstall-hook":
        print("Removed pre-commit hook" if hook.uninstall(root) else "No hook installed")
        return 0

    cfg = load_config(root, a.config)
    cfg.entropy = cfg.entropy and not a.no_entropy
    cfg.decode_base64 = cfg.decode_base64 and not a.no_base64
    if a.b64_threshold is not None:
        cfg.b64_threshold = a.b64_threshold
    if a.hex_threshold is not None:
        cfg.hex_threshold = a.hex_threshold
    cfg.ignore_paths += a.ignore + load_ignore_file(os.path.join(root, ".gitsecretsignore"))

    show_progress = sys.stderr.isatty() and a.format == "text" and not a.output
    jobs = getattr(a, "jobs", None)
    source = getattr(a, "source", a.cmd)
    if source == "history":
        findings = scan_history(root, cfg, getattr(a, "revs", None) or None, jobs,
                                _progress if show_progress else None)
    elif source == "staged":
        findings = scan_staged(root, cfg)
    else:
        findings = scan_tree(root, cfg)

    if a.cmd == "baseline":
        path = a.baseline or os.path.join(root, baseline.DEFAULT_NAME)
        n = baseline.write(path, findings)
        print(f"Wrote {n} fingerprint(s) to {path}")
        return 0

    suppressed = 0
    base_path = a.baseline or os.path.join(root, baseline.DEFAULT_NAME)
    if not a.no_baseline and (a.baseline or os.path.exists(base_path)):
        findings, suppressed = baseline.filter_new(findings, baseline.load(base_path))
    if a.verify:
        print("note: --verify sends candidate secrets to their provider's API", file=sys.stderr)
        for f in findings:
            verify(f)

    if a.format == "json":
        report = render_json(findings, a.show_secrets, suppressed)
    elif a.format == "sarif":
        report = render_sarif(findings)
    else:
        report = render_text(findings, a.show_secrets,
                             color=sys.stdout.isatty() and not a.output, suppressed=suppressed)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    else:
        print(report)
    if findings and a.cmd == "staged" and a.format == "text":
        print("Commit blocked. Remove the secret, add `gitsecrets:ignore` to the line "
              "if it's a false positive, or bypass with --no-verify.", file=sys.stderr)
    return 1 if findings and not a.exit_zero else 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for key, value in DEFAULTS.items():
        if not hasattr(args, key):
            setattr(args, key, list(value) if isinstance(value, list) else value)
    try:
        return _run(args)
    except (RuntimeError, FileExistsError, OSError) as e:  # ConfigError is a RuntimeError
        print(f"error: {e}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
