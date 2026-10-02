"""Command-line interface."""
import argparse
import json
import os
import sys

from . import hook
from .detector import PathFilter, load_ignore_file
from .gitscan import repo_root, scan_history, scan_staged, scan_tree

RED, YEL, DIM, RST = "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def _print(findings, as_json: bool, show_secrets: bool):
    if as_json:
        print(json.dumps([f.to_dict() if not show_secrets else f.__dict__
                          for f in findings], indent=2))
        return
    tty = sys.stdout.isatty()
    c = (lambda code, s: f"{code}{s}{RST}") if tty else (lambda code, s: s)
    for f in findings:
        print(c(RED, f"[{f.rule}]") + f" {f.description}")
        print(f"  file:   {f.path}:{f.line}")
        if f.commit:
            print(f"  commit: {f.commit[:10]}  {f.author}  {f.date}")
        print(f"  secret: {f.secret if show_secrets else f.redacted}"
              + c(DIM, f"  (entropy {f.entropy:.2f})"))
        print()
    print(c(YEL, f"{len(findings)} potential secret(s) found") if findings
          else "No secrets found.")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="gitsecrets",
                                description="Find API keys and tokens in files, git history, and staged changes.")
    p.add_argument("-C", dest="cwd", default=".", help="repository path")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--show-secrets", action="store_true", help="print secrets unredacted")
    p.add_argument("--no-entropy", action="store_true", help="regex rules only")
    p.add_argument("--b64-threshold", type=float, default=4.3, help="base64 entropy cutoff (bits/char)")
    p.add_argument("--hex-threshold", type=float, default=3.0, help="hex entropy cutoff (bits/char)")
    p.add_argument("--ignore", action="append", default=[], metavar="GLOB", help="extra path glob to skip")
    sub = p.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("history", help="scan every commit on every branch")
    h.add_argument("revs", nargs="*", help="rev-list args (default: --all)")
    sub.add_parser("staged", help="scan staged changes (used by the hook)")
    sub.add_parser("tree", help="scan current working files")
    i = sub.add_parser("install-hook", help="install pre-commit hook")
    i.add_argument("--force", action="store_true")
    sub.add_parser("uninstall-hook", help="remove pre-commit hook")
    a = p.parse_args(argv)

    try:
        root = repo_root(a.cwd) if a.cmd != "tree" else _tree_root(a.cwd)
        if a.cmd == "install-hook":
            print(f"Installed {hook.install(root, a.force)}")
            return 0
        if a.cmd == "uninstall-hook":
            print("Removed pre-commit hook" if hook.uninstall(root) else "No hook installed")
            return 0
        pf = PathFilter(a.ignore + load_ignore_file(os.path.join(root, ".gitsecretsignore")))
        kw = dict(entropy=not a.no_entropy, b64_threshold=a.b64_threshold,
                  hex_threshold=a.hex_threshold)
        if a.cmd == "history":
            findings = scan_history(root, pf, a.revs or None, **kw)
        elif a.cmd == "staged":
            findings = scan_staged(root, pf, **kw)
        else:
            findings = scan_tree(root, pf, **kw)
    except (RuntimeError, FileExistsError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    _print(findings, a.json, a.show_secrets)
    if findings and a.cmd == "staged" and not a.json:
        print("Commit blocked. Remove the secret, add `gitsecrets:ignore` to the line "
              "if it's a false positive, or bypass with --no-verify.", file=sys.stderr)
    return 1 if findings else 0


def _tree_root(cwd: str) -> str:
    try:
        return repo_root(cwd)
    except RuntimeError:
        return os.path.abspath(cwd)


if __name__ == "__main__":
    sys.exit(main())
