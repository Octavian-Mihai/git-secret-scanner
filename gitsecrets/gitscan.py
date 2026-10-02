"""Scan git history, staged changes, and working-tree files."""
import os
import subprocess
from typing import Iterable, Iterator, List, Optional, Tuple

from .detector import Finding, PathFilter, scan_line

COMMIT_MARK = "\x01COMMIT\x02"


def _git(args: List[str], cwd: str) -> subprocess.Popen:
    return subprocess.Popen(["git", *args], cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)


def repo_root(cwd: str = ".") -> str:
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd,
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError("not inside a git repository")
    return out.stdout.strip()


def _parse_diff(lines: Iterable[str]) -> Iterator[Tuple[Optional[tuple], str, int, str]]:
    """Yield (commit, path, new_lineno, text) for every added line in a `git log -p`/`git diff` stream."""
    commit, path, lineno = None, None, 0
    for raw in lines:
        line = raw.rstrip("\n")
        if line.startswith(COMMIT_MARK):
            sha, author, date = (line[len(COMMIT_MARK):].split("\x00") + ["", ""])[:3]
            commit, path = (sha, author, date), None
        elif line.startswith("+++ "):
            target = line[4:]
            path = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
        elif line.startswith("@@"):
            # @@ -a,b +c,d @@
            try:
                lineno = int(line.split("+")[1].split(" ")[0].split(",")[0])
            except (IndexError, ValueError):
                lineno = 0
        elif path and line.startswith("+") and not line.startswith("+++"):
            yield commit, path, lineno, line[1:]
            lineno += 1


def _scan_stream(lines, pf: PathFilter, dedupe: bool, **kw) -> List[Finding]:
    findings, seen = [], set()
    for commit, path, lineno, text in _parse_diff(lines):
        if pf.skip(path):
            continue
        for rule, desc, secret, ent in scan_line(text, **kw):
            key = (rule, secret, path)
            if dedupe and key in seen:
                continue
            seen.add(key)
            findings.append(Finding(rule, desc, secret, path, lineno,
                                    *(commit or (None, None, None)), entropy=ent))
    return findings


def scan_history(root: str, pf: PathFilter, rev_args: Optional[List[str]] = None,
                 **kw) -> List[Finding]:
    """Walk every commit on every ref (oldest first, so the *introducing* commit is reported)."""
    fmt = f"--format={COMMIT_MARK}%H%x00%an%x00%aI"
    args = ["log", "--reverse", "-p", "-U0", "--no-color", "--no-ext-diff",
            "--diff-filter=AM", "-m", fmt] + (rev_args or ["--all"])
    proc = _git(args, root)
    lines = (l.decode("utf-8", "replace") for l in proc.stdout)
    findings = _scan_stream(lines, pf, dedupe=True, **kw)
    err = proc.stderr.read().decode("utf-8", "replace")
    if proc.wait() != 0 and "does not have any commits" not in err:
        raise RuntimeError(err.strip() or "git log failed")
    return findings


def scan_staged(root: str, pf: PathFilter, **kw) -> List[Finding]:
    proc = _git(["diff", "--cached", "-U0", "--no-color", "--no-ext-diff",
                 "--diff-filter=AM"], root)
    lines = (l.decode("utf-8", "replace") for l in proc.stdout)
    findings = _scan_stream(lines, pf, dedupe=False, **kw)
    if proc.wait() != 0:
        raise RuntimeError(proc.stderr.read().decode("utf-8", "replace").strip())
    return findings


def _is_binary(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(4096)
    except OSError:
        return True


def scan_tree(root: str, pf: PathFilter, **kw) -> List[Finding]:
    """Scan current files: tracked + untracked (non-ignored) in a repo, else a plain walk."""
    try:
        out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"],
                             cwd=root, capture_output=True, text=True, check=True).stdout
        paths = [p for p in out.splitlines()]
    except (subprocess.CalledProcessError, FileNotFoundError):
        paths = []
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x != ".git"]
            paths += [os.path.relpath(os.path.join(d, f), root) for f in files]
    findings = []
    for rel in paths:
        full = os.path.join(root, rel)
        if pf.skip(rel) or not os.path.isfile(full) or _is_binary(full):
            continue
        with open(full, encoding="utf-8", errors="replace") as f:
            for i, text in enumerate(f, 1):
                for rule, desc, secret, ent in scan_line(text.rstrip("\n"), **kw):
                    findings.append(Finding(rule, desc, secret, rel, i, entropy=ent))
    return findings
