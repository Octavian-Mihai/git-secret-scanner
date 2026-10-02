"""Scan git history (in parallel), staged changes, and working-tree files."""
from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor

from .config import Config
from .detector import Finding, PathFilter
from .detectors import scan_line

COMMIT_MARK = "\x01COMMIT\x02"
HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
UNESCAPE = re.compile(r'\\(["\\tn])')
GIT = ["git", "-c", "core.quotepath=off"]
# Don't even ask git for diffs of vendored dirs (PathFilter would drop them anyway).
PATHSPEC = ["--", ".", ":(exclude,glob)**/node_modules/**", ":(exclude,glob)**/vendor/**"]
MAX_CHUNK = 500
MIN_PARALLEL_COMMITS = 100

Progress = Callable[[int, int], None]


def repo_root(cwd: str = ".") -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd,
                             capture_output=True, text=True)
    except OSError as e:
        raise RuntimeError(f"cannot run git in {cwd!r}: {e.strerror}") from e
    if out.returncode != 0:
        raise RuntimeError("not inside a git repository")
    return out.stdout.strip()


def _unquote(path: str) -> str:
    if len(path) >= 2 and path[0] == path[-1] == '"':
        path = UNESCAPE.sub(lambda m: {"t": "\t", "n": "\n"}.get(m.group(1), m.group(1)), path[1:-1])
    return path


def parse_diff(lines: Iterable[str]) -> Iterator[tuple[tuple | None, str, int, str]]:
    """Yield (commit, path, new_lineno, text) for each added line in a `git log -p` / `git diff` stream.

    Hunk header counts tell us exactly how many content lines follow, so an added line
    that happens to read `++ x` (shown as `+++ x`) is never mistaken for a file header.
    """
    commit: tuple | None = None
    path: str | None = None
    lineno = old_left = new_left = 0
    for raw in lines:
        line = raw.rstrip("\n")
        if old_left > 0 or new_left > 0:
            if line.startswith("+"):
                new_left -= 1
                if path:
                    yield commit, path, lineno, line[1:]
                lineno += 1
            elif line.startswith("-"):
                old_left -= 1
            # "\ No newline at end of file" and anything else: ignore
            continue
        if line.startswith(COMMIT_MARK):
            sha, author, date = (line[len(COMMIT_MARK):].split("\x00") + ["", ""])[:3]
            commit, path = (sha, author, date), None
        elif line.startswith("+++ "):
            target = _unquote(line[4:].rstrip("\t"))
            path = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
        elif (m := HUNK.match(line)):
            old_left = int(m.group(1)) if m.group(1) is not None else 1
            lineno = int(m.group(2))
            new_left = int(m.group(3)) if m.group(3) is not None else 1


def _scan_lines(lines: Iterable[str], cfg: Config) -> list[Finding]:
    pf = PathFilter(cfg.ignore_paths)
    findings = []
    for commit, path, lineno, text in parse_diff(lines):
        if pf.skip(path):
            continue
        sha, author, date = commit or (None, None, None)
        for hit in scan_line(text, cfg):
            findings.append(Finding(hit.rule, hit.description, hit.secret, path, lineno,
                                    sha, author, date, entropy=hit.entropy))
    return findings


def _dedupe(findings: Iterable[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.rule, f.secret, f.path)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _decode(stream) -> Iterator[str]:
    return (ln.decode("utf-8", "replace") for ln in stream)


def _scan_chunk(args: tuple[str, list[str], Config]) -> list[Finding]:
    root, shas, cfg = args
    fmt = f"--format={COMMIT_MARK}%H%x00%an%x00%aI"
    cmd = GIT + ["log", "--no-walk=unsorted", "--stdin", "-p", "-U0", "--no-color",
                 "--no-ext-diff", "--diff-filter=ACMR", fmt, *PATHSPEC]
    with subprocess.Popen(cmd, cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as proc:
        assert proc.stdin and proc.stdout and proc.stderr
        proc.stdin.write(("\n".join(shas) + "\n").encode())
        proc.stdin.close()
        findings = _scan_lines(_decode(proc.stdout), cfg)
        err = proc.stderr.read().decode("utf-8", "replace")
    if proc.returncode != 0:
        raise RuntimeError(err.strip() or "git log failed")
    return findings


def scan_history(root: str, cfg: Config, rev_args: list[str] | None = None,
                 jobs: int | None = None, progress: Progress | None = None) -> list[Finding]:
    """Scan every commit (default: all refs), oldest first, so each secret is reported
    at the commit that introduced it. Commits are split into chunks scanned in parallel."""
    proc = subprocess.run(GIT + ["rev-list", "--reverse", *(rev_args or ["--all"])],
                          cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "git rev-list failed")
    shas = proc.stdout.split()
    total = len(shas)
    if total == 0:
        return []
    jobs = jobs or min(os.cpu_count() or 1, 8)
    if jobs <= 1 or total < MIN_PARALLEL_COMMITS:
        chunks = [shas]
        jobs = 1
    else:
        size = max(1, min(MAX_CHUNK, -(-total // (jobs * 4))))
        chunks = [shas[i:i + size] for i in range(0, total, size)]
    work = [(root, c, cfg) for c in chunks]
    results: list[list[Finding]] = []
    done = 0
    if jobs == 1:
        mapped: Iterable[list[Finding]] = map(_scan_chunk, work)
        pool = None
    else:
        pool = ProcessPoolExecutor(max_workers=jobs)
        mapped = pool.map(_scan_chunk, work)  # yields in submission order
    try:
        for chunk, res in zip(chunks, mapped, strict=True):
            results.append(res)
            done += len(chunk)
            if progress:
                progress(done, total)
    finally:
        if pool:
            pool.shutdown()
    return _dedupe(f for r in results for f in r)


def scan_staged(root: str, cfg: Config) -> list[Finding]:
    cmd = GIT + ["diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--diff-filter=ACMR", *PATHSPEC]
    with subprocess.Popen(cmd, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        assert proc.stdout and proc.stderr
        findings = _scan_lines(_decode(proc.stdout), cfg)
        err = proc.stderr.read().decode("utf-8", "replace")
    if proc.returncode != 0:
        raise RuntimeError(err.strip() or "git diff failed")
    return findings


def _is_binary(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(4096)
    except OSError:
        return True


def scan_tree(root: str, cfg: Config) -> list[Finding]:
    """Scan current files: tracked + untracked (non-ignored) in a repo, else a plain walk."""
    pf = PathFilter(cfg.ignore_paths)
    try:
        out = subprocess.run(GIT + ["ls-files", "-co", "--exclude-standard", "-z"],
                             cwd=root, capture_output=True, check=True).stdout
        paths = [p.decode("utf-8", "replace") for p in out.split(b"\0") if p]
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
                for hit in scan_line(text.rstrip("\n"), cfg):
                    findings.append(Finding(hit.rule, hit.description, hit.secret, rel, i,
                                            entropy=hit.entropy))
    return findings
