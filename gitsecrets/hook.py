"""Install/uninstall the pre-commit hook."""
from __future__ import annotations

import os
import stat
import subprocess
import sys

MARKER = "# gitsecrets-hook"


def _hooks_dir(root: str) -> str:
    out = subprocess.run(["git", "rev-parse", "--git-path", "hooks"], cwd=root,
                         capture_output=True, text=True, check=True).stdout.strip()
    return out if os.path.isabs(out) else os.path.join(root, out)


def _script() -> str:
    return f"""#!/bin/sh
{MARKER}
# Blocks the commit if staged changes contain secrets. Bypass: git commit --no-verify
if command -v gitsecrets >/dev/null 2>&1; then
    exec gitsecrets staged
fi
exec "{sys.executable}" -m gitsecrets staged
"""


def install(root: str, force: bool = False) -> str:
    hooks = _hooks_dir(root)
    os.makedirs(hooks, exist_ok=True)
    path = os.path.join(hooks, "pre-commit")
    if os.path.exists(path):
        with open(path) as f:
            ours = MARKER in f.read()
        if not ours and not force:
            raise FileExistsError(f"{path} exists and was not created by gitsecrets (use --force)")
    with open(path, "w") as f:
        f.write(_script())
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def uninstall(root: str) -> bool:
    path = os.path.join(_hooks_dir(root), "pre-commit")
    if os.path.exists(path):
        with open(path) as f:
            if MARKER not in f.read():
                raise FileExistsError(f"{path} was not created by gitsecrets; leaving it alone")
        os.remove(path)
        return True
    return False
