import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Fake credentials are assembled at runtime so this repo has no credential-shaped literals.
AWS = "AKIA" + "IOSFODNN7EXAMPL" + "Q"
GH = "ghp_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"  # gitsecrets:ignore
RANDOM = "q8Zr3Kx9Lm2Vb7Nc5Tw1Yh4Gd6Fs0Ap"  # gitsecrets:ignore


def git(cwd, *args, env=None):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                          text=True, env=env).stdout


class RepoCase(unittest.TestCase):
    """A throwaway git repo in self.d."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.d = os.path.realpath(self._tmp.name)
        git(self.d, "init", "-q", "-b", "main")
        git(self.d, "config", "user.email", "t@t.t")
        git(self.d, "config", "user.name", "tester")

    def write(self, name, content):
        full = os.path.join(self.d, name)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(content)

    def commit(self, name, content, msg="c"):
        self.write(name, content)
        git(self.d, "add", "-A")
        git(self.d, "commit", "-q", "-m", msg)

    def env(self):
        return {**os.environ, "PYTHONPATH": ROOT}
