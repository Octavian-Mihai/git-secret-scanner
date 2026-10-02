import os
import subprocess
import tempfile
import unittest

from gitsecrets import hook
from gitsecrets.detector import PathFilter, scan_line
from gitsecrets.entropy import shannon
from gitsecrets.gitscan import scan_history, scan_staged

# Fake credentials are assembled at runtime so this file itself doesn't trip scanners.
AWS = "AKIA" + "IOSFODNN7EXAMPLQ"
GH = "ghp_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"
RANDOM = "q8Zr3Kx9Lm2Vb7Nc5Tw1Yh4Gd6Fs0Ap"


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


class DetectorTests(unittest.TestCase):
    def test_regex_rules(self):
        self.assertEqual(scan_line(f"key = {AWS}")[0][0], "aws-access-key-id")
        self.assertEqual(scan_line(f"t: {GH}")[0][0], "github-token")

    def test_entropy_assignment(self):
        rules = [h[0] for h in scan_line(f'api_secret = "{RANDOM}"')]
        self.assertIn("generic-secret-assignment", rules)

    def test_no_false_positives(self):
        for line in ["password = 'changeme123'", "token = os.environ['TOKEN']",
                     "def get_user_authentication_handler(self):",
                     "sha = 'd41d8cd98f00b204e9800998ecf8427e'"[:10]]:
            self.assertEqual(scan_line(line), [], line)

    def test_ignore_marker(self):
        self.assertEqual(scan_line(f"{AWS}  # gitsecrets:ignore"), [])

    def test_entropy_ordering(self):
        self.assertGreater(shannon(RANDOM), shannon("aaaaaaaabbbbbbbb"))


class GitTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        git(self.d, "init", "-q")
        git(self.d, "config", "user.email", "t@t.t")
        git(self.d, "config", "user.name", "tester")
        self.pf = PathFilter()

    def commit(self, name, content, msg):
        with open(os.path.join(self.d, name), "w") as f:
            f.write(content)
        git(self.d, "add", name)
        git(self.d, "commit", "-q", "-m", msg)

    def test_history_finds_deleted_secret(self):
        self.commit("cfg.py", f"KEY = '{AWS}'\n", "add key")
        self.commit("cfg.py", "KEY = None\n", "remove key")
        self.assertEqual(scan_history(self.d, self.pf), scan_history(self.d, self.pf))
        found = scan_history(self.d, self.pf)
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].path, found[0].line), ("cfg.py", 1))
        self.assertTrue(found[0].commit)

    def test_staged_and_hook(self):
        self.commit("a.txt", "hello\n", "init")
        with open(os.path.join(self.d, "b.txt"), "w") as f:
            f.write(f"tok={GH}\n")
        git(self.d, "add", "b.txt")
        self.assertEqual(len(scan_staged(self.d, self.pf)), 1)
        hook.install(self.d)
        r = subprocess.run(["git", "commit", "-m", "leak"], cwd=self.d,
                           capture_output=True, text=True,
                           env={**os.environ, "PYTHONPATH": os.getcwd()})
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue(hook.uninstall(self.d))


if __name__ == "__main__":
    unittest.main()
