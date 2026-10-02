import json
import os
import subprocess
import sys
import unittest

from helpers import AWS, GH, ROOT, RepoCase, git


class CliTests(RepoCase):
    def run_cli(self, *args, check_exit=None, cwd=None):
        r = subprocess.run([sys.executable, "-m", "gitsecrets", *args], cwd=cwd or self.d,
                           capture_output=True, text=True, env=self.env())
        if check_exit is not None:
            self.assertEqual(r.returncode, check_exit, r.stdout + r.stderr)
        return r

    def test_exit_codes(self):
        self.commit("a.txt", "clean\n")
        self.run_cli("history", check_exit=0)
        self.commit("b.txt", f"k={AWS}\n")
        self.run_cli("history", check_exit=1)
        self.run_cli("history", "--exit-zero", check_exit=0)
        self.run_cli("-C", "/nonexistent-dir-xyz", "history", check_exit=2)

    def test_options_work_before_and_after_subcommand(self):
        self.commit("b.txt", f"k={AWS}\n")
        a = json.loads(self.run_cli("--json", "history").stdout)
        b = json.loads(self.run_cli("history", "--json").stdout)
        c = json.loads(self.run_cli("-C", self.d, "history", "--json", cwd=ROOT).stdout)
        self.assertEqual(a, b)
        self.assertEqual(a["findings"], c["findings"])

    def test_json_schema_and_redaction(self):
        self.commit("b.txt", f"k={AWS}\n")
        out = self.run_cli("history", "--json").stdout
        self.assertNotIn(AWS, out)
        f = json.loads(out)["findings"][0]
        for key in ("rule", "path", "line", "commit", "secret", "fingerprint", "verified"):
            self.assertIn(key, f)
        shown = json.loads(self.run_cli("history", "--json", "--show-secrets").stdout)
        self.assertEqual(shown["findings"][0]["secret"], AWS)

    def test_sarif_has_no_secret(self):
        self.commit("b.txt", f"k={AWS}\n")
        out = self.run_cli("history", "--format", "sarif", "--show-secrets").stdout
        self.assertNotIn(AWS, out)
        sarif = json.loads(out)
        self.assertEqual(sarif["version"], "2.1.0")
        res = sarif["runs"][0]["results"][0]
        self.assertEqual(res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "b.txt")

    def test_output_file(self):
        self.commit("b.txt", f"k={AWS}\n")
        out = os.path.join(self.d, "report.sarif")
        self.run_cli("history", "--format", "sarif", "-o", out, "--exit-zero", check_exit=0)
        with open(out) as fh:
            self.assertEqual(json.load(fh)["version"], "2.1.0")

    def test_baseline_roundtrip(self):
        self.commit("b.txt", f"k={AWS}\n")
        self.run_cli("baseline", check_exit=0)
        r = self.run_cli("history", check_exit=0)
        self.assertIn("suppressed by baseline", r.stdout)
        self.commit("c.txt", f"t={GH}\n")  # a new secret still gets reported
        r = self.run_cli("history", "--json", check_exit=1)
        data = json.loads(r.stdout)
        self.assertEqual([f["path"] for f in data["findings"]], ["c.txt"])
        self.assertEqual(data["suppressed_by_baseline"], 1)
        self.run_cli("history", "--no-baseline", check_exit=1)

    def test_baseline_survives_line_moves(self):
        self.commit("b.txt", f"k={AWS}\n")
        self.run_cli("baseline", "--source", "tree", check_exit=0)
        self.commit("b.txt", f"# comment\n\nk={AWS}\n")
        self.run_cli("tree", check_exit=0)

    def test_config_file(self):
        self.write(".gitsecrets.toml", '''
disable_rules = ["aws-access-key-id"]
[[rules]]
id = "acme"
description = "Acme token"
regex = 'ACME-[0-9]{6}'
keywords = ["acme-"]
[allowlist]
paths = ["fixtures/*"]
''')
        self.commit("b.txt", f"k={AWS}\nx=ACME-123456\n")
        self.commit("fixtures/y.txt", "x=ACME-654321\n")
        data = json.loads(self.run_cli("tree", "--json").stdout)
        self.assertEqual([(f["rule"], f["path"]) for f in data["findings"]], [("acme", "b.txt")])

    def test_bad_config_is_exit_2(self):
        self.write(".gitsecrets.toml", "bogus = 1\n")
        self.commit("a.txt", "x\n")
        r = self.run_cli("tree", check_exit=2)
        self.assertIn("unknown key", r.stderr)
        self.write(".gitsecrets.toml", '[[rules]]\nid="x"\ndescription="d"\nregex="("\n')
        self.assertIn("invalid regex", self.run_cli("tree", check_exit=2).stderr)

    def test_hook_blocks_commit_and_uninstalls(self):
        self.commit("a.txt", "hello\n")
        self.run_cli("install-hook", check_exit=0)
        self.write("b.txt", f"tok={GH}\n")
        git(self.d, "add", "b.txt")
        r = subprocess.run(["git", "commit", "-m", "leak"], cwd=self.d, capture_output=True,
                           text=True, env=self.env())
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ghp_", r.stdout + r.stderr)
        git(self.d, "commit", "-q", "--no-verify", "-m", "bypass")
        self.run_cli("uninstall-hook", check_exit=0)
        self.assertFalse(os.path.exists(os.path.join(self.d, ".git/hooks/pre-commit")))

    def test_hook_will_not_clobber_foreign_hook(self):
        hook = os.path.join(self.d, ".git/hooks/pre-commit")
        os.makedirs(os.path.dirname(hook), exist_ok=True)
        with open(hook, "w") as f:
            f.write("#!/bin/sh\necho mine\n")
        self.run_cli("install-hook", check_exit=2)
        self.run_cli("uninstall-hook", check_exit=2)
        self.run_cli("install-hook", "--force", check_exit=0)

    def test_tree_outside_git_repo(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "x.env"), "w") as f:
                f.write(f"k={AWS}\n")
            self.assertEqual(self.run_cli("tree", cwd=d).returncode, 1)


if __name__ == "__main__":
    unittest.main()
