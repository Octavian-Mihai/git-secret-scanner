import unittest

from helpers import AWS, GH, RepoCase, git

from gitsecrets.config import load_config
from gitsecrets.gitscan import parse_diff, scan_history, scan_staged, scan_tree

CFG = load_config()


class ParseDiffTests(unittest.TestCase):
    def test_added_line_that_looks_like_file_header(self):
        diff = ["diff --git a/f b/f", "--- a/f", "+++ b/f", "@@ -0,0 +1,2 @@",
                "+++ not a header", "+second"]
        self.assertEqual([(p, n, t) for _, p, n, t in parse_diff(diff)],
                         [("f", 1, "++ not a header"), ("f", 2, "second")])

    def test_quoted_and_tab_suffixed_paths(self):
        diff = ['+++ b/my file.py\t', "@@ -0,0 +1 @@", "+a",
                '+++ "b/we\\"ird.py"', "@@ -0,0 +1 @@", "+b"]
        self.assertEqual([p for _, p, _, _ in parse_diff(diff)], ["my file.py", 'we"ird.py'])


class HistoryTests(RepoCase):
    def test_finds_deleted_secret_at_introducing_commit(self):
        self.commit("cfg.py", "x = 1\n", "init")
        self.commit("cfg.py", f"KEY = '{AWS}'\n", "add key")
        introducer = git(self.d, "rev-parse", "HEAD").strip()
        self.commit("cfg.py", "KEY = None\n", "remove key")
        found = scan_history(self.d, CFG)
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].path, found[0].line, found[0].commit), ("cfg.py", 1, introducer))
        self.assertEqual(scan_tree(self.d, CFG), [])  # gone from the working tree

    def test_all_branches(self):
        self.commit("a.txt", "hi\n")
        git(self.d, "checkout", "-q", "-b", "feature")
        self.commit("b.txt", f"t={GH}\n", "feat")
        git(self.d, "checkout", "-q", "main")
        self.assertEqual(len(scan_history(self.d, CFG)), 1)
        self.assertEqual(scan_history(self.d, CFG, ["main"]), [])

    def test_rename_with_modification_is_scanned(self):
        self.commit("old.py", "a=1\n" * 10, "init")
        git(self.d, "mv", "old.py", "new.py")
        self.write("new.py", "a=1\n" * 10 + f"k='{AWS}'\n")
        git(self.d, "add", "-A")
        git(self.d, "commit", "-q", "-m", "rename+edit")
        found = scan_history(self.d, CFG)
        self.assertEqual([f.path for f in found], ["new.py"])

    def test_filenames_with_spaces(self):
        self.commit("my dir/my file.py", f"k='{AWS}'\n")
        self.assertEqual(scan_history(self.d, CFG)[0].path, "my dir/my file.py")
        self.assertEqual(scan_tree(self.d, CFG)[0].path, "my dir/my file.py")

    def test_merge_commits_do_not_duplicate(self):
        self.commit("a.txt", "x\n")
        git(self.d, "checkout", "-q", "-b", "f")
        self.commit("s.py", f"k='{AWS}'\n", "secret")
        git(self.d, "checkout", "-q", "main")
        self.commit("m.txt", "m\n")
        git(self.d, "merge", "-q", "--no-ff", "f", "-m", "merge")
        self.assertEqual(len(scan_history(self.d, CFG)), 1)

    def test_vendored_dirs_skipped_in_history_and_staged(self):
        for path in ["node_modules/pkg/i.js", "web/node_modules/x.js", "vendor/v.go", "src/app.py"]:
            self.write(path, f"k='{AWS}'\n")
        git(self.d, "add", "-A")
        self.assertEqual([f.path for f in scan_staged(self.d, CFG)], ["src/app.py"])
        git(self.d, "commit", "-q", "-m", "all")
        self.assertEqual([f.path for f in scan_history(self.d, CFG)], ["src/app.py"])

    def test_empty_repo(self):
        self.assertEqual(scan_history(self.d, CFG), [])

    def test_parallel_matches_serial(self):
        for i in range(120):
            self.write(f"f{i}.txt", f"line {i}\n" + (f"k='{AWS}'\n" if i == 77 else ""))
        git(self.d, "add", "-A")
        git(self.d, "commit", "-q", "-m", "bulk")
        for i in range(120):  # many small commits => parallel path (>=100 commits)
            self.commit("counter.txt", f"{i}\n", f"c{i}")
        serial = scan_history(self.d, CFG, jobs=1)
        parallel = scan_history(self.d, CFG, jobs=4)
        self.assertEqual([(f.path, f.line, f.commit) for f in serial],
                         [(f.path, f.line, f.commit) for f in parallel])
        self.assertEqual(len(serial), 1)

    def test_progress_callback(self):
        self.commit("a.txt", "x\n")
        calls = []
        scan_history(self.d, CFG, progress=lambda d, t: calls.append((d, t)))
        self.assertEqual(calls[-1], (1, 1))


class StagedTests(RepoCase):
    def test_staged_only(self):
        self.commit("a.txt", f"k={AWS}\n", "old")  # committed already, not staged
        self.write("b.txt", f"tok={GH}\n")
        git(self.d, "add", "b.txt")
        found = scan_staged(self.d, CFG)
        self.assertEqual([f.path for f in found], ["b.txt"])


if __name__ == "__main__":
    unittest.main()
