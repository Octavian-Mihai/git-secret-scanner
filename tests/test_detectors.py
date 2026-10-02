import base64
import unittest

from helpers import AWS, GH, RANDOM  # noqa: F401  (also sets sys.path)

from gitsecrets.config import load_config
from gitsecrets.detector import PathFilter
from gitsecrets.detectors import detect_assignment, detect_base64, detect_entropy, detect_regex, scan_line
from gitsecrets.entropy import shannon

CFG = load_config()


class DetectorTests(unittest.TestCase):
    def test_regex_rules(self):
        self.assertEqual(scan_line(f"key = {AWS}", CFG)[0].rule, "aws-access-key-id")
        self.assertEqual(scan_line(f"t: {GH}", CFG)[0].rule, "github-token")

    def test_anthropic_wins_over_openai(self):
        line = "k = sk-ant-api03-" + RANDOM + RANDOM
        self.assertEqual([h.rule for h in scan_line(line, CFG)], ["anthropic-key"])

    def test_each_detector_in_isolation(self):
        self.assertTrue(list(detect_regex(AWS, CFG)))
        self.assertFalse(list(detect_regex(RANDOM, CFG)))
        self.assertTrue(list(detect_assignment(f'api_secret = "{RANDOM}"', CFG)))
        self.assertTrue(list(detect_entropy(f'x = "{RANDOM}"', CFG)))
        self.assertFalse(list(detect_assignment(f'x = "{RANDOM}"', CFG)))

    def test_base64_decoding(self):
        enc = base64.b64encode(f"token={GH}".encode()).decode()
        hits = list(detect_base64(f"blob: {enc}", CFG))
        self.assertEqual(hits[0].rule, "github-token+base64")
        self.assertEqual(hits[0].secret, GH)

    def test_base64_non_text_ignored(self):
        enc = base64.b64encode(bytes(range(200, 256)) * 2).decode()
        self.assertEqual(list(detect_base64(enc, CFG)), [])

    def test_long_lines_still_get_regex_rules(self):
        line = "x" * 5000 + " " + AWS
        self.assertEqual(scan_line(line, CFG)[0].rule, "aws-access-key-id")
        self.assertEqual(scan_line("a" * 3000 + " " + RANDOM, CFG), [])  # entropy skipped

    def test_hex_needs_context(self):
        sha = "d41d8cd98f00b204e9800998ecf8427e" * 2
        self.assertEqual(scan_line(f"git checkout {sha}", CFG), [])
        self.assertTrue(scan_line(f"api_key = {sha}", CFG))

    def test_ignore_marker_and_placeholders(self):
        self.assertEqual(scan_line(f"{AWS}  # gitsecrets:ignore", CFG), [])
        self.assertEqual(scan_line("password = 'changeme123'", CFG), [])
        self.assertEqual(scan_line("token = os.environ['TOKEN']", CFG), [])

    def test_keyword_prefilter_does_not_change_results(self):
        no_kw = load_config()
        no_kw.rules = [type(r)(r.id, r.description, r.regex, r.group, (), r.min_entropy, r.allowlist)
                       for r in no_kw.rules]
        for line in [f"a {AWS}", f"b {GH}", f"c = '{RANDOM}'", "nothing here"]:
            self.assertEqual(scan_line(line, CFG), scan_line(line, no_kw), line)

    def test_global_allowlist(self):
        import re
        cfg = load_config()
        cfg.allow_regexes = [re.compile("^AKIA")]
        self.assertEqual(scan_line(f"k = {AWS}", cfg), [])

    def test_thresholds_respected(self):
        cfg = load_config()
        cfg.b64_threshold = 9.0
        self.assertEqual(list(detect_entropy(f'x = "{RANDOM}"', cfg)), [])

    def test_path_filter(self):
        pf = PathFilter()
        for p in ["node_modules/a/b.js", "web/node_modules/x.js", ".package-lock.json", "vendor/x.go"]:
            self.assertTrue(pf.skip(p), p)
        self.assertFalse(pf.skip("src/app.js"))
        self.assertTrue(PathFilter(["docs/*"]).skip("docs/a.md"))

    def test_entropy_ordering(self):
        self.assertGreater(shannon(RANDOM), shannon("aaaaaaaabbbbbbbb"))


if __name__ == "__main__":
    unittest.main()
