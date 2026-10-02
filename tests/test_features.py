import json
import unittest
import urllib.error

from helpers import GH  # noqa: F401

from gitsecrets import baseline
from gitsecrets.detector import Finding
from gitsecrets.report import render_json, render_sarif, render_text
from gitsecrets.verify import verify


def finding(rule="github-token", secret="s3cr3t-value-xyz", path="a.py", line=1):
    return Finding(rule, "desc", secret, path, line, "abc123def456", "me", "2026-01-01")


class FakeResp:
    def __init__(self, status, body=""):
        self.status, self._body = status, body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body.encode()


def opener_for(status, body=""):
    seen = []

    def opener(req, timeout=None):
        seen.append(req)
        if status >= 400:
            raise urllib.error.HTTPError(req.full_url, status, "err", {}, None)  # type: ignore[arg-type]
        return FakeResp(status, body)
    opener.seen = seen  # type: ignore[attr-defined]
    return opener


class VerifyTests(unittest.TestCase):
    def test_github_live_and_revoked(self):
        o = opener_for(200)
        f = verify(finding(), o)
        self.assertTrue(f.verified)
        self.assertEqual(o.seen[0].full_url, "https://api.github.com/user")
        self.assertIs(verify(finding(), opener_for(401)).verified, False)

    def test_inconclusive_on_server_error_and_network_failure(self):
        self.assertIsNone(verify(finding(), opener_for(503)).verified)

        def boom(req, timeout=None):
            raise urllib.error.URLError("offline")
        f = verify(finding(), boom)
        self.assertIsNone(f.verified)
        self.assertIn("inconclusive", f.verify_note)

    def test_slack_and_stripe(self):
        self.assertTrue(verify(finding("slack-token"), opener_for(200, '{"ok": true}')).verified)
        self.assertIs(verify(finding("slack-token"), opener_for(200, '{"ok": false}')).verified, False)
        self.assertTrue(verify(finding("stripe-key"), opener_for(200)).verified)

    def test_unsupported_rule_never_calls_network(self):
        def fail(*a, **k):
            raise AssertionError("network call")
        f = verify(finding("aws-access-key-id"), fail)
        self.assertIsNone(f.verified)
        self.assertIn("no verifier", f.verify_note)


class BaselineTests(unittest.TestCase):
    def test_fingerprint_ignores_line_and_commit(self):
        a, b = finding(line=1), finding(line=99)
        b.commit = "other"
        self.assertEqual(a.fingerprint, b.fingerprint)
        self.assertNotEqual(a.fingerprint, finding(path="b.py").fingerprint)
        self.assertNotEqual(a.fingerprint, finding(secret="different-secret-1").fingerprint)

    def test_filter(self):
        import os
        import tempfile
        old, new = finding(), finding(path="new.py")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "b.json")
            self.assertEqual(baseline.write(p, [old]), 1)
            kept, suppressed = baseline.filter_new([old, new], baseline.load(p))
        self.assertEqual((kept, suppressed), ([new], 1))

    def test_bad_baseline(self):
        with self.assertRaises(RuntimeError):
            baseline.load("/nonexistent/baseline.json")


class ReportTests(unittest.TestCase):
    def test_text_redacts_and_shows_status(self):
        f = finding()
        f.verified, f.verify_note = True, "token is valid"
        out = render_text([f])
        self.assertNotIn(f.secret, out)
        self.assertIn("LIVE", out)
        self.assertIn("No secrets found.", render_text([]))
        self.assertIn("2 suppressed", render_text([], suppressed=2))

    def test_json_schema_version(self):
        data = json.loads(render_json([finding()]))
        self.assertEqual(data["schema_version"], 1)
        self.assertNotIn("s3cr3t", json.dumps(data))

    def test_sarif_shape(self):
        s = json.loads(render_sarif([finding(), finding(rule="jwt", path="b.py")]))
        run = s["runs"][0]
        self.assertEqual({r["id"] for r in run["tool"]["driver"]["rules"]}, {"github-token", "jwt"})
        self.assertEqual(run["results"][0]["partialFingerprints"]["gitsecrets/v1"], finding().fingerprint)


if __name__ == "__main__":
    unittest.main()
