import unittest

from helpers import ROOT  # noqa: F401  (sets sys.path)

from benchmarks import corpus
from benchmarks.evaluate import evaluate
from gitsecrets.config import load_config


class CorpusTests(unittest.TestCase):
    """Regression gate: any new false positive / miss must be added to the corpus and fixed."""

    @classmethod
    def setUpClass(cls):
        cls.res = evaluate(load_config())

    def test_no_misses(self):
        self.assertEqual(self.res["missed"], [])

    def test_no_false_positives(self):
        self.assertEqual(self.res["false_pos"], [])

    def test_corpus_has_no_credential_literals(self):
        # sanity: positives are generated, and fully distinct
        lines = [line for _, line in corpus.POSITIVES]
        self.assertEqual(len(lines), len(set(lines)))


if __name__ == "__main__":
    unittest.main()
