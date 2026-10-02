"""Measure precision/recall on the labelled corpus and sweep the entropy threshold.

    python -m benchmarks.evaluate            # human-readable
    python -m benchmarks.evaluate --markdown # tables for the README
"""
from __future__ import annotations

import argparse
import random
import string
from collections import defaultdict

from gitsecrets.config import Config, load_config
from gitsecrets.detectors import scan_line

from . import corpus


def evaluate(cfg: Config) -> dict:
    per_rule: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # rule -> [detected, total]
    missed, false_pos = [], []
    for rule, line in corpus.POSITIVES:
        hit_rules = {h.rule for h in scan_line(line, cfg)}
        per_rule[rule][1] += 1
        if rule in hit_rules:
            per_rule[rule][0] += 1
        else:
            missed.append((rule, line, sorted(hit_rules)))
    for category, line in corpus.NEGATIVES:
        hits = scan_line(line, cfg)
        if hits:
            false_pos.append((category, line, [h.rule for h in hits]))
    tp = sum(d for d, _ in per_rule.values())
    fn = len(corpus.POSITIVES) - tp
    fp = len(false_pos)
    tn = len(corpus.NEGATIVES) - fp
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else 1.0,
            "recall": tp / (tp + fn) if tp + fn else 1.0,
            "per_rule": dict(per_rule), "missed": missed, "false_pos": false_pos}


# --- synthetic sweep: random secrets vs. identifier-like text -------------------------------

_WORDS = ("get user auth handler factory create session token refresh manager service client "
          "config load default provider request response parse build render update delete list "
          "find merge split format validate normalize connection pool cache store queue worker").split()


def _synthetic(n: int = 500, seed: int = 7) -> tuple[list[str], list[str]]:
    r = random.Random(seed)
    alphabet = string.ascii_letters + string.digits
    pos = [f'x = "{"".join(r.choice(alphabet) for _ in range(r.randint(24, 48)))}"' for _ in range(n)]
    neg = []
    for _ in range(n):
        words = [r.choice(_WORDS) for _ in range(r.randint(3, 6))]
        style = r.choice(["camel", "snake", "kebab", "path"])
        if style == "camel":
            tok = words[0] + "".join(w.title() for w in words[1:])
        elif style == "snake":
            tok = "_".join(words) + str(r.randint(0, 99))
        elif style == "kebab":
            tok = "-".join(words) + "-v" + str(r.randint(1, 9))
        else:
            tok = "/".join(words[:2]) + "/" + words[2].title() + str(r.randint(0, 9))
        neg.append(f'x = "{tok}"')
    return pos, neg


def sweep(thresholds: list[float]) -> list[tuple[float, float, float]]:
    pos, neg = _synthetic()
    rows = []
    for t in thresholds:
        cfg = load_config()
        cfg.b64_threshold = t
        tp = sum(1 for line in pos if scan_line(line, cfg))
        fp = sum(1 for line in neg if scan_line(line, cfg))
        rows.append((t, tp / len(pos), tp / (tp + fp) if tp + fp else 1.0))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--markdown", action="store_true")
    args = ap.parse_args()
    res = evaluate(load_config())
    print(f"Corpus: {len(corpus.POSITIVES)} positives, {len(corpus.NEGATIVES)} negatives")
    print(f"precision {res['precision']:.1%}   recall {res['recall']:.1%}   "
          f"(TP {res['tp']}  FP {res['fp']}  FN {res['fn']}  TN {res['tn']})\n")
    for rule, line, got in res["missed"]:
        print(f"MISSED   [{rule}] {line[:90]}  -> got {got}")
    for cat, line, got in res["false_pos"]:
        print(f"FALSEPOS ({cat}) {line[:90]}  -> {got}")
    print("\nEntropy threshold sweep (synthetic: random 24-48 char strings vs identifier-like strings)")
    rows = sweep([3.5, 3.8, 4.0, 4.2, 4.3, 4.5, 4.8])
    if args.markdown:
        print("\n| b64 threshold | recall | precision |\n|---|---|---|")
        for t, rec, prec in rows:
            print(f"| {t} | {rec:.1%} | {prec:.1%} |")
        print("\n| rule | detected |\n|---|---|")
        for rule, (d, tot) in sorted(res["per_rule"].items()):
            print(f"| {rule} | {d}/{tot} |")
    else:
        for t, rec, prec in rows:
            print(f"  threshold {t}: recall {rec:.1%}  precision {prec:.1%}")


if __name__ == "__main__":
    main()
