# Architecture

`gitsecrets` scans the working tree, staged changes, or the entire git history for secrets using regex rules plus entropy, and can run as a pre-commit hook. Pure Python, no dependencies.

```mermaid
flowchart LR
    User([CLI · pre-commit hook · GitHub Action]) --> CLI["cli.py<br/>history · staged · tree · install-hook"]
    Cfg[".gitsecrets.toml · ignore file · baseline"] --> Conf[config.py / baseline.py]
    Conf --> CLI

    CLI --> GS["gitscan.py<br/>scan_history · scan_staged · scan_tree"]
    GS <-->|git log / diff / ls-files| Git[(Git repository)]
    GS -->|ProcessPool workers, -j N| Det["detectors.py<br/>scan_line"]
    Rules["rules.toml<br/>regex rule set"] --> Det
    Ent[entropy.py] --> Det
    Det --> Fnd["detector.py<br/>Finding · PathFilter"]

    Fnd -.optional --verify.-> Ver["verify.py<br/>read-only liveness checks"]
    Ver <-->|HTTPS| Prov[(Provider APIs)]
    Fnd --> Rep["report.py<br/>text · JSON · SARIF"]
    Ver --> Rep
    Rep -->|exit 0 clean · 1 findings · 2 error| CLI

    Hook[hook.py] -->|runs staged scan on commit| CLI
    Bench["benchmarks/<br/>corpus · evaluate"] -.measure precision/recall.-> Det
```
