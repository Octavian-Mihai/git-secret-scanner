"""Run the real demo in a temp repo and render its output as an animated terminal SVG.

    python scripts/make_demo_svg.py        # writes docs/demo.svg
The fake key is built at runtime and elided in the displayed command.
"""
import html
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAKE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def run(cwd, cmd, env):
    r = subprocess.run(cmd + " 2>&1", shell=True, cwd=cwd, capture_output=True, text=True, env=env)
    return r.stdout.rstrip("\n").splitlines()


def classify(out):
    if out.startswith("["):
        return "rule"
    if "potential" in out or "blocked" in out:
        return "warn"
    return "dim" if out.startswith("  ") else "out"


def main():
    env = {**os.environ, "PYTHONPATH": ROOT, "NO_COLOR": "1"}
    gs = f"{sys.executable} -m gitsecrets"
    # (shown command, real command, show its output?)
    steps = [
        ("gitsecrets install-hook", f"{gs} install-hook | sed 's#Installed .*/.git#Installed .git#'", True),
        ("echo 'AWS_KEY = \"AKIA...\"' > cfg.py     # a fake AWS example key",
         f"printf 'AWS_KEY = \"{FAKE_KEY}\"\n' > cfg.py", False),
        ("git add cfg.py && git commit -m 'add config'", "git add cfg.py && git commit -m 'add config'", True),
        ("git commit --no-verify -m 'add config'     # bypass the hook",
         "git commit -q --no-verify -m 'add config'", False),
        ("git commit -am 'remove key'                # key deleted from the code",
         "echo 'AWS_KEY = None' > cfg.py && git commit -qam 'remove key'", False),
        ("gitsecrets tree                            # current files: clean", f"{gs} tree", True),
        ("gitsecrets history                         # ...but still in git history", f"{gs} history", True),
    ]
    lines = []  # (text, css class)
    with tempfile.TemporaryDirectory() as d:
        run(d, "git init -q -b main && git config user.email d@d.d && git config user.name demo", env)
        for shown, real, show in steps:
            out = run(d, real, env)
            lines.append((f"$ {shown}", "cmd"))
            if show:
                lines += [(o, classify(o)) for o in out]

    lh, pad = 20, 16
    w = int(max(len(t) for t, _ in lines) * 8.5) + 2 * pad
    h = len(lines) * lh + 2 * pad + 28
    colors = {"cmd": "#e6edf3", "out": "#8b949e", "rule": "#ff7b72", "warn": "#d29922", "dim": "#8b949e"}
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
             f'aria-label="gitsecrets terminal demo">',
             "<style>text{font:14px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre}"
             "g.l{animation:s .01s backwards}@keyframes s{from{opacity:0}}</style>",
             f'<rect width="{w}" height="{h}" rx="10" fill="#0d1117"/>',
             '<circle cx="20" cy="18" r="6" fill="#ff5f56"/><circle cx="40" cy="18" r="6" fill="#ffbd2e"/>'
             '<circle cx="60" cy="18" r="6" fill="#27c93f"/>']
    t = 0.4
    for i, (text, kind) in enumerate(lines):
        y = 28 + pad + (i + 1) * lh - 6
        parts.append(f'<g class="l" style="animation-delay:{t:.2f}s"><text x="{pad}" y="{y}" fill="{colors[kind]}">'
                     f"{html.escape(text)}</text></g>")
        t += 0.9 if kind == "cmd" else 0.12
    parts.append("</svg>")
    out = os.path.join(ROOT, "docs", "demo.svg")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(parts) + "\n")
    print(f"wrote {out} ({len(lines)} lines)")
    print("\n".join(t for t, _ in lines))


if __name__ == "__main__":
    main()
