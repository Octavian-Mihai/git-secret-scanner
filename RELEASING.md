# Releasing to PyPI

Publishing uses PyPI **trusted publishing** (OIDC): no API token is stored in GitHub.

## One-time setup

1. Create a PyPI account (with 2FA) at https://pypi.org/account/register/.
2. Go to https://pypi.org/manage/account/publishing/ and **add a pending publisher**:
   - PyPI project name: `gitsecrets`
   - Owner: `Octavian-Mihai`
   - Repository name: `git-secret-scanner`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
3. In GitHub: repo **Settings → Environments → New environment** named `pypi`
   (optionally add yourself as a required reviewer so each publish needs your approval).

## Each release

1. Bump `__version__` in `gitsecrets/__init__.py` and add a `CHANGELOG.md` entry.
2. Commit, then `git tag -a vX.Y.Z -m vX.Y.Z && git push --follow-tags`.
3. On GitHub: **Releases → Draft a new release**, pick the tag, **Publish release**.
   The *Release* workflow builds the sdist/wheel and uploads them. (Or run it from the Actions tab.)
4. Check https://pypi.org/project/gitsecrets/ and try `pipx install gitsecrets`.

PyPI versions are immutable: a published version can't be re-uploaded, only yanked.

## Local sanity check before tagging

```bash
python3 -m pip install build twine
python3 -m build && python3 -m twine check dist/*
```
