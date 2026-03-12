# Contributing to AIIR

Thank you for your interest in AIIR! We welcome contributions from the community.

## Quick start

```bash
git clone https://github.com/invariant-systems-ai/aiir.git
cd aiir
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"    # installs pytest + hypothesis
pre-commit install && pre-commit install --hook-type post-commit --hook-type pre-push
python -m pytest tests/ -q  # 1893 tests, ~4 min
```

> **Note**: `pip install -e ".[dev]"` installs `hypothesis` (property-based fuzz
> testing) and `pytest`. The pre-commit hooks enforce secret scanning, linting,
> and a local CI preflight on every push. If you install only `pytest`, fuzz
> tests in `tests/test_fuzz.py` will be skipped gracefully — all other tests
> pass without `hypothesis`. CI always installs both.

## Ways to contribute

- **Bug reports** — [open an issue](https://github.com/invariant-systems-ai/aiir/issues/new?template=bug_report.yml)
- **Feature requests** — [start a discussion](https://github.com/invariant-systems-ai/aiir/issues/new?template=feature_request.yml)
- **Security vulnerabilities** — see [SECURITY.md](SECURITY.md) (do **not** open a public issue)
- **Code contributions** — fork, branch, PR (see below)

## Pull request process

1. Fork the repo and create a feature branch from `main`
2. Write tests for any new functionality
3. Run the local preflight: `scripts/ci-local.sh required`
4. (Optional) Run the full suite: `scripts/ci-local.sh full`
5. **Sign off every commit** (see DCO below): `git commit -s`
6. Open a PR with a clear description of the change

### CI gates (all must pass before merge)

PRs to `main` require **all three** status checks to pass:

| Gate | Workflow | What it checks |
|---|---|---|
| `ci-ok` | Tests | Full test matrix (Python 3.9–3.13), 100% coverage |
| `quality-ok` | Quality | Type checking, markdown lint, hadolint, YAML, SPDX, spelling |
| `security-ok` | Security | Gitleaks, Bandit, Semgrep, ruff, pip-audit, license check |

Plus: **1 approving review** from a CODEOWNER, all review threads resolved,
and the last push must be approved (prevents sneaking in changes after approval).

> **Copilot code review** is enabled — it will automatically review your PR
> against our [review instructions](.github/copilot-review-instructions.md).
> Human review is still required.

### Dependabot PRs

Minor/patch dependency updates are auto-approved and auto-merged after CI
passes. Major version bumps require human review.

### Release process

Only repository admins can create releases:

1. All CI must be GREEN on `main`
2. Bump version in `aiir/__init__.py` (single source of truth)
3. Run `python scripts/sync-version.py --fix` to propagate
4. Commit, tag `vX.Y.Z`, push — the Publish workflow handles the rest
5. PyPI and npm only publish **after** CI + verification pass

### Local preflight

Run `scripts/ci-local.sh` before pushing to catch CI failures locally:

| Profile | Command | What it runs |
|---------|---------|-------------|
| `required` | `scripts/ci-local.sh required` | pytest, fuzz, 100% coverage, version sync, package smoke |
| `full` | `scripts/ci-local.sh full` | All of `required` + mypy, ruff, bandit, semgrep, pip-audit, licenses, SPDX |
| `mutation` | `scripts/ci-local.sh mutation` | Mutation testing gate (mutmut) |
| `all` | `scripts/ci-local.sh all` | All of the above |

### Developer Certificate of Origin (DCO)

All contributions must include a `Signed-off-by` line certifying the
[Developer Certificate of Origin v1.1](https://developercertificate.org/):

```text
Signed-off-by: Your Name <your@email.com>
```

Add it automatically with `git commit -s`. This certifies that you have
the right to submit the contribution under the project's Apache-2.0
license, and that Invariant Systems, Inc. may continue to distribute it
(including under additional license terms for enterprise offerings).

PRs with unsigned commits will not be merged.

### Commit messages

Use clear, descriptive commit messages. Examples:

- `fix: handle empty commit range gracefully`
- `feat: add --format csv output option`
- `test: add fuzz coverage for unicode filenames`

## Code standards

- **Zero runtime dependencies.** This is a hard rule. AIIR ships with nothing but the Python standard library.
- **Test everything.** We maintain 1,893 tests across unit, integration, security, and fuzz suites. 100% coverage enforced.
- **Security-first.** All inputs are validated. All outputs are deterministic. See the [Threat Model](THREAT_MODEL.md).

## Development setup

AIIR requires Python 3.9+. Dev dependencies:

```bash
pip install -e ".[dev]"  # installs pytest, etc.
```

## Trademarks

"AIIR", "AI Integrity Receipts", and "Invariant Systems" are trademarks
of Invariant Systems, Inc. See [TRADEMARK.md](TRADEMARK.md) for usage
guidelines.

## License

By contributing, you agree that your contributions will be licensed under
the [Apache License 2.0](LICENSE), and you certify your contribution
under the [Developer Certificate of Origin v1.1](https://developercertificate.org/).
