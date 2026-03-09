# Contributing to AIIR

Thank you for your interest in AIIR! We welcome contributions from the community.

## Quick start

```bash
git clone https://github.com/invariant-systems-ai/aiir.git
cd aiir
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"    # installs pytest + hypothesis
python -m pytest tests/ -q  # 710+ tests, ~2 min
```

> **Note**: `pip install -e ".[dev]"` installs `hypothesis` (property-based fuzz
> testing) and `pytest`. If you install only `pytest`, fuzz tests in
> `tests/test_fuzz.py` will be skipped gracefully — all other tests pass
> without `hypothesis`. CI always installs both.

## Ways to contribute

- **Bug reports** — [open an issue](https://github.com/invariant-systems-ai/aiir/issues/new?template=bug_report.yml)
- **Feature requests** — [start a discussion](https://github.com/invariant-systems-ai/aiir/issues/new?template=feature_request.yml)
- **Security vulnerabilities** — see [SECURITY.md](SECURITY.md) (do **not** open a public issue)
- **Code contributions** — fork, branch, PR (see below)

## Pull request process

1. Fork the repo and create a feature branch from `main`
2. Write tests for any new functionality
3. Run the full test suite: `python -m pytest tests/ -q`
4. Ensure zero lint errors and all tests pass
5. **Sign off every commit** (see DCO below)
6. Open a PR with a clear description of the change

### Developer Certificate of Origin (DCO)

All contributions must include a `Signed-off-by` line certifying the
[Developer Certificate of Origin v1.1](https://developercertificate.org/):

```
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
- **Test everything.** We maintain 710+ tests across unit, integration, security, and fuzz suites.
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
