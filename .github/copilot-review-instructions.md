# Copilot Code Review Instructions

## Project Context

AIIR (AI Integrity Receipts) is a security-critical, zero-dependency Python
library that produces tamper-evident cryptographic receipts for git commits.
It ships as a PyPI package, npm SDK, Docker image, GitHub Action, and GitLab
CI component.

## Hard Rules — always flag as blocking

1. **No new runtime dependencies.** AIIR uses only the Python standard library.
   Any `import` of a third-party package outside `tests/`, `scripts/`, or
   `contrib/` is a release-blocker.

2. **Hash verification must be constant-time.** Any comparison of SHA-256
   digests, HMAC tags, or signature bytes must use `hmac.compare_digest()`
   or equivalent. Never use `==` for security-sensitive comparisons.

3. **No secrets in code.** Flag any hardcoded tokens, API keys, private keys,
   or credentials — even in tests. Tests must use deterministic fixtures or
   mocks, never real secrets.

4. **Pinned CI action SHAs.** All `uses:` directives in `.github/workflows/`
   must reference a full 40-character SHA, not a branch or short tag.
   Example: `uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd`

5. **SPDX headers.** Every Python source file under `aiir/` must start with
   the SPDX license header:

   ```python
   # SPDX-License-Identifier: Apache-2.0
   # Copyright 2025 Invariant Systems, Inc.
   ```

6. **Version consistency.** `aiir/__init__.py` is the single source of truth.
   Any PR that changes `__version__` must also pass `scripts/sync-version.py --check`.

## Soft Rules — flag as suggestions

1. **Coverage gaps.** If new code paths are added without corresponding tests,
   suggest adding tests. Target: 100% line coverage (`--fail-under=100`).

2. **Type annotations.** New public functions should have type annotations.
   Internal helpers are encouraged but not required.

3. **Docstrings.** Public API functions (`aiir/` module-level exports) should
   have Google-style docstrings.

4. **Commit message format.** Prefer Conventional Commits:
   `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `ci:`, `style:`.

5. **Markdown style.** Follow `.markdownlint.yaml` rules. No bare URLs,
   proper heading hierarchy, fenced code blocks with language tags.

## Architecture Awareness

- `aiir/_detect.py` — Git commit scanning and AI signal detection
- `aiir/_schema.py` — Receipt schema validation (content-addressed JSON)
- `aiir/_verify.py` — Cryptographic verification (SHA-256, Sigstore, Merkle)
- `aiir/cli.py` — CLI entry point (`aiir` command + `aiir-mcp-server`)
- `aiir/mcp.py` — Model Context Protocol server implementation
- `tests/` — Pytest suite (1682+ tests, 100% coverage)
- `.github/workflows/` — 14 CI workflows, all must pass before merge

## Security Model

AIIR is part of a software supply chain integrity tool. Reviewers should be
extra vigilant about:

- Path traversal in file operations
- Command injection in git subprocess calls
- Signature bypass in verification logic
- TOCTOU races in receipt generation
- Denial of service via crafted inputs (large files, deep nesting)
