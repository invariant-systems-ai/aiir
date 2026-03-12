# AIIR — Agent Instructions

> **Read this before writing code.** It applies to every AI coding agent
> (Copilot, Claude, Cursor, Cline, Windsurf, etc.) working in this repo.

**Version**: 1.0.0
**Repo**: `invariant-systems-ai/aiir` (public, T0)
**License**: Apache-2.0

---

## §1 — What This Repo Is

AIIR is a **public, security-critical** Python library and CLI that produces
content-addressed receipts for git commits with declared AI involvement.

It ships as a PyPI package, GitHub Action, GitLab CI/CD Catalog component,
Docker image, and MCP server. Zero runtime dependencies — stdlib only.

**This is a T0 (public) repository.** Every committed byte is visible to the
world. Never introduce internal project names, core IP terminology, private
URLs, real credentials, or references to private infrastructure.

---

## §2 — Preflight Protocol (Non-Negotiable)

Before pushing any branch, you MUST run the local CI preflight:

```bash
scripts/ci-local.sh required
```

This runs: pytest (full suite), Hypothesis fuzzing, 100% coverage gate,
version-sync check, and package smoke test. The pre-push git hook enforces
this automatically — do not bypass it with `--no-verify`.

For a more thorough check (recommended before opening a PR):

```bash
scripts/ci-local.sh full     # adds mypy, ruff, bandit, semgrep, pip-audit
scripts/ci-local.sh all      # adds mutation testing
```

### Hook installation

```bash
pre-commit install && pre-commit install --hook-type post-commit --hook-type pre-push
```

---

## §3 — Branch and PR Protocol

1. **Never push directly to `main`.** Always create a feature branch.
2. **Branch naming**: `feat/<slug>`, `fix/<slug>`, `docs/<slug>`, `chore/<slug>`.
3. **Conventional commits**: `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`.
4. **DCO sign-off required on every commit**: use `git commit -s`.
5. **Open a PR** targeting `main` with a clear description.
6. **Wait for all four CI gates** before requesting review:
   - `ci-ok` — test matrix (Python 3.9–3.13, Linux/Win/macOS), 100% coverage
   - `quality-ok` — mypy, markdownlint, link-check, spelling, hadolint, yamllint, SPDX
   - `security-ok` — gitleaks, bandit, semgrep, ruff, pip-audit, license-check
   - `ai-gate` — Copilot review + all three gates above
7. **Do not merge without human approval.** Auto-merge is only enabled after
   Copilot review + CI pass + human CODEOWNER approval.

---

## §4 — Copilot Review Response Protocol

Copilot automatically reviews every PR against
[`.github/copilot-review-instructions.md`](.github/copilot-review-instructions.md).

### Hard rules (blocking — must fix before merge)

1. No new runtime dependencies (stdlib-only)
2. Hash comparisons must use `hmac.compare_digest()` (constant-time)
3. No hardcoded secrets, even in tests
4. All `uses:` in workflows must reference full 40-char SHA pins
5. Every `.py` file under `aiir/` needs SPDX header
6. Version changes must pass `scripts/sync-version.py --check`

### When Copilot review comments arrive

- Read every comment, including the inline ones.
- **Hard-rule violations**: fix them immediately; push a new commit.
- **Soft-rule suggestions**: evaluate; apply if they improve the code,
  otherwise explain why in a reply and resolve the thread.
- Do **not** bulk-resolve threads without addressing them.
- After fixing, re-check that the `ai-gate` status updates to `success`.

---

## §5 — Content Rules (T0 Public Repo)

The following must **never** appear in any committed file, commit message,
or git blob:

- Internal project names (`invariant-systems-workspace`, `kaleidos-core`)
- Core IP terms (`MetaID256`, `hv15`, `Codon64`, `trace-map algebra`, `kgraph.jsonl`)
- Hub URLs (`hub.invariantsystems.io`)
- Financial projections, investor names, fundraising status
- Patent filing numbers or IP portfolio details
- Real API keys, tokens, or credentials (use obvious fakes in tests)
- Architecture internals not already documented in this repo's public files

---

## §6 — Architecture Quick Reference

| Module | Role | Security-critical? |
|--------|------|--------------------|
| `aiir/_core.py` | Receipt generation, constants | Yes |
| `aiir/_detect.py` | AI signal detection (TR39, Unicode normalization) | Yes |
| `aiir/_schema.py` | Receipt schema validation | Yes |
| `aiir/_verify.py` | Content-hash and Sigstore verification | Yes |
| `aiir/_canonical_cbor.py` | CBOR canonical encoding | Yes |
| `aiir/cli.py` | CLI entry point | Yes (input validation) |
| `aiir/mcp.py` | MCP server | Yes (transport boundary) |
| `aiir/_policy.py` | Policy evaluation engine | No |
| `tests/` | 1,800+ tests (pytest + Hypothesis) | — |
| `.github/workflows/` | 18 CI workflows | Yes (supply chain) |

---

## §7 — Dual-Remote Policy

This repo mirrors to GitHub (primary) and GitLab. See `.local/AGENTS.md`
(workstation-only, gitignored) for the dual-push commands and GitLab
branch protection API details. If `.local/AGENTS.md` is not present, ask
the developer — never hardcode GitLab credentials or tokens.

---

## §8 — Testing Standards

- **Coverage**: 100% line coverage is enforced. `--fail-under=100`.
- **Hypothesis**: Property-based tests are required for serialization and
  normalization code paths.
- **Mutation testing**: Security-critical modules (`_verify.py`,
  `_canonical_cbor.py`, `_verify_cbor.py`) must maintain ≥75% mutant
  kill rate.
- **Test vectors**: Changes to receipt format or hashing must update
  `schemas/test_vectors.json` (25 conformance vectors).
