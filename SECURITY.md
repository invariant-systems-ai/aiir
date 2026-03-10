# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.2.x   | ✅ Active (current) |
| 1.1.x   | ✅ Security fixes |
| 1.0.x   | ✅ Security fixes |
| < 1.0.0 | ❌ Unsupported — upgrade to 1.2.x |

## Reporting a Vulnerability

**This is a security-critical tool.** We take every report seriously.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities via:

- **Email**: [noah@invariantsystems.io](mailto:noah@invariantsystems.io)
- **Subject prefix**: `[VULN] aiir: <brief description>`

### What to include

1. Description of the vulnerability
2. Steps to reproduce
3. Affected versions
4. Severity assessment (if known)
5. Suggested fix (if any)

### Response timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | 24 hours |
| Initial triage | 48 hours |
| Fix for Critical/High | 7 days |
| Fix for Medium/Low | 30 days |
| Public disclosure | After fix is released |

### Scope

The following are in scope:

- **aiir/cli.py** — public API shell and CLI entry point
- **aiir/_core.py** — constants, encoding helpers, git operations, hashing
- **aiir/_detect.py** — AI signal detection and commit metadata parsing
- **aiir/_receipt.py** — receipt building, generation, formatting, writing
- **aiir/_verify.py** — receipt content-addressed integrity verification
- **aiir/_sign.py** — Sigstore signing and verification
- **aiir/_ledger.py** — append-only JSONL ledger with auto-index
- **aiir/_stats.py** — badge, stats dashboard, policy checks
- **aiir/_github.py** — GitHub Actions integration
- **aiir/mcp_server.py** — MCP server for AI assistants (path-restricted, error-sanitized)
- **action.yml** — GitHub Actions composite action
- **Receipt integrity** — content-addressed hashing chain
- **Output injection** — GitHub Actions output/summary manipulation
- **Supply chain** — dependency pinning and integrity

### Out of scope

- AI detection bypass (this is a known limitation of heuristic detection — see README)
- Issues in upstream dependencies (`actions/setup-python`, `actions/upload-artifact`, etc.)
- Denial of service via extremely large repositories (mitigated by `--max-count` limit)

## Security Design

### Threat model

This tool processes untrusted input from:

1. **Git commit metadata** — author names, emails, subjects, message bodies
2. **GitHub Actions inputs** — `commit-range`, `ai-only`, `output-dir`
3. **Diff content** — full diffs are hashed but not stored in receipts

### Security properties

- **Content-addressed receipts**: The `receipt_id` and `content_hash` are derived from SHA-256 of the canonical JSON receipt core. Modifying any field invalidates both.
- **Sigstore keyless signing** (optional): Receipts can be cryptographically signed using Sigstore, providing non-repudiation and a public transparency log entry (Rekor). Uses OIDC keyless signing — no key management required. In GitHub Actions, ambient credentials are used automatically when `id-token: write` is set.
- **NUL-byte delimited parsing**: Git metadata fields are parsed using `%x00` delimiters to prevent field injection via pipes or other characters in author names.
- **Ref validation**: All user-provided git refs are validated to reject option-like strings (e.g., `--all`), preventing git argument injection.
- **Heredoc output pattern**: GitHub Actions outputs use the heredoc delimiter pattern to prevent output injection via multiline values.
- **Pinned dependencies**: All action dependencies are pinned to full commit SHAs, not mutable version tags.
- **Markdown sanitization**: Commit subjects in step summaries are sanitized to prevent image beacon, phishing link, and HTML injection.
- **Zero dependencies**: Only Python standard library. No supply chain attack surface from pip packages.
- **PEP 740 digital attestations**: Every wheel and sdist published to PyPI includes in-toto-style digital attestations (SLSA provenance + PyPI Publish predicates), cryptographically signed via short-lived OIDC identities from Trusted Publishing. No static keys to compromise.
- **SLSA provenance**: GitHub Actions `attest-build-provenance` generates SLSA provenance attestations for both wheel and sdist, binding each artifact to the specific build invocation.
- **PyPI Integrity API verification**: Post-publish CI verifies that attestations are retrievable via PyPI's Integrity API (`GET /integrity/aiir/<version>/<file>/provenance`). A standalone verification script (`scripts/verify-pypi-provenance.py`) is provided for consumers.
- **Trusted Publishing (OIDC)**: PyPI uploads use GitHub's OIDC identity provider — short-lived, scoped tokens instead of long-lived API tokens. No `PYPI_TOKEN` secret to rotate or leak.

### Verifying AIIR release provenance

Consumers can verify that any AIIR release was built by the official CI pipeline:

```bash
# Verify the latest release attestations (zero dependencies)
python scripts/verify-pypi-provenance.py

# Verify a specific version
python scripts/verify-pypi-provenance.py 1.2.2

# Strict mode — fail if any artifact lacks attestations
python scripts/verify-pypi-provenance.py --strict
```

Alternatively, query the PyPI Integrity API directly:

```bash
# Fetch attestations for a specific file
curl -s https://pypi.org/integrity/aiir/1.2.2/aiir-1.2.2-py3-none-any.whl/provenance | python3 -m json.tool
```

## Secret rotation

The AIIR project minimises long-lived secrets through OIDC Trusted Publishing
(PyPI), Sigstore keyless signing, and the automatic `GITHUB_TOKEN`. Three
repository-level secrets remain:

| Secret | Type | Scope | Rotation cadence |
|--------|------|-------|------------------|
| `GITLAB_TOKEN` | GitLab PAT | `write_repository` on the GitLab mirror | 90 days |
| `NPM_TOKEN` | npm granular token | `publish` on `@invariantsystems/aiir` | 90 days |
| `WEBSITE_DISPATCH_TOKEN` | GitHub fine-grained PAT | `contents:read` on `invariantsystems.io` | 90 days |

**Rotation procedure:**

1. Generate a new token with the scopes listed above.
2. Update the secret in **Settings → Secrets and variables → Actions**.
3. Trigger a test workflow run to verify the new token works.
4. Revoke the old token immediately after confirming the new one.

**Design intent:** If any secret expires or is revoked, the failure mode is
graceful — GitLab sync, npm publish, and website dispatch all have fallback
paths (CI mirror cron, manual publish, 6-hour self-heal schedule).

## Acknowledgments

We gratefully acknowledge security researchers who report vulnerabilities responsibly.
