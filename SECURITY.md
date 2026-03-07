# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Active |
| < 1.0.0 | ❌ Unsupported — upgrade to 1.0.x |

## Reporting a Vulnerability

**This is a security-critical tool.** We take every report seriously.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities via:

- **Email**: [security@invariantsystems.io](mailto:security@invariantsystems.io)
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

- **aiir/cli.py** — receipt generation, AI detection, hashing, verification
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

## Acknowledgments

We gratefully acknowledge security researchers who report vulnerabilities responsibly.
