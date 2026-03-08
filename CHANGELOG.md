# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.3] — 2026-03-08

### Changed

- **Module split**: Monolithic `cli.py` (2,459 lines) decomposed into 8 focused submodules — `_core`, `_detect`, `_receipt`, `_ledger`, `_stats`, `_github`, `_verify`, `_sign` — with `cli.py` as a thin re-export shell. All public API imports remain backward-compatible.
- **Claims tightened**: "tamper-proof" → "tamper-evident" across website and docs; EU AI Act language softened to "supports compliance evidence"; version references updated.
- **Signal categories**: AI signals in README split into "Declared AI assistance" (Copilot, ChatGPT, Claude, etc.) and "Automation / bot activity" (Dependabot, Renovate, etc.) with filtering guidance.
- **Signed CI as default**: README GitHub Action example now defaults to signed receipts (`id-token: write`, `sign: true`); unsigned workflow moved to collapsible details block.
- **Artifact upload claim**: README and docs corrected to match `action.yml` conditional behavior.

### Fixed

- 16 test monkeypatch targets updated to resolve names in correct submodule namespaces after module split.
- THREAT_MODEL.md version and date synced to 1.0.2.

## [1.0.2] — 2026-03-08

### Added

- **GitLab CI/CD Catalog component** (`templates/receipt/template.yml`) — one-line include with typed `spec:` inputs for stage, version, ai-only, output-dir, artifact-expiry, extra-args, python-image, and job-prefix.
- **Multi-platform CI templates**: Bitbucket Pipelines, Azure DevOps, CircleCI, Jenkins.
- **Docker support**: `Dockerfile` + `.dockerignore` for container-based usage in any CI/CD system.
- **Root `.gitlab-ci.yml`** for component testing and automated release publishing via semantic version tags.
- GitLab CI/CD Catalog badge in README.
- Expanded README with quick-start examples for all supported platforms.

## [1.0.1] — 2026-03-07

### Fixed

- Version bump for Trusted Publisher OIDC test.

## [1.0.0] — 2026-03-07

### Added

- **Cryptographic receipt generation** for git commits — content-addressed, tamper-evident audit trail.
- **AI authorship detection** (heuristic_v1): 31 signal patterns covering Copilot, ChatGPT, Claude, Cursor, Aider, Amazon Q, CodeWhisperer, Devin, Gemini, Tabnine, and 13 bot author patterns.
- **Sigstore keyless signing**: Opt-in cryptographic signing via `--sign`. Uses ambient OIDC in GitHub Actions; interactive browser flow locally.
- **Signature verification**: `--verify-signature` with `--signer-identity` / `--signer-issuer` pinning.
- **MCP server** (`aiir-mcp-server`): Zero-dependency stdio JSON-RPC server exposing `aiir_receipt` and `aiir_verify` as MCP tools for AI assistants.
- **GitHub Action**: Composite action with step summary, artifact upload, and optional Sigstore signing.
- **Content-addressed receipt IDs** (`g1-` prefix + SHA-256).
- **Offline verification**: `--verify FILE` checks receipt integrity without network access.
- **`--pretty`** human-readable terminal output with encoding-safe emoji/box-drawing (ASCII fallback on non-UTF-8 terminals).
- **`--output`** writes receipts to disk with collision-resistant filenames (UUID + O_EXCL).
- **Ledger mode** (default): receipts append to `.aiir/receipts.jsonl` with auto-deduplication via `.aiir/index.json`. Run `aiir` twice on the same commit — zero duplicates.
- **`--json`** prints receipt JSON to stdout (bypasses ledger, for piping).
- **`--ledger`** allows custom ledger directory.
- **`--ai-only`** filters to AI-authored commits only.
- **`--redact-files`** omits file paths from receipts for privacy.
- **`--jsonl`** newline-delimited JSON output.
- **Multi-receipt JSON array** output when generating multiple receipts.
- **Friendly CLI UX**: Emoji-prefixed errors with actionable hints, typo suggestions via `difflib`, 8 usage examples in `--help`.

### Security

- 142 security controls covering STRIDE threat categories.
- Unicode homoglyph detection: NFKC normalization + 36-entry confusable map (Cyrillic/Greek).
- Unicode format character (Cf) and combining mark (Mn/Me) stripping before signal matching.
- Constant-time hash comparison (`hmac.compare_digest`) to prevent timing side-channels.
- Path traversal prevention via `Path.relative_to` with post-mkdir TOCTOU re-verification.
- Symlink rejection on all file read/write paths.
- File size caps (50 MB receipts, 1 MB GitHub outputs/summaries).
- Git subprocess hardening: `--no-ext-diff`, `--no-textconv`, `--no-mailmap`, `--no-optional-locks`, `GIT_TERMINAL_PROMPT=0`.
- Streaming diff hashing with timeout and zombie process cleanup.
- Markdown sanitization: HTML entities, GFM emphasis/strikethrough, autolinks, pipe delimiters, backslash escapes, ANSI/C1 terminal sequences.
- MCP server: message size cap (10 MB), JSON-RPC 2.0 validation, path restriction to cwd, argument type coercion, error message sanitization.
- GitHub Actions output injection prevention: heredoc delimiters, key validation, byte-aware truncation.
- JSON depth limit (64 levels, iterative) to prevent stack exhaustion.
- `python -P -m aiir` in action.yml to block CWD module shadowing.
- Sigstore pin: `>=4.0.0,<5.0.0`.
- All action dependencies pinned to full commit SHAs.

### Documentation

- [THREAT_MODEL.md](THREAT_MODEL.md): Full STRIDE analysis, DREAD risk scoring, attack trees, fuzzing coverage map.
- [SECURITY.md](SECURITY.md): Vulnerability disclosure policy and trust model.
- Detection limitations documented with honest caveats (heuristic, not forensic).

### Testing

- 564 tests: 512 unit/integration tests and 52 Hypothesis property-based fuzz tests.
- Zero dependencies — uses only Python standard library (sigstore optional for signing).
- Python 3.9–3.13 supported.
- Apache-2.0 license.
