# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.11] — 2026-03-08

### Added

- **`--detail` flag**: New detailed human-readable receipt view showing all fields — schema identity, full commit SHA, committer, message/diff hashes, file list, authorship class, detection method, signal counts, bot attestation, provenance, and extensions. Combines with any output mode (`--output`, `--json`, `--jsonl`). File list capped at 20 entries for terminal safety.

## [1.0.10] — 2026-03-08

### Added

- **`Signed` line in pretty-print output**: `format_receipt_pretty()` now accepts an optional `signed` parameter (default `"none"`). When `--sign` is active, the pretty receipt displays `Signed:  YES (sigstore)`. Display-only — receipt JSON is unchanged.

### Changed

- **Bottom border width**: Pretty-print bottom border now uses 42 dashes (`└` + 42×`─`) for visual consistency with the header.

## [1.0.9] — 2026-03-08

### Fixed

- **`--ledger` flag pass-through**: `--badge`, `--stats`, `--check`, and `--export` now correctly read from a custom ledger directory when `--ledger DIR` is specified. Previously these sub-commands ignored the flag and always read from the default `.aiir/`.
- **MCP argument validation**: `tools/call` with non-dict `arguments` (string, list, number) now returns a proper error instead of silently falling back to `{}`.
- **Sigstore error hints**: OIDC credential failure message now includes actionable steps (`SIGSTORE_ID_TOKEN`, `--no-sign`, `sign: false`).

### Changed

- **`--ledger` help text**: Clarified that the argument takes a directory path, not a file path. Added `metavar="DIR"` and documented that the directory will contain `receipts.jsonl` and `index.json`.
- **`--namespace` help text**: Now states that namespace is stored in `extensions.namespace` and is not part of the content hash.
- **`--export` help text**: Now notes that the path must be relative to the project root.
- **No-remote provenance warning**: CLI now prints a hint to stderr when receipts are generated without a git remote configured, explaining that `receipt_id` will change once an origin is set.
- **Coverage gate**: CI coverage threshold set to 92% (actual: 94% local, 92% CI floor due to environment-dependent OIDC detection paths).
- **Template versions**: All CI platform templates bumped to 1.0.9.
- **README test count**: Updated from "604 tests" to "660+ tests".

## [1.0.8] — 2026-03-08

### Added

- **Dependabot config**: `.github/dependabot.yml` auto-updates pinned action SHAs (checkout, setup-python, upload-artifact, pypi-publish) and pip dependencies weekly. Grouped minor+patch PRs to reduce noise.
- **Action Health workflow**: `action-health.yml` runs post-release smoke tests using the *published* `@v1` action (not local `./`) — catches packaging regressions dogfood testing misses. Includes unsigned + signed receipt validation, Sigstore bundle verification, and PyPI version cross-check. Auto-creates P0 issue on failure.
- **Dependency freshness audit**: Weekly check comparing pinned SHAs against latest releases. Auto-creates advisory issue when staleness is detected.
- **OSSF Scorecard**: `scorecard.yml` runs weekly, publishes supply chain security results to GitHub Security tab and OpenSSF badge API.
- **Drift auto-issue**: `sync.yml` now auto-creates a GitHub issue (label: `version-drift`) when distribution channel drift is detected, instead of only logging warnings.

### Changed

- **Commit-range validation**: `action.yml` range step now rejects inputs containing shell metacharacters (`;`, `&`, `|`, `$`, backticks, control chars) and warns on ranges exceeding 500 commits.

## [1.0.7] — 2026-03-08

### Added

- **CI OIDC detection**: `sign_receipt()` now detects CI environments (GitHub Actions, GitLab CI, Bitbucket, CircleCI, Jenkins, Azure Pipelines) and raises a clear, actionable error when ambient OIDC credentials are missing — instead of falling through to an interactive browser flow that hangs on headless runners. Fork PR context is explicitly mentioned in the GitHub Actions error.
- **`receipts_overflow` output**: Documented in README and docs. When `receipts_json` exceeds 1 MB, it is set to `"OVERFLOW"` and `receipts_overflow` is set to `"true"`.
- **3 new tests**: CI OIDC detection for GitHub Actions, fork PRs, and generic CI (567 total).

### Changed

- **Template versions**: All 5 CI platform templates (GitLab, Azure Pipelines, Bitbucket, CircleCI, Jenkins) updated from 1.0.0–1.0.2 to 1.0.7. Previously, non-GitHub CI users were running code missing 40% of AI tool detection.
- **GitLab template shell quoting**: All `$AIIR_AI_ONLY` and `$AIIR_EXTRA_ARGS` variable expansions now use `${VAR:+"$VAR"}` pattern to prevent shell injection via pipeline variables.
- **Recommended workflow triggers**: GitHub Action YAML examples in README and docs now use `push: { tags-ignore: ['**'] }` instead of bare `on: [push, pull_request]` to prevent tag pushes from receipting the entire repo history.
- **upload-artifact SHA pins**: Aligned action.yml and dogfood.yml to v4.6.2 (was v4.6.0).
- **Messaging alignment**: All template header comments updated from "AI-generated code commits" to "commits with declared AI involvement". Article 13 references retired.

### Fixed

- **README `sign` default**: Inputs table corrected from `false` to `true` (actual default since v1.0.5).
- **README GitLab `output-dir` default**: Corrected from `.receipts` to `.aiir-receipts` to match actual template.yml spec.
- **Fork PR resilience**: Fork PRs with `sign: true` now fail fast with a clear error message instead of hanging on interactive browser OIDC.

## [1.0.6] — 2026-03-08

### Changed

- **Messaging normalization**: All public surfaces now use "commits with declared AI involvement" instead of "AI-generated code commits" — aligns with the website's existing "declared AI involvement" framing. Updated: `pyproject.toml` description, `action.yml` description, `__init__.py` docstring, GitHub repo description.
- **EU AI Act framing**: Retired the incorrect "Article 13" shorthand. Article 13 is technical documentation for high-risk systems; transparency obligations are in Article 50. README now uses "EU AI Act transparency and provenance requirements" — accurate without overspecifying.
- **Development Status**: Downgraded PyPI classifier from "Production/Stable" to "Beta" — honest for a project at this maturity stage.
- **PyPI metadata**: Homepage and Documentation URLs now point to `invariantsystems.io` and `invariantsystems.io/docs` instead of GitHub.
- **THREAT_MODEL.md**: CLI version bumped from 1.0.2 to 1.0.6.

### Fixed

- **Docs page**: `sign` input default corrected from `false` to `true` in the GitHub Action inputs table (actual default has been `true` since v1.0.5).
- **About page timeline**: Added v1.0.4, v1.0.5, and v1.0.6 entries — timeline previously stopped at v1.0.3.

## [1.0.5] — 2026-03-08

### Added

- **`authorship_class` field**: Receipts now include a structured `authorship_class` in `ai_attestation` — one of `"human"`, `"ai-assisted"`, `"bot-generated"`, or `"ai+bot"`. This gives downstream tools a single enum-like field for classification, eliminating the need to interpret boolean pairs.
- **Trust stack architecture**: Website now includes a concrete OSS → Hub → Fortress diagram showing what each layer provides.

### Changed

- **Signing default**: GitHub Action now defaults to `sign: true` (Sigstore keyless signing). Ambient OIDC in GitHub Actions makes this zero-config. Opt out with `sign: false`.
- **Surface synchronization**: Every public surface (README, website, org profile, GitLab template, version.js) now uses consistent version refs, `tamper-evident` language, and `heuristic_v2` references. Fixed: org profile "tamper-proof" → "tamper-evident", README GitLab version table, stale bot note, incomplete index.json example.

## [1.0.4] — 2026-03-08

### Changed

- **heuristic_v2 — AI / bot signal split**: `detect_ai_signals()` now returns a `(ai_signals, bot_signals)` tuple, cleanly separating genuine AI-tool involvement (Copilot, ChatGPT, Claude, Cursor, Aider, etc.) from pure automation bots (Dependabot, Renovate, GitHub Actions, Snyk, DeepSource). Receipt schema gains `is_bot_authored`, `bot_signals_detected`, and `bot_signal_count` fields; ledger index gains `bot_commit_count`. Detection method bumped to `heuristic_v2`.
- **Test suite split**: Monolithic 7,338-line `test_cli.py` decomposed into 12 focused modules under `tests/` — core, detect, receipt, ledger, verify, sign, github, mcp, redteam, cli_integration, fuzz, conftest. CI updated to use `tests/` directory.
- **Claims language**: "tamper-proof" → "tamper-evident" in MCP server tool descriptions; EU AI Act wording softened to "supports compliance evidence" across all CI templates.
- **Sigstore guidance**: README now documents `--signer-identity` / `--signer-issuer` pinning for Trusted Publisher OIDC verification.

### Fixed

- **Test timeout stall**: `test_stdout_closed_on_timeout` now patches `aiir._core.GIT_TIMEOUT` (where `_hash_diff_streaming` reads it) instead of the stale `aiir.cli.GIT_TIMEOUT` re-export — test suite drops from 303 s → 1.6 s.
- **SECURITY.md scope**: In-scope module list expanded to cover all 8 submodules after the 1.0.3 module split.

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
