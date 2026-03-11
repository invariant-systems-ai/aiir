# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.2.7] — 2026-03-11

### Added

- **Enterprise Protected Branch Profile v1.0**: 12 deterministic, machine-evaluable
  rules (EPB-001 through EPB-012) that replace prose-stated enterprise requirements
  with typed claims consuming commit receipts, review receipts, and release VSAs.
  See `docs/enterprise-profile-v1.md`.
- **Decision Receipt schema** (`aiir/decision_receipt.v1`): Per-rule, per-commit,
  per-gate-invocation receipt — finer grain than commit receipts. Each decision
  captures `rule_id`, `result` (PASS/FAIL/SKIP), `evaluator`, `evidence`, and the
  policy digest it was evaluated against.
- **Profile validator** (`scripts/validate_profile.py`): Standalone, zero-dependency
  script that validates enterprise profile JSON against the schema and evaluates all
  12 EPB rules against a receipt ledger. Works as both local preflight and CI step.
- **Self-healing tests** (`tests/test_enterprise_profile.py`, 47 tests): Schema
  structural health, doc ↔ schema cross-reference parity, conformance manifest
  registration, validator schema/rule/CLI tests, full profile evaluation tests.
- **CI integration**: `profile-validate` job added to `quality.yml`, wired into the
  `quality-ok` summary gate.
- **Conformance manifest**: Registered `enterprise_profile.v1.schema.json` and
  `decision_receipt.v1.schema.json` in `schemas/conformance-manifest.json`.

## [1.2.6] — 2026-03-11

### Added

- **AI Gate**: `ai-gate` is now a required status check on `main`. The AI Gate
  workflow emits a commit status after verifying first-party authorship, Copilot
  review on the current HEAD, and all composite CI checks (`ci-ok`, `quality-ok`,
  `security-ok`).

## [1.2.5] — 2026-03-11

### Changed

- Version bump to `1.2.5` for the next PyPI and npm release.
- Synchronized all in-repo version references via `scripts/sync-version.py`.

### Fixed

- Added coverage tests for hardened security branches so release CI stays at 100% coverage.

## [1.2.4] — 2026-03-11

### Fixed

- **CI fully green**: Closed all 4 CI failures from v1.2.3 release.
- **Ruff lint**: Removed 4 unused imports and fixed F821 type annotation in
  `test_transport_attestation.py`.
- **Ruff format**: Applied canonical formatting to new test files.
- **Markdown lint**: Fixed 30+ violations (MD032 blanks-around-lists, MD034 bare
  URLs, MD049 emphasis style, MD007/MD029 list indentation, MD056 table column
  count). Added `.markdownlint-cli2.yaml` to ignore `node_modules`. Disabled
  MD060 (compact tables are project style).
- **Coverage 100%**: Added 14 coverage-gap tests in `test_coverage_gaps.py`
  covering invalid tree/parent SHA validation (`_detect.py`), DAG binding field
  validation (`_schema.py`), review attestation flags and CI auto-detection
  (`cli.py`). All 1682 tests pass.

## [1.2.3] — 2026-03-11

### Added

- **Markdown lint enforcement**: Fixed all 78 markdown lint violations across 20 files and re-enabled all suppressed rules in `.markdownlint.yaml`. CI now enforces the full rule set.
- **Verification pipeline documentation**: New "How It Works — The Verification Pipeline" section in README with ASCII architecture diagram showing `git commit → receipt → Sigstore → policy → VSA → CI gate`.
- **Example gallery** (`examples/README.md`): Real receipt JSON, verification output, CI check mockup, policy evaluation example, and badge usage guide.
- **GitHub community profile**: Added `.github/SECURITY.md` for detection and `.github/ISSUE_TEMPLATE/config.yml` with security policy redirect and discussions link.
- **CI badge**: Added CI status badge to README badge row.

### Changed

- **README messaging**: Tagline updated from consumer-style to infra-grade positioning. Test count updated to 1600+. Audience-specific bullets for developers, security teams, and auditors.

## [1.2.2] — 2026-03-10

### Added

- **DAG binding hardening** (`commit_receipt.v2`): Receipt core now includes `tree_sha` (directory state) and `parent_shas` (graph position) in the hashed `commit` object. Closes the theoretical "receipt laundering" vector identified in red-team review — a receipt is now cryptographically bound to the commit's exact position in the DAG, not just its content hash. Backwards-compatible: v1 receipts still verify. JSON Schema: `schemas/commit_receipt.v2.schema.json`. New controls: R24-DAG-01, R24-DAG-02.
- **P0: GitHub Check Run** (`create_check_run()`): AIIR verification now posts a visible `aiir/verify` check run on every PR when running as a GitHub Action. Enforceable via branch protection rules. Requires `checks: write` permission.
- **P1: Review Receipts** (`build_review_receipt()`, `--review`): New receipt type (`aiir/review_receipt.v1`) for human review attestations. Content-addressed, schema-validated, appended to the same ledger. Supports `--review-outcome` (approved/rejected/commented) and `--review-comment`. JSON Schema: `schemas/review_receipt.v1.schema.json`.
- **P2: Project Init** (`--init`): Scaffold a `.aiir/` directory with `receipts.jsonl`, `index.json`, `config.json`, `.gitignore`, and optional `policy.json`. Path-traversal guarded. Idempotent (safe to re-run).
- **P3: PR Comment** (`post_pr_comment()`): Automatic receipt summary comment on every PR in GitHub Actions mode. Idempotent (updates existing comment via hidden HTML marker). Requires `pull-requests: write` permission.
- **P4: Commit Trailers** (`format_commit_trailer()`, `--trailer`): Print `AIIR-Receipt`, `AIIR-Type`, `AIIR-AI`, `AIIR-Verified` trailer lines suitable for `git interpret-trailers`. Terminal-escape sanitized, capped at 10 trailers.
- **Transport-level agent attestation** (`extensions.agent_attestation`): 3-tier confidence model for AI authorship evidence:
  - `"declared"` — self-reported via `--agent-tool`/`--agent-model`/`--agent-context` CLI flags (existing).
  - `"transport"` — **NEW**: MCP server auto-populates `confidence: "transport"` because the MCP protocol itself guarantees an AI client invoked the tool. Generator stamped as `aiir.mcp`.
  - `"environment"` — **NEW**: CI auto-detection reads `GITHUB_ACTOR` / `GITLAB_USER_LOGIN` and auto-populates attestation when the actor matches known AI/bot patterns (e.g., `copilot`, `dependabot[bot]`, `gitlab-duo`). Explicit `--agent-*` flags always take precedence.
  - Review receipts (`build_review_receipt`) now accept and propagate `agent_attestation`.
- **PEP 740 digital attestations**: Publish workflow now explicitly enables `attestations: true` on `pypa/gh-action-pypi-publish`. Every wheel and sdist uploaded to PyPI includes in-toto-style digital attestations (SLSA provenance + PyPI Publish predicates), cryptographically signed via short-lived OIDC identities from Trusted Publishing.
- **SLSA provenance for sdist**: `actions/attest-build-provenance` now covers both `.whl` and `.tar.gz` artifacts (was wheel-only).
- **PyPI Integrity API verification**: Post-publish CI step queries `GET /integrity/aiir/<version>/<file>/provenance` for every release artifact and reports attestation coverage.
- **Consumer verification script** (`scripts/verify-pypi-provenance.py`): Zero-dependency (stdlib-only) tool for downstream consumers to verify PEP 740 attestations on any AIIR release. Supports `--strict` mode for CI gating.
- **5 new supply-chain security controls** (R22-SC-01 through R22-SC-05) in THREAT_MODEL.md. **147 total controls.**
- **JCS compatibility regression test** (`tests/test_canonicalization.py`): Proves `_canonical_json` produces byte-identical output to RFC 8785 for all receipt-schema types (strings, ints, bools, null, arrays, objects). 500-example Hypothesis fuzz suite. Float canary tests document the exact IEEE-754 divergence that would trigger JCS adoption.
- **Normative canonicalization contract** (SPEC.md §6.5): Explicit type inventory, RFC 8785 equivalence statement, and documented migration trigger for SDK authors. Spec version → 1.1.0.

### Changed

- **SECURITY.md**: Added PyPI attestation verification section with consumer-facing instructions.
- **THREAT_MODEL.md**: Updated to v3.2.0 — PEP 740 attestations, Integrity API verification, and SBOM attestation moved from "Future Hardening" to "Done".

### Fixed

- **MCP server generator identity**: MCP server called `generate_receipt()`/`generate_receipts_for_range()` without `generator` or `agent_attestation` — receipts from MCP were indistinguishable from CLI receipts. Now stamps `generator: "aiir.mcp"` and `agent_attestation.confidence: "transport"` on all 3 call sites (`_handle_aiir_receipt` single + range, `_handle_aiir_gitlab_summary`).
- **Review receipt attestation gap**: `build_review_receipt()` did not accept `agent_attestation`. Now propagates `--agent-*` flags and CI auto-detection to review receipts.
- **PR comment markdown injection**: `_format_pr_comment()` now uses `_sanitize_md()` instead of `_strip_terminal_escapes()` — neutralises markdown metacharacters (`|`, `` ` ``, `<`) in user-controlled fields rendered in GitHub PR comment tables.
- **`--init` path traversal**: Replaced `startswith()` with `relative_to()` to prevent prefix-collision attacks (`/repo` vs `/repo_evil`).
- **`--review` ref resolution**: CLI now resolves symbolic refs (e.g., `HEAD`) to full hex SHAs via `git rev-parse` before building review receipts. Previously, `--review HEAD` produced a receipt with `reviewed_commit.sha = "HEAD"`, which violated the JSON Schema.
- **PR number validation**: `post_pr_comment()` now validates that the PR number is numeric, preventing URL path injection via crafted event payloads.
- **Check Run code spans**: `create_check_run()` now uses double-backtick delimiters (consistent with `format_github_summary()`) to prevent code-span breakage from embedded backticks.
- **GitLab component `enforce_approval_rules` import**: Function existed in `aiir._gitlab` but was not exported from `aiir.__init__`. The GitLab component's `approval-threshold` code path raised `ImportError`. Now exported in `__all__`.
- **GitLab component signing default**: Changed from `false` to `true`, matching the GitHub Action's default. Both CI integrations now ship the same provenance strength by default.
- **Stale GitLab component README**: Updated version default (`1.0.14` → `1.2.2`), test count (`760+` → `1,600+`), added missing inputs (`sign`, `gl-sast-report`, `approval-threshold`) to the input table.
- **Version drift**: All version-bearing files (`__init__.py`, `THREAT_MODEL.md`, `SECURITY.md`, `mcp-manifest.json`, `README.md`, `templates/`) now reference `1.2.2` consistently.
- **SPEC.md stale control count**: Updated cross-reference from "142 controls" to "147 controls" to match `THREAT_MODEL.md`.
- **Hardening test false failures**: Differential GFM tests now probe `_MD.render()` during setup, correctly skipping when `linkify-it-py` is missing (was only guarding on `markdown-it-py` import).

## [1.2.1] — 2026-03-09

### Fixed

- **`--verify-release` crash**: `list_commits_in_range()` returns plain SHA strings but the caller attempted `.sha` attribute access, causing `AttributeError` on every invocation. Fixed by removing the incorrect attribute dereference.
- **Signing footgun**: When `--sign` failed (missing `sigstore`, network error), the unsigned receipt was left on disk. Now cleaned up on failure with a clear error message.
- **MCP manifest description**: Aligned with canonical one-liner ("Tamper-evident receipts for commits with declared AI involvement").
- **Positioning audit**: Updated GitHub repo description, contrib posts, and examples to use "declared AI involvement" consistently. Feature-level labels (`ai_commit_count`, `is_ai_authored`) intentionally unchanged — they describe detection results.

## [1.2.0] — 2026-03-09

### Added

- **Release verification engine** (`aiir/_verify_release.py`): Release-scoped verification that evaluates a set of commit receipts against policy, computes commit coverage, and produces a pass/fail result. 679 lines. Supports `strict`, `balanced`, and `permissive` policy presets with configurable enforcement levels (`hard-fail`, `soft-fail`, `warn`).
- **Verification Summary Attestation (VSA)**: SLSA-style VSA predicate builder and in-toto Statement v1 wrapper. Emits machine-readable attestations that record verifier identity, policy digest, coverage metrics, and evaluation results.
- **VSA JSON Schema** (`schemas/verification_summary.v1.schema.json`): JSON Schema (draft 2020-12) for the VSA predicate format. 227 lines.
- **`--verify-release` CLI flag**: Verify all receipts against policy and output a release report. Accepts `--receipts`, `--emit-vsa`, and `--subject` flags.
- **`aiir_verify_release` MCP tool**: Release verification exposed as an MCP tool for AI-assisted compliance workflows.
- **62 new tests** across 14 test classes covering coverage calculation, receipt evaluation, receipt loading, VSA predicate builder, in-toto wrapper, end-to-end verification, range tests, report formatting, schema compliance, constants, CLI integration, MCP integration, public exports, and edge cases.
- **1093 tests passing** (up from 1084 in v1.1.0).

### Changed

- **Public API**: Added `verify_release`, `format_release_report`, and `VSA_PREDICATE_TYPE` to `aiir/__init__.py` public API and `__all__`.
- **MCP surface**: Expanded from 5 to 6 tools (`aiir_verify_release`).

## [1.1.0] — 2026-03-09

### Added

- **Native GitLab CI integration** (`aiir/_gitlab.py`): Full-featured module for GitLab CI/CD — MR comment posting, GL-SAST report generation, dotenv artifact outputs, approval rule enforcement, webhook parsing, GraphQL receipt queries, and dashboard HTML generation. 829 lines, 53 dedicated tests.
- **GitLab Duo AI detection**: 10 new signal patterns for GitLab Duo (`gitlab duo`, `duo code suggestions`, `duo chat`, `duo enterprise`, `co-authored-by: gitlab duo`, and more), plus `gitlab-duo` and `duo[bot]` bot signals, and `gitlab-bot` automation signal.
- **`--gitlab-ci` CLI flag**: Native GitLab CI output mode — sets dotenv variables, posts best-effort MR comments, and auto-detects `CI_MERGE_REQUEST_IID`.
- **`--gl-sast-report` CLI flag**: Generates GitLab Security Dashboard–compatible SAST JSON report from receipt findings.
- **Sigstore signing in GitLab CI**: Receipt template gains `sign`, `gl-sast-report`, and `approval-threshold` inputs with OIDC `id_tokens` blocks for keyless signing.
- **NIST SSDF / SLSA hardening**: CycloneDX SBOM generation in publish pipeline, SLSA provenance attestation job, Semgrep taint-tracking SAST workflow.
- **Security workflows**: `security.yml` (bandit + gitleaks + pip-audit + ruff), `verify-receipts.yml` (reusable Check Run verification).
- **Pre-commit security hooks**: Added gitleaks, bandit, and ruff to `.pre-commit-config.yaml`.
- **JS/TS receipt verifier SDK** (`sdks/js/aiir-verify.js`): Zero-dependency browser + Node.js receipt verification. TypeScript declarations included.
- **25 conformance test vectors**: Expanded from 15 to 25 vectors in `schemas/test_vectors.json`. Conformance runner validates 25/25.
- **VS Code extension skeleton**: `extensions/vscode/` with package.json, tsconfig, and activation stub.
- **GitLab docs**: `gitlab-compliance-framework.md`, `gitlab-pages-dashboard.md`, `gitlab-webhooks.md`.
- **GitLab templates**: `gitlab-pages-dashboard.yml`, `gitlab-publish-pypi.yml`.
- **Trust tiers documentation**: Three-tier receipt trust model (Unsigned → Signed → Enveloped) in README and docs.
- **`generator` parameter**: `build_commit_receipt`, `generate_receipt`, and `generate_receipts_for_range` accept a `generator` string to identify the calling tool (`aiir.cli`, `aiir.github`, `aiir.gitlab`).
- **1084 tests passing** (up from 1022 in v1.0.15).

### Changed

- **Public API**: Added 6 GitLab functions to `aiir/__init__.py` public API and `__all__`.
- **Receipt template**: Added Sigstore OIDC, SAST artifact reports, and dotenv outputs to `templates/receipt/template.yml`.
- **GitLab CI template**: All `aiir` invocations now include `--gitlab-ci` flag for native integration.

## [1.0.15] — 2026-03-09

### Added

- **Public Python API** (`__init__.py`): Added `__all__` with 21 re-exported symbols — `generate_receipt`, `verify_receipt`, `detect_ai_signals`, `explain_verification`, `validate_receipt`, `check_policy`, `format_stats`, and more. Enables `from aiir import generate_receipt` one-liner usage for SDK consumers.
- **3 new MCP tools**: `aiir_stats` (ledger statistics), `aiir_explain` (human-readable verification explanation), `aiir_policy_check` (AI percentage policy enforcement). Expands MCP surface from 2 to 5 tools.
- **Full Unicode TR39 confusable detection**: Expanded `_CONFUSABLE_TO_ASCII` map from 182 to 669 entries covering 69 scripts. Hardens receipt verification against homoglyph attacks across Arabic, Cyrillic, Greek, Georgian, Armenian, Cherokee, Ethiopic, CJK, and 60+ additional Unicode blocks.
- **Red team adversarial suite**: 80 new hostile tests targeting MCP injection, path traversal, Unicode abuse, resource exhaustion, symlink attacks, and signal-count forgery. All passing.

### Changed

- **MCP protocol version**: Updated from `2024-11-05` to `2025-03-26` (latest stable MCP specification).
- **Website version fallbacks**: Updated all `v1.0.11` fallbacks to `v1.0.15` in `index.html` and `docs.html`.
- **PR template**: Fixed stale test command (`test_cli.py fuzz_cli.py -v` → `tests/ -q`).
- **CONTRIBUTING.md**: Updated test count to 840+.

### Fixed

- **Security hardening**: Multiple input validation and output sanitization improvements identified during adversarial red-team review. All hardened with bounds checks, input validation, and safe defaults. See [THREAT_MODEL.md](THREAT_MODEL.md) for the full control inventory.

## [1.0.14] — 2026-03-09

### Added

- **in-toto Statement v1 wrapper** (`--in-toto`): Wrap receipts in a standard [in-toto Statement v1](https://in-toto.io/Statement/v1) envelope. Makes AIIR receipts native to the supply-chain attestation ecosystem — compatible with SLSA verifiers, Sigstore policy-controller, Kyverno, OPA/Gatekeeper, and Tekton Chains. Predicate type: `https://aiir.dev/commit_receipt/v1`. Subject identifies the git commit by repository and SHA.
- **Claude Code hooks recipe** (`docs/claude-code-hooks.md`): Step-by-step guide for auto-generating receipts via Claude Code's PostToolUse hooks. Covers basic, signed, agent attestation, in-toto envelope, and quiet mode variants.
- **GitLab Duo recipe** (`docs/gitlab-duo-recipe.md`): `.gitlab-ci.yml` examples for receipting Duo-generated MRs. Covers MR detection, agent attestation, in-toto output, policy enforcement, and MR comment integration.
- **Continue, Cline, and Windsurf MCP configs**: Added MCP server configuration examples for Continue (YAML and JSON), Cline, and Windsurf alongside existing Claude Desktop, VS Code/Copilot, and Cursor configs in README.

### Changed

- **ARCHITECTURE.md**: Added Integration Recipes section and in-toto integration bridge documentation.
- **README.md**: MCP intro now lists all six supported clients (Claude, Copilot, Cursor, Continue, Cline, Windsurf).

## [1.0.13] — 2026-03-08

### Added

- **Explainable verification** (`--explain`): Human-readable verification output for non-crypto users. Categorizes failures (hash mismatch, unknown type/schema, invalid version, malformed input) with plain-English problem descriptions, common causes, and remediation steps. Schema warnings displayed independently of hash verdict.
- **Org policy engine** (`--policy PRESET`, `--policy-init PRESET`): Three enforcement presets — `strict` (hard-fail, signing required, max 50% AI commits), `balanced` (soft-fail, signing recommended), `permissive` (warn-only). Policies stored in `.aiir/policy.json`. Per-receipt checks: signing status, provenance repo, authorship class, schema validity. Aggregate ledger check: AI commit percentage cap. Integrates with `--check` for CI enforcement.
- **Agent attestation envelope** (`--agent-tool`, `--agent-model`, `--agent-context`): Structured metadata for AI-agent-generated commits stored in `extensions.agent_attestation`. Six allowlisted keys (`tool_id`, `model_class`, `session_id`, `run_context`, `tool_version`, `confidence`) with sanitization — string coercion, 200-char cap, no core hash impact.
- **Architecture document** (`ARCHITECTURE.md`): Architecture overview with module responsibilities, shipped capabilities, schema evolution policy, and backward compatibility guarantees.

### Changed

- **CONTRIBUTING.md**: Fixed stale test commands (`test_cli.py fuzz_cli.py` → `tests/ -q`), added hypothesis dependency note explaining graceful degradation, updated test count from 500+ to 710+.
- **README.md**: Updated test count to 710+. Specification & Schemas table no longer hardcodes security control count.

## [1.0.12] — 2026-03-08

### Added

- **Formal JSON Schema** (`schemas/commit_receipt.v1.schema.json`): Machine-readable JSON Schema (draft 2020-12) describing the `aiir/commit_receipt.v1` structure — all fields, types, regex patterns, `$defs` for Commit, GitIdentity, AIAttestation, Provenance. `oneOf` constraint for `files` vs `files_redacted` mutual exclusivity. Published `$id`: `https://invariantsystems.io/schemas/aiir/commit_receipt.v1.schema.json`.
- **Normative specification** (`SPEC.md`): 15-section specification using RFC 2119 language covering receipt structure, canonical JSON encoding algorithm, content addressing, verification algorithm, file verification, Sigstore signing integration, security surfaces, and IANA considerations. Intended for third-party implementors.
- **Conformance test vectors** (`schemas/test_vectors.json`): 15 test vectors with computed hashes — 5 valid (human, AI-assisted, redacted files, null repo, extensions) and 10 invalid (tampered subject, wrong type, wrong schema, wrong content_hash, wrong receipt_id, missing content_hash, version injection, bot commit, not-a-dict, non-string schema). All verified against reference implementation.
- **Schema validation module** (`aiir/_schema.py`): Zero-dependency structural validator checking all required fields, types, const values, regex patterns, signal count consistency, files/files_redacted mutual exclusivity, authorship_class enum, and Python `bool`/`int` subclass distinction. Returns list of human-readable error strings.
- **`schema_errors` in verification result**: `verify_receipt()` now runs structural schema validation after hash verification and includes a `schema_errors` list in the result when violations are found. Supplementary — does not override hash-based verdict for backward compatibility.

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

- **`authorship_class` field**: Receipts now include a structured `authorship_class` in `ai_attestation` — one of `"human"`, `"ai_assisted"`, `"bot"`, or `"ai+bot"`. This gives downstream tools a single enum-like field for classification, eliminating the need to interpret boolean pairs. *(v1.0.14 aligned values with SPEC; legacy hyphenated forms from v1.0.4–v1.0.13 are accepted by the validator for backward compatibility.)*
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
