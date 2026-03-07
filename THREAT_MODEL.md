# Threat Model — AIIR (AI Integrity Receipts)

**Document version**: 3.0.0
**CLI version**: 1.0.0
**Date**: 2025-07-15 (updated 2026-03-07)
**Methodology**: STRIDE-per-element · DREAD risk scoring · Attack trees
**Author**: Invariant Systems Security Team (supplemented by Hypothesis property-based fuzzing)

---

## 1. System Overview

Invariant Receipt is a **zero-dependency Python CLI** and **GitHub Action** that
generates content-addressed cryptographic receipts for git commits.  It detects
AI authorship signals, hashes the diff, and produces a JSON receipt whose
`receipt_id` is deterministically derived from its content.

### 1.1 Execution Contexts

| Context | Runner | Trust | Privileges |
|---------|--------|-------|------------|
| **GitHub Action** | `ubuntu-latest` shared runner | Medium — any public repo can invoke | `contents: read`, optional `id-token: write` for Sigstore |
| **Local CLI** | Developer workstation | High — user-controlled environment | File system + git repo access |
| **CI/CD (other)** | GitLab CI, Jenkins, etc. | Medium | Varies by pipeline config |

### 1.2 Key Assets

| ID | Asset | Sensitivity | Description |
|----|-------|-------------|-------------|
| A1 | Receipt JSON | Medium | Content-addressed attestation; tampering = false compliance |
| A2 | Sigstore bundle | High | Cryptographic proof of signer identity |
| A3 | `GITHUB_OUTPUT` file | High | Controls downstream workflow step outputs |
| A4 | `GITHUB_STEP_SUMMARY` file | Medium | Rendered as HTML in Actions UI |
| A5 | Git repository contents | High | Source code, diffs, commit history |
| A6 | OIDC identity token | Critical | Sigstore ambient credential; impersonation risk |
| A7 | Git remote URL | Medium | May contain embedded credentials (PATs, tokens) |

---

## 2. Trust Boundaries

```
┌───────────────────────────────────────────────────────────────────┐
│  TB-0: Untrusted Input (attacker-controlled)                      │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  • Commit messages (subject, body, trailers)                │  │
│  │  • Author / committer names and emails                      │  │
│  │  • Branch names, tag names, commit-range specs              │  │
│  │  • File paths in diffs                                      │  │
│  │  • action.yml inputs (ai-only, commit-range, output-dir)    │  │
│  │  • Receipt JSON files passed to --verify                    │  │
│  │  • Sigstore bundles passed to --verify-signature            │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                              ▼ crosses TB-1                       │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  TB-1: Input Validation Boundary                            │  │
│  │  _validate_ref · _sanitize_md · _strip_terminal_escapes     │  │
│  │  _strip_url_credentials · set_github_output key validation  │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                              ▼ crosses TB-2                       │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  TB-2: Core Processing                                      │  │
│  │  get_commit_info · detect_ai_signals · build_commit_receipt │  │
│  │  _canonical_json · _sha256 · _hash_diff_streaming           │  │
│  │  verify_receipt · verify_receipt_file                        │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                              ▼ crosses TB-3                       │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  TB-3: Output / Side-Effect Boundary                        │  │
│  │  write_receipt · set_github_output · set_github_summary     │  │
│  │  sign_receipt_file · format_github_summary                  │  │
│  │  format_receipt_pretty (terminal output)                    │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                              ▼ crosses TB-4                       │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │  TB-4: External Systems                                     │  │
│  │  • Git subprocess (git log, git diff, git rev-list)         │  │
│  │  • Filesystem (write receipts, read receipts for verify)    │  │
│  │  • Sigstore TUF / Fulcio / Rekor (signing / verification)  │  │
│  │  • GitHub Actions runtime (GITHUB_OUTPUT, STEP_SUMMARY)     │  │
│  └─────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
```

---

## 3. STRIDE-per-Element Analysis

### 3.1 Spoofing (S)

| ID | Element | Threat | Mitigation | Status |
|----|---------|--------|------------|--------|
| S-01 | `detect_ai_signals` | Attacker inserts zero-width Unicode (ZWJ, ZWNJ) into "Copilot" to evade detection | R3-09: Strip `Cf` category chars before matching | ✅ Mitigated |
| S-02 | `detect_ai_signals` | Attacker uses visually-identical homoglyphs (Cyrillic "С" for Latin "C") | R7-03: Confusable character map + NFKC normalization; 36 Cyrillic/Greek mappings | ✅ Partially mitigated |
| S-03 | Sigstore signing | Stolen OIDC token used to sign receipts under victim's identity | Ambient credential detection; short-lived tokens (10 min); identity policy in verification | ✅ Mitigated (defense in depth) |
| S-04 | `verify_receipt` | Forged receipt with matching content_hash but different semantics | SHA-256 content addressing; no known preimage attacks | ✅ Mitigated |

### 3.2 Tampering (T)

| ID | Element | Threat | Mitigation | Status |
|----|---------|--------|------------|--------|
| T-01 | Receipt JSON file | Modify receipt after generation (change `is_ai_authored`, remove signals) | `content_hash` and `receipt_id` detect any change to core fields | ✅ Mitigated |
| T-02 | `write_receipt` | Overwrite existing receipt file via race condition or filename prediction | R3-06: UUID in filename + O_EXCL atomic create | ✅ Mitigated |
| T-03 | `write_receipt` | Path traversal via crafted `output-dir` (e.g., `../../etc`) | R3-01: `resolve().relative_to(cwd)` check + R3-04: recheck after mkdir (TOCTOU narrowing) | ✅ Mitigated |
| T-04 | `GITHUB_OUTPUT` | Inject additional outputs via crafted key or value | R5-04: Key validation (no `\n`, `\r`, `=`, control chars); R3-13: UUID heredoc delimiter for values | ✅ Mitigated |
| T-05 | `verify_receipt_file` | Supply symlinked file to probe arbitrary filesystem paths | R5-07: Reject `path.is_symlink()` before reading | ✅ Mitigated |
| T-06 | `sign_receipt_file` | Sign a symlinked non-receipt file (information leak via Sigstore log) | R4-02: Reject symlinks + validate JSON before signing | ✅ Mitigated |

### 3.3 Repudiation (R)

| ID | Element | Threat | Mitigation | Status |
|----|---------|--------|------------|--------|
| R-01 | Receipt system | Developer denies AI tool was used to generate code | AI signal detection in commit messages, trailers, author/committer fields | ✅ Mitigated (heuristic) |
| R-02 | Receipt system | Developer claims receipt was fabricated | Sigstore keyless signing (optional) provides non-repudiation with transparency log | ✅ Mitigated (when signing enabled) |
| R-03 | Unsigned receipts | Without Sigstore, receipts are self-attested — anyone who can forge a receipt can fabricate one | Content addressing prevents tampering but not fabrication; CLI warns when unsigned; signing is the proper mitigation | ✅ Partially mitigated (warning + opt-in signing) |

### 3.4 Information Disclosure (I)

| ID | Element | Threat | Mitigation | Status |
|----|---------|--------|------------|--------|
| I-01 | `_run_git` | Git stderr leaks internal paths, credentials, or repo structure | R5-02: Truncate stderr to first line, max 200 chars | ✅ Mitigated |
| I-02 | `_strip_url_credentials` | Git remote URL contains embedded PAT or token | HACK-08: Strip userinfo from URL; R3-03: Also strip query params and fragments | ✅ Mitigated |
| I-03 | `detect_ai_signals` | Trailer values leak internal tool configs (e.g., API keys in `tool: gpt-4/key=...`) | VULN-07: Only record trailer key, never value | ✅ Mitigated |
| I-04 | `verify_receipt_signature` | Sigstore verification error messages leak OIDC details or paths | R4-07: Sanitize to first line, max 200 chars | ✅ Mitigated |
| I-05 | Receipt JSON | `files` field enumerates up to 100 changed file paths (may reveal internal project structure) | Capped at 100; `--redact-files` flag omits paths entirely | ✅ Mitigated (opt-out available) |

### 3.5 Denial of Service (D)

| ID | Element | Threat | Mitigation | Status |
|----|---------|--------|------------|--------|
| D-01 | `generate_receipts_for_range` | Attacker pushes 100,000 commits to trigger unbounded loop | VULN-04: `MAX_RECEIPTS_PER_RANGE = 1000` cap | ✅ Mitigated |
| D-02 | `_hash_diff_streaming` | Enormous diff (e.g., multi-GB binary) loaded into memory | HACK-04: Stream in 64KB chunks; R5-08: Enforce `GIT_TIMEOUT` deadline | ✅ Mitigated |
| D-03 | `_run_git` | Git subprocess hangs indefinitely | R5-16: `timeout=300s` on all subprocess calls | ✅ Mitigated |
| D-04 | `verify_receipt_file` | Attacker supplies multi-GB JSON file | R4-05: `MAX_RECEIPT_FILE_SIZE = 50MB` check before read | ✅ Mitigated |
| D-05 | `verify_receipt_file` | Array with thousands of receipts causes quadratic CPU | R4-01: Cap array length at `MAX_RECEIPTS_PER_RANGE` | ✅ Mitigated |
| D-06 | `_validate_ref` | Overlong ref string causes regex/processing overhead | Max length 1024 chars; reject newlines and NUL bytes | ✅ Mitigated |
| D-07 | `_canonical_json` | Deeply nested JSON object causes stack overflow | Explicit depth limit (64 levels) in `_check_json_depth` + `RecursionError` guard in `verify_receipt` | ✅ Mitigated |

### 3.6 Elevation of Privilege (E)

| ID | Element | Threat | Mitigation | Status |
|----|---------|--------|------------|--------|
| E-01 | `_run_git` | Argument injection via crafted ref (e.g., `--upload-pack=evil`) | VULN-03: `_validate_ref` rejects refs starting with `-` | ✅ Mitigated |
| E-02 | `action.yml` (bash) | Shell injection via `$COMMIT_RANGE` containing `$(cmd)` or backticks | HACK-03: Heredoc with crypto-random delimiter for GITHUB_OUTPUT; bash variable quoting | ✅ Mitigated |
| E-03 | `set_github_output` | Inject arbitrary workflow outputs via newline in key | R5-04: Key validated against `\n`, `\r`, `=`, control chars | ✅ Mitigated |
| E-04 | `format_github_summary` | XSS via commit subject rendered in Actions step summary | VULN-06: `_sanitize_md` escapes `<`, `>`, pipe, backtick, link, image | ✅ Mitigated |
| E-05 | `format_receipt_pretty` | Terminal escape injection via commit subject or author name (e.g., cursor repositioning, title rewrite) | R5-10: `_strip_terminal_escapes` removes CSI, OSC, and control chars | ✅ Mitigated |
| E-06 | `write_receipt` | Symlink attack on `output-dir` to write receipts outside allowed directory | R3-01 + R3-04: Double resolve check (before and after mkdir) | ✅ Mitigated |

---

## 4. Attack Trees

### 4.1 Forge a False "No AI" Receipt

```
Goal: Produce a valid receipt that says is_ai_authored=false for an AI commit
├── 1. Evade AI signal detection
│   ├── 1a. Zero-width char insertion in "Copilot" → BLOCKED (R3-09 strip Cf)
│   ├── 1b. Homoglyph substitution (Cyrillic) → PARTIAL (not detected)
│   ├── 1c. Use unrecognized AI tool name → PARTIAL (heuristic limitation)
│   └── 1d. Remove Co-authored-by trailer before push → WORKS (commit rewrite)
├── 2. Tamper with receipt after generation
│   ├── 2a. Modify JSON and fix content_hash → BLOCKED (SHA-256 preimage)
│   └── 2b. Regenerate receipt from modified commit → WORKS (if no Sigstore)
└── 3. Fabricate receipt from scratch
    ├── 3a. Without signing → WORKS (content addressing ≠ authentication)
    └── 3b. With signing → BLOCKED (requires valid OIDC identity)
```

**Residual risk**: Without Sigstore signing, receipts are tamper-evident but
not tamper-proof.  An actor who controls the git history can regenerate
receipts.  **Recommendation**: Enable `sign: true` for compliance-critical
workflows.

### 4.2 Inject Malicious Content via Receipt Action

```
Goal: Execute arbitrary code or exfiltrate data from the Actions runner
├── 1. Shell injection via commit-range input
│   ├── 1a. $(curl evil) in INPUT_COMMIT_RANGE → BLOCKED (quoted in bash)
│   └── 1b. Newline injection to break heredoc → BLOCKED (HACK-03 crypto delim)
├── 2. Git argument injection
│   ├── 2a. --upload-pack=evil as ref → BLOCKED (_validate_ref rejects -)
│   └── 2b. NUL byte to truncate ref → BLOCKED (_validate_ref rejects \x00)
├── 3. Output injection to poison downstream steps
│   ├── 3a. Newline in GITHUB_OUTPUT key → BLOCKED (R5-04 key validation)
│   ├── 3b. Delimiter collision in value → BLOCKED (R3-13 UUID delimiter)
│   └── 3c. Control chars in key → BLOCKED (R5-04 ord < 0x20 check)
├── 4. Path traversal via output-dir
│   ├── 4a. ../../etc/passwd → BLOCKED (R3-01 relative_to check)
│   └── 4b. Symlink race after mkdir → BLOCKED (R3-04 post-mkdir recheck)
└── 5. XSS via step summary
    ├── 5a. <script> in commit subject → BLOCKED (_sanitize_md escapes < >)
    └── 5b. Bidi override in subject → BLOCKED (R5-01 dangerous codepoints)
```

### 4.3 Denial of Service

```
Goal: Make the receipt action hang or consume excessive resources
├── 1. Push massive commit range
│   └── 1a. 100K commits → BLOCKED (MAX_RECEIPTS_PER_RANGE = 1000)
├── 2. Generate enormous diff
│   ├── 2a. 10 GB binary diff → MITIGATED (streaming + GIT_TIMEOUT)
│   └── 2b. Diff that produces infinite output → BLOCKED (300s timeout)
├── 3. Supply giant receipt file for --verify
│   └── 3a. 1 GB JSON → BLOCKED (50 MB file size limit)
└── 4. Deeply nested JSON in receipt
    └── 4a. 10000-level nesting → BLOCKED (explicit depth limit = 64 + RecursionError guard)
```

---

## 5. Data Flow Diagram

```
                     ┌──────────────┐
                     │  Attacker /  │
                     │  Contributor │
                     └──────┬───────┘
                            │ commits, inputs
                            ▼
┌──────────────────────────────────────────────────────┐
│                action.yml (TB-0)                      │
│  inputs: commit-range, ai-only, output-dir, sign     │
│  env: GITHUB_OUTPUT, GITHUB_STEP_SUMMARY             │
└──────────────────────┬───────────────────────────────┘
                       │ bash → python cli.py
                       ▼
┌──────────────────────────────────────────────────────┐
│           cli.py — Input Validation (TB-1)            │
│  _validate_ref() · NUL/newline/length/option checks   │
│  _sanitize_md() · HTML/pipe/backtick/bidi/autolink    │
│  _strip_terminal_escapes() · CSI/OSC/control chars    │
│  _strip_url_credentials() · userinfo/query/fragment   │
│  set_github_output() key validation                   │
└──────────────────────┬───────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────┐
│           cli.py — Core Processing (TB-2)             │
│  git subprocess ──→ CommitInfo ──→ detect_ai_signals  │
│  build_commit_receipt ──→ _canonical_json ──→ SHA-256 │
│  content_hash = SHA-256(canonical(core))              │
│  receipt_id = "g1-" + SHA-256(canonical(core))[:32]   │
│  verify_receipt: hmac.compare_digest (constant-time)  │
└──────────────────────┬───────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────┐
│         cli.py — Output / Side-Effects (TB-3)         │
│  write_receipt() → O_EXCL atomic file creation        │
│  set_github_output() → heredoc with UUID delimiter    │
│  set_github_summary() → sanitized Markdown table      │
│  format_receipt_pretty() → escape-stripped terminal    │
│  sign_receipt_file() → Sigstore keyless (optional)    │
└──────────────────────┬───────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────┐
│             External Systems (TB-4)                   │
│  GitHub Actions runner filesystem                     │
│  Git subprocess (git log, diff, rev-list)             │
│  Sigstore infrastructure (Fulcio, Rekor, TUF)         │
│  GitHub Actions workflow engine                       │
└──────────────────────────────────────────────────────┘
```

---

## 6. DREAD Risk Scoring (Residual)

Scoring: 1 (low) – 3 (high) per dimension.  Total = sum / 5.

| Threat | D | R | E | A | D | Score | Level |
|--------|---|---|---|---|---|-------|-------|
| S-02: Homoglyph evasion | 1 | 2 | 2 | 1 | 2 | 1.6 | Low |
| R-03: Unsigned receipt fabrication | 2 | 2 | 2 | 2 | 2 | 2.0 | Medium |
| Commit history rewrite (external) | 2 | 2 | 2 | 2 | 2 | 2.0 | Medium |

**Summary**: No residual **High** or **Critical** risks remain after comprehensive
adversarial hardening + automated fuzzing.  D-07 (deep JSON) and I-05 (file
enumeration) are now fully mitigated with explicit depth limits and `--redact-files`.
R-03 is mitigated via CLI warning + opt-in Sigstore signing.  The two remaining
**Medium** risks require Sigstore signing (now supported) and are documented as
accepted trade-offs when signing is not enabled.

---

## 7. Security Controls Inventory

Cross-reference of all hardening fixes applied during security review.

| Fix ID | Category | Description | STRIDE |
|--------|----------|-------------|--------|
| VULN-01 | Input | NUL-delimited git format (prevents pipe injection) | T |
| VULN-03 | Input | `_validate_ref` rejects option-like refs | E |
| VULN-04 | DoS | `MAX_RECEIPTS_PER_RANGE` commit cap | D |
| VULN-06 | Output | `_sanitize_md` for Markdown injection | E |
| VULN-07 | Disclosure | AI trailer: record key only, not value | I |
| VULN-12 | Input | Root commit fallback (dynamic empty tree hash) | T |
| HACK-03 | Output | Crypto-random heredoc delimiter in bash | T, E |
| HACK-04 | DoS | Streaming diff hash (64KB chunks) | D |
| HACK-08 | Disclosure | Strip URL credentials from remote | I |
| HACK-11 | Input | Detect null SHA on first push | T |
| R3-01 | Output | Path traversal prevention (relative_to) | T, E |
| R3-03 | Disclosure | Strip query params/fragments from URLs | I |
| R3-04 | Output | Post-mkdir symlink recheck (TOCTOU) | T |
| R3-05 | Output | Break GFM autolinks with ZWSP | E |
| R3-06 | Output | UUID in receipt filename + O_EXCL | T |
| R3-09 | Input | Strip Cf chars before AI signal matching | S |
| R3-11 | Input | Allowlist-only core keys in verify | T |
| R3-13 | Output | UUID heredoc delimiter for multiline values | T, E |
| R4-01 | DoS | Cap receipt array length for verify | D |
| R4-02 | Tampering | Reject symlinks for sign + validate JSON | T, I |
| R4-05 | DoS | Max receipt file size (50 MB) | D |
| R4-06 | Output | O_EXCL for Sigstore bundle files | T |
| R4-07 | Disclosure | Sanitize Sigstore error messages | I |
| R4-09 | Supply chain | Pin Sigstore version range | T |
| R4-10 | Output | Explicit 0o644 perms on bundle files | T |
| R5-01 | Input | Targeted bidi/dangerous codepoint stripping | S, E |
| R5-02 | Disclosure | Truncate git stderr (200 chars) | I |
| R5-03 | Tampering | Constant-time hash comparison (hmac) | S |
| R5-04 | Output | GitHub output key validation (no injection) | T, E |
| R5-07 | Tampering | Reject symlinks in verify_receipt_file | T |
| R5-08 | DoS | Timeout enforcement in streaming diff hash | D |
| R5-10 | Output | Strip terminal escape sequences | E |
| R5-13 | DoS | Max file size for signature verification | D |
| R5-15 | Input | Remove empty tree SHA constant | T |
| R5-16 | DoS | Git subprocess timeout (300s) | D |
| R6-01 | Input | Guard verify_receipt against non-dict input | D |
| R6-02 | Input | Encode to bytes before hmac.compare_digest | D |
| R6-03 | Output | Use heredoc when value contains `<<` | T, E |
| R6-04 | Input | Reject `<<` in GitHub output keys (heredoc ambiguity) | T, E |
| R7-01 | Input | `--no-ext-diff`/`--no-textconv` blocks malicious diff drivers | T |
| R7-02 | Input | `--no-mailmap` prevents masking AI bot identity | S |
| R7-03 | Input | Confusable character map + NFKC for homoglyph detection | S, E |
| R7-04 | Output | Full ECMA-48 CSI final byte range in escape stripper | E |
| R7-05 | Output | Sanitize `receipt_id` and `sha` in GitHub summary | T, E |
| R7-06 | DoS | 1 MB size limit on GitHub step summary | D |
| R7-07 | DoS | `proc.wait()` after `proc.kill()` prevents zombie leak | D |
| R8-01 | Input | action.yml uses `python -m aiir` with PYTHONPATH (fixes ModuleNotFoundError) | E |
| R9-01 | Disclosure | Catch `TimeoutExpired` in main() — clean message, no path leaks | I |
| R9-02 | DoS | Timeout on root-commit `hash-object` subprocess | D |
| R9-03 | Output | Friendly error when `git` binary not found | I |
| R9-04 | DoS | RecursionError guard in `verify_receipt` | D |
| R11-01 | Output | Sanitize all fields (receipt_id, sha, timestamp) in pretty formatter | E |
| R11-02 | Input | Validate `jsonrpc: "2.0"` field in MCP server | T |
| R12-01 | Provenance | URI-based tool identifier for SLSA/in-toto compatibility | T |
| R13-03 | Output | `files_capped: true` indicator when file list truncated | I |
| R14-01 | Observability | Structured logging via `logging` module + `--verbose` flag | D |
| R15-01 | Input | Removed inaccurate confusable entries (ґ→g, Ԑ→q) | S |
| R7-TECH-02 | Input | Validate receipt type and schema in `verify_receipt` | T |
| R7-TECH-04 | Output | Coerce `files_changed` to int in `format_receipt_pretty` | E |
| R7-SEC-02 | Supply chain | Sigstore pin in pyproject.toml matches action.yml | T |
| R7-SEC-04 | Disclosure | Redact filesystem paths in `_run_git` stderr | I |
| R8-TECH-01 | Output | Sanitize signal strings in `format_receipt_pretty` | E |
| R8-TECH-03 | Output | Strip PM (ESC ^) and APC (ESC _) sequences | E |
| R8-SEC-02 | Disclosure | Redact paths in MCP `_sanitize_error` | I |
| R8-SEC-03 | Input | Validate receipt version field format | T |
| R9-SEC-01 | Output | Validate signal list item types and cap length in pretty formatter | E |
| R9-SEC-02 | DoS | Cap `set_github_output` value size at 4 MB | D |
| R9-SEC-03 | Tampering | Check intermediate path components for symlinks in MCP verify | T |
| R9-SEC-04 | DoS | File size cap for `sign_receipt_file` (50 MB) | D |
| R9-SEC-05 | Input | Hardened MCP tool descriptions with security constraints | S |
| R9-TECH-01 | Disclosure | Redact paths in `verify_receipt_signature` errors | I |
| R9-TECH-02 | DoS | Close stdout pipe in `_hash_diff_streaming` | D |
| R9-TECH-03 | Input | Strip Cf from author/committer fields in `detect_ai_signals` | S |
| R9-TECH-04 | Output | Strip SOS (ESC X) and DCS (ESC P) sequences | E |
| R9-PUB-02 | Output | Exit code documentation in CLI `--help` epilog | I |
| I-05-FIX | Privacy | `--redact-files` flag omits file paths from receipts | I |
| R-03-FIX | Output | CLI warns when generating unsigned receipts | R |
| D-07-FIX | DoS | Explicit JSON depth limit (64 levels) in `_check_json_depth` | D |
| R10-SEC-01 | Supply chain | action.yml `-P` flag prevents CWD module shadowing | T, E |
| R10-SEC-02 | Privacy | MCP handler supports `redact_files` parameter | I |
| R10-SEC-03 | Disclosure | `_strip_url_credentials` returns safe placeholder on exception | I |
| R10-SEC-04 | Input | Removed dead code in MCP `_safe_verify_path` | T |
| R10-PUB-01 | Output | README security stats corrected to actual counts | I |
| R10-PUB-02 | Output | CHANGELOG false `<details>` removal claim corrected | I |
| R10-ACAD-01 | Tampering | R-03 reclassified "Partially mitigated" for DREAD consistency | R |
| R10-ACAD-02 | DoS | D-07 recommendation updated to reflect existing depth check | D |
| R10-R-01 | DoS | `_check_json_depth` converted from recursive to iterative | D |
| R10-R-02 | DoS | `_hash_diff_streaming` cleanup on exception path | D |
| R10-R-03 | DoS | `main()` catches `OSError` from `get_repo_root()` and receipt generation | D, I |
| R11-SEC-01 | Output | `_sanitize_md` escapes `&` → `&amp;` to block HTML entity pre-encoding bypass | E |
| R11-SEC-02 | Output | Unterminated C1 control strings (DCS/SOS/PM/APC) stripped even without ST | E |
| R11-SEC-03 | Output | DEL (U+007F) and 8-bit C1 controls (U+0080–U+009F) stripped from terminal output | E |
| R11-SEC-04 | DoS | `set_github_output` value cap uses byte count (UTF-8) not char count | D |
| R11-TECH-01 | DoS | `format_receipt_pretty` catches `OverflowError` from `int(float('inf'))` | D |
| R11-PUB-01 | Maintenance | Removed dead `_current` parameter from `_check_json_depth` | D |
| R11-SEC-05 | Input | `verify_receipt` validates `schema` field type before `.startswith()` call | T |
| R12-SEC-01 | Output | `_sanitize_md` escapes GFM emphasis/strikethrough markers (`*`, `_`, `~`) | E |
| R12-SEC-02 | Input | MCP `serve_stdio` validates `params` type per JSON-RPC 2.0 §4.2 | T |
| R12-SEC-03 | Input | `get_commit_info` validates SHA format from git output (`^[0-9a-f]{40,64}$`) | T |
| R12-TECH-01 | DoS | `_hash_diff_streaming` closes `proc.stdout` on all paths via `finally` | D |
| R12-TECH-02 | Input | Extracted `_normalize_for_detection` helper — consistent Cf/NFKC/confusable/Mn/Me pipeline | S |
| R12-ACAD-01 | Documentation | THREAT_MODEL Section 7 note clarified: batch IDs vs round IDs naming convention | I |
| R12-PUB-01 | Documentation | `_sanitize_md` docstring updated to list all escaped characters | I |
| R13-SEC-01 | Input | MCP `handle_tools_call` validates `arguments` type — non-dict coerced to `{}` | T |
| R13-SEC-02 | Output | `_sanitize_md` escapes `\` before all `\`-based escapes — blocks `\|` table breakout and `\*`/`\_`/`\~` emphasis bypass | E |
| R13-TECH-01 | Output | `format_receipt_pretty` guards non-list `signals_detected` — prevents `TypeError` crash on `dict[:3]` | D |
| R13-TECH-02 | DoS | `_hash_diff_streaming` final `proc.wait()` guarded with kill fallback — prevents zombie on timeout | D |
| R14-SEC-01 | Input | `verify_receipt` guards `commit` field type — non-dict values (string/list/int/None) no longer crash `.get().get()` chain | T |
| R14-SEC-02 | Input | `format_receipt_pretty` / `format_github_summary` guard `commit` and `ai_attestation` types — non-dict values coerced to `{}` | T |
| R14-TECH-01 | DoS | `_hash_diff_streaming` tracks cleanup-kill — returns valid hash when process killed after successful data read | D |
| R14-PUB-01 | Documentation | README/CHANGELOG/THREAT_MODEL test count corrected to include fuzz tests (was unit-only) | I |
| R15-SEC-01 | Input | `format_receipt_pretty` guards `author` sub-field type — non-dict values coerced to `{}` | T |
| R15-SEC-02 | Output | `write_receipt` sanitizes SHA in filename — path traversal via crafted SHA prevented | T, E |
| R15-TECH-01 | Maintenance | `unicodedata` import moved to module level — eliminates repeated inline imports | I |
| R15-PUB-01 | Documentation | README/CHANGELOG/THREAT_MODEL stats updated for Round 15 | I |
| R16-UX-01 | UX | `--pretty` and `--output` now independent — both flags work together | E |
| R16-UX-02 | UX | `ValueError` from `write_receipt` caught in `main()` — clean error instead of traceback | I |
| R16-UX-03 | UX | `--verbose` and `--quiet` mutually exclusive via argparse | I |
| R17-UX-01 | UX | All error messages use ❌ emoji + 💡 actionable hint | I |
| R17-UX-02 | UX | "No commits" message shows 🤷 + context-specific hint | I |
| R17-UX-03 | UX | Summary uses ✅/🤖/🖊️ emoji; unsigned tip uses 📝 prefix | I |
| R17-UX-04 | UX | `--help` epilog includes 8 usage examples | I |
| R17-UX-05 | UX | `_FriendlyParser` suggests closest flag on typo (difflib) | I |
| R17-UX-06 | UX | Verify pass says "All good!"; fail includes 💡 hint | I |
| R18-SEC-01 | Output | `_FriendlyParser` sanitises user tokens with `_strip_terminal_escapes` | E |
| R18-SEC-02 | Output | `_run_git` stderr and range hint strip terminal escapes | E, I |
| R18-TECH-01 | Maintenance | `ai_count` hoisted — eliminates duplicate computation | D |
| R18-TECH-02 | Output | Verify-fail on arrays shows per-receipt error detail | I |
| R18-ACAD-01 | Documentation | Section 7 table updated with R16/R17/R18 controls + corrected totals | I |
| R18-ACAD-02 | Documentation | Document version header updated to 2.4.0 | I |
| R18-PUB-01 | UX | `_FriendlyParser` always uses friendly ❌ format (no fallthrough) | E |
| R18-PUB-02 | Documentation | DREAD summary round count updated to 18 | I |
| R19-PUB-01 | Encoding | All terminal emoji replaced with `_e()` encoding-safe helper — ASCII fallback on cp1252/cp437/ASCII | E |
| R19-PUB-02 | Encoding | Box-drawing chars replaced with `_b()` encoding-safe helper — ASCII fallback on cp1252/ASCII/latin-1 | E |
| R20-UX-01 | UX | Context-aware verify-failure tips — file-not-found, invalid JSON, symlink, too-large each get a specific hint | I |
| R20-UX-02 | UX | Empty repo (no commits) shows friendly message instead of raw git stderr | I |
| R20-UX-03 | UX | Multi-receipt stdout wrapped in JSON array — single receipt stays as plain object (backward compat) | I |
| R21-SEC-01 | Output | `set_github_summary` truncation now byte-aware — prevents 3× overflow with multi-byte UTF-8 | E |
| R21-SEC-02 | Subprocess | `_run_git` + `_hash_diff_streaming` set `GIT_TERMINAL_PROMPT=0`, `GIT_ASKPASS=` — prevents 300 s auth hang | E |
| R21-PUB-01 | Detection | AI_SIGNALS expanded: +Amazon Q, +CodeWhisperer, +Devin (3 specific patterns), +Gemini Code Assist, +Google Gemini, +Tabnine, +codegen by gemini (20 → 30) | E |
| R21-PUB-02 | Detection | Bot patterns expanded: +devin[bot], +devin-bot, +amazon-q, +tabnine, +gemini[bot], +gemini-bot (7 → 13) | E |
| R21-TECH-01 | Subprocess | `_run_git` + `_hash_diff_streaming` pass `--no-optional-locks` — prevents CI lock contention on network FS | D |

**142 total security controls.**

## 8. Fuzzing Coverage Map

Property-based tests (Hypothesis) covering each security-critical function:

| Function | Tests | Properties Verified |
|----------|-------|-------------------|
| `_sanitize_md` | 8 | No crashes; no raw HTML; no unescaped pipes/backticks; no bidi; no C0 controls; autolinks broken; no raw HTML entities |
| `_validate_ref` | 4 | No unexpected crashes; option-like rejected; NUL rejected; overlong rejected |
| `set_github_output` | 4 | No crashes; valid keys accepted; no extra entries; dangerous keys (incl. `<<`) rejected |
| `_strip_terminal_escapes` | 6 | No crashes; no ESC sequences; no BEL; no control chars (except tab); printable text preserved; no C1 controls |
| `_canonical_json` | 4 | Valid JSON output; deterministic; no whitespace; sorted keys |
| `detect_ai_signals` | 2 | No crashes; no false positives on innocent text |
| `verify_receipt` | 3 | No crashes on arbitrary strings; no crashes on random dicts; valid receipts always verify |
| `_strip_url_credentials` | 3 | No crashes; no credentials in output; credentials actually stripped |
| `format_receipt_pretty` | 2 | No crashes; no escape sequences in output |
| `verify_receipt_file` | 2 | No crashes on random bytes; no crashes on random JSON |
| `format_github_summary` | 2 | No raw HTML in data rows; no crashes on arbitrary fields |
| Regressions | 2 | Bidi regression; GitHub output injection regression |
| Homoglyph detection | 2 | Substitution detected; bot name homoglyph detected |
| CSI escape range | 1 | All CSI final bytes (0x40–0x7E) stripped |
| Emphasis escaping | 1 | No unescaped `*`, `_`, `~` after `_sanitize_md` |
| Normalize helper | 1 | No crashes; no Cf/Mn/Me chars in output |
| Backslash escape | 2 | All `|` preceded by odd backslash count; all `*`/`_`/`~` preceded by odd backslash count |
| `verify_receipt` nested types | 1 | Never crashes regardless of `commit`/`ai_attestation` field types |
| `format_receipt_pretty` nested types | 1 | Never crashes regardless of `commit`/`ai_attestation` field types |
| `format_receipt_pretty` author types | 1 | Never crashes regardless of `author` sub-field type (R15-SEC-01) |

**Total**: 52 property-based fuzz tests × 500 examples each = **26,000
inputs per test run**.

---

## 9. Recommendations

### 9.1 Enable by Default

- **Sigstore signing** (`sign: true`): Converts receipts from tamper-evident
  to tamper-proof.  Recommended for any compliance-critical deployment.

### 9.2 Future Hardening

| Priority | Recommendation | Addresses |
|----------|---------------|-----------|
| P1 | Add `--strict-ai-detection` mode with configurable signal list | S-02 (homoglyphs), R-01 |
| P1 | Integrate with GitHub Artifact Attestations API for immutable provenance | R-03 |
| P2 | Add JSON Schema validation for receipt structure (structural validation beyond existing depth check) | D-07 |
| P2 | Consider `resource.setrlimit` to cap memory/CPU in CLI process | D-02 |
| P3 | Add SBOM-style dependency attestation for the action itself | Supply chain |
| P3 | Fuzzing in CI with extended examples (10K+) and Hypothesis CI profile | All |

### 9.3 Operational

- Pin `actions/setup-python` and `actions/upload-artifact` to **full SHA** (already done ✅)
- Rotate any PATs stored in repository secrets on a 90-day cycle
- Review Sigstore transparency log entries periodically for unexpected signing events

---

## 10. Changelog

| Version | Date | Changes |
|---------|------|---------|
| 3.0.0 | 2026-03-07 | v1.0.0 release — 142 security controls, 504 tests, 52 fuzz tests; 36 confusable mappings, 31 AI signals; comprehensive STRIDE/DREAD analysis |

