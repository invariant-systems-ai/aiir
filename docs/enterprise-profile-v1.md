# AIIR Enterprise Protected Branch Profile v1.0

> **Status**: Draft
> **Version**: 1.0.0
> **Date**: 2026-03-11
> **Spec Dependency**: AIIR Spec v1.1.0
> **Schema**: [`enterprise_profile.v1.schema.json`](../schemas/enterprise_profile.v1.schema.json)

---

## 1. Purpose

This profile defines a set of **deterministic, machine-evaluable rules** for
protected branches that consume AIIR commit receipts, review receipts, and
release Verification Summary Attestations (VSAs). Each rule maps a previously
prose-stated enterprise requirement to an exact combination of artifact fields
and a boolean pass/fail predicate.

A conforming policy engine (OPA/Rego, Kyverno, Gatekeeper, or any
JSON-evaluating system) can enforce this profile without interpreting English
prose. The same evidence bundle plus the same profile digest MUST always
produce the same PASS/FAIL result, and an independent verifier MUST be able
to replay it.

### 1.1 Design Principles

1. **Typed claims, not prose.** Every enforceable sentence becomes one of four
   rule types: schema rule, integrity rule, coverage/accounting rule, or policy
   predicate.
2. **Artifacts are the source of truth.** Rules consume fields from three
   artifact families — `commit_receipt.v1/v2`, `review_receipt.v1`, and
   `verification_summary.v1` — not human-readable descriptions of those
   artifacts.
3. **Extensions are not policy inputs unless signed.** Per SPEC §8, unsigned
   extension fields (including `agent_attestation`) MUST NOT appear as inputs
   to any rule at Trust Tier 1. At Tier 2+, the Sigstore signature covers the
   full receipt including extensions, making them admissible.
4. **Declared provenance, not universal inference.** This profile gates on what
   the evidence records, not on what was not recorded. Detection coverage limits
   are documented, not hidden.

### 1.2 Scope

This profile applies to a single protected branch (typically `main`) in one
repository. It governs:

- Individual commit receipt integrity
- Review receipt requirements per authorship class
- Release-scoped verification and coverage
- Trust tier minimums
- Aggregate accounting thresholds

It does NOT govern:

- Detection of undeclared AI usage (inline completions, unattributed copy-paste)
- Repository access control (handled by the hosting platform)
- CI/CD pipeline security (handled by platform rulesets)

---

## 2. Artifact Families

Each rule references fields from one or more of these three artifact types.
Field names use dot-path notation relative to the receipt root.

| Artifact | Schema | Type field | Hash-relevant fields |
|----------|--------|------------|----------------------|
| **Commit Receipt** | `aiir/commit_receipt.v1` or `v2` | `aiir.commit_receipt` | `type`, `schema`, `version`, `commit`, `ai_attestation`, `provenance` (6 CORE_KEYS) |
| **Review Receipt** | `aiir/review_receipt.v1` | `aiir.review_receipt` | `type`, `schema`, `version`, `reviewed_commit`, `reviewer`, `review_outcome`, `provenance` |
| **Release VSA** | `verification_summary.v1` (in-toto Statement v1) | `https://slsa.dev/verification_summary/v1` | `verifier`, `policy`, `inputAttestations`, `verificationResult`, `coverage`, `evaluation` |

---

## 3. Rule Catalog

Twelve deterministic rules organized into four categories. Every rule has a
unique identifier, a type, the exact artifact fields it consumes, and a
boolean predicate.

### Category A — Schema Rules

These rules enforce structural validity. They are preconditions for all
subsequent rules.

#### Rule EPB-001: Commit Receipt Schema Validity

| Property | Value |
|----------|-------|
| **ID** | `EPB-001` |
| **Type** | Schema |
| **Applies to** | Every commit receipt in the ledger |
| **Consumes** | Entire receipt object |
| **Predicate** | Receipt validates against `commit_receipt.v1.schema.json` (or `v2`). All required fields present with correct types. `type == "aiir.commit_receipt"`. `schema` starts with `"aiir/"`. `version` matches SemVer pattern. |
| **Fail** | Any commit in the range has no receipt, or its receipt fails schema validation. |

#### Rule EPB-002: Review Receipt Schema Validity

| Property | Value |
|----------|-------|
| **ID** | `EPB-002` |
| **Type** | Schema |
| **Applies to** | Every review receipt in the ledger |
| **Consumes** | Entire receipt object |
| **Predicate** | Receipt validates against `review_receipt.v1.schema.json`. All required fields present. `type == "aiir.review_receipt"`. `review_outcome ∈ {"approved", "rejected", "commented"}`. |
| **Fail** | Any review receipt in the ledger fails schema validation. |

### Category B — Integrity Rules

These rules enforce content-addressing and cryptographic integrity.

#### Rule EPB-003: Content Hash Integrity

| Property | Value |
|----------|-------|
| **ID** | `EPB-003` |
| **Type** | Integrity |
| **Applies to** | Every commit receipt and review receipt |
| **Consumes** | `content_hash`, `receipt_id`, all CORE_KEYS |
| **Predicate** | `content_hash == "sha256:" + hex(SHA-256(canonical_json(core_keys)))` AND `receipt_id == "g1-" + hex(SHA-256(canonical_json(core_keys)))[:32]`. Comparison MUST be constant-time per SPEC §9.2. |
| **Fail** | Any receipt has a mismatched `content_hash` or `receipt_id`. |

#### Rule EPB-004: Minimum Trust Tier

| Property | Value |
|----------|-------|
| **ID** | `EPB-004` |
| **Type** | Integrity |
| **Applies to** | Every commit receipt |
| **Consumes** | Presence of Sigstore bundle (`.sigstore` sidecar or embedded `signatures` field) |
| **Parameter** | `min_trust_tier` ∈ {1, 2, 3}. Default: **2** (signed). |
| **Predicate** | If `min_trust_tier >= 2`: receipt MUST have a valid Sigstore signature with a Rekor transparency log entry. If `min_trust_tier == 3`: receipt MUST additionally be wrapped in an in-toto Statement v1 envelope. |
| **Fail** | Any receipt is below the required trust tier. |

#### Rule EPB-005: DAG Binding (v2 Envelope)

| Property | Value |
|----------|-------|
| **ID** | `EPB-005` |
| **Type** | Integrity |
| **Applies to** | Every commit receipt |
| **Consumes** | `commit.tree_sha`, `commit.parent_shas`, `commit.sha` |
| **Parameter** | `require_dag_binding`: boolean. Default: **true**. |
| **Predicate** | If enabled: `schema == "aiir/commit_receipt.v2"` AND `commit.tree_sha` matches the git tree SHA for this commit AND `commit.parent_shas` matches the parent SHAs in the git DAG. |
| **Fail** | Receipt uses v1 schema (no DAG fields) or DAG fields don't match the live git object store. Prevents receipt laundering. |

### Category C — Coverage and Accounting Rules

These rules enforce aggregate properties over a commit range.

#### Rule EPB-006: Receipt Coverage

| Property | Value |
|----------|-------|
| **ID** | `EPB-006` |
| **Type** | Coverage |
| **Applies to** | The commit range being merged |
| **Consumes** | VSA `coverage.commitsTotal`, `coverage.receiptsFound`, `coverage.receiptsMissing`, `coverage.coveragePercent` |
| **Parameter** | `min_coverage_percent`: number 0–100. Default: **100**. |
| **Predicate** | `coverage.coveragePercent >= min_coverage_percent` AND `coverage.receiptsMissing == 0` (when `min_coverage_percent == 100`). |
| **Fail** | Any commit in the merge range lacks a receipt. |

#### Rule EPB-007: AI Authorship Cap

| Property | Value |
|----------|-------|
| **ID** | `EPB-007` |
| **Type** | Accounting |
| **Applies to** | The full ledger on the protected branch |
| **Consumes** | `ai_attestation.authorship_class` across all commit receipts, VSA `constraints.maxAiPercent` |
| **Parameter** | `max_ai_percent`: number 0–100. Default: **50**. |
| **Predicate** | Count of receipts where `ai_attestation.authorship_class ∈ {"ai_assisted", "ai+bot"}` divided by total receipts ≤ `max_ai_percent / 100`. |
| **Fail** | Merging this PR would push the aggregate AI percentage above the cap. |

#### Rule EPB-008: No Invalid Receipts

| Property | Value |
|----------|-------|
| **ID** | `EPB-008` |
| **Type** | Coverage |
| **Applies to** | The release VSA |
| **Consumes** | VSA `evaluation.invalidReceipts`, `evaluation.policyViolations` |
| **Predicate** | `evaluation.invalidReceipts == 0` AND `evaluation.policyViolations == 0`. |
| **Fail** | The VSA reports any integrity failures or policy violations. |

### Category D — Policy Predicates

These rules enforce behavioral policies that map enterprise requirements
to receipt fields.

#### Rule EPB-009: Human Review Required for AI-Assisted Changes

| Property | Value |
|----------|-------|
| **ID** | `EPB-009` |
| **Type** | Policy Predicate |
| **Applies to** | Every commit receipt where `ai_attestation.authorship_class ∈ {"ai_assisted", "ai+bot"}` |
| **Consumes** | `commit_receipt.commit.sha`, `commit_receipt.ai_attestation.authorship_class`, `review_receipt.reviewed_commit.sha`, `review_receipt.reviewer`, `review_receipt.review_outcome` |
| **Predicate** | For each qualifying commit receipt: there EXISTS at least one `review_receipt` where `reviewed_commit.sha == commit.sha` AND `review_outcome == "approved"` AND `reviewer.email != commit_receipt.commit.author.email` (reviewer is not the commit author). At Trust Tier 2+, the review receipt MUST also be signed. |
| **Fail** | Any AI-assisted or AI+bot commit reaches the protected branch without an approved review receipt from a non-author reviewer. |

This is the deterministic encoding of "AI-assisted code must be reviewed
by a human" — the single most common enterprise prose rule.

#### Rule EPB-010: Bot Commits Require Receipt and Provenance Match

| Property | Value |
|----------|-------|
| **ID** | `EPB-010` |
| **Type** | Policy Predicate |
| **Applies to** | Every commit receipt where `ai_attestation.authorship_class == "bot"` |
| **Consumes** | `ai_attestation.is_bot_authored`, `ai_attestation.bot_signals_detected`, `provenance.repository`, `provenance.tool` |
| **Predicate** | `is_bot_authored == true` AND `len(bot_signals_detected) >= 1` AND `provenance.repository` matches the repository URL of the protected branch AND `provenance.tool` starts with `"https://"`. |
| **Fail** | A bot-authored commit has no bot signals, mismatched provenance, or non-URI tool identifier. |

#### Rule EPB-011: VSA Policy Digest Binding

| Property | Value |
|----------|-------|
| **ID** | `EPB-011` |
| **Type** | Policy Predicate |
| **Applies to** | The release VSA gate |
| **Consumes** | VSA `policy.uri`, `policy.digest.sha256` |
| **Parameter** | `expected_policy_digest`: hex string (64 chars). |
| **Predicate** | `policy.digest.sha256 == expected_policy_digest`. The policy used for evaluation MUST be the exact policy the branch protection expects. Prevents policy substitution (evaluating against a permissive policy and presenting the passing VSA to a strict gate). |
| **Fail** | The VSA was produced with a different policy than the one pinned in the branch rule. |

#### Rule EPB-012: VSA Verifier Identity

| Property | Value |
|----------|-------|
| **ID** | `EPB-012` |
| **Type** | Policy Predicate |
| **Applies to** | The release VSA gate |
| **Consumes** | VSA `verifier.id`, `verifier.version.aiir`, `verificationResult` |
| **Parameter** | `trusted_verifiers`: array of URI strings. Default: `["https://invariantsystems.io/verifiers/aiir"]`. |
| **Predicate** | `verifier.id ∈ trusted_verifiers` AND `verificationResult == "PASSED"`. |
| **Fail** | The VSA was produced by an unrecognized verifier, or the verification result is FAILED. |

---

## 4. Rule Summary Matrix

| ID | Category | Rule | Artifact(s) | Key Fields | Default Parameter |
|----|----------|------|-------------|------------|-------------------|
| EPB-001 | Schema | Commit receipt validity | Commit Receipt | (all) | — |
| EPB-002 | Schema | Review receipt validity | Review Receipt | (all) | — |
| EPB-003 | Integrity | Content hash match | Commit + Review | `content_hash`, `receipt_id`, CORE_KEYS | — |
| EPB-004 | Integrity | Trust tier minimum | Commit Receipt | Sigstore bundle | `min_trust_tier: 2` |
| EPB-005 | Integrity | DAG binding | Commit Receipt | `commit.tree_sha`, `commit.parent_shas` | `require_dag_binding: true` |
| EPB-006 | Coverage | Receipt coverage | VSA | `coverage.*` | `min_coverage_percent: 100` |
| EPB-007 | Accounting | AI authorship cap | Commit Receipt (agg) | `ai_attestation.authorship_class` | `max_ai_percent: 50` |
| EPB-008 | Coverage | No invalid receipts | VSA | `evaluation.invalidReceipts`, `evaluation.policyViolations` | — |
| EPB-009 | Predicate | Human review for AI changes | Commit + Review | `authorship_class`, `reviewed_commit.sha`, `reviewer`, `review_outcome` | — |
| EPB-010 | Predicate | Bot provenance match | Commit Receipt | `is_bot_authored`, `bot_signals_detected`, `provenance.*` | — |
| EPB-011 | Predicate | VSA policy digest pin | VSA | `policy.uri`, `policy.digest.sha256` | `expected_policy_digest` (required) |
| EPB-012 | Predicate | VSA verifier identity | VSA | `verifier.id`, `verificationResult` | `trusted_verifiers: [invariantsystems.io]` |

---

## 5. Evaluation Order and Short-Circuit Semantics

Rules MUST be evaluated in category order: A → B → C → D.

1. **Schema rules (A)** gate all subsequent evaluation. If EPB-001 or EPB-002
   fails, the remaining rules are not evaluated and the profile result is FAIL.
2. **Integrity rules (B)** gate coverage and predicate evaluation. If any
   integrity rule fails, evaluation stops with FAIL.
3. **Coverage rules (C)** and **policy predicates (D)** are evaluated
   independently. All must pass for the profile to pass.

Short-circuit on category failure avoids evaluating policy predicates
against tampered or malformed artifacts.

---

## 6. Profile Configuration Schema

A profile instance is a JSON document conforming to
[`enterprise_profile.v1.schema.json`](../schemas/enterprise_profile.v1.schema.json).

Example — strict enterprise configuration:

```json
{
  "profile": "aiir/enterprise_protected_branch.v1",
  "version": "1.0.0",
  "description": "Production branch — strict controls",
  "rules": {
    "EPB-001": { "enabled": true },
    "EPB-002": { "enabled": true },
    "EPB-003": { "enabled": true },
    "EPB-004": { "enabled": true, "min_trust_tier": 2 },
    "EPB-005": { "enabled": true, "require_dag_binding": true },
    "EPB-006": { "enabled": true, "min_coverage_percent": 100 },
    "EPB-007": { "enabled": true, "max_ai_percent": 50 },
    "EPB-008": { "enabled": true },
    "EPB-009": { "enabled": true },
    "EPB-010": { "enabled": true },
    "EPB-011": { "enabled": true, "expected_policy_digest": "a1b2c3..." },
    "EPB-012": { "enabled": true, "trusted_verifiers": ["https://invariantsystems.io/verifiers/aiir"] }
  }
}
```

Rules that are `"enabled": false` are skipped during evaluation. The profile
MUST contain all twelve rule IDs; omitting a rule is a schema validation error.

The profile document itself is content-addressed in the VSA:
`policy.digest.sha256` in the VSA predicate MUST equal
`SHA-256(canonical_json(profile_document))`.

---

## 7. Enforcement Model

### 7.1 CI/CD Gate (Primary)

The profile is evaluated during `aiir --verify-release --emit-vsa`:

1. AIIR reads the profile from `.aiir/enterprise-profile.json` (or
   `--profile <path>`).
2. AIIR evaluates all enabled rules against the receipt ledger.
3. AIIR emits a VSA with `verificationResult: "PASSED"` or `"FAILED"`.
4. The CI system's branch protection checks the VSA (via `aiir/verify`
   check run, commit status, or artifact attestation).

### 7.2 External Policy Engine (Secondary)

For environments using OPA, Kyverno, or Gatekeeper:

1. Export the profile as a Rego/CEL policy bundle (planned: `aiir --export-opa`).
2. The policy engine evaluates the receipt bundle and profile at admission time.
3. The VSA is the portable proof-of-evaluation: downstream gates trust the
   signed VSA rather than replaying every receipt.

### 7.3 Platform Integration

| Platform | Gate mechanism | Artifact checked |
|----------|---------------|------------------|
| GitHub | Required status check (`aiir/verify`) | VSA `verificationResult` |
| GitLab | External status check or MR approval rule | VSA `verificationResult` |
| Azure DevOps | Branch policy (build validation) | VSA `verificationResult` |
| Kubernetes | Admission webhook (Kyverno/Gatekeeper) | Signed VSA attestation |

---

## 8. Detection Scope Acknowledgment

This profile operates on **declared provenance**. Per AIIR Spec §8 and the
project's detection documentation:

- `heuristic_v2` detects declared AI signals in commit metadata (trailers,
  author patterns, message patterns).
- It does NOT detect: inline completions without metadata, unattributed
  copy-paste, squash-merged AI branches with clean messages, or amended
  commits that remove AI trailers.

This is intentional. The profile enforces the integrity and completeness of
**what was recorded**, not the completeness of all AI involvement. Enterprise
policies that require disclosure of all AI usage should mandate tool-level
integration (AIIR GitHub Action, GitLab CI component, or MCP server) rather
than relying on post-hoc heuristic detection.

---

## 9. Future Extensions (Informative)

These items are not part of the v1.0 profile but are anticipated for v1.1:

1. **Signed Agent Predicate (EPB-013)**: When `agent_attestation` is promoted
   to a first-class signed predicate (or hashed field set), add rules for
   tool allowlists (`tool_id ∈ approved_tools`), model family restrictions
   (`model_class ∈ approved_models`), and managed session requirements.

2. **OSCAL Control Mapping**: Machine-readable mapping of EPB rules to
   NIST 800-53, SOC 2 TSC, EU AI Act, and ISO 27001 controls via
   OSCAL catalog/profile/component-definition format.

3. **Cross-Repository Aggregate**: Extend EPB-007 (AI authorship cap)
   to operate across multiple repositories under a single organizational
   policy.

4. **SCITT Transparency Receipt**: When the SCITT architecture RFC is
   published, add a rule requiring registration of the VSA with a
   transparency service.

---

## 10. Conformance

An implementation conforms to this profile if:

1. It can parse the profile configuration JSON and validate it against
   `enterprise_profile.v1.schema.json`.
2. It evaluates all twelve rules in the specified order.
3. It produces a VSA whose `policy.digest.sha256` matches the SHA-256
   of the canonical JSON encoding of the profile configuration.
4. Given identical inputs (receipt ledger, profile configuration, git
   object store), it produces an identical `verificationResult`.

---

## Appendix A: Rule Type Definitions

| Rule Type | Definition | Example |
|-----------|-----------|---------|
| **Schema** | Receipt validates against its JSON Schema. Pure structural check. | EPB-001, EPB-002 |
| **Integrity** | Cryptographic invariant holds. Content hash, signature, or DAG binding is correct. | EPB-003, EPB-004, EPB-005 |
| **Coverage / Accounting** | Aggregate numeric property over a commit range or ledger meets a threshold. | EPB-006, EPB-007, EPB-008 |
| **Policy Predicate** | Boolean condition over fields from one or more artifacts, parameterized by the profile. | EPB-009 – EPB-012 |

## Appendix B: Mapping to Common Enterprise Requirements

| Enterprise Requirement (prose) | Profile Rule(s) | Gate artifact |
|-------------------------------|-----------------|---------------|
| "Every commit must have a receipt" | EPB-001, EPB-006 | Commit Receipt, VSA |
| "Receipts must be tamper-proof" | EPB-003, EPB-004 | Commit Receipt |
| "AI-assisted code must be reviewed by a human" | EPB-009 | Commit Receipt + Review Receipt |
| "No more than 50% AI-authored commits" | EPB-007 | Commit Receipt (aggregate) |
| "Release must pass policy evaluation" | EPB-008, EPB-011, EPB-012 | VSA |
| "Bot commits must have verifiable provenance" | EPB-010 | Commit Receipt |
| "Prevent receipt laundering across branches" | EPB-005 | Commit Receipt (v2) |
| "Policy cannot be silently substituted" | EPB-011 | VSA |
| "Only trusted verifiers accepted" | EPB-012 | VSA |
