# AIIR Specification Governance

**Document version**: 1.0.0  
**Spec covered**: AIIR Commit Receipt Specification v1.1.x and later  
**Status**: Active  
**Last updated**: 2026-03-11  
**Maintainer**: Invariant Systems, Inc.

> This document defines how the AIIR receipt format specification is maintained,
> versioned, and extended. It is the binding reference for anyone building a
> conforming implementation, proposing a change, or registering an extension.

---

## Table of Contents

1. [Scope](#1-scope)
2. [Versioning policy](#2-versioning-policy)
3. [Change control process](#3-change-control-process)
4. [Compatibility guarantees](#4-compatibility-guarantees)
5. [Extension mechanism](#5-extension-mechanism)
6. [Extension registry](#6-extension-registry)
7. [Release cadence](#7-release-cadence)
8. [Working group structure](#8-working-group-structure)
9. [Decision-making](#9-decision-making)
10. [IP policy and licensing](#10-ip-policy-and-licensing)
11. [Standards-track roadmap](#11-standards-track-roadmap)

---

## 1. Scope

This governance document covers:

- **`SPEC.md`** - the AIIR Commit Receipt Specification
- **`schemas/commit_receipt.v1.schema.json`** and subsequent schema versions
- **`schemas/test_vectors.json`** and **`schemas/cbor_test_vectors.json`**
- **`schemas/conformance-manifest.json`** implementer registry and vector index
- Any future schema versions under `schemas/`

It does **not** cover internal implementation details of the `aiir` reference
implementation, which are governed by normal open-source maintainer discretion.

---

## 2. Versioning Policy

AIIR uses [Semantic Versioning 2.0.0](https://semver.org/) for the specification
independently of the Python package version.

### Spec version anatomy

```text
MAJOR.MINOR.PATCH
  |      |     \-- Clarifications, editorial fixes, non-breaking vector adds
  |      \-------- New optional fields/hooks/conformance levels (compatible)
  \--------------- Breaking changes to semantics/required fields/hashing
```

### Breaking changes (MAJOR)

- Canonical JSON encoding algorithm changes
- `content_hash` or `receipt_id` computation changes
- Removing or renaming REQUIRED fields
- Changing semantics of existing REQUIRED fields
- Removing a conformance level
- CBOR changes that alter existing Level 3 hash outcomes

### Non-breaking changes (MINOR/PATCH)

- Adding OPTIONAL fields
- Adding conformance levels
- Adding test vectors
- Clarifying normative language without behavior change
- Adding extension hooks
- Deprecating (not removing) fields

### Receipt format versioning

The `version` field in a receipt records the implementation version that
generated it, not the spec version.

---

## 3. Change Control Process

All spec changes follow this flow.

### Stage 1 - Proposal

Open a GitHub issue in `invariant-systems-ai/aiir` with label `spec-change`.

A proposal MUST include:

- Problem statement
- Proposed text/schema diff
- Compatibility impact (breaking vs non-breaking)
- Test vector impact
- Reference implementation plan

### Stage 2 - Review

Minimum review windows:

- Non-breaking: 14 days
- Breaking: 30 days

Review criteria:

1. Is the problem real and reproducible?
2. Is the proposal minimal?
3. Is compatibility preserved or major bump justified?
4. Are vector updates sufficient?

### Stage 3 - Acceptance

A proposal is accepted when:

- The review period has elapsed
- At least one Steering member has approved
- No unresolved blocking objections remain

### Stage 4 - Implementation

The implementation PR MUST include:

1. `SPEC.md` updates
2. Schema updates (if applicable)
3. Test vector updates
4. Reference implementation updates
5. `schemas/conformance-manifest.json` updates

The PR must pass full CI before merge.

---

## 4. Compatibility Guarantees

### Receipt durability

Receipts from `aiir >= 1.0.0` remain verifiable by conforming implementations.

### Forward compatibility

Verifiers MUST ignore unknown fields during verification.

### `@v1` stability

`@v1` (GitHub Action) and `receipt@1` (GitLab component) track stable `1.x.y`.

### Deprecation policy

Deprecated fields get at least 12 months notice before removal.

---

## 5. Extension Mechanism

AIIR supports optional extensions under `extensions`.

### Extension structure

```json
{
  "extensions": {
    "com.example.myext": {
      "version": "1.0.0",
      "data": {}
    }
  }
}
```

### Extension rules

1. Keys MUST be namespaced (`com.example.*` style)
2. Extensions MUST NOT alter hash computation
3. Extensions MUST NOT redefine core required fields
4. Verifiers MUST NOT fail on unknown extension keys
5. Extensions MAY version themselves independently

### Registering an extension

Open a PR adding registry metadata in `schemas/conformance-manifest.json` with:

- Extension key
- Description
- Link to extension spec
- Maintainer organization
- Status (`experimental`, `stable`, `deprecated`)

---

## 6. Extension Registry

Current state: no third-party extensions registered.

| Extension key | Description | Status | Maintainer | Spec |
|---|---|---|---|---|
| *(none yet)* | | | | |

---

## 7. Release Cadence

### Spec releases

- PATCH: as needed
- MINOR: typically quarterly or by demand
- MAJOR: only when strictly necessary

### Implementation releases

`aiir` package releases independently; spec updates ship with implementation
releases.

### Notice windows

- MINOR: 14-day notice
- MAJOR: 60-day notice + migration guide

---

## 8. Working Group Structure

### Current structure

- Steering group: Invariant Systems, Inc.
- Primary contact: [noah@invariantsystems.io](mailto:noah@invariantsystems.io)
- External participation: open via GitHub proposals and reviews

### External maintainers/editors

Admission criteria:

1. Sustained spec-review participation
2. Sponsorship by existing Steering member
3. Explicit acceptance of IP policy

Privileges:

- Maintainer status on repository
- Voting rights on MINOR changes (one vote per org)
- Listed editorial authorship

Target: multi-org steering by 2026 Q4.

---

## 9. Decision-Making

### Normal decisions (PATCH/MINOR)

Lazy consensus with Steering approval.

### Major decisions

Major bumps/governance/standards submissions require explicit Steering vote.

### Blocking objections

A blocking objection MUST:

1. Identify a concrete technical issue
2. Propose an alternative
3. Be raised inside the review window

---

## 10. IP Policy and Licensing

- Spec/schemas/vectors contributions are Apache-2.0
- Contributors certify rights to contribute under Apache-2.0
- No CLA currently required
- Extension specs may use separate licenses; registry entries remain Apache-2.0

---

## 11. Standards-Track Roadmap

Current positioning: vendor-led open spec on a transparent standards path.

| Milestone | Target | Status |
|---|---|---|
| Normative spec + conformance suite published | 2026 Q1 | Done |
| `SPEC_GOVERNANCE.md` published | 2026 Q1 | Done |
| CDDL grammar for receipt schema | 2026 Q2 | In planning |
| External spec review | 2026 Q2 | Not started |
| Third-party implementation (non-Python) | 2026 Q2 | Not started |
| External editor/co-maintainer | 2026 Q3 | Not started |
| IETF individual draft | 2026 Q3 | Not started |
| CNCF Sandbox proposal | 2026 Q4 | Not started |

Weekly status is tracked in `docs/standards-readiness.md`.

---

*Invariant Systems, Inc. · Apache-2.0 · [noah@invariantsystems.io](mailto:noah@invariantsystems.io)*
