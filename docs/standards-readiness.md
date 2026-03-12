# AIIR Standards-Readiness Scorecard

> **Update cadence**: weekly, every Monday.
> **Automation**: `.github/workflows/standards-readiness.yml` opens/updates a GitHub issue each cycle.
> **Rationale**: AIIR is a vendor-led open specification on a public standards track.
> Transparent, weekly readiness scoring signals good-faith governance and tracks gap closure.
>
> **Public target**: 4 green categories (score ≥ 3.5/5) + no open P0 for 4 consecutive weeks → louder standards messaging.

---

## Weekly Operating Score: 2026-W11

Last updated: 2026-03-11

| Category | Score (0–5) | Status | Key gap |
|---|---|---|---|
| 🔴 Governance | 1.8 | ❌ red | No neutral IP home, no IETF draft, single-org steering |
| ✅ Reliability | 4.5 | ✅ green | Adversarial corpus published; second impl needed for 5.0 |
| 🟡 Interoperability | 3.8 | 🟡 yellow | JS verifier passes all encoder vectors; Rust CBOR verifier; external impl needed for 5.0 |
| 🔴 Adoption | 1.7 | ❌ red | Dogfooding only; no external pilots on record |
| ✅ Consistency | 4.0 | ✅ green | Encoder interop vectors published; external review needed for 5.0 |
| **Open P0s** | 0 | ✅ green | |

> **Green target**: ≥ 3.5/5 on all 5 categories for 4 consecutive weeks.
> Current: 3 green categories out of 5.

---

## Detailed 6-Dimension Score (underlying methodology)

Last updated: 2026-03-11 · Cycle: 2026-W11

| Dimension | Weight | Score (0–5) | Weighted | Gap |
|---|---|---|---|---|
| Technical completeness | 20 | 4.6 | 18.4 | External review for 5.0 |
| Reference implementation quality | 20 | 4.5 | 18.0 | External (non-Invariant) implementation for 5.0 |
| Specification clarity | 15 | 4.2 | 12.6 | External review |
| Reliability & ecosystem | 15 | 4.2 | 12.6 | Community plugins; external verifier |
| Governance neutrality | 20 | 1.8 | 7.2 | Multi-stakeholder body; neutral IP home |
| Adoption maturity | 10 | 1.7 | 3.4 | Published case studies; integrations in the wild |
| **Composite** | **100** | | **72.2** | |

*5-category → 6-dimension mapping*: Governance ≈ Governance neutrality. Reliability ≈ Technical completeness + Reference impl quality. Interoperability ≈ Reliability & ecosystem. Adoption ≈ Adoption maturity. Consistency ≈ Specification clarity + metric consistency.

Version of this doc: v1.1.0

---

## Scoring Rubric

Each dimension is scored 0–5 by the maintainer, reviewed weekly.
A score of 5 means "demonstrably complete — a standards body could adopt this today."

### Technical Completeness (weight 20)

| Score | Criteria |
|---|---|
| 0 | No spec; ad-hoc behavior |
| 1 | Informal draft; core concepts present |
| 2 | Spec covers happy path; edge cases underspecified |
| 3 | Spec covers error cases; versioning defined |
| 4 | Schema versioning, multi-encoder interop defined |
| 5 | CDDL/ABNF normative grammar; formal conformance suite |

**Current: 4.6** — Schema versioned in `schemas/`; deterministic CBOR + JSON dual encoding; `schemas/conformance-manifest.json` published (2026-03-11); normative CDDL grammar in `schemas/receipt.cddl` covering JSON + CBOR wire formats (2026-03-11); cross-language encoder interop test vectors published in `schemas/test-vectors/` (8 vectors covering key ordering, Unicode, booleans, numerics, boundary arrays — 2026-03-11). Missing: external review.
*Last verified: 2026-03-11*

**Gap tasks:**

- [x] ~~Publish machine-readable conformance manifest~~ → `schemas/conformance-manifest.json` (2026-03-11)
- [x] ~~Write CDDL grammar for the receipt schema~~ → `schemas/receipt.cddl` (2026-03-11)
- [x] ~~Add encoder interop test vectors~~ → `schemas/test-vectors/encoder_interop_vectors.json` (2026-03-11)
- [ ] Publish test vector registry linked from `SPEC.md`

---

### Reference Implementation Quality (weight 20)

| Score | Criteria |
|---|---|
| 0 | No test suite |
| 1 | Basic happy-path tests |
| 2 | Statement coverage ≥ 80% |
| 3 | Statement + branch coverage = 100% |
| 4 | Mutation tested; fuzzing in CI; adversarial inputs in suite |
| 5 | Formal adversarial corpus; independent implementation verified identical output |

**Current: 4.5** — 100% statement + branch coverage (1893 tests collected, *last verified: 2026-03-12*); mutation testing; Atheris fuzzing in CI; structured adversarial rounds per release; post-release smoke tests automated; **formal adversarial test corpus published** in `tests/adversarial/` — 32 fixtures across 4 categories (injection, tampering, parsing, bypass) with auto-discovery pytest runner (2026-03-11). **JS verifier (`sdks/js/`) passes 8/8 encoder interop vectors and 8/8 full receipt verifications** (2026-03-11); **Rust CBOR verifier (`sdks/rust/`) passes round-trip vectors** (2026-03-11). Missing: external (non-Invariant Systems) implementation.
*Last verified: 2026-03-12*

**Gap tasks:**

- [x] ~~Post-release smoke test workflow~~ → `.github/workflows/release-smoke.yml` (2026-03-11)
- [x] ~~Publish adversarial test fixtures~~ → `tests/adversarial/` (32 fixtures, 4 categories — 2026-03-11)
- [x] ~~Document JS + Rust as second implementations~~ → `docs/implementers.md` (2026-03-11)
- [ ] Sponsor or recruit an independent (external org) implementation

---

### Specification Clarity (weight 15)

| Score | Criteria |
|---|---|
| 0 | No spec |
| 1 | README-level prose |
| 2 | `SPEC.md` exists with normative sections |
| 3 | Conformance profiles defined; `conformance.html` published |
| 4 | ABNF/CDDL normative grammar; unambiguous field semantics |
| 5 | Standards-body editorial style; external review completed |

**Current: 4.2** — `SPEC.md` with normative language; `conformance.html` live; receipt field semantics precisely defined; `SPEC_GOVERNANCE.md` published with change control, compat guarantees, extension registry, release cadence (2026-03-11); normative CDDL grammar in `schemas/receipt.cddl` referenced from `SPEC.md` section 1.3 (2026-03-11). Missing: external review.
*Last verified: 2026-03-11*

**Gap tasks:**

- [x] ~~Publish change control + compatibility policy~~ → `SPEC_GOVERNANCE.md` (2026-03-11)
- [x] ~~Add `schemas/receipt.cddl` (CDDL grammar; normative)~~ → (2026-03-11)
- [x] ~~Add "Conformance Testing" section to `SPEC.md` referencing test vectors~~ → SPEC.md §13 updated (2026-03-11)
- [ ] Solicit one external spec review (security researcher or standards professional)

---

### Reliability & Ecosystem (weight 15)

| Score | Criteria |
|---|---|
| 0 | No CI |
| 1 | Single-platform CI |
| 2 | Multi-platform CI; CI badge visible |
| 3 | Multi-platform + multi-Python; current main push fans out to 44 public checks |
| 4 | Third-party verifier (non-AIIR) working; 2+ language SDKs |
| 5 | 3+ independent verifiers; community plugin ecosystem |

**Current: 4.2** — 44 public check runs on the latest `main` commit, with `ci-ok`, `quality-ok`, and `security-ok` enforced by branch protection (*last verified: 2026-03-12*); Python 3.9–3.13 × Ubuntu/Windows/macOS; GitHub + GitLab dual-publish; MCP tool; `docs/release-health.md` with P0 RCA policy and smoke test badge published; **JS verifier (`sdks/js/`) and Rust CBOR verifier (`sdks/rust/`) published — 2 language SDKs verified against test vectors** (2026-03-11). Missing: community plugins, external verifier.
*Last verified: 2026-03-12*

**Gap tasks:**

- [x] ~~Release health page + P0 RCA policy~~ → `docs/release-health.md` (2026-03-11)
- [x] ~~Post-release smoke tests~~ → `.github/workflows/release-smoke.yml` (2026-03-11)
- [x] ~~Write standalone receipt verifier in JS~~ → `sdks/js/aiir-verify.js` (Level 1 — 2026-03-11)
- [ ] Document the MCP interface in `mcp-manifest.json` as a first-class integration point
- [ ] Publish SDK guidance in `docs/sdks.md`

---

### Governance Neutrality (weight 20)

| Score | Criteria |
|---|---|
| 0 | Single vendor, no public governance |
| 1 | Apache 2.0 license; public repo |
| 2 | Public governance docs; contributor ladder |
| 3 | IP contributed to neutral home (e.g., CNCF sandbox) or formal RFC submitted |
| 4 | Active multi-org steering committee |
| 5 | Adopted by a standards body (ISO, IETF, W3C, NIST) |

**Current: 2.2** — Apache 2.0; public repo; public `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`; `SPEC_GOVERNANCE.md` published with SIG structure, change control, extension registry, IP policy, and standards-track roadmap (2026-03-11). Missing: neutral IP home, RFC submission, multi-org steering.
*Last verified: 2026-03-11*

**Gap tasks (high-leverage, ordered by effort):**

- [x] ~~Publish `SPEC_GOVERNANCE.md` with SIG structure, RFC process, IP policy~~ (2026-03-11)
- [ ] Draft an IETF Individual Draft (`draft-invariantsystems-aiir-receipt-00.txt`)
- [ ] Open a CNCF Sandbox proposal (requires 2 additional organizations)
- [ ] Invite 2–3 external organizations to a working group
- [ ] Recruit external editor (≥ 1 org)

---

### Adoption Maturity (weight 10)

| Score | Criteria |
|---|---|
| 0 | No documented users |
| 1 | Creator uses it in their own repo |
| 2 | 2–5 public repos using AIIR receipts |
| 3 | Published case study; 10+ repos |
| 4 | Enterprise reference customer; recorded talk at a conference |
| 5 | Mentioned in a regulation, standard, or widely-cited OSS project |

**Current: 1.7** — AIIR uses AIIR (dogfooding, *last verified: 2026-03-11*); PyPI+GitHub Marketplace live; EU AI Act compliance positioning; `docs/implementers.md` registry published (invites external entries). Missing: public case studies, third-party adopters on record.
*Last verified: 2026-03-11*

**Gap tasks (highest ROI for standards positioning):**

- [x] ~~Publish implementers/pilots registry~~ → `docs/implementers.md` (2026-03-11)
- [ ] Publish a first case study (even internal: "AIIR generates receipts for AIIR itself")
- [ ] Reach out to 3 OSS projects that commit AI-assisted code; offer to help them adopt
- [ ] Write a blog post / talk abstract: "Verifiable AI provenance in practice"
- [ ] Submit a talk to a supply-chain security conference (SOSS, OpenSSF Day, KubeCon)

---

## Canonical Metric Sources

> **Policy**: all comparison numbers in docs and on the website MUST trace to one of these sources.
> No hand-edited stat may appear without a "Last verified" date.

| Metric | Canonical source | Last verified |
|---|---|---|
| Test count | `pytest --collect-only -q \| tail -1` | 2026-03-12 (1893 tests collected) |
| CI check count | GitHub check-runs API on the latest `main` commit | 2026-03-12 (44 public checks; 3 required merge gates) |
| Coverage | `pytest --cov=aiir --cov-fail-under=100` | 2026-03-11 (100%) |
| Runtime dependencies | `pip show aiir \| grep Requires` | 2026-03-11 (0) |
| Conformance vectors | `schemas/conformance-manifest.json` | 2026-03-11 (25 JSON + 24 CBOR + 8 encoder interop) |
| Release version | `aiir --version` / PyPI | 2026-03-11 (v1.2.5) |
| Governance score | This doc, Governance Neutrality section | 2026-03-11 (2.2/5) |
| Adoption score | `docs/implementers.md` | 2026-03-11 (1.7/5) |

---

## Weekly Update History

| Cycle | Date | Score | Key change |
|---|---|---|---|
| 2026-W11 | 2026-03-11 | 72.2 | Adversarial corpus (32 fixtures, 4 categories) → Reliability 4.5; encoder interop vectors (8 vectors) → Consistency 4.0; JS verifier passes all vectors → Interop 3.8; Reliability+Ecosystem 4.2; composite +3.3 |
| 2026-W11 | 2026-03-11 | 68.9 | v1.1 scorecard → +1.4 CDDL: SPEC_GOVERNANCE.md, release-health.md, smoke tests, conformance-manifest.json, implementers.md, 5-category weekly model; normative CDDL grammar (schemas/receipt.cddl); SPEC.md section 1.3 + conformance-manifest updated |

---

## 90-Day Gap-Closure Roadmap

```text
Week 1–2 (Mar 2026): Governance mechanics + infrastructure [IN PROGRESS]
  ✅ SPEC_GOVERNANCE.md published (change control, compat policy, extension registry)
  ✅ schemas/conformance-manifest.json published (machine-readable implementer registry)
  ✅ docs/release-health.md published (P0 policy, RCA template, smoke test badge)
  ✅ .github/workflows/release-smoke.yml (automated post-release smoke, P0 alert)
  ✅ docs/implementers.md published (third-party implementations + pilots registry)
  ✅ Weekly standards-readiness issue workflow
  Next: CDDL grammar, adversarial corpus, external recruits

Month 1 remainder (Mar 2026): Reliability + Consistency
  ✅ CDDL grammar (schemas/receipt.cddl)
  ✅ Encoder interop test vectors (schemas/test-vectors/encoder_interop_vectors.json — 8 vectors)
  ✅ Publish adversarial fixture corpus (tests/adversarial/ — 32 fixtures, 4 categories)
  ✦ "Last verified" dates on all website stat blocks
  Target: +5 pts → ~72.5

Month 2 (Apr 2026): Governance depth + Interop
  ✦ Draft IETF Individual Draft (draft-invariantsystems-aiir-receipt-00)
  ✦ Recruit 2 external organization contacts; first external editor added
  ✦ Standalone JavaScript receipt verifier (browser-native, Level 1)
  Target: +8 pts → ~80.5

Month 3 (May 2026): Adoption proof
  ✦ Publish 2 case studies (1 internal, 1 external)
  ✦ Conference abstract submitted (OpenSSF Day / SOSS)
  ✦ 3+ external repos with receipts on record in docs/implementers.md
  Target: +4 pts → ~84.5

Green target: 4 categories ≥ 3.5/5 + 0 open P0s for 4 consecutive weeks
Estimated achievement: late April 2026 (wk 2026-W17)
```

---

## Methodology Notes

- Scores are maintainer-assessed; targets must be verifiable (link to artifact, PR, or commit).
- The weekly GitHub Action creates a tracking issue with a pre-filled update template.
- All historical scores are preserved in the "Weekly Update History" table above.
- This document lives at `docs/standards-readiness.md` and is linked from `invariantsystems.io`.

---

*AIIR is a vendor-led open specification on a transparent standards track.*
*We publish this scorecard weekly to signal good-faith governance and track gap closure in the open.*
