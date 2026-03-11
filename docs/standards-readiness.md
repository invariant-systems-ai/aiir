# AIIR Standards-Readiness Scorecard

> **Update cadence**: weekly, every Monday.
> **Automation**: `.github/workflows/standards-readiness.yml` opens/updates a GitHub issue each cycle.
> **Rationale**: AIIR is a vendor-led open specification on a public standards track.
> Transparent, weekly readiness scoring signals good-faith governance and tracks gap closure.
>
> **Public target**: 4 green categories (score ≥ 3.5/5) + no open P0 for 4 consecutive weeks → louder standards messaging.

---

## Weekly Operating Score: 2026-W11

*Last updated: 2026-03-11*

| Category | Score (0–5) | Status | Key gap |
|---|---|---|---|
| 🔴 Governance | 1.8 | ❌ red | No neutral IP home, no IETF draft, single-org steering |
| 🟡 Reliability | 4.1 | 🟡 yellow | Smoke test now live; adversarial corpus not yet published |
| 🟡 Interoperability | 3.4 | 🟡 yellow | Conformance manifest published; no second implementation yet |
| 🔴 Adoption | 1.7 | ❌ red | Dogfooding only; no external pilots on record |
| 🟡 Consistency | 3.5 | 🟡 yellow | Canonical source defined; "Last verified" dates not yet on all pages |
| **Open P0s** | 0 | ✅ green | |

> **Green target**: ≥ 3.5/5 on all 5 categories for 4 consecutive weeks.
> Current: 0 green categories out of 5.

---

## Detailed 6-Dimension Score (underlying methodology)

*Last updated: 2026-03-11 · Cycle: 2026-W11*

| Dimension | Weight | Score (0–5) | Weighted | Gap |
|---|---|---|---|---|
| Technical completeness | 20 | 4.1 | 16.4 | Formal CDDL grammar; encoder interop suite |
| Reference implementation quality | 20 | 4.2 | 16.8 | Published adversarial corpus; second implementation |
| Specification clarity | 15 | 4.0 | 12.0 | Normative grammar (ABNF/CDDL); external review |
| Reliability & ecosystem | 15 | 3.9 | 11.7 | Third-party verifier; SDK breadth |
| Governance neutrality | 20 | 1.8 | 7.2 | Multi-stakeholder body; neutral IP home |
| Adoption maturity | 10 | 1.7 | 3.4 | Published case studies; integrations in the wild |
| **Composite** | **100** | | **67.5** | |

*5-category → 6-dimension mapping*: Governance ≈ Governance neutrality. Reliability ≈ Technical completeness + Reference impl quality. Interoperability ≈ Reliability & ecosystem. Adoption ≈ Adoption maturity. Consistency ≈ Specification clarity + metric consistency.

*Version of this doc: v1.1.0*

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

**Current: 4.1** — Schema versioned in `schemas/`; deterministic CBOR + JSON dual encoding; missing: formal CDDL grammar and an independent encoder-level test corpus.

**Gap tasks:**
- [ ] Write CDDL grammar for the receipt schema in `schemas/receipt.cddl`
- [ ] Add encoder interop test vectors (at least: Python, Node, Go) in `schemas/test-vectors/`
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

**Current: 4.2** — 100% statement + branch coverage; mutation testing; fuzzing (Atheris); structured adversarial rounds per release. Missing: a published, versioned adversarial corpus and an independent second implementation.

**Gap tasks:**
- [ ] Publish adversarial test fixtures in `tests/adversarial/` and include in release artifacts
- [ ] Sponsor or document an independent implementation (Go or Rust reference)

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

**Current: 4.0** — `SPEC.md` with normative language; `conformance.html` live; receipt field semantics precisely defined. Missing: formal grammar file and external independent edit review.

**Gap tasks:**
- [ ] Add `schemas/receipt.cddl` (CDDL grammar; normative)
- [ ] Solicit one external spec review (security researcher or standards professional)
- [ ] Add "Conformance Testing" section to `SPEC.md` referencing test vectors

---

### Reliability & Ecosystem (weight 15)

| Score | Criteria |
|---|---|
| 0 | No CI |
| 1 | Single-platform CI |
| 2 | Multi-platform CI; CI badge visible |
| 3 | Multi-platform + multi-Python; 34-check pipeline |
| 4 | Third-party verifier (non-AIIR) working; 2+ language SDKs |
| 5 | 3+ independent verifiers; community plugin ecosystem |

**Current: 3.9** — 34-check CI; Python 3.9–3.13 × Ubuntu/Windows/macOS; GitHub + GitLab dual-publish; MCP tool; conformance matrix. Missing: any non-Python verifier, community plugins.

**Gap tasks:**
- [ ] Encourage or write a standalone receipt verifier in a second language (target: JavaScript/Node for browser use)
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

**Current: 1.8** — Apache 2.0; public repo; public `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`; basic governance in place. Missing: neutral IP home, RFC submission, multi-org steering.

**Gap tasks (high-leverage, ordered by effort):**
- [ ] Draft an IETF Individual Draft (`draft-invariantsystems-aiir-receipt-00.txt`)
- [ ] Open a CNCF Sandbox proposal (requires 2 additional organizations)
- [ ] Invite 2–3 external organizations to a working group; document in `GOVERNANCE.md`
- [ ] Create `GOVERNANCE.md` with SIG structure, voting rules, RFC process

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

**Current: 1.7** — AIIR uses AIIR (dogfooding); PyPI+GitHub Marketplace live; EU AI Act compliance positioning. Missing: public case studies, third-party adopters on record.

**Gap tasks (highest ROI for standards positioning):**
- [ ] Publish a first case study (even internal: "AIIR generates receipts for AIIR itself")
- [ ] Reach out to 3 OSS projects that commit AI-assisted code; offer to help them adopt
- [ ] Write a blog post / talk abstract: "Verifiable AI provenance in practice"
- [ ] Submit a talk to a supply-chain security conference (SOSS, OpenSSF Day, KubeCon)

---

## Weekly Update History

| Cycle | Date | Score | Key change |
|---|---|---|---|
| 2026-W11 | 2026-03-11 | 62.6 | Initial scorecard published |

---

## 90-Day Gap-Closure Roadmap

```
Month 1 (Mar 2026): Reliability + Spec clarity
  ✦ Write CDDL grammar (schemas/receipt.cddl)
  ✦ Add encoder test vectors (schemas/test-vectors/)
  ✦ Publish adversarial fixture corpus
  ✦ Draft JavaScript receipt verifier (browser-native)
  Target: +6 pts → ~68.6

Month 2 (Apr 2026): Governance
  ✦ Create GOVERNANCE.md (SIG structure, RFC process)
  ✦ Draft IETF Individual Draft (aiir-receipt-00)
  ✦ Recruit 2 external organization contacts for steering group
  Target: +8 pts → ~76.6

Month 3 (May 2026): Adoption proof
  ✦ Publish 2 case studies
  ✦ Conference abstract submitted
  ✦ 5 external repos with receipts on record
  Target: +6 pts → ~82.6
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
