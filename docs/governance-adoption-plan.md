# Governance & Adoption — Action Plan

> Concrete next steps to move Governance (1.8 → 3.0+) and Adoption (1.7 → 2.5+)
> toward yellow/green on the standards-readiness scorecard.
>
> **Owner**: Noah / Invariant Systems
> **Created**: 2026-03-11
> **Target**: End of Month 3 (May 2026)

---

## Governance: 1.8 → 3.0 requires *one* of: IETF draft or CNCF sandbox

### Action G1: IETF Individual Draft (Month 2 — April 2026)

**Goal**: Submit `draft-invariantsystems-aiir-receipt-00` as an IETF Individual Draft.

An Individual Draft doesn't require IETF WG adoption — any author can submit one.
This immediately demonstrates standards-track intent and is sufficient for score 3.0.

**Steps**:

1. **Convert SPEC.md to I-D XML** using [`xml2rfc`](https://xml2rfc.ietf.org/) or
   [`kramdown-rfc`](https://github.com/cabo/kramdown-rfc) (Markdown → RFC XML).
   - Map existing sections to RFC structure: Abstract, Introduction, Terminology,
     Data Model, Canonical Encoding, Content Addressing, Verification, IANA Considerations
   - IANA section already written in SPEC.md §14
   - CDDL grammar (§1.3) maps directly to normative appendix
2. **Register the draft name**: `draft-invariantsystems-aiir-receipt-00`
3. **Submit via [datatracker.ietf.org](https://datatracker.ietf.org/submit/)**
4. **Announce on relevant mailing lists**: `ietf-announce`, `scitt@ietf.org` (Supply Chain
   Integrity, Transparency, and Trust WG — closest IETF WG)

**Blockers**: None — this is a solo-author deliverable.

**Score impact**: Governance 2.2 → 3.0 (+0.8), composite +3.2 points.

### Action G2: External Contact Outreach (Month 2 — April 2026)

**Goal**: Invite 2–3 organizations to an informal working group / advisory role.

**Target organizations** (prioritized by alignment):

| Organization | Why | Contact path |
|---|---|---|
| OpenSSF / SLSA | Supply-chain provenance is their mission | GitHub issue on slsa-framework/slsa |
| CNCF / in-toto | Attestation format interop | GitHub issue on in-toto/attestation |
| Trail of Bits / Sigstore | Signing + verification expertise | Direct email or SOSS slack |
| GitHub Next | Copilot provenance signals | Internal contacts |
| GitLab | GitLab CI component already ships | Developer advocacy |

**Steps**:

1. Draft a 1-page "AIIR Receipt Format: Call for Review" document
2. Email or open issues on 3 target orgs' repos
3. Offer co-authorship on the I-D to any org that contributes review

**Score impact**: Each external org added → Governance +0.3–0.5.

### Action G3: CNCF Sandbox Proposal (Month 3 — May 2026)

**Prerequisite**: At least 2 organizations expressing support (from G2).

**Steps**:

1. Write a [CNCF Sandbox proposal](https://github.com/cncf/toc/blob/main/process/project_proposals.md)
2. Identify 2 TOC sponsors
3. Submit via CNCF TOC GitHub repo

**Score impact**: If accepted → Governance 3.0 → 4.0.

---

## Adoption: 1.7 → 2.5 requires *public case studies + 2–5 external repos*

### Action A1: Internal Case Study (Month 2 — April 2026)

**Goal**: Publish "AIIR Generates Receipts for AIIR" case study.

This is pure documentation of existing dogfooding, not new engineering.

**Content outline**:

- How AIIR generates a receipt for every commit (GitHub Action + GitLab CI)
- Receipt verification in CI pipeline (36 checks, 0 false positives in N releases)
- File permission hardening story (PR #32)
- Metrics: receipts generated, verification throughput, zero-dependency advantage

**Deliverable**: `docs/case-studies/aiir-self-dogfood.md` + link from README.

**Score impact**: Adoption 1.7 → 2.0 (+0.3).

### Action A2: OSS Project Outreach (Month 2–3)

**Goal**: Help 3 public OSS projects generate AIIR receipts.

**Selection criteria**: Projects that use AI-assisted coding (Copilot, Claude, etc.)
and have a CI pipeline where the GitHub Action can drop in.

**Approach**:

1. Identify 5 candidate repos (search: repos with `.github/copilot-instructions.md`
   or `@copilot` mentions in recent PRs, or repos that discuss AI code generation)
2. Open an issue: "Verifiable AI provenance with AIIR receipts — zero dependencies, 1 workflow line"
3. Offer to submit the PR adding the GitHub Action
4. Each repo that generates a receipt → add to `docs/implementers.md`

**Score impact**: 3 repos → Adoption 2.0 → 2.5 (+0.5).

### Action A3: Conference / Blog (Month 2–3)

**Goal**: Public visibility through at least one external talk or post.

**Target venues**:

| Venue | Deadline | Format |
|---|---|---|
| [SOSS Community Day](https://openssf.org/events/) | Varies | 20-min talk |
| [OpenSSF Day](https://openssf.org/events/) | Varies | Lightning talk |
| [KubeCon NA](https://events.linuxfoundation.org/kubecon-cloudnativecon-north-america/) | ~June for Oct | 35-min talk |
| Blog post (invariantsystems.io) | Anytime | Long-form |

**Deliverables**:

1. Write a talk abstract: "Verifiable AI Provenance in Practice: Content-Addressed Receipts for Every Commit"
2. Submit to at least 2 conferences by end of April
3. Publish a blog post regardless of conference acceptance

**Score impact**: Published talk/blog → Adoption 2.5 → 3.0 (+0.5).

---

## Combined Scorecard Impact (projected)

| Category | Current | With G1+A1 (Apr) | With G2+G3+A2+A3 (May) |
|---|---|---|---|
| Governance | 1.8 | 3.0 | 3.5–4.0 |
| Reliability | 4.5 | 4.5 | 4.5 |
| Interop | 3.8 | 3.8 | 4.0 |
| Adoption | 1.7 | 2.0 | 2.5–3.0 |
| Consistency | 4.0 | 4.0 | 4.0 |
| **Composite** | **72.2** | **~78** | **~82–85** |

Green target (≥3.5 on all 5 categories): achievable by end of Month 3 if G2
recruits 2+ external orgs and A2 lands 3+ public repos.

---

## Risk Register

| Risk | Likelihood | Mitigation |
|---|---|---|
| No external orgs respond to outreach | Medium | Cast wider net (5+ orgs); offer co-authorship incentive |
| IETF draft takes longer due to XML formatting | Low | Use kramdown-rfc (Markdown-native); budget 2 days |
| CNCF Sandbox requires more traction | High | Focus on I-D + adoption first; sandbox is Month 3 stretch goal |
| Conference CFPs close before we submit | Medium | Blog post is the backstop; always publishable |
