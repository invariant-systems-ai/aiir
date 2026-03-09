# Launch Sequence — Pre-Launch Checklist

> **Strategy**: Technical communities first → GitHub distribution → selective
> Reddit/Lobsters → Product Hunt → buyer outreach.
> **Rule**: No firehose. Earn proof points before seeking broad attention.

---

## Pre-launch gates (fix before inviting attention)

- [x] **End-to-end demo above the fold** — Generate → Verify → CI in one visual
- [x] **Fix mailto early-access flow** — pricing.html now POSTs to workers.dev
- [x] **GitLab copy-paste fix** — index.html Catalog snippet uses `@1` (major pin)
- [x] **Stale test count** — stats.json + index.html updated to 1171
- [x] **Proof Points section** — README now has 9-row verifiable evidence table
- [x] **Marketplace badge** — added to README
- [x] **Repo description** — updated to mention verification + attestation
- [x] **Repo topics** — added slsa, verification, attestation, in-toto, supply-chain-security
- [x] **Release notes template** — .github/release.yml with structured categories
- [ ] **Pin demo GIF/SVG** — ensure docs/demo.svg is current and renders well on GitHub
- [ ] **Verify browser verifier** — test invariantsystems.io/verify with a real receipt
- [ ] **Create sample repo** — tiny repo showing receipt generation + browser verification + CI artifact in one pass

---

## Channel 1: Show HN

- [ ] Review [docs/launch/show-hn-draft.md](show-hn-draft.md)
- [ ] Post Tuesday–Thursday, 8–10am ET
- [ ] Reply to every comment in first 2 hours
- [ ] Be transparent about limitations and 0-star repo
- [ ] Link to THREAT_MODEL.md when limitations are raised

## Channel 2: GitHub distribution

- [ ] Ensure README renders perfectly on github.com (images, badges, links)
- [ ] Verify Marketplace listing shows latest README
- [ ] Consider creating `invariant-systems-ai/aiir-example` sample repo
- [ ] Star the repo from personal account (not org)

## Channel 3: Reddit / Lobsters (selective, personal)

- [ ] Only post as founder with disclosed affiliation
- [ ] Target: r/netsec, r/devops, r/programming, r/ExperiencedDevs
- [ ] Lobsters: submit with `show` tag, AI + security tags
- [ ] Keep self-promotion to <25% of total activity on each platform
- [ ] Never ask for upvotes

## Channel 4: Product Hunt (later)

- [ ] Wait for HN/GitHub proof points first
- [ ] Collect screenshots, early-user quotes
- [ ] Schedule as a separate beat after initial traction

## Channel 5: Buyer outreach (parallel)

- [ ] Create one crisp artifact: signed receipt from sample repo + verifier demo
- [ ] LinkedIn/X posts from founder account
- [ ] Direct outreach to design partners (security teams, compliance officers)
- [ ] Target: SOC 2 auditors, EU AI Act compliance leads, insurance underwriters
