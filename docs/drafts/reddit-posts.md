# Reddit Post Drafts

Three targeted posts for different subreddits. Each has a distinct angle.

---

## 1. r/Python — Technical audience

**Title:** I built a zero-dependency Python tool that generates cryptographic receipts for AI-assisted git commits

**Body:**

I've been working on [AIIR](https://github.com/invariant-systems-ai/aiir) (AI Integrity Receipts) — a CLI + library that generates content-addressed, optionally Sigstore-signed JSON receipts for every commit in a git repo.

**Quick start:**

```bash
pip install aiir
cd your-repo
aiir --pretty
```

What it does:

- Scans commits for AI authorship signals (Co-authored-by trailers, commit message patterns, bot accounts)
- Generates tamper-evident receipts with SHA-256 content hashing
- Signs with Sigstore keyless (same infra as PyPI, npm, K8s)
- Evaluates against configurable policy and emits SLSA Verification Summary Attestations
- Also works as a GitHub Action, GitLab CI/CD Catalog component, and MCP server

**Why zero dependencies matters:** `pip install aiir` pulls exactly one package. No transitive deps, no supply chain risk, no version conflicts. The whole package is ~9k LOC of pure Python.

It's tested with 1,893 tests including mutation testing, fuzz testing, and adversarial corpus fixtures. Apache 2.0.

The use case: EU AI Act transparency rules are phasing in, and compliance teams are starting to ask "which commits involved AI tools?" This gives them a cryptographic audit trail.

Happy to answer questions about the design or the receipt schema.

---

## 2. r/DevOps — CI/CD angle

**Title:** We added AI audit receipts to our CI pipeline in 5 minutes — here's the GitHub Action workflow

**Body:**

If your team uses Copilot/ChatGPT/Claude and you're starting to get questions from compliance about AI usage tracking, here's what we set up:

```yaml
# .github/workflows/aiir.yml
name: AIIR Receipts
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  id-token: write  # For Sigstore signing

jobs:
  receipt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: invariant-systems-ai/aiir@v1
        with:
          sign: "true"
```

That's the whole workflow. Every push generates receipts for each commit, recording which ones have AI authorship signals (Co-authored-by trailers, bot patterns, etc.) and signs them with Sigstore.

The receipts are content-addressed JSON — change one byte and the hash breaks. They land in `.aiir/receipts.jsonl` as an append-only ledger.

It also works with GitLab CI/CD (there's a Catalog component) and as an MCP server for AI assistants.

Tool: [AIIR](https://github.com/invariant-systems-ai/aiir) — open source, Apache 2.0, zero dependencies.

The EU AI Act angle is the driver, but even without compliance pressure it's useful to have a machine-readable record of which commits involved AI tools.

---

## 3. r/ExperiencedDevs — Professional/strategic angle

**Title:** How are you tracking AI tool usage in your codebase for compliance?

**Body:**

Curious what others are doing here. Our compliance team started asking about AI usage tracking after the EU AI Act transparency requirements were announced (general-purpose AI rules from August 2025, high-risk from August 2026).

The ask was basically: "Can you tell us which commits involved AI tools? Can you prove it?"

We ended up building an open-source tool called [AIIR](https://github.com/invariant-systems-ai/aiir) that generates cryptographic receipts per commit. It reads declared signals (Co-authored-by trailers, commit message patterns, bot accounts) — it's not trying to detect AI by code style, just recording what's declared.

The receipts are content-addressed JSON with SHA-256 hashing, optionally signed with Sigstore, and the tool can evaluate them against policy and emit SLSA-compatible attestations.

We run it as a GitHub Action on every PR. Zero runtime dependencies, so the supply chain surface is minimal.

What I'm curious about:

- Is your compliance team asking about AI usage yet?
- If so, what approach are you taking?
- Any concerns about the "declared signals" approach vs. AI detection?

---

*Posting notes:*

- r/Python: Technical focus, show code, emphasize zero-deps and test coverage
- r/DevOps: CI/CD workflow copy-paste, emphasize 5-minute setup
- r/ExperiencedDevs: Discussion-first, don't lead with promotion — ask a genuine question
- Post at ~10am ET on Tuesday or Wednesday for best visibility
- Engage with every comment
- Don't crosspost simultaneously — space them 1-2 days apart
