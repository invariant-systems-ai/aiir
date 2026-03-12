# Reddit Post Drafts

Three targeted posts for different subreddits. Each has a distinct angle.

---

## 1. r/Python — Technical audience

**Title:** I built a zero-dependency Python tool that generates cryptographic receipts for AI-assisted git commits

**Body:**

I've been working on [AIIR](https://github.com/invariant-systems-ai/aiir) (AI Integrity Receipts) — a CLI and library that generates content-addressed, optionally Sigstore-signed JSON receipts for every commit in a git repo.

```bash
pip install aiir
cd your-repo
aiir --pretty
```

**How it works under the hood:**

Each receipt is a JSON object containing the commit metadata (SHA, author, date, file list), a diff hash, and an `ai_attestation` block that records detected signals. The core fields are serialized in a canonical order, then SHA-256 hashed to produce a `content_hash`. The `receipt_id` is derived from that hash. Change any field and the hash breaks — that's the tamper-detection guarantee.

Receipts append to `.aiir/receipts.jsonl` — an append-only JSONL ledger with automatic deduplication (same commit = same content hash = no duplicate). An index file (`.aiir/index.json`) maps commit SHAs to their `receipt_id` and ledger line number for effectively O(1) lookup, deduplication, and stats.

Detection is signal-based, not stylistic: Co-authored-by trailers (Copilot, Claude, etc.), known bot account patterns, commit message markers. The threat model is explicit — AIIR records what's *declared*, not what's *true*. A developer who strips Co-authored-by trailers before committing will produce a receipt that says "no AI detected." The receipt is honest about its inputs; it doesn't claim omniscience. (See THREAT_MODEL.md in the repo.)

For signing, `pip install aiir[sign]` adds Sigstore keyless OIDC — same trust infrastructure used by PyPI, npm, and Kubernetes. Signatures go into the Sigstore transparency log, giving you a public, immutable record that a specific CI identity generated a specific receipt at a specific time.

Policy evaluation runs over a set of receipts and emits a PASS/FAIL decision as an in-toto Statement v1 / SLSA Verification Summary Attestation. Three built-in policies (strict/balanced/permissive) cover AI-ratio thresholds; custom policies are JSON.

**Why zero dependencies:** `pip install aiir` pulls exactly one package. No transitive deps, no supply chain risk, no version conflicts. ~9k LOC of pure Python, 1,800+ tests including mutation testing, fuzz testing, and an adversarial corpus of malformed inputs. Apache 2.0.

Also runs as a GitHub Action, GitLab CI/CD Catalog component, and MCP server. Receipt schema has a formal CDDL grammar (RFC 8610).

Happy to answer questions about the design, the trust model, or the receipt schema.

---

## 2. r/DevOps — CI/CD angle

**Title:** We added AI audit receipts to our CI pipeline in 5 minutes — here's the GitHub Action workflow

**Body:**

If your team uses Copilot/ChatGPT/Claude and you want a machine-readable record of which commits involved AI tools, here's what we set up:

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

That's the whole workflow. Every push generates a receipt per commit — a content-addressed JSON record of the commit metadata plus an `ai_attestation` block listing detected AI signals. Change one byte and the SHA-256 hash breaks; sign with Sigstore and the receipt lands in a public transparency log.

Receipts accumulate in `.aiir/receipts.jsonl` as an append-only ledger with dedup and indexing. You can verify them offline (`aiir --verify`) or evaluate a release against policy and get a SLSA Verification Summary Attestation (`aiir --verify-release --policy strict --emit-vsa`).

Detection is signal-based: Co-authored-by trailers, bot accounts, commit message patterns. It doesn't try to detect AI by code style — it records what's declared. The threat model is documented: THREAT_MODEL.md.

Also works with GitLab CI/CD (there's a [Catalog component](https://gitlab.com/explore/catalog/invariant-systems/aiir)) and as an MCP server for AI assistants.

Tool: [AIIR](https://github.com/invariant-systems-ai/aiir) — open source, Apache 2.0, zero runtime dependencies.

---

## 3. r/ExperiencedDevs — Professional/strategic angle

**Title:** How are you tracking AI tool usage in your codebase for compliance?

**Body:**

Curious what others are doing here. Our compliance team started asking about AI usage tracking after the EU AI Act timeline started materializing — the Act entered into force in August 2024, GPAI transparency obligations applied from August 2025, and the broader transparency and high-risk system rules phase in through 2026–2027.

The ask was basically: "Can you tell us which commits involved AI tools? Can you prove it?"

We ended up building an open-source tool called [AIIR](https://github.com/invariant-systems-ai/aiir) that generates cryptographic receipts per commit. It reads declared signals (Co-authored-by trailers, commit message patterns, bot accounts) — it's not trying to detect AI by code style, just recording what's declared. The threat model is explicit about this: if a developer strips the trailers, the receipt honestly says "no AI detected." (THREAT_MODEL.md in the repo.)

The receipts are content-addressed JSON — SHA-256 over canonical fields, append-only JSONL ledger, optional Sigstore signing for non-repudiation. The tool evaluates receipts against policy and emits SLSA-compatible Verification Summary Attestations that downstream systems (CI gates, GRC platforms) can consume without re-evaluating.

We run it as a GitHub Action on every PR. Zero runtime dependencies, so the supply chain surface is minimal. 1,800+ tests, mutation-tested, fuzz-tested. Apache 2.0.

What I'm curious about:

- Is your compliance team asking about AI usage yet?
- If so, what approach are you taking?
- Any concerns about the "declared signals" approach vs. stylistic AI detection?
