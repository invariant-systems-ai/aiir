# Show HN Draft

> **Post this as a text submission to <https://news.ycombinator.com/submit>**

---

**Title:** Show HN: AIIR – Tamper-evident receipts for AI-assisted git commits (zero deps)

**URL:** <https://github.com/invariant-systems-ai/aiir>

**Text:**

Hi HN,

I built AIIR (AI Integrity Receipts) — an open-source tool that generates content-addressed receipts for every git commit, recording whether AI tools were involved.

```text
pip install aiir && cd your-repo && aiir --pretty
```

That's it. Zero dependencies. Python 3.9+. Your last commit now has a tamper-evident receipt in `.aiir/receipts.jsonl`.

**Why this exists:** AI writes a large share of new code now, but `git log` doesn't distinguish declared AI assistance from human-only work. The EU AI Act transparency rules phase in August 2025, and SOC 2 / ISO 27001 auditors are starting to ask "which commits involved AI?"

**What it does:**

- Scans commits for AI authorship signals (Copilot, ChatGPT, Claude, Cursor, etc.)
- Generates content-addressed JSON receipts — change one byte, the hash breaks
- Optionally signs with Sigstore (`pip install aiir[sign]` — keyless OIDC, same infra as npm/PyPI/K8s)
- Evaluates against policy (strict/balanced/permissive) and emits SLSA-compatible Verification Summary Attestations
- Works as a GitHub Action (`uses: invariant-systems-ai/aiir@v1`), GitLab CI/CD Catalog component, CLI, or MCP server

**What it doesn't do:** It doesn't detect AI-written code by style. It reads declared signals — Co-authored-by trailers, commit message patterns, bot accounts. This is an attestation tool, not an AI detector.

**Technical details:**

- ~9k LOC Python, 1,893 tests collected, 100% coverage, mutation-tested
- Content hashing uses SHA-256 over canonical JSON
- Receipt format is a documented open schema (AIIR Spec v1)
- Receipts are append-only JSONL with automatic dedup and indexing
- Built-in CDDL grammar for the receipt format (RFC 8610)

Feedback welcome — especially on the receipt schema and policy model. The spec is in SPEC.md in the repo.

---

*Notes for posting:*

- Show HN posts go to /newest first, then may hit front page based on upvotes
- Best posting times: ~9-11am ET weekdays (Tue-Thu best)
- Reply to every comment promptly and substantively
- Don't ask for upvotes or share the link asking people to upvote
