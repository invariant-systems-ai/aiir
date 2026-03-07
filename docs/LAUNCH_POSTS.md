# Launch Posts — AIIR v1.0.0

## Hacker News

**Title:** AIIR – Cryptographic receipts for AI-generated code (zero dependencies, 502 tests)

**URL:** https://github.com/invariant-systems-ai/aiir-action

**Text (if self-post):**

Hi HN,

We built AIIR (AI Integrity Receipts) — a tool that generates cryptographic receipts for every git commit, recording whether AI assisted the code and producing a tamper-evident hash chain.

**Why this exists:** The EU AI Act requires knowing what's AI-generated. Half of new code is written by AI assistants. Most teams have no record of which commits were human vs. machine. When an auditor asks "what percentage of your codebase was AI-authored?" — you need an answer better than "we think maybe 40%?"

**What it does:**
- Scans git metadata for AI signals (Copilot, Claude, ChatGPT, Cursor, Windsurf, Devin, Tabnine, etc.)
- Generates content-addressed receipts (SHA-256 hash chain)
- Optional Sigstore keyless signing for non-repudiation
- Runs as: GitHub Action, CLI, pre-commit hook, MCP server, or GitLab CI

**The unusual parts:**
- Zero runtime dependencies. Only Python stdlib. `pip install aiir` installs nothing else.
- 502 tests including 21 rounds of adversarial red-teaming (terminal escape injection, homoglyph evasion, field delimiter attacks)
- Single file: `aiir/cli.py` (~1,200 lines). You can audit it in an afternoon.
- The tool receipts its own commits (dogfood: https://github.com/invariant-systems-ai/aiir-action/tree/main/.receipts)

**What it's NOT:**
- Not a code scanner. It doesn't analyze code quality or detect AI by writing style.
- Not a watermark. It reads git metadata signals that AI tools already leave behind.
- Heuristic detection is best-effort — AI tools that leave no trace won't be caught.

Apache 2.0. No telemetry. No phone-home.

---

## Twitter/X Thread

**Tweet 1 (hook):**

Half your codebase is AI-generated.

You have no record of which half.

Today we're open-sourcing AIIR — cryptographic receipts for every git commit.

Zero dependencies. 502 tests. One `pip install`.

🧾 https://github.com/invariant-systems-ai/aiir-action

**Tweet 2 (what it does):**

AIIR scans each commit for AI signals:
• Co-authored-by: Copilot
• Claude, ChatGPT, Cursor, Windsurf, Devin
• Bot authors and trailers

Then generates a tamper-evident receipt with SHA-256 hash chain.

Optional: Sigstore keyless signing for cryptographic proof.

**Tweet 3 (why now):**

The EU AI Act requires transparency about AI-generated code.

Most teams: "uhh... we use Copilot sometimes?"

With AIIR: machine-readable, auditable, immutable records. Per commit.

Auditor asks → you answer with data, not vibes.

**Tweet 4 (the flex):**

The unusual bits:

☐ Zero pip dependencies (stdlib only)
☐ 502 tests, 21 red-team rounds
☐ Single file you can audit in an afternoon
☐ Runs as: GitHub Action, CLI, pre-commit hook, MCP server, GitLab CI
☐ The repo receipts its own commits

**Tweet 5 (CTA):**

Try it in 10 seconds:

```
pip install aiir
cd your-repo
aiir --pretty
```

Apache 2.0. No telemetry. No phone-home.

Star it if you think AI transparency matters:
🧾 https://github.com/invariant-systems-ai/aiir-action

---

## LinkedIn Post

**AI-generated code has no paper trail. We're fixing that.**

Today we're releasing AIIR (AI Integrity Receipts) v1.0.0 — an open-source tool that generates cryptographic receipts for every git commit, recording whether AI assisted the code.

**The problem:** Over 50% of new code is now AI-assisted, but most organizations have zero visibility into which commits were human-authored vs. machine-generated. When regulators, auditors, or insurers ask about AI usage — there's no data to give them.

**What AIIR does:**
→ Scans git metadata for 15+ AI tool signals (Copilot, Claude, ChatGPT, Cursor, and more)
→ Generates content-addressed receipts with SHA-256 hash chains
→ Optional Sigstore keyless signing for cryptographic non-repudiation
→ Integrates as: GitHub Action, CLI, pre-commit hook, MCP server, GitLab CI

**Why it matters now:**
The EU AI Act's transparency requirements are approaching. Engineering teams need machine-readable records of AI participation — not just policies, but evidence.

**The engineering philosophy:**
• Zero runtime dependencies (Python stdlib only)
• 502 tests including 21 rounds of adversarial security review
• Single-file architecture (~1,200 lines) — auditable in an afternoon
• Apache 2.0 licensed, no telemetry

We dogfood this on our own repo. Every commit has a receipt.

→ Try it: `pip install aiir && aiir --pretty`
→ GitHub: https://github.com/invariant-systems-ai/aiir-action
→ Website: https://invariantsystems.io

#AIGovernance #OpenSource #SoftwareEngineering #EUAIAct #DevTools

---

## Reddit (r/programming, r/python)

**Title:** We built a zero-dependency tool that generates cryptographic receipts for AI-authored git commits (502 tests, Apache 2.0)

**Body:**

`pip install aiir && aiir --pretty`

That's it. No config file. No API key. No account.

**What it does:** Scans your git history for AI signals (Copilot co-author trailers, Claude/ChatGPT patterns, bot committers, etc.) and generates a content-addressed receipt per commit with SHA-256 hash chain.

**Why:** The EU AI Act is coming. Insurance companies are starting to ask. Your VP of Engineering will ask eventually. "What percentage of our code is AI-generated?" — you'll need an answer.

**The flex:**
- Zero pip dependencies. Only stdlib. `pip install aiir` adds nothing to your dependency tree.
- 502 tests. 21 rounds of hostile red-team review. We tested homoglyph evasion, terminal escape injection, delimiter attacks, and more.
- Single file (`aiir/cli.py`, ~1,200 lines). Read the whole thing on a coffee break.
- Runs as: GitHub Action · CLI · pre-commit hook · MCP server · GitLab CI template
- Apache 2.0. No telemetry. The tool receipts its own commits.

**What it's NOT:**
- Not an AI code detector. It reads signals that tools already leave in git metadata.
- Not a watermark or DRM.
- Known limitation: if an AI tool leaves zero trace, we can't detect it. Honest about this in the README.

Repo: https://github.com/invariant-systems-ai/aiir-action

Happy to answer any questions.
