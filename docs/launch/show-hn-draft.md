# Show HN Draft

> **Status**: Draft — review before posting.
> **Target**: [Hacker News – Show HN](https://news.ycombinator.com/showhn.html)
> **Guidance followed**: HN says — show something people can try, explain the
> backstory, state plainly what it does, avoid marketing language.

---

## Title

```text
Show HN: AIIR – tamper-evident receipts for AI-assisted git commits
```

Alternative titles (pick what feels right on the day):

```text
Show HN: AIIR – show which commits declared AI assistance
Show HN: AIIR – track AI-assisted git commits with cryptographic receipts
```

---

## Body

Hi HN — I'm Noah, founder of Invariant Systems. I built AIIR because I
couldn't answer a simple question about my own repo: which commits involved
AI tools?

**What it does**: AIIR scans your git history for declared AI signals
(Co-authored-by trailers, bot authors, commit message markers for 48+ tools
including Copilot, ChatGPT, Claude, Cursor, Gemini, Amazon Q, Devin, etc.)
and generates a content-addressed, SHA-256 receipt for each commit. Change
one byte of the receipt — the hash breaks. That's the tamper detection.

**Try it**:

```bash
pip install aiir
cd any-repo
aiir --pretty
```

That's it. No account, no cloud, no dependencies. Python 3.9+, Apache 2.0.
Works offline.

**What it doesn't do**: AIIR catches commits with *declared* AI markers. It
does not detect silent copy-paste from ChatGPT or Copilot completions that
don't leave a trailer. Detection is heuristic, not magic. The [threat model](https://github.com/invariant-systems-ai/aiir/blob/main/THREAT_MODEL.md)
is public and covers exactly what's in scope and what isn't.

**Why**: Stack Overflow's 2025 survey says 84% of developers use or plan to
use AI coding tools. EU AI Act transparency obligations start phasing in
August 2025. Your auditors, insurance underwriters, and compliance teams will
eventually ask: "which code was AI-generated?" Right now most companies can't
answer that question.

**Trust posture**: 1,893 tests collected with 100% coverage across Python
3.9–3.13 on three OSes. Zero runtime dependencies. Public STRIDE/DREAD
threat model. SLSA provenance on every PyPI release. CycloneDX SBOM on every
GitHub release. OpenSSF Scorecard. We receipt our own repo — every commit to
main gets a receipt
committed back automatically, and you can verify them:

```bash
for f in .receipts/*.json; do aiir --verify "$f"; done
```

**Signing**: Optional Sigstore keyless signing binds receipts to OIDC
identities via a transparency log. On by default in CI. That gets you from
tamper-evident (hash integrity) to tamper-proof (cryptographic non-repudiation).

**Integrations**: CLI, GitHub Action (Marketplace), GitLab CI/CD Catalog
component, MCP tool (works with Claude Desktop, VS Code Copilot, Cursor, etc.),
Docker, pre-commit hook. Also works with Azure Pipelines, Bitbucket, CircleCI,
Jenkins.

**Browser verifier**: <https://invariantsystems.io/verify> — paste a receipt,
verification runs entirely client-side. No upload, no server processing.

Repo: <https://github.com/invariant-systems-ai/aiir>
Docs: <https://invariantsystems.io/docs>
Spec: <https://invariantsystems.io/spec> (formal specification with conformance
vectors and CDDL grammar)

Happy to answer questions about the design, the detection heuristics, why
zero dependencies matters, or the Sigstore integration.

---

## Posting notes

- Post on a weekday, ideally Tuesday–Thursday 8–10am ET (HN peak)
- Title must start with "Show HN:" — no editorializing
- Don't ask for upvotes anywhere
- Reply to every comment in the first 2 hours
- Be transparent about limitations (declared-signal detection, solo founder)
- If someone asks about commercial plans, be honest: AIIR is free forever,
  Hub/Fortress are planned paid tiers for teams
- Link to THREAT_MODEL.md proactively when someone raises a limitation —
  it's already documented
