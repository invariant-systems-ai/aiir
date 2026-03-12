# Show HN: AIIR

**Title:** Show HN: AIIR – Cryptographic receipts for AI-assisted git commits (zero deps, Apache 2.0)

**URL:** <https://github.com/invariant-systems-ai/aiir>

**Text:**

Hi HN,

I built AIIR (AI Integrity Receipts) — an open-source tool that generates content-addressed receipts for every git commit, recording whether AI tools were involved.

    pip install aiir && cd your-repo && aiir --pretty

Zero dependencies. Python 3.9+. Your last commit now has a tamper-evident receipt in `.aiir/receipts.jsonl`. Also on PyPI: <https://pypi.org/project/aiir/>

The problem: AI writes a growing share of production code — Copilot, ChatGPT, Claude, Cursor — but git log doesn't distinguish human from machine. When your auditor asks "which commits involved AI?", you're grepping commit messages and hoping.

AIIR scans commits for declared AI signals (Co-authored-by trailers, bot accounts, commit message patterns), generates SHA-256 content-addressed JSON receipts, and optionally signs them with Sigstore (keyless OIDC — same infra as npm, PyPI, and Kubernetes). It evaluates receipts against configurable policy and emits SLSA-compatible Verification Summary Attestations.

It runs as a CLI, GitHub Action (uses: invariant-systems-ai/aiir@v1), GitLab CI/CD Catalog component, or MCP server for AI assistants.

~9k LOC Python, 1,800+ tests (mutation-tested, fuzz-tested, adversarial corpus), open receipt schema with a CDDL grammar (RFC 8610). Apache 2.0.

The EU AI Act (entered into force August 2024) is making this more concrete — GPAI transparency obligations applied from August 2025, and the broader transparency and high-risk rules phase in through 2026–2027. But even without a compliance driver, having a machine-readable record of which commits involved AI tools is useful for any team that ships code.

Feedback welcome on the receipt schema and policy model. The spec is in SPEC.md.
