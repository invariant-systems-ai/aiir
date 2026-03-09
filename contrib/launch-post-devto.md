---
title: "AI writes 40% of your code. Here's how to audit it."
description: "Introducing AIIR — open-source cryptographic receipts for AI-authored commits. EU AI Act compliance, SOC 2 evidence, and engineering visibility in one tool."
tags: ai, security, opensource, devops
canonical_url: https://invariantsystems.io/blog/introducing-aiir
---

# AI writes 40% of your code. Here's how to audit it.

GitHub reports that Copilot generates 46% of code in files where it's enabled. Claude Code, Cursor, Windsurf, and Devin are accelerating this further. By end of 2026, the majority of new code at many companies will be AI-generated.

But here's the problem: **none of it is tracked.**

Every AI-generated code change goes into `git commit` with no systematic record of what was human and what was machine. When your SOC 2 auditor asks "which code was AI-generated?" — or when the EU AI Act transparency requirements kick in — most teams will have no answer.

## Introducing AIIR

**AIIR** (AI Integrity Receipts) is an open-source tool that generates cryptographic receipts for every commit with AI involvement.

```bash
pip install aiir
aiir --range HEAD~5..HEAD --pretty
```

That's it. Zero dependencies. Apache 2.0.

## What's a receipt?

A receipt is a content-addressed JSON record that captures:

- **Who** made the commit (author, committer)
- **What** changed (files, diff hash)
- **Whether AI was involved** (50+ detection signals across Copilot, ChatGPT, Claude, Cursor, Windsurf, Devin, Gemini, Tabnine, Amazon Q, GitLab Duo)
- **Cryptographic proof** — SHA-256 hash over canonical JSON. Modify one bit and the hash breaks.

Optional **Sigstore signing** adds non-repudiation — keyless, OIDC-based, no key management.

## The compliance angle

### EU AI Act (phasing in now)

The EU AI Act's transparency obligations for general-purpose AI started in August 2025. High-risk system requirements follow in August 2026. If your product uses AI-generated code, you need provenance evidence.

AIIR receipts provide:
- Per-commit AI attribution with specific signal evidence
- Tamper-evident audit trail (content-addressed)
- Release-level coverage reports ("42% of commits in this release were AI-authored")
- SLSA-style Verification Summary Attestations (VSA) for release gates

### SOC 2 / ISO 27001

Auditors are starting to ask about AI code provenance. AIIR receipts slot directly into your control evidence:

> *"We track all AI involvement in code commits using content-addressed receipts with cryptographic integrity verification."*

That's a sentence your auditor wants to hear.

## How to integrate

### GitHub Actions (one line)

```yaml
- uses: invariant-systems-ai/aiir@v1
  with:
    sign: "true"
```

Every push generates receipts. Every PR gets a summary. Receipts are uploaded as artifacts.

### GitLab CI

```yaml
include:
  - component: $CI_SERVER_HOST/invariant-systems/aiir/receipt@main
```

Native MR comments, SAST dashboard reports, GitLab Duo detection.

### MCP Server (Claude, Copilot, Cursor)

AIIR is an MCP-native tool with 7 tools. In Claude Desktop:

```json
{
  "mcpServers": {
    "aiir": {
      "command": "aiir-mcp-server"
    }
  }
}
```

Then just say: *"receipt the last 5 commits"* in Claude Chat.

### Pre-commit

```yaml
repos:
  - repo: https://github.com/invariant-systems-ai/aiir
    rev: v1.2.0
    hooks:
      - id: aiir-receipt
```

### Policy enforcement

```bash
aiir --check --policy strict
```

Three presets:
- **strict**: Max 50% AI commits, signing required, hard-fail
- **balanced**: Signing recommended, soft-fail
- **permissive**: Warn-only

## The technical details

- **1,171 tests** across 17 modules
- **Zero runtime dependencies** — Python standard library only
- **Full specification** (SPEC.md, 553 lines) — any implementation that follows the spec produces identical hashes
- **Threat model** (503 lines) — 80+ adversarial test cases covering MCP injection, Unicode homoglyphs, path traversal, symlink attacks
- **JSON Schema** for receipt validation
- **25 conformance test vectors** for cross-implementation testing
- **JS/TS SDK** — zero-dependency receipt verification for browsers and Node.js

## What's next

We're working on:
- GitHub Marketplace listing (this week)
- VS Code extension with receipt visualization
- npm package for the JS SDK
- Receipt aggregation dashboard
- Deeper Anthropic MCP integration

## Try it

```bash
pip install aiir
cd your-project
aiir --range HEAD~10..HEAD --pretty
```

Or add it to your CI in 60 seconds with the GitHub Action.

**GitHub**: [github.com/invariant-systems-ai/aiir](https://github.com/invariant-systems-ai/aiir)
**PyPI**: [pypi.org/project/aiir](https://pypi.org/project/aiir/)
**Website**: [invariantsystems.io](https://invariantsystems.io)

---

*Built by [Invariant Systems](https://invariantsystems.io). We'd love feedback — especially from teams dealing with AI compliance in regulated industries. Open an issue or reach out at noah@invariantsystems.io.*
