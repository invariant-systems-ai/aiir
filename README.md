<p align="center">
  <a href="https://invariantsystems.io">
    <img src="docs/logo.svg" alt="Invariant Systems" width="120" height="120">
  </a>
</p>

# AIIR — AI Integrity Receipts

**AI wrote your code. Here's the receipt.** 🧾

[![PyPI](https://img.shields.io/pypi/v/aiir?color=blue)](https://pypi.org/project/aiir/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](https://github.com/invariant-systems-ai/aiir)
[![GitLab CI/CD Catalog](https://img.shields.io/badge/GitLab-CI%2FCD%20Catalog-orange?logo=gitlab)](https://gitlab.com/explore/catalog/invariant-systems/aiir)
[![AIIR Receipted](https://img.shields.io/badge/AIIR-Receipted%20✓-blue)](https://github.com/invariant-systems-ai/aiir)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/invariant-systems-ai/aiir/badge)](https://scorecard.dev/viewer/?uri=github.com/invariant-systems-ai/aiir)

<p align="center">
  <img src="docs/demo.svg" alt="AIIR terminal demo — pip install aiir && aiir --pretty" width="720">
</p>

---

## Why?

AI writes 30–50% of new code at most companies. Copilot, ChatGPT, Claude, Cursor — it all goes into `git commit` with no systematic record of what was human and what was machine.

> **EU AI Act** transparency obligations are phasing in now — general-purpose AI transparency rules from August 2025, high-risk system requirements from August 2026. AI-generated code with no provenance is a compliance gap.

Your auditors will ask: *"Which code was AI-generated? Can you prove it?"*

| Who asks | What they need |
|----------|---------------|
| **SOC 2 / ISO 27001 auditor** | Tamper-evident record of AI involvement per commit |
| **EU AI Act compliance** | Supports transparency and provenance evidence |
| **Insurance underwriter** | Record of AI involvement per commit |
| **Engineering leadership** | "We track all AI code" — with cryptographic receipts |

AIIR answers that question — for every commit with declared AI involvement. One command. Zero dependencies. Apache 2.0.

---

## What's a receipt?

```
┌─ Receipt: g1-a3f8b2c1d4e5f6a7b8c9d0e1...
│  Commit:  c4dec85630
│  Subject: feat: add new auth middleware
│  Author:  Jane Dev <jane@example.com>
│  Files:   4 changed
│  AI:      YES (copilot)
│  Hash:    sha256:7f3a...
│  Time:    2026-03-06T09:48:59Z
└──────────────────────────────────────────
```

Every commit gets a **content-addressed** receipt — a JSON object that records *what* was committed, *who* wrote it, and *whether AI was involved*. Change one character? The hash breaks. That's **integrity** (tamper detection).

For **authenticity** (proving *who* generated the receipt), enable Sigstore keyless signing — see [Sigstore signing](#sigstore-signing) below. Without signing, receipts prove internal consistency but not provenance — anyone who can run `aiir` on the same commit can produce an equivalent receipt.

---

## Try It

```bash
pip install aiir
cd your-repo
aiir --pretty
```

That's it. Your last commit now has a receipt in `.aiir/receipts.jsonl` — a
tamper-evident JSONL ledger that auto-indexes and deduplicates. Run it again:
same commit, zero duplicates. Zero dependencies. Python 3.9+.

### Verify a receipt

Receipts are content-addressed — change one byte, the hash breaks:

```bash
aiir --verify .aiir/receipts.jsonl --explain
```

See [Tamper Detection](docs/tamper-detection.md) for a walkthrough of what
happens when a receipt is modified.

---

## Every Platform. One Command.

### 🤖 MCP Tool — Let your AI do it

Any MCP-aware AI assistant (Claude, Copilot, Cursor, Continue, Cline, Windsurf) can discover and use AIIR as a tool. Add to your MCP config:

```json
{
  "mcpServers": {
    "aiir": {
      "command": "aiir-mcp-server",
      "args": ["--stdio"]
    }
  }
}
```

Now your AI assistant generates receipts automatically after writing code. It says: *"I just committed code for you. Let me generate an AIIR receipt."*

### 💻 CLI — Run it yourself

```bash
# Receipt the last commit (auto-saves to .aiir/receipts.jsonl)
aiir --pretty

# Receipt a whole PR branch
aiir --range origin/main..HEAD --pretty

# Only AI-authored commits, save to directory (CI mode)
aiir --ai-only --output .receipts/

# Print JSON to stdout for piping (bypasses ledger)
aiir --json | jq .receipt_id

# JSON Lines output for streaming / piping
aiir --range HEAD~5..HEAD --jsonl | jq .receipt_id

# Custom ledger location
aiir --ledger .audit/

# Verify a receipt hasn't been tampered with
aiir --verify receipt.json
```

### ⚙️ GitHub Action — Automate it in CI

```yaml
# .github/workflows/aiir.yml — signed receipts (default)
name: AIIR
on:
  push:
    tags-ignore: ['**']   # Don't receipt tag pushes (receipts the whole history)
  pull_request:

permissions:
  id-token: write   # Required for Sigstore keyless signing
  contents: read

jobs:
  receipt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: invariant-systems-ai/aiir@v1
        with:
          output-dir: .receipts/
```

Signing is **on by default** — each receipt gets a Sigstore bundle (Fulcio certificate + Rekor transparency log entry).
Artifacts uploaded automatically when `output-dir` is set.

<details>
<summary><strong>Unsigned (opt out of signing, no permissions needed)</strong></summary>

```yaml
name: AIIR
on:
  push:
    tags-ignore: ['**']
  pull_request:

jobs:
  receipt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: invariant-systems-ai/aiir@v1
        with:
          sign: false
```

> **Note**: Without signing, receipts are *tamper-evident* (hash integrity) but not
> *tamper-proof* (anyone who can run `aiir` on the same commit can recreate a matching receipt).
> For cryptographic non-repudiation, use the signed default above.

</details>

### 🪝 pre-commit Hook — Receipt every commit locally

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/invariant-systems-ai/aiir
    rev: v1.0.15
    hooks:
      - id: aiir
```

Runs **post-commit** (after your commit is created, since it needs the commit SHA to generate a receipt). Customise with args:

```yaml
      - id: aiir
        args: ["--ai-only", "--output", ".receipts"]
```

### 🦊 GitLab CI — Receipt merge requests and pushes

**CI/CD Catalog component** (recommended — [browse in Catalog](https://gitlab.com/explore/catalog/invariant-systems/aiir)):

```yaml
# .gitlab-ci.yml — one line
include:
  - component: gitlab.com/invariant-systems/aiir/receipt@1
    inputs:
      stage: test
```

All inputs are optional and typed:

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `stage` | string | `test` | Pipeline stage |
| `version` | string | `1.0.15` | AIIR version from PyPI |
| `ai-only` | boolean | `false` | Only receipt AI-authored commits |
| `output-dir` | string | `.aiir-receipts` | Artifact output directory |
| `artifact-expiry` | string | `90 days` | Artifact retention |
| `extra-args` | string | `""` | Additional CLI flags |

**Legacy include** (still works — no Catalog required):

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/invariant-systems-ai/aiir/v1.0.15/templates/gitlab-ci.yml'
```

**Self-hosted GitLab?** Mirror the repo and use `project:` instead:

```yaml
include:
  - project: 'your-group/aiir'
    ref: 'v1.0.15'
    file: '/templates/gitlab-ci.yml'
```

Customise via pipeline variables: `AIIR_VERSION`, `AIIR_AI_ONLY`, `AIIR_EXTRA_ARGS`, `AIIR_ARTIFACT_EXPIRY`. See [templates/gitlab-ci.yml](templates/gitlab-ci.yml) for the full template.

### 🐳 Docker — Run anywhere

```bash
# Receipt the current repo (mount it in)
docker run --rm -v "$(pwd):/repo" -w /repo invariantsystems/aiir --pretty

# AI-only, save receipts
docker run --rm -v "$(pwd):/repo" -w /repo invariantsystems/aiir --ai-only --output .receipts/
```

Works in any CI/CD system that supports container steps — Tekton, Buildkite, Drone, Woodpecker, etc.

### More CI/CD Platforms

<details>
<summary><strong>Bitbucket Pipelines</strong></summary>

```yaml
# bitbucket-pipelines.yml
pipelines:
  default:
    - step:
        name: AIIR Receipt
        image: python:3.11
        script:
          - pip install aiir
          - aiir --pretty --output .receipts/
        artifacts:
          - .receipts/**
```

Full template with PR support: [templates/bitbucket-pipelines.yml](templates/bitbucket-pipelines.yml)

</details>

<details>
<summary><strong>Azure DevOps</strong></summary>

```yaml
# azure-pipelines.yml
steps:
  - task: UsePythonVersion@0
    inputs: { versionSpec: '3.11' }
  - script: pip install aiir && aiir --pretty --output .receipts/
    displayName: 'Generate AIIR receipt'
  - publish: .receipts/
    artifact: aiir-receipts
```

Full template with PR/CI detection: [templates/azure-pipelines.yml](templates/azure-pipelines.yml)

</details>

<details>
<summary><strong>CircleCI</strong></summary>

```yaml
# .circleci/config.yml
jobs:
  receipt:
    docker:
      - image: cimg/python:3.11
    steps:
      - checkout
      - run: pip install aiir && aiir --pretty --output .receipts/
      - store_artifacts:
          path: .receipts
```

Full template: [templates/circleci/config.yml](templates/circleci/config.yml)

</details>

<details>
<summary><strong>Jenkins</strong></summary>

```groovy
// Jenkinsfile
pipeline {
    agent { docker { image 'python:3.11' } }
    stages {
        stage('AIIR Receipt') {
            steps {
                sh 'pip install aiir && aiir --pretty --output .receipts/'
                archiveArtifacts artifacts: '.receipts/**'
            }
        }
    }
}
```

Full template: [templates/jenkins/Jenkinsfile](templates/jenkins/Jenkinsfile)

</details>

---

## What It Detects

AIIR detects three categories of signals in commit metadata:

### Declared AI assistance

Commits where a human or tool explicitly attributed AI involvement.

| Signal | Examples |
|--------|----------|
| **Copilot** | `Co-authored-by: Copilot`, `Co-authored-by: GitHub Copilot` |
| **ChatGPT** | `Generated by ChatGPT`, `Co-authored-by: ChatGPT` |
| **Claude** | `Generated by Claude`, `Co-authored-by: Claude` |
| **Cursor** | `Generated by Cursor`, `Co-authored-by: Cursor` |
| **Amazon Q / CodeWhisperer** | `amazon q`, `codewhisperer`, `Co-authored-by: Amazon Q` |
| **Devin** | `Co-authored-by: Devin`, `devin[bot]` |
| **Gemini** | `gemini code assist`, `google gemini`, `gemini[bot]` |
| **Tabnine** | `tabnine` in commit metadata |
| **Aider** | `aider:` prefix in commit messages |
| **Generic markers** | `AI-generated`, `LLM-generated`, `machine-generated` |
| **Git trailers** | `Generated-by:`, `AI-assisted:`, `Tool:` git trailers |

### Automation / bot activity

Commits made by CI bots and automated dependency tools. These are *not* gen-AI assistance — they indicate automated (non-human) authorship.

| Signal | Examples |
|--------|----------|
| **Dependabot** | `dependabot[bot]` as author |
| **Renovate** | `renovate[bot]` as author |
| **Snyk** | `snyk-bot` as author |
| **CodeRabbit** | `coderabbit[bot]` as author |
| **GitHub Actions** | `github-actions[bot]` as author |
| **DeepSource** | `deepsource[bot]` as author |

> **Note**: Since v1.0.4, bot and AI signals are fully separated. A Dependabot commit gets `is_bot_authored: true` and `authorship_class: "bot"`, **not** `is_ai_authored: true`. The `authorship_class` field provides a single structured value: `"human"`, `"ai_assisted"`, `"bot"`, or `"ai+bot"`.

<details>
<summary><strong>Detection limitations</strong></summary>

AI detection uses `heuristic_v2` — matching on commit metadata signals.

**What it catches:**
- Commits with `Co-authored-by: Copilot` or similar trailers
- Bot-authored commits (Dependabot, Renovate) — classified separately as `bot`
- Explicit AI markers (`AI-generated`, `Generated by ChatGPT`, etc.)

**What it doesn't catch:**
- Copilot inline completions (no metadata trace by default)
- ChatGPT/Claude copy-paste without attribution
- Squash-merged AI branches with clean messages
- Amended commits that remove AI trailers

This is by design — AIIR receipts what's declared, not what's hidden.

</details>

---

## Deep Dive

<details>
<summary><strong>Ledger — .aiir/ directory</strong></summary>

By default, `aiir` appends receipts to a local JSONL ledger:

```
.aiir/
├── receipts.jsonl   # One receipt per line (append-only)
└── index.json       # Auto-maintained lookup index
```

**Why a ledger?**
- **One file to commit** — `git add .aiir/` is your entire audit trail
- **Auto-deduplicates** — re-running `aiir` on the same commit is a no-op
- **Git-friendly** — append-only JSONL means clean diffs and easy `git blame`
- **Queryable** — `jq`, `grep`, and `wc -l` all work naturally

**index.json** tracks every commit SHA, receipt count, and authorship breakdown:

```json
{
  "version": 1,
  "receipt_count": 42,
  "ai_commit_count": 7,
  "bot_commit_count": 3,
  "ai_percentage": 16.7,
  "unique_authors": 5,
  "first_receipt": "2026-03-01T10:00:00Z",
  "latest_timestamp": "2026-03-06T09:48:59Z",
  "commits": {
    "c4dec85630...": { "receipt_id": "g1-a3f8...", "ai": true, "bot": false, "authorship_class": "ai_assisted", "author": "jane@example.com" },
    "e7b1a9f203...": { "receipt_id": "g1-b2c1...", "ai": false, "bot": true, "authorship_class": "bot", "author": "dependabot[bot]" }
  }
}
```

**Output modes:**

| Flag | Behaviour |
|------|-----------|
| _(none)_ | Append to `.aiir/receipts.jsonl` (default) |
| `--ledger .audit/` | Append to custom ledger directory |
| `--json` | Print JSON to stdout — no ledger write* |
| `--jsonl` | Print JSON Lines to stdout — no ledger write* |
| `--output dir/` | Write individual files to `dir/` — no ledger write* |
| `--pretty` | Human-readable summary to stderr (combines with any mode) |

\* Adding `--ledger` explicitly overrides and writes to **both** destinations.

**Tip**: Add `.aiir/` to your repo. It becomes a permanent, auditable,
append-only record of every receipted commit.

</details>

<details>
<summary><strong>Receipt format</strong></summary>

Each receipt is a content-addressed JSON document:

```json
{
  "type": "aiir.commit_receipt",
  "schema": "aiir/commit_receipt.v1",
  "receipt_id": "g1-a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4",
  "content_hash": "sha256:7f3a...",
  "timestamp": "2026-03-06T09:48:59Z",
  "commit": {
    "sha": "c4dec85630232666aba81b6588894a11d07e5d18",
    "author": { "name": "Jane Dev", "email": "jane@example.com" },
    "subject": "feat: add receipt generation to CI",
    "diff_hash": "sha256:b2c1...",
    "files_changed": 4
  },
  "ai_attestation": {
    "is_ai_authored": true,
    "signals_detected": ["message_match:co-authored-by: copilot"],
    "signal_count": 1,
    "is_bot_authored": false,
    "bot_signals_detected": [],
    "bot_signal_count": 0,
    "authorship_class": "ai_assisted",
    "detection_method": "heuristic_v2"
  },
  "extensions": {}
}
```

**Content-addressed** = the `receipt_id` is derived from SHA-256 of the receipt's canonical JSON. Change any field → hash changes → receipt invalid.

> **`is_ai_authored`** = true when AI coding tools are detected (Copilot, ChatGPT, Claude, etc.).
> **`is_bot_authored`** = true when automation/CI bots are detected (Dependabot, Renovate, etc.).
> **`authorship_class`** = structured category: `"human"`, `"ai_assisted"`, `"bot"`, or `"ai+bot"`.
> These are fully independent — a Dependabot commit gets `bot`, not `ai_assisted`.

> **Note**: Unsigned receipts are *tamper-evident*, not *tamper-proof*. Anyone who can re-run `aiir` on the same commit can recreate a matching receipt. For cryptographic non-repudiation, enable [Sigstore signing](#sigstore-signing).

> **Receipt identity depends on repository provenance.**
> The `provenance.repository` field (your `git remote get-url origin`) is part
> of the content hash. The same commit will produce a **different `receipt_id`**
> if the remote URL changes — for example after a fork, a repo rename, or
> adding an origin to a previously local-only repo. If you need stable receipt
> identity as a durable external reference, generate receipts after your remote
> is configured. Fields inside `extensions` (such as `namespace`) are *not*
> part of the content hash, so they can change without invalidating a receipt.

</details>

<details>
<summary><strong>GitHub Action — inputs & outputs</strong></summary>

### Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `ai-only` | Only receipt AI-authored commits | `false` |
| `commit-range` | Specific commit range (e.g., `main..HEAD`) | Auto-detected from event |
| `output-dir` | Directory to write receipt JSON files | _(prints to log)_ |
| `sign` | Sign receipts with Sigstore | `true` |

### Outputs

| Output | Description |
|--------|-------------|
| `receipt_count` | Number of receipts generated |
| `ai_commit_count` | Number of AI-authored commits detected |
| `receipts_json` | Full JSON array of all receipts (set to `"OVERFLOW"` if >1 MB) |
| `receipts_overflow` | `"true"` when `receipts_json` exceeded 1 MB and was truncated |

> ⚠️ **Security note on `receipts_json`**: Contains commit metadata which may include shell metacharacters. **Never** interpolate directly into `run:` steps via `${{ }}`. Write to a file instead.

### Example: PR Comment with AI Summary

```yaml
name: AI Audit Trail
on: pull_request

jobs:
  receipt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: invariant-systems-ai/aiir@v1
        id: receipt
        with:
          output-dir: .receipts/

      - name: Comment on PR
        if: steps.receipt.outputs.ai_commit_count > 0
        uses: actions/github-script@v7
        with:
          script: |
            const count = '${{ steps.receipt.outputs.ai_commit_count }}';
            const total = '${{ steps.receipt.outputs.receipt_count }}';
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `🔐 **AIIR**: ${total} commits receipted, ${count} AI-authored.\n\nReceipts uploaded as build artifacts.`
            });
```

### Example: Enforce Receipt Policy

```yaml
name: Require AI Receipts
on: pull_request

jobs:
  receipt-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: invariant-systems-ai/aiir@v1
        id: receipt

      - name: Enforce receipt policy
        if: steps.receipt.outputs.ai_commit_count > 0
        run: |
          echo "✅ ${{ steps.receipt.outputs.ai_commit_count }} AI commits receipted"
```

</details>

<details id="sigstore-signing">
<summary><strong>Sigstore signing</strong></summary>

Optionally sign receipts with [Sigstore](https://sigstore.dev) keyless signing for cryptographic non-repudiation:

```yaml
name: AIIR (Signed)
on:
  push:
    tags-ignore: ['**']
  pull_request:

permissions:
  id-token: write
  contents: read

jobs:
  receipt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: invariant-systems-ai/aiir@v1
        with:
          output-dir: .receipts/
          sign: true
```

> **Fork PRs**: GitHub does not grant OIDC tokens to fork pull requests. If your project accepts external contributions, either use `sign: false` for PRs or conditionally skip signing on forks. AIIR will detect the missing credential and fail with a clear error rather than hanging.

Each receipt gets an accompanying `.sigstore` bundle:
- **Fulcio certificate** — short-lived cert proving the signer's OIDC identity
- **Rekor transparency log** — tamper-evident public record
- **Signature** — cryptographic binding

Verify locally:

```bash
# Basic: checks signature is valid (any signer)
aiir --verify receipt.json --verify-signature

# Recommended: pin to a specific CI identity for non-repudiation
aiir --verify receipt.json --verify-signature \
  --signer-identity "https://github.com/myorg/myrepo/.github/workflows/aiir.yml@refs/heads/main" \
  --signer-issuer "https://token.actions.githubusercontent.com"
```

> ⚠️ **Always use `--signer-identity` and `--signer-issuer` in production.**
> Without identity pinning, verification accepts any valid Sigstore signature.
> That proves *someone* signed it, but not *your CI* signed it.
> Extensions fields are **not** part of the content hash and should not be treated as security-relevant.

Install signing support: `pip install aiir[sign]`

</details>

<details>
<summary><strong>MCP server details</strong></summary>

The AIIR MCP server exposes two tools:

| Tool | Description |
|------|-------------|
| `aiir_receipt` | Generate receipts for commit(s). Accepts `commit`, `range`, `ai_only`, `pretty`. |
| `aiir_verify` | Verify a receipt file's integrity. Accepts `file` path. |

**Install globally:**

```bash
pip install aiir
```

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "aiir": {
      "command": "aiir-mcp-server",
      "args": ["--stdio"]
    }
  }
}
```

**VS Code / Copilot** (`.vscode/mcp.json`):
```json
{
  "servers": {
    "aiir": {
      "command": "aiir-mcp-server",
      "args": ["--stdio"]
    }
  }
}
```

**Cursor** (`.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "aiir": {
      "command": "aiir-mcp-server",
      "args": ["--stdio"]
    }
  }
}
```

**Continue** (`.continue/mcpServers/aiir.yaml`):
```yaml
name: AIIR
version: 0.0.1
schema: v1
mcpServers:
  - name: aiir
    command: aiir-mcp-server
    args:
      - --stdio
```

Or copy any JSON MCP config (e.g., from Claude Desktop) into `.continue/mcpServers/mcp.json` —
Continue auto-discovers it.

**Cline** (open MCP Servers panel → add to `cline_mcp_settings.json`):
```json
{
  "mcpServers": {
    "aiir": {
      "command": "aiir-mcp-server",
      "args": ["--stdio"]
    }
  }
}
```

**Windsurf** (`~/.codeium/windsurf/mcp_config.json`):
```json
{
  "mcpServers": {
    "aiir": {
      "command": "aiir-mcp-server",
      "args": ["--stdio"]
    }
  }
}
```

The server uses the same zero-dependency core as the CLI. No extra packages needed.

</details>

<details>
<summary><strong>Detection internals</strong></summary>

See [THREAT_MODEL.md](THREAT_MODEL.md) for full STRIDE analysis, DREAD scoring, and attack trees.

Homoglyph detection uses the full [Unicode TR39 confusable map](https://www.unicode.org/reports/tr39/) — 669 single-codepoint → ASCII mappings across 69 scripts (Cyrillic, Greek, Armenian, Cherokee, Coptic, Lisu, Warang Citi, Mathematical, and others). Combined with NFKC normalization, this covers all single-character homoglyphs documented by the Unicode Consortium. Multi-character confusable sequences are not covered — see S-02 in the threat model.

</details>

---

## Dogfood: This Repo Receipts Itself

AIIR eats its own dogfood. Every commit to `main` gets a
cryptographic receipt committed back to `.receipts/` automatically.

**Verify it yourself:**

```bash
pip install aiir
for f in .receipts/*.json; do aiir --verify "$f"; done
```

The [dogfood CI workflow](.github/workflows/dogfood.yml) generates receipts
on every push to `main` and commits them back to the repo. Locally, the
[pre-commit hook](.pre-commit-config.yaml) receipts every commit at
`post-commit` stage.

---

## Security

Extensive [security controls](THREAT_MODEL.md). 1075+ tests. Zero dependencies.

See [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md), and
[Tamper Detection](docs/tamper-detection.md).
### Trust Tiers

Receipts exist at three trust levels. Choose the right one for your use case:

| Tier | What you get | Use when |
|------|-------------|----------|
| **Unsigned** (`sign: false`) | Tamper-evident — hash integrity detects modification, but anyone can recreate a matching receipt from the same commit | Local development, smoke testing, internal audit trails |
| **Signed** (`sign: true`, default) | Tamper-proof — Sigstore signature binds the *entire* receipt (including extensions) to an OIDC identity via a transparency log | CI/CD compliance, SOC 2 evidence, regulatory audit |
| **Enveloped** (in-toto Statement) | Signed + wrapped in a supply-chain attestation envelope with explicit subject and predicate binding | SLSA provenance, cross-system verification, EU AI Act evidence packages |

> **Rule of thumb**: For anything an auditor will read, use **Signed** or
> **Enveloped**. Unsigned receipts are developer convenience — do not
> cite them as tamper-proof evidence. See [SPEC.md §11.1](SPEC.md) for
> the full normative definition.
---

## Specification & Schemas

AIIR publishes a formal specification and machine-readable schema for third-party implementors:

| Document | Purpose |
|----------|---------|
| [SPEC.md](SPEC.md) | Normative specification — canonical JSON, content addressing, verification algorithm (RFC 2119) |
| [schemas/commit_receipt.v1.schema.json](schemas/commit_receipt.v1.schema.json) | JSON Schema (draft 2020-12) for `aiir/commit_receipt.v1` |
| [schemas/test_vectors.json](schemas/test_vectors.json) | 25 conformance test vectors with precomputed hashes |
| [THREAT_MODEL.md](THREAT_MODEL.md) | STRIDE/DREAD threat model with comprehensive security controls |
| [docs/tamper-detection.md](docs/tamper-detection.md) | Walkthrough — what happens when a receipt is modified |

---

## About

Built by [Invariant Systems, Inc.](https://invariantsystems.io)

**License**: Apache-2.0 — See [LICENSE](LICENSE)

**Trademarks**: "AIIR", "AI Integrity Receipts", and "Invariant Systems"
are trademarks of Invariant Systems, Inc. See [TRADEMARK.md](TRADEMARK.md).

**Signed releases**: Every PyPI release is published using
[Trusted Publishers](https://docs.pypi.org/trusted-publishers/) (OIDC) —
no static API tokens. The GitHub Actions workflow authenticates to PyPI via
short-lived OIDC tokens issued by GitHub's identity provider. This means:

- **No secrets to leak** — publishing credentials are ephemeral
- **Verifiable provenance** — each release is tied to a specific GitHub Actions
  run, commit SHA, and workflow file
- **Tamper-resistant pipeline** — the publish environment is protected by
  GitHub's deployment protection rules

The [publish workflow](.github/workflows/publish.yml) runs: tag push →
full test suite → build → OIDC publish → verify on PyPI.

**Enterprise**: The AIIR open-source library is and will remain free under
Apache-2.0. Invariant Systems may offer additional commercial products and
services (hosted verification, enterprise dashboards, SLA-backed APIs)
under separate terms.
