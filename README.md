<!-- markdownlint-disable MD041 -->
<p align="center">
  <a href="https://invariantsystems.io">
    <img src="docs/logo.svg" alt="Invariant Systems" width="120" height="120">
  </a>
</p>

# AIIR — AI Integrity Receipts

**Verifiable provenance for AI-assisted commits. Generate receipts. Verify releases. Attest for auditors.** 🧾

> `git commit` → receipt → policy evaluation → signed [Verification Summary Attestation](https://slsa.dev/spec/v1.0/verification_summary) (VSA)

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-AIIR-blue?logo=github)](https://github.com/marketplace/actions/aiir-ai-integrity-receipts)
[![PyPI](https://img.shields.io/pypi/v/aiir?color=blue)](https://pypi.org/project/aiir/)
[![CI](https://github.com/invariant-systems-ai/aiir/actions/workflows/ci.yml/badge.svg)](https://github.com/invariant-systems-ai/aiir/actions/workflows/ci.yml)
[![Release Smoke](https://github.com/invariant-systems-ai/aiir/actions/workflows/release-smoke.yml/badge.svg)](https://github.com/invariant-systems-ai/aiir/actions/workflows/release-smoke.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](https://github.com/invariant-systems-ai/aiir)
[![GitLab CI/CD Catalog](https://img.shields.io/badge/GitLab-CI%2FCD%20Catalog-orange?logo=gitlab)](https://gitlab.com/explore/catalog/invariant-systems/aiir)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/invariant-systems-ai/aiir/badge)](https://scorecard.dev/viewer/?uri=github.com/invariant-systems-ai/aiir)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12134/badge)](https://www.bestpractices.dev/projects/12134)
[![Standards Readiness](https://img.shields.io/badge/Standards--Readiness-68.9%2F100-orange)](docs/standards-readiness.md)
[![AIIR Receipted](https://img.shields.io/badge/AIIR-Receipted%20✓-blue)](https://github.com/invariant-systems-ai/aiir)
[![GitHub stars](https://img.shields.io/github/stars/invariant-systems-ai/aiir?style=social)](https://github.com/invariant-systems-ai/aiir/stargazers)

> **Using AIIR?** Please [★ star this repo](https://github.com/invariant-systems-ai/aiir/stargazers) — it helps others discover the project and signals community support.
> Citing in research or policy? See the [**Cite this repository**](https://github.com/invariant-systems-ai/aiir) button on GitHub (powered by `CITATION.cff`).

<p align="center">
  <img src="docs/demo.svg" alt="AIIR terminal demo — pip install aiir && aiir --pretty" width="720">
</p>

## Quick Start — 30 seconds

```bash
pip install aiir        # zero dependencies, Python 3.9+
cd your-repo
aiir --pretty           # receipt your last commit → .aiir/receipts.jsonl
```

> **CI?** Drop [`examples/github-actions`](examples/github-actions/.github/workflows/aiir.yml) into your repo, or `uses: invariant-systems-ai/aiir@v1` in any workflow.<br>
> **GitLab?** See [`examples/gitlab-demo`](examples/gitlab-demo/.gitlab-ci.yml) or the [CI/CD Catalog component](https://gitlab.com/explore/catalog/invariant-systems/aiir).<br>
> **MCP?** `aiir-mcp-server --stdio` — your AI assistant generates receipts automatically.

---

## Why?

AI writes 30–50% of new code at most companies. Copilot, ChatGPT, Claude, Cursor — it all goes into `git commit` with no systematic record of what was human and what was machine.

> **EU AI Act** transparency obligations are phasing in now — general-purpose AI transparency rules from August 2025, high-risk system requirements from August 2026. Code with undocumented AI involvement is a compliance gap.

Your auditors will ask: *"Which commits involved AI tools? Can you show the audit trail?"*

And then: *"Did you verify every release against policy before shipping?"*

| Who asks | What they need |
|----------|---------------|
| **SOC 2 / ISO 27001 auditor** | Tamper-evident record of declared AI involvement per commit |
| **EU AI Act compliance** | Transparency evidence for commits with AI markers + verified release attestation |
| **Insurance underwriter** | Policy-evaluated verification of declared AI involvement per release |
| **GRC / supply-chain security** | SLSA-compatible Verification Summary Attestation (VSA) |
| **Engineering leadership** | "We track declared AI involvement *and* verify every release" — with cryptographic receipts |

AIIR answers both questions. **Generate** receipts for every commit. **Verify** releases against policy. **Attest** the result as a machine-readable VSA. One tool. Zero dependencies. Apache 2.0.

---

## What's a receipt?

```text
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

## How It Works — The Verification Pipeline

AIIR operates at three levels, matching modern supply-chain security architecture:

```text
git commit
    ↓
AIIR receipt (content-addressed, per-commit)
    ↓
Sigstore signing (OIDC identity, transparency log)
    ↓
Policy evaluation (org rules, AI-usage thresholds)
    ↓
Verification Summary Attestation (in-toto Statement v1)
    ↓
CI gate (PASS / FAIL — enforceable via branch protection)
```

This aligns directly with [SLSA](https://slsa.dev), [Sigstore](https://sigstore.dev), and [in-toto](https://in-toto.io) — the same stack used by npm, PyPI, Kubernetes, and the Linux kernel.

**For developers**: Add `aiir` to your CI and get a pass/fail check on every PR.
**For security teams**: Get policy-evaluated verification results as signed attestations.
**For auditors**: Query the JSONL ledger or VSA artifacts — every claim is cryptographically verifiable.

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

### Verify a release

Evaluate all receipts against policy and emit a [Verification Summary Attestation](https://slsa.dev/verification_summary) (VSA):

```bash
aiir --verify-release --policy strict --emit-vsa
```

AIIR acts as a **verifier** — it identifies itself (`https://invariantsystems.io/verifiers/aiir`), names the policy, evaluates every receipt, computes commit coverage, and emits a signed PASS/FAIL decision as an [in-toto Statement v1](https://in-toto.io/Statement/v1). Downstream CI gates, auditors, and GRC platforms consume the VSA without re-evaluating receipts themselves.

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

# Verify a receipt — with human-readable explanation
aiir --verify receipt.json --explain

# Wrap receipts in an in-toto Statement v1 envelope (SLSA-compatible)
aiir --range HEAD~3..HEAD --in-toto --output .receipts/

# Sign + wrap for full supply-chain attestation
aiir --sign --in-toto --output .receipts/

# Attach agent attestation metadata (Copilot, Cursor, Claude, etc.)
aiir --agent-tool copilot --agent-model gpt-4o --agent-context ide

# Initialize .aiir/ directory for a new project
aiir --init                        # scaffolds receipts.jsonl, index, config, .gitignore
aiir --init --policy strict        # also creates policy.json

# Review receipts — human attestation that a commit was reviewed
aiir --review HEAD                 # defaults to "approved"
aiir --review abc123 --review-outcome rejected --review-comment "needs refactor"

# Commit trailers — append AIIR metadata to git commit messages
aiir --trailer                     # prints AIIR-Receipt, AIIR-Type, AIIR-AI, AIIR-Verified

# Policy engine — initialise and enforce org-wide rules
aiir --policy-init strict          # creates .aiir/policy.json
aiir --check --policy strict       # CI gate: fail if policy violated
aiir --check --max-ai-percent 50   # fail if >50% commits are AI-authored

# Verify an entire release against policy, emit a VSA
aiir --verify-release --receipts .aiir/receipts.jsonl --emit-vsa --policy strict

# Ledger utilities
aiir --stats                       # dashboard of ledger statistics
aiir --badge                       # shields.io badge Markdown
aiir --export backup.json          # portable JSON bundle

# Privacy — omit file paths from receipts
aiir --redact-files --namespace acme-corp

# Native GitLab CI mode (MR comments, dotenv outputs)
aiir --gitlab-ci --output .receipts/

# GitLab SAST report for Security Dashboard
aiir --gitlab-ci --gl-sast-report
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
  id-token: write      # Required for Sigstore keyless signing
  contents: read
  checks: write        # P0: aiir/verify Check Run on every PR
  pull-requests: write # P3: automatic receipt summary comment on PRs

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

> **Automatic PR integration**: When `GITHUB_TOKEN` is available, the Action automatically:
>
> - **Creates an `aiir/verify` Check Run** — visible as a pass/fail status check on every PR (enforce via branch protection). Requires `checks: write`.
> - **Posts a receipt summary comment** — idempotent (updates in place, no comment spam). Requires `pull-requests: write`.

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
    rev: v1.2.5
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
| `version` | string | `1.2.5` | AIIR version from PyPI |
| `ai-only` | boolean | `false` | Only receipt AI-authored commits |
| `output-dir` | string | `.aiir-receipts` | Artifact output directory |
| `artifact-expiry` | string | `90 days` | Artifact retention |
| `sign` | boolean | `true` | Sigstore keyless signing (GitLab OIDC) |
| `gl-sast-report` | boolean | `false` | Generate SAST report for Security Dashboard |
| `approval-threshold` | number | `0` | AI% threshold for extra MR approvals (0 = off) |
| `extra-args` | string | `""` | Additional CLI flags |

**Legacy include** (still works — no Catalog required):

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/invariant-systems-ai/aiir/v1.2.5/templates/gitlab-ci.yml'
```

**Self-hosted GitLab?** Mirror the repo and use `project:` instead:

```yaml
include:
  - project: 'your-group/aiir'
    ref: 'v1.2.5'
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
| **GitLab Duo** | `gitlab duo`, `duo code suggestions`, `duo chat`, `duo enterprise`, `Co-authored-by: gitlab duo` |
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
| **GitLab Bot** | `gitlab-bot` as author |
| **DeepSource** | `deepsource[bot]` as author |

> **Note**: Since v1.0.4, bot and AI signals are fully separated. A Dependabot commit gets `is_bot_authored: true` and `authorship_class: "bot"`, **not** `is_ai_authored: true`. The `authorship_class` field provides a single structured value: `"human"`, `"ai_assisted"`, `"bot"`, or `"ai+bot"`.

<details open>
<summary><strong>Detection scope and limitations</strong></summary>

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

This is by design — AIIR receipts what's *declared*, not what's hidden. Receipts prove the integrity of what was recorded, not the completeness of AI involvement.

</details>

---

## Deep Dive

<details>
<summary><strong>Ledger — .aiir/ directory</strong></summary>

By default, `aiir` appends receipts to a local JSONL ledger:

```text
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
| *(none)* | Append to `.aiir/receipts.jsonl` (default) |
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

<!-- -->

> **Note**: Unsigned receipts are *tamper-evident*, not *tamper-proof*. Anyone who can re-run `aiir` on the same commit can recreate a matching receipt. For cryptographic non-repudiation, enable [Sigstore signing](#sigstore-signing).

<!-- -->

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
| `output-dir` | Directory to write receipt JSON files | *(prints to log)* |
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

The AIIR MCP server exposes seven tools:

| Tool | Description |
|------|-------------|
| `aiir_receipt` | Generate receipts for commit(s). Accepts `commit`, `range`, `ai_only`, `pretty`. |
| `aiir_verify` | Verify a receipt file's integrity. Accepts `file` path. |
| `aiir_stats` | Ledger statistics: receipt count, AI percentage, unique authors. |
| `aiir_explain` | Human-readable explanation of verification results. |
| `aiir_policy_check` | Check ledger against org AI-usage policy thresholds. |
| `aiir_verify_release` | Release-scoped verification — evaluate receipts against policy, emit VSA. |
| `aiir_gitlab_summary` | GitLab-flavored Markdown summary for Duo Chat, MR comments, and CI. |

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
<summary><strong>Release verification & VSA</strong></summary>

Verify an entire release against policy and produce a machine-readable [Verification Summary Attestation (VSA)](https://slsa.dev/verification_summary):

```bash
# Verify receipts against strict policy, emit VSA
aiir --verify-release --receipts .aiir/receipts.jsonl --policy strict --emit-vsa

# Custom subject for the VSA (e.g., an OCI image digest)
aiir --verify-release --receipts .aiir/receipts.jsonl \
  --subject 'oci://ghcr.io/myorg/app@sha256:abc123...' --emit-vsa aiir-vsa.intoto.jsonl
```

The VSA is an [in-toto Statement v1](https://in-toto.io/Statement/v1) with a `https://slsa.dev/verification_summary/v1` predicate that records:

- **Verifier identity** — who ran the check
- **Policy digest** — SHA-256 of the policy that was evaluated
- **Coverage metrics** — commit coverage percentage, AI/bot/human breakdown
- **Pass/fail result** — per-receipt and aggregate evaluation

Policy presets: `strict` (hard-fail, signing required, max 50% AI), `balanced` (soft-fail, signing recommended), `permissive` (warn-only). Customise via `.aiir/policy.json`.

</details>

<details>
<summary><strong>Policy engine</strong></summary>

Enforce organisational AI-usage policies in CI:

```bash
# Initialise a policy file from a preset
aiir --policy-init strict   # creates .aiir/policy.json
aiir --policy-init balanced
aiir --policy-init permissive

# Run policy checks against the ledger
aiir --check --policy strict

# Quick gate: fail if AI-authored percentage exceeds a threshold
aiir --check --max-ai-percent 50
```

Three presets:

| Preset | Enforcement | Signing | Max AI % | Use case |
|--------|-------------|---------|----------|----------|
| `strict` | Hard-fail | Required | 50% | Regulated industries, SOC 2, EU AI Act |
| `balanced` | Soft-fail | Recommended | 80% | Most teams — catches issues without blocking |
| `permissive` | Warn-only | Optional | 100% | Early adoption, experimentation |

Per-receipt checks: signing status, provenance repository, authorship class, schema validity.  
Aggregate checks: AI commit percentage cap.

Commit `.aiir/policy.json` to your repo so every contributor and CI run uses the same rules.

</details>

<details>
<summary><strong>Agent attestation</strong></summary>

Attach structured metadata identifying which AI tool generated a commit:

```bash
aiir --agent-tool copilot --agent-model gpt-4o --agent-context ide
aiir --agent-tool cursor --agent-model claude-sonnet-4-20250514 --agent-context ide
aiir --agent-tool claude-code --agent-context cli
```

Stored in `extensions.agent_attestation` (not part of the content hash — adding or changing agent metadata does not invalidate receipts):

```json
{
  "extensions": {
    "agent_attestation": {
      "tool_id": "copilot",
      "model_class": "gpt-4o",
      "run_context": "ide"
    }
  }
}
```

Six allowlisted keys: `tool_id`, `model_class`, `session_id`, `run_context`, `tool_version`, `confidence`. All values are sanitised (string coercion, 200-char cap).

</details>

<details>
<summary><strong>in-toto Statement wrapping</strong></summary>

Wrap receipts in a standard [in-toto Statement v1](https://in-toto.io/Statement/v1) envelope for compatibility with the supply-chain attestation ecosystem:

```bash
# Wrap a receipt in an in-toto envelope
aiir --in-toto --output .receipts/

# Combine with signing for full attestation
aiir --sign --in-toto --output .receipts/
```

The predicate type is `https://aiir.dev/commit_receipt/v1`. The subject identifies the git commit by repository URL and SHA. This makes AIIR receipts native to:

- **SLSA** verifiers
- **Sigstore** policy-controller
- **Kyverno** / **OPA/Gatekeeper** admission policies
- **Tekton Chains** supply-chain security

</details>

<details>
<summary><strong>Detection internals</strong></summary>

See [THREAT_MODEL.md](THREAT_MODEL.md) for full STRIDE analysis, DREAD scoring, and attack trees.

Homoglyph detection uses the full [Unicode TR39 confusable map](https://www.unicode.org/reports/tr39/) — 669 single-codepoint → ASCII mappings across 69 scripts (Cyrillic, Greek, Armenian, Cherokee, Coptic, Lisu, Warang Citi, Mathematical, and others). Combined with NFKC normalization, this covers all single-character homoglyphs documented by the Unicode Consortium. Multi-character confusable sequences are not covered — see S-02 in the threat model.

</details>

---

## Proof Points

Everything below is verifiable. No testimonials-behind-a-login — just public artifacts you can audit yourself.

| Proof | What it proves | Verify it |
|-------|---------------|-----------|
| **This repo receipts itself** | Dogfood — AIIR generates its own receipts on every push to `main` | `for f in .receipts/*.json; do aiir --verify "$f"; done` |
| **1,893 tests collected, 100% coverage** | Every release passes Python 3.9–3.13 × Ubuntu/macOS/Windows | [CI runs](https://github.com/invariant-systems-ai/aiir/actions/workflows/ci.yml) |
| **25 conformance test vectors** | Third-party implementors can verify their hashing against ours | [schemas/test_vectors.json](schemas/test_vectors.json) |
| **Public threat model** | Full STRIDE/DREAD analysis — we show attackers what we defend against | [THREAT_MODEL.md](THREAT_MODEL.md) |
| **SLSA provenance on every release** | PyPI wheel has a verifiable build attestation | `gh attestation verify aiir-*.whl --repo invariant-systems-ai/aiir` |
| **OpenSSF Scorecard** | Automated security health assessment (branch protection, SAST, signing) | [Scorecard](https://scorecard.dev/viewer/?uri=github.com/invariant-systems-ai/aiir) |
| **CycloneDX SBOM on every release** | Machine-readable bill of materials attached to every GitHub Release | [Latest release](https://github.com/invariant-systems-ai/aiir/releases/latest) → `aiir-sbom.cdx.json` |
| **Zero dependencies** | Nothing to compromise — `pip show aiir` shows `Requires:` empty | `pip install aiir && pip show aiir` |
| **Browser verifier** | Client-side receipt verification — no upload, no account, no server | [invariantsystems.io/verify](https://invariantsystems.io/verify) |

The [dogfood CI workflow](.github/workflows/dogfood.yml) generates receipts
on every push to `main` and commits them back to `.receipts/`. Locally, the
[pre-commit hook](.pre-commit-config.yaml) receipts every commit at
`post-commit` stage.

---

## Security

Extensive [security controls](THREAT_MODEL.md). 1,893 tests collected. Zero dependencies.

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
| [SPEC_GOVERNANCE.md](SPEC_GOVERNANCE.md) | Specification governance — change control, compatibility policy, extension registry, standards-track roadmap |
| [schemas/commit_receipt.v1.schema.json](schemas/commit_receipt.v1.schema.json) | JSON Schema (draft 2020-12) for `aiir/commit_receipt.v1` |
| [schemas/receipt.cddl](schemas/receipt.cddl) | CDDL grammar (RFC 8610) — normative for CBOR, informative for JSON |
| [schemas/conformance-manifest.json](schemas/conformance-manifest.json) | Machine-readable implementer registry, test vector index, and extension registry |
| [schemas/verification_summary.v1.schema.json](schemas/verification_summary.v1.schema.json) | JSON Schema for the Verification Summary Attestation (VSA) predicate |
| [schemas/test_vectors.json](schemas/test_vectors.json) | 25 conformance test vectors with precomputed hashes |
| [THREAT_MODEL.md](THREAT_MODEL.md) | STRIDE/DREAD threat model with comprehensive security controls |
| [docs/tamper-detection.md](docs/tamper-detection.md) | Walkthrough — what happens when a receipt is modified |
| [docs/standards-readiness.md](docs/standards-readiness.md) | Weekly standards-readiness scorecard (5-category, updated every Monday) |
| [docs/release-health.md](docs/release-health.md) | Release health policy — severity definitions, P0 RCA process, smoke test coverage |
| [docs/implementers.md](docs/implementers.md) | Third-party implementations and pilots registry |

---

## About

Built by [Invariant Systems, Inc.](https://invariantsystems.io)

**License**: Apache-2.0 — See [LICENSE](LICENSE).
If you redistribute AIIR or derivative works, please include a copy of the
[LICENSE](LICENSE), preserve the [NOTICE](NOTICE) file, and retain attribution
to Invariant Systems, as required by the Apache-2.0 license.

**Citing AIIR**: Use the **Cite this repository** button on GitHub or see
[CITATION.cff](CITATION.cff).

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
