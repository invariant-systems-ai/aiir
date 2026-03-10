# GitLab Compliance Framework + AIIR

> Enforce AI receipt generation across all projects in your GitLab group
> using [Compliance Frameworks](https://docs.gitlab.com/ee/user/group/compliance_frameworks.html)
> (GitLab Premium/Ultimate).

## Overview

GitLab Compliance Frameworks let group owners define enforced CI/CD
pipeline configurations that automatically run on every project tagged
with a specific framework label. This means you can require AIIR
receipts for **every MR across your entire organization** — no per-project
setup needed.

## Setup

### 1. Create the compliance framework

<!-- markdownlint-disable-next-line MD036 -->
**Group → Settings → Compliance → Frameworks → New framework**

- **Name**: `AI Policy — AIIR Receipts`
- **Description**: Enforces AI integrity receipts for all merge requests.
  Detects Copilot, ChatGPT, Claude, Cursor, GitLab Duo, and 30+ AI
  tools. Produces tamper-evident cryptographic receipts for audit trails.
- **Color**: `#6366f1` (or your brand color)
- **Compliance pipeline configuration**: Point to a project containing
  the enforced `.gitlab-ci.yml` (see step 2).

### 2. Create the enforced pipeline config

In a dedicated compliance project (e.g., `your-group/compliance-pipelines`),
create `.aiir-compliance.yml`:

```yaml
# .aiir-compliance.yml — enforced by Compliance Framework
# This pipeline runs automatically on every MR in projects tagged with
# the "AI Policy — AIIR Receipts" framework.

stages:
  - compliance

aiir-compliance-receipt:
  stage: compliance
  image: python:3.11-slim
  id_tokens:
    SIGSTORE_ID_TOKEN:
      aud: sigstore
  before_script:
    - apt-get update -qq && apt-get install -y -qq git >/dev/null 2>&1
    - pip install --quiet "aiir>=1.0.15" sigstore
  script:
    - git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" --depth=100
    - |
      aiir --range "origin/${CI_MERGE_REQUEST_TARGET_BRANCH_NAME}..${CI_COMMIT_SHA}" \
        --output .aiir-receipts/ \
        --pretty \
        --gitlab-ci \
        --sign \
        --gl-sast-report gl-sast-report.json
  artifacts:
    paths:
      - .aiir-receipts/
    reports:
      dotenv: aiir.env
      sast: gl-sast-report.json
    expire_in: 1 year
    when: always
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
  allow_failure: false
```

### 3. Configure the framework to use this pipeline

In the compliance framework settings, set:

- **Compliance pipeline configuration**: `your-group/compliance-pipelines:.aiir-compliance.yml@main`

### 4. Tag projects with the framework

For each project that should enforce AI receipts:
**Project → Settings → General → Compliance frameworks → Select "AI Policy — AIIR Receipts"**

Or use the API to bulk-tag:

```bash
# Tag project 123 with framework ID 456
curl --request PUT \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  --data '{"compliance_framework_id": 456}' \
  "https://gitlab.example.com/api/v4/projects/123"
```

## What happens

Once configured, every MR in tagged projects will:

1. ✅ **Generate receipts** for all commits in the MR
2. ✅ **Post a summary comment** on the MR with authorship breakdown
3. ✅ **Sign receipts** with Sigstore keyless signing (GitLab OIDC)
4. ✅ **Report to Security Dashboard** — AI findings appear as informational items
5. ✅ **Export dotenv variables** — `AIIR_RECEIPT_COUNT`, `AIIR_AI_COMMIT_COUNT`, `AIIR_AI_PERCENT`

## Adding policy enforcement

Combine with `--check --policy strict` to **fail the pipeline** when
AI authorship exceeds your organization's threshold:

```yaml
  script:
    # ... receipt generation (above) ...
    # Enforce policy — fail if >60% AI or unsigned
    - aiir --check --policy strict --max-ai-percent 60
```

## With approval rules

Automatically require additional reviewers when AI % is high:

```yaml
  after_script:
    - |
      AI_PCT=$(cat aiir.env | grep AIIR_AI_PERCENT | cut -d= -f2)
      if [ $(echo "$AI_PCT > 50" | bc -l) -eq 1 ]; then
        echo "AI% is ${AI_PCT}% — posting approval rule via AIIR"
        python3 -c "
        from aiir._gitlab import enforce_approval_rules
        enforce_approval_rules(${AI_PCT}, threshold=50, required_approvals=2)
        "
      fi
```

---

**Links**: [AIIR on PyPI](https://pypi.org/project/aiir/) ·
[AIIR on GitHub](https://github.com/invariant-systems-ai/aiir) ·
[GitLab Compliance Frameworks](https://docs.gitlab.com/ee/user/group/compliance_frameworks.html)
