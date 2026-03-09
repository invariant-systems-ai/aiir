# GitLab Duo + AIIR — AI Receipts for Duo-Generated MRs

> Receipt and audit AI-assisted merge requests created by GitLab Duo.
> This recipe adds AIIR receipts alongside Duo's code suggestions,
> giving your team a tamper-evident record of what was human and what
> was machine in every MR.

## Quick Setup

Add this to your `.gitlab-ci.yml`:

```yaml
stages:
  - test
  - receipt

# Your existing test stage
test:
  stage: test
  script:
    - echo "run your tests here"

# AIIR receipt stage — runs after tests pass
aiir-receipt:
  stage: receipt
  image: python:3.11-slim
  script:
    - pip install --quiet aiir
    # Receipt all commits in this MR
    - |
      if [ -n "$CI_MERGE_REQUEST_DIFF_BASE_SHA" ]; then
        aiir --range "${CI_MERGE_REQUEST_DIFF_BASE_SHA}..HEAD" \
             --pretty \
             --output .aiir-receipts/
      else
        aiir --pretty --output .aiir-receipts/
      fi
    # Show stats
    - aiir --stats || true
  artifacts:
    paths:
      - .aiir-receipts/
    expire_in: 90 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

## With Duo Code Suggestions detection

GitLab Duo adds `Suggested by: GitLab Duo` or similar trailers to
commits. AIIR's heuristic detector catches these automatically and
classifies the commit as `ai-assisted`.

For explicit tracking, add agent attestation:

```yaml
aiir-receipt:
  stage: receipt
  image: python:3.11-slim
  script:
    - pip install --quiet aiir
    - |
      if [ -n "$CI_MERGE_REQUEST_DIFF_BASE_SHA" ]; then
        aiir --range "${CI_MERGE_REQUEST_DIFF_BASE_SHA}..HEAD" \
             --pretty \
             --output .aiir-receipts/ \
             --agent-tool gitlab-duo \
             --agent-context ci
      else
        aiir --pretty --output .aiir-receipts/
      fi
  artifacts:
    paths:
      - .aiir-receipts/
    expire_in: 90 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

## In-toto envelope output (supply-chain integration)

Wrap receipts in standard in-toto Statement v1 envelopes for
compatibility with SLSA verifiers and policy controllers:

```yaml
aiir-receipt:
  stage: receipt
  image: python:3.11-slim
  script:
    - pip install --quiet aiir
    - |
      if [ -n "$CI_MERGE_REQUEST_DIFF_BASE_SHA" ]; then
        aiir --range "${CI_MERGE_REQUEST_DIFF_BASE_SHA}..HEAD" \
             --in-toto --jsonl \
             > .aiir-receipts/attestations.jsonl
      else
        aiir --in-toto --json > .aiir-receipts/attestation.json
      fi
  artifacts:
    paths:
      - .aiir-receipts/
    expire_in: 90 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

## With policy enforcement

Fail the pipeline if AI-authored commits exceed your org threshold:

```yaml
aiir-policy:
  stage: receipt
  image: python:3.11-slim
  script:
    - pip install --quiet aiir
    # Generate receipts
    - |
      if [ -n "$CI_MERGE_REQUEST_DIFF_BASE_SHA" ]; then
        aiir --range "${CI_MERGE_REQUEST_DIFF_BASE_SHA}..HEAD" --pretty
      else
        aiir --pretty
      fi
    # Enforce policy — strict = max 50% AI, signing required
    - aiir --check --policy strict
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  allow_failure: false
```

## Using the CI/CD Catalog component

If you prefer the packaged component:

```yaml
include:
  - component: gitlab.com/invariant-systems/aiir/receipt@1
    inputs:
      stage: receipt
      extra-args: "--agent-tool gitlab-duo --agent-context ci"
```

## Combining with Duo Chat MR summaries

GitLab Duo Chat can summarize MRs. You can reference AIIR receipts
in the summary by adding the receipt stats as an MR comment:

```yaml
aiir-comment:
  stage: receipt
  image: python:3.11-slim
  script:
    - pip install --quiet aiir
    - |
      if [ -n "$CI_MERGE_REQUEST_DIFF_BASE_SHA" ]; then
        aiir --range "${CI_MERGE_REQUEST_DIFF_BASE_SHA}..HEAD" --pretty
      fi
    - |
      STATS=$(aiir --stats 2>&1 || echo "No receipts yet")
      # Post to MR (requires GITLAB_TOKEN with api scope)
      curl --silent --request POST \
        --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
        --data-urlencode "body=### 🔐 AIIR Receipt Summary\n\n\`\`\`\n${STATS}\n\`\`\`" \
        "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/merge_requests/${CI_MERGE_REQUEST_IID}/notes"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

---

**Links**: [AIIR on PyPI](https://pypi.org/project/aiir/) ·
[AIIR on GitHub](https://github.com/invariant-systems-ai/aiir) ·
[AIIR GitLab CI/CD Component](https://gitlab.com/explore/catalog/invariant-systems/aiir) ·
[GitLab Duo](https://about.gitlab.com/gitlab-duo/)
