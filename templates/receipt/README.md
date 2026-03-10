# AIIR Receipt — GitLab CI/CD Component

Generate tamper-evident cryptographic receipts for every commit with declared AI involvement in your GitLab CI/CD pipelines.

## Quick start

```yaml
# .gitlab-ci.yml
include:
  - component: $CI_SERVER_FQDN/invariant-systems/aiir/receipt@1
    inputs:
      stage: test
```

That's it. Every push and merge request now generates receipts, uploaded as CI artifacts.

## What it does

1. Installs `aiir` (zero dependencies, Python standard library only)
2. Scans commits for AI-involvement signals (Copilot, ChatGPT, Claude, Cursor, Amazon Q, Devin, Gemini, and 20+ more)
3. Generates a content-addressed cryptographic receipt for each commit
4. Uploads receipt JSON files as pipeline artifacts

## Inputs

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `stage` | string | `test` | Pipeline stage for the receipt job |
| `version` | string | `1.2.2` | AIIR version to install |
| `ai-only` | boolean | `false` | Only receipt AI-authored commits |
| `artifact-expiry` | string | `90 days` | How long to keep receipt artifacts |
| `output-dir` | string | `.aiir-receipts` | Directory for receipt JSON files |
| `extra-args` | string | `""` | Additional aiir CLI flags |
| `python-image` | string | `python:3.11-slim` | Docker image (override for air-gapped registries) |
| `job-prefix` | string | `aiir` | Prefix for job names (for multiple includes) |
| `sign` | boolean | `true` | Sigstore keyless signing (GitLab OIDC) |
| `gl-sast-report` | boolean | `false` | Generate SAST report for Security Dashboard |
| `approval-threshold` | number | `0` | AI% threshold for extra MR approvals (0 = off) |

## Examples

### Default — receipt all commits

```yaml
include:
  - component: $CI_SERVER_FQDN/invariant-systems/aiir/receipt@1
```

### AI-only commits with custom expiry

```yaml
include:
  - component: $CI_SERVER_FQDN/invariant-systems/aiir/receipt@1
    inputs:
      ai-only: true
      artifact-expiry: "1 year"
```

### Self-hosted GitLab (mirrored repo)

```yaml
include:
  - component: $CI_SERVER_FQDN/your-group/aiir/receipt@1
    inputs:
      python-image: your-registry.example.com/python:3.11-slim
```

### Redact file paths (privacy-sensitive repos)

```yaml
include:
  - component: $CI_SERVER_FQDN/invariant-systems/aiir/receipt@1
    inputs:
      extra-args: "--redact-files"
```

## About

- **Zero dependencies** — Python standard library only
- **Apache 2.0** — free forever, no usage limits
- **EU AI Act** — supports transparency and provenance evidence
- **1,600+ tests** — unit + property-based fuzz + adversarial red-team tests
Built by [Invariant Systems, Inc.](https://invariantsystems.io)

- [Full documentation](https://github.com/invariant-systems-ai/aiir)
- [PyPI](https://pypi.org/project/aiir/)
- [Threat model](https://github.com/invariant-systems-ai/aiir/blob/main/THREAT_MODEL.md)
