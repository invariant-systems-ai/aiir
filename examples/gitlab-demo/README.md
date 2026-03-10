# GitLab-First Partner Demo

> **Component → Receipt → Security Dashboard → Duo Chat summary** in one
> pipeline.

This example shows how AIIR integrates into GitLab's native compliance
surface in under 10 lines of CI config.

## What you get

| Step | GitLab feature | AIIR does |
| --- | --- | --- |
| 1 | **CI/CD Catalog component** | `include: component:` — one-line setup |
| 2 | **Receipt artifacts** | Tamper-evident JSON for every commit |
| 3 | **Security Dashboard** | `gl-sast-report.json` → AI findings in the security tab |
| 4 | **Compliance artifact** | `reports: dotenv:` → MR variables (`AIIR_AI_PERCENT`, etc.) |
| 5 | **MR comment** | `--gitlab-ci` auto-posts an AI authorship summary |
| 6 | **Sigstore signing** | `--sign` with GitLab OIDC (`id_tokens`) — keyless |
| 7 | **Duo Chat** | Ask Duo: _"Summarize the AI authorship in this MR"_ — it reads the receipt artifacts and MR comment |

## Quick start

### Option A: CI/CD Catalog component (recommended)

```yaml
# .gitlab-ci.yml
include:
  - component: gitlab.com/invariant-systems/aiir/receipt@1
    inputs:
      sign: true
      gl-sast-report: true
```

That's it. Every push and MR now:
- generates receipts in `.aiir-receipts/`
- signs them with Sigstore (GitLab OIDC)
- reports AI findings to the Security Dashboard
- posts a summary comment on MRs

### Option B: Remote include (no Catalog)

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/invariant-systems-ai/aiir/v1.2.2/templates/gitlab-ci.yml'
```

### Option C: Full control (copy-paste)

See [`.gitlab-ci.yml`](.gitlab-ci.yml) in this directory for a
self-contained pipeline with all features enabled and annotated.

## The pipeline flow

```
MR opened
  │
  ├─► aiir-receipt-mr
  │     ├─ pip install aiir sigstore
  │     ├─ aiir --range origin/main..HEAD \
  │     │       --output .aiir-receipts/ \
  │     │       --pretty --gitlab-ci --sign \
  │     │       --gl-sast-report gl-sast-report.json
  │     │
  │     ├─ artifacts:
  │     │     paths: .aiir-receipts/
  │     │     reports:
  │     │       dotenv: aiir.env          ← MR variables
  │     │       sast: gl-sast-report.json ← Security Dashboard
  │     │
  │     └─ MR comment: "3 commits receipted, 2 AI-authored (67%)"
  │
  ├─► Security Dashboard
  │     └─ "AI-authored commit" findings (informational severity)
  │
  ├─► Compliance tab
  │     └─ AIIR_RECEIPT_COUNT=3, AIIR_AI_PERCENT=67, ...
  │
  └─► Duo Chat
        └─ "Summarize AI authorship" → reads artifacts + MR note
```

## Duo Chat integration

Once AIIR receipts are in your MR, GitLab Duo can summarize them.
In the MR, open Duo Chat and ask:

> _Summarize the AI authorship findings in this merge request._

Duo reads the MR comment posted by `--gitlab-ci` and the receipt
artifacts to produce a natural-language summary.

For deeper integration, add AIIR as an MCP tool for Duo:

```json
// .gitlab/duo/mcp.json
{
  "mcpServers": {
    "aiir": {
      "command": "aiir-mcp-server",
      "args": ["--stdio"]
    }
  }
}
```

Now Duo can call `aiir_receipt`, `aiir_verify`, and `aiir_verify_release`
directly during code review.

## Compliance Framework (org-wide enforcement)

For Premium/Ultimate customers, AIIR can be enforced on **every project**
via a [Compliance Framework](https://docs.gitlab.com/ee/user/group/compliance_frameworks.html).
See [`gitlab-compliance-framework.md`](../../docs/gitlab-compliance-framework.md).

## Verifying receipts

```bash
# Verify a single receipt
aiir --verify .aiir-receipts/abc123.json

# Verify an entire release
aiir --verify-release --receipts .aiir-receipts/ --emit-vsa vsa.json
```

## Links

- [AIIR on GitLab CI/CD Catalog](https://gitlab.com/explore/catalog/invariant-systems/aiir)
- [AIIR on PyPI](https://pypi.org/project/aiir/)
- [Component source](../../templates/receipt/template.yml)
- [Duo recipe](../../docs/gitlab-duo-recipe.md)
- [Compliance Framework guide](../../docs/gitlab-compliance-framework.md)
