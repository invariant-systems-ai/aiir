# AIIR Examples

Concrete examples of AIIR in action — receipts, verification, CI checks, and policy evaluation.

## Example Receipt

A real receipt generated from a commit in this repository:

```json
{
  "type": "aiir.commit_receipt",
  "schema": "aiir/commit_receipt.v1",
  "version": "1.2.3",
  "commit": {
    "sha": "a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
    "author": {
      "name": "Jane Dev",
      "email": "jane@example.com",
      "date": "2026-03-10T09:48:59-04:00"
    },
    "committer": {
      "name": "Jane Dev",
      "email": "jane@example.com",
      "date": "2026-03-10T09:48:59-04:00"
    },
    "subject": "feat: add new auth middleware",
    "message_hash": "sha256:1a2b3c4d...",
    "diff_hash": "sha256:5e6f7a8b...",
    "files_changed": 4,
    "files": [
      "src/auth/middleware.py",
      "src/auth/tokens.py",
      "tests/test_auth.py",
      "docs/auth.md"
    ]
  },
  "ai_attestation": {
    "is_ai_authored": true,
    "signals_detected": ["co-authored-by: copilot"],
    "signal_count": 1,
    "is_bot_authored": false,
    "bot_signals_detected": [],
    "bot_signal_count": 0,
    "authorship_class": "ai_assisted",
    "detection_method": "heuristic_v2"
  },
  "provenance": {
    "repository": "https://github.com/your-org/your-repo.git",
    "tool": "https://github.com/invariant-systems-ai/aiir@1.2.3",
    "generator": "aiir.cli"
  },
  "receipt_id": "g1-7f3a4b5c6d7e8f9a0b1c2d3e",
  "content_hash": "sha256:7f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a",
  "timestamp": "2026-03-10T13:48:59Z",
  "extensions": {}
}
```

Key fields:

- **`ai_attestation.is_ai_authored`** = `true` — Copilot was detected via `Co-authored-by` trailer
- **`ai_attestation.authorship_class`** = `"ai_assisted"` — structured category for filtering
- **`content_hash`** = SHA-256 of the canonical JSON core — change any field and this breaks
- **`receipt_id`** = first 32 hex chars of the content hash, prefixed with `g1-`

## Example Verification

```bash
$ aiir --verify receipt.json --explain

✅ All good! 1 receipt verified -- integrity intact.
   g1-7f3a4b5c6d7e8f9a0b1c2d3e commit=a3f8b2c1d4e5 ✔

VERIFICATION PASSED

What was checked:
  1. Recomputed the SHA-256 hash of the receipt's core fields
     (type, schema, version, commit, ai_attestation, provenance).
  2. Compared the recomputed content_hash against the stored value — they match.
  3. Derived receipt_id from the same hash — it matches.

What this means:
  The receipt has not been modified since it was created. The commit metadata,
  AI attestation, and provenance are exactly as recorded.

What this does NOT prove:
  Integrity only proves the receipt hasn't been tampered with. It does not
  prove WHO generated it. For authenticity, verify a Sigstore signature.
```

## Example CI Check Output

When AIIR runs in GitHub Actions with `checks: write` permission, it creates
a **Check Run** visible on every PR:

```text
┌──────────────────────────────────────────────────────────┐
│  ✅ AIIR Verification                                    │
│                                                          │
│  Commit: a3f8b2c1d4e5  (feat: add new auth middleware)   │
│  AI involvement detected: yes (copilot)                  │
│  Files touched: 4                                        │
│  Receipt verified: ✅                                     │
│  Policy: PASS                                            │
│  Signer: github-actions (sigstore)                       │
│                                                          │
│  Coverage: 3/3 commits receipted (100%)                  │
└──────────────────────────────────────────────────────────┘
```

This check is enforceable via branch protection rules — require `aiir/verify`
to pass before merging.

## Example Policy Evaluation

```bash
# Initialize a policy for your org
$ aiir --policy-init moderate
📋 Created .aiir/policy.json (moderate preset)

# Verify a release against policy and emit a VSA
$ aiir --verify-release --policy .aiir/policy.json --output vsa.json

Release Verification Summary
  Commits evaluated: 47
  Receipts found:    47 (100% coverage)
  AI-authored:       12 (25.5%)
  Policy result:     PASS

  VSA written to vsa.json (in-toto Statement v1, signed)
```

The VSA (Verification Summary Attestation) is an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
that auditors and downstream systems can consume directly.

## Example Badge

Add to your README after integrating AIIR:

```markdown
[![AIIR Receipted](https://img.shields.io/badge/AIIR-Receipted%20✓-blue)](https://github.com/invariant-systems-ai/aiir)
```

Result: [![AIIR Receipted](https://img.shields.io/badge/AIIR-Receipted%20✓-blue)](https://github.com/invariant-systems-ai/aiir)

## More Examples

- [GitHub Actions integration](github-actions/) — full workflow with signing
- [GitLab CI integration](gitlab-demo/) — MR comments, compliance pipeline
- [MCP server setup](../README.md#-mcp-tool--let-your-ai-do-it) — Claude, VS Code, Cursor, Continue, Windsurf
