# AIIR Architecture

> Architecture overview for AIIR — the reference implementation of AI Integrity Receipts.

## Current Architecture (v1.0.x)

```
┌─────────────────────────────────────────────────────────────┐
│  CLI / GitHub Action / MCP Server                           │
│  (aiir/cli.py, action.yml, mcp_server.py)                   │
├─────────────────────────────────────────────────────────────┤
│  Receipt Builder         Verification Engine                │
│  (_receipt.py)           (_verify.py + _schema.py)          │
├─────────────────────────────────────────────────────────────┤
│  Detection    Ledger     Signing      Policy     Explain    │
│  (_detect.py) (_ledger)  (_sign.py)   (_policy)  (_explain) │
├─────────────────────────────────────────────────────────────┤
│  Core: canonical JSON, content hashing, receipt ID          │
│  (_core.py)                                                 │
└─────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Zero runtime dependencies** — stdlib-only for trust minimization
2. **Canonical determinism** — identical inputs always produce identical receipts
3. **Separation of core and extensions** — six CORE_KEYS form the content hash;
   everything else lives in `extensions` (excluded from hash, backward-compatible)
4. **Layered verification** — hash integrity first, then structural schema
   validation, then optional Sigstore signature verification
5. **Progressive disclosure** — `--json` for machines, pretty-print for humans,
   `--detail` for deep inspection, `--explain` for non-crypto users

### Module Responsibilities

| Module | Responsibility |
| --- | --- |
| `_core.py` | Canonical JSON encoding, SHA-256 hashing, receipt ID construction |
| `_receipt.py` | Receipt builder: commit → structured receipt with detection signals |
| `_detect.py` | AI-authorship detection: bot patterns, trailer parsing, signal aggregation |
| `_verify.py` | Hash verification, schema validation, Sigstore bundle verification |
| `_schema.py` | Zero-dependency structural validator (JSON Schema semantics, no library) |
| `_explain.py` | Human-readable verification explanations with categorized failure diagnostics |
| `_policy.py` | Org policy engine: presets (strict/balanced/permissive), staged enforcement |
| `_ledger.py` | Append-only JSONL ledger + index management |
| `_sign.py` | Sigstore integration (optional dependency) |
| `_stats.py` | Ledger statistics and health checks |
| `_github.py` | GitHub API helpers for CI context detection |
| `cli.py` | Argument parsing, sub-command dispatch, output formatting |
| `mcp_server.py` | Model Context Protocol server for AI-agent integration |

---

## Shipped Capabilities

All capabilities listed below are available in the current release and
maintain full backward compatibility with existing receipts.

| Capability | Since | Notes |
| --- | --- | --- |
| Explainable verification (`--explain`) | v1.0.13 | Plain-English failure diagnostics with remediation |
| Org policy presets (`--policy`) | v1.0.13 | strict / balanced / permissive; `.aiir/policy.json` |
| Policy initialization (`--policy-init`) | v1.0.13 | Scaffolds policy file with chosen preset |
| Agent attestation envelope | v1.0.13 | `extensions.agent_attestation` — tool, model, context |
| in-toto Statement v1 wrapper (`--in-toto`) | v1.0.14 | Native supply-chain attestation envelope |
| Schema validation in `--check` | v1.0.12 | `schema_errors` in verification result |
| Public Python API | v1.0.15 | `from aiir import generate_receipt, verify_receipt` |
| 5 MCP tools | v1.0.15 | receipt, verify, stats, explain, policy_check |
| Full Unicode TR39 confusable detection | v1.0.15 | 669 entries across 69 scripts |
| Adversarial red-team hardening | v1.0.15 | 80 hostile tests, 142 security controls |

---

## Future Direction

AIIR's roadmap focuses on three themes: **deeper provenance primitives**,
**richer verification experiences**, and **tighter ecosystem integration**.
New capabilities follow the schema evolution policy below — extensions
first, promotion after proven stability.

See [SPEC.md](SPEC.md) for the canonical specification and
[CHANGELOG.md](CHANGELOG.md) for the latest shipped capabilities.

---

## Independent Implementations

AIIR's specification is designed for third-party implementation. Multiple
independent verifiers exist to prove the spec is sufficient:

| Language | Package | Scope | Conformant |
| --- | --- | --- | --- |
| Python | [`aiir`](https://pypi.org/project/aiir/) | Full (generate + verify) | ✅ Reference |
| TypeScript | [`@aiir/verifier`](contrib/ts-verifier/) | Verification only | ✅ 15/15 vectors |

The TypeScript implementation was written from the specification alone (not
ported from Python) and passes all published test vectors. See
[`contrib/ts-verifier/`](contrib/ts-verifier/) for source and instructions.

---

## Schema Evolution Policy

1. **CORE_KEYS are immutable within a major version.**
   The six core fields (`type`, `schema`, `version`, `commit`, `ai_attestation`,
   `provenance`) define the content hash. Adding or removing a core key is a
   major version change.

2. **Extensions are the expansion mechanism.**
   Any new data goes into `extensions.<namespace>`. Extensions are excluded
   from the content hash and are always optional for consumers.

3. **Promotion path**: `extensions.*` → observe for 2 minor versions →
   propose RFC → promote to CORE_KEY in next major version.

4. **Deprecation**: Deprecated fields remain in the schema for one full
   major version with a `deprecated: true` annotation before removal.

---

## Backward Compatibility Guarantees

- **Receipt JSON**: Any receipt produced by v1.0.0+ will verify correctly
  with any future v1.x verifier. New fields in `extensions` are ignored
  by older verifiers.

- **CLI flags**: No existing flag will change semantics. New flags are
  additive. Default behavior changes (e.g., signed-by-default) will be
  gated behind a minor version bump with opt-out.

- **Ledger format**: The JSONL append-only ledger and `index.json`
  structure are stable within v1.x. Future ledger features add new
  index fields without removing existing ones.

- **GitHub Action**: The `v1` floating tag always points to the latest
  v1.x.x release. Breaking changes require `v2`.

---

## Integration Recipes

AIIR ships integration guides for popular AI coding tools and CI/CD platforms:

| Recipe | Path |
| --- | --- |
| Claude Code hooks | [`docs/claude-code-hooks.md`](docs/claude-code-hooks.md) |
| GitLab Duo + CI/CD | [`docs/gitlab-duo-recipe.md`](docs/gitlab-duo-recipe.md) |
| MCP server configs | [README.md § MCP Tool](README.md#-mcp-tool--let-your-ai-do-it) (Claude, Copilot, Cursor, Continue, Cline, Windsurf) |
| GitHub Action | [README.md § GitHub Action](README.md#️-github-action--automate-it-in-ci) |
| pre-commit hook | [README.md § pre-commit](README.md#-pre-commit-hook--receipt-every-commit-locally) |

### in-toto as the Integration Bridge

The `--in-toto` flag wraps every AIIR receipt in a standard
[in-toto Statement v1](https://in-toto.io/Statement/v1) envelope:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "repo@sha", "digest": {"gitCommit": "abc..."}}],
  "predicateType": "https://aiir.dev/commit_receipt/v1",
  "predicate": { "...the full AIIR receipt..." }
}
```

This makes AIIR receipts a **native citizen** of the supply-chain
attestation ecosystem. Every tool from Sigstore policy-controller to
Tekton Chains to OPA/Gatekeeper understands this shape. The predicate
type URI (`https://aiir.dev/commit_receipt/v1`) allows routing policies
to match on AIIR-specific content without parsing the inner receipt.

---

## Security Model

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full STRIDE/DREAD analysis.

Key architectural security properties:

- **Deterministic hashing**: Canonical JSON eliminates serialization ambiguity
- **Content addressing**: Receipt ID = f(content_hash, repo, commit) — unforgeable
- **Sigstore transparency**: Signed receipts are logged in the Rekor transparency log
- **Zero-dependency core**: No supply chain attack surface in the core path
- **Schema validation**: Structural checks catch malformed receipts before hash verification

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and
the adversarial review protocol.

Architecture changes require an RFC (open an issue with the `rfc` label)
and must maintain backward compatibility within the current major version.
