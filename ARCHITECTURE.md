# AIIR Architecture

> Target architecture and phased evolution roadmap for AIIR.
> This document is informed by external evaluation findings and the project's
> goal of becoming a first-class AI commit-provenance layer.

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

## Evolution Roadmap

The roadmap is organized in three phases. Each phase builds on the previous
one and maintains full backward compatibility with existing receipts.

### Phase 1 — Assurance Baseline (v1.0.13 – v1.1.x)

**Goal**: Strengthen evidence quality and human experience without breaking
the receipt format.

| Capability | Status | Notes |
| --- | --- | --- |
| Explainable verification (`--explain`) | ✅ Shipped | Plain-English failure diagnostics with remediation |
| Org policy presets (`--policy`) | ✅ Shipped | strict / balanced / permissive; `.aiir/policy.json` |
| Policy initialization (`--policy-init`) | ✅ Shipped | Scaffolds policy file with chosen preset |
| Agent attestation envelope | ✅ Shipped | `extensions.agent_attestation` — tool, model, context |
| in-toto Statement v1 wrapper (`--in-toto`) | ✅ Shipped | Native supply-chain attestation envelope |
| Signed-by-default posture | 🔲 Planned | `--sign` default when OIDC available; `--no-sign` opt-out |
| CONTRIBUTING.md onboarding fixes | ✅ Shipped | Correct test commands, hypothesis note |
| Schema validation in `--check` | ✅ Shipped (v1.0.12) | `schema_errors` in verification result |

### Phase 2 — Provenance Depth (v1.2.x)

**Goal**: Richer provenance primitives that support audit trails and
cross-system correlation.

| Capability | Target | Notes |
| --- | --- | --- |
| Chained receipts | v1.2.0 | `parent_receipt_id` linking sequential commits |
| Diff-level attestation | v1.2.0 | Per-hunk AI vs human classification |
| SLSA Build Level 2 provenance | v1.2.x | Build environment attestation in extensions |
| Receipt chain verification | v1.2.x | `--verify-chain` validates parent linkage |
| CI template: signed-by-default | v1.2.0 | All platform templates enable `--sign` |
| Policy: per-path rules | v1.2.x | Different policies for `src/` vs `docs/` vs `tests/` |

**Schema evolution strategy**: New fields go into `extensions.*` (no core
hash change). When a field proves stable across two minor versions, it may
be promoted to a CORE_KEY in the next major version with a migration guide.

### Phase 3 — AI-First Experience (v2.0.x)

**Goal**: Purpose-built UX for AI-agent workflows and organizational
governance dashboards.

| Capability | Target | Notes |
| --- | --- | --- |
| PR-native risk summaries | v2.0.0 | GitHub Check Run with per-commit risk scoring |
| Agent session correlation | v2.0.0 | Link receipts across a multi-commit agent session |
| Org dashboard API | v2.0.x | Aggregate policy compliance across repositories |
| Receipt format v2 | v2.0.0 | Promote stable extensions to core; deprecate v1 fields |
| CBOR compact encoding | v2.0.x | Binary receipt format for high-throughput pipelines |
| Webhook integration | v2.0.x | Push receipt events to external audit systems |

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
  structure are stable within v1.x. Future ledger features (e.g., chain
  verification) add new index fields without removing existing ones.

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
