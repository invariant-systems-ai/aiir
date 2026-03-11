# Implementers and Pilots

> **Public registry of known AIIR implementations and organizations using AIIR in production or pilot.**
>
> This registry is the adoption proof for the [standards-readiness scorecard](standards-readiness.md).
> It feeds the conformance manifest at `schemas/conformance-manifest.json`.
>
> **To add your implementation or organization**: open a PR editing this file. No approval gatekeeping — if you pass the conformance vectors, you're listed. If you're a pilot user, even anonymized entries help.

**Last updated**: 2026-03-11

---

## Implementations

Implementations are listed here when they:

1. Pass all **Level 1** test vectors at minimum (see [conformance guide](https://invariantsystems.io/conformance))
2. Submit a PR with a link to their conformance test results

| Name | Language | Level | Status | Maintainer | Verified | Notes |
|---|---|---|---|---|---|---|
| [aiir](https://github.com/invariant-systems-ai/aiir) | Python 3.9–3.13 | 3 (Full) | Reference | Invariant Systems | 2026-03-11 | Reference implementation. Zero dependencies. Includes CLI, GitHub Action, GitLab CI component, MCP tool. |

### Conformance levels

| Level | Meaning |
|---|---|
| 1 — Verify | Can verify existing receipts (content_hash + receipt_id) |
| 2 — Generate | Level 1 + can produce valid receipts with canonical JSON encoding |
| 3 — Full | Level 2 + CBOR round-trip (JSON → CBOR → JSON produces identical hashes) |

**Machine-readable**: see [`schemas/conformance-manifest.json`](../schemas/conformance-manifest.json).

---

## Pilots and Production Users

Organizations using AIIR to generate or verify receipts — even in evaluation — can be listed here.
Anonymized entries (e.g., "Series A startup, fintech") are welcome and count toward adoption proof.

| Organization | Use case | Since | Anonymized? | Notes |
|---|---|---|---|---|
| Invariant Systems | AIIR receipts every commit in the aiir repo itself (dogfooding) | 2025-11 | No | Uses all four interfaces: CLI, GitHub Action, GitLab CI, MCP |

### How to add your organization

Open a PR with a row in the table above. You may:

- Use your real org name and link to a public repo showing aiir in use
- Use an anonymized description if you prefer not to be named publicly
- Include a public case study link (even a blog post) if you have one

Pilots count even if aiir is not yet in production. The goal is to demonstrate real-world demand.

---

## Third-Party Extensions

Extensions extend the AIIR receipt format without breaking interoperability.
See the [extension mechanism in SPEC_GOVERNANCE.md](../SPEC_GOVERNANCE.md#5-extension-mechanism).

| Extension key | Description | Status | Maintainer | Spec |
|---|---|---|---|---|
| *(none registered yet)* | | | | |

---

## Want to Build an Implementation?

Start with the [conformance guide](https://invariantsystems.io/conformance):

1. Read [`SPEC.md`](../SPEC.md) — the normative specification
2. Download [`schemas/test_vectors.json`](../schemas/test_vectors.json) — 25 JSON test vectors
3. Download [`schemas/cbor_test_vectors.json`](../schemas/cbor_test_vectors.json) — 24 CBOR vectors (for Level 3)
4. Pass all vectors → open a PR to add your implementation to this registry

Questions? Open an issue or email <noah@invariantsystems.io>.
