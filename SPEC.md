# AIIR Commit Receipt Specification

**Specification version**: 1.0.1
**Schema identifier**: `aiir/commit_receipt.v1`
**Status**: Stable
**Date**: 2026-03-09
**Author**: Invariant Systems, Inc.
**License**: Apache-2.0

---

## 1. Introduction

This document is the **normative specification** for the AIIR commit receipt
format (`aiir/commit_receipt.v1`). It defines the receipt structure, field
semantics, canonical JSON encoding, content-addressing algorithm, verification
procedure, and extension mechanism.

An independent implementation that follows this specification MUST produce
identical `content_hash` and `receipt_id` values for the same input data, and
MUST accept or reject receipts identically to the reference implementation.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as
described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

### 1.2 Reference Implementation

The reference implementation is the `aiir` Python package:
- Repository: <https://github.com/invariant-systems-ai/aiir>
- PyPI: <https://pypi.org/project/aiir/>
- License: Apache-2.0

### 1.3 Machine-Readable Schema

A JSON Schema (draft 2020-12) is provided at:
- [`schemas/commit_receipt.v1.schema.json`](schemas/commit_receipt.v1.schema.json)

---

## 2. Receipt Structure

A receipt is a JSON object with the following top-level fields:

| Field | Type | In CORE | Description |
|-------|------|---------|-------------|
| `type` | string (const) | ✅ | `"aiir.commit_receipt"` |
| `schema` | string (const) | ✅ | `"aiir/commit_receipt.v1"` |
| `version` | string | ✅ | SemVer version of the generating tool |
| `commit` | object | ✅ | Git commit metadata (§3) |
| `ai_attestation` | object | ✅ | AI authorship detection results (§4) |
| `provenance` | object | ✅ | Tool and repository metadata (§5) |
| `receipt_id` | string | ❌ | Content-addressed identifier (§7) |
| `content_hash` | string | ❌ | SHA-256 of canonical core (§7) |
| `timestamp` | string | ❌ | RFC 3339 UTC generation time |
| `extensions` | object | ❌ | Extension point (§8) |

### 2.1 CORE_KEYS

The **core** of a receipt is the subset of fields that contribute to the
content hash. The core keys are exactly:

```
CORE_KEYS = {"type", "schema", "version", "commit", "ai_attestation", "provenance"}
```

These six keys — and ONLY these six — form the hash input. All other fields
(`receipt_id`, `content_hash`, `timestamp`, `extensions`) are **derived** or
**non-content** and MUST NOT affect the hash.

> **Forward-compatibility**: New top-level fields added in future schema
> versions MUST NOT be included in CORE_KEYS unless the schema identifier
> changes (e.g., `aiir/commit_receipt.v2`). The CORE_KEYS set is an explicit
> allowlist, not a denylist.

---

## 3. Commit Object

The `commit` field is a JSON object with the following structure:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sha` | string | ✅ | Full hex SHA of the git commit (40 or 64 chars) |
| `author` | GitIdentity | ✅ | Author identity |
| `committer` | GitIdentity | ✅ | Committer identity |
| `subject` | string | ✅ | First line of commit message |
| `message_hash` | string | ✅ | `"sha256:" + SHA-256(message_body)` |
| `diff_hash` | string | ✅ | `"sha256:" + SHA-256(full_diff)` |
| `files_changed` | integer | ✅ | Number of files changed |
| `files` | string[] | Conditional | File paths (max 100). Present when not redacted. |
| `files_redacted` | `true` | Conditional | Present when `--redact-files` active. Mutually exclusive with `files`. |
| `files_capped` | `true` | Optional | Present when file list was truncated at 100. |

### 3.1 GitIdentity

```json
{
  "name": "string",
  "email": "string",
  "date": "string (RFC 3339 or git default format)"
}
```

All three fields are REQUIRED. No additional properties are permitted.

### 3.2 Hash Computation

- **message_hash**: `"sha256:" + hex(SHA-256(body.encode("utf-8")))` where
  `body` is the full commit message body (everything after the subject line,
  including trailers).

- **diff_hash**: `"sha256:" + hex(SHA-256(diff_bytes))` where `diff_bytes` is
  the raw output of `git diff <parent> <sha>` with flags:
  - `--no-ext-diff` (prevent custom diff drivers)
  - `--no-textconv` (prevent text conversion filters)
  - `--no-optional-locks` (prevent lock contention)

  For root commits (no parent), the diff is computed against the empty tree.

---

## 4. AI Attestation Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `is_ai_authored` | boolean | ✅ | True if any AI signal detected |
| `signals_detected` | string[] | ✅ | List of detected AI signals |
| `signal_count` | integer | ✅ | `len(signals_detected)` |
| `is_bot_authored` | boolean | Optional | True if bot pattern matched |
| `bot_signals_detected` | string[] | Optional | Bot signal list |
| `bot_signal_count` | integer | Optional | `len(bot_signals_detected)` |
| `authorship_class` | string | Optional | One of: `"human"`, `"ai_assisted"`, `"bot"`, `"ai+bot"` |
| `detection_method` | string | ✅ | Algorithm identifier (e.g., `"heuristic_v2"`) |

### 4.1 Detection Method

The `detection_method` field identifies the algorithm used. The reference
implementation uses `"heuristic_v2"`, which performs:

1. NFKC normalization of all text fields
2. Confusable character resolution (Cyrillic/Greek → Latin)
3. Unicode category Cf (format) and Mn/Me (mark) stripping
4. Case-insensitive pattern matching against known AI tool signatures
5. Bot author/committer pattern matching

Third-party implementations MAY use different detection methods and SHOULD
identify them with a distinct `detection_method` value.

### 4.2 Authorship Classification

| Class | Criteria |
|-------|----------|
| `human` | No AI or bot signals detected |
| `ai_assisted` | AI signals detected, human author |
| `bot` | Bot signals detected, no AI signals |
| `ai+bot` | AI signals detected AND bot author |

> **Note:** `ai_generated` appeared in schema versions ≤ 1.0.13 but was
> never emitted by the reference implementation. It is accepted by the
> validator for backward compatibility but SHOULD NOT be produced.
> Use `ai+bot` for commits with both AI and bot signals.

---

## 5. Provenance Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `repository` | string \| null | ✅ | Git remote URL (credentials stripped). Null if no remote. |
| `tool` | string | ✅ | URI identifier: `"https://github.com/invariant-systems-ai/aiir@{version}"` |
| `generator` | string | ✅ | Generator ID: `"aiir.cli"`, `"aiir.action"`, `"aiir.mcp"`, or custom |

### 5.1 Credential Stripping

The `repository` field MUST have all credentials removed:
- Userinfo component of the URL (e.g., `https://token@github.com/...` → `https://github.com/...`)
- Query parameters (may contain tokens)
- URL fragments

Implementations MUST strip credentials before including the URL in the receipt.

---

## 6. Canonical JSON Encoding

The canonical JSON encoding is the **sole deterministic serialization** used
for content addressing. All implementations MUST produce byte-identical output
for the same input object.

### 6.1 Algorithm

```
canonical_json(obj) → UTF-8 string
```

1. Serialize `obj` to JSON with:
   - **Sorted keys**: All object keys are sorted lexicographically (by Unicode code point)
   - **No whitespace**: No spaces after `:` or `,` separators
   - **ASCII-safe**: All non-ASCII characters are escaped as `\uXXXX`
   - **No NaN/Infinity**: `NaN` and `Infinity` are rejected (not valid JSON per RFC 8259)
2. The separators MUST be exactly `(",", ":")`
3. Key sorting MUST be recursive (all nested objects are also sorted)

### 6.2 Reference

In Python's `json` module:

```python
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
```

### 6.3 Depth Limit

Implementations MUST reject JSON structures exceeding 64 levels of nesting
to prevent stack overflow attacks. The depth check SHOULD be iterative
(stack-based), not recursive.

### 6.4 Examples

Input:
```json
{"b": 1, "a": {"d": 2, "c": 3}}
```

Canonical output:
```
{"a":{"c":3,"d":2},"b":1}
```

---

## 7. Content Addressing

### 7.1 Content Hash

```
content_hash = "sha256:" + hex(SHA-256(canonical_json(core)))
```

Where `core` is the receipt object filtered to only CORE_KEYS:

```python
core = {k: v for k, v in receipt.items() if k in CORE_KEYS}
```

The SHA-256 is computed over the UTF-8 encoding of the canonical JSON string.

### 7.2 Receipt ID

```
receipt_id = "g1-" + hex(SHA-256(canonical_json(core)))[:32]
```

The `g1-` prefix denotes **generation 1** of the ID scheme. Future ID
schemes (e.g., using different hash functions or encoding) would use
`g2-`, `g3-`, etc.

The receipt ID is a **truncated** hash (128 bits / 16 bytes). It is
sufficient for uniqueness within practical receipt sets but MUST NOT be
used alone for tamper detection — use `content_hash` for integrity
verification.

### 7.3 Determinism

Given identical CORE_KEYS values, any conforming implementation MUST produce
the same `content_hash` and `receipt_id`. This is the fundamental
interoperability guarantee.

---

## 8. Extensions

The `extensions` field is a JSON object that MAY contain arbitrary keys.
It is NOT part of CORE_KEYS and does NOT affect `content_hash` or
`receipt_id`.

> **⚠️ Normative**: Extension data is **annotation-only metadata**.
> Extensions (including `agent_attestation`, `instance_id`, etc.) are
> NOT covered by the content-addressing scheme. A receipt's
> `content_hash` and `receipt_id` remain unchanged if extension fields
> are added, modified, or removed.
>
> If extension data is policy-significant (e.g., agent identity,
> model name, or context window), the receipt MUST be wrapped in a
> signed envelope (Sigstore per §11, or in-toto Statement per §14.2)
> to bind extension content cryptographically. Implementations MUST
> NOT treat unsigned extension fields as audit-grade evidence.

Known extension keys:

| Key | Type | Description |
|-----|------|-------------|
| `instance_id` | string | User-supplied instance identifier |
| `namespace` | string | Organizational grouping label |
| `agent_attestation` | object | Agent identity, model, and context metadata (annotation-only; see warning above) |

Implementations SHOULD preserve unknown extension keys when round-tripping
receipts.

---

## 9. Verification Algorithm

To verify a receipt, an implementation MUST:

1. **Schema validation**: Verify the receipt is a JSON object containing all
   required fields with correct types (see JSON Schema).

2. **Type check**: Verify `type == "aiir.commit_receipt"`.

3. **Schema version check**: Verify `schema` starts with `"aiir/"`.

4. **Version format check**: Verify `version` matches `^[0-9]+\.[0-9]+\.[0-9]+([.+\-][0-9a-zA-Z.+\-]*)?$` (SemVer).

5. **Core extraction**: Extract `core = {k: v for k, v in receipt.items() if k in CORE_KEYS}`.

6. **Canonical encoding**: Compute `core_json = canonical_json(core)`.

7. **Hash computation**: Compute:
   - `expected_hash = "sha256:" + hex(SHA-256(core_json.encode("utf-8")))`
   - `expected_id = "g1-" + hex(SHA-256(core_json.encode("utf-8")))[:32]`

8. **Constant-time comparison**: Compare `expected_hash` against
   `receipt["content_hash"]` and `expected_id` against
   `receipt["receipt_id"]` using constant-time comparison
   (e.g., `hmac.compare_digest`).

9. **Result**: The receipt is valid if and only if BOTH comparisons succeed.

### 9.1 Error Reporting

On failure, implementations SHOULD report which check failed:
- `"content hash mismatch"` — core fields were modified after generation
- `"receipt_id mismatch"` — receipt ID was modified
- `"unknown receipt type"` — not an AIIR receipt
- `"unknown schema"` — unrecognized schema version
- `"invalid version format"` — version string contains prohibited characters

### 9.2 Security Considerations

- **No expected hash on failure**: On verification failure, implementations
  MUST NOT expose the expected hash values. Doing so would be a **forgery
  oracle** — an attacker could extract the correct hash and splice it in.

- **Constant-time comparison**: String comparison MUST use constant-time
  algorithms to prevent timing side-channel attacks.

- **Depth limit**: The canonical JSON encoder MUST enforce a depth limit
  (64 levels) to prevent stack overflow from crafted receipts.

---

## 10. File Verification

When verifying a receipt from a file, implementations MUST:

1. Reject symlinks (prevent filesystem probing)
2. Reject files larger than 50 MB (prevent memory exhaustion)
3. Parse as UTF-8 JSON
4. Handle both single receipt (JSON object) and batch (JSON array)
5. Cap array length at 1000 entries (prevent quadratic DoS)

---

## 11. Sigstore Signing (Optional)

Receipts MAY be cryptographically signed using [Sigstore](https://sigstore.dev)
keyless signing. Signing adds:

- Non-repudiation (proves who generated the receipt)
- Tamper-proof integrity (beyond self-attested content addressing)
- Transparency log entry (public audit trail via Rekor)

Without signing, receipts are **tamper-evident** (modification is detectable)
but not **tamper-proof** (a new valid receipt can be fabricated by anyone who
can run the tool on the same commit).

Signing is RECOMMENDED for compliance-critical workflows.

### 11.1 Trust Tiers

Receipts exist at one of three trust tiers. Consumers MUST understand
which tier applies before making policy decisions:

| Tier | Configuration | Integrity | Authenticity | Suitable for |
|------|--------------|-----------|-------------|-------------|
| **Tier 1 — Unsigned** | `sign: false` | Tamper-**evident** (content hash) | None — anyone who can run `aiir` on the same commit can produce an identical receipt | Developer convenience, local audit trails, smoke testing |
| **Tier 2 — Signed** | `sign: true` (default in GitHub Action) | Tamper-**proof** (Sigstore bundle) | Signer identity bound via OIDC + transparency log | CI/CD compliance, SOC 2 evidence, audit-grade provenance |
| **Tier 3 — Enveloped** | in-toto Statement wrapper (§14.2) | Tamper-**proof** + envelope integrity | Predicate + subject bound to signer | Supply-chain attestation, SLSA provenance, cross-system verification |

**Extensions at each tier:**

- **Tier 1**: Extensions are mutable annotation. They MAY change without
  affecting `receipt_id`. Do NOT use for policy decisions.
- **Tier 2**: The Sigstore signature covers the **entire** receipt JSON
  (including extensions). Modification of any field — core or extension —
  invalidates the signature.
- **Tier 3**: The in-toto envelope binds the full predicate (receipt) to
  a subject and signer. Extensions are cryptographically bound.

> **Guideline**: For regulatory compliance (EU AI Act, SOC 2, ISO 27001),
> use Tier 2 or Tier 3. Tier 1 receipts are useful for development
> workflows but SHOULD NOT be cited as tamper-proof evidence.

---

## 12. Security Surfaces

The AIIR tool operates across multiple security surfaces with different
threat models:

| Surface | Read restriction | Write restriction | Rationale |
|---------|-----------------|-------------------|-----------|
| CLI `--verify` | None (user-explicit path) | N/A (read-only) | User typed the path. No oracle risk. |
| CLI `--output` | N/A | CWD boundary enforced | Prevent writes outside project. |
| MCP `aiir_verify` | CWD boundary enforced | N/A (read-only) | AI assistant could be tricked into using verify as a filesystem oracle (F4-02). |
| MCP `aiir_generate` | N/A | CWD boundary enforced | Prevent AI-directed writes outside project. |
| GitHub Action | Runner workspace | Runner workspace | Sandboxed by Actions runtime. |

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full STRIDE analysis (142 controls).

---

## 13. Test Vectors

Machine-readable test vectors are provided at:
- [`schemas/test_vectors.json`](schemas/test_vectors.json)

Each test vector includes:
- A complete receipt JSON
- Expected verification result (`valid: true/false`)
- Expected error messages (if invalid)
- A human-readable description

Conforming implementations MUST pass all test vectors.

---

## 14. IANA Considerations

### 14.1 Media Type Registration

The following media type registration is prepared per
[RFC 6838](https://www.rfc-editor.org/rfc/rfc6838) §3.2 (Vendor Tree):

| Field | Value |
|-------|-------|
| **Type name** | `application` |
| **Subtype name** | `vnd.aiir.commit-receipt+json` |
| **Required parameters** | None |
| **Optional parameters** | `schema` — the receipt schema identifier (e.g., `aiir/commit_receipt.v1`). When absent, consumers SHOULD inspect the `schema` field in the JSON body. |
| **Encoding considerations** | 8bit. The content is UTF-8 encoded JSON per [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259). |
| **Security considerations** | See §12 and [THREAT_MODEL.md](THREAT_MODEL.md). Receipts contain git commit metadata including author names, email addresses, and commit subjects. Consumers MUST validate receipts using the verification algorithm (§9) before trusting content. Receipt fields may contain user-controlled text — display layers MUST sanitize to prevent injection (XSS, terminal escape, log injection). The `content_hash` field MUST be verified via constant-time comparison (§9.2) to prevent timing side-channel attacks. |
| **Interoperability considerations** | All conforming implementations MUST produce identical `content_hash` and `receipt_id` values for the same input data (§7.3). Interoperability is verified via published test vectors (§13). Two independent implementations (Python, TypeScript) currently pass all vectors. |
| **Published specification** | This document ([SPEC.md](https://github.com/invariant-systems-ai/aiir/blob/main/SPEC.md)). Machine-readable schema: [`commit_receipt.v1.schema.json`](https://invariantsystems.io/schemas/aiir/commit_receipt.v1.schema.json). |
| **Applications which use this media type** | AIIR CLI, AIIR GitHub Action, AIIR MCP Server, CI/CD pipelines, compliance audit systems, supply-chain attestation frameworks (via in-toto envelope). |
| **Fragment identifier considerations** | None. |
| **Restrictions on usage** | None. |
| **Additional information** | File extension: `.json`, `.jsonl` (when stored as append-only ledger). Macintosh file type code: None. Deprecated alias names: None. Magic number: The first bytes of a receipt will match `{"type":"aiir.commit_receipt"` after whitespace normalization. |
| **Person & email address to contact** | Noah — `noah@invariantsystems.io` |
| **Intended usage** | COMMON |
| **Change controller** | Invariant Systems, Inc. |

### 14.2 Predicate Type URI

The in-toto predicate type URI is:

```
https://aiir.dev/commit_receipt/v1
```

This URI identifies AIIR commit receipt predicates within
[in-toto Statement v1](https://in-toto.io/Statement/v1) envelopes.
It resolves to a human-readable description of the predicate format
with links to the specification and schema.

Canonical alias (until `aiir.dev` DNS is delegated):
`https://invariantsystems.io/predicates/aiir/commit_receipt/v1`

### 14.3 Schema URI

The JSON Schema `$id` URI is:

```
https://invariantsystems.io/schemas/aiir/commit_receipt.v1.schema.json
```

This URI resolves to the machine-readable JSON Schema (draft 2020-12)
for the `aiir/commit_receipt.v1` receipt format.

---

## 15. Specification Governance

### 15.1 Stewardship

This specification is maintained by **Invariant Systems, Inc.** The
canonical source is the `SPEC.md` file in the
[aiir repository](https://github.com/invariant-systems-ai/aiir).

### 15.2 Versioning Policy

The specification uses **Semantic Versioning** (SemVer):

- **Patch** (1.0.x): Clarifications, typo fixes, additional test vectors.
  No behavioral changes. Existing implementations remain conformant.
- **Minor** (1.x.0): Backward-compatible additions — new optional fields,
  new extension points, additional security surfaces. Existing receipts
  remain valid. Existing implementations remain conformant for the fields
  they support.
- **Major** (x.0.0): Breaking changes — new CORE_KEYS, changed canonical
  JSON rules, new schema identifier (e.g., `aiir/commit_receipt.v2`).
  Existing implementations MUST update to remain conformant. The previous
  schema version will be documented as deprecated but MUST continue to
  verify correctly for receipts generated under that version.

### 15.3 Change Process

1. **Proposal**: Open a GitHub issue or pull request against SPEC.md with
   a clear description of the proposed change and its rationale.
2. **Discussion**: Changes are discussed publicly on the pull request.
   Security-sensitive changes may be discussed privately per
   [SECURITY.md](SECURITY.md) and disclosed when fixed.
3. **Reference implementation**: All spec changes MUST ship with a
   corresponding update to the reference implementation and test vectors.
   A spec change without tests will not be merged.
4. **Release**: Spec version bumps are released alongside the reference
   implementation version that implements them.

### 15.4 Backward Compatibility Guarantees

- A receipt generated by `aiir/commit_receipt.v1` MUST verify correctly
  against any future 1.x implementation.
- The CORE_KEYS set (`type`, `schema`, `version`, `commit`,
  `ai_attestation`, `provenance`) MUST NOT change within a major version.
- The canonical JSON algorithm MUST NOT change within a major version.
- Test vectors from previous spec versions MUST continue to pass.

### 15.5 Interoperability

Third-party implementations claiming AIIR compatibility SHOULD:
- Reference the spec version they conform to
- Pass all published test vectors for that version
- Follow the badge usage guidelines in [TRADEMARK.md](TRADEMARK.md)

---

## 16. Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-03-09 | Initial specification extracted from reference implementation |
| 1.0.1 | 2026-03-09 | §14: IANA media type registration template, predicate type URI, schema URI resolution |
