# Tamper Detection — How AIIR Receipts Protect Integrity

Every AIIR receipt is **content-addressed**: the `receipt_id` and
`content_hash` are derived from a SHA-256 hash of the receipt's canonical
JSON core fields. Change one character — the hash breaks, and verification
fails.

This guide walks through exactly what happens when a receipt is modified.

---

## How content addressing works

A receipt has **six core fields** that contribute to the hash:

```text
CORE_KEYS = {"type", "schema", "version", "commit", "ai_attestation", "provenance"}
```

These are serialized as **canonical JSON** (sorted keys, no extra whitespace,
ASCII-safe Unicode escaping), then SHA-256 hashed. The resulting hash becomes
the `content_hash`, and a truncated form becomes the `receipt_id`.

**Non-core fields** — `receipt_id`, `content_hash`, `timestamp`, `extensions`
— are derived or informational. They don't affect the hash.

---

## A valid receipt

Here's a receipt for a human-authored commit:

```json
{
  "type": "aiir.commit_receipt",
  "schema": "aiir/commit_receipt.v1",
  "version": "1.0.12",
  "commit": {
    "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "author": {
      "name": "Alice",
      "email": "alice@example.com",
      "date": "2026-03-09T00:00:00Z"
    },
    "committer": {
      "name": "Alice",
      "email": "alice@example.com",
      "date": "2026-03-09T00:00:00Z"
    },
    "subject": "feat: add widget",
    "message_hash": "sha256:375aca2c5a71c7ffaaa0c3602ed0f82d27986ce0776b5c5c1bc2d2a5638b18bb",
    "diff_hash": "sha256:a9b7bc7b29f22a8b1ae213c4105d73c39b9e3f218d75bb6a288207c1d86b96fe",
    "files_changed": 1,
    "files": ["widget.py"]
  },
  "ai_attestation": {
    "is_ai_authored": false,
    "signals_detected": [],
    "signal_count": 0,
    "is_bot_authored": false,
    "bot_signals_detected": [],
    "bot_signal_count": 0,
    "authorship_class": "human",
    "detection_method": "heuristic_v2"
  },
  "provenance": {
    "repository": "https://github.com/example/repo",
    "tool": "https://github.com/invariant-systems-ai/aiir@1.0.12",
    "generator": "aiir.cli"
  },
  "receipt_id": "g1-ff76d2a88adff37fcd3a37fa42bb52b8",
  "content_hash": "sha256:ff76d2a88adff37fcd3a37fa42bb52b8eec24750e123a6e9d6925ef9f5e719da",
  "timestamp": "2026-03-09T00:00:00Z",
  "extensions": {}
}
```

Verify it:

```bash
aiir --verify receipt.json
# ✅ VALID — content hash matches
```

With explanation:

```bash
aiir --verify receipt.json --explain
# Shows step-by-step: canonical JSON → SHA-256 → hash comparison → PASS
```

---

## What happens when you tamper

### Scenario 1: Change the author name

Change `"Alice"` to `"Mallory"` in the `commit.author.name` field.

**Result**: `content_hash` no longer matches the recomputed hash.

```bash
aiir --verify tampered-receipt.json
# ❌ INVALID — content hash mismatch
#    Expected: sha256:ff76d2a88adff37fcd3a37fa42bb52b8...
#    Got:      sha256:a1b2c3d4... (different — author changed)
```

The `commit` object is a core field. Any change inside it — author, SHA,
subject, files — invalidates the receipt.

### Scenario 2: Flip AI authorship

Change `"is_ai_authored": false` to `"is_ai_authored": true`.

**Result**: Immediate verification failure.

```bash
aiir --verify tampered-receipt.json
# ❌ INVALID — content hash mismatch
#    The ai_attestation object changed, so the hash changed
```

An attacker cannot claim a commit was human-authored when it was AI-assisted,
or vice versa. The attestation is bound into the hash.

### Scenario 3: Change the receipt_id only

Change the `receipt_id` value but leave everything else intact.

**Result**: Verification detects the ID doesn't match the hash.

```bash
aiir --verify tampered-receipt.json
# ❌ INVALID — receipt_id does not match content_hash
#    The receipt_id must be derived from the content_hash
```

### Scenario 4: Modify a non-core field (timestamp)

Change the `timestamp` value.

**Result**: The content hash still matches (timestamps are non-core), but
the receipt_id remains valid. This is by design — timestamps record *when*
the receipt was generated, not *what* was committed.

```bash
aiir --verify modified-timestamp.json
# ✅ VALID — timestamp is not part of the content hash
```

### Scenario 5: Add an extension field

Add `"extensions": {"custom": "metadata"}`.

**Result**: Valid. Extensions are non-core.

```bash
aiir --verify receipt-with-extension.json
# ✅ VALID — extensions are not part of the content hash
```

---

## Why this matters

| Property | What it means |
|----------|--------------|
| **Tamper-evident** | Any modification to core fields is detectable |
| **Deterministic** | Same input always produces same hash |
| **Field-level binding** | Author, commit SHA, AI signals, and provenance are all bound together |
| **Forward-compatible** | New non-core fields (extensions, timestamps) don't break existing receipts |

### Unsigned vs. signed receipts

Content addressing provides **tamper evidence** — you can detect if a receipt
was modified after generation.

For **tamper proof** (proving *who* generated the receipt), enable
[Sigstore keyless signing](../README.md#sigstore-signing). A signed receipt
binds the content hash to a verifiable identity (e.g., your CI pipeline's
OIDC token), recorded in the Rekor transparency log.

```bash
# Verify content integrity + cryptographic signature + signer identity
aiir --verify receipt.json --verify-signature \
  --signer-identity "https://github.com/myorg/myrepo/.github/workflows/aiir.yml@refs/heads/main" \
  --signer-issuer "https://token.actions.githubusercontent.com"
```

---

## Try it yourself

```bash
# 1. Generate a receipt
pip install aiir
cd your-repo
aiir --json > receipt.json

# 2. Verify it
aiir --verify receipt.json --explain

# 3. Tamper with it
# Open receipt.json, change the commit subject, save
aiir --verify receipt.json
# ❌ INVALID

# 4. Verify the conformance test vectors
curl -O https://raw.githubusercontent.com/invariant-systems-ai/aiir/main/schemas/test_vectors.json
# Use the test vectors to validate your own implementation
```

---

## Conformance test vectors

The AIIR specification includes [15 conformance test vectors](../schemas/test_vectors.json)
with precomputed hashes covering:

- Valid human, AI-assisted, bot, and mixed-authorship receipts
- Tampered receipts (wrong hash, wrong receipt_id, schema mismatch)
- Edge cases (Unicode, empty fields, multiple AI signals)

Any implementation claiming AIIR compatibility MUST pass all test vectors.
See [SPEC.md § 13](../SPEC.md#13-test-vectors) for details.
