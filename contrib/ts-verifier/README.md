# AIIR TypeScript Verifier — Conformance Implementation

Independent TypeScript implementation of the [AIIR commit receipt verification algorithm](../../SPEC.md).

This is **not** a port of the Python reference implementation — it was written from the specification alone. It exists to prove that SPEC.md is sufficient for interoperable third-party implementations.

## Conformance

This implementation passes all 15 published [test vectors](../../schemas/test_vectors.json) from spec version 1.0.0.

## Quick Start

```bash
# Install (TypeScript compiler only — zero runtime dependencies)
npm install

# Build and run conformance tests
npm test
```

## API

```typescript
import { verifyReceipt, canonicalJson } from "@aiir/verifier";

// Verify a receipt
const result = verifyReceipt(receiptObject);
// → { valid: true, errors: [] }
// → { valid: false, errors: ["content hash mismatch"] }

// Produce canonical JSON (for custom integrations)
const encoded = canonicalJson({ b: 1, a: { d: 2, c: 3 } });
// → '{"a":{"c":3,"d":2},"b":1}'
```

## What It Implements

| SPEC.md Section | Feature | Status |
|-----------------|---------|--------|
| §6 Canonical JSON Encoding | Sorted keys, no whitespace, ASCII-safe | ✅ |
| §6.3 Depth Limit | 64-level nesting cap | ✅ |
| §7.1 Content Hash | `sha256:` + SHA-256 of canonical core | ✅ |
| §7.2 Receipt ID | `g1-` + truncated hash | ✅ |
| §9 Verification Algorithm | All 9 steps | ✅ |
| §9.2 Constant-time comparison | `crypto.timingSafeEqual` | ✅ |
| §9.2 No expected hash on failure | Forgery oracle prevention | ✅ |

## Requirements

- **Node.js 18+** (for built-in `crypto` module)
- **TypeScript 5.4+** (build only)
- **Zero runtime dependencies**

## How It Relates to the Python Reference

| Aspect | Python (`aiir`) | TypeScript (`@aiir/verifier`) |
|--------|----------------|-------------------------------|
| Scope | Full CLI + generation + verification | Verification only |
| Dependencies | Zero (stdlib) | Zero (Node.js built-in) |
| Written from | Original implementation | SPEC.md specification |
| Test vectors | Generates + passes | Passes |
| Purpose | Reference implementation | Conformance proof |

## License

Apache-2.0 — Copyright 2025-2026 Invariant Systems, Inc.
