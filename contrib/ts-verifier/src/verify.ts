/**
 * AIIR Commit Receipt Verifier — TypeScript Conformance Implementation
 *
 * Independent implementation of the AIIR verification algorithm as specified
 * in SPEC.md §9. Zero runtime dependencies — uses only Node.js built-in
 * `crypto` module.
 *
 * This implementation MUST produce identical verification results to the
 * Python reference implementation for all published test vectors.
 *
 * Specification: https://github.com/invariant-systems-ai/aiir/blob/main/SPEC.md
 * Schema: https://invariantsystems.io/schemas/aiir/commit_receipt.v1.schema.json
 *
 * Copyright 2025-2026 Invariant Systems, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { createHash, timingSafeEqual } from "node:crypto";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * The six core keys that contribute to the content hash.
 * SPEC.md §2.1: These keys — and ONLY these — form the hash input.
 */
const CORE_KEYS: ReadonlySet<string> = new Set([
  "type",
  "schema",
  "version",
  "commit",
  "ai_attestation",
  "provenance",
]);

/**
 * SemVer pattern from SPEC.md §9 step 4.
 */
const VERSION_RE =
  /^[0-9]+\.[0-9]+\.[0-9]+([.+\-][0-9a-zA-Z.+\-]*)?$/;

/**
 * Maximum JSON nesting depth (SPEC.md §6.3).
 */
const MAX_DEPTH = 64;

// ---------------------------------------------------------------------------
// Canonical JSON Encoding (SPEC.md §6)
// ---------------------------------------------------------------------------

/**
 * Encode a string as a JSON string literal with ensure_ascii semantics.
 *
 * Matches Python's `json.dumps(s, ensure_ascii=True)` exactly:
 * - Control chars (0x00–0x1f): short escapes for \b \t \n \f \r, else \uXXXX
 * - Printable ASCII (0x20–0x7e): literal, except " → \" and \ → \\
 * - DEL (0x7f) and above: \uXXXX (surrogate pairs for astral plane)
 */
function asciiSafeStringify(s: string): string {
  let result = '"';
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code === 0x22) {
      result += '\\"';
    } else if (code === 0x5c) {
      result += "\\\\";
    } else if (code === 0x08) {
      result += "\\b";
    } else if (code === 0x09) {
      result += "\\t";
    } else if (code === 0x0a) {
      result += "\\n";
    } else if (code === 0x0c) {
      result += "\\f";
    } else if (code === 0x0d) {
      result += "\\r";
    } else if (code >= 0x20 && code <= 0x7e) {
      result += s[i];
    } else {
      // Control chars, DEL, all non-ASCII → \uXXXX (lowercase hex, zero-padded)
      result += "\\u" + code.toString(16).padStart(4, "0");
    }
  }
  return result + '"';
}

/**
 * Produce the canonical JSON encoding of a value.
 *
 * SPEC.md §6.1:
 * - Sorted keys (recursive, lexicographic by Unicode code point)
 * - No whitespace (separators: "," and ":")
 * - ASCII-safe (all non-ASCII escaped as \uXXXX)
 * - No NaN/Infinity
 *
 * Equivalent to Python:
 *   json.dumps(obj, sort_keys=True, separators=(",", ":"),
 *              ensure_ascii=True, allow_nan=False)
 */
export function canonicalJson(obj: unknown, depth: number = 0): string {
  if (depth > MAX_DEPTH) {
    throw new Error(`JSON depth exceeds ${MAX_DEPTH} levels`);
  }

  if (obj === null) return "null";

  if (typeof obj === "boolean") return obj ? "true" : "false";

  if (typeof obj === "number") {
    if (!Number.isFinite(obj)) {
      throw new Error("NaN and Infinity are not valid JSON values");
    }
    return JSON.stringify(obj);
  }

  if (typeof obj === "string") {
    return asciiSafeStringify(obj);
  }

  if (Array.isArray(obj)) {
    const items = obj.map((v) => canonicalJson(v, depth + 1));
    return "[" + items.join(",") + "]";
  }

  if (typeof obj === "object") {
    const keys = Object.keys(obj).sort();
    const pairs = keys.map(
      (k) =>
        asciiSafeStringify(k) +
        ":" +
        canonicalJson((obj as Record<string, unknown>)[k], depth + 1)
    );
    return "{" + pairs.join(",") + "}";
  }

  throw new Error(`Unsupported type: ${typeof obj}`);
}

// ---------------------------------------------------------------------------
// Content Addressing (SPEC.md §7)
// ---------------------------------------------------------------------------

/**
 * Compute SHA-256 of a UTF-8 string, returned as lowercase hex.
 */
function sha256hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

/**
 * Constant-time string comparison (SPEC.md §9.2).
 * Returns false if lengths differ (without leaking which bytes differ).
 */
function safeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

// ---------------------------------------------------------------------------
// Verification Result
// ---------------------------------------------------------------------------

export interface VerifyResult {
  /** True if and only if all checks pass. */
  valid: boolean;
  /** List of human-readable error descriptions. Empty when valid. */
  errors: string[];
}

// ---------------------------------------------------------------------------
// Verification Algorithm (SPEC.md §9)
// ---------------------------------------------------------------------------

/**
 * Verify an AIIR commit receipt.
 *
 * Implements the 9-step verification algorithm from SPEC.md §9:
 * 1. Schema validation (structural — is it a JSON object?)
 * 2. Type check (must be "aiir.commit_receipt")
 * 3. Schema version check (must start with "aiir/")
 * 4. Version format check (SemVer regex)
 * 5. Core extraction (filter to CORE_KEYS)
 * 6. Canonical encoding
 * 7. Hash computation (SHA-256)
 * 8. Constant-time comparison
 * 9. Result
 *
 * Security: On failure, expected hash values are NOT exposed (SPEC.md §9.2).
 */
export function verifyReceipt(receipt: unknown): VerifyResult {
  // Step 1: Must be a JSON object (not null, not array, not primitive)
  if (
    typeof receipt !== "object" ||
    receipt === null ||
    Array.isArray(receipt)
  ) {
    return { valid: false, errors: ["receipt is not a dict"] };
  }

  const r = receipt as Record<string, unknown>;

  // Step 2: Type check
  if (r.type !== "aiir.commit_receipt") {
    const typeRepr =
      typeof r.type === "string" ? `'${r.type}'` : String(r.type);
    return {
      valid: false,
      errors: [`unknown receipt type: ${typeRepr}`],
    };
  }

  // Step 3: Schema version check
  if (typeof r.schema !== "string") {
    return {
      valid: false,
      errors: [`unknown schema: ${JSON.stringify(r.schema) ?? String(r.schema)}`],
    };
  }
  if (!r.schema.startsWith("aiir/")) {
    return {
      valid: false,
      errors: [`unknown schema: '${r.schema}'`],
    };
  }

  // Step 4: Version format check
  if (typeof r.version !== "string" || !VERSION_RE.test(r.version)) {
    const verRepr =
      typeof r.version === "string"
        ? `'${r.version}'`
        : String(r.version);
    return {
      valid: false,
      errors: [`invalid version format: ${verRepr}`],
    };
  }

  // Steps 5–6: Core extraction and canonical encoding
  const core: Record<string, unknown> = {};
  for (const key of Object.keys(r).sort()) {
    if (CORE_KEYS.has(key)) {
      core[key] = r[key];
    }
  }
  const coreJson = canonicalJson(core);

  // Step 7: Hash computation
  const hash = sha256hex(coreJson);
  const expectedHash = `sha256:${hash}`;
  const expectedId = `g1-${hash.slice(0, 32)}`;

  // Step 8: Constant-time comparison
  const actualHash =
    typeof r.content_hash === "string" ? r.content_hash : "";
  const actualId =
    typeof r.receipt_id === "string" ? r.receipt_id : "";

  const errors: string[] = [];
  if (!safeCompare(expectedHash, actualHash)) {
    errors.push("content hash mismatch");
  }
  if (!safeCompare(expectedId, actualId)) {
    errors.push("receipt_id mismatch");
  }

  // Step 9: Result
  return { valid: errors.length === 0, errors };
}
