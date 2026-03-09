/**
 * @aiir/verify — AIIR receipt verification for JavaScript/TypeScript
 *
 * Zero dependencies. Works in browsers (via SubtleCrypto) and Node.js (≥18).
 * Implements the full verification algorithm from SPEC.md §9.
 *
 * @license Apache-2.0
 * @see https://github.com/invariant-systems-ai/aiir
 * @see https://invariantsystems.io/spec
 */

// ── Constants ─────────────────────────────────────────────────────────
const CORE_KEYS = new Set(['type', 'schema', 'version', 'commit', 'ai_attestation', 'provenance']);
const MAX_DEPTH = 64;
const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+([.+\-][0-9a-zA-Z.+\-]*)?$/;

// ── Canonical JSON ────────────────────────────────────────────────────

/**
 * Produce canonical JSON encoding per SPEC.md §6.
 * - Sorted keys (recursive, lexicographic by Unicode code point)
 * - No whitespace (separators: "," and ":")
 * - ASCII-safe (\uXXXX escaping for non-ASCII)
 * - No NaN/Infinity
 * - Depth limit: 64 levels
 *
 * @param {unknown} obj - The value to serialize
 * @returns {string} Canonical JSON string
 */
function canonicalJson(obj) {
  return _encode(obj, 0);
}

function _encode(val, depth) {
  if (depth > MAX_DEPTH) {
    throw new Error('canonical JSON depth limit exceeded (max 64)');
  }

  if (val === null) return 'null';
  if (val === undefined) return undefined;

  const t = typeof val;

  if (t === 'boolean') return val ? 'true' : 'false';

  if (t === 'number') {
    if (!isFinite(val)) {
      throw new Error('canonical JSON does not allow NaN or Infinity');
    }
    return JSON.stringify(val);
  }

  if (t === 'string') {
    // ensure_ascii: escape all non-ASCII as \uXXXX
    let out = '"';
    for (let i = 0; i < val.length; i++) {
      const c = val.charCodeAt(i);
      if (c === 0x22) { out += '\\"'; }       // "
      else if (c === 0x5c) { out += '\\\\'; }  // \
      else if (c === 0x08) { out += '\\b'; }
      else if (c === 0x0c) { out += '\\f'; }
      else if (c === 0x0a) { out += '\\n'; }
      else if (c === 0x0d) { out += '\\r'; }
      else if (c === 0x09) { out += '\\t'; }
      else if (c < 0x20) {
        out += '\\u' + c.toString(16).padStart(4, '0');
      } else if (c > 0x7e) {
        // Handle surrogate pairs
        if (c >= 0xd800 && c <= 0xdbff && i + 1 < val.length) {
          const lo = val.charCodeAt(i + 1);
          if (lo >= 0xdc00 && lo <= 0xdfff) {
            out += '\\u' + c.toString(16).padStart(4, '0');
            out += '\\u' + lo.toString(16).padStart(4, '0');
            i++;
            continue;
          }
        }
        out += '\\u' + c.toString(16).padStart(4, '0');
      } else {
        out += val[i];
      }
    }
    out += '"';
    return out;
  }

  if (Array.isArray(val)) {
    const items = [];
    for (let i = 0; i < val.length; i++) {
      const encoded = _encode(val[i], depth + 1);
      items.push(encoded === undefined ? 'null' : encoded);
    }
    return '[' + items.join(',') + ']';
  }

  if (t === 'object') {
    const keys = Object.keys(val).sort();
    const pairs = [];
    for (const k of keys) {
      const v = _encode(val[k], depth + 1);
      if (v !== undefined) {
        pairs.push(_encode(k, depth + 1) + ':' + v);
      }
    }
    return '{' + pairs.join(',') + '}';
  }

  throw new Error('canonical JSON cannot encode type: ' + t);
}

// ── SHA-256 ───────────────────────────────────────────────────────────

/**
 * Compute SHA-256 of a UTF-8 string.
 * Uses SubtleCrypto (browser/Node ≥18) with Node.js crypto fallback.
 *
 * @param {string} str
 * @returns {Promise<string>} Hex-encoded SHA-256 hash
 */
async function sha256(str) {
  const bytes = new TextEncoder().encode(str);

  // Try SubtleCrypto first (available in browsers + Node ≥18)
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    const buf = await globalThis.crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // Node.js fallback
  if (typeof require !== 'undefined') {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(bytes).digest('hex');
  }

  throw new Error('No SHA-256 implementation available (need SubtleCrypto or Node.js crypto)');
}

// ── Constant-time comparison ──────────────────────────────────────────

/**
 * Constant-time string comparison to prevent timing side-channel attacks.
 * Per SPEC.md §9.2.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ── Verification ──────────────────────────────────────────────────────

/**
 * @typedef {Object} VerifyResult
 * @property {boolean} valid - True if receipt passes all checks
 * @property {string[]} errors - List of error messages (empty if valid)
 */

/**
 * Verify an AIIR commit receipt per SPEC.md §9.
 *
 * @param {unknown} receipt - Parsed receipt JSON
 * @returns {Promise<VerifyResult>}
 */
async function verify(receipt) {
  const errors = [];

  // 1. Must be an object
  if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
    return { valid: false, errors: ['receipt is not a dict'] };
  }

  // 2. Type check
  if (receipt.type !== 'aiir.commit_receipt') {
    return { valid: false, errors: ['unknown receipt type: \'' + String(receipt.type) + '\''] };
  }

  // 3. Schema version check
  if (typeof receipt.schema !== 'string') {
    return { valid: false, errors: ['unknown schema: ' + String(receipt.schema)] };
  }
  if (!receipt.schema.startsWith('aiir/')) {
    return { valid: false, errors: ['unknown schema: \'' + receipt.schema + '\''] };
  }

  // 4. Version format check
  if (typeof receipt.version !== 'string' || !VERSION_RE.test(receipt.version)) {
    return { valid: false, errors: ['invalid version format: \'' + String(receipt.version) + '\''] };
  }

  // 5. Core extraction
  const core = {};
  for (const key of Object.keys(receipt)) {
    if (CORE_KEYS.has(key)) {
      core[key] = receipt[key];
    }
  }

  // 6 + 7. Hash computation
  const coreJson = canonicalJson(core);
  const hash = await sha256(coreJson);
  const expectedHash = 'sha256:' + hash;
  const expectedId = 'g1-' + hash.slice(0, 32);

  // 8. Constant-time comparison — NEVER expose expected values on failure (§9.2)
  if (!constantTimeEqual(expectedHash, receipt.content_hash || '')) {
    errors.push('content hash mismatch');
  }
  if (!constantTimeEqual(expectedId, receipt.receipt_id || '')) {
    errors.push('receipt_id mismatch');
  }

  return { valid: errors.length === 0, errors };
}

// ── Exports ───────────────────────────────────────────────────────────

// Support both ESM and CommonJS
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { canonicalJson, sha256, verify, constantTimeEqual };
}

// Also export for ESM / browser script module usage
if (typeof globalThis !== 'undefined') {
  globalThis.AIIR = { canonicalJson, sha256, verify, constantTimeEqual };
}
