# @aiir/verify

**AIIR receipt verification for JavaScript and TypeScript** — zero dependencies, works in browsers and Node.js (≥18).

Verify the cryptographic integrity of [AIIR commit receipts](https://github.com/invariant-systems-ai/aiir) in any JavaScript environment.

## Install

```bash
npm install @aiir/verify
```

## Usage

### Node.js

```javascript
const { verify } = require('@aiir/verify');

const receipt = JSON.parse(fs.readFileSync('receipt.aiir.json', 'utf-8'));
const result = await verify(receipt);

if (result.valid) {
  console.log('✅ Receipt verified');
} else {
  console.log('❌ Verification failed:', result.errors);
}
```

### TypeScript

```typescript
import { verify, VerifyResult } from '@aiir/verify';

const result: VerifyResult = await verify(receipt);
```

### Browser

```html
<script src="https://unpkg.com/@aiir/verify"></script>
<script>
  const result = await AIIR.verify(receiptObject);
</script>
```

Or as an ES module:

```javascript
import { verify } from '@aiir/verify';
```

## API

### `verify(receipt: unknown): Promise<VerifyResult>`

Verify an AIIR commit receipt per [SPEC.md §9](https://github.com/invariant-systems-ai/aiir/blob/main/SPEC.md).

Returns `{ valid: boolean, errors: string[] }`.

### `canonicalJson(obj: unknown): string`

Produce canonical JSON encoding per SPEC.md §6 (sorted keys, no whitespace, ASCII-safe).

### `sha256(str: string): Promise<string>`

Compute SHA-256 of a UTF-8 string. Uses SubtleCrypto (browser/Node ≥18) with Node.js `crypto` fallback.

### `constantTimeEqual(a: string, b: string): boolean`

Constant-time string comparison to prevent timing side-channel attacks (SPEC.md §9.2).

## What It Checks

1. Receipt type is `aiir.commit_receipt`
2. Schema starts with `aiir/`
3. Version is valid SemVer
4. `content_hash` matches SHA-256 of canonical core fields
5. `receipt_id` matches the expected `g1-` prefix + hash prefix
6. All comparisons use constant-time equality

## Zero Dependencies

This package has **zero runtime dependencies**. It uses the Web Crypto API (`SubtleCrypto`) for SHA-256, which is available in:

- All modern browsers
- Node.js ≥18
- Deno
- Bun
- Cloudflare Workers

## Specification

The verification algorithm is defined in the [AIIR Commit Receipt Specification](https://github.com/invariant-systems-ai/aiir/blob/main/SPEC.md) (§9 Verification Procedure).

## License

Apache-2.0 — [Invariant Systems, Inc.](https://invariantsystems.io)
