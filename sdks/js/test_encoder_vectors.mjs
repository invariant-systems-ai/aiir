// Quick cross-language encoder interop validation
// Run: node sdks/js/test_encoder_vectors.mjs

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { verify, canonicalJson, sha256 } = require('./aiir-verify.js');

import { readFileSync } from 'fs';
const vectors = JSON.parse(readFileSync(new URL('../../schemas/test-vectors/encoder_interop_vectors.json', import.meta.url), 'utf8'));

let pass = 0, fail = 0;
for (const v of vectors.vectors) {
  const core = v.input_core;
  const cj = canonicalJson(core);
  const hash = await sha256(cj);
  const contentHash = 'sha256:' + hash;
  const receiptId = 'g1-' + hash.slice(0, 32);

  const exp = v.expected;
  const cjMatch = cj === exp.canonical_json;
  const chMatch = contentHash === exp.content_hash;
  const idMatch = receiptId === exp.receipt_id;

  if (cjMatch && chMatch && idMatch) {
    pass++;
    console.log(`  PASS: ${v.id}`);
  } else {
    fail++;
    console.log(`  FAIL: ${v.id}`, { cjMatch, chMatch, idMatch });
    if (!cjMatch) {
      console.log('    expected:', exp.canonical_json.slice(0, 100));
      console.log('    got:     ', cj.slice(0, 100));
    }
  }
}
console.log(`\nEncoder vectors: ${pass}/${pass + fail} passed`);

// Also verify full receipts
let vpass = 0;
for (const v of vectors.vectors) {
  const result = await verify(v.full_receipt);
  if (result.valid) {
    vpass++;
  } else {
    console.log(`  verify FAIL: ${v.id}`, result.errors);
  }
}
console.log(`Full receipt verify: ${vpass}/${vectors.vectors.length} passed`);

if (fail > 0 || vpass < vectors.vectors.length) process.exit(1);
