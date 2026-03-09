/**
 * AIIR Conformance Test Runner
 *
 * Loads test vectors from schemas/test_vectors.json and runs each through
 * the TypeScript verifier. Exits 0 if all pass, 1 otherwise.
 *
 * Usage:
 *   npm test
 *   # or after build:
 *   node dist/test/run-vectors.js
 *
 * Copyright 2025-2026 Invariant Systems, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyReceipt } from "../src/verify.js";

// ---------------------------------------------------------------------------
// Locate test vectors (relative to repo root)
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
// From dist/test/ → repo root is four levels up (dist/test → dist → ts-verifier → contrib → aiir)
const vectorsPath = resolve(__dirname, "..", "..", "..", "..", "schemas", "test_vectors.json");

interface TestVector {
  id: string;
  description: string;
  receipt: unknown;
  expected: {
    valid: boolean;
    errors: string[];
  };
}

interface TestVectorsFile {
  spec_version: string;
  vectors: TestVector[];
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

function main(): void {
  const raw = readFileSync(vectorsPath, "utf-8");
  const data: TestVectorsFile = JSON.parse(raw);

  console.log(
    `AIIR Conformance Test — spec ${data.spec_version} — ${data.vectors.length} vectors\n`
  );

  let pass = 0;
  let fail = 0;
  const failures: string[] = [];

  for (const tv of data.vectors) {
    const result = verifyReceipt(tv.receipt);

    // Check 1: valid boolean must match
    const validMatch = result.valid === tv.expected.valid;

    // Check 2: error list must contain all expected errors
    // (implementation may include additional diagnostic errors)
    const expectedErrors = new Set(tv.expected.errors);
    const actualErrors = new Set(result.errors);
    const missingErrors: string[] = [];
    for (const err of expectedErrors) {
      if (!actualErrors.has(err)) {
        missingErrors.push(err);
      }
    }

    const passed = validMatch && missingErrors.length === 0;

    if (passed) {
      pass++;
      console.log(`  ✅ ${tv.id}: ${tv.description}`);
    } else {
      fail++;
      let reason = "";
      if (!validMatch) {
        reason += `valid: expected=${tv.expected.valid} got=${result.valid}`;
      }
      if (missingErrors.length > 0) {
        if (reason) reason += "; ";
        reason += `missing errors: ${JSON.stringify(missingErrors)}`;
      }
      if (result.errors.length > 0 && validMatch) {
        reason += ` (got errors: ${JSON.stringify(result.errors)})`;
      }
      console.log(`  ❌ ${tv.id}: ${reason}`);
      console.log(`     ${tv.description}`);
      failures.push(`${tv.id}: ${reason}`);
    }
  }

  console.log(`\nResults: ${pass} pass, ${fail} fail out of ${data.vectors.length} vectors`);

  if (failures.length > 0) {
    console.log("\nFailures:");
    for (const f of failures) {
      console.log(`  ${f}`);
    }
    process.exit(1);
  } else {
    console.log("\n✅ All conformance vectors pass — implementation is AIIR-conformant.");
    process.exit(0);
  }
}

main();
