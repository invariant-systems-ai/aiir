#!/usr/bin/env python3
"""AIIR Conformance Test Runner — validates any implementation against
the official test vectors.

Usage:
    python conformance.py                    # use bundled test vectors
    python conformance.py vectors.json       # use custom vector file
    python conformance.py --verify-only      # run verification-only vectors

Exit code 0 if all vectors pass, 1 otherwise.

This script is self-contained — it does NOT import the aiir package so
that it can be used to validate independent implementations. It
implements canonical JSON + SHA-256 + verification from SPEC.md §6–§9.

License: Apache-2.0
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from typing import Any

# ── Constants ──────────────────────────────────────────────────────────

CORE_KEYS = frozenset({"type", "schema", "version", "commit", "ai_attestation", "provenance"})
MAX_DEPTH = 64
VERSION_RE = r"^[0-9]+\.[0-9]+\.[0-9]+([.+\-][0-9a-zA-Z.+\-]*)?$"


# ── Canonical JSON (SPEC.md §6) ───────────────────────────────────────

def canonical_json(obj: Any, _depth: int = 0) -> str:
    """Produce canonical JSON per SPEC.md §6.

    - Sorted keys (recursive)
    - No whitespace
    - ASCII-safe (\\uXXXX for non-ASCII)
    - Depth limit: 64
    """
    if _depth > MAX_DEPTH:
        raise ValueError("canonical JSON depth limit exceeded (max 64)")

    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        if not (obj == obj) or obj == float("inf") or obj == float("-inf"):
            raise ValueError("NaN/Infinity not allowed in canonical JSON")
        return json.dumps(obj)
    if isinstance(obj, str):
        # json.dumps with ensure_ascii=True gives the right encoding
        return json.dumps(obj, ensure_ascii=True)
    if isinstance(obj, (list, tuple)):
        items = [canonical_json(v, _depth + 1) for v in obj]
        return "[" + ",".join(items) + "]"
    if isinstance(obj, dict):
        pairs = []
        for k in sorted(obj.keys()):
            pairs.append(
                json.dumps(k, ensure_ascii=True) + ":" + canonical_json(obj[k], _depth + 1)
            )
        return "{" + ",".join(pairs) + "}"
    raise TypeError(f"Cannot encode type {type(obj).__name__} to canonical JSON")


# ── Verification (SPEC.md §9) ─────────────────────────────────────────

def verify(receipt: Any) -> tuple[bool, list[str]]:
    """Verify an AIIR commit receipt. Returns (valid, errors)."""
    import re

    errors: list[str] = []

    # 1. Must be a dict
    if not isinstance(receipt, dict):
        return False, ["receipt is not a dict"]

    # 2. Type check
    if receipt.get("type") != "aiir.commit_receipt":
        return False, [f"unknown receipt type: {receipt.get('type')!r}"]

    # 3. Schema check
    schema = receipt.get("schema")
    if not isinstance(schema, str):
        return False, [f"unknown schema: {schema!r}"]
    if not schema.startswith("aiir/"):
        return False, [f"unknown schema: {schema!r}"]

    # 4. Version format
    version = receipt.get("version", "")
    if not isinstance(version, str) or not re.match(VERSION_RE, version):
        return False, [f"invalid version format: {version!r}"]

    # 5. Core extraction
    core = {k: v for k, v in receipt.items() if k in CORE_KEYS}

    # 6 + 7. Hash computation
    core_json = canonical_json(core)
    digest = hashlib.sha256(core_json.encode("utf-8")).hexdigest()
    expected_hash = f"sha256:{digest}"
    expected_id = f"g1-{digest[:32]}"

    # 8. Constant-time comparison (SPEC.md §9.2)
    actual_hash = receipt.get("content_hash", "")
    actual_id = receipt.get("receipt_id", "")

    if not hmac.compare_digest(expected_hash, actual_hash):
        errors.append("content hash mismatch")
    if not hmac.compare_digest(expected_id, actual_id):
        errors.append("receipt_id mismatch")

    return len(errors) == 0, errors


# ── Test runner ────────────────────────────────────────────────────────

def run_vectors(path: Path) -> tuple[int, int, list[str]]:
    """Run all test vectors from a JSON file. Returns (passed, total, failures)."""
    data = json.loads(path.read_text("utf-8"))
    vectors = data["vectors"]

    passed = 0
    failures: list[str] = []

    for vec in vectors:
        vid = vec["id"]
        receipt = vec["receipt"]
        expected_valid = vec["expected"]["valid"]
        expected_errors = set(vec["expected"]["errors"])

        valid, errors = verify(receipt)
        actual_errors = set(errors)

        if valid != expected_valid:
            failures.append(
                f"  {vid}: expected valid={expected_valid}, got valid={valid} "
                f"(errors={errors})"
            )
        elif not expected_valid and expected_errors and not expected_errors.issubset(actual_errors):
            missing = expected_errors - actual_errors
            failures.append(
                f"  {vid}: missing expected errors: {missing} "
                f"(got: {actual_errors})"
            )
        else:
            passed += 1

    return passed, len(vectors), failures


def main() -> int:
    # Find test vectors
    if len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
        vectors_path = Path(sys.argv[1])
    else:
        # Look for bundled vectors relative to script or repo root
        candidates = [
            Path(__file__).parent.parent / "schemas" / "test_vectors.json",
            Path(__file__).parent / "test_vectors.json",
            Path("schemas/test_vectors.json"),
        ]
        vectors_path = None
        for c in candidates:
            if c.exists():
                vectors_path = c
                break
        if vectors_path is None:
            print("ERROR: Cannot find test_vectors.json", file=sys.stderr)
            print("Usage: python conformance.py [path/to/test_vectors.json]", file=sys.stderr)
            return 1

    print(f"AIIR Conformance Test Runner")
    print(f"Vectors: {vectors_path}")
    print(f"{'─' * 60}")

    passed, total, failures = run_vectors(vectors_path)

    if failures:
        print(f"\n❌ FAILED ({passed}/{total} passed)\n")
        for f in failures:
            print(f)
        return 1
    else:
        print(f"\n✅ ALL {total} VECTORS PASSED")
        return 0


if __name__ == "__main__":
    sys.exit(main())
