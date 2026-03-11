#!/usr/bin/env python3
"""Generate cross-language encoder interop test vectors.

These test vectors define deterministic input → output mappings for:
1. Canonical JSON serialization (sorted keys, no whitespace)
2. SHA-256 content hash computation
3. Receipt ID derivation (g1- prefix + first 32 hex chars)
4. CBOR deterministic encoding

Any conforming implementation in any language MUST produce identical
outputs for each vector's input.

Run from repo root:
    python schemas/test-vectors/generate_encoder_vectors.py

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from aiir._core import _canonical_json, _sha256  # noqa: E402

try:
    from aiir._receipt import _canonical_receipt_cbor_bytes  # noqa: E402

    HAS_CBOR = True
except ImportError:
    HAS_CBOR = False

OUTPUT_DIR = os.path.dirname(__file__)

# CORE_KEYS must match the verifier's allowlist
CORE_KEYS = {"type", "schema", "version", "commit", "ai_attestation", "provenance"}


def _compute(core: dict) -> dict:
    """Compute canonical JSON, content_hash, receipt_id for a core dict."""
    cj = _canonical_json(core)
    h = _sha256(cj)
    return {
        "canonical_json": cj,
        "canonical_json_sha256": h,
        "content_hash": f"sha256:{h}",
        "receipt_id": f"g1-{h[:32]}",
    }


def _full_receipt(core: dict, computed: dict) -> dict:
    """Build a complete receipt from core + computed values."""
    return {
        **core,
        "receipt_id": computed["receipt_id"],
        "content_hash": computed["content_hash"],
        "timestamp": "2026-03-11T00:00:00Z",
        "extensions": {},
    }


# ── Vector definitions ─────────────────────────────────────────────
VECTORS = []


def _add_vector(vector_id, description, core, notes=""):
    computed = _compute(core)
    receipt = _full_receipt(core, computed)

    vec = {
        "id": vector_id,
        "description": description,
        "input_core": core,
        "expected": computed,
        "full_receipt": receipt,
    }
    if notes:
        vec["implementation_notes"] = notes

    # Add CBOR encoding if available
    if HAS_CBOR:
        try:
            cbor_bytes = _canonical_receipt_cbor_bytes(receipt)
            vec["expected"]["cbor_hex"] = cbor_bytes.hex()
            vec["expected"]["cbor_sha256"] = hashlib.sha256(cbor_bytes).hexdigest()
            vec["expected"]["cbor_length"] = len(cbor_bytes)
        except Exception:
            pass

    VECTORS.append(vec)


# ── V1: Minimal valid receipt (human, no AI) ──────────────────────
_add_vector(
    "enc-01-minimal-human",
    "Minimal valid receipt — human-authored, single file, no extensions",
    {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.0.12",
        "commit": {
            "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "author": {
                "name": "Alice",
                "email": "alice@example.com",
                "date": "2026-03-09T00:00:00Z",
            },
            "committer": {
                "name": "Alice",
                "email": "alice@example.com",
                "date": "2026-03-09T00:00:00Z",
            },
            "subject": "feat: add widget",
            "message_hash": "sha256:375aca2c5a71c7ffaaa0c3602ed0f82d27986ce0776b5c5c1bc2d2a5638b18bb",
            "diff_hash": "sha256:a9b7bc7b29f22a8b1ae213c4105d73c39b9e3f218d75bb6a288207c1d86b96fe",
            "files_changed": 1,
            "files": ["widget.py"],
        },
        "ai_attestation": {
            "is_ai_authored": False,
            "signals_detected": [],
            "signal_count": 0,
            "is_bot_authored": False,
            "bot_signals_detected": [],
            "bot_signal_count": 0,
            "authorship_class": "human",
            "detection_method": "heuristic_v2",
        },
        "provenance": {
            "repository": "https://github.com/example/repo",
            "tool": "https://github.com/invariant-systems-ai/aiir@1.0.12",
            "generator": "aiir.cli",
        },
    },
)

# ── V2: AI-assisted commit with signals ───────────────────────────
_add_vector(
    "enc-02-ai-assisted",
    "AI-assisted commit — Copilot co-author signal detected",
    {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.0.12",
        "commit": {
            "sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "author": {
                "name": "Bob",
                "email": "bob@example.com",
                "date": "2026-03-10T12:34:56Z",
            },
            "committer": {
                "name": "Bob",
                "email": "bob@example.com",
                "date": "2026-03-10T12:34:56Z",
            },
            "subject": "feat: add copilot-generated parser",
            "message_hash": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "diff_hash": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "files_changed": 3,
            "files": ["parser.py", "tests/test_parser.py", "README.md"],
        },
        "ai_attestation": {
            "is_ai_authored": True,
            "signals_detected": ["co-author: GitHub Copilot"],
            "signal_count": 1,
            "is_bot_authored": False,
            "bot_signals_detected": [],
            "bot_signal_count": 0,
            "authorship_class": "ai_assisted",
            "detection_method": "heuristic_v2",
        },
        "provenance": {
            "repository": "https://github.com/example/repo",
            "tool": "https://github.com/invariant-systems-ai/aiir@1.0.12",
            "generator": "aiir.cli",
        },
    },
)

# ── V3: Unicode in all string fields ──────────────────────────────
_add_vector(
    "enc-03-unicode-fields",
    "Unicode characters in all string fields — tests canonical JSON ensure_ascii=True encoding",
    {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.0.12",
        "commit": {
            "sha": "cccccccccccccccccccccccccccccccccccccccc",
            "author": {
                "name": "\u00c9milie Dupont-L\u00e9ger",
                "email": "emilie@example.com",
                "date": "2026-03-11T00:00:00Z",
            },
            "committer": {
                "name": "\u00c9milie Dupont-L\u00e9ger",
                "email": "emilie@example.com",
                "date": "2026-03-11T00:00:00Z",
            },
            "subject": "feat: ajouter widget \u2014 premi\u00e8re version",
            "message_hash": "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "diff_hash": "sha256:cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
            "files_changed": 2,
            "files": ["src/\u00e9diteur.py", "docs/LISEZMOI.md"],
        },
        "ai_attestation": {
            "is_ai_authored": False,
            "signals_detected": [],
            "signal_count": 0,
            "is_bot_authored": False,
            "bot_signals_detected": [],
            "bot_signal_count": 0,
            "authorship_class": "human",
            "detection_method": "heuristic_v2",
        },
        "provenance": {
            "repository": "https://github.com/example/repo",
            "tool": "https://github.com/invariant-systems-ai/aiir@1.0.12",
            "generator": "aiir.cli",
        },
    },
    notes="ensure_ascii=True means non-ASCII chars become \\uXXXX escapes. All conforming implementations MUST use the same escaping.",
)

# ── V4: Empty files array (files_redacted) ────────────────────────
_add_vector(
    "enc-04-redacted-files",
    "Receipt with files_redacted=true and empty files array — tests empty array encoding",
    {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.0.12",
        "commit": {
            "sha": "dddddddddddddddddddddddddddddddddddddd",
            "author": {
                "name": "Charlie",
                "email": "charlie@example.com",
                "date": "2026-03-09T00:00:00Z",
            },
            "committer": {
                "name": "Charlie",
                "email": "charlie@example.com",
                "date": "2026-03-09T00:00:00Z",
            },
            "subject": "chore: redacted commit",
            "message_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "diff_hash": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "files_changed": 5,
            "files": [],
            "files_redacted": True,
        },
        "ai_attestation": {
            "is_ai_authored": False,
            "signals_detected": [],
            "signal_count": 0,
            "is_bot_authored": False,
            "bot_signals_detected": [],
            "bot_signal_count": 0,
            "authorship_class": "human",
            "detection_method": "heuristic_v2",
        },
        "provenance": {
            "repository": None,
            "tool": "https://github.com/invariant-systems-ai/aiir@1.0.12",
            "generator": "aiir.cli",
        },
    },
    notes="null repository and empty files array - tests JSON null encoding and empty array handling",
)

# ── V5: Boolean edge cases ────────────────────────────────────────
_add_vector(
    "enc-05-boolean-encoding",
    "Both AI and bot flags true — tests JSON boolean encoding across languages",
    {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.0.12",
        "commit": {
            "sha": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "author": {
                "name": "dependabot[bot]",
                "email": "49699333+dependabot[bot]@users.noreply.github.com",
                "date": "2026-03-09T00:00:00Z",
            },
            "committer": {
                "name": "GitHub",
                "email": "noreply@github.com",
                "date": "2026-03-09T00:00:00Z",
            },
            "subject": "chore(deps): bump requests from 2.31.0 to 2.32.0",
            "message_hash": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "diff_hash": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            "files_changed": 2,
            "files": ["requirements.txt", "requirements-dev.txt"],
        },
        "ai_attestation": {
            "is_ai_authored": True,
            "signals_detected": ["co-author: GitHub Copilot"],
            "signal_count": 1,
            "is_bot_authored": True,
            "bot_signals_detected": ["author: dependabot[bot]"],
            "bot_signal_count": 1,
            "authorship_class": "ai_and_bot",
            "detection_method": "heuristic_v2",
        },
        "provenance": {
            "repository": "https://github.com/example/repo",
            "tool": "https://github.com/invariant-systems-ai/aiir@1.0.12",
            "generator": "aiir.cli",
        },
    },
    notes="JSON booleans: Python True/False, JS true/false, Go true/false. All MUST serialize as lowercase true/false.",
)

# ── V6: Large files array (boundary test) ─────────────────────────
files_100 = [f"src/file_{i:03d}.py" for i in range(100)]
_add_vector(
    "enc-06-max-files",
    "Receipt with exactly 100 files (CDDL max) — boundary test for array encoding",
    {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.0.12",
        "commit": {
            "sha": "ffffffffffffffffffffffffffffffffffffffff",
            "author": {
                "name": "Alice",
                "email": "alice@example.com",
                "date": "2026-03-09T00:00:00Z",
            },
            "committer": {
                "name": "Alice",
                "email": "alice@example.com",
                "date": "2026-03-09T00:00:00Z",
            },
            "subject": "refactor: massive rename",
            "message_hash": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
            "diff_hash": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
            "files_changed": 100,
            "files": files_100,
            "files_capped": True,
        },
        "ai_attestation": {
            "is_ai_authored": False,
            "signals_detected": [],
            "signal_count": 0,
            "is_bot_authored": False,
            "bot_signals_detected": [],
            "bot_signal_count": 0,
            "authorship_class": "human",
            "detection_method": "heuristic_v2",
        },
        "provenance": {
            "repository": "https://github.com/example/repo",
            "tool": "https://github.com/invariant-systems-ai/aiir@1.0.12",
            "generator": "aiir.cli",
        },
    },
    notes="100 files is the CDDL maximum per receipt.cddl. Tests array serialization with many elements.",
)

# ── V7: Key ordering test ─────────────────────────────────────────
# Specifically tests that canonical JSON sorts keys deterministically
# even when they are inserted in different orders
core_v7 = {
    "version": "1.0.12",  # deliberately out of alphabetical order
    "type": "aiir.commit_receipt",
    "provenance": {
        "tool": "https://github.com/invariant-systems-ai/aiir@1.0.12",
        "repository": "https://github.com/example/repo",
        "generator": "aiir.cli",
    },
    "schema": "aiir/commit_receipt.v1",
    "ai_attestation": {
        "signal_count": 0,
        "is_ai_authored": False,
        "authorship_class": "human",
        "signals_detected": [],
        "detection_method": "heuristic_v2",
        "is_bot_authored": False,
        "bot_signals_detected": [],
        "bot_signal_count": 0,
    },
    "commit": {
        "files": ["main.go"],
        "sha": "1111111111111111111111111111111111111111",
        "subject": "init: go module",
        "files_changed": 1,
        "author": {
            "email": "dev@example.com",
            "date": "2026-03-09T00:00:00Z",
            "name": "Dev",
        },
        "committer": {
            "email": "dev@example.com",
            "date": "2026-03-09T00:00:00Z",
            "name": "Dev",
        },
        "message_hash": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
        "diff_hash": "sha256:8888888888888888888888888888888888888888888888888888888888888888",
    },
}
_add_vector(
    "enc-07-key-ordering",
    "Keys deliberately out of alphabetical order — tests that canonical JSON always sorts keys recursively",
    core_v7,
    notes="Canonical JSON MUST use sort_keys=True (Python) or equivalent. Key order in source MUST NOT affect output.",
)

# ── V8: Numeric field encoding ─────────────────────────────────────
_add_vector(
    "enc-08-numeric-fields",
    "Receipt with zero-valued numeric fields — tests integer 0 encoding (not false, not null)",
    {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.0.12",
        "commit": {
            "sha": "2222222222222222222222222222222222222222",
            "author": {
                "name": "Alice",
                "email": "alice@example.com",
                "date": "2026-03-09T00:00:00Z",
            },
            "committer": {
                "name": "Alice",
                "email": "alice@example.com",
                "date": "2026-03-09T00:00:00Z",
            },
            "subject": "chore: empty commit",
            "message_hash": "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            "diff_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "files_changed": 0,
            "files": [],
        },
        "ai_attestation": {
            "is_ai_authored": False,
            "signals_detected": [],
            "signal_count": 0,
            "is_bot_authored": False,
            "bot_signals_detected": [],
            "bot_signal_count": 0,
            "authorship_class": "human",
            "detection_method": "heuristic_v2",
        },
        "provenance": {
            "repository": "https://github.com/example/repo",
            "tool": "https://github.com/invariant-systems-ai/aiir@1.0.12",
            "generator": "aiir.cli",
        },
    },
    notes="Integer 0 must encode as 0, not false or null. In JS: JSON.stringify(0) === '0', not 'false'.",
)


# ═══════════════════════════════════════════════════════════════════
# Generate output
# ═══════════════════════════════════════════════════════════════════

def main():
    output = {
        "$schema": "https://invariantsystems.io/schemas/aiir/encoder_test_vectors.v1.json",
        "description": "Cross-language encoder interop test vectors for AIIR commit receipt. Any conforming implementation MUST produce identical canonical_json, content_hash, and receipt_id for each vector's input_core.",
        "spec_version": "1.1.0",
        "canonical_json_rules": {
            "sort_keys": True,
            "separators": [",", ":"],
            "ensure_ascii": True,
            "allow_nan": False,
            "depth_limit": 64,
        },
        "hash_algorithm": "SHA-256",
        "receipt_id_format": "g1-{first_32_hex_of_content_hash}",
        "generated_by": "schemas/test-vectors/generate_encoder_vectors.py",
        "generated_at": "2026-03-11T00:00:00Z",
        "vectors": VECTORS,
    }

    outpath = os.path.join(OUTPUT_DIR, "encoder_interop_vectors.json")
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=True)
        f.write("\n")

    print(f"Generated {len(VECTORS)} encoder interop vectors → {outpath}")
    for v in VECTORS:
        ch = v["expected"]["content_hash"][:30] + "..."
        print(f"  {v['id']}: {ch}")


if __name__ == "__main__":
    main()
