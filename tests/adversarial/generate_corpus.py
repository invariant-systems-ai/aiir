#!/usr/bin/env python3
"""Generate adversarial test fixtures for AIIR receipt verification.

Run from repo root:
    python tests/adversarial/generate_corpus.py

Outputs individual JSON fixtures into category subdirectories and
a corpus.json manifest.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import copy
import json
import os
import sys

# Add repo root to path for AIIR imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from aiir._core import _canonical_json, _sha256  # noqa: E402

CORPUS_DIR = os.path.dirname(__file__)

# ── Base valid receipt ──────────────────────────────────────────────
BASE_CORE = {
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
}


def _make_receipt(core_overrides=None):
    """Build a valid receipt with correct hashes from optional core overrides."""
    core = copy.deepcopy(BASE_CORE)
    if core_overrides:
        _deep_merge(core, core_overrides)
    cj = _canonical_json(core)
    h = _sha256(cj)
    return {
        **core,
        "receipt_id": f"g1-{h[:32]}",
        "content_hash": f"sha256:{h}",
        "timestamp": "2026-03-09T00:00:00Z",
        "extensions": {},
    }


def _deep_merge(base, override):
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


# ── Fixture definitions ────────────────────────────────────────────
FIXTURES = []


def _add(fixture_id, category, description, receipt, expected, spec_section="§7"):
    FIXTURES.append(
        {
            "id": fixture_id,
            "category": category,
            "description": description,
            "spec_section": spec_section,
            "receipt": receipt,
            "expected": expected,
        }
    )


def _reject(error_pattern=""):
    return {"valid": False, "must_reject": True, "error_pattern": error_pattern}


# ═══════════════════════════════════════════════════════════════════
# Category: injection — encoding & content injection attacks
# ═══════════════════════════════════════════════════════════════════

# INJ-001: HTML in version field
r = _make_receipt()
r["version"] = '<script>alert("xss")</script>'
_add(
    "adv-INJ-001",
    "injection",
    "HTML script tag in version field — MUST be rejected by version format regex",
    r,
    _reject("invalid version format"),
)

# INJ-002: Null byte in commit subject
r = _make_receipt({"commit": {"subject": "feat: normal\x00; rm -rf /"}})
r["content_hash"] = (
    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)
_add(
    "adv-INJ-002",
    "injection",
    "Null byte in commit subject — hash mismatch after sanitization",
    r,
    _reject("content hash mismatch"),
)

# INJ-003: Unicode bidi override in author name
r = _make_receipt(
    {
        "commit": {
            "author": {
                "name": "\u202eMalice\u202c",
                "email": "alice@example.com",
                "date": "2026-03-09T00:00:00Z",
            }
        }
    }
)
r["content_hash"] = (
    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)
_add(
    "adv-INJ-003",
    "injection",
    "Unicode bidi override (U+202E) in author name — visual spoofing attack",
    r,
    _reject("content hash mismatch"),
)

# INJ-004: CRLF injection in file path
r = _make_receipt({"commit": {"files": ["normal.py\r\nSet-Cookie: evil=1"]}})
r["content_hash"] = (
    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)
_add(
    "adv-INJ-004",
    "injection",
    "CRLF injection in file path — HTTP header injection vector",
    r,
    _reject("content hash mismatch"),
)

# INJ-005: SQL-like payload in schema field
r = _make_receipt()
r["schema"] = "aiir/commit_receipt.v1'; DROP TABLE receipts;--"
_add(
    "adv-INJ-005",
    "injection",
    "SQL injection payload in schema field — schema starts with aiir/ so passes prefix check, but hash mismatches",
    r,
    _reject("content hash mismatch"),
)

# INJ-006: Zero-width characters in authorship_class
r = _make_receipt({"ai_attestation": {"authorship_class": "hum\u200ban"}})
r["content_hash"] = (
    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)
_add(
    "adv-INJ-006",
    "injection",
    "Zero-width space in authorship_class — detection evasion via invisible chars",
    r,
    _reject("content hash mismatch"),
)

# INJ-007: Path traversal in files array
r = _make_receipt({"commit": {"files": ["../../../etc/passwd"]}})
r["content_hash"] = (
    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)
_add(
    "adv-INJ-007",
    "injection",
    "Path traversal in files array (../../etc/passwd)",
    r,
    _reject("content hash mismatch"),
)

# ═══════════════════════════════════════════════════════════════════
# Category: tampering — hash/id/field manipulation
# ═══════════════════════════════════════════════════════════════════

# TAM-001: Flip single bit in content_hash
r = _make_receipt()
h = r["content_hash"]
# Flip last hex char
flipped = h[:-1] + ("0" if h[-1] != "0" else "1")
r["content_hash"] = flipped
_add(
    "adv-TAM-001",
    "tampering",
    "Single bit flip in content_hash — MUST detect integrity violation",
    r,
    _reject("content hash mismatch"),
)

# TAM-002: Swap content_hash and receipt_id values
r = _make_receipt()
r["content_hash"], r["receipt_id"] = r["receipt_id"], r["content_hash"]
_add(
    "adv-TAM-002",
    "tampering",
    "Swap content_hash and receipt_id — both should fail validation",
    r,
    _reject("content hash mismatch"),
)

# TAM-003: Flip is_ai_authored without rehashing
r = _make_receipt()
r["ai_attestation"]["is_ai_authored"] = True  # was False
# Don't recompute hash — simulates post-generation tampering
_add(
    "adv-TAM-003",
    "tampering",
    "Flip is_ai_authored flag without rehashing — AI attestation tampering",
    r,
    _reject("content hash mismatch"),
)

# TAM-004: Change author email without rehashing
r = _make_receipt()
r["commit"]["author"]["email"] = "mallory@evil.com"
_add(
    "adv-TAM-004",
    "tampering",
    "Change author email without rehashing — provenance tampering",
    r,
    _reject("content hash mismatch"),
)

# TAM-005: Add extra core-like key to trick hash
r = _make_receipt()
r["type2"] = "aiir.commit_receipt"  # extra key outside allowlist
# Hash is still valid because extra keys are excluded from core
_add(
    "adv-TAM-005",
    "tampering",
    "Extra non-core key added — verifier MUST ignore extra keys in hash computation (valid receipt)",
    r,
    {"valid": True, "must_reject": False, "error_pattern": ""},
)

# TAM-006: Truncated content_hash
r = _make_receipt()
r["content_hash"] = r["content_hash"][:20]
_add(
    "adv-TAM-006",
    "tampering",
    "Truncated content_hash (20 chars) — MUST reject incomplete hash",
    r,
    _reject("content hash mismatch"),
)

# TAM-007: Empty content_hash
r = _make_receipt()
r["content_hash"] = ""
_add(
    "adv-TAM-007",
    "tampering",
    "Empty content_hash — MUST reject",
    r,
    _reject("content hash mismatch"),
)

# TAM-008: content_hash with wrong algorithm prefix
r = _make_receipt()
r["content_hash"] = "md5:" + r["content_hash"][7:]
_add(
    "adv-TAM-008",
    "tampering",
    "content_hash with md5: prefix — wrong algorithm, MUST reject",
    r,
    _reject("content hash mismatch"),
)

# ═══════════════════════════════════════════════════════════════════
# Category: parsing — structure & resource exhaustion
# ═══════════════════════════════════════════════════════════════════

# PAR-001: Receipt is a string, not a dict
_add(
    "adv-PAR-001",
    "parsing",
    "Receipt is a plain string, not a JSON object",
    "not a receipt",
    _reject("receipt is not a dict"),
)

# PAR-002: Receipt is null
_add(
    "adv-PAR-002",
    "parsing",
    "Receipt is JSON null",
    None,
    _reject("receipt is not a dict"),
)

# PAR-003: Receipt is an array
_add(
    "adv-PAR-003",
    "parsing",
    "Receipt is a JSON array",
    [1, 2, 3],
    _reject("receipt is not a dict"),
)

# PAR-004: Receipt is an integer
_add(
    "adv-PAR-004",
    "parsing",
    "Receipt is an integer",
    42,
    _reject("receipt is not a dict"),
)

# PAR-005: Deeply nested JSON (depth bomb) — extensions are excluded from core hash,
# so deeply nested extensions don't break integrity. The verifier should not crash.
r = _make_receipt()
nested = {"a": None}
current = nested
for _ in range(100):
    current["a"] = {"a": None}
    current = current["a"]
r["extensions"] = nested
_add(
    "adv-PAR-005",
    "parsing",
    "Deeply nested JSON (100 levels) in extensions — verifier must not crash; extensions excluded from hash so receipt is still valid",
    r,
    {"valid": True, "must_reject": False, "error_pattern": ""},
)

# PAR-006: Extremely long string field
r = _make_receipt({"commit": {"subject": "A" * 1_000_000}})
r["content_hash"] = (
    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)
_add(
    "adv-PAR-006",
    "parsing",
    "1 MB string in commit subject — resource exhaustion vector",
    r,
    _reject("content hash mismatch"),
)

# PAR-007: Empty receipt object
_add(
    "adv-PAR-007",
    "parsing",
    "Empty JSON object — no fields at all",
    {},
    _reject("unknown receipt type"),
)

# PAR-008: Missing all required fields except type
_add(
    "adv-PAR-008",
    "parsing",
    "Only type field present, all others missing",
    {"type": "aiir.commit_receipt"},
    _reject("unknown schema"),
)

# PAR-009: Version is a number, not a string
r = _make_receipt()
r["version"] = 1.0
_add(
    "adv-PAR-009",
    "parsing",
    "Version field is a float (1.0) instead of a string",
    r,
    _reject("invalid version format"),
)

# PAR-010: Schema field is an array
r = _make_receipt()
r["schema"] = ["aiir/commit_receipt.v1"]
_add(
    "adv-PAR-010",
    "parsing",
    "Schema field is an array instead of a string",
    r,
    _reject("unknown schema"),
)

# ═══════════════════════════════════════════════════════════════════
# Category: bypass — detection evasion & logic bypass
# ═══════════════════════════════════════════════════════════════════

# BYP-001: Correct hash but wrong type
r = _make_receipt()
r["type"] = "evil.commit_receipt"
# Recompute hash with wrong type
evil_core = copy.deepcopy(BASE_CORE)
evil_core["type"] = "evil.commit_receipt"
cj = _canonical_json(evil_core)
h = _sha256(cj)
r["content_hash"] = f"sha256:{h}"
r["receipt_id"] = f"g1-{h[:32]}"
_add(
    "adv-BYP-001",
    "bypass",
    "Receipt with valid hash but wrong type — type check MUST precede hash check",
    r,
    _reject("unknown receipt type"),
)

# BYP-002: Correct hash but wrong schema prefix
r = _make_receipt()
evil_core = copy.deepcopy(BASE_CORE)
evil_core["schema"] = "evil/commit_receipt.v1"
cj = _canonical_json(evil_core)
h = _sha256(cj)
r["type"] = "aiir.commit_receipt"
r["schema"] = "evil/commit_receipt.v1"
r["content_hash"] = f"sha256:{h}"
r["receipt_id"] = f"g1-{h[:32]}"
_add(
    "adv-BYP-002",
    "bypass",
    "Receipt with valid hash but non-aiir schema prefix — schema check MUST precede hash check",
    r,
    _reject("unknown schema"),
)

# BYP-003: Future schema version with valid hash
r = _make_receipt()
evil_core = copy.deepcopy(BASE_CORE)
evil_core["schema"] = "aiir/commit_receipt.v99"
cj = _canonical_json(evil_core)
h = _sha256(cj)
r["schema"] = "aiir/commit_receipt.v99"
r["content_hash"] = f"sha256:{h}"
r["receipt_id"] = f"g1-{h[:32]}"
_add(
    "adv-BYP-003",
    "bypass",
    "Future schema version (v99) with valid hash — implementers decide accept/reject policy",
    r,
    {"valid": True, "must_reject": False, "error_pattern": ""},
    spec_section="§4",
)

# BYP-004: Replay — valid receipt with duplicate receipt_id
r1 = _make_receipt()
r2 = copy.deepcopy(r1)
# Same receipt_id — replay detection is out of scope for verify but flagged
_add(
    "adv-BYP-004",
    "bypass",
    "Exact duplicate receipt (replay) — content-addressed so same id is expected; dedup is policy layer",
    r2,
    {"valid": True, "must_reject": False, "error_pattern": ""},
    spec_section="§7.3",
)

# BYP-005: Valid receipt with repository URL containing credentials
r = _make_receipt(
    {
        "provenance": {
            "repository": "https://token:x-oauth-basic@github.com/example/repo",
            "tool": "https://github.com/invariant-systems-ai/aiir@1.0.12",
            "generator": "aiir.cli",
        }
    }
)
# Hash computed over core including the credential-bearing URL
cj = _canonical_json(
    {
        k: v
        for k, v in r.items()
        if k in {"type", "schema", "version", "commit", "ai_attestation", "provenance"}
    }
)
h = _sha256(cj)
r["content_hash"] = f"sha256:{h}"
r["receipt_id"] = f"g1-{h[:32]}"
_add(
    "adv-BYP-005",
    "bypass",
    "Repository URL with embedded credentials — verifier should flag but receipt is structurally valid",
    r,
    {"valid": True, "must_reject": False, "error_pattern": ""},
    spec_section="§6.1",
)

# BYP-006: Timestamp in the future
r = _make_receipt()
r["timestamp"] = "2099-12-31T23:59:59Z"
_add(
    "adv-BYP-006",
    "bypass",
    "Timestamp far in the future (2099) — structural integrity valid, policy layer should flag",
    r,
    {"valid": True, "must_reject": False, "error_pattern": ""},
    spec_section="§7.3",
)

# BYP-007: receipt_id has correct prefix but wrong hash
r = _make_receipt()
r["receipt_id"] = "g1-00000000000000000000000000000000"
_add(
    "adv-BYP-007",
    "bypass",
    "receipt_id with correct g1- prefix but wrong hash — MUST be rejected",
    r,
    _reject("receipt_id mismatch"),
)


# ═══════════════════════════════════════════════════════════════════
# Generate output
# ═══════════════════════════════════════════════════════════════════


def main():
    categories = {}
    manifest = []
    for f in FIXTURES:
        cat = f["category"]
        categories.setdefault(cat, [])
        categories[cat].append(f)
        manifest.append(
            {
                "id": f["id"],
                "category": f["category"],
                "description": f["description"],
                "file": f"tests/adversarial/{cat}/{f['id']}.json",
            }
        )

    # Write category subdirectories
    for cat, fixtures in categories.items():
        cat_dir = os.path.join(CORPUS_DIR, cat)
        os.makedirs(cat_dir, exist_ok=True)
        for f in fixtures:
            filepath = os.path.join(cat_dir, f"{f['id']}.json")
            with open(filepath, "w", encoding="utf-8") as fp:
                json.dump(f, fp, indent=2, ensure_ascii=False)
                fp.write("\n")

    # Write manifest
    manifest_path = os.path.join(CORPUS_DIR, "corpus.json")
    corpus = {
        "description": "AIIR adversarial test corpus — machine-readable fixture manifest",
        "spec_version": "1.1.0",
        "generated_by": "tests/adversarial/generate_corpus.py",
        "categories": sorted(categories.keys()),
        "total_fixtures": len(FIXTURES),
        "fixtures": manifest,
    }
    with open(manifest_path, "w", encoding="utf-8") as fp:
        json.dump(corpus, fp, indent=2, ensure_ascii=False)
        fp.write("\n")

    print(
        f"Generated {len(FIXTURES)} adversarial fixtures in {len(categories)} categories"
    )
    for cat in sorted(categories):
        print(f"  {cat}: {len(categories[cat])} fixtures")


if __name__ == "__main__":
    main()
