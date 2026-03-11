"""Cross-language encoder interop vector tests.

Validates that the Python reference implementation produces the exact
canonical JSON, content_hash, and receipt_id specified in each vector.

These tests serve as the ground truth for any second implementation
(Node.js, Go, Rust, etc.) — if this test passes, the vectors are
authoritative.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aiir._core import _canonical_json, _sha256
from aiir._verify import verify_receipt

VECTORS_PATH = Path(__file__).parent / "encoder_interop_vectors.json"
CORE_KEYS = {"type", "schema", "version", "commit", "ai_attestation", "provenance"}


def _load_vectors():
    data = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    return [(v["id"], v) for v in data["vectors"]]


_VECTORS = _load_vectors()


@pytest.mark.parametrize(
    "vector_id,vector",
    _VECTORS,
    ids=[vid for vid, _ in _VECTORS],
)
def test_canonical_json_matches(vector_id, vector):
    """Canonical JSON output must match the vector's expected value exactly."""
    core = {k: v for k, v in vector["input_core"].items() if k in CORE_KEYS}
    actual = _canonical_json(core)
    assert actual == vector["expected"]["canonical_json"], (
        f"{vector_id}: canonical JSON mismatch"
    )


@pytest.mark.parametrize(
    "vector_id,vector",
    _VECTORS,
    ids=[vid for vid, _ in _VECTORS],
)
def test_content_hash_matches(vector_id, vector):
    """Content hash must match the vector's expected value exactly."""
    core = {k: v for k, v in vector["input_core"].items() if k in CORE_KEYS}
    cj = _canonical_json(core)
    actual_hash = f"sha256:{_sha256(cj)}"
    assert actual_hash == vector["expected"]["content_hash"], (
        f"{vector_id}: content_hash mismatch"
    )


@pytest.mark.parametrize(
    "vector_id,vector",
    _VECTORS,
    ids=[vid for vid, _ in _VECTORS],
)
def test_receipt_id_matches(vector_id, vector):
    """Receipt ID must match the vector's expected value exactly."""
    core = {k: v for k, v in vector["input_core"].items() if k in CORE_KEYS}
    cj = _canonical_json(core)
    h = _sha256(cj)
    actual_id = f"g1-{h[:32]}"
    assert actual_id == vector["expected"]["receipt_id"], (
        f"{vector_id}: receipt_id mismatch"
    )


@pytest.mark.parametrize(
    "vector_id,vector",
    _VECTORS,
    ids=[vid for vid, _ in _VECTORS],
)
def test_full_receipt_verifies(vector_id, vector):
    """Full receipt built from vector must pass verify_receipt."""
    result = verify_receipt(vector["full_receipt"])
    assert result["valid"], (
        f"{vector_id}: full receipt failed verification: {result.get('errors')}"
    )
