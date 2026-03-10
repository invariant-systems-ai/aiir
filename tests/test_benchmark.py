"""Performance regression benchmarks for AIIR hot paths.

Copyright 2025-2026 Invariant Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

These benchmarks use pytest-benchmark to track performance of
security-critical functions. Run with:

    pytest tests/test_benchmark.py -v --benchmark-only

Or via nox:

    nox -s benchmark

Regressions are caught by comparing against stored baselines.
"""

from __future__ import annotations

import unittest
from typing import Any, Dict

import pytest

# Import guards — tests are skipped if pytest-benchmark is not installed.
try:
    import pytest_benchmark  # noqa: F401

    HAS_BENCHMARK = True
except ImportError:
    HAS_BENCHMARK = False

from aiir._core import (
    _canonical_json,
    _check_json_depth,
    _sanitize_md,
    _sha256,
    _strip_url_credentials,
)
from aiir._detect import detect_ai_signals
from aiir._schema import validate_receipt_schema
from aiir._verify import verify_receipt

pytestmark = pytest.mark.benchmark


# ── Fixtures ──────────────────────────────────────────────────────────


def _make_receipt(**overrides: Any) -> Dict[str, Any]:
    """Build a minimal valid receipt for benchmarking."""
    base = {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.0.0",
        "commit": {
            "sha": "a" * 40,
            "subject": "feat: add widget support",
            "author": "Alice <alice@example.com>",
            "committer": "Alice <alice@example.com>",
            "timestamp": "2026-01-15T10:30:00Z",
            "repository": "https://github.com/example/repo",
            "files": ["src/widget.py", "tests/test_widget.py"],
        },
        "ai_attestation": {
            "ai_assisted": True,
            "ai_tools": ["copilot"],
            "ai_percent_estimate": 30,
            "authorship_class": "human_led",
        },
        "provenance": {
            "generator": "aiir-cli",
            "generator_version": "1.2.1",
        },
    }
    base.update(overrides)
    # Build with proper hashing
    content = _canonical_json(
        {k: v for k, v in base.items() if k not in ("receipt_id", "content_hash")}
    )
    base["content_hash"] = "sha256:" + _sha256(content)
    base["receipt_id"] = "g1-" + _sha256(content)[:32]
    return base


SAMPLE_RECEIPT = _make_receipt()
LARGE_MARKDOWN = (
    "# Heading\n\n" + "This is a paragraph with **bold** and *italic* text.\n" * 500
)
NESTED_OBJ = {"a": {"b": {"c": {"d": {"e": "deep"}}}}}


# ── Benchmarks ────────────────────────────────────────────────────────


@pytest.mark.skipif(not HAS_BENCHMARK, reason="pytest-benchmark not installed")
class TestCanonicalJsonBenchmark:
    """Benchmark canonical JSON serialisation."""

    def test_small_object(self, benchmark: Any) -> None:
        obj = {"key": "value", "number": 42}
        benchmark(_canonical_json, obj)

    def test_receipt_sized_object(self, benchmark: Any) -> None:
        benchmark(_canonical_json, SAMPLE_RECEIPT)

    def test_large_nested_object(self, benchmark: Any) -> None:
        obj = {f"key_{i}": {"nested": f"value_{i}"} for i in range(100)}
        benchmark(_canonical_json, obj)


@pytest.mark.skipif(not HAS_BENCHMARK, reason="pytest-benchmark not installed")
class TestSha256Benchmark:
    """Benchmark SHA-256 hashing."""

    def test_short_string(self, benchmark: Any) -> None:
        benchmark(_sha256, "hello world")

    def test_receipt_content(self, benchmark: Any) -> None:
        content = _canonical_json(SAMPLE_RECEIPT)
        benchmark(_sha256, content)

    def test_large_content(self, benchmark: Any) -> None:
        content = "x" * 100_000
        benchmark(_sha256, content)


@pytest.mark.skipif(not HAS_BENCHMARK, reason="pytest-benchmark not installed")
class TestVerifyReceiptBenchmark:
    """Benchmark receipt verification (the hot path in CI)."""

    def test_valid_receipt(self, benchmark: Any) -> None:
        benchmark(verify_receipt, SAMPLE_RECEIPT)

    def test_invalid_receipt(self, benchmark: Any) -> None:
        tampered = dict(SAMPLE_RECEIPT)
        tampered["commit"] = dict(tampered["commit"])
        tampered["commit"]["subject"] = "tampered"
        benchmark(verify_receipt, tampered)


@pytest.mark.skipif(not HAS_BENCHMARK, reason="pytest-benchmark not installed")
class TestValidateReceiptBenchmark:
    """Benchmark schema validation."""

    def test_valid_receipt(self, benchmark: Any) -> None:
        benchmark(validate_receipt_schema, SAMPLE_RECEIPT)


@pytest.mark.skipif(not HAS_BENCHMARK, reason="pytest-benchmark not installed")
class TestDetectAiSignalsBenchmark:
    """Benchmark AI signal detection."""

    def test_clean_commit(self, benchmark: Any) -> None:
        benchmark(
            detect_ai_signals,
            "feat: add widget support",
            "Alice <alice@example.com>",
            "",
        )

    def test_ai_commit(self, benchmark: Any) -> None:
        benchmark(
            detect_ai_signals,
            "feat: add widget support\n\nCo-authored-by: Copilot",
            "Alice <alice@example.com>",
            "",
        )


@pytest.mark.skipif(not HAS_BENCHMARK, reason="pytest-benchmark not installed")
class TestSanitizeMdBenchmark:
    """Benchmark markdown sanitisation."""

    def test_short_text(self, benchmark: Any) -> None:
        benchmark(_sanitize_md, "Hello **world**")

    def test_large_document(self, benchmark: Any) -> None:
        benchmark(_sanitize_md, LARGE_MARKDOWN)


@pytest.mark.skipif(not HAS_BENCHMARK, reason="pytest-benchmark not installed")
class TestJsonDepthCheckBenchmark:
    """Benchmark JSON nesting depth check."""

    def test_shallow(self, benchmark: Any) -> None:
        benchmark(_check_json_depth, {"a": "b"})

    def test_moderately_nested(self, benchmark: Any) -> None:
        benchmark(_check_json_depth, NESTED_OBJ)


@pytest.mark.skipif(not HAS_BENCHMARK, reason="pytest-benchmark not installed")
class TestStripUrlCredentialsBenchmark:
    """Benchmark URL credential stripping."""

    def test_clean_url(self, benchmark: Any) -> None:
        benchmark(_strip_url_credentials, "https://github.com/org/repo.git")

    def test_url_with_credentials(self, benchmark: Any) -> None:
        benchmark(_strip_url_credentials, "https://user:token@github.com/org/repo.git")


# ── Non-benchmark regression sanity checks ────────────────────────────
# These always run (no pytest-benchmark required) to verify correctness.


class TestBenchmarkSanity(unittest.TestCase):
    """Sanity checks that benchmark subjects produce correct results."""

    def test_canonical_json_deterministic(self) -> None:
        a = _canonical_json({"b": 2, "a": 1})
        b = _canonical_json({"a": 1, "b": 2})
        self.assertEqual(a, b)

    def test_sha256_known_value(self) -> None:
        # SHA-256 of empty string
        self.assertEqual(
            _sha256(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_verify_receipt_valid(self) -> None:
        result = verify_receipt(SAMPLE_RECEIPT)
        self.assertTrue(result["valid"])

    def test_verify_receipt_tampered(self) -> None:
        tampered = dict(SAMPLE_RECEIPT)
        tampered["commit"] = dict(tampered["commit"])
        tampered["commit"]["subject"] = "tampered"
        result = verify_receipt(tampered)
        self.assertFalse(result["valid"])
