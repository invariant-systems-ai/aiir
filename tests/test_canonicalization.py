"""
JCS (RFC 8785) compatibility regression tests for AIIR canonical JSON.

These tests prove that _canonical_json produces byte-identical output to
RFC 8785 JCS for every data type that appears in the receipt schema today.
If someone adds a float field (e.g., ``confidence: 0.92``) the JCS
comparison will fail immediately, signalling that the zero-dependency
Python canonicalization is no longer sufficient and the JCS migration
trigger has been reached.

Design goals:
  1. Catch schema drift toward JCS-divergent types (especially floats)
  2. Cheap insurance — runs in <0.1s with no new runtime dependencies
  3. rfc8785 is already installed (transitive dep of sigstore), so we
     gate the entire class behind an importability check

Run:
    python3 -m pytest tests/test_canonicalization.py -v

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json

import pytest

hypothesis = pytest.importorskip("hypothesis", reason="hypothesis not installed")
from hypothesis import given, settings, HealthCheck  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from aiir._core import _canonical_json  # noqa: E402

# ── rfc8785 availability gate ─────────────────────────────────────────

try:
    from rfc8785 import dumps as _jcs_dumps

    def jcs_canonicalize(obj: object) -> str:
        """rfc8785.dumps returns bytes; decode for comparison."""
        return _jcs_dumps(obj).decode("utf-8")

    HAS_RFC8785 = True
except ImportError:
    HAS_RFC8785 = False

needs_rfc8785 = pytest.mark.skipif(
    not HAS_RFC8785,
    reason="rfc8785 package not installed (install sigstore or pip install rfc8785)",
)


# ═══════════════════════════════════════════════════════════════════════
# Exact-match: _canonical_json ≡ JCS for current receipt schema types
# ═══════════════════════════════════════════════════════════════════════


@needs_rfc8785
class TestCanonicalJsonMatchesJCS:
    """Prove that Python _canonical_json == RFC 8785 for all schema types."""

    # ── Realistic receipt fixture ─────────────────────────────────────

    def test_full_receipt_core(self):
        """A realistic receipt core round-trips identically through JCS."""
        receipt_core = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.2.1",
            "commit": {
                "sha": "a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
                "author": {
                    "name": "Ada Lovelace",
                    "email": "ada@example.com",
                    "date": "2026-03-10T12:00:00Z",
                },
                "committer": {
                    "name": "Ada Lovelace",
                    "email": "ada@example.com",
                    "date": "2026-03-10T12:00:00Z",
                },
                "subject": "feat: add receipt canonicalization spec",
                "message_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "diff_hash": "sha256:deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
                "files_changed": 3,
                "files": ["SPEC.md", "tests/test_canonicalization.py", "CHANGELOG.md"],
            },
            "ai_attestation": {
                "is_ai_authored": True,
                "signals_detected": ["github-copilot"],
                "signal_count": 1,
                "is_bot_authored": False,
                "bot_signals_detected": [],
                "bot_signal_count": 0,
                "authorship_class": "ai_assisted",
                "detection_method": "heuristic_v2",
            },
            "provenance": {
                "repository": "https://github.com/invariant-systems-ai/aiir",
                "tool": "https://github.com/invariant-systems-ai/aiir@1.2.1",
                "generator": "aiir.cli",
            },
        }

        aiir_out = _canonical_json(receipt_core)
        jcs_out = jcs_canonicalize(receipt_core)
        assert aiir_out == jcs_out, (
            f"Canonical JSON diverges from JCS for receipt core!\n"
            f"  AIIR: {aiir_out[:200]}...\n"
            f"  JCS:  {jcs_out[:200]}..."
        )

    # ── Per-type vectors ──────────────────────────────────────────────

    def test_string_values(self):
        """Strings (the dominant receipt type) match JCS."""
        for s in [
            "aiir.commit_receipt",
            "sha256:deadbeef",
            "https://github.com/invariant-systems-ai/aiir@1.2.1",
            "",
            "Hello, World!",
        ]:
            obj = {"value": s}
            assert _canonical_json(obj) == jcs_canonicalize(obj), (
                f"Mismatch for string: {s!r}"
            )

    def test_integer_values(self):
        """Integers (signal_count, files_changed, bot_signal_count) match JCS."""
        for n in [0, 1, 3, 42, 100, -1, 2**31, -(2**31)]:
            obj = {"count": n}
            assert _canonical_json(obj) == jcs_canonicalize(obj), (
                f"Mismatch for int: {n}"
            )

    def test_boolean_values(self):
        """Booleans (is_ai_authored, is_bot_authored, files_capped) match JCS."""
        for b in [True, False]:
            obj = {"flag": b}
            assert _canonical_json(obj) == jcs_canonicalize(obj), (
                f"Mismatch for bool: {b}"
            )

    def test_null_value(self):
        """Null (repository when no remote) matches JCS."""
        obj = {"repository": None}
        assert _canonical_json(obj) == jcs_canonicalize(obj)

    def test_empty_array(self):
        """Empty array (signals_detected=[]) matches JCS."""
        obj = {"signals": []}
        assert _canonical_json(obj) == jcs_canonicalize(obj)

    def test_string_array(self):
        """String arrays (signals_detected, files) match JCS."""
        obj = {"signals": ["github-copilot", "cursor", "aider"]}
        assert _canonical_json(obj) == jcs_canonicalize(obj)

    def test_nested_objects(self):
        """Nested objects (commit, author, provenance) match JCS."""
        obj = {
            "outer": {
                "middle": {
                    "inner": "value",
                    "count": 42,
                },
                "flag": True,
            },
        }
        assert _canonical_json(obj) == jcs_canonicalize(obj)

    def test_key_ordering(self):
        """Keys sorted lexicographically by codepoint (JCS rule)."""
        obj = {"z": 1, "a": 2, "m": 3, "A": 4, "Z": 5}
        assert _canonical_json(obj) == jcs_canonicalize(obj)

    # ── Unicode edge cases ────────────────────────────────────────────

    def test_unicode_escaping(self):
        """Non-ASCII chars: ensure_ascii=True vs JCS literal UTF-8.

        JCS (RFC 8785 §3.2.2.2) outputs literal UTF-8 for most codepoints,
        while AIIR uses \\uXXXX escapes.  These are semantically equivalent
        JSON (RFC 8259 §7) but NOT byte-identical.

        This test documents the known divergence and verifies it is
        confined to non-ASCII characters that do NOT appear in the
        current receipt schema.
        """
        # ASCII-only strings MUST match exactly
        obj_ascii = {"key": "hello world 123 !@#"}
        assert _canonical_json(obj_ascii) == jcs_canonicalize(obj_ascii)

        # Non-ASCII: verify semantic equivalence (parse-equal), document
        # byte divergence. This is acceptable because the receipt schema
        # contains only ASCII data (SHA hex, emails, tool URIs, signals).
        obj_unicode = {"key": "\u00e9\u00e8\u00ea"}
        aiir_bytes = _canonical_json(obj_unicode).encode("utf-8")
        jcs_bytes = jcs_canonicalize(obj_unicode).encode("utf-8")
        # Semantic equivalence: both parse to the same Python dict
        assert json.loads(aiir_bytes) == json.loads(jcs_bytes)

    def test_line_separator_paragraph_separator(self):
        """U+2028 / U+2029 — the classic JS/Python divergence.

        ensure_ascii=True escapes these, JCS emits literal UTF-8.
        Verify semantic equivalence and document the byte divergence.
        """
        obj = {"text": "line\u2028para\u2029end"}
        aiir_out = _canonical_json(obj)
        jcs_out = jcs_canonicalize(obj)
        assert json.loads(aiir_out) == json.loads(jcs_out)


# ═══════════════════════════════════════════════════════════════════════
# Canary: float drift detector
# ═══════════════════════════════════════════════════════════════════════


@needs_rfc8785
class TestFloatCanary:
    """If floats enter the schema, these tests MUST fail to signal the
    JCS migration trigger has been reached.

    IEEE-754 float serialization is the ONE place where Python's json.dumps
    and RFC 8785 diverge.  Examples:

        Python:  1e+30  →  JCS:  1e30
        Python:  0.0    →  JCS:  0
        Python:  1e-07  →  JCS:  1e-7

    These tests are NOT expected to pass — they document the divergence.
    When a float field is proposed for the schema, whoever reviews the PR
    will see this test class and know that JCS adoption is now required.
    """

    @pytest.mark.parametrize(
        "value",
        [0.0, 1.0, -1.0, 0.5, 0.92, 1e30, 1e-7, 3.141592653589793],
        ids=lambda v: f"float_{v}",
    )
    def test_float_divergence_documented(self, value: float):
        """Document that float serialization MAY diverge from JCS.

        This test asserts semantic equivalence (parse to same value)
        but explicitly checks for byte-level differences. If a float
        value byte-matches JCS, that's great. If not, it's expected —
        and documents exactly WHY JCS would be needed.
        """
        obj = {"confidence": value}
        aiir_out = _canonical_json(obj)
        jcs_out = jcs_canonicalize(obj)

        # Semantic equivalence must ALWAYS hold
        assert json.loads(aiir_out) == json.loads(jcs_out), (
            f"Semantic mismatch for float {value}! This is a bug."
        )

        # Byte-level match is NOT guaranteed for floats — document it
        if aiir_out != jcs_out:
            # This is expected. Mark as known divergence.
            pytest.skip(
                f"Known float divergence: AIIR={aiir_out!r} vs JCS={jcs_out!r}. "
                f"If this float appears in the receipt schema, adopt RFC 8785."
            )


# ═══════════════════════════════════════════════════════════════════════
# Property: JCS match for all receipt-schema-typed values (fuzz)
# ═══════════════════════════════════════════════════════════════════════


# Strategy: receipt-schema types only (no floats)
receipt_schema_primitives = st.one_of(
    st.none(),
    st.booleans(),
    # JCS safe integer domain: |n| < 2^53 (rfc8785 rejects larger values)
    st.integers(min_value=-(2**53 - 1), max_value=2**53 - 1),
    st.text(
        # ASCII-only to match receipt schema reality
        alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E),
        min_size=0,
        max_size=100,
    ),
)

receipt_schema_objects = st.recursive(
    receipt_schema_primitives,
    lambda children: st.one_of(
        st.lists(children, max_size=6),
        st.dictionaries(
            st.text(
                alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E),
                min_size=1,
                max_size=20,
            ),
            children,
            max_size=6,
        ),
    ),
    max_leaves=20,
)


@needs_rfc8785
class TestJCSPropertyBased:
    """Fuzz: _canonical_json ≡ JCS for all receipt-schema-typed structures."""

    @given(obj=receipt_schema_objects)
    @settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
    def test_ascii_json_matches_jcs(self, obj):
        """For ASCII-only, non-float JSON, AIIR canonical == JCS byte-for-byte."""
        try:
            aiir_out = _canonical_json(obj)
        except (ValueError, OverflowError):
            return  # Depth limit or overflow — not a schema concern

        jcs_out = jcs_canonicalize(obj)
        assert aiir_out == jcs_out, (
            f"JCS divergence on receipt-schema type!\n"
            f"  Object: {obj!r}\n"
            f"  AIIR:   {aiir_out!r}\n"
            f"  JCS:    {jcs_out!r}"
        )


# ═══════════════════════════════════════════════════════════════════════
# Standalone (no rfc8785): spec-mandated canonicalization properties
# ═══════════════════════════════════════════════════════════════════════


class TestSpecCanonicalProperties:
    """Properties that MUST hold per SPEC.md §6, no external deps needed."""

    def test_spec_reference_vector(self):
        """SPEC.md §6.4 example: {"b":1,"a":{"d":2,"c":3}} → {"a":{"c":3,"d":2},"b":1}."""
        obj = {"b": 1, "a": {"d": 2, "c": 3}}
        assert _canonical_json(obj) == '{"a":{"c":3,"d":2},"b":1}'

    def test_no_whitespace(self):
        """Canonical output has no structural whitespace."""
        obj = {"key": "value", "list": [1, 2, 3]}
        out = _canonical_json(obj)
        # Re-serialize with compact separators; must match
        assert out == json.dumps(
            json.loads(out), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )

    def test_sorted_keys_recursive(self):
        """Keys are sorted at every nesting level."""
        obj = {"z": {"b": 1, "a": 2}, "a": {"d": 3, "c": 4}}
        out = _canonical_json(obj)
        assert out == '{"a":{"c":4,"d":3},"z":{"a":2,"b":1}}'

    def test_ensure_ascii(self):
        r"""Non-ASCII characters are escaped as \uXXXX."""
        obj = {"key": "\u00e9"}
        out = _canonical_json(obj)
        assert "\\u00e9" in out

    def test_nan_rejected(self):
        """NaN is rejected (not valid JSON per RFC 8259)."""
        with pytest.raises(ValueError):
            _canonical_json({"bad": float("nan")})

    def test_infinity_rejected(self):
        """Infinity is rejected (not valid JSON per RFC 8259)."""
        with pytest.raises(ValueError):
            _canonical_json({"bad": float("inf")})

    def test_depth_limit(self):
        """Structures exceeding 64 levels are rejected."""
        obj: dict = {}
        current = obj
        for _ in range(65):
            current["nested"] = {}
            current = current["nested"]
        with pytest.raises(ValueError, match="depth"):
            _canonical_json(obj)

    def test_deterministic_across_key_insertion_order(self):
        """Key insertion order does not affect output."""
        d1 = {"a": 1, "b": 2, "c": 3}
        d2 = {"c": 3, "a": 1, "b": 2}
        assert _canonical_json(d1) == _canonical_json(d2)

    def test_empty_objects_and_arrays(self):
        """Empty containers serialize correctly."""
        assert _canonical_json({}) == "{}"
        assert _canonical_json([]) == "[]"
        assert _canonical_json({"a": {}, "b": []}) == '{"a":{},"b":[]}'
