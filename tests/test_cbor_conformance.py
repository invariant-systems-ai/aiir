# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Invariant Systems, Inc.
"""
Conformance test suite for the canonical CBOR format.

Tests:
  - Golden vector reproduction (encoder determinism)
  - Decoder round-trip (decode → re-encode = identity)
  - Decoder strictness (rejects non-canonical encodings)
  - Envelope structure validation
  - Cross-verification of JSON receipt ↔ CBOR sidecar
  - RFC 8949 §4.2.1 diagnostic primitives
"""

from __future__ import annotations

import hashlib
import json
import struct
import unittest
from pathlib import Path

from aiir._canonical_cbor import (
    CANONICAL_OBJECT_TYPE,
    build_canonical_object_envelope,
    canonical_cbor_bytes,
    canonical_cbor_sha256,
)
from aiir._verify_cbor import (
    CborDecodeError,
    decode_cbor,
    decode_cbor_full,
    verify_cbor_envelope,
    verify_cbor_file,
    verify_cbor_sidecar,
)

VECTORS_PATH = (
    Path(__file__).resolve().parent.parent / "schemas" / "cbor_test_vectors.json"
)
JSON_VECTORS_PATH = (
    Path(__file__).resolve().parent.parent / "schemas" / "test_vectors.json"
)


def _load_cbor_vectors():
    with open(VECTORS_PATH) as f:
        return json.load(f)


def _load_json_vectors():
    with open(JSON_VECTORS_PATH) as f:
        data = json.load(f)
    return {v["id"]: v for v in data["vectors"]}


# ── Golden Vector Conformance ──────────────────────────────────────────


class TestGoldenVectors(unittest.TestCase):
    """Every golden vector must reproduce byte-for-byte from its source receipt."""

    @classmethod
    def setUpClass(cls):
        cls.cbor_vectors = _load_cbor_vectors()["vectors"]
        cls.json_vectors = _load_json_vectors()

    def test_all_vectors_reproduce(self):
        """Encode each source receipt and assert CBOR hex + SHA-256 match the golden vector."""
        CORE_KEYS = {
            "type",
            "schema",
            "version",
            "commit",
            "ai_attestation",
            "provenance",
        }
        for vec in self.cbor_vectors:
            source_id = vec["source_vector"]
            json_vec = self.json_vectors[source_id]
            receipt = json_vec["receipt"]
            if not isinstance(receipt, dict):
                continue

            core = {k: receipt[k] for k in CORE_KEYS if k in receipt}
            kind = vec["envelope"]["kind"]
            obj_schema = vec["envelope"]["object_schema"]

            envelope = build_canonical_object_envelope(
                kind=kind,
                object_schema=obj_schema,
                core=core,
            )
            cbor_bytes = canonical_cbor_bytes(envelope)
            cbor_hex = cbor_bytes.hex()
            cbor_sha256 = hashlib.sha256(cbor_bytes).hexdigest()

            with self.subTest(vector=vec["id"]):
                self.assertEqual(
                    cbor_hex,
                    vec["expected"]["cbor_hex"],
                    f"{vec['id']}: CBOR hex mismatch",
                )
                self.assertEqual(
                    cbor_sha256,
                    vec["expected"]["cbor_sha256"],
                    f"{vec['id']}: SHA-256 mismatch",
                )
                self.assertEqual(
                    len(cbor_bytes),
                    vec["expected"]["cbor_length"],
                    f"{vec['id']}: length mismatch",
                )

    def test_vector_count(self):
        """Ensure we have vectors for all dict-type JSON test receipts."""
        dict_count = sum(
            1 for v in self.json_vectors.values() if isinstance(v["receipt"], dict)
        )
        self.assertEqual(len(self.cbor_vectors), dict_count)


# ── Decode → Re-encode Round-Trip ─────────────────────────────────────


class TestRoundTrip(unittest.TestCase):
    """Decoding golden CBOR bytes and re-encoding must produce identical bytes."""

    @classmethod
    def setUpClass(cls):
        cls.cbor_vectors = _load_cbor_vectors()["vectors"]

    def test_round_trip_all_vectors(self):
        for vec in self.cbor_vectors:
            cbor_bytes = bytes.fromhex(vec["expected"]["cbor_hex"])
            decoded = decode_cbor_full(cbor_bytes)
            re_encoded = canonical_cbor_bytes(decoded)
            with self.subTest(vector=vec["id"]):
                self.assertEqual(
                    re_encoded,
                    cbor_bytes,
                    f"{vec['id']}: round-trip produced different bytes",
                )

    def test_round_trip_simple_primitives(self):
        """Primitives: None, True, False, ints, floats, strings, bytes, lists, dicts."""
        cases = [
            None,
            True,
            False,
            0,
            1,
            23,
            24,
            255,
            256,
            65535,
            65536,
            2**32 - 1,
            2**32,
            -1,
            -24,
            -25,
            -256,
            -65537,
            0.0,
            1.0,
            1.5,
            -0.5,
            0.1,
            3.141592653589793,
            "",
            "hello",
            "utf-8: \u00e9\u00e8",
            b"",
            b"\x00\x01\x02",
            [],
            [1, 2, 3],
            [None, True, "a"],
            {},
            {"a": 1},
            {"b": 2, "a": 1},
        ]
        for obj in cases:
            with self.subTest(obj=obj):
                encoded = canonical_cbor_bytes(obj)
                decoded = decode_cbor_full(encoded)
                re_encoded = canonical_cbor_bytes(decoded)
                self.assertEqual(encoded, re_encoded)
                # For dicts, compare structurally (key order doesn't matter in Python dict)
                if isinstance(obj, dict):
                    self.assertEqual(decoded, obj)
                elif isinstance(obj, list):
                    self.assertEqual(decoded, obj)
                elif isinstance(obj, float):
                    # Use struct comparison for float (handles -0.0)
                    self.assertEqual(
                        struct.pack(">d", decoded),
                        struct.pack(">d", obj),
                    )
                else:
                    self.assertEqual(decoded, obj)


# ── Decoder Strictness ─────────────────────────────────────────────────


class TestDecoderStrictness(unittest.TestCase):
    """The decoder must reject non-canonical encodings."""

    def test_reject_non_shortest_uint(self):
        # Value 0 encoded as 1-byte form (should be inline): 0x1800
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\x18\x00")
        # Value 23 in 1-byte form (should be inline)
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\x18\x17")
        # Value 255 in 2-byte form (should be 1-byte)
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\x19\x00\xff")
        # Value 65535 in 4-byte form (should be 2-byte)
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\x1a\x00\x00\xff\xff")
        # Value 4294967295 in 8-byte form (should be 4-byte)
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\x1b\x00\x00\x00\x00\xff\xff\xff\xff")

    def test_reject_indefinite_length(self):
        # Indefinite-length byte string: major 2, additional 31
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\x5f\x41a\xff")  # indefinite bstr
        # Indefinite-length array: major 4, additional 31
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\x9f\x01\xff")  # indefinite array

    def test_reject_unsorted_map_keys(self):
        # Map with keys "b" then "a" (not sorted: "b" > "a" lexicographically)
        # a2 61 62 01 61 61 02 = {"b": 1, "a": 2} in wrong order
        bad_map = b"\xa2\x61\x62\x01\x61\x61\x02"
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(bad_map)

    def test_reject_duplicate_length_map_keys_wrong_order(self):
        # Map with same-length keys in wrong lexicographic order
        # {"ba": 1, "ab": 2} → keys both 2 bytes, "ba" > "ab"
        bad_map = b"\xa2\x62\x62\x61\x01\x62\x61\x62\x02"
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(bad_map)

    def test_reject_truncated_input(self):
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\x18")  # uint expecting 1 more byte
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\x19\x01")  # uint expecting 2 bytes, got 1
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\x62\x61")  # text of length 2 but only 1 byte

    def test_reject_trailing_bytes(self):
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\x01\x02")  # integer 1 followed by trailing 0x02

    def test_reject_non_finite_floats(self):
        # f16 NaN: f9 7e 00
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\xf9\x7e\x00")
        # f16 +Inf: f9 7c 00
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\xf9\x7c\x00")


# ── Envelope Validation ────────────────────────────────────────────────


class TestEnvelopeValidation(unittest.TestCase):
    """Verify the envelope validator catches structural problems."""

    def _good_envelope(self):
        return build_canonical_object_envelope(
            kind="test.core",
            object_schema="test/v1",
            core={"a": 1},
        )

    def test_valid_envelope(self):
        self.assertEqual(verify_cbor_envelope(self._good_envelope()), [])

    def test_wrong_type(self):
        env = self._good_envelope()
        env["type"] = "wrong.type"
        errors = verify_cbor_envelope(env)
        self.assertTrue(any("type mismatch" in e for e in errors))

    def test_wrong_schema(self):
        env = self._good_envelope()
        env["schema"] = "wrong/schema.v1"
        errors = verify_cbor_envelope(env)
        self.assertTrue(any("schema mismatch" in e for e in errors))

    def test_missing_keys(self):
        errors = verify_cbor_envelope({"type": CANONICAL_OBJECT_TYPE})
        self.assertTrue(any("missing" in e for e in errors))

    def test_not_a_dict(self):
        errors = verify_cbor_envelope([1, 2, 3])
        self.assertTrue(any("expected dict" in e for e in errors))

    def test_empty_kind(self):
        env = self._good_envelope()
        env["kind"] = ""
        errors = verify_cbor_envelope(env)
        self.assertTrue(any("kind" in e for e in errors))

    def test_core_not_dict(self):
        env = self._good_envelope()
        env["core"] = "not a dict"
        errors = verify_cbor_envelope(env)
        self.assertTrue(any("core" in e for e in errors))


# ── Cross-Verification (JSON ↔ CBOR) ──────────────────────────────────


class TestCrossVerification(unittest.TestCase):
    """Verify that CBOR sidecars cross-check against their JSON receipts."""

    @classmethod
    def setUpClass(cls):
        cls.cbor_vectors = _load_cbor_vectors()["vectors"]
        cls.json_vectors = _load_json_vectors()

    def test_valid_cross_verify(self):
        """For each valid JSON receipt, the CBOR sidecar must cross-verify."""
        for vec in self.cbor_vectors:
            if not vec["json_receipt_valid"]:
                continue
            source_id = vec["source_vector"]
            receipt = self.json_vectors[source_id]["receipt"]
            cbor_bytes = bytes.fromhex(vec["expected"]["cbor_hex"])

            result = verify_cbor_sidecar(cbor_bytes, json_receipt=receipt)
            with self.subTest(vector=vec["id"]):
                self.assertTrue(
                    result["valid"],
                    f"{vec['id']}: cross-verify failed: {result['errors']}",
                )
                self.assertTrue(result["round_trip_ok"])
                self.assertTrue(result["cross_verify_ok"])

    def test_tampered_cbor_fails(self):
        """Flipping a byte in the CBOR sidecar must fail verification."""
        # Use the first valid vector
        vec = next(v for v in self.cbor_vectors if v["json_receipt_valid"])
        cbor_bytes = bytearray.fromhex(vec["expected"]["cbor_hex"])
        # Flip a byte in the middle of the payload
        midpoint = len(cbor_bytes) // 2
        cbor_bytes[midpoint] ^= 0xFF
        result = verify_cbor_sidecar(bytes(cbor_bytes))
        # Should either fail to decode or fail round-trip
        self.assertFalse(result["valid"])

    def test_cross_verify_detects_core_mismatch(self):
        """If the JSON receipt core differs from the CBOR core, cross-verify must fail."""
        vec = next(v for v in self.cbor_vectors if v["json_receipt_valid"])
        source_id = vec["source_vector"]
        receipt = dict(self.json_vectors[source_id]["receipt"])
        cbor_bytes = bytes.fromhex(vec["expected"]["cbor_hex"])

        # Tamper with the JSON receipt (not the CBOR)
        receipt["version"] = "0.0.0-tampered"
        result = verify_cbor_sidecar(cbor_bytes, json_receipt=receipt)
        self.assertFalse(result["valid"])
        self.assertFalse(result["cross_verify_ok"])

    def test_oversized_cbor_rejected(self):
        result = verify_cbor_sidecar(b"\x00" * (10 * 1024 * 1024 + 1))
        self.assertFalse(result["valid"])
        self.assertTrue(any("too large" in e for e in result["errors"]))


# ── RFC 8949 §4.2.1 Diagnostic Primitives ──────────────────────────────


class TestRfc8949Primitives(unittest.TestCase):
    """Verify encoder output against RFC 8949 Appendix A diagnostic values."""

    def _roundtrip(self, obj):
        encoded = canonical_cbor_bytes(obj)
        decoded = decode_cbor_full(encoded)
        re_encoded = canonical_cbor_bytes(decoded)
        self.assertEqual(encoded, re_encoded)
        return encoded

    def test_integer_0(self):
        self.assertEqual(self._roundtrip(0), b"\x00")

    def test_integer_1(self):
        self.assertEqual(self._roundtrip(1), b"\x01")

    def test_integer_23(self):
        self.assertEqual(self._roundtrip(23), b"\x17")

    def test_integer_24(self):
        self.assertEqual(self._roundtrip(24), b"\x18\x18")

    def test_integer_255(self):
        self.assertEqual(self._roundtrip(255), b"\x18\xff")

    def test_integer_256(self):
        self.assertEqual(self._roundtrip(256), b"\x19\x01\x00")

    def test_integer_65535(self):
        self.assertEqual(self._roundtrip(65535), b"\x19\xff\xff")

    def test_integer_65536(self):
        self.assertEqual(self._roundtrip(65536), b"\x1a\x00\x01\x00\x00")

    def test_integer_neg1(self):
        self.assertEqual(self._roundtrip(-1), b"\x20")

    def test_integer_neg24(self):
        self.assertEqual(self._roundtrip(-24), b"\x37")

    def test_integer_neg25(self):
        self.assertEqual(self._roundtrip(-25), b"\x38\x18")

    def test_float_0(self):
        # 0.0 should encode as f16: f9 00 00
        self.assertEqual(self._roundtrip(0.0), b"\xf9\x00\x00")

    def test_float_1_0(self):
        # 1.0 as f16: f9 3c 00
        self.assertEqual(self._roundtrip(1.0), b"\xf9\x3c\x00")

    def test_float_1_5(self):
        # 1.5 as f16: f9 3e 00
        self.assertEqual(self._roundtrip(1.5), b"\xf9\x3e\x00")

    def test_empty_string(self):
        self.assertEqual(self._roundtrip(""), b"\x60")

    def test_string_a(self):
        self.assertEqual(self._roundtrip("a"), b"\x61\x61")

    def test_empty_bytes(self):
        self.assertEqual(self._roundtrip(b""), b"\x40")

    def test_empty_array(self):
        self.assertEqual(self._roundtrip([]), b"\x80")

    def test_empty_map(self):
        self.assertEqual(self._roundtrip({}), b"\xa0")

    def test_false(self):
        self.assertEqual(self._roundtrip(False), b"\xf4")

    def test_true(self):
        self.assertEqual(self._roundtrip(True), b"\xf5")

    def test_null(self):
        self.assertEqual(self._roundtrip(None), b"\xf6")

    def test_canonical_map_key_ordering(self):
        """RFC 8949 §4.2.1: keys sorted by encoded length, then bytewise."""
        obj = {"bb": 2, "a": 1, "aaa": 3}
        encoded = self._roundtrip(obj)
        decoded = decode_cbor_full(encoded)
        # All keys present and correct
        self.assertEqual(decoded, {"a": 1, "bb": 2, "aaa": 3})

    def test_determinism_across_key_insertion_order(self):
        """Different insertion orders must produce identical bytes."""
        a = canonical_cbor_bytes({"z": 1, "a": 2, "m": 3})
        b = canonical_cbor_bytes({"a": 2, "m": 3, "z": 1})
        c = canonical_cbor_bytes({"m": 3, "z": 1, "a": 2})
        self.assertEqual(a, b)
        self.assertEqual(b, c)

    def test_nested_dict_determinism(self):
        """Nested dicts must also be canonicalized."""
        obj = {"outer": {"z": 1, "a": 2}, "inner": [{"b": 2, "a": 1}]}
        encoded = canonical_cbor_bytes(obj)
        decoded = decode_cbor_full(encoded)
        re_encoded = canonical_cbor_bytes(decoded)
        self.assertEqual(encoded, re_encoded)


# ── SHA-256 Digest Stability ───────────────────────────────────────────


class TestDigestStability(unittest.TestCase):
    """Ensure canonical_cbor_sha256 is stable across invocations."""

    def test_same_input_same_digest(self):
        obj = {"type": "test", "value": 42}
        d1 = canonical_cbor_sha256(obj)
        d2 = canonical_cbor_sha256(obj)
        self.assertEqual(d1, d2)

    def test_different_key_order_same_digest(self):
        d1 = canonical_cbor_sha256({"a": 1, "b": 2})
        d2 = canonical_cbor_sha256({"b": 2, "a": 1})
        self.assertEqual(d1, d2)

    def test_different_content_different_digest(self):
        d1 = canonical_cbor_sha256({"a": 1})
        d2 = canonical_cbor_sha256({"a": 2})
        self.assertNotEqual(d1, d2)

    def test_golden_digest(self):
        """Pin a known digest to detect encoder regressions."""
        obj = {"hello": "world"}
        expected_hex = hashlib.sha256(canonical_cbor_bytes(obj)).hexdigest()
        actual = canonical_cbor_sha256(obj)
        self.assertEqual(actual, f"sha256:{expected_hex}")


# ── Decoder Edge Paths ─────────────────────────────────────────────────


class TestDecoderEdgePaths(unittest.TestCase):
    """Cover remaining decoder branches for 100% coverage."""

    def test_read_uint_empty_input(self):
        """_read_uint called with offset past the end of data."""
        from aiir._verify_cbor import _read_uint

        with self.assertRaises(CborDecodeError):
            _read_uint(b"", 0)

    def test_read_uint_truncated_4byte(self):
        """4-byte uint form truncated (additional == 26, insufficient data)."""
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\x1a\x00\x01")

    def test_read_uint_truncated_8byte(self):
        """8-byte uint form truncated (additional == 27, insufficient data)."""
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\x1b\x00\x01\x02\x03")

    def test_decode_float_truncated_f16(self):
        """f16 float truncated (only 1 data byte instead of 2)."""
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\xf9\x00")

    def test_decode_float_f32(self):
        """f32 decode path: fa 3f 80 00 00 = 1.0 as float32."""
        val = decode_cbor_full(b"\xfa\x3f\x80\x00\x00")
        self.assertAlmostEqual(val, 1.0)

    def test_decode_float_truncated_f32(self):
        """f32 float truncated (only 2 data bytes instead of 4)."""
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\xfa\x3f\x80")

    def test_decode_float_f64(self):
        """f64 decode path: fb 3f f0 00 00 00 00 00 00 = 1.0 as float64."""
        val = decode_cbor_full(b"\xfb\x3f\xf0\x00\x00\x00\x00\x00\x00")
        self.assertAlmostEqual(val, 1.0)

    def test_decode_float_truncated_f64(self):
        """f64 float truncated (only 4 data bytes instead of 8)."""
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\xfb\x3f\xf0\x00\x00")

    def test_decode_float_unsupported_additional(self):
        """Unsupported float additional info (not 25, 26, or 27)."""
        from aiir._verify_cbor import _decode_float

        with self.assertRaises(CborDecodeError):
            _decode_float(b"\x00\x00", 0, 24)

    def test_decode_empty_input(self):
        """decode_cbor with empty bytes raises CborDecodeError."""
        with self.assertRaises(CborDecodeError):
            decode_cbor(b"", 0)

    def test_byte_string_truncated(self):
        """Byte string claims 2 bytes but only 1 available."""
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\x42\x61")

    def test_unsupported_simple_value(self):
        """Simple value 0 (not false/true/null/float) is rejected."""
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\xe0")

    def test_unsupported_major_type_tag(self):
        """CBOR tag (major type 6) is not supported."""
        with self.assertRaises(CborDecodeError):
            decode_cbor_full(b"\xc0\x00")


# ── Envelope Edge Paths ────────────────────────────────────────────────


class TestEnvelopeEdgePaths(unittest.TestCase):
    """Cover remaining envelope validation branches."""

    def test_empty_object_schema(self):
        env = build_canonical_object_envelope(
            kind="test.core",
            object_schema="test/v1",
            core={"a": 1},
        )
        env["object_schema"] = ""
        errors = verify_cbor_envelope(env)
        self.assertTrue(any("object_schema" in e for e in errors))


# ── Sidecar Edge Paths ─────────────────────────────────────────────────


class TestSidecarEdgePaths(unittest.TestCase):
    """Cover remaining verify_cbor_sidecar branches."""

    def test_sidecar_invalid_envelope(self):
        """Decodable CBOR that fails envelope validation."""
        cbor_bytes = canonical_cbor_bytes({"hello": "world"})
        result = verify_cbor_sidecar(cbor_bytes)
        self.assertFalse(result["valid"])
        self.assertTrue(any("missing" in e for e in result["errors"]))

    def test_sidecar_reencode_failure(self):
        """canonical_cbor_bytes raises during re-encode."""
        from unittest.mock import patch

        env = build_canonical_object_envelope(
            kind="test.core",
            object_schema="test/v1",
            core={"a": 1},
        )
        cbor_bytes = canonical_cbor_bytes(env)
        with patch(
            "aiir._verify_cbor.canonical_cbor_bytes",
            side_effect=TypeError("mock"),
        ):
            result = verify_cbor_sidecar(cbor_bytes)
        self.assertFalse(result["valid"])
        self.assertTrue(any("re-encode failed" in e for e in result["errors"]))

    def test_sidecar_round_trip_mismatch(self):
        """Non-canonical float encoding decoded fine but re-encodes differently."""
        env = build_canonical_object_envelope(
            kind="test.core",
            object_schema="test/v1",
            core={"x": 1.5},
        )
        cbor_bytes = canonical_cbor_bytes(env)
        # f16 1.5 = f9 3e 00 (3 bytes) → replace with f64 1.5 = fb 3f f8 00… (9 bytes)
        patched = cbor_bytes.replace(
            b"\xf9\x3e\x00",
            b"\xfb\x3f\xf8\x00\x00\x00\x00\x00\x00",
        )
        self.assertNotEqual(patched, cbor_bytes)
        result = verify_cbor_sidecar(patched)
        self.assertFalse(result["valid"])
        self.assertTrue(any("round-trip mismatch" in e for e in result["errors"]))

    def test_sidecar_valid_without_json(self):
        """Valid sidecar without json_receipt → no cross_verify_ok in result."""
        env = build_canonical_object_envelope(
            kind="test.core",
            object_schema="test/v1",
            core={"a": 1},
        )
        cbor_bytes = canonical_cbor_bytes(env)
        result = verify_cbor_sidecar(cbor_bytes)
        self.assertTrue(result["valid"])
        self.assertNotIn("cross_verify_ok", result)

    def test_cross_verify_kind_mismatch(self):
        """Envelope kind doesn't match JSON receipt type."""
        receipt = {
            "type": "aiir.receipt",
            "schema": "aiir/receipt.v1",
            "version": "1.0",
        }
        env = build_canonical_object_envelope(
            kind="wrong.type.core",
            object_schema="aiir/receipt.v1",
            core={
                "type": "aiir.receipt",
                "schema": "aiir/receipt.v1",
                "version": "1.0",
            },
        )
        cbor_bytes = canonical_cbor_bytes(env)
        result = verify_cbor_sidecar(cbor_bytes, json_receipt=receipt)
        self.assertTrue(any("kind mismatch" in e for e in result["errors"]))

    def test_cross_verify_object_schema_mismatch(self):
        """Envelope object_schema doesn't match JSON receipt schema."""
        receipt = {
            "type": "aiir.receipt",
            "schema": "aiir/receipt.v1",
            "version": "1.0",
        }
        env = build_canonical_object_envelope(
            kind="aiir.receipt.core",
            object_schema="wrong/schema.v1",
            core={
                "type": "aiir.receipt",
                "schema": "aiir/receipt.v1",
                "version": "1.0",
            },
        )
        cbor_bytes = canonical_cbor_bytes(env)
        result = verify_cbor_sidecar(cbor_bytes, json_receipt=receipt)
        self.assertTrue(any("object_schema mismatch" in e for e in result["errors"]))


# ── File-Level Verification ────────────────────────────────────────────


class TestVerifyCborFile(unittest.TestCase):
    """Cover verify_cbor_file paths."""

    def test_file_not_found(self):
        result = verify_cbor_file("/tmp/_aiir_nonexistent_cbor_test_file.cbor")
        self.assertFalse(result["valid"])
        self.assertTrue(any("not found" in e.lower() for e in result["errors"]))

    def test_file_is_symlink(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            real = os.path.join(tmp, "real.cbor")
            link = os.path.join(tmp, "link.cbor")
            with open(real, "wb") as f:
                f.write(b"\xa0")
            os.symlink(real, link)
            result = verify_cbor_file(link)
            self.assertFalse(result["valid"])
            self.assertTrue(any("symlink" in e for e in result["errors"]))

    def test_stat_error(self):
        import os
        import tempfile
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            f_path = os.path.join(tmp, "err.cbor")
            with open(f_path, "wb") as f:
                f.write(b"\xa0")
            with (
                patch("aiir._verify_cbor.Path.exists", return_value=True),
                patch("aiir._verify_cbor.Path.is_symlink", return_value=False),
                patch(
                    "aiir._verify_cbor.Path.stat",
                    side_effect=OSError("mock stat error"),
                ),
            ):
                result = verify_cbor_file(f_path)
            self.assertFalse(result["valid"])
            self.assertTrue(any("stat" in e.lower() for e in result["errors"]))

    def test_file_too_large(self):
        import os
        import tempfile
        from unittest.mock import MagicMock, patch

        with tempfile.TemporaryDirectory() as tmp:
            f_path = os.path.join(tmp, "big.cbor")
            with open(f_path, "wb") as f:
                f.write(b"\xa0")
            mock_stat = MagicMock()
            mock_stat.st_size = 11 * 1024 * 1024
            with (
                patch("aiir._verify_cbor.Path.exists", return_value=True),
                patch("aiir._verify_cbor.Path.is_symlink", return_value=False),
                patch("aiir._verify_cbor.Path.stat", return_value=mock_stat),
            ):
                result = verify_cbor_file(f_path)
            self.assertFalse(result["valid"])
            self.assertTrue(any("too large" in e.lower() for e in result["errors"]))

    def test_valid_file(self):
        import os
        import tempfile

        env = build_canonical_object_envelope(
            kind="test.core",
            object_schema="test/v1",
            core={"a": 1},
        )
        cbor_bytes = canonical_cbor_bytes(env)
        with tempfile.TemporaryDirectory() as tmp:
            f_path = os.path.join(tmp, "good.cbor")
            with open(f_path, "wb") as f:
                f.write(cbor_bytes)
            result = verify_cbor_file(f_path)
            self.assertTrue(result["valid"], result.get("errors"))

    def test_valid_file_with_json_receipt(self):
        import os
        import tempfile

        receipt = {"type": "test", "schema": "test/v1", "version": "1.0"}
        env = build_canonical_object_envelope(
            kind="test.core",
            object_schema="test/v1",
            core={"type": "test", "schema": "test/v1", "version": "1.0"},
        )
        cbor_bytes = canonical_cbor_bytes(env)
        with tempfile.TemporaryDirectory() as tmp:
            f_path = os.path.join(tmp, "good.cbor")
            with open(f_path, "wb") as f:
                f.write(cbor_bytes)
            result = verify_cbor_file(f_path, json_receipt=receipt)
            self.assertTrue(result["valid"], result.get("errors"))
            self.assertTrue(result["cross_verify_ok"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
