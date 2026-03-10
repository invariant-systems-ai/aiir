# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Invariant Systems, Inc.
"""Unit tests for the deterministic canonical CBOR helpers."""

from __future__ import annotations

import math
import unittest

from aiir._canonical_cbor import (
    CANONICAL_OBJECT_SCHEMA,
    CANONICAL_OBJECT_TYPE,
    _encode_float_canonical,
    _encode_item,
    _encode_uint,
    _f16_to_f64,
    _try_f16,
    build_canonical_object_envelope,
    canonical_cbor_bytes,
    canonical_cbor_sha256,
)


class TestCanonicalCbor(unittest.TestCase):
    def test_envelope_uses_aiir_branding(self) -> None:
        envelope = build_canonical_object_envelope(
            kind="aiir.commit_receipt.core",
            object_schema="aiir/commit_receipt.v2",
            core={"a": 1},
        )
        self.assertEqual(envelope["type"], CANONICAL_OBJECT_TYPE)
        self.assertEqual(envelope["schema"], CANONICAL_OBJECT_SCHEMA)

    def test_canonical_cbor_sha256_prefix(self) -> None:
        digest = canonical_cbor_sha256({"a": 1})
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(len(digest), 71)

    def test_encode_uint_ranges_and_negative_guard(self) -> None:
        self.assertEqual(_encode_uint(0, 0), b"\x00")
        self.assertEqual(_encode_uint(0, 23), b"\x17")
        self.assertEqual(_encode_uint(0, 24), b"\x18\x18")
        self.assertEqual(_encode_uint(0, 255), b"\x18\xff")
        self.assertEqual(_encode_uint(0, 256), b"\x19\x01\x00")
        self.assertEqual(_encode_uint(0, 65535), b"\x19\xff\xff")
        self.assertEqual(_encode_uint(0, 65536), b"\x1a\x00\x01\x00\x00")
        self.assertEqual(
            _encode_uint(0, 4294967296),
            b"\x1b\x00\x00\x00\x01\x00\x00\x00\x00",
        )
        with self.assertRaisesRegex(ValueError, "negative_uint"):
            _encode_uint(0, -1)

    def test_encode_float_canonical_variants(self) -> None:
        self.assertEqual(_encode_float_canonical(1.5), b"\xf9>\x00")
        self.assertEqual(_encode_float_canonical(100000.0)[:1], b"\xfa")
        self.assertEqual(_encode_float_canonical(0.1)[:1], b"\xfb")
        for value in (math.nan, math.inf, -math.inf):
            with self.assertRaisesRegex(ValueError, "non-finite float"):
                _encode_float_canonical(value)

    def test_try_f16_and_f16_to_f64_cover_branches(self) -> None:
        self.assertIsNone(_try_f16(math.inf))
        self.assertIsNone(_try_f16(1e-20))
        self.assertIsNone(_try_f16(2**-30))
        self.assertIsNotNone(_try_f16(2**-20))
        self.assertEqual(_f16_to_f64(0), 0.0)
        self.assertGreater(_f16_to_f64(1), 0.0)
        self.assertEqual(_f16_to_f64(0x3C00), 1.0)

    def test_encode_item_primitives(self) -> None:
        self.assertEqual(_encode_item(None), b"\xf6")
        self.assertEqual(_encode_item(False), b"\xf4")
        self.assertEqual(_encode_item(True), b"\xf5")
        self.assertEqual(_encode_item(10), b"\x0a")
        self.assertEqual(_encode_item(-1), b"\x20")
        self.assertEqual(_encode_item(1.5), b"\xf9>\x00")
        self.assertEqual(_encode_item(b"ab"), b"Bab")
        self.assertEqual(_encode_item(bytearray(b"ab")), b"Bab")
        self.assertEqual(_encode_item(memoryview(b"ab")), b"Bab")
        self.assertEqual(_encode_item("hi"), b"bhi")

    def test_encode_item_sequences_and_dict_sorting(self) -> None:
        self.assertEqual(_encode_item([1, 2]), b"\x82\x01\x02")
        self.assertEqual(_encode_item((1, 2)), b"\x82\x01\x02")
        left = canonical_cbor_bytes({"b": 2, "a": 1})
        right = canonical_cbor_bytes({"a": 1, "b": 2})
        self.assertEqual(left, right)

    def test_encode_item_unsupported_type(self) -> None:
        with self.assertRaisesRegex(TypeError, "unsupported_type_for_cbor"):
            _encode_item(object())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
