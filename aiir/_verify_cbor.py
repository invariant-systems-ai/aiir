# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 Invariant Systems, Inc.
"""
AIIR internal — canonical CBOR sidecar verification.

Provides a minimal deterministic CBOR *decoder* (the dual of the encoder in
_canonical_cbor.py) and verification logic that can:

  1. Decode a .cbor sidecar and validate its envelope structure.
  2. Re-encode the decoded object and assert byte-identity (round-trip).
  3. Cross-verify against a companion JSON receipt (same core → same digest).

Zero dependencies — stdlib only.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aiir._canonical_cbor import (
    CANONICAL_OBJECT_SCHEMA,
    CANONICAL_OBJECT_TYPE,
    canonical_cbor_bytes,
)

# ---------------------------------------------------------------------------
# Deterministic CBOR decoder (RFC 8949 subset matching our encoder)
# ---------------------------------------------------------------------------

# CBOR major types
_MT_UINT = 0
_MT_NEGINT = 1
_MT_BSTR = 2
_MT_TSTR = 3
_MT_ARRAY = 4
_MT_MAP = 5
_MT_SIMPLE = 7

# Maximum nesting depth for arrays/maps (prevents stack-overflow DoS)
_MAX_CBOR_DEPTH = 64


class CborDecodeError(ValueError):
    """Raised when CBOR bytes cannot be decoded or violate determinism rules."""


def _read_uint(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a CBOR unsigned integer argument, return (value, new_offset)."""
    if offset >= len(data):
        raise CborDecodeError("unexpected end of input")
    additional = data[offset] & 0x1F
    offset += 1
    if additional < 24:
        return additional, offset
    if additional == 24:
        if offset >= len(data):
            raise CborDecodeError("unexpected end of input")
        val = data[offset]
        if val < 24:
            raise CborDecodeError(f"non-canonical uint encoding: {val} in 1-byte form")
        return val, offset + 1
    if additional == 25:
        if offset + 2 > len(data):
            raise CborDecodeError("unexpected end of input")
        val = int.from_bytes(data[offset : offset + 2], "big")
        if val < 256:
            raise CborDecodeError(f"non-canonical uint encoding: {val} in 2-byte form")
        return val, offset + 2
    if additional == 26:
        if offset + 4 > len(data):
            raise CborDecodeError("unexpected end of input")
        val = int.from_bytes(data[offset : offset + 4], "big")
        if val < 65536:
            raise CborDecodeError(f"non-canonical uint encoding: {val} in 4-byte form")
        return val, offset + 4
    if additional == 27:
        if offset + 8 > len(data):
            raise CborDecodeError("unexpected end of input")
        val = int.from_bytes(data[offset : offset + 8], "big")
        if val < 4294967296:
            raise CborDecodeError(f"non-canonical uint encoding: {val} in 8-byte form")
        return val, offset + 8
    # 28-30 are reserved; 31 is indefinite-length (not canonical)
    raise CborDecodeError(f"non-canonical or unsupported additional info: {additional}")


def _decode_float(data: bytes, offset: int, additional: int) -> Tuple[float, int]:
    """Decode a CBOR float (f16/f32/f64) at *offset* (past the initial byte)."""
    if additional == 25:  # f16
        if offset + 2 > len(data):
            raise CborDecodeError("unexpected end of input for f16")
        bits = int.from_bytes(data[offset : offset + 2], "big")
        sign = -1.0 if (bits & 0x8000) else 1.0
        exp = (bits >> 10) & 0x1F
        frac = bits & 0x03FF
        if exp == 0:
            val = sign * (frac / 1024.0) * (2.0**-14)
        elif exp == 0x1F:
            raise CborDecodeError("non-finite float not allowed in canonical CBOR")
        else:
            val = sign * (1.0 + frac / 1024.0) * (2.0 ** (exp - 15))
        return val, offset + 2
    if additional == 26:  # f32
        if offset + 4 > len(data):
            raise CborDecodeError("unexpected end of input for f32")
        (val,) = struct.unpack(">f", data[offset : offset + 4])
        return val, offset + 4
    if additional == 27:  # f64
        if offset + 8 > len(data):
            raise CborDecodeError("unexpected end of input for f64")
        (val,) = struct.unpack(">d", data[offset : offset + 8])
        return val, offset + 8
    raise CborDecodeError(f"unsupported float additional info: {additional}")


def decode_cbor(data: bytes, offset: int = 0, _depth: int = 0) -> Tuple[Any, int]:
    """Decode one CBOR data item. Returns (value, new_offset).

    Enforces canonical encoding rules:
    - Integers use shortest form.
    - No indefinite-length containers.
    - Map keys sorted by encoded length then lexicographically.

    *_depth* is an internal recursion counter.  Raises CborDecodeError when
    nesting exceeds _MAX_CBOR_DEPTH to prevent stack-overflow DoS (CWE-400).
    """
    if _depth > _MAX_CBOR_DEPTH:
        raise CborDecodeError(f"CBOR nesting depth exceeds maximum ({_MAX_CBOR_DEPTH})")
    if offset >= len(data):
        raise CborDecodeError("unexpected end of input")

    initial = data[offset]
    major = (initial >> 5) & 0x07
    additional = initial & 0x1F

    if major == _MT_UINT:
        val, off = _read_uint(data, offset)
        return val, off

    if major == _MT_NEGINT:
        val, off = _read_uint(data, offset)
        return -1 - val, off

    if major == _MT_BSTR:
        length, off = _read_uint(data, offset)
        if off + length > len(data):
            raise CborDecodeError("byte string extends past end of input")
        return data[off : off + length], off + length

    if major == _MT_TSTR:
        length, off = _read_uint(data, offset)
        if off + length > len(data):
            raise CborDecodeError("text string extends past end of input")
        try:
            text = data[off : off + length].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CborDecodeError(f"invalid UTF-8 in text string: {exc}") from exc
        return text, off + length

    if major == _MT_ARRAY:
        count, off = _read_uint(data, offset)
        items: List[Any] = []
        for _ in range(count):
            item, off = decode_cbor(data, off, _depth + 1)
            items.append(item)
        return items, off

    if major == _MT_MAP:
        count, off = _read_uint(data, offset)
        result: Dict[Any, Any] = {}
        prev_key_bytes: Optional[bytes] = None
        for _ in range(count):
            key_start = off
            key, off = decode_cbor(data, off, _depth + 1)
            key_bytes = data[key_start:off]
            # Verify canonical key ordering: sort by (length, bytes)
            if prev_key_bytes is not None:
                if (len(key_bytes), key_bytes) <= (len(prev_key_bytes), prev_key_bytes):
                    raise CborDecodeError("map keys not in canonical order")
            prev_key_bytes = key_bytes
            value, off = decode_cbor(data, off, _depth + 1)
            if not isinstance(key, (str, int, float, bool, bytes)) and key is not None:
                raise CborDecodeError("unhashable CBOR map key")
            result[key] = value
        return result, off

    if major == _MT_SIMPLE:
        if additional == 20:  # false
            return False, offset + 1
        if additional == 21:  # true
            return True, offset + 1
        if additional == 22:  # null
            return None, offset + 1
        if additional in (25, 26, 27):  # float
            return _decode_float(data, offset + 1, additional)
        raise CborDecodeError(f"unsupported simple value: {additional}")

    raise CborDecodeError(f"unsupported CBOR major type: {major}")


def decode_cbor_full(data: bytes) -> Any:
    """Decode exactly one CBOR item consuming all bytes. Trailing bytes are an error."""
    value, offset = decode_cbor(data, 0)
    if offset != len(data):
        raise CborDecodeError(
            f"trailing bytes: {len(data) - offset} bytes after CBOR item"
        )
    return value


# ---------------------------------------------------------------------------
# Envelope verification
# ---------------------------------------------------------------------------

_ENVELOPE_REQUIRED_KEYS = {"type", "schema", "kind", "object_schema", "core"}


def verify_cbor_envelope(obj: Any) -> List[str]:
    """Validate the canonical Layer-0 envelope structure.

    Returns a list of error strings (empty = valid).
    """
    errors: List[str] = []
    if not isinstance(obj, dict):
        return [f"envelope is {type(obj).__name__}, expected dict"]

    missing = _ENVELOPE_REQUIRED_KEYS - set(obj.keys())
    if missing:
        errors.append(f"missing envelope keys: {sorted(missing)}")
        return errors  # can't check further

    if obj["type"] != CANONICAL_OBJECT_TYPE:
        errors.append(
            f"envelope type mismatch: {obj['type']!r} != {CANONICAL_OBJECT_TYPE!r}"
        )
    if obj["schema"] != CANONICAL_OBJECT_SCHEMA:
        errors.append(
            f"envelope schema mismatch: {obj['schema']!r} != {CANONICAL_OBJECT_SCHEMA!r}"
        )
    if not isinstance(obj["kind"], str) or not obj["kind"]:
        errors.append("envelope kind must be a non-empty string")
    if not isinstance(obj["object_schema"], str) or not obj["object_schema"]:
        errors.append("envelope object_schema must be a non-empty string")
    if not isinstance(obj["core"], dict):
        errors.append(f"envelope core is {type(obj['core']).__name__}, expected dict")
    return errors


# ---------------------------------------------------------------------------
# Sidecar verification
# ---------------------------------------------------------------------------

_MAX_CBOR_SIZE = 10 * 1024 * 1024  # 10 MB


def verify_cbor_sidecar(
    cbor_bytes: bytes,
    *,
    json_receipt: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Verify a canonical CBOR sidecar.

    Checks:
      1. Decodes without error.
      2. Envelope structure is valid.
      3. Round-trip: re-encoding the decoded object produces identical bytes.
      4. If *json_receipt* is given, the core fields match.

    Returns a result dict with ``valid``, ``errors``, and diagnostic fields.
    """
    errors: List[str] = []

    if len(cbor_bytes) > _MAX_CBOR_SIZE:
        return {
            "valid": False,
            "errors": [f"CBOR sidecar too large ({len(cbor_bytes)} bytes)"],
        }

    # 1. Decode
    try:
        obj = decode_cbor_full(cbor_bytes)
    except CborDecodeError as exc:
        return {"valid": False, "errors": [f"CBOR decode error: {exc}"]}

    # 2. Envelope structure
    env_errors = verify_cbor_envelope(obj)
    if env_errors:
        return {"valid": False, "errors": env_errors}

    # 3. Round-trip determinism
    try:
        re_encoded = canonical_cbor_bytes(obj)
    except (TypeError, ValueError) as exc:
        return {"valid": False, "errors": [f"re-encode failed: {exc}"]}

    if re_encoded != cbor_bytes:
        errors.append(
            f"round-trip mismatch: decoded and re-encoded CBOR differs "
            f"(original {len(cbor_bytes)} bytes, re-encoded {len(re_encoded)} bytes)"
        )

    cbor_sha256 = hashlib.sha256(cbor_bytes).hexdigest()

    # 4. Cross-verify against JSON receipt core
    cross_valid = True
    if json_receipt is not None and isinstance(json_receipt, dict):
        CORE_KEYS = {
            "type",
            "schema",
            "version",
            "commit",
            "ai_attestation",
            "provenance",
            "reviewed_commit",
            "reviewer",
            "review_outcome",
            "comment",
        }
        json_core = {k: json_receipt[k] for k in CORE_KEYS if k in json_receipt}
        cbor_core = obj.get("core", {})

        if json_core != cbor_core:
            errors.append("CBOR core fields do not match JSON receipt core")
            cross_valid = False

        # Verify the envelope kind matches the receipt type
        expected_kind = f"{json_receipt.get('type', 'aiir.receipt')}.core"
        if obj.get("kind") != expected_kind:
            errors.append(
                f"envelope kind mismatch: {obj.get('kind')!r} != {expected_kind!r}"
            )
            cross_valid = False

        # Verify object_schema matches receipt schema
        expected_schema = str(json_receipt.get("schema", ""))
        if obj.get("object_schema") != expected_schema:
            errors.append(
                f"envelope object_schema mismatch: "
                f"{obj.get('object_schema')!r} != {expected_schema!r}"
            )
            cross_valid = False

    valid = len(errors) == 0
    result: Dict[str, Any] = {
        "valid": valid,
        "errors": errors,
        "cbor_sha256": "sha256:" + cbor_sha256,
        "cbor_length": len(cbor_bytes),
        "envelope_kind": obj.get("kind"),
        "envelope_object_schema": obj.get("object_schema"),
        "round_trip_ok": re_encoded == cbor_bytes,
    }
    if json_receipt is not None:
        result["cross_verify_ok"] = cross_valid
    return result


def verify_cbor_file(
    filepath: str,
    *,
    json_receipt: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Load and verify a .cbor sidecar file."""
    path = Path(filepath)
    if not path.exists():
        return {"valid": False, "errors": [f"File not found: {filepath}"]}
    if path.is_symlink():
        return {
            "valid": False,
            "errors": [f"CBOR file is a symlink (refusing to verify): {filepath}"],
        }
    try:
        file_size = path.stat().st_size
    except OSError as exc:
        return {"valid": False, "errors": [f"Cannot stat file: {exc}"]}
    if file_size > _MAX_CBOR_SIZE:
        return {
            "valid": False,
            "errors": [f"File too large ({file_size} bytes, max {_MAX_CBOR_SIZE})"],
        }
    cbor_bytes = path.read_bytes()
    return verify_cbor_sidecar(cbor_bytes, json_receipt=json_receipt)
