"""
AIIR internal — deterministic Canonical CBOR helpers.

This module keeps AIIR zero-dependency while still being able to emit
canonical CBOR sidecars for receipt cores. It intentionally supports the
subset of types AIIR emits in receipts: dict, list/tuple, str, bytes,
int, float, bool, and None.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any, Dict, Mapping


CANONICAL_OBJECT_TYPE = "aiir.canonical_object"
CANONICAL_OBJECT_SCHEMA = "aiir/canonical_object.v1"


def canonical_cbor_bytes(obj: Any) -> bytes:
    """Encode an object using RFC 8949 deterministic CBOR rules."""

    return _encode_item(obj)


def canonical_cbor_sha256(obj: Any) -> str:
    """Return a receipts-style sha256 digest over canonical CBOR bytes."""

    return "sha256:" + hashlib.sha256(canonical_cbor_bytes(obj)).hexdigest()


def build_canonical_object_envelope(
    *,
    kind: str,
    object_schema: str,
    core: Mapping[str, Any],
) -> Dict[str, Any]:
    """Wrap a core object in the canonical Layer-0 envelope."""

    return {
        "type": CANONICAL_OBJECT_TYPE,
        "schema": CANONICAL_OBJECT_SCHEMA,
        "kind": str(kind),
        "object_schema": str(object_schema),
        "core": dict(core),
    }


def _encode_uint(major: int, n: int) -> bytes:
    if n < 0:
        raise ValueError("negative_uint")
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 4294967296:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def _encode_float_canonical(x: float) -> bytes:
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("non-finite float not allowed in canonical CBOR")
    want = struct.pack(">d", x)
    f16 = _try_f16(x)
    if f16 is not None:
        return b"\xf9" + f16
    f32v = struct.unpack(">f", struct.pack(">f", x))[0]
    if struct.pack(">d", f32v) == want:
        return b"\xfa" + struct.pack(">f", x)
    return b"\xfb" + want


def _try_f16(x: float) -> bytes | None:
    f32v = struct.unpack(">f", struct.pack(">f", x))[0]
    if struct.pack(">d", f32v) != struct.pack(">d", x):
        return None
    bits32 = struct.unpack(">I", struct.pack(">f", f32v))[0]
    sign = (bits32 >> 16) & 0x8000
    exp = (bits32 >> 23) & 0xFF
    mant = bits32 & 0x7FFFFF
    exp16 = exp - 127 + 15
    if exp == 0xFF or exp16 >= 0x1F:
        return None
    if exp16 <= 0:
        if exp16 < -10:
            half = sign
        else:
            mantissa = mant | 0x800000
            shift = 14 - exp16
            half = sign | ((mantissa >> shift) & 0xFFFF)
    else:
        half = sign | ((exp16 & 0x1F) << 10) | ((mant >> 13) & 0x3FF)
    if struct.pack(">d", _f16_to_f64(half)) == struct.pack(">d", x):
        return struct.pack(">H", half)
    return None


def _f16_to_f64(bits: int) -> float:
    sign = -1.0 if (bits & 0x8000) else 1.0
    exp = (bits >> 10) & 0x1F
    frac = bits & 0x03FF
    if exp == 0:
        return sign * (frac / 1024.0) * (2.0 ** -14)
    return sign * (1.0 + frac / 1024.0) * (2.0 ** (exp - 15))


def _encode_item(obj: Any) -> bytes:
    if obj is None:
        return b"\xf6"
    if obj is False:
        return b"\xf4"
    if obj is True:
        return b"\xf5"

    if isinstance(obj, int) and not isinstance(obj, bool):
        if obj >= 0:
            return _encode_uint(0, obj)
        return _encode_uint(1, (-1 - obj))

    if isinstance(obj, float):
        return _encode_float_canonical(obj)

    if isinstance(obj, (bytes, bytearray, memoryview)):
        data = bytes(obj)
        return _encode_uint(2, len(data)) + data

    if isinstance(obj, str):
        data = obj.encode("utf-8", errors="strict")
        return _encode_uint(3, len(data)) + data

    if isinstance(obj, (list, tuple)):
        out = bytearray(_encode_uint(4, len(obj)))
        for item in obj:
            out += _encode_item(item)
        return bytes(out)

    if isinstance(obj, dict):
        out = bytearray(_encode_uint(5, len(obj)))
        encoded_items = []
        for key, value in obj.items():
            key_bytes = _encode_item(key)
            encoded_items.append((len(key_bytes), key_bytes, value))
        encoded_items.sort(key=lambda item: (item[0], item[1]))
        for _, key_bytes, value in encoded_items:
            out += key_bytes
            out += _encode_item(value)
        return bytes(out)

    raise TypeError(f"unsupported_type_for_cbor: {type(obj).__name__}")