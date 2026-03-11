// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Invariant Systems, Inc.
//
// Golden vector conformance tests — proves Python↔Rust CBOR determinism.

use super::*;
use sha2::{Digest, Sha256};
use serde::Deserialize;

/// JSON structure of a single golden vector.
#[derive(Deserialize)]
struct GoldenVector {
    id: String,
    #[allow(dead_code)]
    source_vector: String,
    #[allow(dead_code)]
    json_receipt_valid: bool,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    cbor_hex: String,
    cbor_sha256: String,
    cbor_length: usize,
}

#[derive(Deserialize)]
struct VectorsFile {
    vectors: Vec<GoldenVector>,
}

fn load_vectors() -> Vec<GoldenVector> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/cbor_test_vectors.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read golden vectors at {}: {}", path.display(), e));
    let file: VectorsFile = serde_json::from_str(&data).expect("invalid golden vectors JSON");
    file.vectors
}

// ── Golden vector: decode + round-trip ───────────────────────────────

#[test]
fn golden_vectors_decode_and_roundtrip() {
    let vectors = load_vectors();
    assert!(!vectors.is_empty(), "no golden vectors loaded");

    for vec in &vectors {
        let cbor_bytes = hex::decode(&vec.expected.cbor_hex)
            .unwrap_or_else(|e| panic!("{}: bad hex: {}", vec.id, e));

        // Length matches
        assert_eq!(
            cbor_bytes.len(),
            vec.expected.cbor_length,
            "{}: length mismatch",
            vec.id
        );

        // SHA-256 matches
        let sha = hex::encode(Sha256::digest(&cbor_bytes));
        assert_eq!(
            sha, vec.expected.cbor_sha256,
            "{}: SHA-256 mismatch",
            vec.id
        );

        // Decodes without error
        let decoded = decode_full(&cbor_bytes)
            .unwrap_or_else(|e| panic!("{}: decode failed: {}", vec.id, e));

        // Round-trip: re-encode → identical bytes
        let re_encoded = encode(&decoded)
            .unwrap_or_else(|e| panic!("{}: encode failed: {}", vec.id, e));
        assert_eq!(
            re_encoded, cbor_bytes,
            "{}: round-trip mismatch ({} vs {} bytes)",
            vec.id,
            re_encoded.len(),
            cbor_bytes.len()
        );
    }
}

// ── Envelope verification on golden vectors ──────────────────────────

#[test]
fn golden_vectors_envelope_valid() {
    let vectors = load_vectors();
    for vec in &vectors {
        let cbor_bytes = hex::decode(&vec.expected.cbor_hex).unwrap();
        let decoded = decode_full(&cbor_bytes).unwrap();
        let errors = verify_envelope(&decoded);
        assert!(
            errors.is_empty(),
            "{}: envelope errors: {:?}",
            vec.id,
            errors
        );
    }
}

// ── Full sidecar verification ────────────────────────────────────────

#[test]
fn golden_vectors_sidecar_verify() {
    let vectors = load_vectors();
    for vec in &vectors {
        let cbor_bytes = hex::decode(&vec.expected.cbor_hex).unwrap();
        let (valid, errors, sha) = verify_sidecar(&cbor_bytes);
        assert!(
            valid,
            "{}: sidecar verification failed: {:?}",
            vec.id, errors
        );
        assert_eq!(
            sha, vec.expected.cbor_sha256,
            "{}: sidecar SHA-256 mismatch",
            vec.id
        );
    }
}

// ── RFC 8949 primitive encoding/decoding ─────────────────────────────

#[test]
fn primitives_uint() {
    // 0 → 0x00
    assert_eq!(encode(&CborValue::Uint(0)).unwrap(), vec![0x00]);
    // 1 → 0x01
    assert_eq!(encode(&CborValue::Uint(1)).unwrap(), vec![0x01]);
    // 23 → 0x17
    assert_eq!(encode(&CborValue::Uint(23)).unwrap(), vec![0x17]);
    // 24 → 0x18 0x18
    assert_eq!(encode(&CborValue::Uint(24)).unwrap(), vec![0x18, 0x18]);
    // 255 → 0x18 0xFF
    assert_eq!(encode(&CborValue::Uint(255)).unwrap(), vec![0x18, 0xFF]);
    // 256 → 0x19 0x01 0x00
    assert_eq!(encode(&CborValue::Uint(256)).unwrap(), vec![0x19, 0x01, 0x00]);
    // 65535 → 0x19 0xFF 0xFF
    assert_eq!(encode(&CborValue::Uint(65535)).unwrap(), vec![0x19, 0xFF, 0xFF]);
    // 65536 → 0x1A 0x00 0x01 0x00 0x00
    assert_eq!(
        encode(&CborValue::Uint(65536)).unwrap(),
        vec![0x1A, 0x00, 0x01, 0x00, 0x00]
    );
}

#[test]
fn primitives_negint() {
    // -1 → 0x20
    assert_eq!(encode(&CborValue::NegInt(-1)).unwrap(), vec![0x20]);
    // -24 → 0x37
    assert_eq!(encode(&CborValue::NegInt(-24)).unwrap(), vec![0x37]);
    // -25 → 0x38 0x18
    assert_eq!(encode(&CborValue::NegInt(-25)).unwrap(), vec![0x38, 0x18]);
}

#[test]
fn primitives_text() {
    // "" → 0x60
    assert_eq!(encode(&CborValue::Text(String::new())).unwrap(), vec![0x60]);
    // "a" → 0x61 0x61
    assert_eq!(
        encode(&CborValue::Text("a".into())).unwrap(),
        vec![0x61, 0x61]
    );
}

#[test]
fn primitives_bytes() {
    assert_eq!(encode(&CborValue::Bytes(vec![])).unwrap(), vec![0x40]);
}

#[test]
fn primitives_bool_null() {
    assert_eq!(encode(&CborValue::Bool(false)).unwrap(), vec![0xF4]);
    assert_eq!(encode(&CborValue::Bool(true)).unwrap(), vec![0xF5]);
    assert_eq!(encode(&CborValue::Null).unwrap(), vec![0xF6]);
}

#[test]
fn primitives_float_f16() {
    // 0.0 → f9 00 00
    assert_eq!(
        encode(&CborValue::Float(0.0)).unwrap(),
        vec![0xF9, 0x00, 0x00]
    );
    // 1.0 → f9 3c 00
    assert_eq!(
        encode(&CborValue::Float(1.0)).unwrap(),
        vec![0xF9, 0x3C, 0x00]
    );
    // 1.5 → f9 3e 00
    assert_eq!(
        encode(&CborValue::Float(1.5)).unwrap(),
        vec![0xF9, 0x3E, 0x00]
    );
}

#[test]
fn primitives_empty_containers() {
    assert_eq!(encode(&CborValue::Array(vec![])).unwrap(), vec![0x80]);
    assert_eq!(encode(&CborValue::Map(vec![])).unwrap(), vec![0xA0]);
}

// ── Decoder strictness ───────────────────────────────────────────────

#[test]
fn reject_non_shortest_uint() {
    // 0 in 1-byte form
    assert!(decode_full(&[0x18, 0x00]).is_err());
    // 23 in 1-byte form
    assert!(decode_full(&[0x18, 0x17]).is_err());
    // 255 in 2-byte form
    assert!(decode_full(&[0x19, 0x00, 0xFF]).is_err());
    // 65535 in 4-byte form
    assert!(decode_full(&[0x1A, 0x00, 0x00, 0xFF, 0xFF]).is_err());
    // 4294967295 in 8-byte form
    assert!(decode_full(&[0x1B, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
}

#[test]
fn reject_indefinite_length() {
    // Indefinite byte string
    assert!(decode_full(&[0x5F, 0x41, 0x61, 0xFF]).is_err());
    // Indefinite array
    assert!(decode_full(&[0x9F, 0x01, 0xFF]).is_err());
}

#[test]
fn reject_unsorted_map_keys() {
    // {"b": 1, "a": 2} in wrong order
    assert!(decode_full(&[0xA2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02]).is_err());
}

#[test]
fn reject_trailing_bytes() {
    assert!(decode_full(&[0x01, 0x02]).is_err());
}

#[test]
fn reject_non_finite_f16() {
    // f16 NaN: f9 7e 00
    assert!(decode_full(&[0xF9, 0x7E, 0x00]).is_err());
    // f16 +Inf: f9 7c 00
    assert!(decode_full(&[0xF9, 0x7C, 0x00]).is_err());
}

// ── Round-trip for all primitives ────────────────────────────────────

#[test]
fn roundtrip_primitives() {
    let cases: Vec<CborValue> = vec![
        CborValue::Null,
        CborValue::Bool(false),
        CborValue::Bool(true),
        CborValue::Uint(0),
        CborValue::Uint(1),
        CborValue::Uint(23),
        CborValue::Uint(24),
        CborValue::Uint(255),
        CborValue::Uint(256),
        CborValue::Uint(65535),
        CborValue::Uint(65536),
        CborValue::Uint(u32::MAX as u64),
        CborValue::Uint(u32::MAX as u64 + 1),
        CborValue::NegInt(-1),
        CborValue::NegInt(-24),
        CborValue::NegInt(-25),
        CborValue::NegInt(-256),
        CborValue::Float(0.0),
        CborValue::Float(1.0),
        CborValue::Float(1.5),
        CborValue::Float(-0.5),
        CborValue::Float(3.141592653589793),
        CborValue::Text(String::new()),
        CborValue::Text("hello".into()),
        CborValue::Bytes(vec![]),
        CborValue::Bytes(vec![0, 1, 2]),
        CborValue::Array(vec![]),
        CborValue::Array(vec![CborValue::Uint(1), CborValue::Uint(2)]),
        CborValue::Map(vec![]),
        CborValue::Map(vec![
            (CborValue::Text("a".into()), CborValue::Uint(1)),
            (CborValue::Text("b".into()), CborValue::Uint(2)),
        ]),
    ];

    for val in &cases {
        let encoded = encode(val).unwrap_or_else(|e| panic!("encode {:?}: {}", val, e));
        let decoded =
            decode_full(&encoded).unwrap_or_else(|e| panic!("decode {:?}: {}", val, e));
        let re_encoded =
            encode(&decoded).unwrap_or_else(|e| panic!("re-encode {:?}: {}", val, e));
        assert_eq!(
            encoded, re_encoded,
            "round-trip failed for {:?}",
            val
        );
        assert_eq!(
            *val, decoded,
            "value mismatch for {:?}",
            val
        );
    }
}

// ── Map key ordering ─────────────────────────────────────────────────

#[test]
fn map_keys_sorted_canonical() {
    // Build map {"bb": 2, "a": 1, "aaa": 3} — encoder should sort by (len, lex)
    let m = CborValue::Map(vec![
        (CborValue::Text("bb".into()), CborValue::Uint(2)),
        (CborValue::Text("a".into()), CborValue::Uint(1)),
        (CborValue::Text("aaa".into()), CborValue::Uint(3)),
    ]);
    let encoded = encode(&m).unwrap();
    let decoded = decode_full(&encoded).unwrap();

    // After decode, keys should be in canonical order: "a", "bb", "aaa"
    if let CborValue::Map(entries) = &decoded {
        let keys: Vec<&str> = entries
            .iter()
            .map(|(k, _)| {
                if let CborValue::Text(s) = k {
                    s.as_str()
                } else {
                    panic!("non-text key")
                }
            })
            .collect();
        assert_eq!(keys, vec!["a", "bb", "aaa"]);
    } else {
        panic!("expected map");
    }
}

// ── H-2: Recursion depth limit ──────────────────────────────────────

#[test]
fn decode_rejects_excessive_nesting() {
    // Build a payload of 100 nested arrays: 0x81 = array(1)
    let mut payload = vec![0x81u8; 100];
    payload.push(0x00); // innermost: uint 0
    let result = decode_full(&payload);
    assert!(result.is_err(), "should reject nesting > MAX_DECODE_DEPTH");
    let err = result.unwrap_err().0;
    assert!(err.contains("nesting depth"), "error: {}", err);
}

// ── H-3: OOM guard on Vec::with_capacity ─────────────────────────────

#[test]
fn decode_rejects_huge_array_count() {
    // Array header claiming 2^32 elements but only 1 byte of data follows
    let payload = vec![0x9B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
    let result = decode_full(&payload);
    assert!(result.is_err(), "should fail on count > remaining bytes");
}

// ── H-4: NegInt i64 overflow guard ──────────────────────────────────

#[test]
fn decode_rejects_negint_overflow() {
    // Major type 1, 8-byte value = u64::MAX (0xFFFFFFFFFFFFFFFF)
    let payload = vec![0x3B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let result = decode_full(&payload);
    assert!(result.is_err(), "should reject NegInt exceeding i64 range");
    let err = result.unwrap_err().0;
    assert!(err.contains("i64 range"), "error: {}", err);
}

// ── L-1: Non-canonical float width ──────────────────────────────────

#[test]
fn decode_rejects_f32_when_f16_suffices() {
    // 0.0 encoded as f32 (0xFA 0x00000000) instead of f16 (0xF9 0x0000)
    let payload = vec![0xFA, 0x00, 0x00, 0x00, 0x00];
    let result = decode_full(&payload);
    assert!(result.is_err(), "should reject non-canonical f32 for 0.0");
    let err = result.unwrap_err().0;
    assert!(err.contains("non-canonical float"), "error: {}", err);
}

#[test]
fn decode_rejects_f64_when_f16_suffices() {
    // 0.0 encoded as f64 (0xFB ...) instead of f16
    let payload = vec![0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let result = decode_full(&payload);
    assert!(result.is_err(), "should reject non-canonical f64 for 0.0");
}

#[test]
fn decode_rejects_f64_when_f32_suffices() {
    // 1.5 encoded as f64 (0xFB 3FF8000000000000) instead of f16/f32
    let payload = vec![0xFB, 0x3F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let result = decode_full(&payload);
    assert!(result.is_err(), "should reject non-canonical f64 for 1.5");
}
