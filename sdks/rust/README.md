# aiir-cbor-verify

Deterministic CBOR encoder, decoder, and verifier for
[AIIR](https://github.com/invariant-systems-ai/aiir) commit receipts.

## What it does

- **Encodes** AIIR receipts to canonical CBOR (RFC 8949 §4.2 deterministic encoding)
- **Decodes** CBOR with strict validation — rejects non-canonical forms
- **Verifies** CBOR sidecars by round-tripping through canonical JSON and checking SHA-256

This crate proves cross-language determinism: the same receipt produces the same
`content_hash` whether processed by the Python reference implementation or this
Rust crate.

## Canonicalization rules

| Rule | Detail |
|------|--------|
| Shortest integer encoding | Integers use the smallest CBOR head (1/2/4/8 bytes) |
| No indefinite-length | All strings, arrays, and maps use definite-length encoding |
| Sorted map keys | Keys sorted by `(encoded_length, encoded_bytes)` per RFC 8949 §4.2 |
| No NaN / Infinity | Non-finite IEEE 754 values rejected at encode time |
| Minimal float precision | Prefers f16, promotes to f32/f64 only when lossless round-trip requires it |

## Usage

```rust
use aiir_cbor_verify::{decode_full, verify_sidecar, CborValue};

// Decode a CBOR sidecar and verify its content hash
let cbor_bytes: &[u8] = &[/* ... */];
let json_bytes: &[u8] = &[/* corresponding JSON receipt */];

match verify_sidecar(cbor_bytes, json_bytes) {
    Ok(true)  => println!("CBOR sidecar is valid"),
    Ok(false) => println!("Hash mismatch — tampered"),
    Err(e)    => println!("Decode error: {}", e),
}
```

## Conformance

This crate passes the full AIIR conformance test suite:

- **24 CBOR golden vectors** — decode, re-encode, verify round-trip
- **Envelope validation** — Layer-0 structure checks
- **Sidecar verification** — CBOR → JSON → SHA-256 hash match
- **Strictness tests** — rejects non-shortest uint, indefinite-length, unsorted map keys, trailing bytes, NaN/Infinity

Tests load vectors from `schemas/cbor_test_vectors.json` in the AIIR repository.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
