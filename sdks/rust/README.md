# aiir-cbor-verify

Deterministic CBOR encoder, decoder, and verifier for
[AIIR](https://github.com/invariant-systems-ai/aiir) commit receipts.

## What it does

- **Decodes** CBOR with strict validation — rejects non-canonical forms
- **Verifies** CBOR sidecars by round-tripping through canonical JSON and checking SHA-256
- Proves **cross-language determinism**: the same receipt produces the same
  `content_hash` whether processed by the Python reference implementation or this
  Rust crate

## Canonicalization rules

| Rule | Detail |
|------|--------|
| Shortest integer encoding | Integers use the smallest CBOR head (1/2/4/8 bytes) |
| No indefinite-length | All containers use definite length |
| Deterministic map key order | Sorted by (encoded-length, lexicographic-bytes) |
| No non-finite floats | NaN, ±Inf rejected |

See [RFC 8949 §4.2](https://www.rfc-editor.org/rfc/rfc8949#section-4.2) and the
[AIIR SPEC](https://github.com/invariant-systems-ai/aiir/blob/main/SPEC.md) for details.

## Usage

```toml
[dependencies]
aiir-cbor-verify = "0.1"
```

```rust
use aiir_cbor_verify::{decode, CborValue};

let cbor_bytes: &[u8] = &[/* CBOR-encoded receipt */];
let value: CborValue = decode(cbor_bytes)?;
```

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
