# Adversarial Test Corpus

Published adversarial fixtures for the **AIIR Commit Receipt** format.

Every fixture is a standalone JSON file containing a receipt (or receipt-like
payload) designed to test a specific adversarial pattern. Each fixture includes
metadata fields that describe the attack category, expected verifier behaviour,
and the targeted spec section.

## Directory layout

```text
tests/adversarial/
├── README.md                  ← this file
├── conftest.py                ← pytest auto-discovery + parametric runner
├── corpus.json                ← manifest: one entry per fixture
├── injection/                 ← injection & encoding attacks
├── tampering/                 ← hash/id/field tampering
├── parsing/                   ← parser edge-cases & resource exhaustion
└── bypass/                    ← detection evasion & logic bypass
```

## Fixture format

```json
{
  "id": "adv-INJ-001",
  "category": "injection",
  "description": "...",
  "spec_section": "§7",
  "receipt": { ... },
  "expected": {
    "valid": false,
    "must_reject": true,
    "error_pattern": "content hash mismatch"
  }
}
```

## Running

```bash
python -m pytest tests/adversarial/ -v
```

## Licence

Apache-2.0 — Copyright 2025-2026 Invariant Systems, Inc.
