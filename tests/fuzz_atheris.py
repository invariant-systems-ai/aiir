#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Invariant Systems AI
"""
Atheris-based coverage-guided fuzzing for AIIR security-critical functions.

This harness targets the same entry points as Hypothesis property tests but
uses coverage-guided mutation (libFuzzer via Atheris) to explore code paths
that random generation alone might miss.

Run locally:
    pip install atheris
    python tests/fuzz_atheris.py -max_total_time=60

CI integration:
    The tests/test_fuzz.py (Hypothesis) provides equivalent coverage in CI.
    This file exists for:
      1. OpenSSF Scorecard Fuzzing detection (fuzzedWithPythonAtheris probe)
      2. Deep fuzzing campaigns beyond random generation

Targets:
    - Receipt schema validation (_schema.py)
    - Signature verification (_verify.py)
    - AI detection heuristics (_detect.py)
    - JSON canonicalization (_receipt.py)
"""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


def fuzz_schema_validation(data: bytes) -> None:
    """Fuzz the receipt schema validator with arbitrary JSON-like input."""
    from aiir._schema import validate_receipt

    try:
        payload = json.loads(data)
        if not isinstance(payload, dict):
            return
        validate_receipt(payload)
    except (json.JSONDecodeError, TypeError, ValueError, KeyError):
        pass


def fuzz_verify_receipt(data: bytes) -> None:
    """Fuzz the receipt verifier with arbitrary bytes."""
    from aiir._verify import verify_receipt

    try:
        payload = json.loads(data)
        if not isinstance(payload, dict):
            return
        verify_receipt(payload)
    except (json.JSONDecodeError, TypeError, ValueError, KeyError):
        pass


def fuzz_detect_ai(data: bytes) -> None:
    """Fuzz AI detection with arbitrary commit message bytes."""
    from aiir._detect import detect_ai_commit

    try:
        message = data.decode("utf-8", errors="replace")
        detect_ai_commit(message)
    except (TypeError, ValueError, UnicodeDecodeError):
        pass


def fuzz_canonicalize(data: bytes) -> None:
    """Fuzz JSON canonicalization with arbitrary input."""
    from aiir._receipt import _canonicalize

    try:
        payload = json.loads(data)
        _canonicalize(payload)
    except (json.JSONDecodeError, TypeError, ValueError):
        pass


def main() -> None:
    """Entry point for Atheris fuzzing."""
    try:
        import atheris  # type: ignore[import-untyped]
    except ImportError:
        print("atheris not installed — install with: pip install atheris")
        sys.exit(0)

    # Register all fuzz targets with coverage instrumentation
    atheris.instrument_all()

    targets = [
        fuzz_schema_validation,
        fuzz_verify_receipt,
        fuzz_detect_ai,
        fuzz_canonicalize,
    ]

    # Pick target based on env or default to schema validation
    import os

    target_name = os.environ.get("FUZZ_TARGET", "schema")
    target_map = {
        "schema": fuzz_schema_validation,
        "verify": fuzz_verify_receipt,
        "detect": fuzz_detect_ai,
        "canonicalize": fuzz_canonicalize,
    }
    target = target_map.get(target_name, targets[0])

    atheris.Setup(sys.argv, target)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
