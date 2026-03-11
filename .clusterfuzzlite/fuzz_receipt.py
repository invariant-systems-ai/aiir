#!/usr/bin/env python3
"""ClusterFuzzLite fuzz target for AIIR receipt verification.

Exercises the security-critical verify_receipt() and _canonical_json()
paths with arbitrary byte input. Any crash, hang, or unhandled exception
is a finding.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

import json
import sys

import atheris

with atheris.instrument_imports():
    from aiir._core import _canonical_json, _sha256
    from aiir._verify import verify_receipt


def TestOneInput(data: bytes) -> None:
    """Fuzz entry point called by ClusterFuzzLite/libFuzzer."""
    try:
        obj = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        return
    if not isinstance(obj, dict):
        return

    # SystemExit: atheris docs say to catch it explicitly when library code may
    # call sys.exit() (e.g. via Python package init importing entry-point code).
    # verify_receipt() is designed to always return a dict — any other exception
    # is a genuine finding and intentionally NOT caught here.
    try:
        verify_receipt(obj)
    except SystemExit:
        return

    try:
        canon = _canonical_json(obj)
    except (ValueError, RecursionError):
        return

    assert _canonical_json(obj) == canon, "canonical JSON not deterministic"
    assert _sha256(canon), "sha256 unexpectedly empty"

    reparsed = json.loads(canon)
    try:
        canon2 = _canonical_json(reparsed)
    except (ValueError, RecursionError):
        return
    assert canon == canon2, "canonical JSON not idempotent after round-trip"


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
