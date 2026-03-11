"""Parametric test runner for the AIIR adversarial fixture corpus.

Auto-discovers all fixture JSON files and runs each through
``aiir._verify.verify_receipt``, asserting the expected outcome.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aiir._verify import verify_receipt

CORPUS_DIR = Path(__file__).parent
CATEGORIES = ["injection", "tampering", "parsing", "bypass"]


def _collect_fixtures():
    """Yield (fixture_id, fixture_dict) for all *.json in category dirs."""
    for cat in CATEGORIES:
        cat_dir = CORPUS_DIR / cat
        if not cat_dir.is_dir():
            continue
        for fp in sorted(cat_dir.glob("*.json")):
            data = json.loads(fp.read_text(encoding="utf-8"))
            yield data["id"], data


_FIXTURES = list(_collect_fixtures())


@pytest.mark.parametrize(
    "fixture_id,fixture",
    [(fid, f) for fid, f in _FIXTURES],
    ids=[fid for fid, _ in _FIXTURES],
)
def test_adversarial_fixture(fixture_id, fixture):
    """Run a single adversarial fixture through verify_receipt."""
    receipt = fixture["receipt"]
    expected = fixture["expected"]

    result = verify_receipt(receipt)

    if expected["must_reject"]:
        assert not result["valid"], (
            f"{fixture_id}: expected rejection but got valid=True"
        )
        if expected.get("error_pattern"):
            errors_str = " ".join(result.get("errors", []))
            assert expected["error_pattern"] in errors_str, (
                f"{fixture_id}: expected error containing "
                f"{expected['error_pattern']!r}, got {result['errors']}"
            )
    else:
        assert result["valid"], (
            f"{fixture_id}: expected valid=True but got errors={result.get('errors')}"
        )
