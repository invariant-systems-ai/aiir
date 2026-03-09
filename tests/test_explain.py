"""
Tests for aiir._explain — human-readable verification explanations.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import unittest

from aiir._explain import explain_verification


class TestExplainVerification(unittest.TestCase):
    """Tests for explain_verification()."""

    def test_valid_receipt_explanation(self):
        result = {
            "valid": True,
            "receipt_id": "g1-abc123",
            "content_hash_match": True,
            "receipt_id_match": True,
        }
        text = explain_verification(result)
        self.assertIn("VERIFICATION PASSED", text)
        self.assertIn("SHA-256", text)
        self.assertIn("not been modified", text)
        self.assertIn("does NOT prove", text)
        self.assertIn("Sigstore", text)

    def test_hash_mismatch_explanation(self):
        result = {
            "valid": False,
            "errors": ["content hash mismatch"],
        }
        text = explain_verification(result)
        self.assertIn("VERIFICATION FAILED", text)
        self.assertIn("modified after creation", text)
        self.assertIn("Common causes", text)
        self.assertIn("Regenerate", text)

    def test_both_hash_and_id_mismatch(self):
        result = {
            "valid": False,
            "errors": ["content hash mismatch", "receipt_id mismatch"],
        }
        text = explain_verification(result)
        self.assertIn("Both content_hash and receipt_id", text)

    def test_id_only_mismatch(self):
        result = {
            "valid": False,
            "errors": ["receipt_id mismatch"],
        }
        text = explain_verification(result)
        self.assertIn("receipt_id does not match", text)

    def test_not_a_dict(self):
        result = {
            "valid": False,
            "errors": ["receipt is not a dict"],
        }
        text = explain_verification(result)
        self.assertIn("not a valid receipt", text)
        self.assertIn("JSON object", text)

    def test_unknown_type(self):
        result = {
            "valid": False,
            "errors": ["unknown receipt type: 'other.type'"],
        }
        text = explain_verification(result)
        self.assertIn("doesn't look like an AIIR receipt", text)

    def test_unknown_schema(self):
        result = {
            "valid": False,
            "errors": ["unknown schema: 'bad/schema'"],
        }
        text = explain_verification(result)
        self.assertIn("doesn't look like an AIIR receipt", text)

    def test_invalid_version(self):
        result = {
            "valid": False,
            "errors": ["invalid version format: '<script>'"],
        }
        text = explain_verification(result)
        self.assertIn("version field", text)

    def test_too_deeply_nested(self):
        result = {
            "valid": False,
            "errors": ["receipt structure too deeply nested"],
        }
        text = explain_verification(result)
        self.assertIn("too deeply nested", text)
        self.assertIn("64", text)

    def test_schema_errors_appended(self):
        result = {
            "valid": True,
            "receipt_id": "g1-abc",
            "schema_errors": [
                "commit.sha: required field missing",
                "version: pattern mismatch",
            ],
        }
        text = explain_verification(result)
        self.assertIn("VERIFICATION PASSED", text)
        self.assertIn("Schema warnings (2)", text)
        self.assertIn("commit.sha", text)

    def test_schema_errors_capped_at_10(self):
        result = {
            "valid": False,
            "errors": ["content hash mismatch"],
            "schema_errors": [f"error_{i}" for i in range(15)],
        }
        text = explain_verification(result)
        self.assertIn("... and 5 more", text)


class TestExplainVerificationCLI(unittest.TestCase):
    """Test that --explain integrates with the CLI."""

    def test_explain_flag_accepted(self):
        """--explain must be accepted by the argument parser."""
        import aiir.cli as cli

        # Just check the parser accepts it (doesn't error).
        parser = cli._FriendlyParser(prog="aiir")
        parser.add_argument("--explain", action="store_true")
        ns = parser.parse_args(["--explain"])
        self.assertTrue(ns.explain)


if __name__ == "__main__":
    unittest.main()
