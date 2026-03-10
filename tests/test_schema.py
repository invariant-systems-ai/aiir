"""
Tests for aiir._schema — receipt structural validation.

Tests the schema validation module against valid receipts, invalid receipts,
and the published conformance test vectors.

Copyright 2025-2026 Invariant Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any, Dict

from aiir._schema import validate_receipt_schema
from aiir._verify import verify_receipt


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_valid_receipt(**overrides: Any) -> Dict[str, Any]:
    """Build a structurally valid receipt for testing."""
    import hashlib

    def _sha256(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def _canonical_json(obj: Any) -> str:
        return json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )

    core = {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.0.12",
        "commit": {
            "sha": "a" * 40,
            "author": {
                "name": "Test",
                "email": "test@example.com",
                "date": "2026-01-01T00:00:00Z",
            },
            "committer": {
                "name": "Test",
                "email": "test@example.com",
                "date": "2026-01-01T00:00:00Z",
            },
            "subject": "test commit",
            "message_hash": "sha256:" + _sha256("test"),
            "diff_hash": "sha256:" + _sha256("diff"),
            "files_changed": 1,
            "files": ["test.py"],
        },
        "ai_attestation": {
            "is_ai_authored": False,
            "signals_detected": [],
            "signal_count": 0,
            "is_bot_authored": False,
            "bot_signals_detected": [],
            "bot_signal_count": 0,
            "authorship_class": "human",
            "detection_method": "heuristic_v2",
        },
        "provenance": {
            "repository": "https://github.com/example/repo",
            "tool": "https://github.com/invariant-systems-ai/aiir@1.0.12",
            "generator": "aiir.cli",
        },
    }
    core.update(overrides)

    CORE_KEYS = {"type", "schema", "version", "commit", "ai_attestation", "provenance"}
    core_subset = {k: v for k, v in core.items() if k in CORE_KEYS}
    cj = _canonical_json(core_subset)
    receipt = {
        **core,
        "receipt_id": "g1-" + _sha256(cj)[:32],
        "content_hash": "sha256:" + _sha256(cj),
        "timestamp": "2026-01-01T00:00:00Z",
        "extensions": {},
    }
    return receipt


# ---------------------------------------------------------------------------
# Schema validation tests
# ---------------------------------------------------------------------------


class TestValidateReceiptSchema(unittest.TestCase):
    """Tests for validate_receipt_schema()."""

    def test_valid_receipt_has_no_errors(self):
        receipt = _make_valid_receipt()
        errors = validate_receipt_schema(receipt)
        self.assertEqual(errors, [], f"Unexpected errors: {errors}")

    def test_not_a_dict(self):
        errors = validate_receipt_schema("not a dict")
        self.assertEqual(len(errors), 1)
        self.assertIn("not a JSON object", errors[0])

    def test_not_a_dict_list(self):
        errors = validate_receipt_schema([1, 2, 3])
        self.assertIn("not a JSON object", errors[0])

    def test_missing_type(self):
        r = _make_valid_receipt()
        del r["type"]
        errors = validate_receipt_schema(r)
        self.assertTrue(any("type" in e and "required" in e for e in errors))

    def test_wrong_type_value(self):
        r = _make_valid_receipt()
        r["type"] = "wrong.type"
        errors = validate_receipt_schema(r)
        self.assertTrue(any("aiir.commit_receipt" in e for e in errors))

    def test_wrong_schema_value(self):
        r = _make_valid_receipt()
        r["schema"] = "other/schema.v2"
        errors = validate_receipt_schema(r)
        self.assertTrue(any("aiir/commit_receipt.v1" in e for e in errors))

    def test_invalid_version_format(self):
        r = _make_valid_receipt()
        r["version"] = "<script>alert(1)</script>"
        errors = validate_receipt_schema(r)
        self.assertTrue(any("version" in e for e in errors))

    def test_valid_version_with_prerelease(self):
        r = _make_valid_receipt(version="1.0.12-beta.1+build.42")
        errors = validate_receipt_schema(r)
        # Filter only version errors
        version_errors = [e for e in errors if "version" in e.lower()]
        self.assertEqual(version_errors, [])

    def test_invalid_receipt_id_pattern(self):
        r = _make_valid_receipt()
        r["receipt_id"] = "bad-id"
        errors = validate_receipt_schema(r)
        self.assertTrue(any("receipt_id" in e for e in errors))

    def test_invalid_content_hash_pattern(self):
        r = _make_valid_receipt()
        r["content_hash"] = "md5:abc123"
        errors = validate_receipt_schema(r)
        self.assertTrue(any("content_hash" in e for e in errors))

    def test_missing_commit_sha(self):
        r = _make_valid_receipt()
        del r["commit"]["sha"]
        errors = validate_receipt_schema(r)
        self.assertTrue(any("commit.sha" in e for e in errors))

    def test_invalid_commit_sha_pattern(self):
        r = _make_valid_receipt()
        r["commit"]["sha"] = "ZZZZ"
        errors = validate_receipt_schema(r)
        self.assertTrue(any("commit.sha" in e and "hex" in e for e in errors))

    def test_missing_author_fields(self):
        r = _make_valid_receipt()
        r["commit"]["author"] = {}
        errors = validate_receipt_schema(r)
        self.assertTrue(any("commit.author.name" in e for e in errors))
        self.assertTrue(any("commit.author.email" in e for e in errors))
        self.assertTrue(any("commit.author.date" in e for e in errors))

    def test_files_and_files_redacted_mutually_exclusive(self):
        r = _make_valid_receipt()
        r["commit"]["files_redacted"] = True
        # Now has both files AND files_redacted
        errors = validate_receipt_schema(r)
        self.assertTrue(any("either" in e for e in errors))

    def test_files_redacted_valid(self):
        r = _make_valid_receipt()
        del r["commit"]["files"]
        r["commit"]["files_redacted"] = True
        errors = validate_receipt_schema(r)
        # Only errors should be from hash mismatch in other validators, not schema
        schema_file_errors = [e for e in errors if "files" in e]
        self.assertEqual(schema_file_errors, [])

    def test_files_too_many(self):
        r = _make_valid_receipt()
        r["commit"]["files"] = [f"file{i}.py" for i in range(101)]
        errors = validate_receipt_schema(r)
        self.assertTrue(any("100" in e for e in errors))

    def test_files_non_string_item(self):
        r = _make_valid_receipt()
        r["commit"]["files"] = ["ok.py", 42]
        errors = validate_receipt_schema(r)
        self.assertTrue(any("files[1]" in e for e in errors))

    def test_signal_count_mismatch(self):
        r = _make_valid_receipt()
        r["ai_attestation"]["signal_count"] = 5
        errors = validate_receipt_schema(r)
        self.assertTrue(any("signal_count" in e for e in errors))

    def test_invalid_authorship_class(self):
        r = _make_valid_receipt()
        r["ai_attestation"]["authorship_class"] = "cyborg"
        errors = validate_receipt_schema(r)
        self.assertTrue(any("authorship_class" in e for e in errors))

    def test_valid_authorship_classes(self):
        # Canonical forms + legacy forms accepted for backward compat
        for cls in (
            "human",
            "ai_assisted",
            "ai_generated",
            "bot",
            "ai+bot",
            "ai-assisted",
            "ai-generated",
            "bot-generated",
        ):
            r = _make_valid_receipt()
            r["ai_attestation"]["authorship_class"] = cls
            errors = validate_receipt_schema(r)
            class_errors = [e for e in errors if "authorship_class" in e]
            self.assertEqual(class_errors, [], f"Failed for class {cls}")

    def test_null_repository_valid(self):
        r = _make_valid_receipt()
        r["provenance"]["repository"] = None
        errors = validate_receipt_schema(r)
        repo_errors = [e for e in errors if "repository" in e]
        self.assertEqual(repo_errors, [])

    def test_repository_wrong_type(self):
        r = _make_valid_receipt()
        r["provenance"]["repository"] = 42
        errors = validate_receipt_schema(r)
        self.assertTrue(
            any("repository" in e and "string or null" in e for e in errors)
        )

    def test_invalid_tool_uri(self):
        r = _make_valid_receipt()
        r["provenance"]["tool"] = "http://evil.com/tool"
        errors = validate_receipt_schema(r)
        self.assertTrue(any("tool" in e for e in errors))

    def test_missing_extensions(self):
        r = _make_valid_receipt()
        del r["extensions"]
        errors = validate_receipt_schema(r)
        self.assertTrue(any("extensions" in e for e in errors))

    def test_bool_is_not_int(self):
        """Python's bool is a subclass of int — schema validator must distinguish."""
        r = _make_valid_receipt()
        r["commit"]["files_changed"] = True  # bool, not int
        errors = validate_receipt_schema(r)
        self.assertTrue(any("files_changed" in e and "bool" in e for e in errors))

    def test_int_is_not_bool(self):
        r = _make_valid_receipt()
        r["ai_attestation"]["is_ai_authored"] = 1  # int, not bool
        errors = validate_receipt_schema(r)
        self.assertTrue(any("is_ai_authored" in e for e in errors))

    def test_bot_signal_count_mismatch(self):
        r = _make_valid_receipt()
        r["ai_attestation"]["bot_signal_count"] = 99
        errors = validate_receipt_schema(r)
        self.assertTrue(any("bot_signal_count" in e for e in errors))

    def test_negative_files_changed(self):
        r = _make_valid_receipt()
        r["commit"]["files_changed"] = -1
        errors = validate_receipt_schema(r)
        self.assertTrue(any("files_changed" in e for e in errors))

    def test_extensions_with_custom_keys(self):
        r = _make_valid_receipt()
        r["extensions"] = {"instance_id": "prod", "namespace": "web", "custom": True}
        errors = validate_receipt_schema(r)
        ext_errors = [e for e in errors if "extensions" in e]
        self.assertEqual(ext_errors, [], "Custom extension keys should be allowed")


# ---------------------------------------------------------------------------
# Schema validation integration with verify_receipt
# ---------------------------------------------------------------------------


class TestVerifyReceiptSchemaIntegration(unittest.TestCase):
    """Verify that verify_receipt() includes schema_errors in result."""

    def test_valid_receipt_no_schema_errors(self):
        r = _make_valid_receipt()
        result = verify_receipt(r)
        self.assertTrue(result["valid"])
        self.assertNotIn("schema_errors", result)

    def test_invalid_fields_reported_as_schema_errors(self):
        r = _make_valid_receipt()
        # Make structurally invalid but keep hash valid
        r["commit"]["files_changed"] = True  # bool not int
        result = verify_receipt(r)
        # Hash check may still pass since canonical JSON doesn't distinguish
        # but schema_errors should be present
        self.assertIn("schema_errors", result)
        self.assertTrue(any("files_changed" in e for e in result["schema_errors"]))


# ---------------------------------------------------------------------------
# Conformance test vector runner
# ---------------------------------------------------------------------------


class TestConformanceVectors(unittest.TestCase):
    """Run all published conformance test vectors against verify_receipt()."""

    @classmethod
    def setUpClass(cls):
        vectors_path = Path(__file__).parent.parent / "schemas" / "test_vectors.json"
        if not vectors_path.exists():
            raise unittest.SkipTest(f"Test vectors not found: {vectors_path}")
        with open(vectors_path) as f:
            doc = json.load(f)
        cls.vectors = doc["vectors"]

    def test_all_vectors_pass(self):
        """Every test vector must produce the expected verification result."""
        failures = []
        for tv in self.vectors:
            result = verify_receipt(tv["receipt"])
            expected_valid = tv["expected"]["valid"]
            expected_errors = tv["expected"]["errors"]

            if result["valid"] != expected_valid:
                failures.append(
                    f"{tv['id']}: expected valid={expected_valid}, "
                    f"got valid={result['valid']}, errors={result.get('errors', '')}"
                )
                continue

            if not expected_valid:
                for err in expected_errors:
                    if err not in result.get("errors", []):
                        failures.append(
                            f"{tv['id']}: expected error '{err}' not in "
                            f"{result.get('errors', [])}"
                        )

        if failures:
            self.fail(
                f"{len(failures)} test vector(s) failed:\n"
                + "\n".join(f"  - {f}" for f in failures)
            )

    def test_vector_count(self):
        """Ensure we're testing a meaningful number of vectors."""
        self.assertGreaterEqual(len(self.vectors), 15)


if __name__ == "__main__":
    unittest.main()
