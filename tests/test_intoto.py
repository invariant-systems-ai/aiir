"""Tests for in-toto Statement v1 envelope wrapping."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from typing import Any, Dict

from aiir._receipt import wrap_in_toto_statement, INTOTO_PREDICATE_TYPE


def _make_receipt(**overrides: Any) -> Dict[str, Any]:
    """Build a minimal valid receipt for testing."""
    base: Dict[str, Any] = {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.0.14",
        "commit": {
            "sha": "abc123def456789",
            "author": {"name": "Test", "email": "test@example.com"},
            "subject": "test commit",
        },
        "ai_attestation": {
            "is_ai_authored": False,
            "authorship_class": "human",
        },
        "provenance": {
            "repository": "https://github.com/org/repo.git",
            "tool": "https://github.com/invariant-systems-ai/aiir@1.0.14",
        },
        "receipt_id": "g1-abcdef1234567890",
        "content_hash": "sha256:abcdef1234567890",
        "timestamp": "2026-03-09T00:00:00Z",
        "extensions": {},
    }
    base.update(overrides)
    return base


class TestInTotoWrapper(unittest.TestCase):
    """Tests for wrap_in_toto_statement()."""

    def test_basic_envelope_shape(self):
        """Envelope has required in-toto Statement v1 fields."""
        receipt = _make_receipt()
        stmt = wrap_in_toto_statement(receipt)

        self.assertEqual(stmt["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(stmt["predicateType"], INTOTO_PREDICATE_TYPE)
        self.assertEqual(stmt["predicateType"], "https://invariantsystems.io/predicates/aiir/commit_receipt/v1")
        self.assertIsInstance(stmt["subject"], list)
        self.assertEqual(len(stmt["subject"]), 1)
        self.assertIs(stmt["predicate"], receipt)

    def test_subject_name_format(self):
        """Subject name follows repo@sha convention."""
        receipt = _make_receipt()
        stmt = wrap_in_toto_statement(receipt)

        subject = stmt["subject"][0]
        self.assertEqual(subject["name"], "https://github.com/org/repo.git@abc123def456789")
        self.assertEqual(subject["digest"], {"gitCommit": "abc123def456789"})

    def test_subject_without_remote(self):
        """Subject uses 'unknown' when no repo URL."""
        receipt = _make_receipt(
            provenance={"repository": None, "tool": "aiir@1.0.14"}
        )
        stmt = wrap_in_toto_statement(receipt)

        subject = stmt["subject"][0]
        self.assertIn("unknown", subject["name"])

    def test_subject_without_sha(self):
        """Subject handles missing commit SHA gracefully."""
        receipt = _make_receipt(commit={})
        stmt = wrap_in_toto_statement(receipt)

        subject = stmt["subject"][0]
        self.assertEqual(subject["digest"]["gitCommit"], "")

    def test_predicate_is_original_receipt(self):
        """Predicate is the original receipt object (not a copy)."""
        receipt = _make_receipt()
        stmt = wrap_in_toto_statement(receipt)

        self.assertIs(stmt["predicate"], receipt)

    def test_envelope_is_json_serializable(self):
        """The envelope can be serialized to JSON."""
        receipt = _make_receipt()
        stmt = wrap_in_toto_statement(receipt)

        result = json.dumps(stmt, sort_keys=True)
        parsed = json.loads(result)
        self.assertEqual(parsed["_type"], "https://in-toto.io/Statement/v1")

    def test_credential_stripping_in_subject(self):
        """Credentials in repo URL are stripped from subject name."""
        receipt = _make_receipt(
            provenance={
                "repository": "https://user:pass@github.com/org/repo.git",
                "tool": "aiir@1.0.14",
            }
        )
        stmt = wrap_in_toto_statement(receipt)

        subject = stmt["subject"][0]
        self.assertNotIn("pass", subject["name"])
        self.assertNotIn("user:", subject["name"])

    def test_terminal_escape_sanitization(self):
        """Terminal escapes in commit data are sanitized."""
        receipt = _make_receipt(
            commit={
                "sha": "\x1b[31mmalicious\x1b[0m",
                "author": {"name": "Test"},
                "subject": "test",
            },
            provenance={
                "repository": "https://github.com/org/repo.git",
                "tool": "aiir",
            },
        )
        stmt = wrap_in_toto_statement(receipt)

        subject = stmt["subject"][0]
        self.assertNotIn("\x1b", subject["name"])
        self.assertNotIn("\x1b", subject["digest"]["gitCommit"])

    def test_non_dict_commit_field(self):
        """Handles non-dict commit field without crashing."""
        receipt = _make_receipt(commit="not-a-dict")
        stmt = wrap_in_toto_statement(receipt)

        self.assertEqual(stmt["subject"][0]["digest"]["gitCommit"], "")

    def test_non_dict_provenance_field(self):
        """Handles non-dict provenance field without crashing."""
        receipt = _make_receipt(provenance="not-a-dict")
        stmt = wrap_in_toto_statement(receipt)

        # Should not crash — falls back to unknown
        self.assertIn("unknown", stmt["subject"][0]["name"])

    def test_predicate_type_is_stable_uri(self):
        """Predicate type URI is the documented stable value."""
        self.assertEqual(INTOTO_PREDICATE_TYPE, "https://invariantsystems.io/predicates/aiir/commit_receipt/v1")

    def test_cli_flag_accepted(self):
        """CLI accepts --in-toto without error (basic smoke test)."""
        # Explicit cwd ensures `python -m aiir` can find the package
        # regardless of what previous tests did to os.getcwd().
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # Force UTF-8 encoding for subprocess stdout/stderr so the
        # Unicode arrows (→) in the help epilog don't crash argparse
        # on Windows where the default console encoding is cp1252.
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        result = subprocess.run(
            [sys.executable, "-m", "aiir", "--in-toto", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=repo_root,
            env=env,
        )
        self.assertEqual(
            result.returncode, 0,
            f"CLI exited {result.returncode}; stderr: {result.stderr[:500]}",
        )
        self.assertIn("--in-toto", result.stdout)


class TestInTotoIntegration(unittest.TestCase):
    """Integration tests for in-toto + receipt pipeline."""

    def test_wrapped_receipt_retains_all_fields(self):
        """All original receipt fields are preserved in the predicate."""
        receipt = _make_receipt()
        stmt = wrap_in_toto_statement(receipt)

        predicate = stmt["predicate"]
        self.assertEqual(predicate["type"], "aiir.commit_receipt")
        self.assertEqual(predicate["schema"], "aiir/commit_receipt.v1")
        self.assertEqual(predicate["receipt_id"], "g1-abcdef1234567890")
        self.assertEqual(predicate["content_hash"], "sha256:abcdef1234567890")

    def test_multiple_receipts_produce_independent_statements(self):
        """Each receipt gets its own statement (not batched)."""
        r1 = _make_receipt(commit={"sha": "aaa"})
        r2 = _make_receipt(commit={"sha": "bbb"})

        s1 = wrap_in_toto_statement(r1)
        s2 = wrap_in_toto_statement(r2)

        self.assertEqual(s1["subject"][0]["digest"]["gitCommit"], "aaa")
        self.assertEqual(s2["subject"][0]["digest"]["gitCommit"], "bbb")
        self.assertIsNot(s1, s2)


if __name__ == "__main__":
    unittest.main()
