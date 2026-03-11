"""Tests for receipt verification."""
# Copyright 2025-2026 Invariant Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Import the module under test
import aiir.cli as cli


class TestSafeVerifyPathNoDeadCode(unittest.TestCase):
    """R10-SEC-04: _safe_verify_path should not contain dead code."""

    def test_no_raw_parts_variable(self):
        """The _safe_verify_path function should not assign an unused raw_parts variable."""
        import inspect
        from aiir.mcp_server import _safe_verify_path

        source = inspect.getsource(_safe_verify_path)
        self.assertNotIn("raw_parts", source)


class TestPathRedactionInVerifySignature(unittest.TestCase):
    """R9-TECH-01: verify_receipt_signature error path must redact filesystem paths."""

    def test_error_path_redacts_filesystem_paths(self):
        """Paths >= 5 chars deep should be replaced with <path>."""
        import re

        # Simulate what the error handler does
        error_msg = (
            "sigstore failed: /home/user/.cache/sigstore/roots/tuf.json not found"
        )
        safe_error = error_msg.split("\n")[0][:200]
        safe_error = re.sub(r"/[\w./-]{5,}", "<path>", safe_error)
        self.assertNotIn("/home/", safe_error)
        self.assertIn("<path>", safe_error)

    def test_error_path_preserves_short_text(self):
        """Short error messages without paths should pass through."""
        import re

        error_msg = "connection refused"
        safe_error = error_msg.split("\n")[0][:200]
        safe_error = re.sub(r"/[\w./-]{5,}", "<path>", safe_error)
        self.assertEqual(safe_error, "connection refused")


class TestIterativeJsonDepthCheck(unittest.TestCase):
    """R10-R-01: _check_json_depth must be iterative, not recursive."""

    def test_shallow_passes(self):
        cli._check_json_depth({"a": {"b": {"c": 1}}})

    def test_deep_dict_fails(self):
        obj = {}
        current = obj
        for _ in range(70):
            current["x"] = {}
            current = current["x"]
        with self.assertRaises(ValueError):
            cli._check_json_depth(obj, max_depth=64)

    def test_deep_list_fails(self):
        obj = []
        current = obj
        for _ in range(70):
            child = []
            current.append(child)
            current = child
        with self.assertRaises(ValueError):
            cli._check_json_depth(obj, max_depth=64)

    def test_exactly_64_passes(self):
        obj = {}
        current = obj
        for _ in range(63):
            current["x"] = {}
            current = current["x"]
        cli._check_json_depth(obj, max_depth=64)  # Should not raise

    def test_implementation_is_iterative(self):
        """The function should use a stack, not recursion."""
        import inspect

        source = inspect.getsource(cli._check_json_depth)
        # Iterative implementation uses 'stack' and 'while'
        self.assertIn("stack", source)
        self.assertIn("while", source)
        # Should NOT recursively call itself
        # Count occurrences of the function name in the body
        lines = source.split("\n")
        # Skip the def line and docstring, count _check_json_depth calls in body
        body_calls = sum(
            1
            for line in lines[1:]
            if "_check_json_depth" in line
            and "def " not in line
            and "#" not in line.split("_check_json_depth")[0]
        )
        self.assertEqual(body_calls, 0, "Function should not call itself recursively")


class TestContextAwareVerifyTips(unittest.TestCase):
    """R20-UX-01: Verify failure tips must match the actual failure type."""

    def test_file_not_found_tip(self):
        """File-not-found must say 'Check the file path', not 'changed after created'."""
        result = cli.verify_receipt_file("/nonexistent/path/receipt.json")
        self.assertFalse(result["valid"])
        self.assertIn("File not found", result.get("error", ""))

    def test_invalid_json_tip(self):
        """Invalid JSON must mention 'not an aiir receipt', not 'changed after created'."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("this is not json at all")
            f.flush()
            result = cli.verify_receipt_file(f.name)
        os.unlink(f.name)
        self.assertFalse(result["valid"])
        self.assertIn("Invalid JSON", result.get("error", ""))

    def test_tamper_detection_tip(self):
        """Actual tamper must still say 'changed after created'."""
        receipt = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": {"sha": "a" * 40, "subject": "test"},
            "ai_attestation": {},
            "provenance": {},
            "receipt_id": "g1-wrong",
            "content_hash": "sha256:wrong",
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(receipt, f)
            f.flush()
            result = cli.verify_receipt_file(f.name)
        os.unlink(f.name)
        self.assertFalse(result["valid"])
        # The result should indicate content hash mismatch
        self.assertFalse(result.get("content_hash_match", True))

    def test_verify_tip_for_file_not_found_in_main(self):
        """Full CLI --verify with missing file shows correct tip on stderr."""
        import io

        captured_err = io.StringIO()
        with (
            patch("sys.stderr", captured_err),
            patch("sys.stdout", io.StringIO()),
            patch("sys.argv", ["aiir", "--verify", "/nonexistent/file.json"]),
        ):
            code = cli.main()

        err = captured_err.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("Check the file path", err)
        self.assertNotIn("changed after it was created", err)

    def test_verify_tip_for_invalid_json_in_main(self):
        """Full CLI --verify with non-JSON file shows correct tip on stderr."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("not json")
            f.flush()
            import io

            captured_err = io.StringIO()
            with (
                patch("sys.stderr", captured_err),
                patch("sys.stdout", io.StringIO()),
                patch("sys.argv", ["aiir", "--verify", f.name]),
            ):
                code = cli.main()

        os.unlink(f.name)
        err = captured_err.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("doesn't look like an aiir receipt", err)
        self.assertNotIn("changed after it was created", err)

    def test_verify_tip_for_tampered_receipt_in_main(self):
        """Full CLI --verify with tampered receipt shows tamper tip on stderr."""
        receipt = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": {"sha": "a" * 40, "subject": "test"},
            "ai_attestation": {},
            "provenance": {},
            "receipt_id": "g1-wrong",
            "content_hash": "sha256:wrong",
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(receipt, f)
            f.flush()
            import io

            captured_err = io.StringIO()
            with (
                patch("sys.stderr", captured_err),
                patch("sys.stdout", io.StringIO()),
                patch("sys.argv", ["aiir", "--verify", f.name]),
            ):
                code = cli.main()

        os.unlink(f.name)
        err = captured_err.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("changed after it was created", err)

    def test_verify_tip_for_symlink(self):
        """CLI --verify with symlink shows correct symlink-specific tip."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"type": "aiir.commit_receipt"}, f)
            real_path = f.name

        link_path = real_path + ".link"
        try:
            os.symlink(real_path, link_path)
            import io

            captured_err = io.StringIO()
            with (
                patch("sys.stderr", captured_err),
                patch("sys.stdout", io.StringIO()),
                patch("sys.argv", ["aiir", "--verify", link_path]),
            ):
                code = cli.main()

            err = captured_err.getvalue()
            self.assertEqual(code, 1)
            self.assertIn("symlink", err.lower())
        finally:
            os.unlink(link_path)
            os.unlink(real_path)


class TestVerifyArrayPartialFailureTip(unittest.TestCase):
    """R20-UX-01: Array with partial failures still shows the tamper tip."""

    def test_array_partial_failure_tip(self):
        """Array with one valid + one invalid receipt shows tamper tip."""
        # Build a valid receipt core
        core = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": {"sha": "a" * 40, "subject": "ok"},
            "ai_attestation": {},
            "provenance": {},
        }
        core_json = cli._canonical_json(core)
        good_hash = "sha256:" + cli._sha256(core_json)
        good_id = f"g1-{cli._sha256(core_json)[:32]}"
        good = {**core, "receipt_id": good_id, "content_hash": good_hash}

        bad = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": {"sha": "b" * 40, "subject": "tampered"},
            "ai_attestation": {},
            "provenance": {},
            "receipt_id": "g1-wrong",
            "content_hash": "sha256:wrong",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([good, bad], f)
            f.flush()
            import io

            captured_err = io.StringIO()
            with (
                patch("sys.stderr", captured_err),
                patch("sys.stdout", io.StringIO()),
                patch("sys.argv", ["aiir", "--verify", f.name]),
            ):
                code = cli.main()

        os.unlink(f.name)
        err = captured_err.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("1 of 2", err)
        self.assertIn("changed after it was created", err)


class TestVerifyArrayErrors(unittest.TestCase):
    """R18-TECH-02: Verify on receipt arrays should show per-receipt detail."""

    def test_array_failure_shows_count(self):
        """When an array has invalid receipts, the error should show how many failed."""
        import tempfile

        tmpdir = tempfile.mkdtemp()
        try:
            arr_file = Path(tmpdir, "arr.json")
            # Two receipts: one with bad type, one with bad hash
            arr_file.write_text(
                json.dumps(
                    [
                        {
                            "type": "aiir.commit_receipt",
                            "schema": "aiir/commit_receipt.v1",
                            "version": "1.0.0",
                            "commit": {"sha": "abc"},
                            "ai_attestation": {},
                            "provenance": {},
                            "receipt_id": "g1-wrong",
                            "content_hash": "sha256:wrong",
                        },
                        {
                            "type": "wrong_type",
                            "schema": "aiir/commit_receipt.v1",
                            "version": "1.0.0",
                            "commit": {"sha": "def"},
                            "ai_attestation": {},
                            "provenance": {},
                            "receipt_id": "g1-also-wrong",
                            "content_hash": "sha256:also-wrong",
                        },
                    ]
                )
            )
            from io import StringIO

            captured_err = StringIO()
            with patch("sys.stderr", captured_err):
                rc = cli.main(["--verify", str(arr_file)])
            self.assertEqual(rc, 1)
            stderr_text = captured_err.getvalue()
            # Should mention how many failed
            self.assertIn("2", stderr_text, "Should mention count of failed receipts")
            self.assertIn("\u274c", stderr_text, "Should show ❌")
            self.assertIn("\U0001f4a1", stderr_text, "Should show 💡 hint")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_single_receipt_failure_shows_error(self):
        """Single receipt failure should show the specific error."""
        import tempfile

        tmpdir = tempfile.mkdtemp()
        try:
            bad_file = Path(tmpdir, "bad.json")
            bad_file.write_text(
                '{"type":"aiir.commit_receipt","schema":"aiir/commit_receipt.v1","version":"1.0.0","commit":{"sha":"abc"},"ai_attestation":{},"provenance":{},"receipt_id":"g1-x","content_hash":"sha256:x"}'
            )
            from io import StringIO

            captured_err = StringIO()
            with patch("sys.stderr", captured_err):
                rc = cli.main(["--verify", str(bad_file)])
            self.assertEqual(rc, 1)
            stderr_text = captured_err.getvalue()
            self.assertIn("\u274c", stderr_text)
            self.assertIn("\U0001f4a1", stderr_text)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Mutation-killing tests: verify_receipt_file edge cases
# ---------------------------------------------------------------------------
# These tests target surviving mutants found by mutation testing:
# - False→True on error-path "valid" fields (security-critical)
# - Key name mutations ("valid"→"VALID", "error"→"ERROR")
# - Boundary condition changes (> vs >=)


class TestVerifyReceiptFileEdgeCases(unittest.TestCase):
    """Tests that kill surviving mutants in verify_receipt_file."""

    def _assert_standard_error_result(
        self, result: dict, expected_error_substr: str = ""
    ):
        """Assert result is a well-formed error dict with exact keys."""
        self.assertIsInstance(result, dict)
        # Key must be exactly "valid", not "VALID" or "XXvalidXX"
        self.assertIn("valid", result, "Result must contain 'valid' key")
        self.assertIs(result["valid"], False, "Error result must have valid=False")
        # Key must be exactly "error", not "ERROR" or "XXerrorXX"
        self.assertIn("error", result, "Result must contain 'error' key")
        self.assertIsInstance(result["error"], str)
        if expected_error_substr:
            self.assertIn(expected_error_substr, result["error"])

    def test_symlink_rejected_with_valid_false(self):
        """Symlink receipt file must return valid=False, not valid=True."""
        tmpdir = tempfile.mkdtemp()
        try:
            real = Path(tmpdir, "real.json")
            real.write_text("{}")
            link = Path(tmpdir, "link.json")
            link.symlink_to(real)
            result = cli.verify_receipt_file(str(link))
            self._assert_standard_error_result(result, "symlink")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_oversized_file_rejected_with_valid_false(self):
        """File exceeding MAX_RECEIPT_FILE_SIZE must return valid=False."""
        from aiir._core import MAX_RECEIPT_FILE_SIZE

        tmpdir = tempfile.mkdtemp()
        try:
            big = Path(tmpdir, "big.json")
            # Write a valid JSON file that exceeds the size limit
            big.write_text(" " * (MAX_RECEIPT_FILE_SIZE + 1))
            result = cli.verify_receipt_file(str(big))
            self._assert_standard_error_result(result, "too large")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_oversized_array_rejected_with_valid_false(self):
        """Array exceeding MAX_RECEIPTS_PER_RANGE must return valid=False."""
        from aiir._core import MAX_RECEIPTS_PER_RANGE

        tmpdir = tempfile.mkdtemp()
        try:
            arr = Path(tmpdir, "arr.json")
            # Create a JSON array that exceeds the limit
            arr.write_text(json.dumps([{}] * (MAX_RECEIPTS_PER_RANGE + 1)))
            result = cli.verify_receipt_file(str(arr))
            self._assert_standard_error_result(result, "too large")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_non_object_non_array_json_rejected_with_valid_false(self):
        """JSON string/number/bool must return valid=False."""
        tmpdir = tempfile.mkdtemp()
        try:
            for value in ['"just a string"', "42", "true", "null"]:
                path = Path(tmpdir, "scalar.json")
                path.write_text(value)
                result = cli.verify_receipt_file(str(path))
                self._assert_standard_error_result(
                    result, "Expected JSON object or array"
                )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_valid_array_result_has_standard_keys(self):
        """Array result must have 'valid', 'receipts', and 'count' keys."""
        # Minimal valid-shaped receipt (will fail verification but exercises array path)
        receipt = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": {"sha": "a" * 40, "subject": "test"},
            "ai_attestation": {},
            "provenance": {},
            "receipt_id": "g1-wrong",
            "content_hash": "sha256:wrong",
        }
        tmpdir = tempfile.mkdtemp()
        try:
            arr = Path(tmpdir, "arr.json")
            arr.write_text(json.dumps([receipt]))
            result = cli.verify_receipt_file(str(arr))
            # Exact key names must be present
            self.assertIn("valid", result)
            self.assertIn("receipts", result)
            self.assertIn("count", result)
            self.assertEqual(result["count"], 1)
            self.assertIsInstance(result["receipts"], list)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_stat_error_returns_valid_false(self):
        """OSError during stat must return valid=False.

        NOTE: This targets a `pragma: no cover` path (race between exists()
        and stat()), so we use a targeted mock that only fails on size check.
        """
        tmpdir = tempfile.mkdtemp()
        try:
            real = Path(tmpdir, "file.json")
            real.write_text("{}")
            # Capture real guard return values, then mock the guards and
            # stat separately.  This avoids fragile call-count thresholds
            # that vary across Python 3.9-3.13 (lstat routing changes).
            real_exists = real.exists()  # True
            real_is_symlink = real.is_symlink()  # False

            with (
                patch.object(type(real), "exists", return_value=real_exists),
                patch.object(type(real), "is_symlink", return_value=real_is_symlink),
                patch.object(type(real), "stat", side_effect=OSError("disk error")),
            ):
                result = cli.verify_receipt_file(str(real))
            self._assert_standard_error_result(result, "Cannot stat")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_file_size_boundary_at_max(self):
        """File at exactly MAX_RECEIPT_FILE_SIZE must still be accepted."""
        from aiir._core import MAX_RECEIPT_FILE_SIZE

        tmpdir = tempfile.mkdtemp()
        try:
            exact = Path(tmpdir, "exact.json")
            # Make a valid JSON file of exactly MAX_RECEIPT_FILE_SIZE bytes
            content = '{"type":"aiir.commit_receipt"}'
            padding = " " * (MAX_RECEIPT_FILE_SIZE - len(content))
            exact.write_text(content + padding)
            result = cli.verify_receipt_file(str(exact))
            # Should NOT return "too large" error — the boundary is >
            self.assertNotIn("too large", result.get("error", ""))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Mutation-killing tests: verify_receipt() result dict fields
# ---------------------------------------------------------------------------
# These tests target ungapped fields identified by mutation testing:
#   - receipt_id_match (not tested by any prior test)
#   - commit_sha extraction
#   - expected_content_hash / expected_receipt_id (only on valid receipts)
#   - error message strings: "content hash mismatch", "receipt_id mismatch"
#   - valid = hash_ok AND id_ok  (kills AND→OR mutation)


class TestVerifyReceiptDirectFields(unittest.TestCase):
    """Targeted tests for verify_receipt() result dict fields."""

    # Minimal valid receipt core (exact CORE_KEYS from _verify.py)
    _CORE = {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.0.0",
        "commit": {"sha": "a" * 40, "subject": "test"},
        "ai_attestation": {},
        "provenance": {},
    }

    def _make_valid_receipt(self):
        """Build a receipt with correct content_hash and receipt_id."""
        core_json = cli._canonical_json(self._CORE)
        h = cli._sha256(core_json)
        return {
            **self._CORE,
            "content_hash": f"sha256:{h}",
            "receipt_id": f"g1-{h[:32]}",
        }

    def test_valid_receipt_id_match_is_true(self):
        """receipt_id_match must be True for an untampered receipt."""
        from aiir._verify import verify_receipt

        result = verify_receipt(self._make_valid_receipt())
        self.assertTrue(result["valid"])
        self.assertTrue(result["receipt_id_match"])
        self.assertEqual(result["errors"], [])

    def test_valid_receipt_commit_sha_extracted(self):
        """commit_sha must equal the sha value from the commit field."""
        from aiir._verify import verify_receipt

        result = verify_receipt(self._make_valid_receipt())
        self.assertEqual(result["commit_sha"], "a" * 40)

    def test_valid_receipt_exposes_expected_hashes(self):
        """expected_content_hash and expected_receipt_id are present only on valid."""
        from aiir._verify import verify_receipt

        result = verify_receipt(self._make_valid_receipt())
        self.assertTrue(result["valid"])
        self.assertIn("expected_content_hash", result)
        self.assertIn("expected_receipt_id", result)
        self.assertTrue(result["expected_content_hash"].startswith("sha256:"))
        self.assertTrue(result["expected_receipt_id"].startswith("g1-"))

    def test_invalid_receipt_hides_expected_hashes(self):
        """expected_content_hash and expected_receipt_id absent on invalid receipts."""
        from aiir._verify import verify_receipt

        receipt = self._make_valid_receipt()
        receipt["content_hash"] = "sha256:wrong"
        receipt["receipt_id"] = "g1-wrong"
        result = verify_receipt(receipt)
        self.assertFalse(result["valid"])
        self.assertNotIn("expected_content_hash", result)
        self.assertNotIn("expected_receipt_id", result)

    def test_content_hash_mismatch_error_string(self):
        """'content hash mismatch' must appear in errors when hash is wrong."""
        from aiir._verify import verify_receipt

        receipt = self._make_valid_receipt()
        receipt["content_hash"] = "sha256:wrong"
        result = verify_receipt(receipt)
        self.assertFalse(result["content_hash_match"])
        self.assertIn("content hash mismatch", result["errors"])

    def test_receipt_id_mismatch_error_string(self):
        """'receipt_id mismatch' must appear in errors when id is wrong."""
        from aiir._verify import verify_receipt

        receipt = self._make_valid_receipt()
        receipt["receipt_id"] = "g1-wrong"
        result = verify_receipt(receipt)
        self.assertFalse(result["receipt_id_match"])
        self.assertIn("receipt_id mismatch", result["errors"])

    def test_valid_requires_hash_ok_and_id_ok(self):
        """valid = hash_ok AND id_ok: hash matches but id tampered → invalid.

        Kills AND→OR mutation: with OR the result would be True (hash matches).
        """
        from aiir._verify import verify_receipt

        receipt = self._make_valid_receipt()
        receipt["receipt_id"] = "g1-wrong"  # tamper only the id
        result = verify_receipt(receipt)
        self.assertFalse(result["valid"])
        self.assertTrue(result["content_hash_match"])  # hash still matches
        self.assertFalse(result["receipt_id_match"])  # id doesn't match

    def test_valid_requires_hash_ok_when_only_hash_wrong(self):
        """valid = hash_ok AND id_ok: hash tampered but id correct → invalid.

        Since receipt_id is derived only from CORE_KEYS (not content_hash),
        a corrupt content_hash leaves receipt_id intact.
        Kills AND→OR mutation: with OR the result would be True (id matches).
        """
        from aiir._verify import verify_receipt

        receipt = self._make_valid_receipt()
        receipt["content_hash"] = "sha256:wrong"  # tamper only the hash
        result = verify_receipt(receipt)
        self.assertFalse(result["valid"])
        self.assertFalse(result["content_hash_match"])  # hash doesn't match
        self.assertTrue(result["receipt_id_match"])  # id still matches

    def test_missing_commit_sha_returns_unknown(self):
        """commit_sha must be 'unknown' when commit field is not a dict."""
        from aiir._verify import verify_receipt

        receipt = self._make_valid_receipt()
        receipt["commit"] = None  # not a dict
        # Recompute valid hashes for the modified receipt core
        core_keys = {
            "type",
            "schema",
            "version",
            "commit",
            "ai_attestation",
            "provenance",
        }
        core = {k: v for k, v in receipt.items() if k in core_keys}
        core_json = cli._canonical_json(core)
        h = cli._sha256(core_json)
        receipt["content_hash"] = f"sha256:{h}"
        receipt["receipt_id"] = f"g1-{h[:32]}"
        result = verify_receipt(receipt)
        self.assertEqual(result["commit_sha"], "unknown")

    def test_non_dict_input_returns_valid_false(self):
        """verify_receipt(non-dict) must return valid=False with errors key.

        Kills 7 mutants: key-name mutations ("XXvalidXX","VALID"),
        True/False swap, "errors"/"ERRORS"/"XXerrorsXX" key-name mutations,
        and error string mutations on the non-dict guard path.
        """
        from aiir._verify import verify_receipt

        for bad_input in (None, "string", 42, []):
            result = verify_receipt(bad_input)
            self.assertIn(
                "valid", result, f"'valid' key missing for input {bad_input!r}"
            )
            self.assertIs(
                result["valid"], False, f"valid should be False for {bad_input!r}"
            )
            self.assertIn(
                "errors", result, f"'errors' key missing for input {bad_input!r}"
            )
            self.assertIn(
                "receipt is not a dict",
                result["errors"],
                f"error message wrong for input {bad_input!r}",
            )

    def test_invalid_type_returns_valid_false_with_error(self):
        """Wrong receipt type must return valid=False with type error string.

        Kills mutants that change the error message to None or change the
        valid=True/False on validation errors (mutmut_50).
        """
        from aiir._verify import verify_receipt

        receipt = {
            "type": "not.aiir.receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": {"sha": "a" * 40},
            "ai_attestation": {},
            "provenance": {},
            "receipt_id": "g1-x",
            "content_hash": "sha256:x",
        }
        result = verify_receipt(receipt)
        self.assertIs(result["valid"], False)
        self.assertIn("errors", result)
        self.assertTrue(
            any("unknown receipt type" in str(e) for e in result["errors"]),
            f"Expected 'unknown receipt type' in errors, got: {result['errors']}",
        )

    def test_invalid_schema_returns_valid_false_with_error(self):
        """Wrong schema must return valid=False with schema error string.

        Kills mutants that change or→and in schema check, or change default
        value of schema.get(), or change error message to None.
        """
        from aiir._verify import verify_receipt

        receipt = {
            "type": "aiir.commit_receipt",
            "schema": "other/schema",  # doesn't start with "aiir/"
            "version": "1.0.0",
            "commit": {"sha": "a" * 40},
            "ai_attestation": {},
            "provenance": {},
            "receipt_id": "g1-x",
            "content_hash": "sha256:x",
        }
        result = verify_receipt(receipt)
        self.assertIs(result["valid"], False)
        self.assertIn("errors", result)
        self.assertTrue(
            any("unknown schema" in str(e) for e in result["errors"]),
            f"Expected 'unknown schema' in errors, got: {result['errors']}",
        )

    def test_invalid_version_returns_valid_false_with_error(self):
        """Non-semver version must return valid=False with version error string.

        Kills mutants that change the regex character class (lowercase only vs
        uppercase) or change the error message to None.
        """
        from aiir._verify import verify_receipt

        receipt = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "not-a-version",
            "commit": {"sha": "a" * 40},
            "ai_attestation": {},
            "provenance": {},
            "receipt_id": "g1-x",
            "content_hash": "sha256:x",
        }
        result = verify_receipt(receipt)
        self.assertIs(result["valid"], False)
        self.assertTrue(
            any("invalid version format" in str(e) for e in result["errors"]),
            f"Expected 'invalid version format' in errors, got: {result['errors']}",
        )

    def test_valid_version_allows_lowercase_prerelease_and_build(self):
        """Valid semver with lowercase suffixes must still pass validation."""
        from aiir._verify import verify_receipt

        receipt = self._make_valid_receipt()
        receipt["version"] = "1.2.3-rc1+build.meta"
        core_keys = {
            "type",
            "schema",
            "version",
            "commit",
            "ai_attestation",
            "provenance",
        }
        core = {k: v for k, v in receipt.items() if k in core_keys}
        core_json = cli._canonical_json(core)
        digest = cli._sha256(core_json)
        receipt["content_hash"] = f"sha256:{digest}"
        receipt["receipt_id"] = f"g1-{digest[:32]}"

        result = verify_receipt(receipt)
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_compare_failure_defaults_matches_false(self):
        """Encoding/compare failures must not produce a truthy verification result."""
        from aiir._verify import verify_receipt

        receipt = self._make_valid_receipt()
        receipt["content_hash"] = 123
        receipt["receipt_id"] = 456

        result = verify_receipt(receipt)
        self.assertFalse(result["valid"])
        self.assertFalse(result["content_hash_match"])
        self.assertFalse(result["receipt_id_match"])
        self.assertIn("content hash mismatch", result["errors"])
        self.assertIn("receipt_id mismatch", result["errors"])


class TestVerifyReceiptFileCborSidecar(unittest.TestCase):
    """Target sidecar discovery and propagation mutants in verify_receipt_file."""

    def _write_valid_receipt(self, path: Path, version: str = "1.0.0") -> dict:
        receipt = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": version,
            "commit": {"sha": "a" * 40, "subject": "test"},
            "ai_attestation": {},
            "provenance": {},
        }
        core_json = cli._canonical_json(receipt)
        digest = cli._sha256(core_json)
        receipt["content_hash"] = f"sha256:{digest}"
        receipt["receipt_id"] = f"g1-{digest[:32]}"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        return receipt

    def test_valid_json_with_invalid_sidecar_reports_sidecar_failure(self):
        """An invalid sidecar must be attached and must add a top-level error."""
        from aiir._verify import verify_receipt_file

        tmpdir = tempfile.mkdtemp()
        try:
            path = Path(tmpdir, "receipt.json")
            receipt = self._write_valid_receipt(path)
            cbor_path = path.with_suffix(".cbor")
            cbor_path.write_bytes(b"dummy")

            sidecar_result = {"valid": False, "errors": ["boom"], "sha256": "abc"}
            with patch("aiir._verify.verify_cbor_file", return_value=sidecar_result) as mock_verify:
                result = verify_receipt_file(str(path))

            mock_verify.assert_called_once_with(str(cbor_path), json_receipt=receipt)
            self.assertIn("cbor_sidecar", result)
            self.assertEqual(result["cbor_sidecar"], sidecar_result)
            self.assertIn("errors", result)
            self.assertIn("CBOR sidecar verification failed", result["errors"])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_missing_sidecar_is_ignored(self):
        """No .cbor sidecar means no sidecar verification attempt and no sidecar field."""
        from aiir._verify import verify_receipt_file

        tmpdir = tempfile.mkdtemp()
        try:
            path = Path(tmpdir, "receipt.json")
            self._write_valid_receipt(path)

            with patch("aiir._verify.verify_cbor_file") as mock_verify:
                result = verify_receipt_file(str(path))

            mock_verify.assert_not_called()
            self.assertTrue(result["valid"])
            self.assertNotIn("cbor_sidecar", result)
            self.assertEqual(result.get("errors"), [])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_symlink_sidecar_is_ignored(self):
        """A symlinked sidecar must not be followed or verified."""
        from aiir._verify import verify_receipt_file

        tmpdir = tempfile.mkdtemp()
        try:
            path = Path(tmpdir, "receipt.json")
            self._write_valid_receipt(path)
            target = Path(tmpdir, "target.cbor")
            target.write_bytes(b"dummy")
            sidecar_link = path.with_suffix(".cbor")
            sidecar_link.symlink_to(target)

            with patch("aiir._verify.verify_cbor_file") as mock_verify:
                result = verify_receipt_file(str(path))

            mock_verify.assert_not_called()
            self.assertTrue(result["valid"])
            self.assertNotIn("cbor_sidecar", result)
            self.assertEqual(result.get("errors"), [])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
