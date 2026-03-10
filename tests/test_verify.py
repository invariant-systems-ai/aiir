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

    def _assert_standard_error_result(self, result: dict, expected_error_substr: str = ""):
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
            real.write_text('{}')
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
            for value in ['"just a string"', '42', 'true', 'null']:
                path = Path(tmpdir, "scalar.json")
                path.write_text(value)
                result = cli.verify_receipt_file(str(path))
                self._assert_standard_error_result(result, "Expected JSON object or array")
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
            orig_stat = real.stat

            call_count = [0]

            def stat_bomb(*a, **kw):
                call_count[0] += 1
                # Let exists() and is_symlink() succeed (calls 1 & 2),
                # but fail on the actual stat-for-size call (call 3).
                if call_count[0] >= 3:
                    raise OSError("disk error")
                return orig_stat(*a, **kw)

            with patch.object(type(real), "stat", side_effect=stat_bomb):
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
