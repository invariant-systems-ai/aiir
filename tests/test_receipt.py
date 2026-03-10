"""Tests for receipt integrity and construction."""
# Copyright 2025-2026 Invariant Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

# Import the module under test
import aiir.cli as cli


class TestReceiptIntegrity(unittest.TestCase):
    """Tests for receipt construction and verification."""

    def _make_dummy_commit(self) -> cli.CommitInfo:
        return cli.CommitInfo(
            sha="a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
            author_name="Test User",
            author_email="test@example.com",
            author_date="2026-03-06T10:00:00+00:00",
            committer_name="Test User",
            committer_email="test@example.com",
            committer_date="2026-03-06T10:00:00+00:00",
            subject="test: add unit tests",
            body="test: add unit tests\n\nFull body.",
            diff_stat="1 file changed, 10 insertions(+)",
            diff_hash="sha256:abcdef1234567890",
            files_changed=["test_cli.py"],
            ai_signals_detected=[],
            is_ai_authored=False,
        )

    def test_receipt_has_required_fields(self):
        commit = self._make_dummy_commit()
        receipt = cli.build_commit_receipt(commit)
        self.assertIn("type", receipt)
        self.assertIn("schema", receipt)
        self.assertIn("receipt_id", receipt)
        self.assertIn("content_hash", receipt)
        self.assertIn("timestamp", receipt)
        self.assertIn("commit", receipt)
        self.assertIn("ai_attestation", receipt)
        self.assertIn("provenance", receipt)
        self.assertIn("extensions", receipt)
        self.assertIsInstance(receipt["extensions"], dict)

    def test_receipt_id_format(self):
        commit = self._make_dummy_commit()
        receipt = cli.build_commit_receipt(commit)
        self.assertTrue(receipt["receipt_id"].startswith("g1-"))
        self.assertEqual(len(receipt["receipt_id"]), 3 + 32)  # "g1-" + 32 hex chars

    def test_content_hash_format(self):
        commit = self._make_dummy_commit()
        receipt = cli.build_commit_receipt(commit)
        self.assertTrue(receipt["content_hash"].startswith("sha256:"))
        self.assertEqual(len(receipt["content_hash"]), 7 + 64)  # "sha256:" + 64 hex

    def test_receipt_deterministic(self):
        """Same commit should produce same receipt_id (ignoring timestamp)."""
        commit = self._make_dummy_commit()
        r1 = cli.build_commit_receipt(commit)
        r2 = cli.build_commit_receipt(commit)
        self.assertEqual(r1["receipt_id"], r2["receipt_id"])
        self.assertEqual(r1["content_hash"], r2["content_hash"])

    def test_verify_valid_receipt(self):
        """Round-trip: build a receipt and verify it."""
        commit = self._make_dummy_commit()
        receipt = cli.build_commit_receipt(commit)
        result = cli.verify_receipt(receipt)
        self.assertTrue(result["valid"])
        self.assertTrue(result["content_hash_match"])
        self.assertTrue(result["receipt_id_match"])

    def test_verify_tampered_receipt(self):
        """Changing any field should break verification."""
        commit = self._make_dummy_commit()
        receipt = cli.build_commit_receipt(commit)
        # Tamper with the commit subject
        receipt["commit"]["subject"] = "TAMPERED"
        result = cli.verify_receipt(receipt)
        self.assertFalse(result["valid"])
        self.assertFalse(result["content_hash_match"])

    def test_verify_tampered_ai_attestation(self):
        """Changing AI attestation should break verification."""
        commit = self._make_dummy_commit()
        receipt = cli.build_commit_receipt(commit)
        receipt["ai_attestation"]["is_ai_authored"] = True
        result = cli.verify_receipt(receipt)
        self.assertFalse(result["valid"])

    def test_verify_file_round_trip(self):
        """Write receipt to file, then verify via verify_receipt_file."""
        commit = self._make_dummy_commit()
        receipt = cli.build_commit_receipt(commit)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(receipt, f, indent=2)
            tmppath = f.name
        try:
            result = cli.verify_receipt_file(tmppath)
            self.assertTrue(result["valid"])
        finally:
            os.unlink(tmppath)

    def test_verify_file_not_found(self):
        result = cli.verify_receipt_file("/nonexistent/path.json")
        self.assertFalse(result["valid"])
        self.assertIn("error", result)

    def test_verify_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not json{{{")
            tmppath = f.name
        try:
            result = cli.verify_receipt_file(tmppath)
            self.assertFalse(result["valid"])
            self.assertIn("error", result)
        finally:
            os.unlink(tmppath)

    def test_ai_authored_receipt(self):
        commit = self._make_dummy_commit()
        commit.ai_signals_detected = ["message_match:co-authored-by: copilot"]
        commit.is_ai_authored = True
        receipt = cli.build_commit_receipt(commit)
        self.assertTrue(receipt["ai_attestation"]["is_ai_authored"])
        self.assertEqual(receipt["ai_attestation"]["signal_count"], 1)
        # Verify still works
        result = cli.verify_receipt(receipt)
        self.assertTrue(result["valid"])


# ---------------------------------------------------------------------------
# VULN-01: Delimiter injection resistance
# ---------------------------------------------------------------------------


class TestDelimiterInjection(unittest.TestCase):
    """Ensure pipe characters in author name don't break field parsing (VULN-01)."""

    def test_pipe_in_author_name_does_not_shift_fields(self):
        """If we were still using | delimiter, a pipe in the author name
        would shift all subsequent fields. With NUL delimiter this is safe."""
        # We test this by verifying the format string uses %x00
        # and that parsing uses \x00
        import inspect

        source = inspect.getsource(cli.get_commit_info)
        self.assertIn("%x00", source, "Must use NUL byte delimiter (%x00)")
        self.assertIn("\\x00", source, "Must split on NUL byte")
        self.assertNotIn('"%H|%an|', source, "Must NOT use pipe delimiter")


# ---------------------------------------------------------------------------
# Max-count safety limit (VULN-04)
# ---------------------------------------------------------------------------


class TestMaxCount(unittest.TestCase):
    """Verify max_count is enforced in list_commits_in_range (VULN-04)."""

    def test_default_max_count(self):
        """list_commits_in_range should have max_count parameter."""
        import inspect

        sig = inspect.signature(cli.list_commits_in_range)
        self.assertIn("max_count", sig.parameters)
        default = sig.parameters["max_count"].default
        self.assertIsNotNone(default)
        self.assertGreater(default, 0)
        self.assertLessEqual(default, 10000)

    def test_max_count_in_git_command(self):
        """The function should pass --max-count to git rev-list."""
        import inspect

        source = inspect.getsource(cli.list_commits_in_range)
        self.assertIn("--max-count", source)


# ---------------------------------------------------------------------------
# GitHub Actions output tests
# ---------------------------------------------------------------------------


class TestPublicBasic(unittest.TestCase):
    """R7 Front 1: Public/basic understanding — what a first-time user would trip over."""

    # R7-PUB-01: __main__.py crash guard ----------------------------------------

    def test_r7_pub_01_main_module_handles_keyboard_interrupt(self):
        """python -m aiir must exit cleanly on KeyboardInterrupt, not dump a traceback."""
        import importlib

        src = importlib.util.find_spec("aiir.__main__")
        self.assertIsNotNone(src)
        source = Path(src.origin).read_text()
        # Must catch KeyboardInterrupt
        self.assertIn("KeyboardInterrupt", source)
        self.assertIn("130", source)  # Standard SIGINT exit code

    def test_r7_pub_01_main_module_handles_memory_error(self):
        """python -m aiir must catch MemoryError for clean exit."""
        import importlib

        src = importlib.util.find_spec("aiir.__main__")
        source = Path(src.origin).read_text()
        self.assertIn("MemoryError", source)

    # R7-PUB-02: py.typed marker -----------------------------------------------

    def test_r7_pub_02_py_typed_marker_exists(self):
        """PEP 561 py.typed marker must exist for type checker compatibility."""
        marker = Path(__file__).parent.parent / "aiir" / "py.typed"
        self.assertTrue(
            marker.exists(),
            "aiir/py.typed missing — Typing :: Typed classifier is false",
        )

    # General public-facing robustness ------------------------------------------

    def test_version_format_is_semver(self):
        """Version string must be valid semver (MAJOR.MINOR.PATCH)."""
        parts = cli.CLI_VERSION.split(".")
        self.assertEqual(
            len(parts), 3, f"Version {cli.CLI_VERSION!r} is not MAJOR.MINOR.PATCH"
        )
        for part in parts:
            self.assertTrue(part.isdigit(), f"Non-numeric version component: {part!r}")

    def test_receipt_type_is_documented_constant(self):
        """Receipt type field must be a stable documented constant, not ad-hoc."""
        commit = self._make_commit()
        receipt = cli.build_commit_receipt(commit)
        self.assertEqual(receipt["type"], "aiir.commit_receipt")
        self.assertEqual(receipt["schema"], "aiir/commit_receipt.v2")

    def test_help_text_contains_url(self):
        """--help epilog should contain the project URL for first-time users."""
        import io
        from contextlib import redirect_stderr

        with self.assertRaises(SystemExit):
            with redirect_stderr(io.StringIO()) as f:
                cli.main(["--help"])
        # argparse prints help to stdout normally
        # Just verify the parser has epilog set
        parser = cli.argparse.ArgumentParser()  # proxy test
        # Better: check source
        import inspect

        source = inspect.getsource(cli.main)
        self.assertIn("invariantsystems.io", source)

    def _make_commit(self):
        return cli.CommitInfo(
            sha="a" * 40,
            author_name="Test",
            author_email="t@t.com",
            author_date="2026-03-07T00:00:00Z",
            committer_name="Test",
            committer_email="t@t.com",
            committer_date="2026-03-07T00:00:00Z",
            subject="test commit",
            body="test commit\n\nBody text.",
            diff_stat="1 file changed",
            diff_hash="sha256:" + "0" * 64,
            files_changed=["test.py"],
        )


class TestVerifyNonDictCommit(unittest.TestCase):
    """R14-SEC-01: verify_receipt must not crash when commit field is non-dict."""

    def _make_receipt_with_commit(self, commit_val):
        """Build a structurally valid receipt, then replace commit with given value."""
        return {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": commit_val,
            "ai_attestation": {
                "is_ai_authored": False,
                "signals_detected": [],
                "signal_count": 0,
                "detection_method": "heuristic_v1",
            },
            "provenance": {"repository": "", "tool": "test", "generator": "test"},
            "receipt_id": "g1-fake",
            "content_hash": "sha256:fake",
            "timestamp": "2026-01-01T00:00:00Z",
        }

    def test_non_dict_commit_string(self):
        """commit='hello' must not crash — returns valid=False, sha='unknown'."""
        receipt = self._make_receipt_with_commit("hello")
        result = cli.verify_receipt(receipt)
        self.assertFalse(result["valid"])
        self.assertEqual(result["commit_sha"], "unknown")

    def test_non_dict_commit_list(self):
        """commit=[1,2,3] must not crash."""
        receipt = self._make_receipt_with_commit([1, 2, 3])
        result = cli.verify_receipt(receipt)
        self.assertFalse(result["valid"])
        self.assertEqual(result["commit_sha"], "unknown")

    def test_non_dict_commit_none(self):
        """commit=None must not crash."""
        receipt = self._make_receipt_with_commit(None)
        result = cli.verify_receipt(receipt)
        self.assertFalse(result["valid"])
        self.assertEqual(result["commit_sha"], "unknown")

    def test_non_dict_commit_int(self):
        """commit=42 must not crash."""
        receipt = self._make_receipt_with_commit(42)
        result = cli.verify_receipt(receipt)
        self.assertFalse(result["valid"])
        self.assertEqual(result["commit_sha"], "unknown")


class TestSignReceiptSizeCap(unittest.TestCase):
    """R9-SEC-04: sign_receipt_file must reject files exceeding MAX_RECEIPT_FILE_SIZE."""

    def test_oversized_file_rejected(self):
        """A file larger than MAX_RECEIPT_FILE_SIZE must be rejected."""
        tmpdir = tempfile.mkdtemp()
        try:
            huge_file = Path(tmpdir, "huge.json")
            # Create a sparse file that appears large
            with open(huge_file, "wb") as f:
                f.seek(cli.MAX_RECEIPT_FILE_SIZE + 1)
                f.write(b"\0")
            with self.assertRaises(ValueError) as ctx:
                cli.sign_receipt_file(str(huge_file))
            self.assertIn("too large", str(ctx.exception).lower())
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_normal_file_passes_size_check(self):
        """A file under the limit should not fail the size check (may fail later in signing)."""
        tmpdir = tempfile.mkdtemp()
        try:
            normal_file = Path(tmpdir, "receipt.json")
            normal_file.write_text('{"test": true}')
            # The call may fail at the actual signing step (no sigstore),
            # but it should NOT fail at the size check.
            try:
                cli.sign_receipt_file(str(normal_file))
            except Exception as e:
                # Acceptable: fails at signing, not at size check
                self.assertNotIn("too large", str(e).lower())
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)


# ── Round 9 final — previously-accepted findings, now fixed ──────────────


class TestJsonDepthCheck(unittest.TestCase):
    """D-07-FIX: Explicit JSON depth limit in _canonical_json."""

    def test_shallow_object_ok(self):
        """Normal objects should serialize without error."""
        obj = {"a": {"b": {"c": 1}}}
        result = cli._canonical_json(obj)
        self.assertIn('"a"', result)

    def test_deep_object_raises(self):
        """Objects nested deeper than 64 levels should raise ValueError."""
        # Build a 70-level deep dict
        obj = {"leaf": True}
        for _ in range(70):
            obj = {"nested": obj}
        with self.assertRaises(ValueError) as ctx:
            cli._canonical_json(obj)
        self.assertIn("maximum depth", str(ctx.exception))

    def test_deep_list_raises(self):
        """Lists nested deeper than 64 levels should also raise."""
        obj = [1]
        for _ in range(70):
            obj = [obj]
        with self.assertRaises(ValueError) as ctx:
            cli._canonical_json(obj)
        self.assertIn("maximum depth", str(ctx.exception))

    def test_exactly_64_levels_ok(self):
        """Exactly 64 levels should be accepted."""
        obj = {"leaf": True}
        for _ in range(63):  # 63 wraps + 1 leaf = 64 levels
            obj = {"n": obj}
        result = cli._canonical_json(obj)
        self.assertIn("leaf", result)

    def test_verify_receipt_deep_json_error(self):
        """verify_receipt should gracefully handle deep JSON."""
        # Build a receipt with deeply nested commit field
        deep = {"leaf": True}
        for _ in range(70):
            deep = {"nested": deep}
        receipt = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": deep,
            "ai_attestation": {},
            "provenance": {},
            "content_hash": "sha256:fake",
            "receipt_id": "g1-fake",
        }
        result = cli.verify_receipt(receipt)
        self.assertFalse(result["valid"])
