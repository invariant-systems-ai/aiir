"""Unit tests for scripts/ — check_licenses.py, conformance.py, sync-version.py.

Copyright 2025-2026 Invariant Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

These scripts are part of the CI pipeline but previously had zero test coverage.
This file validates their core logic without requiring external dependencies.
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"


def _load_module(name: str, path: Path):
    """Import a script module by path (they don't live in a package)."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ═══════════════════════════════════════════════════════════════════════
# check_licenses.py
# ═══════════════════════════════════════════════════════════════════════


class TestCheckLicenses(unittest.TestCase):
    """Tests for scripts/check_licenses.py logic."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("check_licenses", SCRIPTS_DIR / "check_licenses.py")

    def test_approved_terms_present(self):
        """APPROVED_TERMS list contains core open-source license families."""
        terms = self.mod.APPROVED_TERMS
        self.assertIn("Apache", terms)
        self.assertIn("MIT", terms)
        self.assertIn("BSD", terms)

    def test_skip_packages_includes_aiir(self):
        """aiir itself should be skipped (not on PyPI during dev)."""
        self.assertIn("aiir", self.mod.SKIP_PACKAGES)

    def test_all_approved(self):
        """All packages approved → exit 0."""
        pkgs = [
            {"Name": "pytest", "Version": "8.0.0", "License": "MIT License"},
            {
                "Name": "hypothesis",
                "Version": "6.0",
                "License": "Mozilla Public License 2.0",
            },
        ]
        tf = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        tf_name = tf.name
        json.dump(pkgs, tf)
        tf.close()  # close before test reads — required on Windows
        try:
            with mock.patch("sys.argv", ["check_licenses.py", tf_name]):
                result = self.mod.main()
            self.assertEqual(result, 0)
        finally:
            os.unlink(tf_name)

    def test_unapproved_license(self):
        """Package with unapproved license → exit 1."""
        pkgs = [
            {"Name": "evil-lib", "Version": "1.0", "License": "Proprietary"},
        ]
        tf = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        tf_name = tf.name
        json.dump(pkgs, tf)
        tf.close()
        try:
            with mock.patch("sys.argv", ["check_licenses.py", tf_name]):
                result = self.mod.main()
            self.assertEqual(result, 1)
        finally:
            os.unlink(tf_name)

    def test_skipped_package_ignored(self):
        """Packages in SKIP_PACKAGES are not checked."""
        pkgs = [
            {"Name": "aiir", "Version": "1.0", "License": "UNKNOWN"},
        ]
        tf = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        tf_name = tf.name
        json.dump(pkgs, tf)
        tf.close()
        try:
            with mock.patch("sys.argv", ["check_licenses.py", tf_name]):
                result = self.mod.main()
            self.assertEqual(result, 0)
        finally:
            os.unlink(tf_name)

    def test_no_args(self):
        """Missing CLI argument → exit 2."""
        with mock.patch("sys.argv", ["check_licenses.py"]):
            result = self.mod.main()
        self.assertEqual(result, 2)


# ═══════════════════════════════════════════════════════════════════════
# conformance.py
# ═══════════════════════════════════════════════════════════════════════


class TestConformance(unittest.TestCase):
    """Tests for scripts/conformance.py logic."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("conformance", SCRIPTS_DIR / "conformance.py")

    def test_canonical_json_sorted_keys(self):
        """Canonical JSON sorts keys."""
        result = self.mod.canonical_json({"b": 2, "a": 1})
        self.assertEqual(result, '{"a":1,"b":2}')

    def test_canonical_json_no_whitespace(self):
        """Canonical JSON has no extraneous whitespace."""
        result = self.mod.canonical_json({"key": "value"})
        self.assertNotIn(" ", result.replace('"key"', "").replace('"value"', ""))

    def test_canonical_json_ascii_escape(self):
        """Non-ASCII characters are \\uXXXX-escaped."""
        result = self.mod.canonical_json({"emoji": "🎉"})
        self.assertIn("\\u", result)
        self.assertNotIn("🎉", result)

    def test_canonical_json_depth_limit(self):
        """Exceeding depth 64 raises ValueError."""
        # Build a 65-deep nested dict
        obj = {"a": "leaf"}
        for _ in range(65):
            obj = {"nested": obj}
        with self.assertRaises(ValueError):
            self.mod.canonical_json(obj)

    def test_canonical_json_null(self):
        self.assertEqual(self.mod.canonical_json(None), "null")

    def test_canonical_json_bool(self):
        self.assertEqual(self.mod.canonical_json(True), "true")
        self.assertEqual(self.mod.canonical_json(False), "false")

    def test_canonical_json_list(self):
        self.assertEqual(self.mod.canonical_json([1, 2, 3]), "[1,2,3]")

    def test_canonical_json_nan_rejected(self):
        with self.assertRaises(ValueError):
            self.mod.canonical_json(float("nan"))

    def test_canonical_json_unsupported_type(self):
        with self.assertRaises(TypeError):
            self.mod.canonical_json(set())

    def test_verify_valid_receipt(self):
        """A properly constructed receipt passes verification."""
        import hashlib

        core = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": {"sha": "a" * 40, "subject": "test"},
            "ai_attestation": {},
            "provenance": {},
        }
        core_json = self.mod.canonical_json(core)
        digest = hashlib.sha256(core_json.encode()).hexdigest()
        receipt = {
            **core,
            "content_hash": f"sha256:{digest}",
            "receipt_id": f"g1-{digest[:32]}",
        }
        valid, errors = self.mod.verify(receipt)
        self.assertTrue(valid, f"Expected valid, got errors: {errors}")

    def test_verify_tampered_receipt(self):
        """A tampered receipt fails verification."""
        receipt = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": {"sha": "a" * 40, "subject": "test"},
            "ai_attestation": {},
            "provenance": {},
            "content_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "receipt_id": "g1-00000000000000000000000000000000",
        }
        valid, errors = self.mod.verify(receipt)
        self.assertFalse(valid)
        self.assertTrue(len(errors) > 0)

    def test_verify_not_dict(self):
        valid, errors = self.mod.verify("not a dict")
        self.assertFalse(valid)

    def test_verify_wrong_type(self):
        valid, errors = self.mod.verify({"type": "wrong"})
        self.assertFalse(valid)

    def test_verify_bad_schema(self):
        valid, errors = self.mod.verify(
            {
                "type": "aiir.commit_receipt",
                "schema": "bad",
            }
        )
        self.assertFalse(valid)

    def test_verify_bad_version(self):
        valid, errors = self.mod.verify(
            {
                "type": "aiir.commit_receipt",
                "schema": "aiir/commit_receipt.v1",
                "version": "not-a-version",
            }
        )
        self.assertFalse(valid)

    def test_run_vectors_with_bundled_vectors(self):
        """run_vectors succeeds on the bundled test_vectors.json."""
        vectors_path = SCHEMAS_DIR / "test_vectors.json"
        if not vectors_path.exists():
            self.skipTest("test_vectors.json not found")
        passed, total, failures = self.mod.run_vectors(vectors_path)
        self.assertEqual(len(failures), 0, f"Failures: {failures}")
        self.assertGreater(total, 0)

    def test_main_with_bundled_vectors(self):
        """main() succeeds when run from repo root."""
        with mock.patch("sys.argv", ["conformance.py"]):
            result = self.mod.main()
        self.assertEqual(result, 0)

    def test_main_missing_vectors(self):
        """main() fails gracefully when vectors file not found."""
        with mock.patch("sys.argv", ["conformance.py", "/nonexistent/vectors.json"]):
            # Should fail to open the file
            with self.assertRaises((FileNotFoundError, SystemExit)):
                self.mod.main()


# ═══════════════════════════════════════════════════════════════════════
# sync-version.py
# ═══════════════════════════════════════════════════════════════════════


class TestSyncVersion(unittest.TestCase):
    """Tests for scripts/sync-version.py logic."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("sync_version", SCRIPTS_DIR / "sync-version.py")

    def test_get_version_reads_init(self):
        """get_version() reads from aiir/__init__.py."""
        version = self.mod.get_version()
        # Should be a valid semver-ish string
        parts = version.split(".")
        self.assertEqual(len(parts), 3)
        for p in parts:
            self.assertTrue(p.isdigit(), f"Non-numeric version part: {p}")

    def test_check_mode_no_drift(self):
        """--check exits 0 when all versions are in sync."""
        with mock.patch("sys.argv", ["sync-version.py", "--check"]):
            result = self.mod.main()
        self.assertEqual(result, 0)

    def test_apply_rules_detects_drift(self):
        """apply_rules detects version drift in a test file."""
        tmpdir = tempfile.mkdtemp()
        try:
            # Create a file with a stale version
            test_file = Path(tmpdir) / "test.md"
            test_file.write_text("rev: v0.0.0\n")

            rules = [
                self.mod.Rule(
                    "test.md",
                    r"rev:\s*v(?P<ver>\d+\.\d+\.\d+)",
                    "rev: v{version}",
                ),
            ]
            drifts = self.mod.apply_rules(rules, Path(tmpdir), "1.2.3", fix=False)
            self.assertEqual(len(drifts), 1)
            self.assertIn("0.0.0", drifts[0])
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_apply_rules_fixes_drift(self):
        """apply_rules with fix=True patches the file."""
        tmpdir = tempfile.mkdtemp()
        try:
            test_file = Path(tmpdir) / "test.md"
            test_file.write_text("rev: v0.0.0\n")

            rules = [
                self.mod.Rule(
                    "test.md",
                    r"rev:\s*v(?P<ver>\d+\.\d+\.\d+)",
                    "rev: v{version}",
                ),
            ]
            drifts = self.mod.apply_rules(rules, Path(tmpdir), "1.2.3", fix=True)
            self.assertEqual(len(drifts), 1)
            content = test_file.read_text()
            self.assertIn("v1.2.3", content)
            self.assertNotIn("v0.0.0", content)
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_apply_rules_missing_file_skipped(self):
        """Missing files are silently skipped."""
        rules = [
            self.mod.Rule("nonexistent.md", r"v(?P<ver>\d+)", "v{version}"),
        ]
        drifts = self.mod.apply_rules(rules, Path("/tmp"), "1.0.0", fix=False)
        self.assertEqual(drifts, [])

    def test_apply_rules_stale_pattern(self):
        """Pattern that doesn't match generates a warning."""
        tmpdir = tempfile.mkdtemp()
        try:
            test_file = Path(tmpdir) / "test.md"
            test_file.write_text("no version here\n")

            rules = [
                self.mod.Rule(
                    "test.md",
                    r"rev:\s*v(?P<ver>\d+\.\d+\.\d+)",
                    "rev: v{version}",
                ),
            ]
            drifts = self.mod.apply_rules(rules, Path(tmpdir), "1.0.0", fix=False)
            self.assertEqual(len(drifts), 1)
            self.assertIn("pattern not found", drifts[0])
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_aiir_rules_not_empty(self):
        """AIIR_RULES covers critical files."""
        paths = [r.path for r in self.mod.AIIR_RULES]
        self.assertIn("mcp-manifest.json", paths)
        self.assertIn("README.md", paths)

    def test_website_rules_present(self):
        """WEBSITE_RULES exist for cross-repo sync."""
        self.assertGreater(len(self.mod.WEBSITE_RULES), 0)


if __name__ == "__main__":
    unittest.main()
