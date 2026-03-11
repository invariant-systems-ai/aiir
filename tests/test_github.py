"""Tests for GitHub integration (outputs, summary, action.yml)."""
# Copyright 2025-2026 Invariant Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Import the module under test
import aiir.cli as cli


class TestGitHubOutputs(unittest.TestCase):
    """Test set_github_output uses heredoc pattern for multiline values."""

    def test_multiline_value_uses_delimiter(self):
        """Multiline values must use the heredoc pattern, not plain echo."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            tmppath = f.name

        try:
            with patch.dict(os.environ, {"GITHUB_OUTPUT": tmppath}):
                cli.set_github_output("test_key", "line1\nline2")

            content = Path(tmppath).read_text()
            # Should use delimiter pattern, not key=value
            self.assertIn("test_key<<", content)
            self.assertIn("line1\nline2", content)
            # Should NOT have the vulnerable pattern
            self.assertNotIn("test_key=line1", content)
        finally:
            os.unlink(tmppath)

    def test_single_line_value(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            tmppath = f.name

        try:
            with patch.dict(os.environ, {"GITHUB_OUTPUT": tmppath}):
                cli.set_github_output("count", "42")

            content = Path(tmppath).read_text()
            self.assertIn("count=42", content)
        finally:
            os.unlink(tmppath)


# ---------------------------------------------------------------------------
# CLI argument parsing tests
# ---------------------------------------------------------------------------


class TestGitHubOutputValueCap(unittest.TestCase):
    """R9-SEC-02: set_github_output must reject values exceeding 4 MB."""

    def test_value_under_limit_accepted(self):
        """Values under 4 MB should pass through normally."""
        tmpdir = tempfile.mkdtemp()
        output_file = Path(tmpdir, "GITHUB_OUTPUT")
        output_file.write_text("")
        try:
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output_file)}):
                cli.set_github_output("key", "short_value")
            content = output_file.read_text()
            self.assertIn("key=short_value", content)
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_value_over_limit_rejected(self):
        """Values over 4 MB must raise ValueError."""
        huge_value = "x" * (4 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError) as ctx:
            cli.set_github_output("key", huge_value)
        self.assertIn("too large", str(ctx.exception))

    def test_value_at_exact_limit_accepted(self):
        """Value at exactly 4 MB should be accepted."""
        tmpdir = tempfile.mkdtemp()
        output_file = Path(tmpdir, "GITHUB_OUTPUT")
        output_file.write_text("")
        exact_value = "x" * (4 * 1024 * 1024)
        try:
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output_file)}):
                cli.set_github_output("k", exact_value)
            # Should not raise
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)


class TestActionYmlSafePath(unittest.TestCase):
    """R10-SEC-01: action.yml must use -P flag to prevent module shadowing."""

    def test_action_yml_uses_safe_path_flag(self):
        """The python invocation in action.yml must include -P."""
        action_path = Path(__file__).parent.parent / "action.yml"
        content = action_path.read_text(encoding="utf-8")
        self.assertIn("python -P -m aiir", content)

    def test_action_yml_has_sec01_comment(self):
        """The -P flag should have a comment explaining why."""
        action_path = Path(__file__).parent.parent / "action.yml"
        content = action_path.read_text(encoding="utf-8")
        self.assertIn("-P flag", content)


class TestGitHubApiRequestHardening(unittest.TestCase):
    """Coverage for URL scheme hardening in _github_api_request."""

    def test_rejects_non_http_scheme(self):
        """file:// endpoints must be rejected before network IO."""
        from aiir._github import _github_api_request

        with self.assertRaises(RuntimeError) as ctx:
            _github_api_request(
                "file:///etc/passwd",
                {"ok": True},
                token="ghp_test",
                method="POST",
            )
        self.assertIn("non-HTTP(S)", str(ctx.exception))
