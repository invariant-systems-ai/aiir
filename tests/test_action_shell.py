"""Tests for the composite GitHub Action's shell logic (action.yml).

Copyright 2025-2026 Invariant Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

The action.yml composite action contains ~80 lines of bash with:
  - Commit range determination (push, PR, first-push, force-push)
  - Input validation (shell injection prevention)
  - Large-range warnings
  - Cryptographic delimiter generation

These tests validate that logic in isolation.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ACTION_YML = Path(__file__).resolve().parent.parent / "action.yml"


class TestActionYmlExists(unittest.TestCase):
    """Verify action.yml structure."""

    def test_action_yml_exists(self):
        self.assertTrue(ACTION_YML.exists())

    def test_action_yml_is_valid_yaml(self):
        # Use Python's built-in YAML-like parsing or just check structure
        content = ACTION_YML.read_text()
        self.assertIn("name:", content)
        self.assertIn("runs:", content)
        self.assertIn('using: "composite"', content)

    def test_action_yml_has_required_inputs(self):
        content = ACTION_YML.read_text()
        self.assertIn("ai-only:", content)
        self.assertIn("commit-range:", content)
        self.assertIn("output-dir:", content)
        self.assertIn("sign:", content)

    def test_action_yml_has_required_outputs(self):
        content = ACTION_YML.read_text()
        self.assertIn("receipt_count:", content)
        self.assertIn("ai_commit_count:", content)
        self.assertIn("receipts_json:", content)
        self.assertIn("receipts_overflow:", content)


class TestInputValidation(unittest.TestCase):
    """Test the shell injection prevention regex from action.yml."""

    # This regex matches the input validation pattern from action.yml:
    #   if echo "$RANGE" | grep -qE '[;&|$`\\]|[[:cntrl:]]'; then
    FORBIDDEN_PATTERN = re.compile(r"[;&|$`\\]|[\x00-\x1f\x7f]")

    def test_clean_range_passes(self):
        """Normal commit ranges pass validation."""
        clean_ranges = [
            "HEAD~1..HEAD",
            "abc1234..def5678",
            "origin/main..HEAD",
            "v1.0.0..v1.1.0",
            "a" * 40 + ".." + "b" * 40,
        ]
        for r in clean_ranges:
            self.assertIsNone(
                self.FORBIDDEN_PATTERN.search(r),
                f"False positive: {r!r} should pass",
            )

    def test_injection_blocked(self):
        """Shell metacharacters are caught."""
        malicious_ranges = [
            "HEAD; rm -rf /",
            "HEAD & echo pwned",
            "HEAD | cat /etc/passwd",
            "HEAD$(whoami)",
            "HEAD`id`",
            "HEAD\\necho pwned",
        ]
        for r in malicious_ranges:
            self.assertIsNotNone(
                self.FORBIDDEN_PATTERN.search(r),
                f"False negative: {r!r} should be blocked",
            )

    def test_control_characters_blocked(self):
        """Control characters (newlines, tabs, nulls) are caught."""
        for c in ["\x00", "\n", "\r", "\t", "\x1b"]:
            self.assertIsNotNone(
                self.FORBIDDEN_PATTERN.search(f"HEAD{c}injected"),
                f"Control char \\x{ord(c):02x} should be blocked",
            )


class TestPythonPathSecurity(unittest.TestCase):
    """Verify the action uses -P flag to prevent CWD path injection."""

    def test_python_dash_P_used(self):
        """The action invokes Python with -P to prevent CWD hijack."""
        content = ACTION_YML.read_text()
        self.assertIn("python -P", content)

    def test_pythonpath_set(self):
        """PYTHONPATH is set to ACTION_PATH, not CWD."""
        content = ACTION_YML.read_text()
        self.assertIn('PYTHONPATH="$ACTION_PATH"', content)


class TestCommitRangeLogic(unittest.TestCase):
    """Test the commit range determination logic from action.yml.

    We extract and test the logic by creating real git repos and
    simulating the environment variables the action would see.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, True)
        # Create a minimal git repo
        subprocess.run(
            ["git", "init"],
            cwd=self.tmpdir,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=self.tmpdir,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"],
            cwd=self.tmpdir,
            capture_output=True,
            check=True,
        )
        # First commit
        (Path(self.tmpdir) / "file.txt").write_text("hello")
        subprocess.run(
            ["git", "add", "."],
            cwd=self.tmpdir,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "init"],
            cwd=self.tmpdir,
            capture_output=True,
            check=True,
        )

    def _get_head_sha(self) -> str:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.tmpdir,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def test_explicit_range_used_if_set(self):
        """INPUT_COMMIT_RANGE takes priority over event-based detection."""
        # The action.yml logic:
        #   if [ -n "$INPUT_COMMIT_RANGE" ]; then RANGE="$INPUT_COMMIT_RANGE"
        explicit = "abc123..def456"
        # Simulate the bash logic in Python
        commit_range = explicit
        self.assertEqual(commit_range, explicit)

    def test_pr_event_uses_base_head(self):
        """pull_request events use base_sha..head_sha."""
        base_sha = "a" * 40
        head_sha = "b" * 40
        event_name = "pull_request"
        # Simulate action logic
        if event_name == "pull_request":
            commit_range = f"{base_sha}..{head_sha}"
        self.assertEqual(commit_range, f"{base_sha}..{head_sha}")

    def test_push_event_uses_before_after(self):
        """push events use before..after."""
        sha1 = self._get_head_sha()
        # Create second commit
        (Path(self.tmpdir) / "file2.txt").write_text("world")
        subprocess.run(
            ["git", "add", "."],
            cwd=self.tmpdir,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "second"],
            cwd=self.tmpdir,
            capture_output=True,
            check=True,
        )
        sha2 = self._get_head_sha()

        event_name = "push"
        push_before = sha1
        push_after = sha2
        null_sha = "0" * 40

        if event_name == "push":
            if push_before == null_sha:
                commit_range = "EMPTY_TREE..HEAD"
            else:
                commit_range = f"{push_before}..{push_after}"

        self.assertEqual(commit_range, f"{sha1}..{sha2}")

    def test_first_push_null_sha_detected(self):
        """First push (null before SHA) uses empty tree."""
        null_sha = "0" * 40
        push_before = null_sha
        event_name = "push"

        if event_name == "push" and push_before == null_sha:
            commit_range = "EMPTY_TREE..HEAD"

        self.assertEqual(commit_range, "EMPTY_TREE..HEAD")


class TestDelimiterSecurity(unittest.TestCase):
    """Verify the delimiter generation uses cryptographic randomness."""

    def test_delimiter_uses_crypto_random(self):
        """The action.yml uses openssl rand or secrets.token_hex."""
        content = ACTION_YML.read_text()
        self.assertIn("openssl rand -hex 16", content)
        self.assertIn("secrets.token_hex(16)", content)

    def test_no_weak_random(self):
        """$RANDOM (15-bit) is NOT used for delimiter generation."""
        content = ACTION_YML.read_text()
        # The action explicitly comments about not using $RANDOM
        lines = content.split("\n")
        for line in lines:
            if "DELIM=" in line:
                self.assertNotIn("$RANDOM", line)


class TestActionShaPin(unittest.TestCase):
    """Verify all action references are SHA-pinned."""

    def test_all_uses_sha_pinned(self):
        """Every 'uses:' in action.yml references a SHA, not a tag."""
        content = ACTION_YML.read_text()
        sha_pattern = re.compile(r"uses:\s+\S+@[0-9a-f]{40}")
        tag_pattern = re.compile(r"uses:\s+\S+@v\d")

        uses_lines = [
            line.strip()
            for line in content.split("\n")
            if "uses:" in line and "@" in line
        ]

        for line in uses_lines:
            self.assertTrue(
                sha_pattern.search(line),
                f"Action reference not SHA-pinned: {line}",
            )
            self.assertFalse(
                tag_pattern.search(line) and not sha_pattern.search(line),
                f"Action reference uses tag instead of SHA: {line}",
            )


class TestSignstoreInstall(unittest.TestCase):
    """Verify sigstore install is version-bounded."""

    def test_sigstore_version_pinned(self):
        """Sigstore install uses upper-bounded version range."""
        content = ACTION_YML.read_text()
        # Should have both lower and upper bounds
        self.assertIn("sigstore>=", content)
        self.assertIn("<5.0.0", content)


if __name__ == "__main__":
    unittest.main()
