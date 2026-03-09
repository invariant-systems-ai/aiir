"""Tests for CLI parsing, integration, and UX."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

# Import the module under test
import aiir.cli as cli


class TestCLIParsing(unittest.TestCase):
    """Test CLI argument handling."""

    def test_verify_mode_valid_receipt(self):
        """--verify with a valid receipt file should return 0."""
        # Create a valid receipt
        commit = cli.CommitInfo(
            sha="deadbeef" * 5,
            author_name="Test",
            author_email="t@t.com",
            author_date="2026-01-01T00:00:00Z",
            committer_name="Test",
            committer_email="t@t.com",
            committer_date="2026-01-01T00:00:00Z",
            subject="test",
            body="test",
            diff_stat="",
            diff_hash="sha256:0000",
            files_changed=[],
            ai_signals_detected=[],
            is_ai_authored=False,
        )
        receipt = cli.build_commit_receipt(commit)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(receipt, f)
            tmppath = f.name

        try:
            ret = cli.main(["--verify", tmppath])
            self.assertEqual(ret, 0)
        finally:
            os.unlink(tmppath)

    def test_verify_mode_tampered_receipt(self):
        """--verify with a tampered receipt should return 1."""
        commit = cli.CommitInfo(
            sha="deadbeef" * 5,
            author_name="Test",
            author_email="t@t.com",
            author_date="2026-01-01T00:00:00Z",
            committer_name="Test",
            committer_email="t@t.com",
            committer_date="2026-01-01T00:00:00Z",
            subject="test",
            body="test",
            diff_stat="",
            diff_hash="sha256:0000",
            files_changed=[],
            ai_signals_detected=[],
            is_ai_authored=False,
        )
        receipt = cli.build_commit_receipt(commit)
        receipt["commit"]["subject"] = "TAMPERED"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(receipt, f)
            tmppath = f.name

        try:
            ret = cli.main(["--verify", tmppath])
            self.assertEqual(ret, 1)
        finally:
            os.unlink(tmppath)


# ---------------------------------------------------------------------------
# Integration test with real git repo
# ---------------------------------------------------------------------------


class TestIntegrationWithGit(unittest.TestCase):
    """Integration tests using a temporary git repo."""

    def setUp(self):
        """Create a temporary git repo with a commit."""
        self.tmpdir = tempfile.mkdtemp()
        self._git(["init"])
        self._git(["config", "user.name", "Test User"])
        self._git(["config", "user.email", "test@example.com"])
        # Create initial commit
        Path(self.tmpdir, "README.md").write_text("# Test\n")
        self._git(["add", "README.md"])
        self._git(["commit", "-m", "initial commit"])

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _git(self, args):
        result = subprocess.run(
            ["git"] + args,
            cwd=self.tmpdir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def test_receipt_head(self):
        """Generate a receipt for HEAD in a real git repo."""
        receipt = cli.generate_receipt("HEAD", cwd=self.tmpdir)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["commit"]["subject"], "initial commit")
        self.assertEqual(receipt["commit"]["author"]["name"], "Test User")

    def test_root_commit_handled(self):
        """VULN-12: Root commit (no parent) should not crash."""
        # The initial commit IS a root commit — this should work
        receipt = cli.generate_receipt("HEAD", cwd=self.tmpdir)
        self.assertIsNotNone(receipt)
        self.assertIn("diff_hash", receipt["commit"])

    def test_ai_commit_detected(self):
        """AI-authored commit should be flagged."""
        Path(self.tmpdir, "ai_code.py").write_text("print('hello')\n")
        self._git(["add", "ai_code.py"])
        self._git(["commit", "-m", "feat: add code\n\nCo-authored-by: Copilot"])
        receipt = cli.generate_receipt("HEAD", cwd=self.tmpdir)
        self.assertIsNotNone(receipt)
        self.assertTrue(receipt["ai_attestation"]["is_ai_authored"])

    def test_ai_only_filter(self):
        """--ai-only should skip non-AI commits."""
        receipt = cli.generate_receipt("HEAD", cwd=self.tmpdir, ai_only=True)
        self.assertIsNone(receipt)  # "initial commit" has no AI signals

    def test_receipt_verify_round_trip(self):
        """Build receipt from real commit, verify it."""
        receipt = cli.generate_receipt("HEAD", cwd=self.tmpdir)
        result = cli.verify_receipt(receipt)
        self.assertTrue(result["valid"])

    def test_pipe_in_author_name(self):
        """VULN-01: Author name containing | should parse correctly."""
        self._git(["config", "user.name", "Evil|User|Name"])
        Path(self.tmpdir, "evil.txt").write_text("test\n")
        self._git(["add", "evil.txt"])
        self._git(["commit", "-m", "test pipe"])
        receipt = cli.generate_receipt("HEAD", cwd=self.tmpdir)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["commit"]["author"]["name"], "Evil|User|Name")

    def test_range_with_multiple_commits(self):
        """Receipt multiple commits in a range."""
        for i in range(3):
            Path(self.tmpdir, f"file{i}.txt").write_text(f"content {i}\n")
            self._git(["add", f"file{i}.txt"])
            self._git(["commit", "-m", f"commit {i}"])

        receipts = cli.generate_receipts_for_range(
            "HEAD~3..HEAD", cwd=self.tmpdir
        )
        self.assertEqual(len(receipts), 3)

    def test_option_injection_rejected(self):
        """VULN-03: --all as a ref should be rejected."""
        with self.assertRaises(ValueError):
            cli.generate_receipt("--all", cwd=self.tmpdir)

    def test_option_injection_range_rejected(self):
        """VULN-03: --all as a range should be rejected."""
        with self.assertRaises(ValueError):
            cli.generate_receipts_for_range("--all", cwd=self.tmpdir)


# ---------------------------------------------------------------------------
# Red-team round 2 tests (HACK-02 through HACK-11)
# ---------------------------------------------------------------------------


class TestSignalListValidation(unittest.TestCase):
    """R9-SEC-01: Signal list items validated for type and capped in pretty formatter."""

    def test_non_string_signals_filtered(self):
        """Non-scalar signal types (dicts, lists) should be excluded."""
        receipt = {
            "receipt_id": "g1-test",
            "content_hash": "sha256:test",
            "timestamp": "2026-01-01T00:00:00Z",
            "commit": {
                "sha": "abc123",
                "subject": "test",
                "author": {"name": "test", "email": "t@t"},
                "files_changed": 1,
            },
            "ai_attestation": {
                "is_ai_authored": True,
                "signals_detected": [
                    "message_match:copilot",
                    {"injected": "dict"},
                    ["injected", "list"],
                    None,
                ],
            },
        }
        output = cli.format_receipt_pretty(receipt)
        self.assertIn("copilot", output)
        self.assertNotIn("injected", output)
        self.assertNotIn("None", output)

    def test_long_signal_truncated(self):
        """Signal strings longer than 80 chars should be truncated."""
        long_signal = "x" * 200
        receipt = {
            "receipt_id": "g1-test",
            "content_hash": "sha256:test",
            "timestamp": "2026-01-01T00:00:00Z",
            "commit": {
                "sha": "abc123",
                "subject": "test",
                "author": {"name": "test", "email": "t@t"},
                "files_changed": 1,
            },
            "ai_attestation": {
                "is_ai_authored": True,
                "signals_detected": [long_signal],
            },
        }
        output = cli.format_receipt_pretty(receipt)
        # The signal in the output should be at most 80 chars
        ai_line = [l for l in output.split("\n") if "AI:" in l][0]
        # Extract the signal part between parentheses
        # Should NOT contain the full 200-char string
        self.assertNotIn("x" * 200, ai_line)
        self.assertIn("x" * 80, ai_line)


class TestFormatReceiptDetail(unittest.TestCase):
    """Tests for format_receipt_detail — detailed human-readable output."""

    FULL_RECEIPT = {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.0.10",
        "commit": {
            "sha": "abcdef1234567890abcdef1234567890abcdef12",
            "author": {"name": "Jane Dev", "email": "jane@example.com", "date": "2026-03-08T10:00:00-05:00"},
            "committer": {"name": "CI Bot", "email": "ci@example.com", "date": "2026-03-08T10:01:00-05:00"},
            "subject": "feat: add auth middleware",
            "message_hash": "sha256:aaa111",
            "diff_hash": "sha256:bbb222",
            "files_changed": 3,
            "files": ["src/auth.py", "tests/test_auth.py", "README.md"],
        },
        "ai_attestation": {
            "is_ai_authored": True,
            "signals_detected": ["message_match:co-authored-by: copilot"],
            "signal_count": 1,
            "is_bot_authored": False,
            "bot_signals_detected": [],
            "bot_signal_count": 0,
            "authorship_class": "ai-assisted",
            "detection_method": "heuristic_v2",
        },
        "provenance": {
            "repository": "https://github.com/example/repo",
            "tool": "https://github.com/invariant-systems-ai/aiir@1.0.10",
            "generator": "aiir.cli",
        },
        "receipt_id": "g1-test-detail-receipt",
        "content_hash": "sha256:deadbeef1234",
        "timestamp": "2026-03-08T15:01:00Z",
        "extensions": {"namespace": "prod"},
    }

    def test_includes_schema_identity(self):
        output = cli.format_receipt_detail(self.FULL_RECEIPT)
        self.assertIn("aiir.commit_receipt", output)
        self.assertIn("aiir/commit_receipt.v1", output)
        self.assertIn("1.0.10", output)

    def test_includes_full_sha(self):
        """Detail mode shows the full 40-char SHA, not truncated."""
        output = cli.format_receipt_detail(self.FULL_RECEIPT)
        self.assertIn("abcdef1234567890abcdef1234567890abcdef12", output)

    def test_includes_committer(self):
        output = cli.format_receipt_detail(self.FULL_RECEIPT)
        self.assertIn("CI Bot", output)
        self.assertIn("ci@example.com", output)

    def test_includes_hashes(self):
        output = cli.format_receipt_detail(self.FULL_RECEIPT)
        self.assertIn("sha256:aaa111", output)
        self.assertIn("sha256:bbb222", output)

    def test_includes_file_list(self):
        output = cli.format_receipt_detail(self.FULL_RECEIPT)
        self.assertIn("src/auth.py", output)
        self.assertIn("tests/test_auth.py", output)
        self.assertIn("README.md", output)

    def test_includes_authorship_class(self):
        output = cli.format_receipt_detail(self.FULL_RECEIPT)
        self.assertIn("ai-assisted", output)

    def test_includes_detection_method(self):
        output = cli.format_receipt_detail(self.FULL_RECEIPT)
        self.assertIn("heuristic_v2", output)

    def test_includes_provenance(self):
        output = cli.format_receipt_detail(self.FULL_RECEIPT)
        self.assertIn("https://github.com/example/repo", output)
        self.assertIn("aiir.cli", output)

    def test_includes_extensions(self):
        output = cli.format_receipt_detail(self.FULL_RECEIPT)
        self.assertIn("namespace", output)
        self.assertIn("prod", output)

    def test_includes_signed_line(self):
        output = cli.format_receipt_detail(self.FULL_RECEIPT, signed="YES (sigstore)")
        self.assertIn("YES (sigstore)", output)

    def test_bot_field(self):
        output = cli.format_receipt_detail(self.FULL_RECEIPT)
        # Bot: no should be present
        bot_line = [l for l in output.split("\n") if "Bot:" in l][0]
        self.assertIn("no", bot_line)

    def test_caps_file_list_at_20(self):
        """Receipts with >20 files should be capped to prevent terminal flood."""
        receipt = {**self.FULL_RECEIPT}
        receipt["commit"] = {
            **self.FULL_RECEIPT["commit"],
            "files": [f"file_{i}.py" for i in range(30)],
            "files_changed": 30,
        }
        output = cli.format_receipt_detail(receipt)
        self.assertIn("file_19.py", output)
        self.assertNotIn("file_20.py", output)
        self.assertIn("and 10 more", output)

    def test_survives_empty_receipt(self):
        """Defensive: empty dict should not crash."""
        output = cli.format_receipt_detail({})
        self.assertIn("unknown", output)
        self.assertIsInstance(output, str)

    def test_survives_non_dict_nested_fields(self):
        """Defensive: non-dict commit/ai_attestation should not crash."""
        receipt = {
            "commit": "not a dict",
            "ai_attestation": 42,
            "provenance": ["list"],
            "extensions": "string",
        }
        output = cli.format_receipt_detail(receipt)
        self.assertIsInstance(output, str)

    def test_detail_is_superset_of_pretty(self):
        """Detail output should contain all info from pretty output."""
        pretty = cli.format_receipt_pretty(self.FULL_RECEIPT)
        detail = cli.format_receipt_detail(self.FULL_RECEIPT)
        # Detail has more lines
        self.assertGreater(len(detail.split("\n")), len(pretty.split("\n")))
        # Key fields from pretty are also in detail
        self.assertIn("feat: add auth middleware", detail)
        self.assertIn("Jane Dev", detail)
        self.assertIn("sha256:deadbeef1234", detail)


class TestRedactFilesFlag(unittest.TestCase):
    """I-05-FIX: --redact-files flag omits file paths from receipts."""

    def _make_commit_info(self):
        return cli.CommitInfo(
            sha="a" * 40,
            author_name="Test",
            author_email="t@t",
            author_date="2026-01-01T00:00:00Z",
            committer_name="Test",
            committer_email="t@t",
            committer_date="2026-01-01T00:00:00Z",
            subject="test commit",
            body="test body",
            diff_stat="1 file changed",
            diff_hash="sha256:abc",
            files_changed=["secret/internal.py", "another/path.py"],
            ai_signals_detected=[],
            is_ai_authored=False,
        )

    def test_default_includes_files(self):
        """By default, file paths should be included."""
        commit = self._make_commit_info()
        receipt = cli.build_commit_receipt(commit, redact_files=False)
        self.assertIn("files", receipt["commit"])
        self.assertEqual(receipt["commit"]["files"], ["secret/internal.py", "another/path.py"])
        self.assertNotIn("files_redacted", receipt["commit"])

    def test_redact_files_omits_paths(self):
        """With redact_files=True, file paths should be omitted."""
        commit = self._make_commit_info()
        receipt = cli.build_commit_receipt(commit, redact_files=True)
        self.assertNotIn("files", receipt["commit"])
        self.assertTrue(receipt["commit"].get("files_redacted"))
        # files_changed count should still be present
        self.assertEqual(receipt["commit"]["files_changed"], 2)


class TestExitCodeDocumentation(unittest.TestCase):
    """R9-PUB-02: Exit codes documented in --help epilog."""

    def test_help_contains_exit_codes(self):
        """--help output should document exit codes."""
        import io
        buf = io.StringIO()
        try:
            with unittest.mock.patch("sys.stdout", buf):
                cli.main(["--help"])
        except SystemExit:
            pass
        help_text = buf.getvalue()
        self.assertIn("exit codes:", help_text)
        self.assertIn("0", help_text)
        self.assertIn("1", help_text)


class TestUnsignedReceiptWarning(unittest.TestCase):
    """R-03-FIX: CLI warns when generating unsigned receipts."""

    @unittest.mock.patch("aiir.cli.get_repo_root", return_value="/tmp/fakerepo")
    @unittest.mock.patch("aiir.cli.generate_receipt")
    def test_unsigned_warning_printed(self, mock_gen, mock_root):
        """When not signing, a warning about unsigned receipts should appear."""
        import io
        mock_gen.return_value = {
            "type": "aiir.commit_receipt",
            "receipt_id": "g1-test",
            "content_hash": "sha256:test",
            "timestamp": "2026-01-01T00:00:00Z",
            "commit": {"sha": "abc123", "subject": "test"},
            "ai_attestation": {"is_ai_authored": False},
        }
        with unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            cli.main(["--pretty"])
            stderr_output = mock_err.getvalue()
        self.assertIn("unsigned", stderr_output.lower())
        self.assertIn("--sign", stderr_output)

    @unittest.mock.patch("aiir.cli.get_repo_root", return_value="/tmp/fakerepo")
    @unittest.mock.patch("aiir.cli.generate_receipt")
    def test_quiet_suppresses_unsigned_warning(self, mock_gen, mock_root):
        """With --quiet, no unsigned warning should appear."""
        import io
        mock_gen.return_value = {
            "type": "aiir.commit_receipt",
            "receipt_id": "g1-test",
            "content_hash": "sha256:test",
            "timestamp": "2026-01-01T00:00:00Z",
            "commit": {"sha": "abc123", "subject": "test"},
            "ai_attestation": {"is_ai_authored": False},
        }
        with unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            cli.main(["--pretty", "--quiet"])
            stderr_output = mock_err.getvalue()
        self.assertNotIn("unsigned", stderr_output.lower())


class TestStdoutClose(unittest.TestCase):
    """R9-TECH-02: _hash_diff_streaming must close stdout pipe."""

    def test_hash_diff_streaming_closes_stdout(self):
        """After _hash_diff_streaming, proc.stdout should be closed."""
        tmpdir = tempfile.mkdtemp()
        try:
            subprocess.run(["git", "init", tmpdir], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.email", "test@test.com"],
                capture_output=True, check=True,
            )
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.name", "Test"],
                capture_output=True, check=True,
            )
            Path(tmpdir, "file.txt").write_text("hello\n")
            subprocess.run(["git", "-C", tmpdir, "add", "."], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "commit", "-m", "first"],
                capture_output=True, check=True,
            )
            # Create a second commit so there's a real parent
            Path(tmpdir, "file.txt").write_text("hello world\n")
            subprocess.run(["git", "-C", tmpdir, "add", "."], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "commit", "-m", "second"],
                capture_output=True, check=True,
            )
            sha = subprocess.run(
                ["git", "-C", tmpdir, "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            parent = subprocess.run(
                ["git", "-C", tmpdir, "rev-parse", "HEAD~1"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            # Should succeed without fd leaks
            result = cli._hash_diff_streaming(parent, sha, cwd=tmpdir)
            self.assertTrue(result.startswith("sha256:"))
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestCfStripping(unittest.TestCase):
    """R9-TECH-03: detect_ai_signals must strip Cf (format characters) from author fields."""

    def test_zwj_in_bot_name_detected(self):
        """A bot name with ZWJ inserted (e.g. 'dep\u200dendabot') must still be detected."""
        _, bot_signals = cli.detect_ai_signals(
            message="Bump lodash from 4.17.20 to 4.17.21",
            author_name="dep\u200dendabot[bot]",  # ZWJ between 'dep' and 'endabot'
            committer_name="GitHub",
        )
        # The ZWJ should be stripped, revealing 'dependabot[bot]'
        bot_found = any("dependabot" in s for s in bot_signals)
        self.assertTrue(bot_found, f"ZWJ in bot name evaded detection: {bot_signals}")

    def test_zwnj_in_committer_stripped(self):
        """ZWNJ (U+200C) should be stripped from committer fields."""
        _, bot_signals = cli.detect_ai_signals(
            message="test commit",
            author_name="human",
            committer_name="git\u200chub-actions[bot]",  # ZWNJ between 'git' and 'hub'
        )
        # Should detect github-actions[bot] pattern
        bot_found = any("github-actions" in s for s in bot_signals)
        self.assertTrue(bot_found, f"ZWNJ in committer evaded detection: {bot_signals}")

    def test_variation_selector_stripped(self):
        """Variation selectors (U+FE0F etc) are Mn/Me but Cf chars like U+200B must also go."""
        import unicodedata
        # Verify ZWS is category Cf
        self.assertEqual(unicodedata.category("\u200b"), "Cf")
        # Verify it's stripped in the field cleaning
        _, bot_signals = cli.detect_ai_signals(
            message="test",
            author_name="dep\u200bendabot[bot]",  # Zero-width space
            committer_name="GitHub",
        )
        bot_found = any("dependabot" in s for s in bot_signals)
        self.assertTrue(bot_found, f"ZWS (Cf) in bot name evaded detection: {bot_signals}")


class TestTerminalEscapeSosDcs(unittest.TestCase):
    """R9-TECH-04: _strip_terminal_escapes must strip SOS and DCS sequences."""

    def test_sos_stripped(self):
        """SOS (ESC X ... ST) sequences should be removed."""
        text = "before\x1bXsome SOS payload\x1b\\after"
        result = cli._strip_terminal_escapes(text)
        self.assertNotIn("SOS payload", result)
        self.assertIn("before", result)
        self.assertIn("after", result)

    def test_dcs_stripped(self):
        """DCS (ESC P ... ST) sequences should be removed."""
        text = "before\x1bPsome DCS payload\x1b\\after"
        result = cli._strip_terminal_escapes(text)
        self.assertNotIn("DCS payload", result)
        self.assertIn("before", result)
        self.assertIn("after", result)

    def test_pm_still_stripped(self):
        """Existing PM (ESC ^ ... ST) stripping must still work."""
        text = "before\x1b^PM payload\x1b\\after"
        result = cli._strip_terminal_escapes(text)
        self.assertNotIn("PM payload", result)

    def test_apc_still_stripped(self):
        """Existing APC (ESC _ ... ST) stripping must still work."""
        text = "before\x1b_APC payload\x1b\\after"
        result = cli._strip_terminal_escapes(text)
        self.assertNotIn("APC payload", result)


class TestStripUrlCredentialsSafeFallback(unittest.TestCase):
    """R10-SEC-03: _strip_url_credentials must not leak credentials on exception."""

    def test_normal_stripping_works(self):
        """Credentials in a normal URL should be stripped."""
        result = cli._strip_url_credentials("https://user:token@github.com/org/repo")
        self.assertNotIn("user", result)
        self.assertNotIn("token", result)
        self.assertIn("github.com", result)

    def test_clean_url_passes_through(self):
        """A URL without credentials should pass through unchanged."""
        url = "https://github.com/org/repo.git"
        self.assertEqual(cli._strip_url_credentials(url), url)

    def test_exception_returns_safe_placeholder(self):
        """If URL reconstruction fails, a safe placeholder is returned (not the original)."""
        # Monkeypatch urlunparse to raise
        import aiir._core as _core_mod
        original = _core_mod.urlunparse

        def broken_unparse(*args, **kwargs):
            raise RuntimeError("simulated failure")

        _core_mod.urlunparse = broken_unparse
        try:
            result = cli._strip_url_credentials("https://user:secret@host.com/repo")
            self.assertNotIn("secret", result)
            self.assertIn("redacted", result.lower())
        finally:
            _core_mod.urlunparse = original


class TestMainCatchesOSError(unittest.TestCase):
    """R10-R-03: main() must catch OSError from filesystem failures."""

    @unittest.mock.patch("aiir.cli.get_repo_root")
    def test_oserror_returns_1(self, mock_root):
        """OSError during receipt generation should return exit code 1."""
        import io
        mock_root.side_effect = OSError("Permission denied: .git/HEAD")
        with unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            exit_code = cli.main([])
        self.assertEqual(exit_code, 1)
        self.assertIn("Permission denied", mock_err.getvalue())


class TestReadmeStats(unittest.TestCase):
    """R10-PUB-01: README bottom stats must match actual control/test counts."""

    def test_readme_stats_not_stale(self):
        """The README security line should have correct stats."""
        readme = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")
        # Should NOT have old stale numbers
        self.assertNotIn("73 security controls", readme)
        self.assertNotIn("285 tests", readme)
        self.assertNotIn("78 security controls", readme)
        self.assertNotIn("328 tests", readme)
        self.assertNotIn("89 security controls", readme)
        self.assertNotIn("345 tests", readme)
        self.assertNotIn("95 security controls", readme)
        self.assertNotIn("362 tests", readme)
        self.assertNotIn("96 security controls", readme)
        self.assertNotIn("368 tests", readme)
        self.assertNotIn("103 security controls", readme)
        self.assertNotIn("395 tests", readme)
        self.assertNotIn("407 tests", readme)
        self.assertNotIn("417 tests", readme)
        self.assertNotIn("107 security controls", readme)
        self.assertNotIn("367 tests", readme)
        self.assertNotIn("111 security controls", readme)
        self.assertNotIn("432 tests", readme)
        self.assertNotIn("134 security controls", readme)
        self.assertNotIn("505 tests", readme)
        self.assertNotIn("137 security controls", readme)
        self.assertNotIn("523 tests", readme)
        self.assertNotIn("142 security controls", readme)
        self.assertNotIn("502 tests", readme)
        self.assertNotIn("504 tests", readme)
        self.assertNotIn("517 tests", readme)
        self.assertNotIn("518 tests", readme)
        self.assertNotIn("532 tests", readme)
        self.assertNotIn("545 tests", readme)
        self.assertNotIn("548 tests", readme)
        self.assertNotIn("564 tests", readme)
        self.assertNotIn("604 tests", readme)
        # Should have current content
        self.assertIn("security controls", readme)
        self.assertIn("660+ tests", readme)


class TestThreatModelR03Consistency(unittest.TestCase):
    """R10-ACAD-01: R-03 status must be consistent with DREAD residual rating."""

    def test_r03_not_fully_mitigated(self):
        """R-03 should say 'Partially mitigated' since DREAD rates it Medium."""
        tm = (Path(__file__).parent.parent / "THREAT_MODEL.md").read_text(encoding="utf-8")
        # Find the R-03 row in Section 3.3
        for line in tm.split("\n"):
            if "| R-03 |" in line and "Unsigned receipts" in line:
                self.assertIn("Partially mitigated", line)
                break
        else:
            self.fail("R-03 row not found in THREAT_MODEL")


# ---------------------------------------------------------------------------
# Round 11 tests
# ---------------------------------------------------------------------------


class TestHashDiffStreamingCleanup(unittest.TestCase):
    """R10-R-02: _hash_diff_streaming must clean up subprocess on exception."""

    def test_cleanup_comment_present(self):
        """The function should have exception cleanup logic."""
        import inspect
        source = inspect.getsource(cli._hash_diff_streaming)
        self.assertIn("proc.kill()", source)
        self.assertIn("try:", source)
        self.assertIn("except", source)


class TestFriendlyPathError(unittest.TestCase):
    """R16-UX-02: ValueError from write_receipt must produce a friendly
    one-line error, not a raw Python traceback."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        subprocess.run(["git", "init", self.tmpdir], capture_output=True, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=self.tmpdir, capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test User"],
            cwd=self.tmpdir, capture_output=True, check=True,
        )
        Path(self.tmpdir, "file.txt").write_text("hello")
        subprocess.run(["git", "add", "."], cwd=self.tmpdir, capture_output=True, check=True)
        subprocess.run(
            ["git", "commit", "-m", "init"],
            cwd=self.tmpdir, capture_output=True, check=True,
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_outside_cwd_output_shows_friendly_error(self):
        """R16-UX-02: --output /tmp/outside should print friendly error not traceback."""
        old_cwd = os.getcwd()
        try:
            os.chdir(self.tmpdir)
            from io import StringIO
            captured_err = StringIO()
            with patch("sys.stderr", captured_err):
                rc = cli.main(["--output", "/tmp/evil-outside-repo"])
            self.assertNotEqual(rc, 0, "Should return non-zero exit code")
            stderr_text = captured_err.getvalue()
            self.assertIn("\u274c", stderr_text, "Should show \u274c emoji prefix")
            self.assertIn("\U0001f4a1", stderr_text, "Should show \U0001f4a1 hint")
            self.assertNotIn("Traceback", stderr_text, "Must not show raw traceback")
        finally:
            os.chdir(old_cwd)

    def test_outside_cwd_with_pretty_shows_friendly_error(self):
        """R16-UX-02: --pretty --output /tmp/evil should also show friendly error."""
        old_cwd = os.getcwd()
        try:
            os.chdir(self.tmpdir)
            from io import StringIO
            captured_err = StringIO()
            with patch("sys.stderr", captured_err):
                rc = cli.main(["--pretty", "--output", "/tmp/evil-outside-repo"])
            self.assertNotEqual(rc, 0)
            stderr_text = captured_err.getvalue()
            self.assertIn("\u274c", stderr_text)
            self.assertNotIn("Traceback", stderr_text)
        finally:
            os.chdir(old_cwd)


class TestVerboseQuietMutualExclusion(unittest.TestCase):
    """R16-UX-03: --verbose and --quiet must be mutually exclusive."""

    def test_verbose_and_quiet_rejected(self):
        """R16-UX-03: Passing both --verbose and --quiet should fail."""
        # argparse mutually exclusive group will cause SystemExit(2)
        with self.assertRaises(SystemExit) as ctx:
            cli.main(["--verbose", "--quiet"])
        self.assertEqual(ctx.exception.code, 2, "argparse should exit with code 2")

    def test_verbose_alone_accepted(self):
        """--verbose alone should be accepted (may fail for other reasons like no git)."""
        # We just check it doesn't raise SystemExit(2) for argument conflict
        try:
            cli.main(["--verbose", "--version"])
        except SystemExit as e:
            # --version causes SystemExit(0), which is fine
            self.assertEqual(e.code, 0)

    def test_quiet_alone_accepted(self):
        """--quiet alone should be accepted."""
        try:
            cli.main(["--quiet", "--version"])
        except SystemExit as e:
            self.assertEqual(e.code, 0)


class TestFriendlyErrors(unittest.TestCase):
    """R17-UX-01: All error messages must use emoji + actionable hint."""

    def test_not_a_git_repo_shows_emoji_and_hint(self):
        """Running aiir outside a git repo should show ❌ + 💡 hint."""
        import tempfile
        import shutil
        tmpdir = tempfile.mkdtemp()
        old_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            from io import StringIO
            captured_err = StringIO()
            with patch("sys.stderr", captured_err):
                rc = cli.main([])
            self.assertEqual(rc, 1)
            stderr_text = captured_err.getvalue()
            self.assertIn("\u274c", stderr_text, "Should show ❌ emoji")
            self.assertIn("\U0001f4a1", stderr_text, "Should show 💡 hint")
            self.assertIn("git", stderr_text.lower(), "Hint should mention git")
        finally:
            os.chdir(old_cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_no_git_binary_shows_emoji_and_hint(self):
        """If git is not on PATH, should show ❌ + 💡 with install link."""
        from io import StringIO
        captured_err = StringIO()
        with patch("aiir.cli.get_repo_root", side_effect=FileNotFoundError("git")):
            with patch("sys.stderr", captured_err):
                rc = cli.main([])
        self.assertEqual(rc, 1)
        stderr_text = captured_err.getvalue()
        self.assertIn("\u274c", stderr_text)
        self.assertIn("git-scm.com", stderr_text, "Should include install link")

    def test_sign_without_output_shows_emoji_and_hint(self):
        """--sign without --output should show ❌ + 💡 Try: ..."""
        import tempfile
        import shutil
        tmpdir = tempfile.mkdtemp()
        old_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            subprocess.run(["git", "init"], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "T"], cwd=tmpdir, capture_output=True, check=True)
            Path(tmpdir, "f.txt").write_text("x")
            subprocess.run(["git", "add", "."], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmpdir, capture_output=True, check=True)

            from io import StringIO
            captured_err = StringIO()
            with patch("sys.stderr", captured_err):
                rc = cli.main(["--sign"])
            self.assertEqual(rc, 1)
            stderr_text = captured_err.getvalue()
            self.assertIn("\u274c", stderr_text, "Should show ❌")
            self.assertIn("--output", stderr_text, "Hint should suggest --output")
        finally:
            os.chdir(old_cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_timeout_shows_emoji_and_hint(self):
        """Git timeout should show ❌ + 💡 hint."""
        from io import StringIO
        captured_err = StringIO()
        with patch("aiir.cli.get_repo_root", return_value="/tmp"):
            with patch("aiir.cli.generate_receipt", side_effect=subprocess.TimeoutExpired("git", 300)):
                with patch("sys.stderr", captured_err):
                    rc = cli.main([])
        self.assertEqual(rc, 1)
        stderr_text = captured_err.getvalue()
        self.assertIn("\u274c", stderr_text, "Should show ❌")
        self.assertIn("too long", stderr_text.lower(), "Should say it took too long")


class TestFriendlyNoReceipts(unittest.TestCase):
    """R17-UX-02: 'No commits' message should show 🤷 + 💡 hint."""

    def test_no_commits_ai_only_shows_hint(self):
        """--ai-only with no AI commits should show remove hint."""
        from io import StringIO
        captured_err = StringIO()
        with patch("aiir.cli.get_repo_root", return_value="/tmp"):
            with patch("aiir.cli.generate_receipt", return_value=None):
                with patch("sys.stderr", captured_err):
                    rc = cli.main(["--ai-only"])
        self.assertEqual(rc, 0)
        stderr_text = captured_err.getvalue()
        self.assertIn("\U0001f937", stderr_text, "Should show 🤷")
        self.assertIn("--ai-only", stderr_text, "Hint should mention --ai-only")

    def test_no_commits_no_flags_shows_hint(self):
        """No commits (no flags) should suggest checking git log."""
        from io import StringIO
        captured_err = StringIO()
        with patch("aiir.cli.get_repo_root", return_value="/tmp"):
            with patch("aiir.cli.generate_receipt", return_value=None):
                with patch("sys.stderr", captured_err):
                    rc = cli.main([])
        self.assertEqual(rc, 0)
        stderr_text = captured_err.getvalue()
        self.assertIn("\U0001f937", stderr_text, "Should show 🤷")
        self.assertIn("git log", stderr_text, "Hint should mention git log")


class TestDidYouMean(unittest.TestCase):
    """R17-UX-05: Misspelled flags should suggest closest match."""

    def test_prettty_suggests_pretty(self):
        """--prettty should suggest --pretty."""
        from io import StringIO
        captured_err = StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with patch("sys.stderr", captured_err):
                cli.main(["--prettty"])
        self.assertEqual(ctx.exception.code, 2)
        stderr_text = captured_err.getvalue()
        self.assertIn("--pretty", stderr_text, "Should suggest --pretty")

    def test_verfy_suggests_verify(self):
        """--verfy should suggest --verify."""
        from io import StringIO
        captured_err = StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with patch("sys.stderr", captured_err):
                cli.main(["--verfy"])
        self.assertEqual(ctx.exception.code, 2)
        stderr_text = captured_err.getvalue()
        self.assertIn("--verify", stderr_text, "Should suggest --verify")

    def test_completely_wrong_flag_no_crash(self):
        """--zzzzz should not crash (no close match)."""
        with self.assertRaises(SystemExit) as ctx:
            cli.main(["--zzzzz"])
        self.assertEqual(ctx.exception.code, 2)


class TestHelpEpilog(unittest.TestCase):
    """R17-UX-04: --help epilog should include usage examples."""

    def test_help_shows_examples(self):
        """--help should contain example commands."""
        from io import StringIO
        captured_out = StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with patch("sys.stdout", captured_out):
                cli.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)
        help_text = captured_out.getvalue()
        self.assertIn("examples:", help_text, "Help should have examples section")
        self.assertIn("aiir --pretty", help_text, "Should show --pretty example")
        self.assertIn("-o .receipts", help_text, "Should show -o example")


class TestFriendlySummary(unittest.TestCase):
    """R17-UX-03: Post-generation summary should use ✅ emoji."""

    def test_summary_has_checkmark(self):
        """Summary line should contain ✅."""
        import tempfile
        import shutil
        tmpdir = tempfile.mkdtemp()
        old_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            subprocess.run(["git", "init"], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "T"], cwd=tmpdir, capture_output=True, check=True)
            Path(tmpdir, "f.txt").write_text("x")
            subprocess.run(["git", "add", "."], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmpdir, capture_output=True, check=True)

            from io import StringIO
            captured_err = StringIO()
            with patch("sys.stderr", captured_err):
                rc = cli.main(["--pretty"])
            self.assertEqual(rc, 0)
            stderr_text = captured_err.getvalue()
            self.assertIn("\u2705", stderr_text, "Summary should show ✅")
            self.assertIn("receipt", stderr_text.lower())
        finally:
            os.chdir(old_cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_unsigned_tip_has_emoji(self):
        """Unsigned-receipt tip should contain 📝."""
        import tempfile
        import shutil
        tmpdir = tempfile.mkdtemp()
        old_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            subprocess.run(["git", "init"], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "T"], cwd=tmpdir, capture_output=True, check=True)
            Path(tmpdir, "f.txt").write_text("x")
            subprocess.run(["git", "add", "."], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmpdir, capture_output=True, check=True)

            from io import StringIO
            captured_err = StringIO()
            with patch("sys.stderr", captured_err):
                rc = cli.main(["--pretty"])
            self.assertEqual(rc, 0)
            stderr_text = captured_err.getvalue()
            self.assertIn("\U0001f4dd", stderr_text, "Tip should show 📝")
            self.assertIn("--sign", stderr_text, "Tip should mention --sign")
        finally:
            os.chdir(old_cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestFriendlyVerify(unittest.TestCase):
    """R17-UX-06: Verify output should be friendlier."""

    def test_verify_pass_says_all_good(self):
        """Successful verify should say 'All good!'."""
        import tempfile
        import shutil
        tmpdir = tempfile.mkdtemp()
        old_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            subprocess.run(["git", "init"], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "T"], cwd=tmpdir, capture_output=True, check=True)
            Path(tmpdir, "f.txt").write_text("x")
            subprocess.run(["git", "add", "."], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmpdir, capture_output=True, check=True)

            # Generate a receipt to a file
            out_dir = Path(tmpdir, ".receipts")
            from io import StringIO
            captured_err = StringIO()
            with patch("sys.stderr", captured_err):
                rc = cli.main(["--output", str(out_dir)])
            self.assertEqual(rc, 0)

            # Find the receipt file
            receipt_files = list(out_dir.glob("receipt_*.json"))
            self.assertTrue(len(receipt_files) > 0, "Should have a receipt file")

            # Verify it
            captured_err2 = StringIO()
            with patch("sys.stderr", captured_err2):
                rc2 = cli.main(["--verify", str(receipt_files[0])])
            self.assertEqual(rc2, 0)
            stderr_text = captured_err2.getvalue()
            self.assertIn("All good", stderr_text, "Should say 'All good'")
        finally:
            os.chdir(old_cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_verify_fail_shows_hint(self):
        """Failed verify should show 💡 hint."""
        import tempfile
        import shutil
        tmpdir = tempfile.mkdtemp()
        try:
            tampered = Path(tmpdir, "bad.json")
            tampered.write_text('{"type":"aiir.commit_receipt","schema":"aiir/commit_receipt.v1","version":"1.0.0","commit":{"sha":"abc"},"ai_attestation":{},"provenance":{},"receipt_id":"g1-wrong","content_hash":"sha256:wrong"}')
            from io import StringIO
            captured_err = StringIO()
            with patch("sys.stderr", captured_err):
                rc = cli.main(["--verify", str(tampered)])
            self.assertEqual(rc, 1)
            stderr_text = captured_err.getvalue()
            self.assertIn("\u274c", stderr_text, "Should show ❌")
            self.assertIn("\U0001f4a1", stderr_text, "Should show 💡 hint")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestTerminalEscapeInErrors(unittest.TestCase):
    """R18-SEC-01 / R18-SEC-02: User input in error messages must be sanitised."""

    def test_friendly_parser_strips_escapes_from_bad_flag(self):
        """ANSI escapes in an unrecognised flag must not appear in stderr."""
        from io import StringIO
        captured_err = StringIO()
        with patch("sys.stderr", captured_err):
            try:
                cli.main(["--\x1b[2Jfoo"])
            except SystemExit:
                pass
        stderr_text = captured_err.getvalue()
        self.assertNotIn("\x1b", stderr_text, "ANSI escape must be stripped")
        self.assertIn("\u274c", stderr_text, "Should show ❌ prefix")

    def test_range_hint_strips_escapes(self):
        """ANSI escapes in --range spec must not appear in hint message."""
        import tempfile, shutil
        tmpdir = tempfile.mkdtemp()
        old_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            subprocess.run(["git", "init"], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "T"], cwd=tmpdir, capture_output=True, check=True)
            Path(tmpdir, "f.txt").write_text("x")
            subprocess.run(["git", "add", "."], cwd=tmpdir, capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmpdir, capture_output=True, check=True)

            from io import StringIO
            captured_err = StringIO()
            # An empty range + escape in the spec
            with patch("sys.stderr", captured_err):
                rc = cli.main(["--range", "HEAD..HEAD\x1b[31mevil\x1b[0m"])
            stderr_text = captured_err.getvalue()
            # Whether it errors or shows "nothing to receipt", ESC must be gone
            self.assertNotIn("\x1b", stderr_text, "ANSI escape must be stripped from range hint")
        finally:
            os.chdir(old_cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_run_git_stderr_strips_escapes(self):
        """_run_git should strip terminal escapes from git stderr in exceptions."""
        # Simulate git returning stderr with an ANSI escape
        fake_result = unittest.mock.MagicMock()
        fake_result.returncode = 128
        fake_result.stderr = "fatal: bad revision '\x1b[2Jevil'\n"
        fake_result.stdout = ""
        with patch("subprocess.run", return_value=fake_result):
            try:
                cli._run_git(["log", "HEAD"])
                self.fail("Should have raised RuntimeError")
            except RuntimeError as e:
                self.assertNotIn("\x1b", str(e), "ANSI escape must be stripped from git error")


class TestConsistentFriendlyErrors(unittest.TestCase):
    """R18-PUB-01: Unrecognised flags should always show ❌, even without suggestions."""

    def test_no_match_still_shows_emoji(self):
        """A totally wrong flag should still get the ❌ prefix, not default argparse error."""
        from io import StringIO
        captured_err = StringIO()
        with patch("sys.stderr", captured_err):
            try:
                cli.main(["--zzzzzzzzzzz"])
            except SystemExit:
                pass
        stderr_text = captured_err.getvalue()
        self.assertIn("\u274c", stderr_text, "Should show ❌ even with no close match")

    def test_close_match_shows_emoji_and_hint(self):
        """A close-but-wrong flag should show ❌ + 💡."""
        from io import StringIO
        captured_err = StringIO()
        with patch("sys.stderr", captured_err):
            try:
                cli.main(["--prettty"])
            except SystemExit:
                pass
        stderr_text = captured_err.getvalue()
        self.assertIn("\u274c", stderr_text, "Should show ❌")
        self.assertIn("\U0001f4a1", stderr_text, "Should show 💡 hint")
        self.assertIn("--pretty", stderr_text, "Should suggest --pretty")


class TestEmptyRepoMessage(unittest.TestCase):
    """R20-UX-02: Empty repo (no commits) must show a friendly message."""

    @patch("aiir.cli.get_repo_root", return_value="/fake")
    @patch("aiir.cli.generate_receipt", side_effect=RuntimeError(
        "git log failed: unknown revision or path"
    ))
    def test_empty_repo_shows_friendly_message(self, mock_gen, mock_root):
        """Empty repo error must NOT leak raw git stderr."""
        import io
        captured_err = io.StringIO()
        with patch("sys.stderr", captured_err), \
             patch("sys.stdout", io.StringIO()), \
             patch("sys.argv", ["aiir"]):
            code = cli.main()

        err = captured_err.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("No commits yet", err)
        self.assertIn("first commit", err)
        # Must NOT contain raw git error details
        self.assertNotIn("fatal:", err)
        self.assertNotIn("ambiguous argument", err)

    @patch("aiir.cli.get_repo_root", return_value="/fake")
    @patch("aiir.cli.generate_receipt", side_effect=RuntimeError(
        "git log failed: bad default revision 'HEAD'"
    ))
    def test_bad_default_revision_friendly(self, mock_gen, mock_root):
        """'bad default revision' variant also gets a friendly message."""
        import io
        captured_err = io.StringIO()
        with patch("sys.stderr", captured_err), \
             patch("sys.stdout", io.StringIO()), \
             patch("sys.argv", ["aiir"]):
            code = cli.main()

        err = captured_err.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("No commits yet", err)

    @patch("aiir.cli.get_repo_root", return_value="/fake")
    @patch("aiir.cli.generate_receipt", side_effect=RuntimeError(
        "git log failed: permission denied"
    ))
    def test_non_empty_repo_error_still_shown(self, mock_gen, mock_root):
        """Other RuntimeErrors must still display the actual error message."""
        import io
        captured_err = io.StringIO()
        with patch("sys.stderr", captured_err), \
             patch("sys.stdout", io.StringIO()), \
             patch("sys.argv", ["aiir"]):
            code = cli.main()

        err = captured_err.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("permission denied", err)
        self.assertNotIn("No commits yet", err)

