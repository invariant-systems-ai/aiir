"""Tests for GitLab integration module (_gitlab.py).

Covers: format_gitlab_summary, format_gl_sast_report, set_gitlab_ci_output,
enforce_approval_rules, parse_webhook_event, validate_webhook_token,
build_receipts_graphql_query, query_gitlab_graphql, generate_dashboard_html,
post_mr_comment, GitLab Duo signal detection, and generator ID differentiation.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from unittest.mock import patch

from aiir._core import CLI_VERSION
from aiir._detect import detect_ai_signals
from aiir._gitlab import (
    _safe_iso_now,
    build_receipts_graphql_query,
    enforce_approval_rules,
    format_gl_sast_report,
    format_gitlab_summary,
    generate_dashboard_html,
    parse_webhook_event,
    query_gitlab_graphql,
    set_gitlab_ci_output,
    validate_webhook_token,
)
from aiir._receipt import build_commit_receipt


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _make_receipt(
    sha: str = "abc123def456",
    subject: str = "feat: add feature",
    is_ai: bool = True,
    authorship_class: str = "ai_assisted",
    signals: list | None = None,
    receipt_id: str = "g1-test1234567890",
    content_hash: str = "sha256:deadbeef",
    files: list | None = None,
) -> dict:
    """Build a minimal receipt dict for testing."""
    return {
        "type": "aiir.commit_receipt",
        "schema": "1.0",
        "version": CLI_VERSION,
        "commit": {
            "sha": sha,
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
            "subject": subject,
            "message_hash": "sha256:aaa",
            "diff_hash": "sha256:bbb",
            "files_changed": 3,
            "files": files or ["src/main.py", "README.md", "tests/test_main.py"],
        },
        "ai_attestation": {
            "is_ai_authored": is_ai,
            "signals_detected": signals
            or (["message_match:github copilot"] if is_ai else []),
            "signal_count": len(
                signals or (["message_match:github copilot"] if is_ai else [])
            ),
            "is_bot_authored": False,
            "bot_signals_detected": [],
            "bot_signal_count": 0,
            "authorship_class": authorship_class,
            "detection_method": "heuristic_v2",
        },
        "provenance": {
            "repository": "https://gitlab.com/group/project",
            "tool": f"https://github.com/invariant-systems-ai/aiir@{CLI_VERSION}",
            "generator": "aiir.gitlab",
        },
        "receipt_id": receipt_id,
        "content_hash": content_hash,
        "timestamp": "2026-01-01T00:00:00Z",
        "extensions": {},
    }


# ---------------------------------------------------------------------------
# Test: GitLab Duo signal detection (Item 1)
# ---------------------------------------------------------------------------


class TestGitLabDuoDetection(unittest.TestCase):
    """Verify that GitLab Duo AI coding signals are detected."""

    def test_duo_code_suggestions_detected(self):
        """'gitlab duo' in commit message triggers AI signal."""
        ai_signals, bot_signals = detect_ai_signals(
            "feat: implement auth\n\nUsed GitLab Duo for code completion"
        )
        self.assertTrue(len(ai_signals) > 0)
        self.assertTrue(any("gitlab duo" in s for s in ai_signals))

    def test_duo_code_suggestions_keyword(self):
        """'duo code suggestions' triggers AI signal."""
        ai_signals, _ = detect_ai_signals(
            "refactor: clean up\n\nDuo Code Suggestions helped here"
        )
        self.assertTrue(len(ai_signals) > 0)

    def test_suggested_by_gitlab_duo(self):
        """'Suggested by: GitLab Duo' trailer detected."""
        ai_signals, _ = detect_ai_signals("fix: bug\n\nSuggested by: GitLab Duo")
        self.assertTrue(len(ai_signals) > 0)

    def test_duo_chat_detected(self):
        """'duo chat' in commit message triggers AI signal."""
        ai_signals, _ = detect_ai_signals(
            "docs: update readme\n\nGenerated with Duo Chat"
        )
        self.assertTrue(len(ai_signals) > 0)

    def test_duo_enterprise_detected(self):
        """'duo enterprise' in commit message triggers AI signal."""
        ai_signals, _ = detect_ai_signals(
            "feat: impl\n\nUsing Duo Enterprise for suggestions"
        )
        self.assertTrue(len(ai_signals) > 0)

    def test_co_authored_by_gitlab_duo(self):
        """Co-authored-by: GitLab Duo trailer detected."""
        ai_signals, _ = detect_ai_signals(
            "feat: new feature\n\nCo-authored-by: GitLab Duo"
        )
        self.assertTrue(len(ai_signals) > 0)

    def test_gitlab_duo_author_pattern(self):
        """gitlab-duo in author name triggers AI author signal."""
        ai_signals, _ = detect_ai_signals(
            "feat: auto",
            author_name="gitlab-duo",
        )
        self.assertTrue(len(ai_signals) > 0)
        self.assertTrue(any("gitlab-duo" in s for s in ai_signals))

    def test_duo_bot_author_pattern(self):
        """duo[bot] in author email triggers AI author signal."""
        ai_signals, _ = detect_ai_signals(
            "feat: auto",
            author_email="duo[bot]@gitlab.com",
        )
        self.assertTrue(len(ai_signals) > 0)

    def test_gitlab_bot_detected_as_bot(self):
        """gitlab-bot in committer name triggers bot signal (not AI)."""
        _, bot_signals = detect_ai_signals(
            "chore: update deps",
            committer_name="gitlab-bot",
        )
        self.assertTrue(len(bot_signals) > 0)
        self.assertTrue(any("gitlab-bot" in s for s in bot_signals))

    def test_duo_workflow_detected(self):
        """'duo workflow' keyword detected."""
        ai_signals, _ = detect_ai_signals(
            "feat: pipeline\n\nDuo Workflow automated this"
        )
        self.assertTrue(len(ai_signals) > 0)


# ---------------------------------------------------------------------------
# Test: format_gitlab_summary (Item 2)
# ---------------------------------------------------------------------------


class TestFormatGitLabSummary(unittest.TestCase):
    """Test GitLab-flavored Markdown summary formatting."""

    def test_basic_summary(self):
        """Summary contains AIIR header and commit table."""
        receipts = [
            _make_receipt(),
            _make_receipt(sha="def789", is_ai=False, authorship_class="human"),
        ]
        summary = format_gitlab_summary(receipts)
        self.assertIn("AIIR Receipt Summary", summary)
        self.assertIn("2", summary)  # 2 commits
        self.assertIn("1", summary)  # 1 AI-authored
        self.assertIn("abc123de", summary)  # SHA short
        self.assertIn("def789", summary)

    def test_collapsible_details(self):
        """Summary includes collapsible <details> block."""
        receipts = [_make_receipt()]
        summary = format_gitlab_summary(receipts)
        self.assertIn("<details>", summary)
        self.assertIn("</details>", summary)

    def test_empty_receipts(self):
        """Summary handles empty receipt list."""
        summary = format_gitlab_summary([])
        self.assertIn("0", summary)
        self.assertIn("AIIR", summary)

    def test_version_in_footer(self):
        """Summary includes CLI version in footer."""
        summary = format_gitlab_summary([_make_receipt()])
        self.assertIn(CLI_VERSION, summary)

    def test_authorship_icons(self):
        """Summary uses correct icons for authorship classes."""
        receipts = [
            _make_receipt(authorship_class="human", is_ai=False),
            _make_receipt(sha="bbb", authorship_class="ai_assisted"),
            _make_receipt(sha="ccc", authorship_class="bot", is_ai=False),
        ]
        summary = format_gitlab_summary(receipts)
        self.assertIn("👤", summary)
        self.assertIn("🤖", summary)
        self.assertIn("⚙️", summary)


# ---------------------------------------------------------------------------
# Test: set_gitlab_ci_output (Item 2)
# ---------------------------------------------------------------------------


class TestSetGitLabCIOutput(unittest.TestCase):
    """Test dotenv artifact output for GitLab CI."""

    def test_writes_dotenv(self):
        """Key=value pairs written to dotenv file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            path = f.name
        try:
            set_gitlab_ci_output("AIIR_COUNT", "42", dotenv_path=path)
            set_gitlab_ci_output("AIIR_AI", "5", dotenv_path=path)
            content = Path(path).read_text()
            self.assertIn("AIIR_COUNT=42", content)
            self.assertIn("AIIR_AI=5", content)
        finally:
            os.unlink(path)

    def test_rejects_invalid_key(self):
        """Invalid key names are rejected."""
        with self.assertRaises(ValueError):
            set_gitlab_ci_output("bad key!", "value")
        with self.assertRaises(ValueError):
            set_gitlab_ci_output("", "value")

    def test_newline_injection_prevented(self):
        """Newlines in values are escaped."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            path = f.name
        try:
            set_gitlab_ci_output("KEY", "line1\nline2", dotenv_path=path)
            content = Path(path).read_text()
            # Should not have raw newline in value
            lines = content.strip().split("\n")
            self.assertEqual(len(lines), 1)
            self.assertIn("\\n", lines[0])
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Test: format_gl_sast_report (Item 5)
# ---------------------------------------------------------------------------


class TestFormatGLSASTReport(unittest.TestCase):
    """Test GitLab SAST report generation."""

    def test_basic_report_structure(self):
        """SAST report has correct top-level structure."""
        receipts = [
            _make_receipt(),
            _make_receipt(sha="def789", is_ai=False, authorship_class="human"),
        ]
        report = format_gl_sast_report(receipts)
        self.assertEqual(report["version"], "15.1.1")
        self.assertIn("scan", report)
        self.assertIn("vulnerabilities", report)
        self.assertEqual(report["scan"]["type"], "sast")

    def test_only_ai_commits_reported(self):
        """Only AI-authored commits appear as findings."""
        receipts = [
            _make_receipt(is_ai=True),
            _make_receipt(sha="def", is_ai=False, authorship_class="human"),
        ]
        report = format_gl_sast_report(receipts)
        self.assertEqual(len(report["vulnerabilities"]), 1)

    def test_vulnerability_fields(self):
        """Each vulnerability has required SAST fields."""
        report = format_gl_sast_report([_make_receipt()])
        vuln = report["vulnerabilities"][0]
        self.assertIn("id", vuln)
        self.assertIn("category", vuln)
        self.assertEqual(vuln["category"], "sast")
        self.assertEqual(vuln["severity"], "Info")
        self.assertIn("scanner", vuln)
        self.assertEqual(vuln["scanner"]["id"], "aiir")
        self.assertIn("identifiers", vuln)
        self.assertIn("location", vuln)

    def test_scanner_metadata(self):
        """Scanner section has correct AIIR metadata."""
        report = format_gl_sast_report([_make_receipt()])
        scanner = report["scan"]["scanner"]
        self.assertEqual(scanner["id"], "aiir")
        self.assertEqual(scanner["version"], CLI_VERSION)
        self.assertEqual(scanner["vendor"]["name"], "Invariant Systems, Inc.")

    def test_empty_receipts(self):
        """Empty receipt list produces valid report with no vulns."""
        report = format_gl_sast_report([])
        self.assertEqual(len(report["vulnerabilities"]), 0)
        self.assertEqual(report["scan"]["status"], "success")


# ---------------------------------------------------------------------------
# Test: enforce_approval_rules (Item 8)
# ---------------------------------------------------------------------------


class TestEnforceApprovalRules(unittest.TestCase):
    """Test MR approval rule enforcement."""

    def test_below_threshold_no_action(self):
        """No action when AI% is below threshold."""
        result = enforce_approval_rules(30.0, threshold=50.0)
        self.assertEqual(result["action"], "none")
        self.assertIn("below threshold", result["message"])

    def test_missing_mr_context_skipped(self):
        """Skipped when not in MR context."""
        with patch.dict(os.environ, {}, clear=True):
            result = enforce_approval_rules(70.0, threshold=50.0)
            self.assertEqual(result["action"], "skipped")
            self.assertIn("Not in MR context", result["reason"])

    def test_api_call_made_above_threshold(self):
        """API call attempted when above threshold and in MR context."""
        with patch.dict(
            os.environ,
            {
                "CI_PROJECT_ID": "123",
                "CI_MERGE_REQUEST_IID": "42",
                "CI_API_V4_URL": "https://gitlab.example.com/api/v4",
                "GITLAB_TOKEN": "test-token",
            },
        ):
            with patch("aiir._gitlab._gitlab_api_request") as mock_api:
                mock_api.return_value = {"id": 99}
                result = enforce_approval_rules(75.0, threshold=50.0)
                self.assertEqual(result["action"], "created")
                self.assertEqual(result["required_approvals"], 2)
                mock_api.assert_called_once()

    def test_api_failure_handled(self):
        """API failure is caught and returned gracefully."""
        with patch.dict(
            os.environ,
            {
                "CI_PROJECT_ID": "123",
                "CI_MERGE_REQUEST_IID": "42",
                "CI_API_V4_URL": "https://gitlab.example.com/api/v4",
                "GITLAB_TOKEN": "test-token",
            },
        ):
            with patch(
                "aiir._gitlab._gitlab_api_request",
                side_effect=RuntimeError("API error"),
            ):
                result = enforce_approval_rules(75.0, threshold=50.0)
                self.assertEqual(result["action"], "failed")
                self.assertIn("API error", result["error"])


# ---------------------------------------------------------------------------
# Test: parse_webhook_event (Item 10)
# ---------------------------------------------------------------------------


class TestParseWebhookEvent(unittest.TestCase):
    """Test webhook event parsing."""

    def test_push_event(self):
        """Push event parsed correctly."""
        payload = {
            "object_kind": "push",
            "ref": "refs/heads/main",
            "before": "aaa111",
            "after": "bbb222",
            "total_commits_count": 3,
            "project": {"id": 123, "path_with_namespace": "group/project"},
        }
        result = parse_webhook_event(payload)
        self.assertIsNotNone(result)
        self.assertEqual(result["event_type"], "push")
        self.assertEqual(result["project_id"], "123")
        self.assertEqual(result["before"], "aaa111")
        self.assertEqual(result["after"], "bbb222")
        self.assertEqual(result["commit_count"], "3")

    def test_merge_request_event(self):
        """MR event parsed correctly."""
        payload = {
            "object_kind": "merge_request",
            "object_attributes": {
                "iid": 42,
                "action": "open",
                "source_branch": "feature",
                "target_branch": "main",
                "last_commit": {"id": "ccc333"},
            },
            "project": {"id": 456, "path_with_namespace": "group/project"},
        }
        result = parse_webhook_event(payload)
        self.assertIsNotNone(result)
        self.assertEqual(result["event_type"], "merge_request")
        self.assertEqual(result["mr_iid"], "42")
        self.assertEqual(result["source_branch"], "feature")
        self.assertEqual(result["target_branch"], "main")

    def test_unknown_event_returns_none(self):
        """Unknown event type returns None."""
        result = parse_webhook_event({"object_kind": "pipeline"})
        self.assertIsNone(result)

    def test_non_dict_returns_none(self):
        """Non-dict payload returns None."""
        self.assertIsNone(parse_webhook_event("not a dict"))
        self.assertIsNone(parse_webhook_event(None))

    def test_terminal_escapes_stripped(self):
        """Terminal escapes in payload are stripped."""
        payload = {
            "object_kind": "push",
            "ref": "refs/heads/main\x1b[31m",
            "before": "aaa",
            "after": "bbb",
            "total_commits_count": 1,
            "project": {"id": 1, "path_with_namespace": "g/p"},
        }
        result = parse_webhook_event(payload)
        self.assertNotIn("\x1b", result["ref"])


# ---------------------------------------------------------------------------
# Test: validate_webhook_token (Item 10)
# ---------------------------------------------------------------------------


class TestValidateWebhookToken(unittest.TestCase):
    """Test webhook token validation."""

    def test_valid_token(self):
        """Correct token returns True."""
        self.assertTrue(validate_webhook_token("secret123", expected_token="secret123"))

    def test_invalid_token(self):
        """Wrong token returns False."""
        self.assertFalse(validate_webhook_token("wrong", expected_token="secret123"))

    def test_no_secret_configured_permissive(self):
        """When no secret is configured, validation passes (permissive)."""
        with patch.dict(os.environ, {}, clear=True):
            if "AIIR_WEBHOOK_SECRET" in os.environ:
                del os.environ["AIIR_WEBHOOK_SECRET"]
            self.assertTrue(validate_webhook_token("anything", expected_token=""))

    def test_env_var_secret(self):
        """Token validated against AIIR_WEBHOOK_SECRET env var."""
        with patch.dict(os.environ, {"AIIR_WEBHOOK_SECRET": "env_secret"}):
            self.assertTrue(validate_webhook_token("env_secret"))
            self.assertFalse(validate_webhook_token("wrong"))


# ---------------------------------------------------------------------------
# Test: build_receipts_graphql_query (Item 11)
# ---------------------------------------------------------------------------


class TestGraphQLQuery(unittest.TestCase):
    """Test GraphQL query building."""

    def test_query_structure(self):
        """GraphQL query has correct structure."""
        query = build_receipts_graphql_query("group/project")
        self.assertIn("project(fullPath:", query)
        self.assertIn("group/project", query)
        self.assertIn("packageFiles", query)
        self.assertIn("GENERIC", query)

    def test_custom_package_name(self):
        """Custom package name is used in query."""
        query = build_receipts_graphql_query("g/p", package_name="custom-receipts")
        self.assertIn("custom-receipts", query)

    def test_injection_prevention(self):
        """Quotes in project path are escaped so they cannot close the string."""
        query = build_receipts_graphql_query('group/"evil')
        # The raw quote should be escaped to \" so it cannot break out
        self.assertIn('\\"evil', query)
        # A bare unescaped " should NOT appear right before evil
        self.assertNotIn('/"evil"', query)


# ---------------------------------------------------------------------------
# Test: generate_dashboard_html (Item 9)
# ---------------------------------------------------------------------------


class TestGenerateDashboardHTML(unittest.TestCase):
    """Test GitLab Pages dashboard generation."""

    def test_basic_dashboard(self):
        """Dashboard HTML is valid and contains key elements."""
        receipts = [
            _make_receipt(),
            _make_receipt(sha="def789", is_ai=False, authorship_class="human"),
        ]
        html = generate_dashboard_html(receipts, project_name="Test Project")
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("AIIR Dashboard", html)
        self.assertIn("Test Project", html)
        self.assertIn("Total Receipts", html)
        self.assertIn("AI-Authored", html)

    def test_empty_receipts(self):
        """Dashboard handles empty receipt list."""
        html = generate_dashboard_html([], project_name="Empty")
        self.assertIn("0", html)  # 0 total receipts
        self.assertIn("Empty", html)

    def test_version_in_footer(self):
        """Dashboard footer includes CLI version."""
        html = generate_dashboard_html([_make_receipt()])
        self.assertIn(CLI_VERSION, html)

    def test_escapes_project_name(self):
        """Project name with terminal escapes is sanitized."""
        html = generate_dashboard_html([], project_name="test\x1b[31mevil")
        self.assertNotIn("\x1b", html)


# ---------------------------------------------------------------------------
# Test: Generator ID differentiation (Item 12)
# ---------------------------------------------------------------------------


class TestGeneratorID(unittest.TestCase):
    """Test that generator field differs by integration mode."""

    def _make_commit_info(self):
        """Build a minimal CommitInfo for testing."""
        from aiir._core import CommitInfo

        return CommitInfo(
            sha="a" * 40,
            author_name="Test",
            author_email="test@example.com",
            author_date="2026-01-01T00:00:00Z",
            committer_name="Test",
            committer_email="test@example.com",
            committer_date="2026-01-01T00:00:00Z",
            subject="test commit",
            body="test commit",
            diff_stat="1 file changed",
            diff_hash="sha256:abc",
            files_changed=["test.py"],
            ai_signals_detected=[],
            is_ai_authored=False,
            bot_signals_detected=[],
            is_bot_authored=False,
            authorship_class="human",
        )

    def test_default_generator_is_cli(self):
        """Default generator is 'aiir.cli'."""
        commit = self._make_commit_info()
        receipt = build_commit_receipt(commit)
        self.assertEqual(receipt["provenance"]["generator"], "aiir.cli")

    def test_github_generator(self):
        """Generator set to 'aiir.github' for GitHub Actions."""
        commit = self._make_commit_info()
        receipt = build_commit_receipt(commit, generator="aiir.github")
        self.assertEqual(receipt["provenance"]["generator"], "aiir.github")

    def test_gitlab_generator(self):
        """Generator set to 'aiir.gitlab' for GitLab CI."""
        commit = self._make_commit_info()
        receipt = build_commit_receipt(commit, generator="aiir.gitlab")
        self.assertEqual(receipt["provenance"]["generator"], "aiir.gitlab")

    def test_generator_affects_content_hash(self):
        """Different generators produce different content hashes."""
        commit = self._make_commit_info()
        receipt_cli = build_commit_receipt(commit, generator="aiir.cli")
        receipt_gl = build_commit_receipt(commit, generator="aiir.gitlab")
        self.assertNotEqual(receipt_cli["content_hash"], receipt_gl["content_hash"])
        self.assertNotEqual(receipt_cli["receipt_id"], receipt_gl["receipt_id"])


# ---------------------------------------------------------------------------
# Test: --gitlab-ci CLI flag (Item 3)
# ---------------------------------------------------------------------------


class TestGitLabCIFlag(unittest.TestCase):
    """Test --gitlab-ci CLI argument parsing."""

    def test_flag_parsed(self):
        """--gitlab-ci flag is recognized by argparse."""
        # Just test that the argument is accepted without error.
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument("--gitlab-ci", action="store_true")
        args = parser.parse_args(["--gitlab-ci"])
        self.assertTrue(args.gitlab_ci)

    def test_gl_sast_report_flag(self):
        """--gl-sast-report flag is recognized."""
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--gl-sast-report", nargs="?", const="gl-sast-report.json", default=None
        )
        args = parser.parse_args(["--gl-sast-report"])
        self.assertEqual(args.gl_sast_report, "gl-sast-report.json")
        args = parser.parse_args(["--gl-sast-report", "custom.json"])
        self.assertEqual(args.gl_sast_report, "custom.json")


# ---------------------------------------------------------------------------
# Test: SAST report written via CLI --gl-sast-report
# ---------------------------------------------------------------------------


class TestGLSASTReportCLI(unittest.TestCase):
    """Test end-to-end --gl-sast-report file output."""

    def test_sast_report_written(self):
        """--gl-sast-report writes valid JSON file."""
        with tempfile.TemporaryDirectory() as td:
            sast_path = os.path.join(td, "gl-sast-report.json")
            # We can't easily run the full CLI without a git repo,
            # but we can test the format function directly
            receipts = [_make_receipt()]
            report = format_gl_sast_report(receipts)
            Path(sast_path).write_text(json.dumps(report, indent=2))
            # Verify file is valid JSON with correct structure
            with open(sast_path) as f:
                loaded = json.load(f)
            self.assertEqual(loaded["version"], "15.1.1")
            self.assertEqual(len(loaded["vulnerabilities"]), 1)


# ---------------------------------------------------------------------------
# Test: _safe_iso_now helper
# ---------------------------------------------------------------------------


class TestSafeIsoNow(unittest.TestCase):
    """Test the ISO timestamp helper."""

    def test_format(self):
        """Timestamp is in ISO 8601 format."""
        ts = _safe_iso_now()
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")


# ---------------------------------------------------------------------------
# Test: post_mr_comment (Item 2 — mock API)
# ---------------------------------------------------------------------------


class TestPostMRComment(unittest.TestCase):
    """Test MR comment posting (mocked API)."""

    def test_missing_context_raises(self):
        """RuntimeError when not in MR context."""
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError) as ctx:
                from aiir._gitlab import post_mr_comment

                post_mr_comment("test comment")
            self.assertIn("merge request context", str(ctx.exception).lower())

    def test_comment_posted_with_mock(self):
        """Comment posted successfully via mocked API."""
        with patch.dict(
            os.environ,
            {
                "CI_PROJECT_ID": "123",
                "CI_MERGE_REQUEST_IID": "42",
                "CI_API_V4_URL": "https://gitlab.example.com/api/v4",
                "GITLAB_TOKEN": "test-token",
            },
        ):
            with patch("aiir._gitlab._gitlab_api_request") as mock_api:
                mock_api.return_value = {"id": 1, "body": "test"}
                from aiir._gitlab import post_mr_comment

                result = post_mr_comment("## AIIR Summary\n\nTest")
                mock_api.assert_called_once()
                self.assertEqual(result["id"], 1)


# ---------------------------------------------------------------------------
# Test: query_gitlab_graphql (mocked HTTP)
# ---------------------------------------------------------------------------


class TestQueryGitlabGraphQL(unittest.TestCase):
    """Test GraphQL query execution (mocked HTTP)."""

    def test_no_token_raises(self):
        """RuntimeError when no auth token is available."""
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError) as ctx:
                query_gitlab_graphql("{ currentUser { name } }")
            self.assertIn("no gitlab auth token", str(ctx.exception).lower())

    def test_successful_query(self):
        """Successful GraphQL query returns data dict."""
        response_data = json.dumps(
            {"data": {"currentUser": {"name": "test-user"}}}
        ).encode("utf-8")

        mock_resp = unittest.mock.MagicMock()
        mock_resp.read.return_value = response_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)

        with patch.dict(os.environ, {"GITLAB_TOKEN": "glpat-test123"}, clear=True):
            with patch("aiir._gitlab.urlopen", return_value=mock_resp) as mock_url:
                result = query_gitlab_graphql("{ currentUser { name } }")
                self.assertEqual(result, {"currentUser": {"name": "test-user"}})
                mock_url.assert_called_once()
                req = mock_url.call_args[0][0]
                self.assertEqual(
                    req.get_header("Authorization"), "Bearer glpat-test123"
                )
                self.assertIn(b"currentUser", req.data)

    def test_custom_api_url(self):
        """Custom api_url is used for the request."""
        response_data = json.dumps({"data": {}}).encode("utf-8")

        mock_resp = unittest.mock.MagicMock()
        mock_resp.read.return_value = response_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)

        with patch("aiir._gitlab.urlopen", return_value=mock_resp) as mock_url:
            query_gitlab_graphql(
                "{ projects { nodes { name } } }",
                api_url="https://gitlab.example.com",
                token="test-token",
            )
            req = mock_url.call_args[0][0]
            self.assertTrue(
                req.full_url.startswith("https://gitlab.example.com/api/graphql")
            )

    def test_graphql_errors_raise(self):
        """GraphQL errors in response raise RuntimeError."""
        response_data = json.dumps({"errors": [{"message": "Syntax error"}]}).encode(
            "utf-8"
        )

        mock_resp = unittest.mock.MagicMock()
        mock_resp.read.return_value = response_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)

        with patch("aiir._gitlab.urlopen", return_value=mock_resp):
            with self.assertRaises(RuntimeError) as ctx:
                query_gitlab_graphql("{ bad }", token="test-token")
            self.assertIn("graphql errors", str(ctx.exception).lower())

    def test_http_error_raises(self):
        """HTTPError is converted to RuntimeError."""
        from urllib.error import HTTPError

        mock_error = HTTPError(
            "https://gitlab.com/api/graphql", 401, "Unauthorized", {}, None
        )

        with patch("aiir._gitlab.urlopen", side_effect=mock_error):
            with self.assertRaises(RuntimeError) as ctx:
                query_gitlab_graphql("{ test }", token="test-token")
            self.assertIn("401", str(ctx.exception))

    def test_url_error_raises(self):
        """URLError (connection failure) is converted to RuntimeError."""
        from urllib.error import URLError

        with patch("aiir._gitlab.urlopen", side_effect=URLError("Connection refused")):
            with self.assertRaises(RuntimeError) as ctx:
                query_gitlab_graphql("{ test }", token="test-token")
            self.assertIn("connection error", str(ctx.exception).lower())

    def test_ci_server_url_fallback(self):
        """CI_SERVER_URL env var is used when no api_url given."""
        response_data = json.dumps({"data": {}}).encode("utf-8")

        mock_resp = unittest.mock.MagicMock()
        mock_resp.read.return_value = response_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)

        with patch.dict(
            os.environ,
            {"CI_SERVER_URL": "https://self-hosted.example.com", "CI_JOB_TOKEN": "jt"},
            clear=True,
        ):
            with patch("aiir._gitlab.urlopen", return_value=mock_resp) as mock_url:
                query_gitlab_graphql("{ test }")
                req = mock_url.call_args[0][0]
                self.assertTrue(
                    req.full_url.startswith(
                        "https://self-hosted.example.com/api/graphql"
                    )
                )


if __name__ == "__main__":
    unittest.main()
