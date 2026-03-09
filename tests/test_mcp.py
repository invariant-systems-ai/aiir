"""Tests for MCP server integration."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
import unittest.mock
from pathlib import Path

# Import the module under test
import aiir.cli as cli


class TestRedTeamMCP(unittest.TestCase):
    """Tests for R5-06/07 MCP server hardening."""

    def test_r5_08_verify_receipt_signature_rejects_symlinks(self):
        """verify_receipt_signature must reject symlink receipt and bundle paths."""
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            # Create a real file and a symlink to it
            real = os.path.join(td, "real.json")
            with open(real, "w") as f:
                f.write("{}")
            link = os.path.join(td, "link.json")
            os.symlink(real, link)
            result = cli.verify_receipt_signature(link)
            self.assertFalse(result["valid"])
            self.assertIn("symlink", result.get("error", "").lower())


class TestMcpSymlinkIntermediate(unittest.TestCase):
    """R9-SEC-03: _safe_verify_path must detect intermediate symlinks."""

    def test_intermediate_symlink_rejected(self):
        """A path with a symlinked intermediate directory must be rejected."""
        tmpdir = tempfile.mkdtemp()
        original_cwd = os.getcwd()
        try:
            real_dir = Path(tmpdir, "real")
            real_dir.mkdir()
            Path(real_dir, "file.json").write_text("{}")
            # Create symlink: tmpdir/link -> tmpdir/real
            link = Path(tmpdir, "link")
            link.symlink_to(real_dir)
            # Import the MCP server module
            import aiir.mcp_server as mcp

            # _safe_verify_path uses Path.cwd(), so chdir
            os.chdir(tmpdir)
            # Access through symlinked directory
            with self.assertRaises(ValueError) as ctx:
                mcp._safe_verify_path(str(link / "file.json"))
            self.assertIn("symlink", str(ctx.exception).lower())
        finally:
            os.chdir(original_cwd)
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_real_path_accepted(self):
        """A normal path without symlinks must be accepted."""
        tmpdir = os.path.realpath(tempfile.mkdtemp())
        original_cwd = os.getcwd()
        try:
            real_dir = Path(tmpdir, "sub")
            real_dir.mkdir()
            Path(real_dir, "file.json").write_text("{}")
            import aiir.mcp_server as mcp

            os.chdir(tmpdir)
            result = mcp._safe_verify_path(str(Path(real_dir, "file.json")))
            self.assertTrue(result.endswith("file.json"))
        finally:
            os.chdir(original_cwd)
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)


class TestMcpToolDescriptions(unittest.TestCase):
    """R9-SEC-05: MCP tool descriptions include security constraints."""

    def test_aiir_receipt_description_has_constraints(self):
        """aiir_receipt tool description should mention security constraints."""
        from aiir.mcp_server import TOOLS

        receipt_tool = next(t for t in TOOLS if t["name"] == "aiir_receipt")
        desc = receipt_tool["description"]
        self.assertIn("current working directory", desc)
        self.assertIn("validated", desc)

    def test_aiir_verify_description_has_constraints(self):
        """aiir_verify tool description should mention path restrictions."""
        from aiir.mcp_server import TOOLS

        verify_tool = next(t for t in TOOLS if t["name"] == "aiir_verify")
        desc = verify_tool["description"]
        self.assertIn("symlinks", desc.lower())
        self.assertIn("50 MB", desc)

    def test_aiir_verify_file_schema_has_constraints(self):
        """aiir_verify file parameter should describe path restrictions."""
        from aiir.mcp_server import TOOLS

        verify_tool = next(t for t in TOOLS if t["name"] == "aiir_verify")
        file_desc = verify_tool["inputSchema"]["properties"]["file"]["description"]
        self.assertIn("..", file_desc)
        self.assertIn("4096", file_desc)


# ---------------------------------------------------------------------------
# Round 10 tests
# ---------------------------------------------------------------------------


class TestMcpParamsValidation(unittest.TestCase):
    """R12-SEC-02: MCP serve_stdio must handle non-dict params gracefully."""

    def test_string_params_treated_as_empty(self):
        """String params should be coerced to empty dict, not crash handler."""
        from aiir.mcp_server import handle_tools_call

        # Simulating what happens after params coercion
        result = handle_tools_call({"name": "aiir_receipt", "arguments": {}})
        # Should not crash — returns a result (receipt or error, depending on git)
        self.assertIn("content", result)

    def test_list_params_coerced(self):
        """List params should be coerced to empty dict by serve_stdio."""
        from aiir.mcp_server import handle_tools_list

        # handle_tools_list ignores params, so any coerced value works
        result = handle_tools_list({})
        self.assertIn("tools", result)
        self.assertEqual(len(result["tools"]), 7)

    def test_null_params_default_to_dict(self):
        """None params (JSON null) should default to empty dict."""
        from aiir.mcp_server import handle_tools_list

        result = handle_tools_list(None)  # Simulates params=None
        self.assertIn("tools", result)


class TestMcpArgumentsValidation(unittest.TestCase):
    """R13-SEC-01: MCP handle_tools_call must validate arguments type."""

    def test_string_arguments_coerced(self):
        """String arguments should be coerced to empty dict, not crash."""
        from aiir.mcp_server import handle_tools_call

        # Pass string instead of dict for arguments
        result = handle_tools_call({"name": "aiir_receipt", "arguments": "bad"})
        # Should return a result (not crash with AttributeError)
        self.assertIn("content", result)

    def test_list_arguments_coerced(self):
        """List arguments should be coerced to empty dict."""
        from aiir.mcp_server import handle_tools_call

        result = handle_tools_call({"name": "aiir_receipt", "arguments": [1, 2]})
        self.assertIn("content", result)

    def test_null_arguments_coerced(self):
        """None (JSON null) arguments should be coerced to empty dict."""
        from aiir.mcp_server import handle_tools_call

        result = handle_tools_call({"name": "aiir_receipt", "arguments": None})
        self.assertIn("content", result)

    def test_number_arguments_coerced(self):
        """Numeric arguments should be coerced to empty dict."""
        from aiir.mcp_server import handle_tools_call

        result = handle_tools_call({"name": "aiir_verify", "arguments": 42})
        self.assertIn("content", result)
        # Should get a proper validation error, not an internal crash
        self.assertTrue(result.get("isError", False))


class TestMcpRedactFiles(unittest.TestCase):
    """R10-SEC-02: MCP aiir_receipt handler must support redact_files param."""

    def test_mcp_tool_schema_has_redact_files(self):
        """The aiir_receipt tool schema should include a redact_files parameter."""
        from aiir.mcp_server import TOOLS

        receipt_tool = next(t for t in TOOLS if t["name"] == "aiir_receipt")
        props = receipt_tool["inputSchema"]["properties"]
        self.assertIn("redact_files", props)
        self.assertEqual(props["redact_files"]["type"], "boolean")

    @unittest.mock.patch("aiir.mcp_server.generate_receipt")
    def test_mcp_handler_passes_redact_files(self, mock_gen):
        """The handler should forward redact_files to generate_receipt."""
        from aiir.mcp_server import _handle_aiir_receipt

        mock_gen.return_value = {
            "type": "aiir.commit_receipt",
            "receipt_id": "g1-test",
            "content_hash": "sha256:abc",
            "timestamp": "2026-01-01T00:00:00Z",
            "commit": {"sha": "abc", "subject": "test"},
            "ai_attestation": {"is_ai_authored": False},
        }
        _handle_aiir_receipt({"redact_files": True})
        _, kwargs = mock_gen.call_args
        self.assertTrue(kwargs.get("redact_files"))


class TestMcpNewToolHandlers(unittest.TestCase):
    """Tests for the new MCP tool handlers (stats, explain, policy_check)."""

    def test_stats_no_ledger(self):
        """aiir_stats returns helpful message when no ledger exists."""
        from aiir.mcp_server import _handle_aiir_stats

        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = _handle_aiir_stats({})
            finally:
                os.chdir(old_cwd)
        self.assertIn("content", result)
        text = result["content"][0]["text"]
        self.assertIn("No AIIR ledger", text)

    def test_explain_missing_file_param(self):
        """aiir_explain returns error when 'file' is missing."""
        from aiir.mcp_server import _handle_aiir_explain

        result = _handle_aiir_explain({})
        self.assertTrue(result.get("isError"))

    def test_verify_missing_file_param(self):
        """aiir_verify returns error when 'file' is missing."""
        from aiir.mcp_server import _handle_aiir_verify

        result = _handle_aiir_verify({})
        self.assertTrue(result.get("isError"))

    def test_policy_check_no_ledger(self):
        """aiir_policy_check returns message when no ledger exists."""
        from aiir.mcp_server import _handle_aiir_policy_check

        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = _handle_aiir_policy_check({})
            finally:
                os.chdir(old_cwd)
        text = result["content"][0]["text"]
        self.assertIn("No AIIR ledger", text)

    def test_policy_check_invalid_threshold(self):
        """aiir_policy_check defaults to 50 when given bad max_ai_percent."""
        from aiir.mcp_server import _handle_aiir_policy_check

        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = _handle_aiir_policy_check({"max_ai_percent": "bad"})
            finally:
                os.chdir(old_cwd)
        text = result["content"][0]["text"]
        self.assertIn("No AIIR ledger", text)


# ---------------------------------------------------------------------------
# Test: aiir_gitlab_summary MCP tool
# ---------------------------------------------------------------------------


def _make_test_receipt(
    sha: str = "abc123def456",
    subject: str = "feat: add feature",
    is_ai: bool = True,
    authorship_class: str = "ai_assisted",
) -> dict:
    """Build a minimal receipt dict for MCP GitLab summary tests."""
    from aiir._core import CLI_VERSION

    return {
        "type": "aiir.commit_receipt",
        "schema": "1.0",
        "version": CLI_VERSION,
        "commit": {
            "sha": sha,
            "author": {"name": "Test", "email": "t@e.com", "date": "2026-01-01T00:00:00Z"},
            "committer": {"name": "Test", "email": "t@e.com", "date": "2026-01-01T00:00:00Z"},
            "subject": subject,
            "message_hash": "sha256:aaa",
            "diff_hash": "sha256:bbb",
            "files_changed": 1,
            "files": ["src/main.py"],
        },
        "ai_attestation": {
            "is_ai_authored": is_ai,
            "signals_detected": ["message_match:copilot"] if is_ai else [],
            "signal_count": 1 if is_ai else 0,
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
        "receipt_id": "g1-test1234567890",
        "content_hash": "sha256:deadbeef",
        "timestamp": "2026-01-01T00:00:00Z",
        "extensions": {},
    }


class TestMcpGitLabSummary(unittest.TestCase):
    """Tests for the aiir_gitlab_summary MCP tool."""

    def test_tool_in_tools_list(self):
        """aiir_gitlab_summary is registered in TOOLS."""
        from aiir.mcp_server import TOOLS

        names = [t["name"] for t in TOOLS]
        self.assertIn("aiir_gitlab_summary", names)

    def test_tool_schema_has_expected_params(self):
        """Input schema includes range, include_sast, post_to_mr."""
        from aiir.mcp_server import TOOLS

        tool = next(t for t in TOOLS if t["name"] == "aiir_gitlab_summary")
        props = tool["inputSchema"]["properties"]
        self.assertIn("range", props)
        self.assertIn("include_sast", props)
        self.assertIn("post_to_mr", props)

    def test_no_ledger_returns_helpful_message(self):
        """Returns guidance when no ledger exists and no range given."""
        from aiir.mcp_server import _handle_aiir_gitlab_summary

        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = _handle_aiir_gitlab_summary({})
            finally:
                os.chdir(old_cwd)
        self.assertIn("content", result)
        text = result["content"][0]["text"]
        self.assertIn("No AIIR ledger", text)

    def test_summary_from_ledger(self):
        """Reads ledger and returns GitLab-flavored Markdown summary."""
        from aiir.mcp_server import _handle_aiir_gitlab_summary

        receipts = [
            _make_test_receipt(sha="aaa111", subject="feat: AI feature", is_ai=True),
            _make_test_receipt(sha="bbb222", subject="fix: human fix", is_ai=False, authorship_class="human"),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_dir = Path(tmpdir) / ".aiir"
            ledger_dir.mkdir()
            ledger_path = ledger_dir / "receipts.jsonl"
            with open(ledger_path, "w") as f:
                for r in receipts:
                    f.write(json.dumps(r) + "\n")

            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = _handle_aiir_gitlab_summary({})
            finally:
                os.chdir(old_cwd)

        text = result["content"][0]["text"]
        self.assertIn("AIIR Receipt Summary", text)
        self.assertIn("aaa111", text)
        self.assertIn("bbb222", text)
        self.assertIn("AI-authored", text)

    def test_include_sast_appends_report(self):
        """include_sast=True adds SAST report JSON in a details block."""
        from aiir.mcp_server import _handle_aiir_gitlab_summary

        receipts = [_make_test_receipt()]

        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_dir = Path(tmpdir) / ".aiir"
            ledger_dir.mkdir()
            with open(ledger_dir / "receipts.jsonl", "w") as f:
                f.write(json.dumps(receipts[0]) + "\n")

            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = _handle_aiir_gitlab_summary({"include_sast": True})
            finally:
                os.chdir(old_cwd)

        text = result["content"][0]["text"]
        self.assertIn("SAST Report Data", text)
        self.assertIn('"version"', text)  # SAST JSON has a version field

    def test_post_to_mr_ignored_outside_ci(self):
        """post_to_mr=True is silently ignored when not in GitLab CI."""
        from aiir.mcp_server import _handle_aiir_gitlab_summary

        receipts = [_make_test_receipt()]

        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_dir = Path(tmpdir) / ".aiir"
            ledger_dir.mkdir()
            with open(ledger_dir / "receipts.jsonl", "w") as f:
                f.write(json.dumps(receipts[0]) + "\n")

            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                with unittest.mock.patch.dict(os.environ, {}, clear=True):
                    result = _handle_aiir_gitlab_summary({"post_to_mr": True})
            finally:
                os.chdir(old_cwd)

        text = result["content"][0]["text"]
        self.assertIn("AIIR Receipt Summary", text)
        self.assertNotIn("posted to merge request", text)

    def test_post_to_mr_in_ci_context(self):
        """post_to_mr=True posts comment when CI_MERGE_REQUEST_IID is set."""
        from aiir.mcp_server import _handle_aiir_gitlab_summary

        receipts = [_make_test_receipt()]

        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_dir = Path(tmpdir) / ".aiir"
            ledger_dir.mkdir()
            with open(ledger_dir / "receipts.jsonl", "w") as f:
                f.write(json.dumps(receipts[0]) + "\n")

            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                env = {
                    "CI_MERGE_REQUEST_IID": "42",
                    "CI_PROJECT_ID": "123",
                    "CI_API_V4_URL": "https://gitlab.example.com/api/v4",
                    "GITLAB_TOKEN": "test-token",
                }
                with unittest.mock.patch.dict(os.environ, env, clear=True):
                    with unittest.mock.patch("aiir.mcp_server.post_mr_comment") as mock_post:
                        mock_post.return_value = {"id": 1}
                        result = _handle_aiir_gitlab_summary({"post_to_mr": True})
                        mock_post.assert_called_once()
            finally:
                os.chdir(old_cwd)

        text = result["content"][0]["text"]
        self.assertIn("posted to merge request", text)

    @unittest.mock.patch("aiir.mcp_server.generate_receipts_for_range")
    def test_range_generates_fresh_receipts(self, mock_gen):
        """range param generates fresh receipts instead of reading ledger."""
        from aiir.mcp_server import _handle_aiir_gitlab_summary

        mock_gen.return_value = [_make_test_receipt()]
        result = _handle_aiir_gitlab_summary({"range": "HEAD~3..HEAD"})

        mock_gen.assert_called_once_with("HEAD~3..HEAD", cwd=None)
        text = result["content"][0]["text"]
        self.assertIn("AIIR Receipt Summary", text)

    @unittest.mock.patch("aiir.mcp_server.generate_receipts_for_range")
    def test_range_empty_returns_message(self, mock_gen):
        """Empty range result returns helpful message."""
        from aiir.mcp_server import _handle_aiir_gitlab_summary

        mock_gen.return_value = []
        result = _handle_aiir_gitlab_summary({"range": "HEAD~1..HEAD"})

        text = result["content"][0]["text"]
        self.assertIn("No receipts found", text)

    def test_handler_in_dispatch(self):
        """aiir_gitlab_summary is in TOOL_HANDLERS dispatch."""
        from aiir.mcp_server import TOOL_HANDLERS

        self.assertIn("aiir_gitlab_summary", TOOL_HANDLERS)

    def test_tools_call_routes_to_handler(self):
        """handle_tools_call routes to gitlab_summary handler."""
        from aiir.mcp_server import handle_tools_call

        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = handle_tools_call(
                    {"name": "aiir_gitlab_summary", "arguments": {}}
                )
            finally:
                os.chdir(old_cwd)
        self.assertIn("content", result)
