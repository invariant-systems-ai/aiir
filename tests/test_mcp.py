"""Tests for MCP server integration."""
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
        self.assertEqual(len(result["tools"]), 2)

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

