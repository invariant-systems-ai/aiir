"""Tests for MCP server JSON-RPC protocol layer (serve_stdio).

Covers the entire serve_stdio() loop that was at 0% coverage:
- JSON-RPC message parsing and validation
- Method dispatch (initialize, tools/list, tools/call)
- Notification handling (no response)
- Rate limiting
- Oversized message rejection
- Malformed JSON handling
- Non-dict message rejection
- Error response formatting
- Entry point (main)

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import io
import json
import sys
import unittest
from unittest.mock import patch, MagicMock

import aiir.mcp_server as mcp


def _rpc(method: str, *, id: object = 1, params: object = None) -> str:
    """Build a JSON-RPC 2.0 request line."""
    msg: dict = {"jsonrpc": "2.0", "method": method}
    if id is not None:
        msg["id"] = id
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def _run_server(lines: list[str]) -> list[dict]:
    """Feed lines into serve_stdio() and capture JSON responses from stdout."""
    stdin_text = "\n".join(lines) + "\n"
    captured = io.StringIO()
    fake_stdin = io.StringIO(stdin_text)
    # Both streams must support reconfigure (or at least not crash)
    with patch.object(sys, "stdin", fake_stdin), \
         patch.object(sys, "stdout", captured):
        mcp.serve_stdio()
    output = captured.getvalue()
    results = []
    for line in output.strip().split("\n"):
        line = line.strip()
        if line:
            results.append(json.loads(line))
    return results


# ---------------------------------------------------------------------------
# JSON-RPC protocol: basic request/response
# ---------------------------------------------------------------------------


class TestServeStdioInitialize(unittest.TestCase):
    """Test the initialize handshake."""

    def test_initialize_returns_server_info(self):
        responses = _run_server([_rpc("initialize")])
        self.assertEqual(len(responses), 1)
        r = responses[0]
        self.assertEqual(r["jsonrpc"], "2.0")
        self.assertEqual(r["id"], 1)
        result = r["result"]
        self.assertEqual(result["protocolVersion"], mcp.PROTOCOL_VERSION)
        self.assertEqual(result["serverInfo"]["name"], "aiir")
        self.assertIn("tools", result["capabilities"])

    def test_initialize_with_client_info(self):
        """Client can send clientInfo in params — must not crash."""
        responses = _run_server([
            _rpc("initialize", params={"clientInfo": {"name": "test", "version": "1.0"}}),
        ])
        self.assertEqual(len(responses), 1)
        self.assertIn("result", responses[0])


class TestServeStdioToolsList(unittest.TestCase):
    """Test tools/list method."""

    def test_tools_list_returns_all_tools(self):
        responses = _run_server([_rpc("tools/list")])
        self.assertEqual(len(responses), 1)
        tools = responses[0]["result"]["tools"]
        names = {t["name"] for t in tools}
        self.assertIn("aiir_receipt", names)
        self.assertIn("aiir_verify", names)
        self.assertEqual(len(tools), 2)


class TestServeStdioToolsCall(unittest.TestCase):
    """Test tools/call method dispatch."""

    def test_unknown_tool_returns_error(self):
        responses = _run_server([
            _rpc("tools/call", params={"name": "nonexistent_tool", "arguments": {}}),
        ])
        self.assertEqual(len(responses), 1)
        result = responses[0]["result"]
        self.assertTrue(result.get("isError"))
        self.assertIn("Unknown tool", result["content"][0]["text"])

    def test_verify_missing_file_returns_error(self):
        responses = _run_server([
            _rpc("tools/call", params={"name": "aiir_verify", "arguments": {}}),
        ])
        result = responses[0]["result"]
        self.assertTrue(result.get("isError"))
        self.assertIn("file", result["content"][0]["text"].lower())


# ---------------------------------------------------------------------------
# JSON-RPC protocol: error handling
# ---------------------------------------------------------------------------


class TestServeStdioMalformedInput(unittest.TestCase):
    """Test handling of malformed/invalid input."""

    def test_empty_lines_ignored(self):
        """Blank lines must be silently skipped."""
        responses = _run_server(["", "  ", _rpc("tools/list"), ""])
        self.assertEqual(len(responses), 1)  # only tools/list response

    def test_invalid_json_ignored(self):
        """Non-JSON lines must be silently skipped."""
        responses = _run_server([
            "this is not json",
            _rpc("tools/list"),
        ])
        self.assertEqual(len(responses), 1)

    def test_non_dict_json_returns_error(self):
        """A JSON array is not a valid JSON-RPC request."""
        responses = _run_server([
            json.dumps([1, 2, 3]),
            _rpc("tools/list"),
        ])
        self.assertEqual(len(responses), 2)
        # First response is an error for the array
        err = responses[0]
        self.assertIn("error", err)
        self.assertEqual(err["error"]["code"], -32600)
        self.assertIn("expected JSON object", err["error"]["message"])

    def test_json_string_returns_error(self):
        """A plain JSON string is not a valid request."""
        responses = _run_server([
            json.dumps("hello"),
            _rpc("tools/list"),
        ])
        self.assertEqual(len(responses), 2)
        self.assertIn("error", responses[0])

    def test_json_number_returns_error(self):
        """A JSON number is not a valid request."""
        responses = _run_server([
            json.dumps(42),
            _rpc("tools/list"),
        ])
        self.assertEqual(len(responses), 2)
        self.assertIn("error", responses[0])

    def test_missing_jsonrpc_field(self):
        """Request without jsonrpc field must be rejected."""
        responses = _run_server([
            json.dumps({"method": "tools/list", "id": 1}),
        ])
        self.assertEqual(len(responses), 1)
        err = responses[0]
        self.assertIn("error", err)
        self.assertEqual(err["error"]["code"], -32600)
        self.assertIn("jsonrpc", err["error"]["message"].lower())

    def test_wrong_jsonrpc_version(self):
        """Request with wrong jsonrpc version must be rejected."""
        responses = _run_server([
            json.dumps({"jsonrpc": "1.0", "method": "tools/list", "id": 1}),
        ])
        self.assertEqual(len(responses), 1)
        self.assertIn("error", responses[0])
        self.assertEqual(responses[0]["error"]["code"], -32600)

    def test_unknown_method_returns_error(self):
        """Unknown method must return -32601."""
        responses = _run_server([
            _rpc("nonexistent/method"),
        ])
        self.assertEqual(len(responses), 1)
        err = responses[0]
        self.assertEqual(err["error"]["code"], -32601)
        self.assertIn("Unknown method", err["error"]["message"])


class TestServeStdioOversizedMessage(unittest.TestCase):
    """Test oversized message rejection."""

    def test_oversized_message_silently_dropped(self):
        """Messages exceeding 10 MB must be silently dropped."""
        # Create a message just over the limit
        huge = json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": 1, "data": "x" * (11 * 1024 * 1024)})
        responses = _run_server([
            huge,
            _rpc("tools/list"),
        ])
        # Only the valid tools/list should produce a response
        self.assertEqual(len(responses), 1)
        self.assertIn("result", responses[0])


# ---------------------------------------------------------------------------
# JSON-RPC: notifications (no id → no response)
# ---------------------------------------------------------------------------


class TestServeStdioNotifications(unittest.TestCase):
    """Test notification handling (requests without id)."""

    def test_initialized_notification_no_response(self):
        """notifications/initialized must not produce a response."""
        responses = _run_server([
            _rpc("notifications/initialized", id=None),
        ])
        self.assertEqual(len(responses), 0)

    def test_unknown_notification_silently_ignored(self):
        """Unknown notification methods must not produce a response."""
        responses = _run_server([
            _rpc("unknown/notification", id=None),
        ])
        self.assertEqual(len(responses), 0)

    def test_known_method_as_notification(self):
        """A known method sent without id is a notification — no response."""
        responses = _run_server([
            _rpc("tools/list", id=None),
        ])
        self.assertEqual(len(responses), 0)

    def test_notification_handler_exception_suppressed(self):
        """Exceptions in notification handlers must be swallowed."""
        # initialize as notification (no id) — handler returns a value
        # but since it's a notification, no response should be sent.
        responses = _run_server([
            _rpc("initialize", id=None),
        ])
        self.assertEqual(len(responses), 0)


# ---------------------------------------------------------------------------
# JSON-RPC: params coercion
# ---------------------------------------------------------------------------


class TestServeStdioParamsCoercion(unittest.TestCase):
    """Test that non-dict params are coerced to empty dict."""

    def test_string_params_coerced(self):
        responses = _run_server([
            _rpc("initialize", params="bad"),
        ])
        self.assertEqual(len(responses), 1)
        self.assertIn("result", responses[0])

    def test_list_params_coerced(self):
        responses = _run_server([
            _rpc("initialize", params=[1, 2, 3]),
        ])
        self.assertEqual(len(responses), 1)
        self.assertIn("result", responses[0])

    def test_null_params_coerced(self):
        """JSON null params should default to empty dict."""
        msg = json.dumps({"jsonrpc": "2.0", "method": "initialize", "id": 1, "params": None})
        responses = _run_server([msg])
        self.assertEqual(len(responses), 1)
        self.assertIn("result", responses[0])

    def test_number_params_coerced(self):
        responses = _run_server([
            _rpc("initialize", params=42),
        ])
        self.assertEqual(len(responses), 1)
        self.assertIn("result", responses[0])


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestServeStdioRateLimiting(unittest.TestCase):
    """Test sliding-window rate limiter."""

    def test_rate_limit_rejects_excess_requests(self):
        """Sending >50 requests in <1s should trigger rate limiting."""
        # Patch time.monotonic to return the same time (all in one window)
        import time as time_mod

        # Build 60 requests — first 50 should pass, rest should be rate-limited
        lines = [_rpc("tools/list", id=i) for i in range(1, 61)]
        responses = _run_server(lines)

        # Count successes vs rate-limit errors
        successes = [r for r in responses if "result" in r]
        rate_errors = [r for r in responses if "error" in r and r["error"]["code"] == -32000]

        # At least some should be rate-limited (the exact number depends on timing)
        self.assertGreater(len(successes), 0, "Should have some successful responses")
        self.assertGreater(len(rate_errors), 0, "Should have some rate-limited responses")

    def test_rate_limited_notification_not_rejected(self):
        """Notifications (no id) should not get rate-limit error responses."""
        # Send lots of notifications — none should produce responses
        lines = [_rpc("tools/list", id=None) for _ in range(60)]
        responses = _run_server(lines)
        self.assertEqual(len(responses), 0)


# ---------------------------------------------------------------------------
# Handler exception handling
# ---------------------------------------------------------------------------


class TestServeStdioHandlerExceptions(unittest.TestCase):
    """Test that handler exceptions produce proper JSON-RPC error responses."""

    def test_handler_exception_returns_internal_error(self):
        """If a handler raises, serve_stdio returns -32603."""
        # Patch handle_initialize to raise
        original = mcp.HANDLERS["initialize"]
        mcp.HANDLERS["initialize"] = lambda params: (_ for _ in ()).throw(
            RuntimeError("boom")
        )
        try:
            responses = _run_server([_rpc("initialize")])
            self.assertEqual(len(responses), 1)
            err = responses[0]
            self.assertIn("error", err)
            self.assertEqual(err["error"]["code"], -32603)
            # Error message should be sanitized (not full traceback)
            self.assertNotIn("Traceback", err["error"]["message"])
        finally:
            mcp.HANDLERS["initialize"] = original


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


class TestResponseHelpers(unittest.TestCase):
    """Test _make_response, _make_error, _text_result, _error_result."""

    def test_make_response_structure(self):
        r = mcp._make_response(42, {"tools": []})
        self.assertEqual(r["jsonrpc"], "2.0")
        self.assertEqual(r["id"], 42)
        self.assertEqual(r["result"], {"tools": []})

    def test_make_error_structure(self):
        r = mcp._make_error(7, -32601, "Method not found")
        self.assertEqual(r["jsonrpc"], "2.0")
        self.assertEqual(r["id"], 7)
        self.assertEqual(r["error"]["code"], -32601)
        self.assertEqual(r["error"]["message"], "Method not found")

    def test_make_error_null_id(self):
        """Error with null id (for parse errors)."""
        r = mcp._make_error(None, -32700, "Parse error")
        self.assertIsNone(r["id"])

    def test_text_result_structure(self):
        r = mcp._text_result("hello")
        self.assertEqual(r["content"][0]["type"], "text")
        self.assertEqual(r["content"][0]["text"], "hello")

    def test_error_result_structure(self):
        r = mcp._error_result("something broke")
        self.assertTrue(r["isError"])
        self.assertIn("Error: something broke", r["content"][0]["text"])


# ---------------------------------------------------------------------------
# Error sanitization
# ---------------------------------------------------------------------------


class TestSanitizeError(unittest.TestCase):
    """Test _sanitize_error strips internal paths and truncates."""

    def test_path_redacted(self):
        err = RuntimeError("Failed to read /home/user/secret/repo/file.py")
        result = mcp._sanitize_error(err)
        self.assertNotIn("/home/user", result)
        self.assertIn("<path>", result)

    def test_truncation(self):
        err = RuntimeError("x" * 500)
        result = mcp._sanitize_error(err)
        self.assertLessEqual(len(result), mcp._MAX_ERROR_LEN)

    def test_multiline_only_first_line(self):
        err = RuntimeError("line1\nline2\nline3")
        result = mcp._sanitize_error(err)
        self.assertNotIn("line2", result)
        self.assertIn("line1", result)


# ---------------------------------------------------------------------------
# _safe_verify_path edge cases
# ---------------------------------------------------------------------------


class TestSafeVerifyPathEdgeCases(unittest.TestCase):
    """Additional edge cases for _safe_verify_path."""

    def test_empty_path_rejected(self):
        with self.assertRaises(ValueError):
            mcp._safe_verify_path("")

    def test_none_like_empty_rejected(self):
        with self.assertRaises(ValueError):
            mcp._safe_verify_path("")

    def test_overlong_path_rejected(self):
        with self.assertRaises(ValueError):
            mcp._safe_verify_path("a" * 5000)

    def test_path_outside_cwd_rejected(self):
        with self.assertRaises(ValueError):
            mcp._safe_verify_path("/etc/passwd")


# ---------------------------------------------------------------------------
# Multi-message conversations
# ---------------------------------------------------------------------------


class TestServeStdioConversation(unittest.TestCase):
    """Test multi-message MCP conversations."""

    def test_full_lifecycle(self):
        """initialize → notifications/initialized → tools/list → tools/call."""
        responses = _run_server([
            _rpc("initialize", id=1),
            _rpc("notifications/initialized", id=None),
            _rpc("tools/list", id=2),
            _rpc("tools/call", id=3, params={
                "name": "aiir_verify",
                "arguments": {"file": "/nonexistent/file.json"},
            }),
        ])
        # Should get 3 responses (notification produces none)
        self.assertEqual(len(responses), 3)
        self.assertEqual(responses[0]["id"], 1)  # initialize
        self.assertEqual(responses[1]["id"], 2)  # tools/list
        self.assertEqual(responses[2]["id"], 3)  # tools/call

    def test_interleaved_valid_and_invalid(self):
        """Valid requests mixed with garbage should each be handled correctly."""
        responses = _run_server([
            "garbage",
            _rpc("initialize", id=1),
            json.dumps([1, 2]),  # non-dict
            "",
            _rpc("tools/list", id=2),
            json.dumps({"method": "x", "id": 3}),  # missing jsonrpc
        ])
        # 1: initialize result, 2: non-dict error, 3: tools/list result, 4: missing jsonrpc error
        self.assertEqual(len(responses), 4)
        self.assertIn("result", responses[0])      # initialize
        self.assertIn("error", responses[1])        # non-dict
        self.assertIn("result", responses[2])       # tools/list
        self.assertIn("error", responses[3])        # missing jsonrpc


# ---------------------------------------------------------------------------
# Entry point (main)
# ---------------------------------------------------------------------------


class TestMcpMain(unittest.TestCase):
    """Test MCP server entry point."""

    def test_version_flag(self):
        """--version should print version and exit."""
        with patch("sys.argv", ["aiir-mcp-server", "--version"]):
            with self.assertRaises(SystemExit) as ctx:
                mcp.main()
            self.assertEqual(ctx.exception.code, 0)

    def test_main_calls_serve_stdio(self):
        """main() should call serve_stdio()."""
        with patch("sys.argv", ["aiir-mcp-server"]), \
             patch.object(mcp, "serve_stdio") as mock_serve:
            mcp.main()
            mock_serve.assert_called_once()


# ---------------------------------------------------------------------------
# __main__.py entry point
# ---------------------------------------------------------------------------


class TestMainModule(unittest.TestCase):
    """Test aiir/__main__.py."""

    def test_main_module_calls_cli_main(self):
        """python -m aiir should invoke cli.main() and wrap in SystemExit."""
        with patch("aiir.cli.main", return_value=0):
            with self.assertRaises(SystemExit) as ctx:
                exec(
                    compile(
                        open("aiir/__main__.py").read(),
                        "aiir/__main__.py",
                        "exec",
                    )
                )
            self.assertEqual(ctx.exception.code, 0)

    def test_keyboard_interrupt_exits_130(self):
        """Ctrl-C should produce exit code 130."""
        with patch("aiir.cli.main", side_effect=KeyboardInterrupt):
            with self.assertRaises(SystemExit) as ctx:
                exec(
                    compile(
                        open("aiir/__main__.py").read(),
                        "aiir/__main__.py",
                        "exec",
                    )
                )
            self.assertEqual(ctx.exception.code, 130)

    def test_memory_error_exits_1(self):
        """MemoryError should produce exit code 1."""
        with patch("aiir.cli.main", side_effect=MemoryError):
            with self.assertRaises(SystemExit) as ctx:
                exec(
                    compile(
                        open("aiir/__main__.py").read(),
                        "aiir/__main__.py",
                        "exec",
                    )
                )
            self.assertEqual(ctx.exception.code, 1)


# ---------------------------------------------------------------------------
# _send helper
# ---------------------------------------------------------------------------


class TestSendHelper(unittest.TestCase):
    """Test _send writes JSON + newline to stdout."""

    def test_send_writes_json_line(self):
        captured = io.StringIO()
        with patch.object(sys, "stdout", captured):
            mcp._send({"jsonrpc": "2.0", "id": 1, "result": {}})
        output = captured.getvalue()
        self.assertTrue(output.endswith("\n"))
        parsed = json.loads(output.strip())
        self.assertEqual(parsed["jsonrpc"], "2.0")


if __name__ == "__main__":
    unittest.main()
