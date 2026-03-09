#!/usr/bin/env python3
"""
AIIR MCP Server — AI Integrity Receipts for any AI coding assistant.

Model Context Protocol (MCP) server that exposes AIIR receipt generation
and verification as tools. Any MCP-aware AI (Copilot, Claude, Cursor, etc.)
can discover and use these tools automatically.

Zero dependencies — uses only Python standard library + aiir.cli.

Usage:
    python -m aiir.mcp_server              # stdio transport (default)
    aiir-mcp-server                         # via pip entry point
    aiir-mcp-server --stdio                 # explicit stdio

MCP config (Claude, Cursor, etc.):
    {
      "mcpServers": {
        "aiir": {
          "command": "aiir-mcp-server",
          "args": ["--stdio"]
        }
      }
    }

Security hardening (v0.6.0):
    - F4-01: Removed 'cwd' parameter — MCP server operates only in its own cwd.
             Cross-repo information disclosure is no longer possible.
    - F4-02: 'aiir_verify' restricts file paths to the current working directory.
             No filesystem oracle via path traversal.
    - F4-03: Error messages are sanitized to prevent leaking internal state
             (git command strings, file paths, stack traces).
    - Removed sys.path.insert() — uses proper package imports.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Import AIIR CLI (proper package import — no sys.path manipulation)
# ---------------------------------------------------------------------------

from aiir.cli import (
    CLI_VERSION,
    format_receipt_pretty,
    format_stats,
    check_policy,
    generate_receipt,
    generate_receipts_for_range,
    verify_receipt_file,
    explain_verification,
    verify_release,
    format_release_report,
    _load_index,
    _ledger_paths,
)
from aiir._gitlab import (
    format_gitlab_summary,
    format_gl_sast_report,
    post_mr_comment,
)

# ---------------------------------------------------------------------------
# Server metadata
# ---------------------------------------------------------------------------

SERVER_NAME = "aiir"
SERVER_VERSION = CLI_VERSION
PROTOCOL_VERSION = "2025-03-26"

# ---------------------------------------------------------------------------
# Security: Path restriction for verify
# ---------------------------------------------------------------------------

# Maximum path length to prevent DoS via path parsing
_MAX_PATH_LEN = 4096


def _safe_verify_path(filepath: str) -> str:
    """Validate that a verify target path is within the current working directory.

    F4-02: Without this, the MCP 'file' parameter is a filesystem oracle —
    an AI assistant could be tricked into probing arbitrary paths.

    Raises ValueError if the path escapes cwd or is a symlink.
    """
    if not filepath or len(filepath) > _MAX_PATH_LEN:
        raise ValueError("Invalid file path")

    cwd = Path.cwd().resolve()
    target = Path(filepath).resolve()

    # Must be within cwd
    try:
        target.relative_to(cwd)
    except ValueError:
        raise ValueError("File path must be within the current working directory")

    # Reject symlinks (same policy as cli.py R5-07)
    # Check both the final component AND any intermediate path components.
    # Path(filepath).is_symlink() only checks the final component — a path like
    # /repo/symlinked_dir/receipt.json passes if only the directory is a symlink.
    # We check every component of the original path against the resolved version.
    for parent in Path(filepath).parents:
        if parent.is_symlink():
            raise ValueError("Path contains a symlink (intermediate component)")
    if Path(filepath).is_symlink():
        raise ValueError("Symlinks are not allowed for verification")

    if not target.is_file():
        raise ValueError("File not found")

    return str(target)


# ---------------------------------------------------------------------------
# Error sanitization
# ---------------------------------------------------------------------------

_MAX_ERROR_LEN = 200


def _sanitize_error(error: Exception) -> str:
    """Sanitize error messages to prevent information disclosure.

    F4-03: Raw error messages from git subprocess calls leak full command
    strings, internal paths, and system state. Truncate and genericize.
    """
    msg = str(error)
    # Only show the first line, truncated
    first_line = msg.split("\n")[0][:_MAX_ERROR_LEN]

    # Redact anything that looks like a filesystem path.
    first_line = re.sub(r"/[\w./-]{5,}", "<path>", first_line)

    return first_line


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "aiir_receipt",
        "description": (
            "Generate a cryptographic receipt for git commits in the current repository. "
            "Detects AI authorship signals (Copilot, ChatGPT, Claude, Cursor, etc.) "
            "and produces a content-addressed JSON receipt for audit trails. "
            "Run this after committing AI-generated code to create a tamper-evident record. "
            "IMPORTANT: This tool only operates on the current working directory. "
            "Do not pass external paths, URLs, or user-supplied directory names. "
            "All inputs are validated and sanitized — invalid refs are rejected."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "commit": {
                    "type": "string",
                    "description": (
                        "Specific commit SHA to receipt. Default: HEAD. "
                        "Must be a valid hex SHA or symbolic ref (e.g., HEAD, main). "
                        "Refs starting with '-' or containing control characters are rejected."
                    ),
                },
                "range": {
                    "type": "string",
                    "description": (
                        "Commit range to receipt (e.g., 'HEAD~3..HEAD', 'main..HEAD'). "
                        "Overrides 'commit' if both are provided. "
                        "Must use standard git range syntax. Maximum 1000 commits."
                    ),
                },
                "ai_only": {
                    "type": "boolean",
                    "description": "Only receipt commits detected as AI-authored.",
                    "default": False,
                },
                "pretty": {
                    "type": "boolean",
                    "description": "Return human-readable summary instead of raw JSON.",
                    "default": False,
                },
                "redact_files": {
                    "type": "boolean",
                    "description": (
                        "Omit individual file paths from receipts (privacy). "
                        "When true, replaces the files list with files_redacted: true. "
                        "Use this for repositories with sensitive internal structure."
                    ),
                    "default": False,
                },
            },
        },
    },
    {
        "name": "aiir_verify",
        "description": (
            "Verify the integrity of an AIIR receipt file in the current directory. "
            "Checks that the content_hash and receipt_id are valid "
            "(content-addressed — any modification invalidates the receipt). "
            "The file MUST be within the current working directory — "
            "absolute paths, path traversal (../), and symlinks are rejected. "
            "Maximum file size: 50 MB. Only JSON files are accepted."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {
                    "type": "string",
                    "description": (
                        "Relative path to the receipt JSON file to verify. "
                        "Must be within the current working directory. "
                        "Absolute paths, '..' traversal, and symlinks are rejected. "
                        "Maximum path length: 4096 characters."
                    ),
                },
            },
            "required": ["file"],
        },
    },
    {
        "name": "aiir_stats",
        "description": (
            "Show statistics for the AIIR receipt ledger in the current repository. "
            "Returns receipt count, AI-authored percentage, unique authors, and "
            "date range. Reads from the .aiir/ ledger directory in the current "
            "working directory. If no ledger exists, returns a helpful message."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "aiir_explain",
        "description": (
            "Provide a human-readable explanation of a receipt verification result. "
            "Takes a receipt file path, verifies it, and returns a plain-English "
            "explanation of what was checked, what passed or failed, and what to do. "
            "Designed for non-cryptography users who need to understand a verification "
            "outcome. The file MUST be within the current working directory."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {
                    "type": "string",
                    "description": (
                        "Relative path to the receipt JSON file to explain. "
                        "Must be within the current working directory."
                    ),
                },
            },
            "required": ["file"],
        },
    },
    {
        "name": "aiir_policy_check",
        "description": (
            "Check the current AIIR ledger against policy constraints. "
            "Evaluates the AI-authored commit percentage against a configurable "
            "threshold. Returns PASS/FAIL with details. Use this to enforce "
            "org-level AI usage policies in CI or during code review. "
            "Reads from the .aiir/ ledger in the current working directory."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "max_ai_percent": {
                    "type": "number",
                    "description": (
                        "Maximum allowed AI-authored commit percentage (0-100). "
                        "Default: 50. The check fails if the ledger's AI percentage "
                        "exceeds this threshold."
                    ),
                    "default": 50,
                },
            },
        },
    },
    {
        "name": "aiir_verify_release",
        "description": (
            "Verify a release by evaluating AIIR receipts against a named policy. "
            "Produces a Verification Summary Attestation (VSA) with pass/fail decision, "
            "coverage statistics, and policy evaluation details. Use this for CI gates, "
            "audit trails, and compliance checks. "
            "Reads receipts from the .aiir/ ledger in the current working directory."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "commit_range": {
                    "type": "string",
                    "description": (
                        "Git commit range to verify (e.g., 'origin/main..HEAD'). "
                        "If omitted, all receipts in the ledger are evaluated."
                    ),
                },
                "policy": {
                    "type": "string",
                    "description": (
                        "Policy preset name ('strict', 'balanced', 'permissive') "
                        "or path to a policy JSON file. Default: balanced."
                    ),
                },
                "emit_intoto": {
                    "type": "boolean",
                    "description": (
                        "If true, wrap the result as an in-toto Statement v1 "
                        "Verification Summary Attestation."
                    ),
                    "default": False,
                },
            },
        },
    },
    {
        "name": "aiir_gitlab_summary",
        "description": (
            "Generate a GitLab-flavored Markdown summary of AIIR receipts. "
            "Returns a formatted table with AI authorship breakdown, per-commit "
            "details in a collapsible block, and optional SAST report data. "
            "Designed for GitLab Duo Chat, MR comments, and CI pipelines. "
            "Can optionally post the summary as a merge request comment when "
            "running inside GitLab CI. Reads from the .aiir/ ledger in cwd."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "range": {
                    "type": "string",
                    "description": (
                        "Commit range to summarize (e.g., 'origin/main..HEAD'). "
                        "If omitted, all receipts in the ledger are summarized."
                    ),
                },
                "include_sast": {
                    "type": "boolean",
                    "description": (
                        "Include SAST report data (Security Dashboard format) "
                        "alongside the Markdown summary."
                    ),
                    "default": False,
                },
                "post_to_mr": {
                    "type": "boolean",
                    "description": (
                        "Post the summary as a comment on the current merge request. "
                        "Only works when running inside GitLab CI with "
                        "CI_MERGE_REQUEST_IID set. Ignored outside CI."
                    ),
                    "default": False,
                },
            },
        },
    },
]

# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


def _handle_aiir_receipt(args: Dict[str, Any]) -> Dict[str, Any]:
    """Generate receipt(s) for git commit(s).

    F4-01: No 'cwd' parameter — always operates in the server's cwd.
    This prevents cross-repo information disclosure where an AI assistant
    could be tricked into receipting a foreign repository.
    """
    ai_only = args.get("ai_only", False)
    pretty = args.get("pretty", False)
    redact_files = args.get("redact_files", False)
    range_spec = args.get("range")
    commit_ref = args.get("commit", "HEAD")

    try:
        if range_spec:
            receipts = generate_receipts_for_range(
                range_spec,
                cwd=None,
                ai_only=ai_only,
                redact_files=redact_files,
            )
        else:
            receipt = generate_receipt(
                commit_ref,
                cwd=None,
                ai_only=ai_only,
                redact_files=redact_files,
            )
            receipts = [receipt] if receipt else []

        if not receipts:
            return _text_result(
                "No commits matched (ai_only filter may have excluded all)."
            )

        if pretty:
            text = "\n\n".join(format_receipt_pretty(r) for r in receipts)
        else:
            text = json.dumps(receipts if len(receipts) > 1 else receipts[0], indent=2)

        return _text_result(text)

    except Exception as e:
        return _error_result(_sanitize_error(e))


def _handle_aiir_verify(args: Dict[str, Any]) -> Dict[str, Any]:
    """Verify a receipt file's integrity.

    F4-02: File path is validated to be within cwd and not a symlink.
    F4-03: Error messages are sanitized.
    """
    filepath = args.get("file")
    if not filepath:
        return _error_result("'file' parameter is required.")

    try:
        # Validate path is within cwd
        safe_path = _safe_verify_path(filepath)

        result = verify_receipt_file(safe_path)
        if result.get("valid"):
            summary = "✅ Receipt verified — integrity intact."
        else:
            summary = "❌ Receipt INVALID — integrity check failed."

        text = summary + "\n\n" + json.dumps(result, indent=2)
        return _text_result(text)

    except ValueError as e:
        # Path validation errors are safe to return directly
        return _error_result(str(e))
    except Exception as e:
        return _error_result(_sanitize_error(e))


def _handle_aiir_stats(args: Dict[str, Any]) -> Dict[str, Any]:
    """Return ledger statistics for the current repository."""
    try:
        ledger_dir = Path.cwd() / ".aiir"
        _, _, index_path = _ledger_paths(str(ledger_dir))
        if not Path(index_path).is_file():
            return _text_result(
                "No AIIR ledger found in this repository.\n"
                "Run 'aiir --pretty' to generate your first receipt."
            )
        index = _load_index(index_path)
        text = format_stats(index)
        return _text_result(text)
    except Exception as e:
        return _error_result(_sanitize_error(e))


def _handle_aiir_explain(args: Dict[str, Any]) -> Dict[str, Any]:
    """Verify a receipt and return a human-readable explanation."""
    filepath = args.get("file")
    if not filepath:
        return _error_result("'file' parameter is required.")

    try:
        safe_path = _safe_verify_path(filepath)
        result = verify_receipt_file(safe_path)
        explanation = explain_verification(result)
        return _text_result(explanation)
    except ValueError as e:
        return _error_result(str(e))
    except Exception as e:
        return _error_result(_sanitize_error(e))


def _handle_aiir_policy_check(args: Dict[str, Any]) -> Dict[str, Any]:
    """Check ledger against AI percentage policy threshold."""
    max_ai_pct = args.get("max_ai_percent", 50)
    try:
        max_ai_pct = float(max_ai_pct)
    except (TypeError, ValueError):
        max_ai_pct = 50.0

    try:
        ledger_dir = Path.cwd() / ".aiir"
        _, _, index_path = _ledger_paths(str(ledger_dir))
        if not Path(index_path).is_file():
            return _text_result(
                "No AIIR ledger found — run 'aiir' first to generate receipts."
            )
        index = _load_index(index_path)
        passed, message = check_policy(index, max_ai_percent=max_ai_pct)
        icon = "✅" if passed else "❌"
        return _text_result(f"{icon} {message}")
    except Exception as e:
        return _error_result(_sanitize_error(e))


def _handle_aiir_verify_release(args: Dict[str, Any]) -> Dict[str, Any]:
    """Verify a release by evaluating receipts against policy."""
    commit_range = args.get("commit_range")
    policy_arg = args.get("policy")
    emit_intoto = args.get("emit_intoto", False)

    ledger_path = str(Path.cwd() / ".aiir" / "receipts.jsonl")

    # Determine policy
    from aiir._policy import POLICY_PRESETS as _PP

    policy_preset = None
    policy_path = None
    if policy_arg:
        if policy_arg in _PP:
            policy_preset = policy_arg
        else:
            # Validate path within cwd
            try:
                safe_path = _safe_verify_path(policy_arg)
                policy_path = safe_path
            except ValueError as e:
                return _error_result(str(e))

    try:
        result = verify_release(
            commit_range=commit_range,
            receipts_path=ledger_path,
            policy_path=policy_path,
            policy_preset=policy_preset,
            emit_intoto=emit_intoto,
        )
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        return _error_result(_sanitize_error(e))
    except Exception as e:
        return _error_result(_sanitize_error(e))

    report = format_release_report(result)
    return _text_result(report)


def _handle_aiir_gitlab_summary(args: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a GitLab-flavored Markdown summary of AIIR receipts.

    Designed for GitLab Duo Chat and MR comment integration.
    Reads receipts from the ledger and produces a native GitLab Markdown
    summary with optional SAST report data and MR comment posting.
    """
    range_spec = args.get("range")
    include_sast = args.get("include_sast", False)
    post_to_mr = args.get("post_to_mr", False)

    try:
        if range_spec:
            # Generate receipts for the specified range
            receipts = generate_receipts_for_range(range_spec, cwd=None)
        else:
            # Load from ledger
            ledger_path = Path.cwd() / ".aiir" / "receipts.jsonl"
            if not ledger_path.is_file():
                return _text_result(
                    "No AIIR ledger found in this repository.\n"
                    "Run 'aiir --pretty' to generate your first receipt, "
                    "then use this tool to create a GitLab summary."
                )
            receipts = []
            with open(ledger_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            receipts.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        if not receipts:
            return _text_result(
                "No receipts found. "
                "Run 'aiir --range <range>' to generate receipts first."
            )

        # Format as GitLab-flavored Markdown
        summary = format_gitlab_summary(receipts)

        # Optionally append SAST report data
        if include_sast:
            sast = format_gl_sast_report(receipts)
            summary += (
                "\n\n<details>\n<summary>🛡️ SAST Report Data</summary>\n\n"
                "```json\n"
                + json.dumps(sast, indent=2)
                + "\n```\n\n</details>"
            )

        # Optionally post to MR (best-effort, non-fatal)
        mr_posted = False
        if post_to_mr:
            import os as _os

            if _os.environ.get("CI_MERGE_REQUEST_IID"):
                try:
                    post_mr_comment(summary)
                    mr_posted = True
                except Exception:
                    pass  # Best-effort — don't fail the tool call

        if mr_posted:
            summary += "\n\n✅ *Summary posted to merge request.*"

        return _text_result(summary)

    except Exception as e:
        return _error_result(_sanitize_error(e))


# ---------------------------------------------------------------------------
# MCP response helpers
# ---------------------------------------------------------------------------


def _text_result(text: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": text}]}


def _error_result(message: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": f"Error: {message}"}], "isError": True}


# ---------------------------------------------------------------------------
# MCP protocol handlers
# ---------------------------------------------------------------------------

TOOL_HANDLERS = {
    "aiir_receipt": _handle_aiir_receipt,
    "aiir_verify": _handle_aiir_verify,
    "aiir_stats": _handle_aiir_stats,
    "aiir_explain": _handle_aiir_explain,
    "aiir_policy_check": _handle_aiir_policy_check,
    "aiir_verify_release": _handle_aiir_verify_release,
    "aiir_gitlab_summary": _handle_aiir_gitlab_summary,
}


def handle_initialize(params: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"tools": {}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
    }


def handle_tools_list(params: Dict[str, Any]) -> Dict[str, Any]:
    return {"tools": TOOLS}


def handle_tools_call(params: Dict[str, Any]) -> Dict[str, Any]:
    name = params.get("name", "")
    arguments = params.get("arguments", {})
    # Validate arguments type — per MCP spec, arguments should
    # be an object (dict).  Non-dict values (string, list, number, null)
    # would cause handler .get() calls to raise AttributeError, producing
    # opaque internal errors instead of proper validation errors.
    if not isinstance(arguments, dict):
        return _error_result(
            "Invalid 'arguments': expected a JSON object (dict), "
            f"got {type(arguments).__name__}."
        )

    handler = TOOL_HANDLERS.get(name)
    if handler is None:
        return _error_result(f"Unknown tool: {name}")

    return handler(arguments)


# ---------------------------------------------------------------------------
# JSON-RPC / stdio transport
# ---------------------------------------------------------------------------

HANDLERS = {
    "initialize": handle_initialize,
    "notifications/initialized": None,  # notification — no response
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
}


def _send(msg: Dict[str, Any]) -> None:
    """Write a JSON-RPC message to stdout."""
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _make_response(msg_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _make_error(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


# Rate limiting to prevent local DoS via request flooding.
# A malicious client could spam tool calls that each spawn git subprocesses.
_RATE_LIMIT_WINDOW = 1.0  # seconds
_RATE_LIMIT_MAX = 50  # max requests per window


def serve_stdio() -> None:
    """Run the MCP server over stdin/stdout."""
    import time
    from collections import deque

    # Ensure UTF-8 stdio — MCP protocol is JSON over stdio, which is UTF-8.
    # On Windows, sys.stdin/stdout default to the console code page (cp1252),
    # which corrupts non-ASCII JSON payloads (e.g., unicode in file paths or
    # commit messages).  reconfigure() is available in Python 3.7+.
    for stream in (sys.stdin, sys.stdout):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except (AttributeError, OSError):  # pragma: no cover
                pass  # Non-reconfigurable stream (e.g., pytest capture)

    # Cap maximum line length to prevent OOM from a single huge message.
    _MAX_MSG_SIZE = 10 * 1024 * 1024  # 10 MB
    # Use bounded deque instead of list — prevents unbounded growth
    # under sustained load. maxlen=_RATE_LIMIT_MAX*2 is generous headroom.
    _request_times: deque = deque(maxlen=_RATE_LIMIT_MAX * 2)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        # Reject oversized messages before parsing.
        if len(line) > _MAX_MSG_SIZE:
            continue

        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Reject non-object JSON (e.g., arrays, strings, ints).
        # msg.get() would raise AttributeError on non-dict types.
        if not isinstance(msg, dict):
            _send(_make_error(None, -32600, "Invalid Request: expected JSON object"))
            continue

        # Validate jsonrpc field per JSON-RPC 2.0 §4.
        if msg.get("jsonrpc") != "2.0":
            _send(
                _make_error(
                    msg.get("id"),
                    -32600,
                    "Invalid Request: missing or wrong jsonrpc version",
                )
            )
            continue

        method = msg.get("method", "")
        msg_id = msg.get("id")
        params = msg.get("params", {})

        # Validate params type per JSON-RPC 2.0 §4.2.
        # Params must be a structured value (object or array); our handlers
        # expect named params (dict).  Non-dict values would crash .get().
        if not isinstance(params, dict):
            params = {}

        # Sliding-window rate limiter — reject requests that
        # exceed the threshold to prevent local DoS via subprocess flooding.
        now = time.monotonic()
        _request_times.append(now)
        # Trim timestamps outside the window
        while _request_times and now - _request_times[0] >= _RATE_LIMIT_WINDOW:
            _request_times.popleft()
        if len(_request_times) > _RATE_LIMIT_MAX and msg_id is not None:
            _send(_make_error(msg_id, -32000, "Rate limit exceeded"))
            continue

        handler = HANDLERS.get(method)

        # Notification (no id) — fire and forget
        if msg_id is None:
            if handler is not None:
                try:
                    handler(params)
                except Exception:
                    pass  # Notifications must not produce responses per JSON-RPC 2.0 §4.1
            # Unknown notification methods are silently ignored per
            # JSON-RPC 2.0 spec — but we no longer run arbitrary probes.
            continue

        # Unknown method
        if handler is None:
            _send(_make_error(msg_id, -32601, f"Unknown method: {method}"))
            continue

        # Call handler
        try:
            result = handler(params)
            _send(_make_response(msg_id, result))
        except Exception as e:
            _send(_make_error(msg_id, -32603, _sanitize_error(e)))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="aiir-mcp-server",
        description="AIIR MCP Server — AI Integrity Receipts for any AI coding assistant.",
    )
    parser.add_argument(
        "--stdio",
        action="store_true",
        default=True,
        help="Use stdio transport (default).",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"aiir-mcp-server {SERVER_VERSION}",
    )
    parser.parse_args()

    serve_stdio()


if __name__ == "__main__":  # pragma: no cover
    main()
