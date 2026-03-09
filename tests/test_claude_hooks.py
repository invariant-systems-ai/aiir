"""Tests for Claude Code hooks recipe (docs/claude-code-hooks.md).

Validates that all JSON configuration examples in the hooks documentation
are valid JSON, structurally correct for Claude Code's settings schema,
and that the AIIR CLI commands embedded in hook commands are well-formed.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


# Path to the hooks documentation
_HOOKS_DOC = Path(__file__).resolve().parent.parent / "docs" / "claude-code-hooks.md"


def _extract_json_blocks(markdown: str) -> list[str]:
    """Extract all ```json ... ``` fenced code blocks from markdown."""
    return re.findall(r"```json\s*\n(.*?)```", markdown, re.DOTALL)


def _extract_bash_blocks(markdown: str) -> list[str]:
    """Extract all ```bash ... ``` fenced code blocks from markdown."""
    return re.findall(r"```bash\s*\n(.*?)```", markdown, re.DOTALL)


class TestClaudeHooksDoc(unittest.TestCase):
    """Validate the claude-code-hooks.md documentation."""

    @classmethod
    def setUpClass(cls):
        cls.doc_text = _HOOKS_DOC.read_text(encoding="utf-8")
        cls.json_blocks = _extract_json_blocks(cls.doc_text)

    def test_doc_exists(self):
        """The hooks documentation file must exist."""
        self.assertTrue(_HOOKS_DOC.exists(), f"Missing: {_HOOKS_DOC}")

    def test_all_json_blocks_parse(self):
        """Every JSON code block in the doc must be valid JSON."""
        self.assertGreater(len(self.json_blocks), 0, "No JSON blocks found in doc")
        for i, block in enumerate(self.json_blocks):
            with self.subTest(block_index=i):
                try:
                    json.loads(block)
                except json.JSONDecodeError as e:
                    self.fail(f"JSON block {i} is invalid: {e}\n\n{block[:200]}")

    def test_hook_configs_have_required_structure(self):
        """Hook config blocks must have hooks.PostToolUse with matcher and command."""
        hook_configs = [json.loads(b) for b in self.json_blocks if '"PostToolUse"' in b]
        self.assertGreater(len(hook_configs), 0, "No PostToolUse hook configs found")

        for i, cfg in enumerate(hook_configs):
            with self.subTest(config_index=i):
                self.assertIn("hooks", cfg, "Missing top-level 'hooks' key")
                self.assertIn("PostToolUse", cfg["hooks"], "Missing 'PostToolUse'")

                entries = cfg["hooks"]["PostToolUse"]
                self.assertIsInstance(entries, list)
                self.assertGreater(len(entries), 0)

                for entry in entries:
                    self.assertIn("matcher", entry, "Hook entry missing 'matcher'")
                    self.assertIn("hooks", entry, "Hook entry missing 'hooks'")

                    # Matcher should match Write or Edit (Claude Code tool names)
                    matcher = entry["matcher"]
                    self.assertTrue(
                        "Write" in matcher or "Edit" in matcher,
                        f"Matcher '{matcher}' doesn't match Write or Edit",
                    )

                    for hook in entry["hooks"]:
                        self.assertIn("type", hook)
                        self.assertEqual(hook["type"], "command")
                        self.assertIn("command", hook)

    def test_hook_commands_contain_aiir(self):
        """Every hook command must invoke aiir."""
        hook_configs = [json.loads(b) for b in self.json_blocks if '"PostToolUse"' in b]
        for cfg in hook_configs:
            for entry in cfg["hooks"]["PostToolUse"]:
                for hook in entry["hooks"]:
                    cmd = hook.get("command", "")
                    self.assertIn(
                        "aiir", cmd, f"Hook command doesn't invoke aiir: {cmd[:100]}"
                    )

    def test_hook_commands_use_project_dir_env(self):
        """Hook commands should use $CLAUDE_PROJECT_DIR for portability."""
        hook_configs = [json.loads(b) for b in self.json_blocks if '"PostToolUse"' in b]
        for cfg in hook_configs:
            for entry in cfg["hooks"]["PostToolUse"]:
                for hook in entry["hooks"]:
                    cmd = hook.get("command", "")
                    self.assertIn(
                        "CLAUDE_PROJECT_DIR",
                        cmd,
                        f"Hook command missing $CLAUDE_PROJECT_DIR: {cmd[:100]}",
                    )

    def test_hook_commands_auto_commit(self):
        """Hook commands should include git commit with claude prefix."""
        hook_configs = [json.loads(b) for b in self.json_blocks if '"PostToolUse"' in b]
        for cfg in hook_configs:
            for entry in cfg["hooks"]["PostToolUse"]:
                for hook in entry["hooks"]:
                    cmd = hook.get("command", "")
                    self.assertIn("git commit", cmd)
                    self.assertIn(
                        "claude:",
                        cmd,
                        "Commit message should contain 'claude:' for AI detection",
                    )

    def test_mcp_config_valid(self):
        """The MCP server configuration example must be valid."""
        mcp_blocks = [json.loads(b) for b in self.json_blocks if '"mcpServers"' in b]
        self.assertGreater(len(mcp_blocks), 0, "No MCP config found in doc")

        for cfg in mcp_blocks:
            self.assertIn("mcpServers", cfg)
            self.assertIn("aiir", cfg["mcpServers"])
            server = cfg["mcpServers"]["aiir"]
            self.assertIn("command", server)
            self.assertEqual(server["command"], "aiir-mcp-server")

    def test_no_stale_aiir_dev_references(self):
        """No references to the squatted aiir.dev domain."""
        self.assertNotIn(
            "aiir.dev",
            self.doc_text,
            "Doc contains references to squatted aiir.dev domain",
        )

    def test_aiir_flags_are_real(self):
        """All --flags used in hook commands must be real AIIR CLI flags."""
        # Known AIIR CLI flags (from cli.py)
        known_flags = {
            "--pretty",
            "--sign",
            "--output",
            "--agent-tool",
            "--agent-model",
            "--agent-context",
            "--in-toto",
            "--json",
            "--ai-only",
            "--quiet",
            "--verify",
            "--explain",
            "--stats",
            "--check",
            "--policy",
            "--policy-init",
            "--range",
            "--jsonl",
            "--detail",
            "--ledger",
            "--badge",
            "--export",
            "--namespace",
            "--redact-files",
            "--version",
            "--no-sign",
        }
        hook_configs = [json.loads(b) for b in self.json_blocks if '"PostToolUse"' in b]
        for cfg in hook_configs:
            for entry in cfg["hooks"]["PostToolUse"]:
                for hook in entry["hooks"]:
                    cmd = hook.get("command", "")
                    # Extract --flags from the aiir portion of the command
                    aiir_part = cmd.split("aiir", 1)[-1] if "aiir" in cmd else ""
                    flags = re.findall(r"(--[\w-]+)", aiir_part)
                    for flag in flags:
                        # Skip git flags
                        if flag in ("--quiet", "--no-verify"):
                            continue
                        self.assertIn(
                            flag,
                            known_flags,
                            f"Unknown AIIR flag in hook command: {flag}",
                        )


if __name__ == "__main__":
    unittest.main()
