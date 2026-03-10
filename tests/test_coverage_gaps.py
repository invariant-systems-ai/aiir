"""Tests to close coverage gaps in _detect.py, _schema.py, and cli.py.

Targets:
  _detect.py:208  — Invalid tree SHA format → ValueError
  _detect.py:216  — Invalid parent SHA format → ValueError
  _schema.py:197  — tree_sha non-string type
  _schema.py:201  — tree_sha invalid hex format
  _schema.py:207  — parent_shas non-list type
  _schema.py:213-216 — parent_shas with invalid entries
  cli.py:759-766,771,773 — Review command with agent attestation flags
  cli.py:1268->1275 — CI auto-detection of AI/bot actors

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import io
import json
import os
import unittest
from typing import Any, Dict
from unittest.mock import patch

from aiir._schema import validate_receipt_schema


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_valid_receipt(**overrides: Any) -> Dict[str, Any]:
    """Build a structurally valid receipt for testing."""
    import hashlib

    def _sha256(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def _canonical_json(obj: Any) -> str:
        return json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )

    core = {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.0.12",
        "commit": {
            "sha": "a" * 40,
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
            "subject": "test commit",
            "message_hash": "sha256:" + _sha256("test"),
            "diff_hash": "sha256:" + _sha256("diff"),
            "files_changed": 1,
            "files": ["test.py"],
        },
        "ai_attestation": {
            "is_ai_authored": False,
            "signals_detected": [],
            "signal_count": 0,
            "is_bot_authored": False,
            "bot_signals_detected": [],
            "bot_signal_count": 0,
            "authorship_class": "human",
            "detection_method": "heuristic_v2",
        },
        "provenance": {
            "repository": "https://github.com/example/repo",
            "tool": "https://github.com/invariant-systems-ai/aiir@1.0.12",
            "generator": "aiir.cli",
        },
    }
    core.update(overrides)

    CORE_KEYS = {"type", "schema", "version", "commit", "ai_attestation", "provenance"}
    core_subset = {k: v for k, v in core.items() if k in CORE_KEYS}
    cj = _canonical_json(core_subset)
    receipt = {
        **core,
        "receipt_id": "g1-" + _sha256(cj)[:32],
        "content_hash": "sha256:" + _sha256(cj),
        "timestamp": "2026-01-01T00:00:00Z",
        "extensions": {},
    }
    return receipt


# ---------------------------------------------------------------------------
# _detect.py — Invalid tree SHA / parent SHA
# ---------------------------------------------------------------------------


class TestDetectInvalidTreeSha(unittest.TestCase):
    """_detect.py:208 — raise ValueError on malformed tree SHA."""

    def test_invalid_tree_sha_raises(self):
        """get_commit_info must reject non-hex tree SHA."""
        from aiir._detect import get_commit_info

        valid_sha = "a" * 40
        # Simulate git log returning a valid commit SHA,
        # but rev-parse for tree SHA returns garbage.
        call_count = {"n": 0}

        def _mock_run_git(args, cwd=None, env=None):
            call_count["n"] += 1
            if args[0] == "log":
                # git log --format=... output (NUL-delimited)
                return f"{valid_sha}\x00Author\x00a@b.com\x002026-01-01T00:00:00+00:00\x00Committer\x00c@d.com\x002026-01-01T00:00:00+00:00\x00test commit"
            if "rev-parse" in args and "^{tree}" in args[-1]:
                # Return invalid tree SHA
                return "NOT_A_VALID_HEX_SHA\n"
            return ""

        with patch("aiir._detect._run_git", side_effect=_mock_run_git):
            with patch("aiir._detect._validate_ref"):
                with self.assertRaises(ValueError) as ctx:
                    get_commit_info("HEAD")
                self.assertIn("Invalid tree SHA", str(ctx.exception))

    def test_invalid_parent_sha_raises(self):
        """_detect.py:216 — raise ValueError on malformed parent SHA."""
        from aiir._detect import get_commit_info

        valid_sha = "a" * 40
        valid_tree = "b" * 40

        def _mock_run_git(args, cwd=None, env=None):
            if args[0] == "log":
                return f"{valid_sha}\x00Author\x00a@b.com\x002026-01-01T00:00:00+00:00\x00Committer\x00c@d.com\x002026-01-01T00:00:00+00:00\x00test commit"
            if "rev-parse" in args:
                if "^{tree}" in args[-1]:
                    return valid_tree + "\n"
                if "^@" in args[-1]:
                    # Return invalid parent SHA
                    return "INVALID_PARENT_HEX\n"
                # rev-parse for ~1 (parent)
                if "~1" in args[-1]:
                    return valid_sha + "\n"
                return valid_sha + "\n"
            return ""

        with patch("aiir._detect._run_git", side_effect=_mock_run_git):
            with patch("aiir._detect._validate_ref"):
                with self.assertRaises(ValueError) as ctx:
                    get_commit_info("HEAD")
                self.assertIn("Invalid parent SHA", str(ctx.exception))


# ---------------------------------------------------------------------------
# _schema.py — DAG binding field validation
# ---------------------------------------------------------------------------


class TestSchemaTreeShaValidation(unittest.TestCase):
    """Coverage for _schema.py:197,201 — tree_sha type and format checks."""

    def test_tree_sha_non_string_type(self):
        """tree_sha = 42 → error about non-string type."""
        receipt = _make_valid_receipt()
        receipt["commit"]["tree_sha"] = 42
        errors = validate_receipt_schema(receipt)
        tree_errors = [e for e in errors if "tree_sha" in e]
        self.assertTrue(tree_errors, f"Expected tree_sha error, got: {errors}")
        self.assertIn("must be a string", tree_errors[0])

    def test_tree_sha_invalid_format(self):
        """tree_sha = 'not_hex' → error about invalid format."""
        receipt = _make_valid_receipt()
        receipt["commit"]["tree_sha"] = "ZZZZ_not_valid_hex"
        errors = validate_receipt_schema(receipt)
        tree_errors = [e for e in errors if "tree_sha" in e]
        self.assertTrue(tree_errors, f"Expected tree_sha error, got: {errors}")
        self.assertIn("hex", tree_errors[0].lower())


class TestSchemaParentShasValidation(unittest.TestCase):
    """Coverage for _schema.py:207,213-216 — parent_shas validation."""

    def test_parent_shas_non_list_type(self):
        """parent_shas = "not a list" → error about non-list type."""
        receipt = _make_valid_receipt()
        receipt["commit"]["parent_shas"] = "not-a-list"
        errors = validate_receipt_schema(receipt)
        parent_errors = [e for e in errors if "parent_shas" in e and "array" in e]
        self.assertTrue(
            parent_errors, f"Expected parent_shas array error, got: {errors}"
        )

    def test_parent_shas_with_invalid_entry(self):
        """parent_shas = ['a'*40, 'INVALID'] → error on invalid entry."""
        receipt = _make_valid_receipt()
        receipt["commit"]["parent_shas"] = ["a" * 40, "INVALID_HEX_VALUE"]
        errors = validate_receipt_schema(receipt)
        parent_errors = [e for e in errors if "parent_shas[" in e]
        self.assertTrue(
            parent_errors, f"Expected parent_shas entry error, got: {errors}"
        )


# ---------------------------------------------------------------------------
# cli.py — Review command with agent attestation flags
# ---------------------------------------------------------------------------


class TestCliReviewAgentAttestation(unittest.TestCase):
    """Coverage for cli.py:759-766,771,773 — review path agent flags."""

    def _run_review_cli(self, extra_argv):
        """Run cli.main() in review mode with mocks, return build_review_receipt kwargs."""
        import aiir.cli as cli_mod

        review_receipt = {
            "type": "aiir.review_receipt",
            "reviewed_commit": "a" * 40,
            "review_outcome": "approved",
        }
        with (
            patch(
                "aiir.cli.build_review_receipt", return_value=review_receipt
            ) as mock_build,
            patch("aiir.cli.write_receipt", return_value="stdout:json"),
            patch(
                "aiir.cli._run_git",
                side_effect=lambda args, cwd=None: "a" * 40 + "\n"
                if "rev-parse" in args
                else "Test User\n"
                if "user.name" in args
                else "test@test.com\n",
            ),
            patch("sys.stderr", io.StringIO()),
            patch("sys.stdout", io.StringIO()),
        ):
            cli_mod.main(["--review", "HEAD"] + extra_argv)
        return mock_build.call_args

    def test_review_with_agent_tool(self):
        """--review with --agent-tool populates agent_attestation.tool_id."""
        call = self._run_review_cli(["--agent-tool", "copilot"])
        kw = call.kwargs if call.kwargs else call[1]
        att = kw.get("agent_attestation")
        self.assertIsNotNone(att)
        self.assertEqual(att["tool_id"], "copilot")
        self.assertEqual(att["confidence"], "declared")

    def test_review_with_agent_model(self):
        """--review with --agent-model populates agent_attestation.model_class."""
        call = self._run_review_cli(["--agent-model", "gpt-4o"])
        kw = call.kwargs if call.kwargs else call[1]
        att = kw.get("agent_attestation")
        self.assertIsNotNone(att)
        self.assertEqual(att["model_class"], "gpt-4o")

    def test_review_with_agent_context(self):
        """--review with --agent-context populates agent_attestation.run_context."""
        call = self._run_review_cli(["--agent-context", "mcp-session"])
        kw = call.kwargs if call.kwargs else call[1]
        att = kw.get("agent_attestation")
        self.assertIsNotNone(att)
        self.assertEqual(att["run_context"], "mcp-session")

    def test_review_github_action_generator(self):
        """--review --github-action sets generator to aiir.github."""
        call = self._run_review_cli(["--github-action"])
        kw = call.kwargs if call.kwargs else call[1]
        self.assertEqual(kw.get("generator"), "aiir.github")

    def test_review_gitlab_ci_generator(self):
        """--review --gitlab-ci sets generator to aiir.gitlab."""
        call = self._run_review_cli(["--gitlab-ci"])
        kw = call.kwargs if call.kwargs else call[1]
        self.assertEqual(kw.get("generator"), "aiir.gitlab")


# ---------------------------------------------------------------------------
# cli.py — CI environment auto-detection of AI/bot actors
# ---------------------------------------------------------------------------


class TestCliCiAutoDetection(unittest.TestCase):
    """Coverage for cli.py:1268->1275 — CI auto-detect AI/bot actors."""

    def _run_commit_cli(self, extra_argv, env_overrides=None):
        """Run cli.main() in commit mode with mocks."""
        import aiir.cli as cli_mod

        receipt = {
            "type": "aiir.commit_receipt",
            "commit": {"sha": "a" * 40},
            "ai_attestation": {"is_ai_authored": False},
        }
        env = os.environ.copy()
        if env_overrides:
            env.update(env_overrides)

        with (
            patch("aiir.cli.generate_receipt", return_value=receipt) as mock_gen,
            patch("aiir.cli.write_receipt", return_value="stdout:json"),
            patch.dict(os.environ, env_overrides or {}),
            patch("sys.stderr", io.StringIO()),
            patch("sys.stdout", io.StringIO()),
        ):
            cli_mod.main(extra_argv)
        return mock_gen.call_args

    def test_github_action_copilot_actor_detected(self):
        """GITHUB_ACTOR=copilot → auto-populates agent_attestation with 'environment'."""
        call = self._run_commit_cli(
            ["--github-action"],
            env_overrides={"GITHUB_ACTOR": "copilot"},
        )
        kw = call.kwargs if call.kwargs else call[1]
        att = kw.get("agent_attestation")
        self.assertIsNotNone(
            att, "Agent attestation should be auto-populated for copilot actor"
        )
        self.assertEqual(att["confidence"], "environment")
        self.assertEqual(att["tool_id"], "copilot")
        self.assertEqual(att["run_context"], "github-actions")

    def test_github_action_dependabot_detected(self):
        """GITHUB_ACTOR=dependabot[bot] → auto-populates as bot."""
        call = self._run_commit_cli(
            ["--github-action"],
            env_overrides={"GITHUB_ACTOR": "dependabot[bot]"},
        )
        kw = call.kwargs if call.kwargs else call[1]
        att = kw.get("agent_attestation")
        self.assertIsNotNone(
            att, "Agent attestation should be auto-populated for dependabot"
        )
        self.assertEqual(att["confidence"], "environment")

    def test_gitlab_ci_bot_actor_detected(self):
        """GITLAB_USER_LOGIN=gitlab-bot → auto-populates agent_attestation."""
        call = self._run_commit_cli(
            ["--gitlab-ci"],
            env_overrides={"GITLAB_USER_LOGIN": "gitlab-bot"},
        )
        kw = call.kwargs if call.kwargs else call[1]
        att = kw.get("agent_attestation")
        self.assertIsNotNone(
            att, "Agent attestation should be auto-populated for gitlab-bot"
        )
        self.assertEqual(att["confidence"], "environment")
        self.assertEqual(att["run_context"], "gitlab-ci")


if __name__ == "__main__":
    unittest.main()
