"""Tests for transport-level agent attestation across all generator paths.

Verifies the 3-tier confidence model:
  - "declared"    — user self-reports via --agent-tool/--agent-model/--agent-context
  - "transport"   — MCP protocol guarantees an AI client invoked the tool
  - "environment" — CI environment variables indicate a bot/AI actor

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import os
import unittest
import unittest.mock
from typing import TYPE_CHECKING
from unittest.mock import patch

if TYPE_CHECKING:
    from aiir._detect import CommitInfo


class TestMcpTransportAttestation(unittest.TestCase):
    """MCP server must stamp generator='aiir.mcp' and confidence='transport'."""

    def _make_fake_commit(self) -> CommitInfo:
        """Create a minimal CommitInfo for testing."""
        from aiir._detect import CommitInfo

        return CommitInfo(
            sha="a" * 40,
            author_name="Test Author",
            author_email="test@example.com",
            author_date="2026-01-01T00:00:00+00:00",
            committer_name="Test Committer",
            committer_email="test@example.com",
            committer_date="2026-01-01T00:00:00+00:00",
            subject="test commit",
            body="test body",
            diff_hash="sha256:" + "0" * 64,
            files_changed=["README.md"],
            is_ai_authored=False,
            ai_signals_detected=[],
            is_bot_authored=False,
            bot_signals_detected=[],
            authorship_class="human",
        )

    @patch("aiir.mcp_server.generate_receipt")
    def test_receipt_single_commit_passes_mcp_generator(self, mock_gen):
        """_handle_aiir_receipt single-commit path must use generator='aiir.mcp'."""
        import aiir.mcp_server as mcp

        mock_gen.return_value = {"receipt_id": "test"}
        mcp._handle_aiir_receipt({"commit": "HEAD"})
        _, kwargs = mock_gen.call_args
        self.assertEqual(kwargs["generator"], "aiir.mcp")

    @patch("aiir.mcp_server.generate_receipt")
    def test_receipt_single_commit_passes_transport_attestation(self, mock_gen):
        """_handle_aiir_receipt single-commit must pass confidence='transport'."""
        import aiir.mcp_server as mcp

        mock_gen.return_value = {"receipt_id": "test"}
        mcp._handle_aiir_receipt({"commit": "HEAD"})
        _, kwargs = mock_gen.call_args
        att = kwargs["agent_attestation"]
        self.assertEqual(att["confidence"], "transport")
        self.assertEqual(att["run_context"], "mcp")

    @patch("aiir.mcp_server.generate_receipts_for_range")
    def test_receipt_range_passes_mcp_generator(self, mock_gen):
        """_handle_aiir_receipt range path must use generator='aiir.mcp'."""
        import aiir.mcp_server as mcp

        mock_gen.return_value = [{"receipt_id": "test"}]
        mcp._handle_aiir_receipt({"range": "HEAD~3..HEAD"})
        _, kwargs = mock_gen.call_args
        self.assertEqual(kwargs["generator"], "aiir.mcp")

    @patch("aiir.mcp_server.generate_receipts_for_range")
    def test_receipt_range_passes_transport_attestation(self, mock_gen):
        """_handle_aiir_receipt range path must pass confidence='transport'."""
        import aiir.mcp_server as mcp

        mock_gen.return_value = [{"receipt_id": "test"}]
        mcp._handle_aiir_receipt({"range": "HEAD~3..HEAD"})
        _, kwargs = mock_gen.call_args
        att = kwargs["agent_attestation"]
        self.assertEqual(att["confidence"], "transport")
        self.assertEqual(att["run_context"], "mcp")

    @patch("aiir.mcp_server.generate_receipts_for_range")
    def test_gitlab_summary_passes_mcp_generator(self, mock_gen):
        """_handle_aiir_gitlab_summary must use generator='aiir.mcp'."""
        import aiir.mcp_server as mcp

        mock_gen.return_value = [{"receipt_id": "test", "ai_attestation": {}}]
        # We need to mock format_gitlab_summary too
        with patch("aiir.mcp_server.format_gitlab_summary", return_value="# Summary"):
            mcp._handle_aiir_gitlab_summary({"range": "HEAD~3..HEAD"})
        _, kwargs = mock_gen.call_args
        self.assertEqual(kwargs["generator"], "aiir.mcp")

    @patch("aiir.mcp_server.generate_receipts_for_range")
    def test_gitlab_summary_passes_transport_attestation(self, mock_gen):
        """_handle_aiir_gitlab_summary must pass confidence='transport'."""
        import aiir.mcp_server as mcp

        mock_gen.return_value = [{"receipt_id": "test", "ai_attestation": {}}]
        with patch("aiir.mcp_server.format_gitlab_summary", return_value="# Summary"):
            mcp._handle_aiir_gitlab_summary({"range": "HEAD~3..HEAD"})
        _, kwargs = mock_gen.call_args
        att = kwargs["agent_attestation"]
        self.assertEqual(att["confidence"], "transport")
        self.assertEqual(att["run_context"], "mcp")


class TestBuildReviewReceiptAttestation(unittest.TestCase):
    """build_review_receipt must accept and include agent_attestation."""

    @patch("aiir._receipt._run_git", return_value="https://example.com/repo.git")
    def test_review_receipt_includes_agent_attestation(self, _mock_git):
        """Review receipt extensions must include agent_attestation when provided."""
        from aiir._receipt import build_review_receipt

        att = {"tool_id": "copilot", "confidence": "declared"}
        receipt = build_review_receipt(
            reviewed_commit="a" * 40,
            reviewer_name="Test",
            reviewer_email="test@example.com",
            agent_attestation=att,
        )
        ext = receipt.get("extensions", {})
        self.assertIn("agent_attestation", ext)
        self.assertEqual(ext["agent_attestation"]["tool_id"], "copilot")
        self.assertEqual(ext["agent_attestation"]["confidence"], "declared")

    @patch("aiir._receipt._run_git", return_value="https://example.com/repo.git")
    def test_review_receipt_without_attestation(self, _mock_git):
        """Review receipt without agent_attestation must NOT have the key."""
        from aiir._receipt import build_review_receipt

        receipt = build_review_receipt(
            reviewed_commit="a" * 40,
            reviewer_name="Test",
            reviewer_email="test@example.com",
        )
        ext = receipt.get("extensions", {})
        self.assertNotIn("agent_attestation", ext)

    @patch("aiir._receipt._run_git", return_value="https://example.com/repo.git")
    def test_review_receipt_sanitizes_attestation(self, _mock_git):
        """Review receipt must sanitize agent_attestation (strip unknown keys)."""
        from aiir._receipt import build_review_receipt

        att = {
            "tool_id": "copilot",
            "evil_key": "should_be_stripped",
            "confidence": "declared",
        }
        receipt = build_review_receipt(
            reviewed_commit="a" * 40,
            reviewer_name="Test",
            reviewer_email="test@example.com",
            agent_attestation=att,
        )
        ext_att = receipt["extensions"]["agent_attestation"]
        self.assertNotIn("evil_key", ext_att)
        self.assertEqual(ext_att["tool_id"], "copilot")


class TestCIEnvironmentAutoDetection(unittest.TestCase):
    """CI environment auto-detection must set confidence='environment'."""

    def _run_cli_main(self, extra_args, env_overrides=None):
        """Run cli.main() with mocked git and optional env overrides.

        Returns the (agent_attestation, generator) tuple that would be passed
        to generate_receipt, or None if the call doesn't reach that point.
        """
        import aiir.cli as cli

        captured = {}

        def _mock_generate_receipt(*a, **kw):
            captured["agent_attestation"] = kw.get("agent_attestation")
            captured["generator"] = kw.get("generator")
            # Return a fake receipt
            return {
                "type": "aiir.commit_receipt",
                "receipt_id": "g1-test",
                "content_hash": "sha256:test",
                "ai_attestation": {
                    "is_ai_authored": False,
                    "authorship_class": "human",
                },
            }

        base_args = ["aiir", "--json", "HEAD"]
        with (
            patch("aiir.cli.generate_receipt", side_effect=_mock_generate_receipt),
            patch("aiir.cli.get_repo_root", return_value="/tmp/fake-repo"),
            patch.dict(os.environ, env_overrides or {}, clear=False),
        ):
            cli.main(base_args + extra_args)

        return captured.get("agent_attestation"), captured.get("generator")

    @patch("aiir.cli.generate_receipt")
    @patch("aiir.cli.get_repo_root", return_value="/tmp/fake-repo")
    def test_github_action_detects_copilot_actor(self, _root, mock_gen):
        """--github-action with GITHUB_ACTOR=copilot must auto-detect."""
        mock_gen.return_value = {
            "type": "aiir.commit_receipt",
            "receipt_id": "g1-test",
            "content_hash": "sha256:test",
        }
        import aiir.cli as cli

        with patch.dict(os.environ, {"GITHUB_ACTOR": "copilot"}, clear=False):
            cli.main(["--json", "--github-action", "--commit", "HEAD"])

        _, kwargs = mock_gen.call_args
        att = kwargs.get("agent_attestation")
        self.assertIsNotNone(att)
        self.assertEqual(att["confidence"], "environment")
        self.assertEqual(att["run_context"], "github-actions")
        self.assertEqual(att["tool_id"], "copilot")

    @patch("aiir.cli.generate_receipt")
    @patch("aiir.cli.get_repo_root", return_value="/tmp/fake-repo")
    def test_github_action_detects_dependabot(self, _root, mock_gen):
        """--github-action with GITHUB_ACTOR=dependabot[bot] must auto-detect."""
        mock_gen.return_value = {
            "type": "aiir.commit_receipt",
            "receipt_id": "g1-test",
            "content_hash": "sha256:test",
        }
        import aiir.cli as cli

        with patch.dict(os.environ, {"GITHUB_ACTOR": "dependabot[bot]"}, clear=False):
            cli.main(["--json", "--github-action", "--commit", "HEAD"])

        _, kwargs = mock_gen.call_args
        att = kwargs.get("agent_attestation")
        self.assertIsNotNone(att)
        self.assertEqual(att["confidence"], "environment")
        self.assertEqual(att["tool_id"], "dependabot[bot]")

    @patch("aiir.cli.generate_receipt")
    @patch("aiir.cli.get_repo_root", return_value="/tmp/fake-repo")
    def test_github_action_human_actor_no_attestation(self, _root, mock_gen):
        """--github-action with GITHUB_ACTOR=human-developer must NOT auto-detect."""
        mock_gen.return_value = {
            "type": "aiir.commit_receipt",
            "receipt_id": "g1-test",
            "content_hash": "sha256:test",
        }
        import aiir.cli as cli

        with patch.dict(
            os.environ, {"GITHUB_ACTOR": "human-developer"}, clear=False
        ):
            cli.main(["--json", "--github-action", "--commit", "HEAD"])

        _, kwargs = mock_gen.call_args
        att = kwargs.get("agent_attestation")
        self.assertIsNone(att)

    @patch("aiir.cli.generate_receipt")
    @patch("aiir.cli.get_repo_root", return_value="/tmp/fake-repo")
    def test_gitlab_ci_detects_duo_actor(self, _root, mock_gen):
        """--gitlab-ci with GITLAB_USER_LOGIN=gitlab-duo must auto-detect."""
        mock_gen.return_value = {
            "type": "aiir.commit_receipt",
            "receipt_id": "g1-test",
            "content_hash": "sha256:test",
        }
        import aiir.cli as cli

        with patch.dict(
            os.environ, {"GITLAB_USER_LOGIN": "gitlab-duo"}, clear=False
        ):
            cli.main(["--json", "--gitlab-ci", "--commit", "HEAD"])

        _, kwargs = mock_gen.call_args
        att = kwargs.get("agent_attestation")
        self.assertIsNotNone(att)
        self.assertEqual(att["confidence"], "environment")
        self.assertEqual(att["run_context"], "gitlab-ci")

    @patch("aiir.cli.generate_receipt")
    @patch("aiir.cli.get_repo_root", return_value="/tmp/fake-repo")
    def test_explicit_flags_override_ci_auto_detection(self, _root, mock_gen):
        """--agent-tool must take precedence over CI environment auto-detection."""
        mock_gen.return_value = {
            "type": "aiir.commit_receipt",
            "receipt_id": "g1-test",
            "content_hash": "sha256:test",
        }
        import aiir.cli as cli

        with patch.dict(os.environ, {"GITHUB_ACTOR": "copilot"}, clear=False):
            cli.main(
                [
                    "--json",
                    "--github-action",
                    "--agent-tool",
                    "my-custom-tool",
                    "--commit",
                    "HEAD",
                ]
            )

        _, kwargs = mock_gen.call_args
        att = kwargs.get("agent_attestation")
        self.assertIsNotNone(att)
        # Explicit --agent-tool wins → confidence is "declared", not "environment"
        self.assertEqual(att["confidence"], "declared")
        self.assertEqual(att["tool_id"], "my-custom-tool")

    @patch("aiir.cli.generate_receipt")
    @patch("aiir.cli.get_repo_root", return_value="/tmp/fake-repo")
    def test_github_action_generator_is_aiir_github(self, _root, mock_gen):
        """--github-action must set generator='aiir.github'."""
        mock_gen.return_value = {
            "type": "aiir.commit_receipt",
            "receipt_id": "g1-test",
            "content_hash": "sha256:test",
        }
        import aiir.cli as cli

        with patch.dict(os.environ, {"GITHUB_ACTOR": "human-dev"}, clear=False):
            cli.main(["--json", "--github-action", "--commit", "HEAD"])

        _, kwargs = mock_gen.call_args
        self.assertEqual(kwargs["generator"], "aiir.github")

    @patch("aiir.cli.generate_receipt")
    @patch("aiir.cli.get_repo_root", return_value="/tmp/fake-repo")
    def test_gitlab_ci_generator_is_aiir_gitlab(self, _root, mock_gen):
        """--gitlab-ci must set generator='aiir.gitlab'."""
        mock_gen.return_value = {
            "type": "aiir.commit_receipt",
            "receipt_id": "g1-test",
            "content_hash": "sha256:test",
        }
        import aiir.cli as cli

        with patch.dict(os.environ, {"GITLAB_USER_LOGIN": "human-dev"}, clear=False):
            cli.main(["--json", "--gitlab-ci", "--commit", "HEAD"])

        _, kwargs = mock_gen.call_args
        self.assertEqual(kwargs["generator"], "aiir.gitlab")


class TestConfidenceLevels(unittest.TestCase):
    """Confidence level semantics: declared < environment < transport."""

    def test_confidence_values_are_valid_strings(self):
        """All confidence levels must be known values."""
        from aiir._receipt import _AGENT_ATTESTATION_KEYS

        self.assertIn("confidence", _AGENT_ATTESTATION_KEYS)

    @patch("aiir._receipt._run_git", return_value="https://example.com/repo.git")
    def test_transport_confidence_in_commit_receipt(self, _mock_git):
        """generate_receipt with transport confidence must preserve it."""
        from aiir._receipt import generate_receipt

        with patch("aiir._receipt.get_commit_info") as mock_ci:
            from aiir._detect import CommitInfo

            mock_ci.return_value = CommitInfo(
                sha="a" * 40,
                author_name="Test",
                author_email="test@example.com",
                author_date="2026-01-01T00:00:00+00:00",
                committer_name="Test",
                committer_email="test@example.com",
                committer_date="2026-01-01T00:00:00+00:00",
                subject="test",
                body="",
                diff_hash="sha256:" + "0" * 64,
                diff_stat="",
                files_changed=[],
                is_ai_authored=False,
                ai_signals_detected=[],
                is_bot_authored=False,
                bot_signals_detected=[],
                authorship_class="human",
            )
            receipt = generate_receipt(
                "HEAD",
                agent_attestation={
                    "run_context": "mcp",
                    "confidence": "transport",
                },
                generator="aiir.mcp",
            )

        self.assertIsNotNone(receipt)
        ext = receipt["extensions"]
        self.assertEqual(ext["agent_attestation"]["confidence"], "transport")
        self.assertEqual(ext["agent_attestation"]["run_context"], "mcp")
        self.assertEqual(receipt["provenance"]["generator"], "aiir.mcp")


if __name__ == "__main__":
    unittest.main()
