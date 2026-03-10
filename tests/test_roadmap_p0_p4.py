"""Tests for P0-P4 roadmap features.

P0: Check Run (create_check_run)
P1: Review Receipt (build_review_receipt)
P2: aiir init (--init CLI)
P3: PR Comment (post_pr_comment)
P4: Commit Trailer (format_commit_trailer)

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import aiir.cli as cli
from aiir._github import (
    _API_TIMEOUT,
    _PR_COMMENT_MARKER,
    _detect_pr_number,
    _find_existing_comment,
    _format_pr_comment,
    _github_api_request,
    create_check_run,
    format_commit_trailer,
    post_pr_comment,
)
from aiir._receipt import (
    REVIEW_RECEIPT_SCHEMA_VERSION,
    build_review_receipt,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

def _make_receipt(**overrides):
    """Build a minimal valid receipt dict for testing."""
    base = {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.2.1",
        "commit": {
            "sha": "a" * 40,
            "author": {"name": "Alice", "email": "alice@example.com", "date": "2026-01-01T00:00:00Z"},
            "committer": {"name": "Alice", "email": "alice@example.com", "date": "2026-01-01T00:00:00Z"},
            "subject": "feat: add feature",
            "message_hash": "sha256:" + "0" * 64,
            "diff_hash": "sha256:" + "1" * 64,
            "files_changed": 2,
            "files": ["src/main.py", "tests/test_main.py"],
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
            "repository": "https://github.com/test/repo",
            "tool": "https://github.com/invariant-systems-ai/aiir@1.2.1",
            "generator": "aiir.cli",
        },
        "receipt_id": "g1-" + "a" * 32,
        "content_hash": "sha256:" + "b" * 64,
        "timestamp": "2026-01-01T00:00:00Z",
        "extensions": {},
    }
    base.update(overrides)
    return base


def _make_ai_receipt(**overrides):
    """Build a receipt with AI authorship signals."""
    r = _make_receipt()
    r["ai_attestation"]["is_ai_authored"] = True
    r["ai_attestation"]["signals_detected"] = ["co-authored-by: copilot"]
    r["ai_attestation"]["signal_count"] = 1
    r["ai_attestation"]["authorship_class"] = "ai_assisted"
    r.update(overrides)
    return r


# ===========================================================================
# P0: Check Run tests
# ===========================================================================


class TestGitHubAPIRequest(unittest.TestCase):
    """Test _github_api_request helper."""

    def test_missing_token_raises(self):
        """No token → RuntimeError."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GITHUB_TOKEN", None)
            with self.assertRaises(RuntimeError) as ctx:
                _github_api_request("https://api.github.com/test", {})
            self.assertIn("No GitHub token", str(ctx.exception))

    def test_successful_request(self):
        """Mocked urlopen returns parsed JSON."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"id": 42}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("aiir._github.urlopen", return_value=mock_resp) as mock_urlopen:
            result = _github_api_request(
                "https://api.github.com/test",
                {"key": "val"},
                token="ghp_test123",
            )
        self.assertEqual(result, {"id": 42})
        # Verify the request was made
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        self.assertEqual(req.full_url, "https://api.github.com/test")
        self.assertEqual(req.get_header("Authorization"), "Bearer ghp_test123")
        self.assertEqual(req.get_method(), "POST")

    def test_http_error_raises_runtime(self):
        """HTTP error → RuntimeError."""
        with patch("aiir._github.urlopen", side_effect=Exception("404 Not Found")):
            with self.assertRaises(RuntimeError) as ctx:
                _github_api_request("https://api.github.com/test", {}, token="ghp_t")
            self.assertIn("GitHub API request failed", str(ctx.exception))

    def test_uses_env_token_fallback(self):
        """Falls back to GITHUB_TOKEN env var when no explicit token."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"ok": true}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_env_token"}):
            with patch("aiir._github.urlopen", return_value=mock_resp) as mock_urlopen:
                _github_api_request("https://api.github.com/test", {})
            req = mock_urlopen.call_args[0][0]
            self.assertEqual(req.get_header("Authorization"), "Bearer ghp_env_token")

    def test_custom_method(self):
        """Custom HTTP method (PATCH)."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"updated": true}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("aiir._github.urlopen", return_value=mock_resp) as mock_urlopen:
            _github_api_request(
                "https://api.github.com/test",
                {"body": "hi"},
                token="ghp_t",
                method="PATCH",
            )
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_method(), "PATCH")


class TestCreateCheckRun(unittest.TestCase):
    """P0: Test create_check_run."""

    def test_missing_repo_raises(self):
        """Missing GITHUB_REPOSITORY → RuntimeError."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GITHUB_REPOSITORY", None)
            os.environ.pop("GITHUB_SHA", None)
            with self.assertRaises(RuntimeError) as ctx:
                create_check_run([_make_receipt()])
            self.assertIn("GITHUB_REPOSITORY", str(ctx.exception))

    def test_creates_check_run_payload(self):
        """Verify correct payload structure for check run."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"id": 999}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        receipts = [_make_receipt(), _make_ai_receipt()]

        env = {
            "GITHUB_REPOSITORY": "test/repo",
            "GITHUB_SHA": "abc123" + "0" * 34,
            "GITHUB_TOKEN": "ghp_test",
            "GITHUB_API_URL": "https://api.github.com",
        }

        with patch.dict(os.environ, env, clear=True):
            with patch("aiir._github.urlopen", return_value=mock_resp) as mock_urlopen:
                result = create_check_run(receipts)

        self.assertEqual(result, {"id": 999})
        req = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["name"], "aiir/verify")
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(payload["conclusion"], "success")
        self.assertIn("2 receipts", payload["output"]["title"])
        self.assertIn("1 AI-authored", payload["output"]["title"])
        self.assertIn("AIIR Verification Summary", payload["output"]["summary"])

    def test_explicit_args_override_env(self):
        """Explicit repo/sha/token override env vars."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"id": 1}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.dict(os.environ, {"GITHUB_API_URL": "https://api.github.com"}, clear=True):
            with patch("aiir._github.urlopen", return_value=mock_resp) as mock_urlopen:
                create_check_run(
                    [_make_receipt()],
                    repo="explicit/repo",
                    sha="deadbeef" + "0" * 32,
                    token="ghp_explicit",
                )
        req = mock_urlopen.call_args[0][0]
        self.assertIn("explicit/repo", req.full_url)
        payload = json.loads(req.data.decode("utf-8"))
        self.assertEqual(payload["head_sha"], "deadbeef" + "0" * 32)

    def test_caps_at_50_rows(self):
        """Summary table caps at 50 rows even with more receipts."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"id": 1}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        receipts = [_make_receipt() for _ in range(60)]
        env = {
            "GITHUB_REPOSITORY": "test/repo",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_TOKEN": "ghp_t",
            "GITHUB_API_URL": "https://api.github.com",
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("aiir._github.urlopen", return_value=mock_resp) as mock_urlopen:
                create_check_run(receipts)
        payload = json.loads(mock_urlopen.call_args[0][0].data.decode("utf-8"))
        summary = payload["output"]["summary"]
        # Count table rows (lines starting with '| `')
        row_count = sum(1 for line in summary.split("\n") if line.startswith("| `"))
        self.assertLessEqual(row_count, 50)

    def test_signed_count_in_summary(self):
        """Signed receipts show in summary."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"id": 1}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        r = _make_receipt()
        r["extensions"]["sigstore_bundle"] = "path/to/bundle"
        env = {
            "GITHUB_REPOSITORY": "test/repo",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_TOKEN": "ghp_t",
            "GITHUB_API_URL": "https://api.github.com",
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("aiir._github.urlopen", return_value=mock_resp) as mock_urlopen:
                create_check_run([r])
        payload = json.loads(mock_urlopen.call_args[0][0].data.decode("utf-8"))
        self.assertIn("signed with Sigstore", payload["output"]["summary"])

    def test_single_receipt_title(self):
        """Single receipt uses singular form."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"id": 1}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        env = {
            "GITHUB_REPOSITORY": "test/repo",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_TOKEN": "ghp_t",
            "GITHUB_API_URL": "https://api.github.com",
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("aiir._github.urlopen", return_value=mock_resp) as mock_urlopen:
                create_check_run([_make_receipt()])
        payload = json.loads(mock_urlopen.call_args[0][0].data.decode("utf-8"))
        self.assertEqual(payload["output"]["title"], "1 receipt")


# ===========================================================================
# P1: Review Receipt tests
# ===========================================================================


class TestBuildReviewReceipt(unittest.TestCase):
    """P1: Test build_review_receipt."""

    def _run_in_git_repo(self, func):
        """Run func inside a temporary git repo."""
        with tempfile.TemporaryDirectory() as tmpdir:
            import subprocess
            subprocess.run(["git", "init", tmpdir], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.email", "test@example.com"],
                capture_output=True, check=True,
            )
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.name", "Test User"],
                capture_output=True, check=True,
            )
            # Create a commit
            Path(tmpdir, "file.txt").write_text("hello\n")
            subprocess.run(["git", "-C", tmpdir, "add", "."], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "commit", "-m", "initial"],
                capture_output=True, check=True,
            )
            head_sha = subprocess.run(
                ["git", "-C", tmpdir, "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            return func(tmpdir, head_sha)

    def test_basic_review_receipt(self):
        """Build a review receipt with default outcome."""
        def _test(tmpdir, head_sha):
            receipt = build_review_receipt(
                reviewed_commit=head_sha,
                reviewer_name="Bob",
                reviewer_email="bob@example.com",
                cwd=tmpdir,
            )
            self.assertEqual(receipt["type"], "aiir.review_receipt")
            self.assertEqual(receipt["schema"], REVIEW_RECEIPT_SCHEMA_VERSION)
            self.assertEqual(receipt["review_outcome"], "approved")
            self.assertEqual(receipt["reviewer"]["name"], "Bob")
            self.assertEqual(receipt["reviewer"]["email"], "bob@example.com")
            self.assertEqual(receipt["reviewed_commit"]["sha"], head_sha)
            self.assertTrue(receipt["receipt_id"].startswith("g1-"))
            self.assertTrue(receipt["content_hash"].startswith("sha256:"))
            self.assertIn("timestamp", receipt)
            self.assertIn("extensions", receipt)
            return receipt

        self._run_in_git_repo(_test)

    def test_review_outcomes(self):
        """All three review outcomes work."""
        def _test(tmpdir, head_sha):
            for outcome in ("approved", "rejected", "commented"):
                r = build_review_receipt(
                    reviewed_commit=head_sha,
                    reviewer_name="Alice",
                    reviewer_email="alice@test.com",
                    review_outcome=outcome,
                    cwd=tmpdir,
                )
                self.assertEqual(r["review_outcome"], outcome)
            return True

        self._run_in_git_repo(_test)

    def test_invalid_outcome_raises(self):
        """Invalid review outcome raises ValueError."""
        def _test(tmpdir, head_sha):
            with self.assertRaises(ValueError) as ctx:
                build_review_receipt(
                    reviewed_commit=head_sha,
                    reviewer_name="Bob",
                    reviewer_email="bob@test.com",
                    review_outcome="invalid_outcome",
                    cwd=tmpdir,
                )
            self.assertIn("Invalid review_outcome", str(ctx.exception))
            return True

        self._run_in_git_repo(_test)

    def test_with_comment(self):
        """Review receipt with comment."""
        def _test(tmpdir, head_sha):
            r = build_review_receipt(
                reviewed_commit=head_sha,
                reviewer_name="Bob",
                reviewer_email="bob@test.com",
                comment="LGTM! Clean code.",
                cwd=tmpdir,
            )
            self.assertEqual(r["comment"], "LGTM! Clean code.")
            return True

        self._run_in_git_repo(_test)

    def test_without_comment(self):
        """Review receipt without comment has no comment key."""
        def _test(tmpdir, head_sha):
            r = build_review_receipt(
                reviewed_commit=head_sha,
                reviewer_name="Bob",
                reviewer_email="bob@test.com",
                cwd=tmpdir,
            )
            self.assertNotIn("comment", r)
            return True

        self._run_in_git_repo(_test)

    def test_with_commit_receipt_id(self):
        """Review receipt can reference a commit receipt."""
        def _test(tmpdir, head_sha):
            r = build_review_receipt(
                reviewed_commit=head_sha,
                reviewer_name="Bob",
                reviewer_email="bob@test.com",
                commit_receipt_id="g1-" + "a" * 32,
                cwd=tmpdir,
            )
            self.assertEqual(
                r["reviewed_commit"]["receipt_id"],
                "g1-" + "a" * 32,
            )
            return True

        self._run_in_git_repo(_test)

    def test_content_addressing(self):
        """Receipt ID is deterministic for same inputs."""
        def _test(tmpdir, head_sha):
            r1 = build_review_receipt(
                reviewed_commit=head_sha,
                reviewer_name="Bob",
                reviewer_email="bob@test.com",
                review_outcome="approved",
                cwd=tmpdir,
            )
            r2 = build_review_receipt(
                reviewed_commit=head_sha,
                reviewer_name="Bob",
                reviewer_email="bob@test.com",
                review_outcome="approved",
                cwd=tmpdir,
            )
            # Same core → same receipt_id and content_hash
            self.assertEqual(r1["receipt_id"], r2["receipt_id"])
            self.assertEqual(r1["content_hash"], r2["content_hash"])
            return True

        self._run_in_git_repo(_test)

    def test_different_outcome_different_hash(self):
        """Different outcomes produce different hashes."""
        def _test(tmpdir, head_sha):
            r1 = build_review_receipt(
                reviewed_commit=head_sha,
                reviewer_name="Bob",
                reviewer_email="bob@test.com",
                review_outcome="approved",
                cwd=tmpdir,
            )
            r2 = build_review_receipt(
                reviewed_commit=head_sha,
                reviewer_name="Bob",
                reviewer_email="bob@test.com",
                review_outcome="rejected",
                cwd=tmpdir,
            )
            self.assertNotEqual(r1["receipt_id"], r2["receipt_id"])
            return True

        self._run_in_git_repo(_test)

    def test_extensions_with_namespace(self):
        """Extensions carry namespace when provided."""
        def _test(tmpdir, head_sha):
            r = build_review_receipt(
                reviewed_commit=head_sha,
                reviewer_name="Bob",
                reviewer_email="bob@test.com",
                namespace="acme-corp",
                instance_id="inst-123",
                cwd=tmpdir,
            )
            self.assertEqual(r["extensions"]["namespace"], "acme-corp")
            self.assertEqual(r["extensions"]["instance_id"], "inst-123")
            return True

        self._run_in_git_repo(_test)

    def test_sanitizes_terminal_escapes(self):
        """Terminal escape sequences are stripped from all inputs."""
        def _test(tmpdir, head_sha):
            r = build_review_receipt(
                reviewed_commit=head_sha,
                reviewer_name="\x1b[31mEvil\x1b[0m",
                reviewer_email="evil\x1b[0m@test.com",
                comment="LGTM\x1b[0m!",
                cwd=tmpdir,
            )
            self.assertNotIn("\x1b", r["reviewer"]["name"])
            self.assertNotIn("\x1b", r["reviewer"]["email"])
            self.assertNotIn("\x1b", r["comment"])
            return True

        self._run_in_git_repo(_test)


class TestReviewReceiptSchema(unittest.TestCase):
    """P1: Test review receipt schema file exists and is valid."""

    def test_schema_exists(self):
        """Schema file exists."""
        schema_path = Path(__file__).parent.parent / "schemas" / "review_receipt.v1.schema.json"
        self.assertTrue(schema_path.exists(), f"Schema not found: {schema_path}")

    def test_schema_valid_json(self):
        """Schema file is valid JSON."""
        schema_path = Path(__file__).parent.parent / "schemas" / "review_receipt.v1.schema.json"
        data = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(data["title"], "AIIR Review Receipt v1")
        self.assertIn("reviewed_commit", data["properties"])
        self.assertIn("reviewer", data["properties"])
        self.assertIn("review_outcome", data["properties"])

    def test_schema_version_constant(self):
        """REVIEW_RECEIPT_SCHEMA_VERSION matches schema file."""
        self.assertEqual(REVIEW_RECEIPT_SCHEMA_VERSION, "aiir/review_receipt.v1")


# ===========================================================================
# P2: aiir init tests
# ===========================================================================


class TestAiirInit(unittest.TestCase):
    """P2: Test --init CLI flag."""

    def test_init_creates_directory(self):
        """--init creates .aiir/ with required files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            aiir_dir = Path(tmpdir) / ".aiir"
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = cli.main(["--init", "--ledger", str(aiir_dir)])
            finally:
                os.chdir(old_cwd)

            self.assertEqual(result, 0)
            self.assertTrue(aiir_dir.exists())
            self.assertTrue((aiir_dir / ".gitignore").exists())
            self.assertTrue((aiir_dir / "receipts.jsonl").exists())
            self.assertTrue((aiir_dir / "index.json").exists())
            self.assertTrue((aiir_dir / "config.json").exists())

    def test_init_idempotent(self):
        """Running --init twice doesn't overwrite files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            aiir_dir = Path(tmpdir) / ".aiir"
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                # First init
                cli.main(["--init", "--ledger", str(aiir_dir)])
                # Write something to config
                cfg = json.loads((aiir_dir / "config.json").read_text())
                instance_id = cfg["instance_id"]

                # Second init — should not overwrite
                result = cli.main(["--init", "--ledger", str(aiir_dir)])
            finally:
                os.chdir(old_cwd)

            self.assertEqual(result, 0)
            cfg2 = json.loads((aiir_dir / "config.json").read_text())
            self.assertEqual(cfg2["instance_id"], instance_id)

    def test_init_with_policy(self):
        """--init --policy balanced creates policy.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            aiir_dir = Path(tmpdir) / ".aiir"
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = cli.main(["--init", "--ledger", str(aiir_dir), "--policy", "balanced"])
            finally:
                os.chdir(old_cwd)

            self.assertEqual(result, 0)
            self.assertTrue((aiir_dir / "policy.json").exists())


# ===========================================================================
# P3: PR Comment tests
# ===========================================================================


class TestDetectPRNumber(unittest.TestCase):
    """P3: Test _detect_pr_number."""

    def test_detects_from_pull_request_event(self):
        """Extracts PR number from pull_request event payload."""
        event = {"pull_request": {"number": 42}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(event, f)
            f.flush()
            tmppath = f.name
        try:
            with patch.dict(os.environ, {"GITHUB_EVENT_PATH": tmppath}):
                self.assertEqual(_detect_pr_number(), "42")
        finally:
            os.unlink(tmppath)

    def test_detects_from_issue_event(self):
        """Extracts PR number from issue event payload."""
        event = {"issue": {"number": 99}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(event, f)
            f.flush()
            tmppath = f.name
        try:
            with patch.dict(os.environ, {"GITHUB_EVENT_PATH": tmppath}):
                self.assertEqual(_detect_pr_number(), "99")
        finally:
            os.unlink(tmppath)

    def test_returns_none_when_no_event_path(self):
        """Returns None when GITHUB_EVENT_PATH is not set."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GITHUB_EVENT_PATH", None)
            self.assertIsNone(_detect_pr_number())

    def test_returns_none_for_invalid_json(self):
        """Returns None for invalid JSON event payload."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not json")
            f.flush()
            tmppath = f.name
        try:
            with patch.dict(os.environ, {"GITHUB_EVENT_PATH": tmppath}):
                self.assertIsNone(_detect_pr_number())
        finally:
            os.unlink(tmppath)

    def test_returns_none_for_push_event(self):
        """Returns None for push event (no PR number)."""
        event = {"ref": "refs/heads/main", "commits": []}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(event, f)
            f.flush()
            tmppath = f.name
        try:
            with patch.dict(os.environ, {"GITHUB_EVENT_PATH": tmppath}):
                self.assertIsNone(_detect_pr_number())
        finally:
            os.unlink(tmppath)

    def test_returns_none_for_missing_file(self):
        """Returns None when event file doesn't exist."""
        with patch.dict(os.environ, {"GITHUB_EVENT_PATH": "/nonexistent/event.json"}):
            self.assertIsNone(_detect_pr_number())


class TestFindExistingComment(unittest.TestCase):
    """P3: Test _find_existing_comment."""

    def test_finds_comment_with_marker(self):
        """Finds a comment containing the AIIR marker."""
        mock_resp = MagicMock()
        comments = [
            {"id": 100, "body": "Some other comment"},
            {"id": 200, "body": f"{_PR_COMMENT_MARKER}\n## AIIR Summary"},
        ]
        mock_resp.read.return_value = json.dumps(comments).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        env = {"GITHUB_TOKEN": "ghp_test", "GITHUB_API_URL": "https://api.github.com"}
        with patch.dict(os.environ, env, clear=True):
            with patch("aiir._github.urlopen", return_value=mock_resp):
                result = _find_existing_comment("test/repo", "42")

        self.assertEqual(result, 200)

    def test_returns_none_when_no_marker(self):
        """Returns None when no comment has the marker."""
        mock_resp = MagicMock()
        comments = [{"id": 100, "body": "Just a normal comment"}]
        mock_resp.read.return_value = json.dumps(comments).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        env = {"GITHUB_TOKEN": "ghp_test", "GITHUB_API_URL": "https://api.github.com"}
        with patch.dict(os.environ, env, clear=True):
            with patch("aiir._github.urlopen", return_value=mock_resp):
                result = _find_existing_comment("test/repo", "42")

        self.assertIsNone(result)

    def test_returns_none_on_error(self):
        """Returns None on API error (non-fatal)."""
        env = {"GITHUB_TOKEN": "ghp_test", "GITHUB_API_URL": "https://api.github.com"}
        with patch.dict(os.environ, env, clear=True):
            with patch("aiir._github.urlopen", side_effect=Exception("timeout")):
                result = _find_existing_comment("test/repo", "42")

        self.assertIsNone(result)

    def test_returns_none_without_token(self):
        """Returns None when no token is available."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GITHUB_TOKEN", None)
            result = _find_existing_comment("test/repo", "42")
        self.assertIsNone(result)

    def test_handles_non_dict_comment(self):
        """Gracefully handles non-dict items in comment array."""
        mock_resp = MagicMock()
        comments = ["not a dict", {"id": 300, "body": _PR_COMMENT_MARKER}]
        mock_resp.read.return_value = json.dumps(comments).encode("utf-8")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        env = {"GITHUB_TOKEN": "ghp_test", "GITHUB_API_URL": "https://api.github.com"}
        with patch.dict(os.environ, env, clear=True):
            with patch("aiir._github.urlopen", return_value=mock_resp):
                result = _find_existing_comment("test/repo", "42")
        self.assertEqual(result, 300)


class TestFormatPRComment(unittest.TestCase):
    """P3: Test _format_pr_comment."""

    def test_includes_marker(self):
        """PR comment includes the hidden HTML marker."""
        body = _format_pr_comment([_make_receipt()])
        self.assertIn(_PR_COMMENT_MARKER, body)

    def test_includes_summary_table(self):
        """PR comment includes the summary table."""
        body = _format_pr_comment([_make_receipt()])
        self.assertIn("AIIR Verification Summary", body)
        self.assertIn("Receipts", body)
        self.assertIn("Verified", body)

    def test_counts_ai_authored(self):
        """PR comment counts AI-authored receipts."""
        receipts = [_make_receipt(), _make_ai_receipt()]
        body = _format_pr_comment(receipts)
        self.assertIn("1", body)  # 1 AI-authored

    def test_details_section(self):
        """PR comment includes collapsible details."""
        body = _format_pr_comment([_make_receipt()])
        self.assertIn("<details>", body)
        self.assertIn("Receipt details", body)
        self.assertIn("</details>", body)

    def test_empty_receipts(self):
        """Empty receipts list produces no details section."""
        body = _format_pr_comment([])
        self.assertIn(_PR_COMMENT_MARKER, body)
        self.assertNotIn("<details>", body)

    def test_caps_at_50_receipts(self):
        """Details table caps at 50 rows."""
        receipts = [_make_receipt() for _ in range(60)]
        body = _format_pr_comment(receipts)
        # Count detail rows (lines starting with '| `')
        row_count = sum(1 for line in body.split("\n") if line.startswith("| `"))
        self.assertLessEqual(row_count, 50)

    def test_sanitizes_fields(self):
        """Fields with terminal escapes are sanitized."""
        r = _make_receipt()
        r["commit"]["subject"] = "\x1b[31mEvil Subject\x1b[0m"
        body = _format_pr_comment([r])
        self.assertNotIn("\x1b", body)


class TestPostPRComment(unittest.TestCase):
    """P3: Test post_pr_comment."""

    def test_missing_repo_raises(self):
        """Missing repo and PR number → RuntimeError."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GITHUB_REPOSITORY", None)
            os.environ.pop("GITHUB_EVENT_PATH", None)
            with self.assertRaises(RuntimeError) as ctx:
                post_pr_comment([_make_receipt()])
            self.assertIn("need GITHUB_REPOSITORY", str(ctx.exception))

    def test_creates_new_comment(self):
        """Creates a new comment when no existing one found."""
        mock_resp_list = MagicMock()
        mock_resp_list.read.return_value = b"[]"
        mock_resp_list.__enter__ = lambda s: s
        mock_resp_list.__exit__ = MagicMock(return_value=False)

        mock_resp_post = MagicMock()
        mock_resp_post.read.return_value = b'{"id": 500}'
        mock_resp_post.__enter__ = lambda s: s
        mock_resp_post.__exit__ = MagicMock(return_value=False)

        env = {
            "GITHUB_REPOSITORY": "test/repo",
            "GITHUB_TOKEN": "ghp_test",
            "GITHUB_API_URL": "https://api.github.com",
        }

        # First call: list comments (GET). Second call: create comment (POST).
        with patch.dict(os.environ, env, clear=True):
            with patch("aiir._github.urlopen", side_effect=[mock_resp_list, mock_resp_post]) as mock_urlopen:
                result = post_pr_comment([_make_receipt()], pr_number="42")

        self.assertEqual(result, {"id": 500})
        # Second call should be POST to issues/42/comments
        second_req = mock_urlopen.call_args_list[1][0][0]
        self.assertIn("/issues/42/comments", second_req.full_url)

    def test_updates_existing_comment(self):
        """Updates an existing comment when marker found."""
        comments_json = json.dumps([
            {"id": 200, "body": f"{_PR_COMMENT_MARKER}\nOld summary"},
        ]).encode("utf-8")

        mock_resp_list = MagicMock()
        mock_resp_list.read.return_value = comments_json
        mock_resp_list.__enter__ = lambda s: s
        mock_resp_list.__exit__ = MagicMock(return_value=False)

        mock_resp_patch = MagicMock()
        mock_resp_patch.read.return_value = b'{"id": 200}'
        mock_resp_patch.__enter__ = lambda s: s
        mock_resp_patch.__exit__ = MagicMock(return_value=False)

        env = {
            "GITHUB_REPOSITORY": "test/repo",
            "GITHUB_TOKEN": "ghp_test",
            "GITHUB_API_URL": "https://api.github.com",
        }

        with patch.dict(os.environ, env, clear=True):
            with patch("aiir._github.urlopen", side_effect=[mock_resp_list, mock_resp_patch]) as mock_urlopen:
                result = post_pr_comment([_make_receipt()], pr_number="42")

        self.assertEqual(result, {"id": 200})
        # Second call should be PATCH to issues/comments/200
        second_req = mock_urlopen.call_args_list[1][0][0]
        self.assertIn("/issues/comments/200", second_req.full_url)
        self.assertEqual(second_req.get_method(), "PATCH")


# ===========================================================================
# P4: Commit Trailer tests
# ===========================================================================


class TestFormatCommitTrailer(unittest.TestCase):
    """P4: Test format_commit_trailer."""

    def test_basic_trailer(self):
        """Generates AIIR-Receipt, AIIR-Type, AIIR-AI, AIIR-Verified lines."""
        trailer = format_commit_trailer([_make_receipt()])
        self.assertIn("AIIR-Receipt:", trailer)
        self.assertIn("AIIR-Type: aiir.commit_receipt", trailer)
        self.assertIn("AIIR-AI: false", trailer)
        self.assertIn("AIIR-Verified: true", trailer)

    def test_ai_authored_trailer(self):
        """AI-authored receipt produces AIIR-AI: true."""
        trailer = format_commit_trailer([_make_ai_receipt()])
        self.assertIn("AIIR-AI: true", trailer)

    def test_empty_receipts(self):
        """Empty receipts list produces empty string."""
        trailer = format_commit_trailer([])
        self.assertEqual(trailer, "")

    def test_receipt_id_in_trailer(self):
        """Receipt ID appears in AIIR-Receipt line."""
        r = _make_receipt()
        trailer = format_commit_trailer([r])
        self.assertIn(r["receipt_id"], trailer)

    def test_custom_ledger_dir(self):
        """Custom ledger dir appears in receipt path."""
        trailer = format_commit_trailer([_make_receipt()], ledger_dir="custom/dir")
        self.assertIn("custom/dir/receipts.jsonl#", trailer)

    def test_caps_at_10_trailers(self):
        """Caps at 10 AIIR-Receipt lines."""
        receipts = [_make_receipt() for _ in range(15)]
        trailer = format_commit_trailer(receipts)
        receipt_lines = [l for l in trailer.split("\n") if l.startswith("AIIR-Receipt:")]
        self.assertEqual(len(receipt_lines), 10)

    def test_ends_with_newline(self):
        """Trailer string ends with newline."""
        trailer = format_commit_trailer([_make_receipt()])
        self.assertTrue(trailer.endswith("\n"))

    def test_multiple_receipts_mixed_authorship(self):
        """Mixed human + AI receipts → AIIR-AI: true."""
        trailer = format_commit_trailer([_make_receipt(), _make_ai_receipt()])
        self.assertIn("AIIR-AI: true", trailer)
        # Two receipt lines
        receipt_lines = [l for l in trailer.split("\n") if l.startswith("AIIR-Receipt:")]
        self.assertEqual(len(receipt_lines), 2)

    def test_sanitizes_receipt_id(self):
        """Terminal escapes in receipt_id are stripped."""
        r = _make_receipt()
        r["receipt_id"] = "\x1b[31mg1-" + "a" * 32
        trailer = format_commit_trailer([r])
        self.assertNotIn("\x1b", trailer)

    def test_sanitizes_type(self):
        """Terminal escapes in type field are stripped."""
        r = _make_receipt()
        r["type"] = "\x1b[31maiir.commit_receipt\x1b[0m"
        trailer = format_commit_trailer([r])
        self.assertNotIn("\x1b", trailer)


# ===========================================================================
# P4: --trailer CLI integration tests
# ===========================================================================


class TestTrailerCLIFlag(unittest.TestCase):
    """P4: Test --trailer CLI flag integration."""

    def test_trailer_flag_exists(self):
        """Parser accepts --trailer flag without error."""
        # This should not raise — just verify parsing works
        parser = cli._FriendlyParser(prog="aiir")
        parser.add_argument("--trailer", action="store_true")
        args = parser.parse_args(["--trailer"])
        self.assertTrue(args.trailer)


# ===========================================================================
# CLI integration: GitHub Action with check run + PR comment
# ===========================================================================


class TestGitHubActionCheckRunIntegration(unittest.TestCase):
    """Test that --github-action wires check run + PR comment."""

    @patch("aiir.cli.create_check_run")
    @patch("aiir.cli.post_pr_comment")
    @patch("aiir.cli.generate_receipt")
    def test_github_action_calls_check_run(self, mock_gen, mock_pr, mock_check):
        """--github-action calls create_check_run when GITHUB_TOKEN is set."""
        mock_gen.return_value = _make_receipt()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create fake GITHUB_OUTPUT and GITHUB_STEP_SUMMARY files
            output_file = Path(tmpdir) / "output"
            summary_file = Path(tmpdir) / "summary"
            output_file.write_text("")
            summary_file.write_text("")

            env = {
                "GITHUB_OUTPUT": str(output_file),
                "GITHUB_STEP_SUMMARY": str(summary_file),
                "GITHUB_TOKEN": "ghp_test",
            }
            with patch.dict(os.environ, env):
                with patch("aiir.cli.get_repo_root", return_value=tmpdir):
                    result = cli.main(["--github-action", "--quiet"])

        self.assertEqual(result, 0)
        mock_check.assert_called_once()
        # PR comment may also be called (but might fail gracefully)

    @patch("aiir.cli.create_check_run")
    @patch("aiir.cli.generate_receipt")
    def test_github_action_skips_check_run_without_token(self, mock_gen, mock_check):
        """--github-action doesn't call create_check_run without GITHUB_TOKEN."""
        mock_gen.return_value = _make_receipt()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "output"
            summary_file = Path(tmpdir) / "summary"
            output_file.write_text("")
            summary_file.write_text("")

            env = {
                "GITHUB_OUTPUT": str(output_file),
                "GITHUB_STEP_SUMMARY": str(summary_file),
            }
            with patch.dict(os.environ, env, clear=True):
                # Make sure GITHUB_TOKEN is not set
                os.environ.pop("GITHUB_TOKEN", None)
                with patch("aiir.cli.get_repo_root", return_value=tmpdir):
                    result = cli.main(["--github-action", "--quiet"])

        self.assertEqual(result, 0)
        mock_check.assert_not_called()


# ===========================================================================
# Public API surface tests
# ===========================================================================


class TestPublicAPI(unittest.TestCase):
    """Test that new symbols are available in the public API."""

    def test_github_exports(self):
        """GitHub functions are in __all__."""
        import aiir
        self.assertIn("create_check_run", aiir.__all__)
        self.assertIn("post_pr_comment", aiir.__all__)
        self.assertIn("format_commit_trailer", aiir.__all__)

    def test_review_receipt_exports(self):
        """Review receipt function is in __all__."""
        import aiir
        self.assertIn("build_review_receipt", aiir.__all__)
        self.assertIn("REVIEW_RECEIPT_SCHEMA_VERSION", aiir.__all__)

    def test_import_all(self):
        """All new symbols are importable."""
        from aiir import (
            create_check_run,
            post_pr_comment,
            format_commit_trailer,
            build_review_receipt,
            REVIEW_RECEIPT_SCHEMA_VERSION,
        )
        self.assertIsNotNone(create_check_run)
        self.assertIsNotNone(post_pr_comment)
        self.assertIsNotNone(format_commit_trailer)
        self.assertIsNotNone(build_review_receipt)
        self.assertEqual(REVIEW_RECEIPT_SCHEMA_VERSION, "aiir/review_receipt.v1")


# ===========================================================================
# action.yml integration tests
# ===========================================================================


class TestActionYmlPermissions(unittest.TestCase):
    """Test that action.yml documents required permissions."""

    def test_action_yml_documents_checks_permission(self):
        """action.yml mentions checks: write permission."""
        action_path = Path(__file__).parent.parent / "action.yml"
        content = action_path.read_text(encoding="utf-8")
        self.assertIn("checks: write", content)

    def test_action_yml_documents_pr_permission(self):
        """action.yml mentions pull-requests: write permission."""
        action_path = Path(__file__).parent.parent / "action.yml"
        content = action_path.read_text(encoding="utf-8")
        self.assertIn("pull-requests: write", content)


# ===========================================================================
# Coverage gap tests: _github.py non-dict guards
# ===========================================================================


class TestCheckRunNonDictGuards(unittest.TestCase):
    """Cover non-dict commit/ai_attestation guards in create_check_run."""

    def _mock_check_run(self, receipts):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"id": 1}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        env = {
            "GITHUB_REPOSITORY": "test/repo",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_TOKEN": "ghp_t",
            "GITHUB_API_URL": "https://api.github.com",
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("aiir._github.urlopen", return_value=mock_resp) as m:
                create_check_run(receipts)
        return json.loads(m.call_args[0][0].data.decode("utf-8"))

    def test_commit_as_string(self):
        """Receipt with commit as string → guard resets to {}."""
        r = _make_receipt()
        r["commit"] = "not-a-dict"
        payload = self._mock_check_run([r])
        # Should still produce a valid table row (with empty fields)
        self.assertIn("| `", payload["output"]["summary"])

    def test_ai_attestation_as_list(self):
        """Receipt with ai_attestation as list → guard resets to {}."""
        r = _make_receipt()
        r["ai_attestation"] = ["not", "a", "dict"]
        payload = self._mock_check_run([r])
        self.assertIn("| `", payload["output"]["summary"])

    def test_both_non_dict(self):
        """Both commit and ai_attestation non-dict → both guards fire."""
        r = _make_receipt()
        r["commit"] = 42
        r["ai_attestation"] = "nope"
        payload = self._mock_check_run([r])
        self.assertIn("| `", payload["output"]["summary"])


class TestFormatPRCommentNonDictGuards(unittest.TestCase):
    """Cover non-dict commit/ai_attestation guards in _format_pr_comment."""

    def test_commit_as_string(self):
        """Receipt with commit as string → guard resets to {}."""
        r = _make_receipt()
        r["commit"] = "not-a-dict"
        body = _format_pr_comment([r])
        self.assertIn("<details>", body)
        self.assertIn("| `", body)

    def test_ai_attestation_as_list(self):
        """Receipt with ai_attestation as list → guard resets to {}."""
        r = _make_receipt()
        r["ai_attestation"] = ["not", "a", "dict"]
        body = _format_pr_comment([r])
        self.assertIn("<details>", body)

    def test_both_non_dict(self):
        """Both commit and ai_attestation non-dict → both guards fire."""
        r = _make_receipt()
        r["commit"] = 42
        r["ai_attestation"] = "nope"
        body = _format_pr_comment([r])
        self.assertIn("| `", body)


# ===========================================================================
# Coverage gap: format_commit_trailer partial branches
# ===========================================================================


class TestFormatCommitTrailerEdgeCases(unittest.TestCase):
    """Cover partial branches in format_commit_trailer."""

    def test_empty_receipt_id_skips_trailer_line(self):
        """Receipt with empty receipt_id → no AIIR-Receipt line for it."""
        r = _make_receipt()
        r["receipt_id"] = ""
        trailer = format_commit_trailer([r])
        # Should NOT have an AIIR-Receipt line (empty rid → skip)
        receipt_lines = [l for l in trailer.split("\n") if l.startswith("AIIR-Receipt:")]
        self.assertEqual(len(receipt_lines), 0)
        # But should still have Type, AI, Verified
        self.assertIn("AIIR-Type:", trailer)
        self.assertIn("AIIR-AI:", trailer)
        self.assertIn("AIIR-Verified:", trailer)

    def test_missing_receipt_id_key(self):
        """Receipt with no receipt_id key → no AIIR-Receipt line."""
        r = _make_receipt()
        del r["receipt_id"]
        trailer = format_commit_trailer([r])
        receipt_lines = [l for l in trailer.split("\n") if l.startswith("AIIR-Receipt:")]
        self.assertEqual(len(receipt_lines), 0)

    def test_ai_attestation_not_dict_in_has_ai(self):
        """Non-dict ai_attestation → has_ai is False."""
        r = _make_receipt()
        r["ai_attestation"] = "string"
        trailer = format_commit_trailer([r])
        self.assertIn("AIIR-AI: false", trailer)

    def test_none_receipt_id(self):
        """Receipt with receipt_id=None → str(None) is truthy but harmless."""
        r = _make_receipt()
        r["receipt_id"] = None
        trailer = format_commit_trailer([r])
        # str(None)[:40] is "None" which is truthy
        self.assertIn("AIIR-Receipt:", trailer)


# ===========================================================================
# Coverage gap: _receipt.py repo_url credential stripping
# ===========================================================================


class TestReviewReceiptRepoUrlStripping(unittest.TestCase):
    """Cover build_review_receipt repo_url credential stripping (lines 239-240)."""

    def test_remote_with_credentials_stripped(self):
        """When origin has credentials, they are stripped from the receipt."""
        import subprocess

        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.email", "t@t.com"],
                capture_output=True, check=True,
            )
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.name", "T"],
                capture_output=True, check=True,
            )
            # Add a remote with credentials in URL
            subprocess.run(
                ["git", "-C", tmpdir, "remote", "add", "origin",
                 "https://user:password@github.com/test/repo.git"],
                capture_output=True, check=True,
            )
            # Create a commit
            Path(tmpdir, "f.txt").write_text("x\n")
            subprocess.run(["git", "-C", tmpdir, "add", "."], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "commit", "-m", "init"],
                capture_output=True, check=True,
            )
            head = subprocess.run(
                ["git", "-C", tmpdir, "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()

            receipt = build_review_receipt(
                reviewed_commit=head,
                reviewer_name="R",
                reviewer_email="r@r.com",
                cwd=tmpdir,
            )

        repo_url = receipt["provenance"]["repository"]
        self.assertNotIn("password", repo_url)
        self.assertNotIn("user:", repo_url)
        self.assertIn("github.com/test/repo", repo_url)

    def test_remote_without_credentials_passthrough(self):
        """When origin has no credentials, URL passes through unchanged."""
        import subprocess

        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.email", "t@t.com"],
                capture_output=True, check=True,
            )
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.name", "T"],
                capture_output=True, check=True,
            )
            subprocess.run(
                ["git", "-C", tmpdir, "remote", "add", "origin",
                 "https://github.com/test/repo.git"],
                capture_output=True, check=True,
            )
            Path(tmpdir, "f.txt").write_text("x\n")
            subprocess.run(["git", "-C", tmpdir, "add", "."], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "commit", "-m", "init"],
                capture_output=True, check=True,
            )
            head = subprocess.run(
                ["git", "-C", tmpdir, "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()

            receipt = build_review_receipt(
                reviewed_commit=head,
                reviewer_name="R",
                reviewer_email="r@r.com",
                cwd=tmpdir,
            )

        self.assertIn(
            "https://github.com/test/repo.git",
            receipt["provenance"]["repository"],
        )


# ===========================================================================
# Coverage gap: cli.py --init path traversal guard
# ===========================================================================


class TestInitPathTraversalGuard(unittest.TestCase):
    """Cover --init path traversal guard (refuses paths outside cwd)."""

    def test_path_outside_cwd_rejected(self):
        """--init --ledger /tmp/evil rejects path outside project root."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Use a ledger dir that resolves outside tmpdir
            evil_ledger = "/tmp/.aiir-evil-test-" + os.urandom(4).hex()
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = cli.main(["--init", "--ledger", evil_ledger])
            finally:
                os.chdir(old_cwd)
                # Clean up in case it was somehow created
                import shutil
                if os.path.exists(evil_ledger):
                    shutil.rmtree(evil_ledger)
            self.assertEqual(result, 1)

    def test_relative_path_within_cwd_accepted(self):
        """--init --ledger .aiir (relative) is accepted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = cli.main(["--init", "--ledger", ".aiir"])
            finally:
                os.chdir(old_cwd)
            self.assertEqual(result, 0)
            self.assertTrue(Path(tmpdir, ".aiir").exists())


# ===========================================================================
# Coverage gap: cli.py --init namespace in config
# ===========================================================================


class TestInitNamespace(unittest.TestCase):
    """Cover namespace injection into config.json during --init."""

    def test_init_with_namespace(self):
        """--init --namespace acme-corp stores namespace in config.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            aiir_dir = Path(tmpdir) / ".aiir"
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = cli.main([
                    "--init", "--ledger", str(aiir_dir),
                    "--namespace", "acme-corp",
                ])
            finally:
                os.chdir(old_cwd)
            self.assertEqual(result, 0)
            cfg = json.loads((aiir_dir / "config.json").read_text())
            self.assertEqual(cfg["namespace"], "acme-corp")

    def test_init_without_namespace(self):
        """--init without --namespace omits namespace from config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            aiir_dir = Path(tmpdir) / ".aiir"
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = cli.main(["--init", "--ledger", str(aiir_dir)])
            finally:
                os.chdir(old_cwd)
            self.assertEqual(result, 0)
            cfg = json.loads((aiir_dir / "config.json").read_text())
            self.assertNotIn("namespace", cfg)


# ===========================================================================
# Coverage gap: cli.py --init with non-preset policy
# ===========================================================================


class TestInitPolicyEdgeCases(unittest.TestCase):
    """Cover --init --policy edge cases."""

    def test_init_policy_strict(self):
        """--init --policy strict creates policy.json with strict preset."""
        with tempfile.TemporaryDirectory() as tmpdir:
            aiir_dir = Path(tmpdir) / ".aiir"
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = cli.main([
                    "--init", "--ledger", str(aiir_dir),
                    "--policy", "strict",
                ])
            finally:
                os.chdir(old_cwd)
            self.assertEqual(result, 0)
            self.assertTrue((aiir_dir / "policy.json").exists())

    def test_init_policy_unknown_preset_falls_back(self):
        """--init --policy unknown-preset falls back to 'balanced'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            aiir_dir = Path(tmpdir) / ".aiir"
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = cli.main([
                    "--init", "--ledger", str(aiir_dir),
                    "--policy", "unknown-preset",
                ])
            finally:
                os.chdir(old_cwd)
            self.assertEqual(result, 0)
            self.assertTrue((aiir_dir / "policy.json").exists())


# ===========================================================================
# Coverage gap: cli.py --review handler (lines 712-792)
# ===========================================================================


class TestReviewCLI(unittest.TestCase):
    """Cover the full --review handler in cli.py."""

    def _run_review_in_git_repo(self, extra_args=None, env_overrides=None):
        """Helper: run --review HEAD in a temp git repo, return (exit_code, stdout, stderr)."""
        import subprocess
        import io
        import contextlib

        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.email", "rev@test.com"],
                capture_output=True, check=True,
            )
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.name", "Reviewer"],
                capture_output=True, check=True,
            )
            # Add remote so repo_url is populated
            subprocess.run(
                ["git", "-C", tmpdir, "remote", "add", "origin",
                 "https://github.com/test/repo.git"],
                capture_output=True, check=True,
            )
            Path(tmpdir, "f.txt").write_text("x\n")
            subprocess.run(["git", "-C", tmpdir, "add", "."], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "commit", "-m", "init"],
                capture_output=True, check=True,
            )

            argv = ["--review", "--ledger", str(Path(tmpdir) / ".aiir")]
            if extra_args:
                argv.extend(extra_args)

            old_cwd = os.getcwd()
            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            try:
                os.chdir(tmpdir)
                if env_overrides:
                    with patch.dict(os.environ, env_overrides):
                        with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                            rc = cli.main(argv)
                else:
                    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                        rc = cli.main(argv)
            finally:
                os.chdir(old_cwd)

        return rc, stdout_buf.getvalue(), stderr_buf.getvalue()

    def test_review_default_approved(self):
        """--review with default outcome=approved produces receipt."""
        rc, stdout, stderr = self._run_review_in_git_repo()
        self.assertEqual(rc, 0)
        receipt = json.loads(stdout)
        self.assertEqual(receipt["type"], "aiir.review_receipt")
        self.assertEqual(receipt["review_outcome"], "approved")
        self.assertIn("Review receipt", stderr)

    def test_review_rejected(self):
        """--review --review-outcome rejected."""
        rc, stdout, stderr = self._run_review_in_git_repo(
            extra_args=["--review-outcome", "rejected"]
        )
        self.assertEqual(rc, 0)
        receipt = json.loads(stdout)
        self.assertEqual(receipt["review_outcome"], "rejected")

    def test_review_commented_with_comment(self):
        """--review --review-outcome commented --review-comment 'needs work'."""
        rc, stdout, stderr = self._run_review_in_git_repo(
            extra_args=[
                "--review-outcome", "commented",
                "--review-comment", "needs work",
            ]
        )
        self.assertEqual(rc, 0)
        receipt = json.loads(stdout)
        self.assertEqual(receipt["review_outcome"], "commented")
        self.assertEqual(receipt["comment"], "needs work")
        self.assertIn("Comment:", stderr)

    def test_review_json_output(self):
        """--review --json outputs indented JSON to stdout."""
        rc, stdout, stderr = self._run_review_in_git_repo(
            extra_args=["--json"]
        )
        self.assertEqual(rc, 0)
        receipt = json.loads(stdout)
        self.assertEqual(receipt["type"], "aiir.review_receipt")

    def test_review_jsonl_output(self):
        """--review --jsonl outputs compact JSON to stdout."""
        rc, stdout, stderr = self._run_review_in_git_repo(
            extra_args=["--jsonl"]
        )
        self.assertEqual(rc, 0)
        # JSONL should be a single line
        lines = [l for l in stdout.strip().split("\n") if l.strip()]
        self.assertEqual(len(lines), 1)
        receipt = json.loads(lines[0])
        self.assertEqual(receipt["type"], "aiir.review_receipt")

    def test_review_quiet(self):
        """--review --quiet suppresses stderr output."""
        rc, stdout, stderr = self._run_review_in_git_repo(
            extra_args=["--quiet"]
        )
        self.assertEqual(rc, 0)
        self.assertNotIn("Review receipt", stderr)

    def test_review_writes_to_stdout_default(self):
        """--review (no --json/--jsonl) still prints receipt JSON to stdout."""
        import subprocess, io, contextlib

        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.email", "r@t.com"],
                capture_output=True, check=True,
            )
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.name", "R"],
                capture_output=True, check=True,
            )
            Path(tmpdir, "f.txt").write_text("x\n")
            subprocess.run(["git", "-C", tmpdir, "add", "."], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "commit", "-m", "init"],
                capture_output=True, check=True,
            )
            ledger = Path(tmpdir) / ".aiir"
            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                # Init the ledger first
                cli.main(["--init", "--ledger", str(ledger)])
                # Now review (default mode: append to ledger + print to stdout)
                with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                    rc = cli.main(["--review", "--ledger", str(ledger)])
            finally:
                os.chdir(old_cwd)

            self.assertEqual(rc, 0)
            receipt = json.loads(stdout_buf.getvalue())
            self.assertEqual(receipt["type"], "aiir.review_receipt")
            self.assertIn("Review receipt", stderr_buf.getvalue())

    def test_review_no_git_identity_uses_env(self):
        """When git config user.name/email fail, falls back to env vars."""
        import subprocess
        import io, contextlib

        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.email", "tmp@t.com"],
                capture_output=True, check=True,
            )
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.name", "Tmp"],
                capture_output=True, check=True,
            )
            Path(tmpdir, "f.txt").write_text("x\n")
            subprocess.run(["git", "-C", tmpdir, "add", "."], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "commit", "-m", "init"],
                capture_output=True, check=True,
            )

            # Mock _run_git to raise for user.name/email queries
            original_run_git = cli._run_git

            def _mock_run_git(args, **kwargs):
                if args == ["config", "user.name"] or args == ["config", "user.email"]:
                    raise RuntimeError("no git identity")
                return original_run_git(args, **kwargs)

            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                env_override = {
                    "GIT_AUTHOR_NAME": "EnvReviewer",
                    "GIT_AUTHOR_EMAIL": "env@test.com",
                }
                with patch.dict(os.environ, env_override):
                    with patch("aiir.cli._run_git", side_effect=_mock_run_git):
                        with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                            rc = cli.main(["--review", "--json"])
            finally:
                os.chdir(old_cwd)

            self.assertEqual(rc, 0)
            receipt = json.loads(stdout_buf.getvalue())
            self.assertEqual(receipt["reviewer"]["name"], "EnvReviewer")
            self.assertEqual(receipt["reviewer"]["email"], "env@test.com")


# ===========================================================================
# Coverage gap: cli.py --trailer output (lines 1578-1580)
# ===========================================================================


class TestTrailerCLIOutput(unittest.TestCase):
    """Cover --trailer flag in receipt generation mode."""

    @patch("aiir.cli.generate_receipt")
    def test_trailer_output_after_receipt(self, mock_gen):
        """--trailer prints trailer lines to stdout after receipt generation."""
        mock_gen.return_value = _make_receipt()

        import subprocess, io, contextlib

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a git repo
            subprocess.run(["git", "init", tmpdir], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.email", "t@t.com"],
                capture_output=True, check=True,
            )
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.name", "T"],
                capture_output=True, check=True,
            )
            Path(tmpdir, "f.txt").write_text("x\n")
            subprocess.run(["git", "-C", tmpdir, "add", "."], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "commit", "-m", "init"],
                capture_output=True, check=True,
            )

            ledger_dir = str(Path(tmpdir) / ".aiir")

            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                with patch("aiir.cli.get_repo_root", return_value=tmpdir):
                    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                        rc = cli.main([
                            "--trailer", "--ledger", ledger_dir,
                            "--quiet",
                        ])
            finally:
                os.chdir(old_cwd)

            self.assertEqual(rc, 0)
            stdout = stdout_buf.getvalue()
            self.assertIn("AIIR-Receipt:", stdout)
            self.assertIn("AIIR-Type:", stdout)
            self.assertIn("AIIR-AI:", stdout)
            self.assertIn("AIIR-Verified:", stdout)


# ===========================================================================
# Coverage gap: cli.py GitHub Action check run + PR comment success logs
# ===========================================================================


class TestGitHubActionSuccessLogs(unittest.TestCase):
    """Cover check run and PR comment success messages in --github-action."""

    @patch("aiir.cli.post_pr_comment")
    @patch("aiir.cli.create_check_run")
    @patch("aiir.cli.generate_receipt")
    def test_check_run_success_message(self, mock_gen, mock_check, mock_pr):
        """Success log appears on stderr when check run succeeds."""
        mock_gen.return_value = _make_receipt()
        mock_check.return_value = {"id": 1}
        mock_pr.side_effect = RuntimeError("no PR")  # PR comment fails (no PR context)

        import io, contextlib

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "output"
            summary_file = Path(tmpdir) / "summary"
            output_file.write_text("")
            summary_file.write_text("")

            env = {
                "GITHUB_OUTPUT": str(output_file),
                "GITHUB_STEP_SUMMARY": str(summary_file),
                "GITHUB_TOKEN": "ghp_test",
            }
            stderr_buf = io.StringIO()
            stdout_buf = io.StringIO()
            with patch.dict(os.environ, env):
                with patch("aiir.cli.get_repo_root", return_value=tmpdir):
                    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                        rc = cli.main(["--github-action"])

        self.assertEqual(rc, 0)
        self.assertIn("Created aiir/verify check run", stderr_buf.getvalue())

    @patch("aiir.cli.post_pr_comment")
    @patch("aiir.cli.create_check_run")
    @patch("aiir.cli.generate_receipt")
    def test_pr_comment_success_message(self, mock_gen, mock_check, mock_pr):
        """Success log appears on stderr when PR comment succeeds."""
        mock_gen.return_value = _make_receipt()
        mock_check.return_value = {"id": 1}
        mock_pr.return_value = {"id": 500}

        import io, contextlib

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "output"
            summary_file = Path(tmpdir) / "summary"
            output_file.write_text("")
            summary_file.write_text("")

            env = {
                "GITHUB_OUTPUT": str(output_file),
                "GITHUB_STEP_SUMMARY": str(summary_file),
                "GITHUB_TOKEN": "ghp_test",
            }
            stderr_buf = io.StringIO()
            stdout_buf = io.StringIO()
            with patch.dict(os.environ, env):
                with patch("aiir.cli.get_repo_root", return_value=tmpdir):
                    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                        rc = cli.main(["--github-action"])

        self.assertEqual(rc, 0)
        stderr = stderr_buf.getvalue()
        self.assertIn("Created aiir/verify check run", stderr)
        self.assertIn("Posted receipt summary to PR", stderr)

    @patch("aiir.cli.create_check_run")
    @patch("aiir.cli.generate_receipt")
    def test_check_run_failure_hint(self, mock_gen, mock_check):
        """Hint message on stderr when check run fails."""
        mock_gen.return_value = _make_receipt()
        mock_check.side_effect = RuntimeError("403 Forbidden")

        import io, contextlib

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "output"
            summary_file = Path(tmpdir) / "summary"
            output_file.write_text("")
            summary_file.write_text("")

            env = {
                "GITHUB_OUTPUT": str(output_file),
                "GITHUB_STEP_SUMMARY": str(summary_file),
                "GITHUB_TOKEN": "ghp_test",
            }
            stderr_buf = io.StringIO()
            stdout_buf = io.StringIO()
            with patch.dict(os.environ, env):
                with patch("aiir.cli.get_repo_root", return_value=tmpdir):
                    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                        rc = cli.main(["--github-action"])

        self.assertEqual(rc, 0)
        self.assertIn("Could not create check run", stderr_buf.getvalue())


# ===========================================================================
# Coverage gap: cli.py error handler branches
# ===========================================================================


class TestInitOSError(unittest.TestCase):
    """Cover except OSError in --init path resolve (lines 634-635)."""

    def test_resolve_oserror_continues(self):
        """If resolve() raises OSError, init continues (graceful fallback)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                with patch("pathlib.Path.resolve", side_effect=OSError("mock resolve failure")):
                    result = cli.main(["--init", "--ledger", ".aiir"])
            finally:
                os.chdir(old_cwd)
            # Should succeed (OSError is caught and ignored)
            self.assertEqual(result, 0)


class TestInitPolicyValueError(unittest.TestCase):
    """Cover except ValueError in --init policy init (lines 691-692)."""

    def test_policy_init_value_error_ignored(self):
        """If init_policy raises ValueError, --init still succeeds."""
        with tempfile.TemporaryDirectory() as tmpdir:
            aiir_dir = Path(tmpdir) / ".aiir"
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                with patch("aiir.cli.init_policy", side_effect=ValueError("bad policy")):
                    result = cli.main([
                        "--init", "--ledger", str(aiir_dir),
                        "--policy", "balanced",
                    ])
            finally:
                os.chdir(old_cwd)
            self.assertEqual(result, 0)
            # policy.json should NOT exist (init_policy failed)
            self.assertFalse((aiir_dir / "policy.json").exists())
            # But other files should exist
            self.assertTrue((aiir_dir / "config.json").exists())


class TestReviewErrorPaths(unittest.TestCase):
    """Cover --review error handler branches in cli.py."""

    def test_review_no_git_repo(self):
        """--review when get_repo_root fails → error + return 1."""
        import io, contextlib

        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            stderr_buf = io.StringIO()
            stdout_buf = io.StringIO()
            try:
                os.chdir(tmpdir)
                with patch("aiir.cli.get_repo_root", side_effect=RuntimeError("not a git repo")):
                    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                        rc = cli.main(["--review"])
            finally:
                os.chdir(old_cwd)
            self.assertEqual(rc, 1)
            self.assertIn("not a git repo", stderr_buf.getvalue())

    def test_review_empty_identity(self):
        """--review with empty reviewer identity → error + return 1."""
        import io, contextlib

        original_run_git = cli._run_git

        def _mock_run_git(args, **kwargs):
            if args == ["config", "user.name"]:
                return ""  # empty name
            if args == ["config", "user.email"]:
                return ""  # empty email
            return original_run_git(args, **kwargs)

        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            stderr_buf = io.StringIO()
            stdout_buf = io.StringIO()
            try:
                os.chdir(tmpdir)
                with patch("aiir.cli.get_repo_root", return_value=tmpdir):
                    with patch("aiir.cli._run_git", side_effect=_mock_run_git):
                        with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                            rc = cli.main(["--review"])
            finally:
                os.chdir(old_cwd)
            self.assertEqual(rc, 1)
            self.assertIn("Cannot determine reviewer identity", stderr_buf.getvalue())

    def test_review_build_receipt_fails(self):
        """--review when build_review_receipt raises ValueError → error."""
        import io, contextlib

        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            stderr_buf = io.StringIO()
            stdout_buf = io.StringIO()
            try:
                os.chdir(tmpdir)
                with patch("aiir.cli.get_repo_root", return_value=tmpdir):
                    with patch("aiir.cli._run_git", return_value="TestUser"):
                        with patch("aiir.cli.build_review_receipt", side_effect=ValueError("bad input")):
                            with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                                rc = cli.main(["--review", "--review-outcome", "approved"])
            finally:
                os.chdir(old_cwd)
            self.assertEqual(rc, 1)
            self.assertIn("bad input", stderr_buf.getvalue())

    def test_review_ledger_append_fails(self):
        """--review when append_to_ledger raises ValueError → error."""
        import io, contextlib, subprocess

        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.email", "t@t.com"],
                capture_output=True, check=True,
            )
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.name", "T"],
                capture_output=True, check=True,
            )
            Path(tmpdir, "f.txt").write_text("x\n")
            subprocess.run(["git", "-C", tmpdir, "add", "."], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "commit", "-m", "init"],
                capture_output=True, check=True,
            )

            old_cwd = os.getcwd()
            stderr_buf = io.StringIO()
            stdout_buf = io.StringIO()
            try:
                os.chdir(tmpdir)
                with patch("aiir.cli.append_to_ledger", side_effect=ValueError("path traversal")):
                    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                        rc = cli.main(["--review", "--ledger", ".aiir"])
            finally:
                os.chdir(old_cwd)
            self.assertEqual(rc, 1)
            self.assertIn("path traversal", stderr_buf.getvalue())


# ===========================================================================
# Coverage gap: partial branches — coverable edge cases
# ===========================================================================


class TestReviewReceiptEmptyRemoteUrl(unittest.TestCase):
    """Cover _receipt.py 'or None' branch when git remote returns empty."""

    def test_empty_remote_url(self):
        """If git remote get-url returns empty, repo_url is None."""
        import subprocess

        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "init", tmpdir], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.email", "t@t.com"],
                capture_output=True, check=True,
            )
            subprocess.run(
                ["git", "-C", tmpdir, "config", "user.name", "T"],
                capture_output=True, check=True,
            )
            Path(tmpdir, "f.txt").write_text("x\n")
            subprocess.run(["git", "-C", tmpdir, "add", "."], capture_output=True, check=True)
            subprocess.run(
                ["git", "-C", tmpdir, "commit", "-m", "init"],
                capture_output=True, check=True,
            )
            head = subprocess.run(
                ["git", "-C", tmpdir, "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()

            # Add origin that returns empty URL somehow — mock _run_git
            from aiir._core import _run_git as orig_run_git

            def _mock_run_git(args, **kwargs):
                if args == ["remote", "get-url", "origin"]:
                    return ""  # empty string → "".strip() is "" → or None → None
                return orig_run_git(args, **kwargs)

            with patch("aiir._receipt._run_git", side_effect=_mock_run_git):
                receipt = build_review_receipt(
                    reviewed_commit=head,
                    reviewer_name="R",
                    reviewer_email="r@r.com",
                    cwd=tmpdir,
                )

            # repo_url should be None (empty string → or None)
            self.assertIsNone(receipt["provenance"]["repository"])


class TestCheckRunFailureQuiet(unittest.TestCase):
    """Cover cli.py partial branch: check run failure with --quiet."""

    @patch("aiir.cli.create_check_run")
    @patch("aiir.cli.generate_receipt")
    def test_check_run_failure_quiet(self, mock_gen, mock_check):
        """Check run failure with --quiet → no hint printed."""
        mock_gen.return_value = _make_receipt()
        mock_check.side_effect = RuntimeError("403 Forbidden")

        import io, contextlib

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "output"
            summary_file = Path(tmpdir) / "summary"
            output_file.write_text("")
            summary_file.write_text("")

            env = {
                "GITHUB_OUTPUT": str(output_file),
                "GITHUB_STEP_SUMMARY": str(summary_file),
                "GITHUB_TOKEN": "ghp_test",
            }
            stderr_buf = io.StringIO()
            stdout_buf = io.StringIO()
            with patch.dict(os.environ, env):
                with patch("aiir.cli.get_repo_root", return_value=tmpdir):
                    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
                        rc = cli.main(["--github-action", "--quiet"])

        self.assertEqual(rc, 0)
        self.assertNotIn("Could not create check run", stderr_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
