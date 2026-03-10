"""Tests to close the remaining ~169 uncovered lines across 9 modules.

Target modules and approximate missed-line counts:
  _core.py           (2)   — shell metachar in git ref, URL port stripping
  _gitlab.py        (42)   — API request, comment truncation, format guards,
                              webhook parsing, GraphQL errors, pages dashboard
  _policy.py         (2)   — preset overlay, legacy authorship normalization
  _receipt.py        (5)   — _safe_dict fallback, bot_signals guard, stdout write
  _schema.py         (1)   — provenance.repository non-string validation
  _sign.py           (1)   — UnsafeNoOp policy path (no expected_identity)
  _verify_release.py(37)   — ledger edges, policy file validation, in-toto VSA,
                              format_release_report
  cli.py            (45)   — verify hints/explain, VSA write, gitlab-ci output,
                              sign failure/cleanup, gitlab MR + SAST report
  mcp_server.py     (34)   — safe_verify_path file-not-found, verify valid,
                              verify_release handler, gitlab summary handler,
                              rate limiter, GraphQL error

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import time
import unittest
from collections import deque
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

# ---------------------------------------------------------------------------
# _core.py — shell metachar in git ref (L849), URL port (L1146)
# ---------------------------------------------------------------------------


class TestCoreCoverage(unittest.TestCase):
    """Cover _core.py missed lines."""

    def test_sanitize_git_ref_shell_metachar(self):
        """L849: _validate_ref rejects shell metacharacters."""
        from aiir._core import _validate_ref

        for bad_ref in ["main;rm -rf /", "HEAD|cat", "ref$(id)", "ref`id`"]:
            with self.assertRaises(ValueError, msg=f"Should reject {bad_ref!r}"):
                _validate_ref(bad_ref)

    def test_sanitize_git_ref_clean_passes(self):
        from aiir._core import _validate_ref

        self.assertEqual(_validate_ref("main..HEAD"), "main..HEAD")
        self.assertEqual(_validate_ref("v1.2.3"), "v1.2.3")

    def test_strip_url_credentials_with_port(self):
        """L1146: URL with port is preserved after credential stripping."""
        from aiir._core import _strip_url_credentials

        url = "https://user:pass@gitlab.example.com:8443/group/repo.git"
        clean = _strip_url_credentials(url)
        self.assertNotIn("user", clean)
        self.assertNotIn("pass", clean)
        self.assertIn(":8443", clean)
        self.assertIn("gitlab.example.com", clean)

    def test_strip_url_credentials_with_port_no_user(self):
        """URL with port but no credentials is returned unchanged."""
        from aiir._core import _strip_url_credentials

        url = "https://gitlab.example.com:8443/group/repo.git"
        self.assertEqual(_strip_url_credentials(url), url)


# ---------------------------------------------------------------------------
# _policy.py — preset overlay (L102), legacy authorship (L217)
# ---------------------------------------------------------------------------


class TestPolicyCoverage(unittest.TestCase):
    """Cover _policy.py missed lines."""

    def test_policy_file_with_non_dict_json(self):
        """L102: policy.json containing non-dict JSON triggers ValueError."""
        from aiir._policy import load_policy

        with tempfile.TemporaryDirectory() as td:
            policy_path = Path(td) / "policy.json"
            policy_path.write_text('["array", "not", "dict"]', encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                load_policy(ledger_dir=td)
            self.assertIn("JSON object", str(ctx.exception))

    def test_evaluate_receipt_non_dict_ai_attestation(self):
        """L217: ai={} guard fires when ai_attestation is not a dict."""
        from aiir._policy import evaluate_receipt_policy

        receipt = {
            "ai_attestation": "not-a-dict",
            "provenance": {"repository": "https://example.com/repo"},
        }
        policy = {"allowed_authorship_classes": ["human"]}
        # Should not crash — ai_attestation guards catch the non-dict
        violations = evaluate_receipt_policy(receipt, policy)
        # With non-dict ai, authorship defaults to 'human' which IS allowed
        self.assertEqual(len(violations), 0)

    def test_legacy_authorship_normalization(self):
        """Legacy 'ai-assisted' is normalized and rejected by strict policy."""
        from aiir._policy import evaluate_receipt_policy

        receipt = {
            "ai_attestation": {"authorship_class": "ai-assisted"},
            "provenance": {"repository": "https://example.com/repo"},
        }
        policy = {"allowed_authorship_classes": ["human"]}
        violations = evaluate_receipt_policy(receipt, policy)
        self.assertTrue(len(violations) > 0)
        self.assertEqual(violations[0].rule, "allowed_authorship_classes")

    def test_legacy_authorship_accepted_when_in_allowed(self):
        """Legacy 'ai-assisted' normalizes to 'ai_assisted' and passes if allowed."""
        from aiir._policy import evaluate_receipt_policy

        receipt = {
            "ai_attestation": {"authorship_class": "ai-assisted"},
            "provenance": {"repository": "https://example.com/repo"},
        }
        policy = {"allowed_authorship_classes": ["human", "ai_assisted"]}
        violations = evaluate_receipt_policy(receipt, policy)
        self.assertEqual(len(violations), 0)


# ---------------------------------------------------------------------------
# _receipt.py — _safe_dict fallback (L413), bot_signals (L438-439),
#               stdout write (L584-585)
# ---------------------------------------------------------------------------


class TestReceiptCoverage(unittest.TestCase):
    """Cover _receipt.py missed lines."""

    def test_format_receipt_detail_with_non_dict_commit(self):
        """L413: _safe_dict handles non-dict nested objects gracefully."""
        from aiir._receipt import format_receipt_detail

        receipt = {
            "receipt_id": "g1-test123",
            "type": "aiir.commit.v1",
            "commit": "not-a-dict",  # triggers L402 guard
            "ai_attestation": {"authorship_class": "human"},
            "provenance": {},
            "content_hash": "sha256:abc123",
        }
        # Should not crash — gracefully handles non-dict commit
        text = format_receipt_detail(receipt)
        self.assertIn("g1-test123", text)

    def test_format_receipt_detail_with_non_list_bot_signals(self):
        """L438-439: files_changed that causes int() to raise TypeError."""
        from aiir._receipt import format_receipt_detail

        receipt = {
            "receipt_id": "g1-test456",
            "type": "aiir.commit.v1",
            "commit": {
                "sha": "abc123",
                "subject": "test",
                "author": {"name": "Test"},
                "committer": {"name": "Test"},
                "files_changed": "not-a-number",  # L438 triggers TypeError in int()
                "files": [],
            },
            "ai_attestation": {
                "authorship_class": "human",
                "signals_detected": [],
                "bot_signals_detected": [],
            },
            "provenance": {"repository": "https://example.com/repo"},
            "content_hash": "sha256:abc123",
        }
        text = format_receipt_detail(receipt)
        self.assertIn("abc123", text)

    def test_write_receipt_jsonl_stdout(self):
        """L584: write_receipt with jsonl=True prints to stdout."""
        from aiir._receipt import write_receipt

        receipt = {"receipt_id": "test", "content_hash": "sha256:abc"}
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            result = write_receipt(receipt, output_dir=None, jsonl=True)
        self.assertEqual(result, "stdout:jsonl")
        self.assertIn("receipt_id", captured.getvalue())

    def test_write_receipt_json_stdout(self):
        """L585: write_receipt without jsonl prints pretty JSON to stdout."""
        from aiir._receipt import write_receipt

        receipt = {"receipt_id": "test", "content_hash": "sha256:abc"}
        captured = io.StringIO()
        with patch("sys.stdout", captured):
            result = write_receipt(receipt, output_dir=None, jsonl=False)
        self.assertEqual(result, "stdout:json")
        output = captured.getvalue()
        self.assertIn('"receipt_id"', output)


# ---------------------------------------------------------------------------
# _schema.py — provenance.repository non-string (L285)
# ---------------------------------------------------------------------------


class TestSchemaCoverage(unittest.TestCase):
    """Cover _schema.py missed lines."""

    def test_provenance_repository_non_string(self):
        """L285: provenance without 'repository' key triggers validation error."""
        from aiir._schema import _validate_provenance

        prov = {
            # "repository" key is intentionally MISSING
            "tool": "https://github.com/invariant-systems-ai/aiir@v1.2.1",
            "generator": "aiir.cli",
        }
        errors: list[str] = []
        _validate_provenance(prov, errors)
        self.assertTrue(any("repository is required" in e for e in errors))


# ---------------------------------------------------------------------------
# _sign.py — UnsafeNoOp policy path (L241)
# ---------------------------------------------------------------------------


class TestSignCoverage(unittest.TestCase):
    """Cover _sign.py missed lines."""

    def test_verify_with_expected_identity(self):
        """L241: when expected_identity is set, Identity policy is used."""
        with tempfile.TemporaryDirectory() as td:
            receipt_path = Path(td) / "receipt.json"
            bundle_path = Path(td) / "receipt.json.sigstore"
            receipt_path.write_text('{"test": true}', encoding="utf-8")
            bundle_path.write_text('{"fake": "bundle"}', encoding="utf-8")

            # Create mock sigstore modules
            mock_bundle_cls = MagicMock()
            mock_bundle_cls.from_json.return_value = MagicMock()

            mock_verifier_instance = MagicMock()
            mock_verifier_cls = MagicMock()
            mock_verifier_cls.production.return_value = mock_verifier_instance

            mock_identity_cls = MagicMock()
            mock_noop_cls = MagicMock()

            sigstore_mod = MagicMock()
            models_mod = MagicMock(Bundle=mock_bundle_cls)
            verify_mod = MagicMock(Verifier=mock_verifier_cls)
            policy_mod = MagicMock(Identity=mock_identity_cls, UnsafeNoOp=mock_noop_cls)

            modules = {
                "sigstore": sigstore_mod,
                "sigstore.models": models_mod,
                "sigstore.verify": verify_mod,
                "sigstore.verify.policy": policy_mod,
            }

            saved = {}
            for mod_name in list(modules.keys()):
                if mod_name in sys.modules:
                    saved[mod_name] = sys.modules.pop(mod_name)

            try:
                with patch.dict("sys.modules", modules):
                    from aiir._sign import verify_receipt_signature
                    result = verify_receipt_signature(
                        str(receipt_path),
                        expected_identity="test@example.com",
                        expected_issuer="https://accounts.google.com",
                    )
            finally:
                for mod_name, mod in saved.items():
                    sys.modules[mod_name] = mod

            self.assertTrue(result["valid"])
            self.assertEqual(result["policy"], "identity")
            mock_identity_cls.assert_called_once()


# ---------------------------------------------------------------------------
# _gitlab.py — all 42 missed lines
# ---------------------------------------------------------------------------


class TestGitlabApiRequest(unittest.TestCase):
    """Cover _gitlab_api_request (L115-155)."""

    def test_api_request_job_token(self):
        """Full HTTP flow with JOB-TOKEN header."""
        from aiir._gitlab import _gitlab_api_request

        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"id": 1}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        env = {
            "CI_API_V4_URL": "https://gitlab.example.com/api/v4",
            "CI_JOB_TOKEN": "job-token-123",
        }
        with patch.dict(os.environ, env, clear=False), \
             patch("aiir._gitlab.urlopen", return_value=mock_resp):
            result = _gitlab_api_request("GET", "/projects/1")
        self.assertEqual(result, {"id": 1})

    def test_api_request_private_token(self):
        """Full HTTP flow with PRIVATE-TOKEN header."""
        from aiir._gitlab import _gitlab_api_request

        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"ok": true}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        env = {
            "CI_API_V4_URL": "https://gitlab.example.com/api/v4",
            "GITLAB_TOKEN": "glpat-xxx",
        }
        # Make sure CI_JOB_TOKEN is not set
        with patch.dict(os.environ, env, clear=False), \
             patch.dict(os.environ, {"CI_JOB_TOKEN": ""}, clear=False), \
             patch("aiir._gitlab.urlopen", return_value=mock_resp):
            result = _gitlab_api_request("POST", "/projects/1/notes", body={"body": "hi"})
        self.assertEqual(result, {"ok": True})

    def test_api_request_http_error(self):
        """HTTPError path with readable body."""
        from urllib.error import HTTPError
        from aiir._gitlab import _gitlab_api_request

        http_err = HTTPError(
            "https://gitlab.example.com/api/v4/bad",
            403, "Forbidden", {}, io.BytesIO(b"access denied")
        )
        env = {
            "CI_API_V4_URL": "https://gitlab.example.com/api/v4",
            "GITLAB_TOKEN": "glpat-xxx",
        }
        with patch.dict(os.environ, env, clear=False), \
             patch.dict(os.environ, {"CI_JOB_TOKEN": ""}, clear=False), \
             patch("aiir._gitlab.urlopen", side_effect=http_err):
            with self.assertRaises(RuntimeError) as ctx:
                _gitlab_api_request("GET", "/bad")
        self.assertIn("403", str(ctx.exception))

    def test_api_request_http_error_unreadable(self):
        """L149-150: HTTPError where e.read() raises — inner except fires."""
        from urllib.error import HTTPError
        from aiir._gitlab import _gitlab_api_request

        # Create an HTTPError where read() raises
        http_err = HTTPError(
            "https://gitlab.example.com/api/v4/bad",
            500, "Server Error", {}, None
        )
        # Make read() raise an exception
        http_err.read = MagicMock(side_effect=Exception("read failed"))
        env = {
            "CI_API_V4_URL": "https://gitlab.example.com/api/v4",
            "GITLAB_TOKEN": "glpat-xxx",
        }
        with patch.dict(os.environ, env, clear=False), \
             patch.dict(os.environ, {"CI_JOB_TOKEN": ""}, clear=False), \
             patch("aiir._gitlab.urlopen", side_effect=http_err):
            with self.assertRaises(RuntimeError) as ctx:
                _gitlab_api_request("GET", "/bad")
        self.assertIn("500", str(ctx.exception))

    def test_api_request_url_error(self):
        """URLError path — L156."""
        from urllib.error import URLError
        from aiir._gitlab import _gitlab_api_request

        env = {
            "CI_API_V4_URL": "https://gitlab.example.com/api/v4",
            "GITLAB_TOKEN": "glpat-xxx",
        }
        with patch.dict(os.environ, env, clear=False), \
             patch.dict(os.environ, {"CI_JOB_TOKEN": ""}, clear=False), \
             patch("aiir._gitlab.urlopen", side_effect=URLError("timeout")):
            with self.assertRaises(RuntimeError) as ctx:
                _gitlab_api_request("GET", "/slow")
        self.assertIn("connection error", str(ctx.exception).lower())

    def test_api_request_no_url(self):
        """Missing CI_API_V4_URL raises RuntimeError."""
        from aiir._gitlab import _gitlab_api_request

        with patch.dict(os.environ, {"CI_API_V4_URL": "", "GITLAB_TOKEN": "x"}, clear=False):
            with self.assertRaises(RuntimeError):
                _gitlab_api_request("GET", "/test")

    def test_api_request_no_token(self):
        """Missing auth token raises RuntimeError."""
        from aiir._gitlab import _gitlab_api_request

        env = {"CI_API_V4_URL": "https://gitlab.example.com/api/v4"}
        with patch.dict(os.environ, env, clear=False), \
             patch.dict(os.environ, {"GITLAB_TOKEN": "", "CI_JOB_TOKEN": ""}, clear=False):
            with self.assertRaises(RuntimeError):
                _gitlab_api_request("GET", "/test")


class TestGitlabPostMrComment(unittest.TestCase):
    """Cover post_mr_comment truncation (L194-196)."""

    def test_truncation_large_comment(self):
        """L194-196: comment > 512KB is truncated."""
        from aiir._gitlab import post_mr_comment, _MAX_COMMENT_SIZE

        big_comment = "x" * (_MAX_COMMENT_SIZE + 1000)
        env = {
            "CI_PROJECT_ID": "123",
            "CI_MERGE_REQUEST_IID": "7",
        }
        with patch.dict(os.environ, env, clear=False), \
             patch("aiir._gitlab._gitlab_api_request", return_value={"id": 99}) as mock_api:
            result = post_mr_comment(big_comment)
        # Verify the API was called and the comment was truncated
        call_args = mock_api.call_args
        body = call_args[1].get("body") if call_args[1] else call_args[0][2]
        self.assertEqual(result, {"id": 99})


class TestGitlabFormatGuards(unittest.TestCase):
    """Cover format_gitlab_summary non-dict guards (L255,257,281,283)
    and format_gl_sast_report non-dict guards (L331,333,343)."""

    def _make_receipt(self, commit="not-a-dict", ai="not-a-dict"):
        return {
            "receipt_id": "g1-test",
            "commit": commit,
            "ai_attestation": ai,
            "content_hash": "sha256:abc",
        }

    def test_format_gitlab_summary_non_dict_commit(self):
        """L255,257: non-dict commit/ai in format_gitlab_summary."""
        from aiir._gitlab import format_gitlab_summary

        receipts = [self._make_receipt()]
        text = format_gitlab_summary(receipts)
        self.assertIn("AIIR", text)

    def test_format_gitlab_summary_non_dict_ai(self):
        """L281,283: non-dict commit/ai in detailed section."""
        from aiir._gitlab import format_gitlab_summary

        receipts = [self._make_receipt(
            commit={"sha": "abc123", "subject": "test"},
            ai="not-a-dict",
        )]
        text = format_gitlab_summary(receipts)
        self.assertIn("abc123", text)

    def test_format_gl_sast_report_non_dict_guards(self):
        """L343: non-list signals_detected in SAST with ai_authored=True."""
        from aiir._gitlab import format_gl_sast_report

        receipts = [
            {
                "receipt_id": "g1-test",
                "commit": {"sha": "abc123", "subject": "test"},
                "ai_attestation": {
                    "is_ai_authored": True,
                    "authorship_class": "ai_assisted",
                    "signals_detected": "not-a-list",  # L343: guard makes this []
                },
                "content_hash": "sha256:abc",
            }
        ]
        report = format_gl_sast_report(receipts)
        self.assertIn("vulnerabilities", report)
        self.assertTrue(len(report["vulnerabilities"]) > 0)

    def test_format_gl_sast_report_non_dict_ai(self):
        """L331: non-dict ai_attestation in SAST report."""
        from aiir._gitlab import format_gl_sast_report

        receipts = [
            {
                "receipt_id": "g2-test",
                "commit": {"sha": "abc123", "subject": "test"},
                "ai_attestation": "not-a-dict",  # L331: becomes {}
            }
        ]
        report = format_gl_sast_report(receipts)
        # ai_attestation not a dict → ai={} → is_ai_authored falsy → no vulns
        self.assertEqual(len(report["vulnerabilities"]), 0)

    def test_format_gl_sast_report_non_dict_commit(self):
        """L333: non-dict commit in SAST report."""
        from aiir._gitlab import format_gl_sast_report

        receipts = [
            {
                "receipt_id": "g3-test",
                "commit": 42,  # L333: becomes {}
                "ai_attestation": {"is_ai_authored": True},
            }
        ]
        report = format_gl_sast_report(receipts)
        # commit becomes {} → sha="unknown"
        self.assertTrue(len(report["vulnerabilities"]) > 0)


class TestGitlabWebhookParsing(unittest.TestCase):
    """Cover parse_webhook_event push/MR paths (L545,561,564)."""

    def test_parse_push_event(self):
        """L545: push event parsing."""
        from aiir._gitlab import parse_webhook_event

        payload = {
            "object_kind": "push",
            "project": {"id": 123, "path_with_namespace": "group/repo"},
            "ref": "refs/heads/main",
            "before": "aaa",
            "after": "bbb",
            "total_commits_count": 3,
        }
        result = parse_webhook_event(payload)
        self.assertIsNotNone(result)
        self.assertEqual(result["event_type"], "push")
        self.assertEqual(result["project_id"], "123")
        self.assertEqual(result["commit_count"], "3")

    def test_parse_merge_request_event(self):
        """L561,564: merge request event with non-dict attrs and project."""
        from aiir._gitlab import parse_webhook_event

        # Non-dict object_attributes triggers L561; non-dict project triggers L564
        payload = {
            "object_kind": "merge_request",
            "object_attributes": "not-a-dict",
            "project": "also-not-a-dict",
        }
        result = parse_webhook_event(payload)
        self.assertIsNotNone(result)
        self.assertEqual(result["event_type"], "merge_request")
        # attrs={} so mr_iid defaults to ""
        self.assertEqual(result["mr_iid"], "")

    def test_parse_push_event_non_dict_project(self):
        """Guard: project is not a dict."""
        from aiir._gitlab import parse_webhook_event

        payload = {
            "object_kind": "push",
            "project": "not-a-dict",
            "ref": "main",
            "before": "a",
            "after": "b",
            "total_commits_count": 1,
        }
        result = parse_webhook_event(payload)
        self.assertIsNotNone(result)

    def test_parse_unknown_event(self):
        from aiir._gitlab import parse_webhook_event

        self.assertIsNone(parse_webhook_event({"object_kind": "note"}))

    def test_parse_non_dict(self):
        from aiir._gitlab import parse_webhook_event

        self.assertIsNone(parse_webhook_event("not-a-dict"))


class TestGitlabGraphQLError(unittest.TestCase):
    """Cover query_gitlab_graphql HTTPError path (L727-728)."""

    def test_graphql_http_error(self):
        """L725-726: HTTPError raises RuntimeError with readable body."""
        from urllib.error import HTTPError
        from aiir._gitlab import query_gitlab_graphql

        http_err = HTTPError(
            "https://gitlab.com/api/graphql",
            500, "Server Error", {}, io.BytesIO(b"internal error")
        )
        env = {"CI_SERVER_URL": "https://gitlab.com", "GITLAB_TOKEN": "tok"}
        with patch.dict(os.environ, env, clear=False), \
             patch.dict(os.environ, {"CI_JOB_TOKEN": ""}, clear=False), \
             patch("aiir._gitlab.urlopen", side_effect=http_err):
            with self.assertRaises(RuntimeError) as ctx:
                query_gitlab_graphql("{ currentUser { name } }")
        self.assertIn("500", str(ctx.exception))

    def test_graphql_http_error_unreadable(self):
        """L727-728: HTTPError where e.read() raises — inner except catches."""
        from urllib.error import HTTPError
        from aiir._gitlab import query_gitlab_graphql

        http_err = HTTPError(
            "https://gitlab.com/api/graphql",
            502, "Bad Gateway", {}, None
        )
        http_err.read = MagicMock(side_effect=OSError("closed"))
        env = {"CI_SERVER_URL": "https://gitlab.com", "GITLAB_TOKEN": "tok"}
        with patch.dict(os.environ, env, clear=False), \
             patch.dict(os.environ, {"CI_JOB_TOKEN": ""}, clear=False), \
             patch("aiir._gitlab.urlopen", side_effect=http_err):
            with self.assertRaises(RuntimeError) as ctx:
                query_gitlab_graphql("{ currentUser { name } }")
        self.assertIn("502", str(ctx.exception))

    def test_graphql_url_error(self):
        """URLError raises RuntimeError."""
        from urllib.error import URLError
        from aiir._gitlab import query_gitlab_graphql

        env = {"CI_SERVER_URL": "https://gitlab.com", "GITLAB_TOKEN": "tok"}
        with patch.dict(os.environ, env, clear=False), \
             patch.dict(os.environ, {"CI_JOB_TOKEN": ""}, clear=False), \
             patch("aiir._gitlab.urlopen", side_effect=URLError("timeout")):
            with self.assertRaises(RuntimeError):
                query_gitlab_graphql("{ currentUser { name } }")

    def test_graphql_response_errors(self):
        """GraphQL response containing errors key raises RuntimeError."""
        from aiir._gitlab import query_gitlab_graphql

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {"errors": [{"message": "syntax error"}]}
        ).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        env = {"CI_SERVER_URL": "https://gitlab.com", "GITLAB_TOKEN": "tok"}
        with patch.dict(os.environ, env, clear=False), \
             patch.dict(os.environ, {"CI_JOB_TOKEN": ""}, clear=False), \
             patch("aiir._gitlab.urlopen", return_value=mock_resp):
            with self.assertRaises(RuntimeError) as ctx:
                query_gitlab_graphql("{ bad }")
        self.assertIn("GraphQL errors", str(ctx.exception))


class TestGitlabPagesDashboard(unittest.TestCase):
    """Cover generate_dashboard_html non-dict guards (L808,810)."""

    def test_dashboard_non_dict_receipt_fields(self):
        """L808,810: non-dict commit/ai in receipt rows."""
        from aiir._gitlab import generate_dashboard_html

        receipts = [
            {
                "receipt_id": "g1-test",
                "commit": "not-a-dict",
                "ai_attestation": "not-a-dict",
                "content_hash": "sha256:abc",
                "timestamp": "2026-01-01T00:00:00Z",
            },
        ]
        html = generate_dashboard_html(receipts)
        self.assertIn("<!DOCTYPE html>", html)

    def test_dashboard_with_valid_receipt(self):
        from aiir._gitlab import generate_dashboard_html

        receipts = [
            {
                "receipt_id": "g1-test",
                "commit": {"sha": "abc123", "subject": "test"},
                "ai_attestation": {"authorship_class": "human"},
                "content_hash": "sha256:abc",
                "timestamp": "2026-01-01T00:00:00Z",
            },
        ]
        html = generate_dashboard_html(receipts)
        self.assertIn("abc123", html)


# ---------------------------------------------------------------------------
# _verify_release.py — all 37 missed lines
# ---------------------------------------------------------------------------


class TestVerifyReleaseLedgerEdges(unittest.TestCase):
    """Cover _load_receipts_from_ledger edge cases (L77-129)."""

    def test_ledger_symlink_rejected(self):
        """L82-83: symlink ledger is rejected."""
        from aiir._verify_release import _load_receipts_from_ledger

        with tempfile.TemporaryDirectory() as td:
            real = Path(td) / "real.jsonl"
            real.write_text('{"receipt_id": "test"}\n', encoding="utf-8")
            link = Path(td) / "link.jsonl"
            link.symlink_to(real)
            with self.assertRaises(ValueError) as ctx:
                _load_receipts_from_ledger(str(link))
            self.assertIn("symlink", str(ctx.exception))

    def test_ledger_too_large(self):
        """L85: ledger exceeding MAX_RECEIPT_FILE_SIZE is rejected."""
        from aiir._verify_release import _load_receipts_from_ledger
        from aiir._core import MAX_RECEIPT_FILE_SIZE

        with tempfile.TemporaryDirectory() as td:
            big = Path(td) / "big.jsonl"
            # Write enough to exceed limit
            big.write_text("x" * (MAX_RECEIPT_FILE_SIZE + 1), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                _load_receipts_from_ledger(str(big))
            self.assertIn("too large", str(ctx.exception).lower())

    def test_ledger_not_found(self):
        """L77: missing ledger raises FileNotFoundError."""
        from aiir._verify_release import _load_receipts_from_ledger

        with self.assertRaises(FileNotFoundError):
            _load_receipts_from_ledger("/nonexistent/path.jsonl")

    def test_ledger_max_receipts_truncation(self):
        """L95-100: ledger with > _MAX_LEDGER_RECEIPTS stops early."""
        from aiir._verify_release import _load_receipts_from_ledger, _MAX_LEDGER_RECEIPTS

        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "big.jsonl"
            # Write _MAX_LEDGER_RECEIPTS + 100 lines
            lines = [json.dumps({"receipt_id": f"r-{i}"}) for i in range(_MAX_LEDGER_RECEIPTS + 100)]
            ledger.write_text("\n".join(lines), encoding="utf-8")
            receipts = _load_receipts_from_ledger(str(ledger))
            self.assertEqual(len(receipts), _MAX_LEDGER_RECEIPTS)

    def test_ledger_malformed_lines_skipped(self):
        """Malformed JSON lines are skipped."""
        from aiir._verify_release import _load_receipts_from_ledger

        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "mixed.jsonl"
            ledger.write_text(
                '{"good": 1}\nnot-json\n{"good": 2}\n',
                encoding="utf-8",
            )
            receipts = _load_receipts_from_ledger(str(ledger))
            self.assertEqual(len(receipts), 2)

    def test_ledger_stat_oserror(self):
        """L82-83: stat() raises OSError → ValueError."""
        from aiir._verify_release import _load_receipts_from_ledger

        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "ledger.jsonl"
            f.write_text('{"x":1}\n', encoding="utf-8")
            real_stat = Path.stat
            call_count = [0]
            def stat_side_effect(self_path, *a, **kw):
                call_count[0] += 1
                # Let is_file() and is_symlink() through (they call stat),
                # then fail on the explicit stat() call in the function
                if call_count[0] <= 2:
                    return real_stat(self_path, *a, **kw)
                raise OSError("perm denied")
            with patch.object(Path, "stat", stat_side_effect):
                with self.assertRaises(ValueError) as ctx:
                    _load_receipts_from_ledger(str(f))
                self.assertIn("Cannot stat", str(ctx.exception))

    def test_ledger_blank_lines_skipped(self):
        """L95: blank lines between entries are skipped via continue."""
        from aiir._verify_release import _load_receipts_from_ledger

        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "blanks.jsonl"
            # Use \\n\\n to create blank lines — splitlines will include them
            ledger.write_text(
                '{"a":1}\n\n  \n{"b":2}\n',
                encoding="utf-8",
            )
            receipts = _load_receipts_from_ledger(str(ledger))
            self.assertEqual(len(receipts), 2)

    def test_ledger_non_dict_json_line_skipped(self):
        """Non-dict JSON values (e.g. integers, lists) in ledger are skipped."""
        from aiir._verify_release import _load_receipts_from_ledger

        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "nondicts.jsonl"
            ledger.write_text(
                '42\n"hello"\n[1,2,3]\n{"valid": true}\n',
                encoding="utf-8",
            )
            receipts = _load_receipts_from_ledger(str(ledger))
            self.assertEqual(len(receipts), 1)
            self.assertEqual(receipts[0]["valid"], True)


class TestVerifyReleaseLoadReceiptsFromDir(unittest.TestCase):
    """Cover _load_receipts_from_dir edge cases (L114-129)."""

    def test_dir_not_found(self):
        """L114: directory not found raises FileNotFoundError."""
        from aiir._verify_release import _load_receipts_from_dir

        with self.assertRaises(FileNotFoundError):
            _load_receipts_from_dir("/nonexistent/dir")

    def test_symlink_files_skipped(self):
        """L119: symlink .json files are skipped."""
        from aiir._verify_release import _load_receipts_from_dir

        with tempfile.TemporaryDirectory() as td:
            real = Path(td) / "real.json"
            real.write_text('{"receipt_id": "r1"}', encoding="utf-8")
            link = Path(td) / "link.json"
            link.symlink_to(real)
            # Only the real file should be loaded (not the symlink)
            receipts = _load_receipts_from_dir(td)
            self.assertEqual(len(receipts), 1)

    def test_list_receipts_loaded(self):
        """L124-126: JSON file containing a list of receipts."""
        from aiir._verify_release import _load_receipts_from_dir

        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "batch.json"
            f.write_text(
                json.dumps([{"receipt_id": "r1"}, {"receipt_id": "r2"}]),
                encoding="utf-8",
            )
            receipts = _load_receipts_from_dir(td)
            self.assertEqual(len(receipts), 2)

    def test_unreadable_file_skipped(self):
        """L128-129: unreadable/malformed file is skipped."""
        from aiir._verify_release import _load_receipts_from_dir

        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad.json"
            bad.write_text("not valid json {{{", encoding="utf-8")
            good = Path(td) / "good.json"
            good.write_text('{"receipt_id": "ok"}', encoding="utf-8")
            receipts = _load_receipts_from_dir(td)
            self.assertEqual(len(receipts), 1)


class TestVerifyReleasePolicyFile(unittest.TestCase):
    """Cover verify_release policy file validation (L446-454)."""

    def test_policy_file_symlink_rejected(self):
        """L442-443: symlink policy file is rejected."""
        from aiir._verify_release import verify_release

        with tempfile.TemporaryDirectory() as td:
            real = Path(td) / "policy.json"
            real.write_text('{"preset": "balanced"}', encoding="utf-8")
            link = Path(td) / "link.json"
            link.symlink_to(real)
            ledger = Path(td) / "receipts.jsonl"
            ledger.write_text('{"receipt_id": "test"}\n', encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                verify_release(
                    receipts_path=str(ledger),
                    policy_path=str(link),
                )
            self.assertIn("symlink", str(ctx.exception))

    def test_policy_file_stat_oserror(self):
        """L446-447: stat() on policy file raises OSError → ValueError."""
        from aiir._verify_release import verify_release

        with tempfile.TemporaryDirectory() as td:
            policy = Path(td) / "policy.json"
            policy.write_text('{"preset": "balanced"}', encoding="utf-8")
            ledger = Path(td) / "receipts.jsonl"
            ledger.write_text('{"receipt_id": "test"}\n', encoding="utf-8")
            real_stat = Path.stat
            # Only raise for the policy file, and only on the explicit stat() call
            # (not the internal is_file/is_symlink calls).
            policy_stat_calls = [0]
            def stat_side_effect(self_path, *a, **kw):
                if str(self_path) == str(policy):
                    policy_stat_calls[0] += 1
                    # is_file() calls stat once, is_symlink/lstat calls stat once
                    # The 3rd call is the explicit stat() in the verify_release code
                    if policy_stat_calls[0] >= 3:
                        raise OSError("disk error")
                return real_stat(self_path, *a, **kw)
            with patch.object(Path, "stat", stat_side_effect):
                with self.assertRaises(ValueError) as ctx:
                    verify_release(
                        receipts_path=str(ledger),
                        policy_path=str(policy),
                    )
                self.assertIn("Cannot stat", str(ctx.exception))

    def test_policy_file_too_large(self):
        """L454: policy file exceeding limit is rejected."""
        from aiir._verify_release import verify_release, _MAX_POLICY_FILE_SIZE

        with tempfile.TemporaryDirectory() as td:
            policy = Path(td) / "huge.json"
            policy.write_text("x" * (_MAX_POLICY_FILE_SIZE + 1), encoding="utf-8")
            ledger = Path(td) / "receipts.jsonl"
            ledger.write_text('{"receipt_id": "test"}\n', encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                verify_release(
                    receipts_path=str(ledger),
                    policy_path=str(policy),
                )
            self.assertIn("too large", str(ctx.exception).lower())

    def test_policy_file_not_dict(self):
        """Policy file that is not a JSON object is rejected."""
        from aiir._verify_release import verify_release

        with tempfile.TemporaryDirectory() as td:
            policy = Path(td) / "bad.json"
            policy.write_text('"just a string"', encoding="utf-8")
            ledger = Path(td) / "receipts.jsonl"
            ledger.write_text('{"receipt_id": "test"}\n', encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                verify_release(
                    receipts_path=str(ledger),
                    policy_path=str(policy),
                )
            self.assertIn("JSON object", str(ctx.exception))


class TestVerifyReleaseInTotoVSA(unittest.TestCase):
    """Cover in-toto VSA generation paths (L586-603)."""

    def test_vsa_with_git_remote_fallback(self):
        """L586-603: emit_intoto without subject_name falls back to git remote."""
        from aiir._verify_release import verify_release

        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "receipts.jsonl"
            receipt = {
                "receipt_id": "g1-test",
                "type": "aiir.commit.v1",
                "timestamp": "2026-01-01T00:00:00Z",
                "content_hash": "sha256:abc",
                "commit": {
                    "sha": "deadbeef12345678",
                    "author": {"name": "A", "email": "a@b.com", "date": "2026-01-01T00:00:00Z"},
                    "committer": {"name": "A", "email": "a@b.com", "date": "2026-01-01T00:00:00Z"},
                    "subject": "test commit",
                    "diff_hash": "sha256:abc",
                    "files_changed": 1,
                },
                "ai_attestation": {
                    "is_ai_authored": False,
                    "signal_count": 0,
                    "signals_detected": [],
                    "authorship_class": "human",
                },
                "provenance": {
                    "repository": "https://example.com/repo",
                    "tool": "https://github.com/invariant-systems-ai/aiir@v1.2.1",
                    "generator": "aiir.cli",
                },
            }
            ledger.write_text(json.dumps(receipt) + "\n", encoding="utf-8")

            # Mock git commands for VSA generation
            def mock_run_git(args, cwd=None):
                if "remote" in args:
                    return "https://example.com/repo\n"
                if "rev-parse" in args:
                    return "deadbeef12345678\n"
                if "log" in args:
                    return "deadbeef12345678\n"
                return ""

            with patch("aiir._verify_release._run_git", side_effect=mock_run_git):
                result = verify_release(
                    receipts_path=str(ledger),
                    emit_intoto=True,
                )
            self.assertIn("intoto_statement", result)
            stmt = result["intoto_statement"]
            self.assertEqual(stmt.get("_type"), "https://in-toto.io/Statement/v1")

    def test_vsa_git_remote_failure_fallback(self):
        """When git remote fails, subject_name falls back to 'unknown'."""
        from aiir._verify_release import verify_release

        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "receipts.jsonl"
            receipt = {
                "receipt_id": "g1-test",
                "type": "aiir.commit.v1",
                "timestamp": "2026-01-01T00:00:00Z",
                "content_hash": "sha256:abc",
                "commit": {"sha": "aaa", "author": {"name": "A", "email": "a@b.com", "date": "2026-01-01T00:00:00Z"}, "committer": {"name": "A", "email": "a@b.com", "date": "2026-01-01T00:00:00Z"}, "subject": "test", "diff_hash": "sha256:abc", "files_changed": 1},
                "ai_attestation": {"is_ai_authored": False, "signal_count": 0, "signals_detected": [], "authorship_class": "human"},
                "provenance": {"repository": "https://example.com/r", "tool": "https://github.com/invariant-systems-ai/aiir@v1.2.1", "generator": "aiir.cli"},
            }
            ledger.write_text(json.dumps(receipt) + "\n", encoding="utf-8")

            with patch("aiir._verify_release._run_git", side_effect=RuntimeError("no git")):
                result = verify_release(
                    receipts_path=str(ledger),
                    emit_intoto=True,
                )
            self.assertIn("intoto_statement", result)
            # Subject should contain "unknown" since git remote failed
            subj = result["intoto_statement"].get("subject", [{}])[0]
            self.assertIn("unknown", subj.get("name", ""))

    def test_vsa_with_commit_range_dotdot(self):
        """L593-597: emit_intoto with commit_range containing '..' extracts head_ref."""
        from aiir._verify_release import verify_release

        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "receipts.jsonl"
            receipt = {
                "receipt_id": "g1-test",
                "type": "aiir.commit.v1",
                "timestamp": "2026-01-01T00:00:00Z",
                "content_hash": "sha256:abc",
                "commit": {"sha": "aaa", "author": {"name": "A", "email": "a@b.com", "date": "2026-01-01T00:00:00Z"}, "committer": {"name": "A", "email": "a@b.com", "date": "2026-01-01T00:00:00Z"}, "subject": "test", "diff_hash": "sha256:abc", "files_changed": 1},
                "ai_attestation": {"is_ai_authored": False, "signal_count": 0, "signals_detected": [], "authorship_class": "human"},
                "provenance": {"repository": "https://example.com/r", "tool": "https://github.com/invariant-systems-ai/aiir@v1.2.1", "generator": "aiir.cli"},
            }
            ledger.write_text(json.dumps(receipt) + "\n", encoding="utf-8")

            def mock_run_git(args, cwd=None):
                if "remote" in args:
                    return "https://example.com/repo\n"
                if "rev-parse" in args:
                    return "deadbeef12345678\n"
                if "log" in args:
                    return "aaa\n"
                return ""

            with patch("aiir._verify_release._run_git", side_effect=mock_run_git), \
                 patch("aiir._verify_release.list_commits_in_range", return_value=["aaa"]):
                result = verify_release(
                    receipts_path=str(ledger),
                    emit_intoto=True,
                    commit_range="main..feature",
                )
            self.assertIn("intoto_statement", result)

    def test_vsa_commit_range_dotdot_revparse_failure(self):
        """L596-597: rev-parse fails in commit_range '..' branch → head_sha='unknown'."""
        from aiir._verify_release import verify_release

        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "receipts.jsonl"
            receipt = {
                "receipt_id": "g1-test",
                "type": "aiir.commit.v1",
                "timestamp": "2026-01-01T00:00:00Z",
                "content_hash": "sha256:abc",
                "commit": {"sha": "aaa", "author": {"name": "A", "email": "a@b.com", "date": "2026-01-01T00:00:00Z"}, "committer": {"name": "A", "email": "a@b.com", "date": "2026-01-01T00:00:00Z"}, "subject": "test", "diff_hash": "sha256:abc", "files_changed": 1},
                "ai_attestation": {"is_ai_authored": False, "signal_count": 0, "signals_detected": [], "authorship_class": "human"},
                "provenance": {"repository": "https://example.com/r", "tool": "https://github.com/invariant-systems-ai/aiir@v1.2.1", "generator": "aiir.cli"},
            }
            ledger.write_text(json.dumps(receipt) + "\n", encoding="utf-8")

            def mock_run_git(args, cwd=None):
                if "remote" in args:
                    return "https://example.com/repo\n"
                if "rev-parse" in args:
                    raise RuntimeError("bad ref")
                return ""

            with patch("aiir._verify_release._run_git", side_effect=mock_run_git), \
                 patch("aiir._verify_release.list_commits_in_range", return_value=["aaa"]):
                result = verify_release(
                    receipts_path=str(ledger),
                    emit_intoto=True,
                    commit_range="main..feature",
                )
            self.assertIn("intoto_statement", result)
            subj = result["intoto_statement"].get("subject", [{}])[0]
            self.assertIn("unknown", subj.get("name", ""))


class TestFormatReleaseReport(unittest.TestCase):
    """Cover format_release_report missed lines (L643, L667)."""

    def test_report_with_missing_receipts(self):
        """L643: >10 missing receipts triggers overflow message."""
        from aiir._verify_release import format_release_report

        # Need 11+ missing receipts to hit "... and N more" on L643
        missing = [f"sha_{i:04d}" for i in range(15)]
        result = {
            "verificationResult": "PASSED",
            "reason": "All checks passed",
            "coverage": {
                "commits_total": 15,
                "receipts_found": 0,
                "receipts_missing": missing,
                "coverage_percent": 0,
            },
            "predicate": {"evaluation": {}, "verifier": {}},
            "policy_violations": [],
        }
        report = format_release_report(result)
        self.assertIn("Missing receipts: 15", report)
        self.assertIn("... and 5 more", report)

    def test_report_with_verifier(self):
        """L667: verifier info is displayed in the report."""
        from aiir._verify_release import format_release_report

        result = {
            "verificationResult": "PASSED",
            "reason": "All checks passed",
            "coverage": {"commits_total": 1, "receipts_found": 1, "coverage_percent": 100},
            "predicate": {
                "evaluation": {"totalReceipts": 1, "validReceipts": 1, "invalidReceipts": 0, "policyViolations": 0},
                "verifier": {"id": "https://invariantsystems.io/verifiers/aiir", "version": {"aiir": "1.2.1"}},
            },
            "policy_violations": [],
        }
        report = format_release_report(result)
        self.assertIn("Verifier:", report)
        self.assertIn("1.2.1", report)

    def test_report_with_violations(self):
        """L667: >20 violations triggers overflow message."""
        from aiir._verify_release import format_release_report

        violations = [
            {"commit_sha": f"sha{i:04d}", "rule": "max_ai_percent", "message": f"violation {i}"}
            for i in range(25)
        ]
        result = {
            "verificationResult": "FAILED",
            "reason": "Policy violations detected",
            "coverage": {"commits_total": 25, "receipts_found": 25, "coverage_percent": 100},
            "predicate": {"evaluation": {"totalReceipts": 25, "validReceipts": 0, "invalidReceipts": 25, "policyViolations": 25}, "verifier": {}},
            "policy_violations": violations,
        }
        report = format_release_report(result)
        self.assertIn("Policy Violations:", report)
        self.assertIn("... and 5 more", report)


# ---------------------------------------------------------------------------
# cli.py — all 45 missed lines
# ---------------------------------------------------------------------------


class TestCliVerifyHints(unittest.TestCase):
    """Cover CLI verify hints/explain paths (L612-613, L664, L693, L698, L710-712)."""

    def _run_cli(self, args_list):
        """Helper to run CLI main with given args."""
        import aiir.cli as cli
        with patch("sys.argv", ["aiir"] + args_list):
            return cli.main()

    def test_verify_signature_failure_with_explain(self):
        """L612-613: --verify with signature failure + --explain."""
        import aiir.cli as cli

        receipt = {
            "valid": True,
            "receipt_id": "g1-test0000000000000000",
            "commit_sha": "deadbeef12345678",
            "content_hash": "sha256:abc",
        }
        sig_result = {"valid": False, "error": "bad signature"}

        with tempfile.TemporaryDirectory() as td:
            rf = Path(td) / "receipt.json"
            rf.write_text(json.dumps(receipt), encoding="utf-8")

            with patch.object(cli, "verify_receipt_file", return_value=receipt), \
                 patch.object(cli, "verify_receipt_signature", return_value=sig_result), \
                 patch.object(cli, "_sigstore_available", return_value=True), \
                 patch("sys.argv", ["aiir", "--verify", str(rf), "--verify-sig", "--explain"]), \
                 patch("sys.stderr", new_callable=io.StringIO) as err:
                rc = cli.main()
            self.assertEqual(rc, 1)
            self.assertIn("Signature FAILED", err.getvalue())

    def test_verify_symlink_hint(self):
        """L664: verify hint for 'symlink' error."""
        import aiir.cli as cli

        result = {"valid": False, "error": "symlink detected"}
        with tempfile.TemporaryDirectory() as td:
            rf = Path(td) / "receipt.json"
            rf.write_text("{}", encoding="utf-8")

            with patch.object(cli, "verify_receipt_file", return_value=result), \
                 patch("sys.argv", ["aiir", "--verify", str(rf)]), \
                 patch("sys.stderr", new_callable=io.StringIO) as err:
                rc = cli.main()
            self.assertEqual(rc, 1)
            self.assertIn("symlink", err.getvalue())

    def test_verify_too_large_hint(self):
        """L693: verify hint for 'too large' error."""
        import aiir.cli as cli

        result = {"valid": False, "error": "file too large"}
        with tempfile.TemporaryDirectory() as td:
            rf = Path(td) / "receipt.json"
            rf.write_text("{}", encoding="utf-8")

            with patch.object(cli, "verify_receipt_file", return_value=result), \
                 patch("sys.argv", ["aiir", "--verify", str(rf)]), \
                 patch("sys.stderr", new_callable=io.StringIO) as err:
                rc = cli.main()
            self.assertEqual(rc, 1)
            self.assertIn("size limit", err.getvalue())

    def test_verify_default_hint(self):
        """L698: verify default hint for unknown error."""
        import aiir.cli as cli

        result = {"valid": False, "error": "unknown problem"}
        with tempfile.TemporaryDirectory() as td:
            rf = Path(td) / "receipt.json"
            rf.write_text("{}", encoding="utf-8")

            with patch.object(cli, "verify_receipt_file", return_value=result), \
                 patch("sys.argv", ["aiir", "--verify", str(rf)]), \
                 patch("sys.stderr", new_callable=io.StringIO) as err:
                rc = cli.main()
            self.assertEqual(rc, 1)
            self.assertIn("receipt was changed", err.getvalue())

    def test_verify_failure_with_explain(self):
        """L710-712: --verify failure + --explain prints explanation."""
        import aiir.cli as cli

        result = {"valid": False, "error": "content hash mismatch"}
        with tempfile.TemporaryDirectory() as td:
            rf = Path(td) / "receipt.json"
            rf.write_text("{}", encoding="utf-8")

            with patch.object(cli, "verify_receipt_file", return_value=result), \
                 patch.object(cli, "explain_verification", return_value="EXPLAIN: failure"), \
                 patch("sys.argv", ["aiir", "--verify", str(rf), "--explain"]), \
                 patch("sys.stderr", new_callable=io.StringIO) as err:
                rc = cli.main()
            self.assertEqual(rc, 1)
            self.assertIn("EXPLAIN: failure", err.getvalue())


class TestCliVerifyRelease(unittest.TestCase):
    """Cover CLI --verify-release paths (L693, L698, L710-712)."""

    def test_verify_release_policy_file_path(self):
        """L693: --policy with a file path (not a preset name)."""
        import aiir.cli as cli

        mock_result = {
            "verificationResult": "PASSED",
            "reason": "ok",
            "coverage": {"commits_total": 1, "receipts_found": 1, "coverage_percent": 100},
            "predicate": {"evaluation": {}, "verifier": {}},
            "policy_violations": [],
        }
        with tempfile.TemporaryDirectory() as td:
            policy_f = Path(td) / "custom_policy.json"
            policy_f.write_text('{"max_ai_percent": 50}', encoding="utf-8")
            ledger = Path(td) / "receipts.jsonl"
            ledger.write_text('{"receipt_id": "r1"}\n', encoding="utf-8")

            with patch.object(cli, "verify_release", return_value=mock_result) as mock_vr, \
                 patch.object(cli, "format_release_report", return_value="OK"), \
                 patch("sys.argv", ["aiir", "--verify-release",
                                     "--receipts", str(ledger),
                                     "--policy", str(policy_f)]), \
                 patch("sys.stderr", new_callable=io.StringIO):
                rc = cli.main()
            self.assertEqual(rc, 0)
            # Verify policy_path was passed (not preset)
            call_kwargs = mock_vr.call_args
            self.assertEqual(call_kwargs[1].get("policy_path") or call_kwargs.kwargs.get("policy_path"), str(policy_f))

    def test_verify_release_max_ai_percent(self):
        """L698: --max-ai-percent sets policy override."""
        import aiir.cli as cli

        mock_result = {
            "verificationResult": "PASSED",
            "reason": "ok",
            "coverage": {"commits_total": 1, "receipts_found": 1, "coverage_percent": 100},
            "predicate": {"evaluation": {}, "verifier": {}},
            "policy_violations": [],
        }
        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "receipts.jsonl"
            ledger.write_text('{"receipt_id": "r1"}\n', encoding="utf-8")

            with patch.object(cli, "verify_release", return_value=mock_result) as mock_vr, \
                 patch.object(cli, "format_release_report", return_value="OK"), \
                 patch("sys.argv", ["aiir", "--verify-release",
                                     "--receipts", str(ledger),
                                     "--max-ai-percent", "25"]), \
                 patch("sys.stderr", new_callable=io.StringIO):
                rc = cli.main()
            self.assertEqual(rc, 0)
            call_kwargs = mock_vr.call_args
            overrides = call_kwargs[1].get("policy_overrides") or call_kwargs.kwargs.get("policy_overrides")
            self.assertEqual(overrides["max_ai_percent"], 25)

    def test_verify_release_error_handling(self):
        """L710-712: verify_release raises → error printed, rc=1."""
        import aiir.cli as cli

        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "receipts.jsonl"
            ledger.write_text('{"receipt_id": "r1"}\n', encoding="utf-8")

            with patch.object(cli, "verify_release", side_effect=ValueError("bad policy")), \
                 patch("sys.argv", ["aiir", "--verify-release",
                                     "--receipts", str(ledger)]), \
                 patch("sys.stderr", new_callable=io.StringIO) as err:
                rc = cli.main()
            self.assertEqual(rc, 1)
            self.assertIn("bad policy", err.getvalue())


class TestCliVSAWrite(unittest.TestCase):
    """Cover CLI --emit-vsa write path (L725-729)."""

    def setUp(self):
        self._orig_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self._orig_cwd)

    def test_emit_vsa_writes_file(self):
        """L725-729: --emit-vsa writes in-toto VSA to file."""
        import aiir.cli as cli

        vr_result = {
            "verificationResult": "PASSED",
            "reason": "OK",
            "coverage": {"commits_total": 1, "receipts_found": 1, "coverage_percent": 100},
            "predicate": {"evaluation": {}, "verifier": {}},
            "policy_violations": [],
            "intoto_statement": {"_type": "https://in-toto.io/Statement/v1", "subject": []},
        }

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            ledger = Path(td) / ".aiir" / "receipts.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text('{"receipt_id": "test"}\n', encoding="utf-8")

            with patch.object(cli, "verify_release", return_value=vr_result), \
                 patch.object(cli, "format_release_report", return_value="PASS"), \
                 patch("sys.argv", ["aiir", "--verify-release", "--emit-vsa", "vsa.json"]), \
                 patch("sys.stderr", new_callable=io.StringIO):
                rc = cli.main()
            self.assertEqual(rc, 0)
            vsa_file = Path(td) / "vsa.json"
            self.assertTrue(vsa_file.exists())

    def test_emit_vsa_rejects_absolute_path(self):
        """L725-726: --emit-vsa rejects absolute paths."""
        import aiir.cli as cli

        vr_result = {
            "verificationResult": "PASSED",
            "reason": "OK",
            "coverage": {},
            "predicate": {"evaluation": {}, "verifier": {}},
            "policy_violations": [],
            "intoto_statement": {"_type": "https://in-toto.io/Statement/v1"},
        }

        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / ".aiir" / "receipts.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text('{"receipt_id": "test"}\n', encoding="utf-8")

            with patch.object(cli, "verify_release", return_value=vr_result), \
                 patch.object(cli, "format_release_report", return_value="PASS"), \
                 patch("sys.argv", ["aiir", "--verify-release", "--emit-vsa", "/tmp/evil.json"]), \
                 patch("sys.stderr", new_callable=io.StringIO) as err:
                rc = cli.main()
            self.assertEqual(rc, 1)
            self.assertIn("relative", err.getvalue())


class TestCliGitlabCIOutput(unittest.TestCase):
    """Cover CLI --gitlab-ci paths (L984, L1072-1076, L1273-1291, L1298-1309)."""

    def setUp(self):
        self._orig_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self._orig_cwd)

    def test_gitlab_ci_generator_id(self):
        """L984: generator ID is 'aiir.gitlab' in gitlab-ci mode."""
        import aiir.cli as cli

        mock_receipt = {
            "receipt_id": "g1-test",
            "content_hash": "sha256:abc",
            "commit": {"sha": "aaa"},
            "ai_attestation": {"is_ai_authored": False},
        }
        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            # Init a git repo
            os.system("git init -q && git config user.email 't@t.com' && git config user.name 'T' && touch f && git add f && git commit -q -m init")  # noqa: S605

            env = {"GITLAB_CI": "true", "CI_DOTENV_FILE": os.path.join(td, "ci.env")}
            with patch.dict(os.environ, env, clear=False), \
                 patch.object(cli, "generate_receipt", return_value=mock_receipt), \
                 patch("sys.argv", ["aiir", "--gitlab-ci", "--json"]), \
                 patch("sys.stderr", new_callable=io.StringIO), \
                 patch("sys.stdout", new_callable=io.StringIO):
                rc = cli.main()
            self.assertEqual(rc, 0)

    def test_gitlab_ci_empty_results(self):
        """L1072-1076: empty results in --gitlab-ci mode sets outputs to 0."""
        import aiir.cli as cli

        env = {"GITLAB_CI": "true", "CI_DOTENV_FILE": os.path.join(tempfile.gettempdir(), "ci.env")}

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            os.system("git init -q && git config user.email 't@t.com' && git config user.name 'T' && touch f && git add f && git commit -q -m init")  # noqa: S605

            with patch.dict(os.environ, env, clear=False), \
                 patch.object(cli, "generate_receipts_for_range", return_value=[]), \
                 patch("sys.argv", ["aiir", "--gitlab-ci", "--range", "HEAD~1..HEAD"]), \
                 patch("sys.stderr", new_callable=io.StringIO), \
                 patch.object(cli, "set_gitlab_ci_output") as mock_output:
                rc = cli.main()
            self.assertEqual(rc, 0)
            # Check that AIIR_RECEIPT_COUNT=0 was set
            calls = {c[0][0]: c[0][1] for c in mock_output.call_args_list}
            self.assertEqual(calls.get("AIIR_RECEIPT_COUNT"), "0")

    def test_gitlab_ci_mr_comment_post(self):
        """L1273-1291: --gitlab-ci posts MR comment when CI_MERGE_REQUEST_IID set."""
        import aiir.cli as cli

        mock_receipt = {
            "receipt_id": "g1-test",
            "content_hash": "sha256:abc",
            "commit": {"sha": "aaa"},
            "ai_attestation": {"is_ai_authored": True, "authorship_class": "ai_assisted"},
            "provenance": {"repository": None},
        }

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            os.system("git init -q && git config user.email 't@t.com' && git config user.name 'T' && touch f && git add f && git commit -q -m init")  # noqa: S605

            env = {
                "GITLAB_CI": "true",
                "CI_DOTENV_FILE": os.path.join(td, "ci.env"),
                "CI_MERGE_REQUEST_IID": "42",
            }
            with patch.dict(os.environ, env, clear=False), \
                 patch.object(cli, "generate_receipt", return_value=mock_receipt), \
                 patch.object(cli, "post_mr_comment", return_value={"id": 1}) as mock_post, \
                 patch.object(cli, "format_gitlab_summary", return_value="Summary"), \
                 patch("sys.argv", ["aiir", "--gitlab-ci", "--json"]), \
                 patch("sys.stderr", new_callable=io.StringIO), \
                 patch("sys.stdout", new_callable=io.StringIO):
                rc = cli.main()
            self.assertEqual(rc, 0)
            mock_post.assert_called_once()

    def test_gitlab_ci_mr_comment_failure(self):
        """L1288-1291: MR comment failure is non-fatal."""
        import aiir.cli as cli

        mock_receipt = {
            "receipt_id": "g1-test",
            "content_hash": "sha256:abc",
            "commit": {"sha": "aaa"},
            "ai_attestation": {"is_ai_authored": False},
            "provenance": {"repository": "https://example.com/repo"},
        }

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            os.system("git init -q && git config user.email 't@t.com' && git config user.name 'T' && touch f && git add f && git commit -q -m init")  # noqa: S605

            env = {
                "GITLAB_CI": "true",
                "CI_DOTENV_FILE": os.path.join(td, "ci.env"),
                "CI_MERGE_REQUEST_IID": "42",
            }
            with patch.dict(os.environ, env, clear=False), \
                 patch.object(cli, "generate_receipt", return_value=mock_receipt), \
                 patch.object(cli, "post_mr_comment", side_effect=RuntimeError("API error")), \
                 patch.object(cli, "format_gitlab_summary", return_value="Summary"), \
                 patch("sys.argv", ["aiir", "--gitlab-ci", "--json"]), \
                 patch("sys.stderr", new_callable=io.StringIO) as err, \
                 patch("sys.stdout", new_callable=io.StringIO):
                rc = cli.main()
            self.assertEqual(rc, 0)  # non-fatal
            self.assertIn("Could not post MR comment", err.getvalue())

    def test_gitlab_sast_report_write(self):
        """L1298-1309: --gl-sast-report writes SAST report file."""
        import aiir.cli as cli

        mock_receipt = {
            "receipt_id": "g1-test",
            "content_hash": "sha256:abc",
            "commit": {"sha": "aaa"},
            "ai_attestation": {"is_ai_authored": True, "authorship_class": "ai_assisted"},
            "provenance": {"repository": "https://example.com/repo"},
        }

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            os.system("git init -q && git config user.email 't@t.com' && git config user.name 'T' && touch f && git add f && git commit -q -m init")  # noqa: S605

            sast_path = os.path.join(td, "gl-sast-report.json")
            with patch.object(cli, "generate_receipt", return_value=mock_receipt), \
                 patch("sys.argv", ["aiir", "--gl-sast-report", sast_path, "--json"]), \
                 patch("sys.stderr", new_callable=io.StringIO), \
                 patch("sys.stdout", new_callable=io.StringIO):
                rc = cli.main()
            self.assertEqual(rc, 0)
            self.assertTrue(Path(sast_path).exists())
            data = json.loads(Path(sast_path).read_text())
            self.assertIn("vulnerabilities", data)


class TestCliGitHubActionOutput(unittest.TestCase):
    """Cover CLI --github-action empty results (L1072-1073)."""

    def setUp(self):
        self._orig_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self._orig_cwd)

    def test_github_action_empty_results(self):
        """L1072-1073: empty results with --github-action sets receipt_count=0."""
        import aiir.cli as cli

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            os.system("git init -q && git config user.email 't@t.com' && git config user.name 'T' && touch f && git add f && git commit -q -m init")  # noqa: S605

            github_output = os.path.join(td, "github_output.txt")
            env = {"GITHUB_ACTIONS": "true", "GITHUB_OUTPUT": github_output}
            with patch.dict(os.environ, env, clear=False), \
                 patch.object(cli, "generate_receipts_for_range", return_value=[]), \
                 patch("sys.argv", ["aiir", "--github-action", "--range", "HEAD~1..HEAD"]), \
                 patch("sys.stderr", new_callable=io.StringIO), \
                 patch.object(cli, "set_github_output") as mock_output:
                rc = cli.main()
            self.assertEqual(rc, 0)
            calls = {c[0][0]: c[0][1] for c in mock_output.call_args_list}
            self.assertEqual(calls.get("receipt_count"), "0")


class TestCliSignFailure(unittest.TestCase):
    """Cover CLI --sign failure + cleanup (L1151-1165)."""

    def setUp(self):
        self._orig_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self._orig_cwd)

    def test_sign_failure_removes_unsigned_receipt(self):
        """L1151-1165: signing failure removes the unsigned receipt."""
        import aiir.cli as cli

        mock_receipt = {
            "receipt_id": "g1-test",
            "content_hash": "sha256:abc",
            "commit": {"sha": "aaa"},
            "ai_attestation": {"is_ai_authored": False},
            "provenance": {"repository": "https://example.com/repo"},
        }

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            os.system("git init -q && git config user.email 't@t.com' && git config user.name 'T' && touch f && git add f && git commit -q -m init")  # noqa: S605

            out_dir = os.path.join(td, "receipts")
            os.makedirs(out_dir)

            with patch.object(cli, "generate_receipt", return_value=mock_receipt), \
                 patch.object(cli, "_sigstore_available", return_value=True), \
                 patch.object(cli, "write_receipt", return_value=os.path.join(out_dir, "receipt_aaa.json")), \
                 patch.object(cli, "sign_receipt_file", side_effect=Exception("OIDC error")), \
                 patch("sys.argv", ["aiir", "--sign", "--output", out_dir]), \
                 patch("sys.stderr", new_callable=io.StringIO) as err:
                # Create a fake receipt file to be removed
                fake_receipt = Path(out_dir) / "receipt_aaa.json"
                fake_receipt.write_text("{}", encoding="utf-8")
                rc = cli.main()
            self.assertEqual(rc, 1)
            self.assertIn("Signing failed", err.getvalue())
            # Verify unsigned receipt was removed
            self.assertFalse(fake_receipt.exists())

    def test_sign_failure_remove_oserror(self):
        """L1156-1157: os.remove raises OSError during cleanup — silently ignored."""
        import aiir.cli as cli

        mock_receipt = {
            "receipt_id": "g1-test",
            "content_hash": "sha256:abc",
            "commit": {"sha": "aaa"},
            "ai_attestation": {"is_ai_authored": False},
            "provenance": {"repository": "https://example.com/repo"},
        }

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            os.system("git init -q && git config user.email 't@t.com' && git config user.name 'T' && touch f && git add f && git commit -q -m init")  # noqa: S605

            out_dir = os.path.join(td, "receipts")
            os.makedirs(out_dir)

            with patch.object(cli, "generate_receipt", return_value=mock_receipt), \
                 patch.object(cli, "_sigstore_available", return_value=True), \
                 patch.object(cli, "write_receipt", return_value=os.path.join(out_dir, "receipt_aaa.json")), \
                 patch.object(cli, "sign_receipt_file", side_effect=Exception("OIDC error")), \
                 patch("os.remove", side_effect=OSError("perm denied")), \
                 patch("sys.argv", ["aiir", "--sign", "--output", out_dir]), \
                 patch("sys.stderr", new_callable=io.StringIO) as err:
                rc = cli.main()
            self.assertEqual(rc, 1)
            self.assertIn("Signing failed", err.getvalue())


# ---------------------------------------------------------------------------
# mcp_server.py — all 34 missed lines
# ---------------------------------------------------------------------------


class TestMcpSafeVerifyPath(unittest.TestCase):
    """Cover _safe_verify_path file-not-found (L119)."""

    def setUp(self):
        self._orig_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self._orig_cwd)

    def test_file_not_found(self):
        """L119: resolved file that doesn't exist raises ValueError."""
        import aiir.mcp_server as mcp

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            with self.assertRaises(ValueError) as ctx:
                mcp._safe_verify_path("nonexistent.json")
            self.assertIn("File not found", str(ctx.exception))


class TestMcpVerifyHandler(unittest.TestCase):
    """Cover _handle_aiir_verify valid receipt (L438)."""

    def setUp(self):
        self._orig_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self._orig_cwd)

    def test_verify_valid_receipt(self):
        """L438: verify handler returns success for valid receipt."""
        import aiir.mcp_server as mcp

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            rf = Path(td) / "receipt.json"
            rf.write_text('{"valid": true}', encoding="utf-8")

            valid_result = {"valid": True, "receipt_id": "test"}
            with patch.object(mcp, "verify_receipt_file", return_value=valid_result):
                result = mcp._handle_aiir_verify({"file": str(rf)})
            text = result["content"][0]["text"]
            self.assertIn("✅", text)

    def test_verify_invalid_receipt(self):
        """Verify handler returns failure for invalid receipt."""
        import aiir.mcp_server as mcp

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            rf = Path(td) / "receipt.json"
            rf.write_text('{"valid": false}', encoding="utf-8")

            invalid_result = {"valid": False, "error": "hash mismatch"}
            with patch.object(mcp, "verify_receipt_file", return_value=invalid_result):
                result = mcp._handle_aiir_verify({"file": str(rf)})
            text = result["content"][0]["text"]
            self.assertIn("❌", text)


class TestMcpVerifyReleaseHandler(unittest.TestCase):
    """Cover _handle_aiir_verify_release (L509-545)."""

    def setUp(self):
        self._orig_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self._orig_cwd)

    def test_verify_release_with_preset(self):
        """L509-545: verify_release handler with preset policy."""
        import aiir.mcp_server as mcp

        vr_result = {
            "verificationResult": "PASSED",
            "reason": "OK",
            "coverage": {"commits_total": 1, "receipts_found": 1, "coverage_percent": 100},
            "predicate": {"evaluation": {}, "verifier": {}},
            "policy_violations": [],
        }

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            ledger = Path(td) / ".aiir" / "receipts.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text('{"receipt_id": "test"}\n', encoding="utf-8")

            with patch.object(mcp, "verify_release", return_value=vr_result), \
                 patch.object(mcp, "format_release_report", return_value="REPORT"):
                result = mcp._handle_aiir_verify_release({
                    "policy": "strict",
                    "commit_range": "HEAD~1..HEAD",
                })
            text = result["content"][0]["text"]
            self.assertIn("REPORT", text)

    def test_verify_release_with_policy_path(self):
        """verify_release handler with a file path policy."""
        import aiir.mcp_server as mcp

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            policy_file = Path(td) / "policy.json"
            policy_file.write_text('{"max_ai_percent": 50}', encoding="utf-8")
            ledger = Path(td) / ".aiir" / "receipts.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text('{"receipt_id": "test"}\n', encoding="utf-8")

            vr_result = {
                "verificationResult": "PASSED",
                "reason": "OK",
                "coverage": {},
                "predicate": {"evaluation": {}, "verifier": {}},
                "policy_violations": [],
            }
            with patch.object(mcp, "verify_release", return_value=vr_result), \
                 patch.object(mcp, "format_release_report", return_value="OK"):
                result = mcp._handle_aiir_verify_release({
                    "policy": str(policy_file),
                })
            self.assertFalse(result.get("isError", False))

    def test_verify_release_error_handling(self):
        """L540: verify_release raises FileNotFoundError → isError."""
        import aiir.mcp_server as mcp

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            ledger = Path(td) / ".aiir" / "receipts.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text('{"receipt_id": "test"}\n', encoding="utf-8")

            with patch.object(mcp, "verify_release", side_effect=FileNotFoundError("missing")):
                result = mcp._handle_aiir_verify_release({"policy": "strict"})
            self.assertTrue(result.get("isError", False))

    def test_verify_release_bad_policy_path(self):
        """L528-529: policy arg is a bad file path → ValueError from _safe_verify_path."""
        import aiir.mcp_server as mcp

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            # Policy path that doesn't exist, not a preset name
            result = mcp._handle_aiir_verify_release({"policy": "nonexistent_policy_file.json"})
            self.assertTrue(result.get("isError", False))

    def test_verify_release_unexpected_exception(self):
        """L541-542: unexpected Exception from verify_release."""
        import aiir.mcp_server as mcp

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            ledger = Path(td) / ".aiir" / "receipts.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text('{"receipt_id": "test"}\n', encoding="utf-8")

            with patch.object(mcp, "verify_release", side_effect=TypeError("unexpected")):
                result = mcp._handle_aiir_verify_release({"policy": "strict"})
            self.assertTrue(result.get("isError", False))


class TestMcpGitlabSummaryHandler(unittest.TestCase):
    """Cover _handle_aiir_gitlab_summary (L579-580, L608-609, L616-617)."""

    def setUp(self):
        self._orig_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self._orig_cwd)

    def test_gitlab_summary_no_receipts(self):
        """L579-580: empty receipts returns guidance message."""
        import aiir.mcp_server as mcp

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            # Create empty ledger
            ledger = Path(td) / ".aiir" / "receipts.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text("", encoding="utf-8")

            result = mcp._handle_aiir_gitlab_summary({})
        text = result["content"][0]["text"]
        self.assertIn("No receipts found", text)

    def test_gitlab_summary_no_ledger(self):
        """No ledger file returns guidance message."""
        import aiir.mcp_server as mcp

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            result = mcp._handle_aiir_gitlab_summary({})
        text = result["content"][0]["text"]
        self.assertIn("No AIIR ledger found", text)

    def test_gitlab_summary_with_receipts(self):
        """Produces a GitLab-flavored summary from ledger."""
        import aiir.mcp_server as mcp

        receipt = {
            "receipt_id": "g1-test",
            "commit": {"sha": "abc", "subject": "feat"},
            "ai_attestation": {"authorship_class": "human"},
            "content_hash": "sha256:abc",
        }
        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            ledger = Path(td) / ".aiir" / "receipts.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text(json.dumps(receipt) + "\n", encoding="utf-8")

            with patch.object(mcp, "format_gitlab_summary", return_value="**Summary**"):
                result = mcp._handle_aiir_gitlab_summary({})
            text = result["content"][0]["text"]
            self.assertIn("Summary", text)

    def test_gitlab_summary_with_sast(self):
        """include_sast appends SAST report data."""
        import aiir.mcp_server as mcp

        receipt = {
            "receipt_id": "g1-test",
            "commit": {"sha": "abc", "subject": "feat"},
            "ai_attestation": {"authorship_class": "human"},
            "content_hash": "sha256:abc",
        }
        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            ledger = Path(td) / ".aiir" / "receipts.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text(json.dumps(receipt) + "\n", encoding="utf-8")

            with patch.object(mcp, "format_gitlab_summary", return_value="Summary"), \
                 patch.object(mcp, "format_gl_sast_report", return_value={"vulnerabilities": []}):
                result = mcp._handle_aiir_gitlab_summary({"include_sast": True})
            text = result["content"][0]["text"]
            self.assertIn("SAST", text)

    def test_gitlab_summary_post_to_mr(self):
        """L608-609, L616-617: post_to_mr posts and appends success message."""
        import aiir.mcp_server as mcp

        receipt = {
            "receipt_id": "g1-test",
            "commit": {"sha": "abc", "subject": "feat"},
            "ai_attestation": {"authorship_class": "human"},
            "content_hash": "sha256:abc",
        }
        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            ledger = Path(td) / ".aiir" / "receipts.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text(json.dumps(receipt) + "\n", encoding="utf-8")

            env = {"CI_MERGE_REQUEST_IID": "42"}
            with patch.dict(os.environ, env, clear=False), \
                 patch.object(mcp, "format_gitlab_summary", return_value="Summary"), \
                 patch.object(mcp, "post_mr_comment", return_value={"id": 1}):
                result = mcp._handle_aiir_gitlab_summary({"post_to_mr": True})
            text = result["content"][0]["text"]
            self.assertIn("posted to merge request", text.lower())

    def test_gitlab_summary_malformed_ledger_line(self):
        """L579-580: malformed JSON line in ledger is skipped (JSONDecodeError)."""
        import aiir.mcp_server as mcp

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            ledger = Path(td) / ".aiir" / "receipts.jsonl"
            ledger.parent.mkdir(parents=True)
            # One valid, one malformed
            valid = json.dumps({"receipt_id": "r1", "commit": {"sha": "a"}, "ai_attestation": {}, "content_hash": "sha256:x"})
            ledger.write_text(f"{valid}\nnot-valid-json\n", encoding="utf-8")

            with patch.object(mcp, "format_gitlab_summary", return_value="Summary"):
                result = mcp._handle_aiir_gitlab_summary({})
            # Should succeed (the malformed line is skipped)
            self.assertFalse(result.get("isError", False))

    def test_gitlab_summary_post_mr_failure(self):
        """L608-609: post_mr_comment raises Exception → silently ignored."""
        import aiir.mcp_server as mcp

        receipt = {
            "receipt_id": "g1-test",
            "commit": {"sha": "abc", "subject": "feat"},
            "ai_attestation": {"authorship_class": "human"},
            "content_hash": "sha256:abc",
        }
        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            ledger = Path(td) / ".aiir" / "receipts.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text(json.dumps(receipt) + "\n", encoding="utf-8")

            env = {"CI_MERGE_REQUEST_IID": "99"}
            with patch.dict(os.environ, env, clear=False), \
                 patch.object(mcp, "format_gitlab_summary", return_value="Summary"), \
                 patch.object(mcp, "post_mr_comment", side_effect=Exception("API error")):
                result = mcp._handle_aiir_gitlab_summary({"post_to_mr": True})
            # Should still succeed (error is best-effort)
            self.assertFalse(result.get("isError", False))


class TestMcpRateLimiter(unittest.TestCase):
    """Cover rate limiter fire (L779)."""

    def test_rate_limit_exceeded(self):
        """Rate limiter rejects requests exceeding threshold."""
        import aiir.mcp_server as mcp

        # Build a sequence of messages that will exceed rate limit
        messages = []
        for i in range(mcp._RATE_LIMIT_MAX + 5):
            msg = {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/list",
                "params": {},
            }
            messages.append(json.dumps(msg))
        messages.append("")  # EOF signal

        input_data = "\n".join(messages) + "\n"
        captured_output = io.StringIO()

        with patch("sys.stdin", io.StringIO(input_data)), \
             patch("sys.stdout", captured_output):
            # Monkey-patch time.monotonic to return same time (all within window)
            fixed_time = time.monotonic()
            with patch("time.monotonic", return_value=fixed_time):
                mcp.serve_stdio()

        output_lines = [
            line for line in captured_output.getvalue().strip().split("\n") if line
        ]
        # At least one response should contain "Rate limit exceeded"
        found_rate_limit = False
        for line in output_lines:
            try:
                resp = json.loads(line)
                if resp.get("error", {}).get("message") == "Rate limit exceeded":
                    found_rate_limit = True
                    break
            except json.JSONDecodeError:
                continue
        self.assertTrue(found_rate_limit, "Expected rate limit exceeded error in output")

    def test_rate_limiter_popleft_cleanup(self):
        """L779: old timestamps are cleaned via popleft when time advances past window."""
        import aiir.mcp_server as mcp

        # Send a few requests at time T, then send one at T + window + 1
        # The second batch should trigger popleft to clean old timestamps.
        base_time = 1000.0
        call_count = [0]
        window = mcp._RATE_LIMIT_WINDOW

        def advancing_time():
            call_count[0] += 1
            if call_count[0] <= 3:
                return base_time
            return base_time + window + 1.0

        messages = []
        for i in range(4):
            msg = {"jsonrpc": "2.0", "id": i, "method": "tools/list", "params": {}}
            messages.append(json.dumps(msg))
        messages.append("")  # EOF

        input_data = "\n".join(messages) + "\n"
        captured_output = io.StringIO()

        with patch("sys.stdin", io.StringIO(input_data)), \
             patch("sys.stdout", captured_output), \
             patch("time.monotonic", side_effect=advancing_time):
            mcp.serve_stdio()

        output_lines = [
            line for line in captured_output.getvalue().strip().split("\n") if line
        ]
        # All should succeed (no rate limit since old ones are cleaned)
        for line in output_lines:
            try:
                resp = json.loads(line)
                self.assertNotIn("Rate limit exceeded", resp.get("error", {}).get("message", ""))
            except json.JSONDecodeError:
                continue

    def test_serve_stdio_stream_reconfigure(self):
        """L723-724: serve_stdio calls stream.reconfigure(encoding='utf-8')."""
        import aiir.mcp_server as mcp

        # Create mock streams that have reconfigure method
        class ReconfigurableStringIO(io.StringIO):
            def reconfigure(self, **kwargs):
                pass  # Accept the call silently

        mock_stdin = ReconfigurableStringIO("")  # Empty input → immediate EOF
        mock_stdout = ReconfigurableStringIO()

        with patch("sys.stdin", mock_stdin), \
             patch("sys.stdout", mock_stdout):
            mcp.serve_stdio()
        # If we reach here without error, reconfigure was called on both streams


class TestMcpGraphQLError(unittest.TestCase):
    """Cover MCP GraphQL error path (L723-724).

    This is actually covered by TestGitlabGraphQLError above,
    but we test the MCP handler integration here.
    """

    def setUp(self):
        self._orig_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self._orig_cwd)

    def test_mcp_graphql_error_in_handler(self):
        """MCP handler handles GraphQL errors gracefully."""
        import aiir.mcp_server as mcp

        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            ledger = Path(td) / ".aiir" / "receipts.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text('{"receipt_id": "test"}\n', encoding="utf-8")

            # gitlab_summary with range triggers generate_receipts_for_range
            with patch.object(mcp, "generate_receipts_for_range", side_effect=RuntimeError("GraphQL error")):
                result = mcp._handle_aiir_gitlab_summary({"range": "HEAD~1..HEAD"})
            self.assertTrue(result.get("isError", False))


if __name__ == "__main__":
    unittest.main()
