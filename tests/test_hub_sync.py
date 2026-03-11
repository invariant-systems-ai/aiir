"""Tests for aiir._hub_sync — Hub push/sync with mocked HTTP.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import io
import json
import urllib.error
from unittest import mock

import pytest

from aiir import _hub_sync


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    """Ensure clean env and cwd for every test."""
    monkeypatch.delenv("AIIR_HUB_URL", raising=False)
    monkeypatch.delenv("AIIR_HUB_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)


@pytest.fixture()
def hub_env(monkeypatch):
    """Set Hub env vars for authenticated tests."""
    monkeypatch.setenv("AIIR_HUB_URL", "https://hub.example.com")
    monkeypatch.setenv("AIIR_HUB_TOKEN", "tok-test-123")


def _mock_response(body: dict | str, status: int = 200):
    """Build a mock urllib response object."""
    raw = json.dumps(body).encode() if isinstance(body, dict) else body.encode()
    resp = mock.MagicMock()
    resp.status = status
    resp.read.return_value = raw
    resp.__enter__ = mock.MagicMock(return_value=resp)
    resp.__exit__ = mock.MagicMock(return_value=False)
    return resp


def _mock_http_error(status: int, body: str = ""):
    err = urllib.error.HTTPError(
        url="https://hub.example.com/v1/test",
        code=status,
        msg="error",
        hdrs=None,  # type: ignore[arg-type]
        fp=io.BytesIO(body.encode()),
    )
    return err


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


class TestConfig:
    def test_default_hub_url(self):
        assert _hub_sync._hub_url() == "https://hub.invariantsystems.io"

    def test_custom_hub_url(self, monkeypatch):
        monkeypatch.setenv("AIIR_HUB_URL", "https://custom.example.com/")
        assert _hub_sync._hub_url() == "https://custom.example.com"

    def test_hub_token_empty(self):
        assert _hub_sync._hub_token() == ""

    def test_hub_token_set(self, monkeypatch):
        monkeypatch.setenv("AIIR_HUB_TOKEN", "abc")
        assert _hub_sync._hub_token() == "abc"


# ---------------------------------------------------------------------------
# Sync state
# ---------------------------------------------------------------------------


class TestSyncState:
    def test_load_synced_ids_no_file(self):
        assert _hub_sync._load_synced_ids() == set()

    def test_load_synced_ids_with_data(self, tmp_path):
        state_dir = tmp_path / ".aiir"
        state_dir.mkdir()
        state_file = state_dir / "hub_sync.jsonl"
        state_file.write_text(
            '{"receipt_id":"r1","synced_at":"2026-01-01T00:00:00Z"}\n'
            '{"receipt_id":"r2","synced_at":"2026-01-01T00:00:00Z"}\n'
            '{"no_receipt_id":"x"}\n'
            "\n"
            "not-valid-json\n"
        )
        ids = _hub_sync._load_synced_ids()
        assert ids == {"r1", "r2"}

    def test_mark_synced_creates_dir(self, tmp_path):
        _hub_sync._mark_synced(["r-new"])
        state_file = tmp_path / ".aiir" / "hub_sync.jsonl"
        assert state_file.exists()
        records = [
            json.loads(line)
            for line in state_file.read_text().splitlines()
            if line.strip()
        ]
        assert len(records) == 1
        assert records[0]["receipt_id"] == "r-new"
        assert "synced_at" in records[0]


# ---------------------------------------------------------------------------
# _api_request
# ---------------------------------------------------------------------------


class TestApiRequest:
    def test_scheme_validation_rejects_file(self, monkeypatch):
        monkeypatch.setenv("AIIR_HUB_URL", "file:///etc/passwd")
        result = _hub_sync._api_request("GET", "/v1/health")
        assert not result["ok"]
        assert "scheme" in result["body"].lower()

    def test_scheme_validation_rejects_ftp(self, monkeypatch):
        monkeypatch.setenv("AIIR_HUB_URL", "ftp://evil.com")
        result = _hub_sync._api_request("GET", "/v1/health")
        assert not result["ok"]

    @mock.patch("aiir._hub_sync.urllib.request.urlopen")
    def test_get_success(self, mock_urlopen, hub_env):
        mock_urlopen.return_value = _mock_response({"status": "ok"})
        result = _hub_sync._api_request("GET", "/v1/health")
        assert result["ok"]
        assert result["status"] == 200
        assert result["body"] == {"status": "ok"}

    @mock.patch("aiir._hub_sync.urllib.request.urlopen")
    def test_get_non_json_body(self, mock_urlopen, hub_env):
        resp = (
            _mock_response.__wrapped__({"x": 1})
            if hasattr(_mock_response, "__wrapped__")
            else _mock_response("plain text")
        )
        mock_urlopen.return_value = resp
        result = _hub_sync._api_request("GET", "/v1/health")
        assert result["ok"]
        assert result["body"] == "plain text"

    @mock.patch("aiir._hub_sync.urllib.request.urlopen")
    def test_http_error(self, mock_urlopen, hub_env):
        mock_urlopen.side_effect = _mock_http_error(401, '{"error":"unauthorized"}')
        result = _hub_sync._api_request("GET", "/v1/health")
        assert not result["ok"]
        assert result["status"] == 401
        assert result["body"] == {"error": "unauthorized"}

    @mock.patch("aiir._hub_sync.urllib.request.urlopen")
    def test_http_error_non_json(self, mock_urlopen, hub_env):
        mock_urlopen.side_effect = _mock_http_error(500, "Internal Server Error")
        result = _hub_sync._api_request("GET", "/v1/health")
        assert not result["ok"]
        assert result["status"] == 500
        assert result["body"] == "Internal Server Error"

    @mock.patch("aiir._hub_sync.urllib.request.urlopen")
    def test_http_error_unreadable(self, mock_urlopen, hub_env):
        err = _mock_http_error(503, "")
        err.read = mock.MagicMock(side_effect=OSError("read failed"))
        mock_urlopen.side_effect = err
        result = _hub_sync._api_request("GET", "/v1/health")
        assert not result["ok"]
        assert result["status"] == 503

    @mock.patch("aiir._hub_sync.urllib.request.urlopen")
    def test_url_error(self, mock_urlopen, hub_env):
        mock_urlopen.side_effect = urllib.error.URLError("DNS failed")
        result = _hub_sync._api_request("GET", "/v1/health")
        assert not result["ok"]
        assert result["status"] == 0
        assert "DNS failed" in result["body"]

    @mock.patch("aiir._hub_sync.urllib.request.urlopen")
    def test_auth_header_set(self, mock_urlopen, hub_env):
        mock_urlopen.return_value = _mock_response({"ok": True})
        _hub_sync._api_request("GET", "/v1/test")
        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Authorization") == "Bearer tok-test-123"

    @mock.patch("aiir._hub_sync.urllib.request.urlopen")
    def test_no_auth_header_without_token(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"ok": True})
        _hub_sync._api_request("GET", "/v1/test")
        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Authorization") is None


# ---------------------------------------------------------------------------
# hub_status
# ---------------------------------------------------------------------------


class TestHubStatus:
    @mock.patch("aiir._hub_sync._api_request")
    def test_status_ok_anonymous(self, mock_api):
        mock_api.return_value = {"ok": True, "status": 200, "body": {"service": "hub"}}
        result = _hub_sync.hub_status()
        assert result["ok"]
        assert not result["authenticated"]

    @mock.patch("aiir._hub_sync._api_request")
    def test_status_ok_authenticated(self, mock_api, hub_env):
        mock_api.side_effect = [
            {"ok": True, "status": 200, "body": {"service": "hub"}},
            {"ok": True, "status": 404, "body": "not found"},
        ]
        result = _hub_sync.hub_status()
        assert result["ok"]
        assert result["authenticated"]

    @mock.patch("aiir._hub_sync._api_request")
    def test_status_ok_bad_token(self, mock_api, hub_env):
        mock_api.side_effect = [
            {"ok": True, "status": 200, "body": {"service": "hub"}},
            {"ok": False, "status": 401, "body": "unauthorized"},
        ]
        result = _hub_sync.hub_status()
        assert result["ok"]
        assert not result["authenticated"]

    @mock.patch("aiir._hub_sync._api_request")
    def test_status_unreachable(self, mock_api):
        mock_api.return_value = {"ok": False, "status": 0, "body": "connection refused"}
        result = _hub_sync.hub_status()
        assert not result["ok"]


# ---------------------------------------------------------------------------
# hub_push
# ---------------------------------------------------------------------------


class TestHubPush:
    def test_push_no_token(self):
        result = _hub_sync.hub_push([{"receipt_id": "r1"}])
        assert not result["ok"]
        assert "TOKEN" in result["error"]

    @mock.patch("aiir._hub_sync._api_request")
    def test_push_success(self, mock_api, hub_env):
        mock_api.return_value = {
            "ok": True,
            "status": 200,
            "body": {
                "results": [{"ok": True, "receipt_id": "r1", "status": "verified"}],
                "verified": 1,
                "failed": 0,
            },
        }
        result = _hub_sync.hub_push([{"receipt_id": "r1"}])
        assert result["ok"]
        assert result["verified"] == 1
        assert result["failed"] == 0

    @mock.patch("aiir._hub_sync._api_request")
    def test_push_batch_failure(self, mock_api, hub_env):
        mock_api.return_value = {"ok": False, "status": 500, "body": "internal error"}
        result = _hub_sync.hub_push([{"receipt_id": "r1"}])
        assert not result["ok"]
        assert result["failed"] == 1


# ---------------------------------------------------------------------------
# hub_push_from_ledger
# ---------------------------------------------------------------------------


class TestHubPushFromLedger:
    def test_no_ledger(self, hub_env):
        result = _hub_sync.hub_push_from_ledger()
        assert result["ok"]
        assert result["pushed"] == 0

    def test_empty_ledger(self, hub_env, tmp_path):
        ledger = tmp_path / ".aiir" / "receipts.jsonl"
        ledger.parent.mkdir(parents=True)
        ledger.write_text("\n\n")
        result = _hub_sync.hub_push_from_ledger()
        assert result["ok"]
        assert result["pushed"] == 0

    @mock.patch("aiir._hub_sync._api_request")
    def test_push_new_receipts(self, mock_api, hub_env, tmp_path):
        ledger = tmp_path / ".aiir" / "receipts.jsonl"
        ledger.parent.mkdir(parents=True)
        ledger.write_text('{"receipt_id":"r1","data":"x"}\n')

        mock_api.return_value = {
            "ok": True,
            "status": 200,
            "body": {
                "results": [{"ok": True, "receipt_id": "r1"}],
                "verified": 1,
                "failed": 0,
            },
        }
        result = _hub_sync.hub_push_from_ledger()
        assert result["ok"]
        assert result["pushed"] == 1

        # Verify sync state was recorded
        sync_file = tmp_path / ".aiir" / "hub_sync.jsonl"
        assert sync_file.exists()

    @mock.patch("aiir._hub_sync._api_request")
    def test_skip_already_synced(self, mock_api, hub_env, tmp_path):
        ledger = tmp_path / ".aiir" / "receipts.jsonl"
        ledger.parent.mkdir(parents=True)
        ledger.write_text('{"receipt_id":"r1"}\n')

        sync_file = tmp_path / ".aiir" / "hub_sync.jsonl"
        sync_file.write_text('{"receipt_id":"r1","synced_at":"2026-01-01T00:00:00Z"}\n')

        result = _hub_sync.hub_push_from_ledger()
        assert result["ok"]
        assert result["pushed"] == 0
        assert result["skipped"] == 1
        mock_api.assert_not_called()

    @mock.patch("aiir._hub_sync._api_request")
    def test_push_with_failures(self, mock_api, hub_env, tmp_path):
        ledger = tmp_path / ".aiir" / "receipts.jsonl"
        ledger.parent.mkdir(parents=True)
        ledger.write_text('{"receipt_id":"r1"}\n')

        mock_api.return_value = {
            "ok": False,
            "status": 200,
            "body": {
                "results": [
                    {"ok": False, "receipt_id": "r1", "errors": ["invalid format"]}
                ],
                "verified": 0,
                "failed": 1,
            },
        }
        result = _hub_sync.hub_push_from_ledger()
        assert not result["ok"]
        assert result["pushed"] == 0

    @mock.patch("aiir._hub_sync._api_request")
    def test_ledger_with_bad_json_lines(self, mock_api, hub_env, tmp_path):
        ledger = tmp_path / ".aiir" / "receipts.jsonl"
        ledger.parent.mkdir(parents=True)
        ledger.write_text('{"receipt_id":"r1"}\nnot-json\n')

        mock_api.return_value = {
            "ok": True,
            "status": 200,
            "body": {
                "results": [{"ok": True, "receipt_id": "r1"}],
                "verified": 1,
                "failed": 0,
            },
        }
        result = _hub_sync.hub_push_from_ledger()
        assert result["ok"]
        assert result["pushed"] == 1


# ---------------------------------------------------------------------------
# hub_cli
# ---------------------------------------------------------------------------


class TestHubCli:
    def test_help(self, capsys):
        assert _hub_sync.hub_cli([]) == 0
        out = capsys.readouterr().out
        assert "usage:" in out

    def test_help_flag(self, capsys):
        assert _hub_sync.hub_cli(["--help"]) == 0

    def test_unknown_subcommand(self, capsys):
        assert _hub_sync.hub_cli(["bogus"]) == 1
        err = capsys.readouterr().err
        assert "unknown" in err

    @mock.patch("aiir._hub_sync.hub_status")
    def test_status_ok_with_service(self, mock_status, capsys, hub_env):
        mock_status.return_value = {
            "ok": True,
            "hub_url": "https://hub.example.com",
            "authenticated": True,
            "detail": {"service": "hub", "api_version": "1"},
        }
        assert _hub_sync.hub_cli(["status"]) == 0
        out = capsys.readouterr().out
        assert "authenticated" in out
        assert "service: hub" in out

    @mock.patch("aiir._hub_sync.hub_status")
    def test_status_ok_anonymous(self, mock_status, capsys, hub_env):
        mock_status.return_value = {
            "ok": True,
            "hub_url": "https://hub.example.com",
            "authenticated": False,
            "detail": "ok",
        }
        assert _hub_sync.hub_cli(["status"]) == 0
        out = capsys.readouterr().out
        assert "anonymous" in out

    @mock.patch("aiir._hub_sync.hub_status")
    def test_status_ok_no_service(self, mock_status, capsys, hub_env):
        mock_status.return_value = {
            "ok": True,
            "hub_url": "https://hub.example.com",
            "authenticated": True,
            "detail": {"service": "", "api_version": "1"},
        }
        assert _hub_sync.hub_cli(["status"]) == 0
        out = capsys.readouterr().out
        assert "service:" not in out

    @mock.patch("aiir._hub_sync.hub_status")
    def test_status_unreachable(self, mock_status, capsys, hub_env):
        mock_status.return_value = {
            "ok": False,
            "hub_url": "https://hub.example.com",
            "authenticated": False,
            "detail": "connection refused",
        }
        assert _hub_sync.hub_cli(["status"]) == 1
        err = capsys.readouterr().err
        assert "unreachable" in err

    def test_sync_no_token(self, capsys):
        assert _hub_sync.hub_cli(["sync"]) == 1
        err = capsys.readouterr().err
        assert "TOKEN" in err

    @mock.patch("aiir._hub_sync.hub_push_from_ledger")
    def test_sync_ok(self, mock_ledger, capsys, hub_env):
        mock_ledger.return_value = {"ok": True, "pushed": 2, "skipped": 0, "errors": []}
        assert _hub_sync.hub_cli(["sync"]) == 0
        out = capsys.readouterr().out
        assert "pushed: 2" in out

    @mock.patch("aiir._hub_sync.hub_push_from_ledger")
    def test_sync_with_errors(self, mock_ledger, capsys, hub_env):
        mock_ledger.return_value = {
            "ok": False,
            "pushed": 0,
            "skipped": 0,
            "errors": ["bad receipt"],
        }
        assert _hub_sync.hub_cli(["sync"]) == 1

    def test_push_no_args(self, capsys, hub_env):
        assert _hub_sync.hub_cli(["push"]) == 1

    def test_push_no_token(self, capsys):
        assert _hub_sync.hub_cli(["push", "file.json"]) == 1

    @mock.patch("aiir._hub_sync.hub_push")
    def test_push_file(self, mock_push, capsys, hub_env, tmp_path):
        receipt_file = tmp_path / "r.json"
        receipt_file.write_text('{"receipt_id":"r1"}')
        mock_push.return_value = {
            "ok": True,
            "total": 1,
            "verified": 1,
            "failed": 0,
            "results": [{"ok": True, "receipt_id": "r1"}],
        }
        assert _hub_sync.hub_cli(["push", str(receipt_file)]) == 0

    @mock.patch("aiir._hub_sync.hub_push")
    def test_push_file_list(self, mock_push, capsys, hub_env, tmp_path):
        receipt_file = tmp_path / "rlist.json"
        receipt_file.write_text('[{"receipt_id":"r1"},{"receipt_id":"r2"}]')
        mock_push.return_value = {
            "ok": True,
            "total": 2,
            "verified": 2,
            "failed": 0,
            "results": [
                {"ok": True, "receipt_id": "r1"},
                {"ok": True, "receipt_id": "r2"},
            ],
        }
        assert _hub_sync.hub_cli(["push", str(receipt_file)]) == 0

    def test_push_missing_file(self, capsys, hub_env):
        assert _hub_sync.hub_cli(["push", "/nonexistent/file.json"]) == 0
        out = capsys.readouterr().out
        assert "no valid receipts" in out

    def test_push_invalid_json(self, capsys, hub_env, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        assert _hub_sync.hub_cli(["push", str(bad)]) == 0

    def test_push_scalar_json(self, capsys, hub_env, tmp_path):
        scalar = tmp_path / "scalar.json"
        scalar.write_text('"just a string"')
        assert _hub_sync.hub_cli(["push", str(scalar)]) == 0
        out = capsys.readouterr().out
        assert "no valid receipts" in out

    @mock.patch("aiir._hub_sync.hub_push")
    def test_push_with_failures(self, mock_push, capsys, hub_env, tmp_path):
        receipt_file = tmp_path / "r.json"
        receipt_file.write_text('{"receipt_id":"r1"}')
        mock_push.return_value = {
            "ok": False,
            "total": 1,
            "verified": 0,
            "failed": 1,
            "results": [
                {"ok": False, "receipt_id": "r1", "errors": ["invalid sig"]},
            ],
        }
        assert _hub_sync.hub_cli(["push", str(receipt_file)]) == 1
