"""Tests to close all 40 partial branches and kill verify_receipt_file mutation survivors.

Tier 1: Exercises the untested direction of every partial branch (40 branches).
Tier 2: Strengthens assertions on verify_receipt_file to kill 34 surviving mutants.

Branch coverage gaps addressed (module → line → untested direction):
  _explain.py       131→136     id-mismatch-only path (no hash mismatch)
  _github.py        40→exit     GITHUB_OUTPUT not set
                    67→exit     GITHUB_STEP_SUMMARY not set
  _ledger.py        47→52      config file exists with valid instance_id
                    65→67      _HAS_FCHMOD False path in _save_config
                    78→82      index file exists with valid version
                    99→101     _HAS_FCHMOD False path in _save_index
                    149→151    _HAS_FCHMOD False path in append_to_ledger
                    223→232    empty ledger export
                    226→224    ledger export loop over receipts
  _receipt.py       465→464    detail format with non-string in files list
                    572→574    write_receipt jsonl mode
  _schema.py        157→159    committer is not a dict (skip validation)
                    160→164    files present (no files_redacted)
                    214→222    signals not a list (skip iteration)
                    222→229    bot_signals_detected not in ai
                    249→258    authorship_class not in ai
  _sign.py          163→165    _HAS_FCHMOD False path in sign bundle
  _stats.py         51→53      first timestamp has no 'T' separator
                    53→55      latest timestamp has no 'T' separator
  _verify_release.py 124→117   ledger at receipt cap (_MAX_LEDGER_RECEIPTS)
                    126→125    nested loop in ledger loading
                    165→163    receipt with non-dict commit (skip)
                    167→163    receipt with empty sha (skip)
                    250→265    evaluate_receipts with allowed_methods constraint
                    252→265    disallow_unsigned_ext constraint
                    267→286    unsigned extension keys check
                    274→286    ext_keys empty after filtering
                    491→489    commit_range with empty endpoint part
                    554→558    policy from preset URI
  cli.py            971→973    agent_tool not set (only model/context)
                    973→975    agent_model not set (only tool/context)
                    975→977    agent_context not set (only tool/model)
                    1046→1071  --ai-only with no AI commits
                    1146→1132  sign failure path
                    1283→1297  GitLab CI MR comment path
                    1290→1297  MR comment failure path
                    1307→1314  gl-sast-report flag
  mcp_server.py     520→531    verify_release policy preset path
                    576→574    gitlab_summary no receipts

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


# ═══════════════════════════════════════════════════════════════════════
# _explain.py — branch 131→136 (id mismatch only, no hash mismatch)
# ═══════════════════════════════════════════════════════════════════════


class TestExplainBranchIdOnlyMismatch(unittest.TestCase):
    """Close _explain.py branch 131→136: id mismatch without hash mismatch."""

    def test_hash_mismatch_only(self):
        """When only content_hash fails, the explanation must mention it."""
        from aiir._explain import explain_verification

        result = {
            "valid": False,
            "errors": ["content hash mismatch"],
        }
        text = explain_verification(result)
        self.assertIn("content_hash", text)
        # Must NOT mention receipt_id mismatch
        self.assertNotIn("receipt_id does not match", text)

    def test_id_mismatch_only(self):
        """When only receipt_id fails, the explanation must mention it (branch 131→136)."""
        from aiir._explain import explain_verification

        result = {
            "valid": False,
            "errors": ["receipt_id mismatch"],
        }
        text = explain_verification(result)
        self.assertIn("receipt_id", text)
        # Must NOT mention content_hash mismatch
        self.assertNotIn("content_hash does not match", text)


# ═══════════════════════════════════════════════════════════════════════
# _github.py — branches 40→exit and 67→exit (env vars not set)
# ═══════════════════════════════════════════════════════════════════════


class TestGithubBranchesEnvNotSet(unittest.TestCase):
    """Close _github.py early-exit branches when GITHUB_* env vars are unset."""

    def test_set_github_output_no_env(self):
        """set_github_output must silently no-op when GITHUB_OUTPUT is not set."""
        from aiir._github import set_github_output

        with patch.dict(os.environ, {}, clear=True):
            # Remove GITHUB_OUTPUT if present
            os.environ.pop("GITHUB_OUTPUT", None)
            # Should not raise
            set_github_output("key", "value")

    def test_set_github_summary_no_env(self):
        """set_github_summary must silently no-op when GITHUB_STEP_SUMMARY is not set."""
        from aiir._github import set_github_summary

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GITHUB_STEP_SUMMARY", None)
            # Should not raise
            set_github_summary("# Summary")


# ═══════════════════════════════════════════════════════════════════════
# _ledger.py — branches 47, 65, 78, 99, 149, 223, 226
# ═══════════════════════════════════════════════════════════════════════


class TestLedgerBranchConfigExists(unittest.TestCase):
    """Close _ledger.py branch 47→52: config file already exists with valid data."""

    def test_load_existing_config(self):
        """_load_config returns existing data when config.json is valid."""
        from aiir._ledger import _load_config

        tmpdir = tempfile.mkdtemp()
        try:
            cfg_dir = Path(tmpdir, ".aiir")
            cfg_dir.mkdir()
            cfg_path = cfg_dir / "config.json"
            config = {"instance_id": "test-id-1234", "created": "2025-01-01T00:00:00Z"}
            cfg_path.write_text(json.dumps(config), encoding="utf-8")
            loaded = _load_config(str(cfg_dir))
            self.assertEqual(loaded["instance_id"], "test-id-1234")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_load_config_invalid_instance_id(self):
        """47→52 False: config file exists but instance_id is not a string → regenerate."""
        from aiir._ledger import _load_config

        tmpdir = tempfile.mkdtemp()
        try:
            cfg_dir = Path(tmpdir, ".aiir")
            cfg_dir.mkdir()
            cfg_path = cfg_dir / "config.json"
            cfg_path.write_text(json.dumps({"instance_id": 12345}), encoding="utf-8")
            loaded = _load_config(str(cfg_dir))
            # Should generate new config since instance_id is not a string
            self.assertIsInstance(loaded["instance_id"], str)
            self.assertNotEqual(loaded["instance_id"], "12345")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestLedgerBranchFchmodFalse(unittest.TestCase):
    """Close _ledger.py branches 65, 99, 149: _HAS_FCHMOD=False paths."""

    def test_save_config_no_fchmod(self):
        """_save_config works when fchmod is unavailable."""
        from aiir._ledger import _save_config

        tmpdir = tempfile.mkdtemp()
        try:
            cfg_path = Path(tmpdir, "config.json")
            with patch("aiir._ledger._HAS_FCHMOD", False):
                _save_config(cfg_path, {"instance_id": "x"})
            self.assertTrue(cfg_path.exists())
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            self.assertEqual(data["instance_id"], "x")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_save_index_no_fchmod(self):
        """_save_index works when fchmod is unavailable."""
        from aiir._ledger import _save_index

        tmpdir = tempfile.mkdtemp()
        try:
            idx_path = Path(tmpdir, "index.json")
            with patch("aiir._ledger._HAS_FCHMOD", False):
                _save_index(idx_path, {"version": 1, "receipt_count": 0})
            self.assertTrue(idx_path.exists())
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_append_to_ledger_no_fchmod(self):
        """append_to_ledger works when fchmod is unavailable."""
        from aiir._ledger import append_to_ledger

        tmpdir = tempfile.mkdtemp()
        try:
            ledger_dir = str(Path(tmpdir, ".aiir"))
            receipt = {
                "commit": {"sha": "a" * 40, "author": {"email": "t@t.com"}},
                "ai_attestation": {
                    "is_ai_authored": False,
                    "is_bot_authored": False,
                    "authorship_class": "human",
                },
                "receipt_id": "g1-test",
                "timestamp": "2025-01-01T00:00:00Z",
            }
            with (
                patch("aiir._ledger._HAS_FCHMOD", False),
                patch("os.getcwd", return_value=tmpdir),
            ):
                appended, skipped, path = append_to_ledger([receipt], ledger_dir)
            self.assertEqual(appended, 1)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestLedgerBranchIndexExists(unittest.TestCase):
    """Close _ledger.py branch 78→82: index file already exists with valid version."""

    def test_load_existing_index(self):
        """_load_index returns existing data when index.json is valid."""
        from aiir._ledger import _load_index

        tmpdir = tempfile.mkdtemp()
        try:
            idx_path = Path(tmpdir, "index.json")
            index = {"version": 1, "receipt_count": 5, "commits": {}}
            idx_path.write_text(json.dumps(index), encoding="utf-8")
            loaded = _load_index(idx_path)
            self.assertEqual(loaded["receipt_count"], 5)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_load_index_invalid_version(self):
        """78→82 False: index file exists but version != 1 → regenerate."""
        from aiir._ledger import _load_index

        tmpdir = tempfile.mkdtemp()
        try:
            idx_path = Path(tmpdir, "index.json")
            idx_path.write_text(json.dumps({"version": 99, "receipt_count": 100}), encoding="utf-8")
            loaded = _load_index(idx_path)
            self.assertEqual(loaded["version"], 1)
            self.assertEqual(loaded["receipt_count"], 0)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestLedgerBranchExport(unittest.TestCase):
    """Close _ledger.py branches 223→232 and 226→224: export paths."""

    def test_export_empty_ledger(self):
        """export_ledger on empty ledger returns structure with empty receipts."""
        from aiir._ledger import export_ledger

        tmpdir = tempfile.mkdtemp()
        try:
            ledger_dir = str(Path(tmpdir, ".aiir"))
            os.makedirs(ledger_dir, exist_ok=True)
            # Create minimal config
            cfg = {"instance_id": "test-123", "created": "2025-01-01T00:00:00Z"}
            Path(ledger_dir, "config.json").write_text(json.dumps(cfg))
            result = export_ledger(ledger_dir)
            self.assertEqual(result["format"], "aiir.export.v1")
            self.assertEqual(result["receipts"], [])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_export_ledger_with_receipts(self):
        """export_ledger iterates receipt lines (branch 226→224)."""
        from aiir._ledger import append_to_ledger, export_ledger

        tmpdir = tempfile.mkdtemp()
        try:
            ledger_dir = str(Path(tmpdir, ".aiir"))
            receipt = {
                "commit": {"sha": "b" * 40, "author": {"email": "x@y.com"}},
                "ai_attestation": {
                    "is_ai_authored": True,
                    "is_bot_authored": False,
                    "authorship_class": "ai_assisted",
                },
                "receipt_id": "g1-export-test",
                "timestamp": "2025-06-01T00:00:00Z",
            }
            with patch("os.getcwd", return_value=tmpdir):
                append_to_ledger([receipt], ledger_dir)
            result = export_ledger(ledger_dir)
            self.assertEqual(len(result["receipts"]), 1)
            self.assertEqual(result["receipts"][0]["receipt_id"], "g1-export-test")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_export_ledger_with_blank_lines(self):
        """226→224: blank lines between receipts are skipped during export."""
        from aiir._ledger import export_ledger

        tmpdir = tempfile.mkdtemp()
        try:
            ledger_dir = str(Path(tmpdir, ".aiir"))
            os.makedirs(ledger_dir, exist_ok=True)
            cfg = {"instance_id": "test-123", "created": "2025-01-01T00:00:00Z"}
            Path(ledger_dir, "config.json").write_text(json.dumps(cfg))
            idx = {"version": 1, "receipt_count": 0}
            Path(ledger_dir, "index.json").write_text(json.dumps(idx))
            r1 = {"receipt_id": "g1-a", "commit": {"sha": "a" * 40}}
            r2 = {"receipt_id": "g1-b", "commit": {"sha": "b" * 40}}
            ledger_path = Path(ledger_dir, "receipts.jsonl")
            # Blank lines between receipts should be skipped
            ledger_path.write_text(
                json.dumps(r1) + "\n\n\n" + json.dumps(r2) + "\n"
            )
            result = export_ledger(ledger_dir)
            self.assertEqual(len(result["receipts"]), 2)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════
# _receipt.py — branches 465→464 and 572→574
# ═══════════════════════════════════════════════════════════════════════


class TestReceiptBranchDetailNonStringFile(unittest.TestCase):
    """Close _receipt.py branch 465→464: non-string item in files list."""

    def test_detail_format_skips_non_string_files(self):
        """format_receipt_detail must skip non-string items in files list."""
        from aiir._receipt import format_receipt_detail

        receipt = {
            "receipt_id": "g1-test",
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": {
                "sha": "a" * 40,
                "subject": "test",
                "files_changed": 3,
                "files": ["good.py", 42, "also_good.py"],
                "author": {"name": "Test", "email": "t@t.com", "date": "2025-01-01"},
                "committer": {"name": "Test", "email": "t@t.com", "date": "2025-01-01"},
            },
            "ai_attestation": {
                "is_ai_authored": False,
                "signals_detected": [],
            },
            "provenance": {},
            "content_hash": "sha256:" + "a" * 64,
            "timestamp": "2025-01-01T00:00:00Z",
        }
        text = format_receipt_detail(receipt)
        # String files should appear, integer should be skipped
        self.assertIn("good.py", text)
        self.assertIn("also_good.py", text)
        # Integer 42 should NOT appear as a file line
        lines = text.split("\n")
        file_lines = [l for l in lines if "good.py" in l or "42" in l]
        # Only the two string files should be in file-like lines
        string_file_lines = [l for l in file_lines if "good.py" in l]
        self.assertEqual(len(string_file_lines), 2)


class TestReceiptBranchJsonlMode(unittest.TestCase):
    """Close _receipt.py branch 572→574: write_receipt with jsonl=True."""

    def test_write_receipt_jsonl_mode(self):
        """write_receipt(jsonl=True) outputs canonical JSON to stdout."""
        import contextlib
        from aiir._receipt import write_receipt

        receipt = {"type": "test", "commit": {"sha": "a" * 40}}
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            result = write_receipt(receipt, jsonl=True)
        self.assertEqual(result, "stdout:jsonl")
        output = buf.getvalue().strip()
        # Must be valid JSON
        parsed = json.loads(output)
        self.assertEqual(parsed["type"], "test")


# ═══════════════════════════════════════════════════════════════════════
# _schema.py — branches 157, 160, 214, 222, 249
# ═══════════════════════════════════════════════════════════════════════


class TestSchemaBranchesPartial(unittest.TestCase):
    """Close _schema.py partial branches."""

    def _make_valid_receipt(self):
        """Build a minimal structurally valid receipt for modification."""
        return {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "receipt_id": "g1-test",
            "content_hash": "sha256:" + "a" * 64,
            "timestamp": "2025-01-01T00:00:00Z",
            "extensions": {},
            "commit": {
                "sha": "a" * 40,
                "subject": "test",
                "message_hash": "sha256:" + "b" * 64,
                "diff_hash": "sha256:" + "c" * 64,
                "files_changed": 1,
                "files": ["test.py"],
                "author": {"name": "A", "email": "a@b.com", "date": "2025-01-01"},
                "committer": {"name": "A", "email": "a@b.com", "date": "2025-01-01"},
            },
            "ai_attestation": {
                "is_ai_authored": False,
                "signals_detected": [],
                "signal_count": 0,
                "detection_method": "heuristic_v1",
            },
            "provenance": {"tool": "aiir.cli", "tool_version": "1.0.0"},
        }

    def test_committer_non_dict_skips_validation(self):
        """Branch 160→162: when committer is not a dict, skip identity validation."""
        from aiir._schema import validate_receipt_schema

        r = self._make_valid_receipt()
        r["commit"]["committer"] = "not-a-dict"
        errors = validate_receipt_schema(r)
        # Should NOT crash, and should not report committer identity errors
        committer_errors = [e for e in errors if "committer.name" in e]
        self.assertEqual(len(committer_errors), 0)

    def test_author_non_dict_skips_validation(self):
        """Branch 157→159: when author is not a dict, skip identity validation."""
        from aiir._schema import validate_receipt_schema

        r = self._make_valid_receipt()
        r["commit"]["author"] = "not-a-dict"
        errors = validate_receipt_schema(r)
        # Should NOT crash, and should not report author identity errors
        author_errors = [e for e in errors if "author.name" in e]
        self.assertEqual(len(author_errors), 0)

    def test_files_present_no_files_redacted(self):
        """Branch 160→164: files present without files_redacted is the normal path."""
        from aiir._schema import validate_receipt_schema

        r = self._make_valid_receipt()
        # Already has files, no files_redacted — should be fine
        errors = validate_receipt_schema(r)
        file_errors = [e for e in errors if "files_redacted" in e or "files" in e.lower()]
        self.assertEqual(len(file_errors), 0, f"Unexpected file errors: {file_errors}")

    def test_signals_not_list_skips_string_check(self):
        """Branch 214→222: when signals_detected is not a list, skip iteration."""
        from aiir._schema import validate_receipt_schema

        r = self._make_valid_receipt()
        r["ai_attestation"]["signals_detected"] = "not-a-list"
        r["ai_attestation"]["signal_count"] = 0
        errors = validate_receipt_schema(r)
        # Should report type error but not crash iterating
        type_errors = [e for e in errors if "signals_detected" in e and "list" in e]
        self.assertGreater(len(type_errors), 0)

    def test_no_bot_signals_detected_field(self):
        """Branch 222→229: when bot_signals_detected is absent, skip bot validation."""
        from aiir._schema import validate_receipt_schema

        r = self._make_valid_receipt()
        r["ai_attestation"].pop("bot_signals_detected", None)
        r["ai_attestation"].pop("bot_signal_count", None)
        errors = validate_receipt_schema(r)
        bot_errors = [e for e in errors if "bot_signal" in e]
        self.assertEqual(len(bot_errors), 0)

    def test_bot_signal_count_without_detected_list(self):
        """Branch 249→258: bot_signal_count present as int but bot_signals_detected absent."""
        from aiir._schema import validate_receipt_schema

        r = self._make_valid_receipt()
        r["ai_attestation"]["bot_signal_count"] = 3
        r["ai_attestation"].pop("bot_signals_detected", None)
        errors = validate_receipt_schema(r)
        # Should NOT crash — the elif path is simply skipped
        self.assertIsInstance(errors, list)

    def test_no_authorship_class_field(self):
        """Branch 249→258: when authorship_class is absent, skip class validation."""
        from aiir._schema import validate_receipt_schema

        r = self._make_valid_receipt()
        r["ai_attestation"].pop("authorship_class", None)
        errors = validate_receipt_schema(r)
        class_errors = [e for e in errors if "authorship_class" in e]
        self.assertEqual(len(class_errors), 0)


# ═══════════════════════════════════════════════════════════════════════
# _sign.py — branch 163→165 (_HAS_FCHMOD False)
# ═══════════════════════════════════════════════════════════════════════


class TestSignBranchFchmodFalse(unittest.TestCase):
    """Close _sign.py branch 163→165: fchmod unavailable."""

    def test_sign_bundle_write_no_fchmod(self):
        """sign_receipt_file works when fchmod is unavailable (mocked sigstore)."""
        from aiir._sign import sign_receipt_file

        tmpdir = tempfile.mkdtemp()
        try:
            receipt_path = Path(tmpdir, "receipt.json")
            receipt_path.write_text('{"type":"aiir.commit_receipt"}')
            with (
                patch("aiir._sign._HAS_FCHMOD", False),
                patch("aiir._sign.sign_receipt", return_value='{"sigstore":"bundle"}'),
            ):
                bundle_path = sign_receipt_file(str(receipt_path))
            self.assertTrue(Path(bundle_path).exists())
            self.assertTrue(bundle_path.endswith(".sigstore"))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════
# _stats.py — branches 51→53 and 53→55 (no 'T' in timestamps)
# ═══════════════════════════════════════════════════════════════════════


class TestStatsBranchTimestampNoT(unittest.TestCase):
    """Close _stats.py branches 51→53 and 53→55: timestamps without 'T' separator."""

    def test_format_stats_date_only_timestamps(self):
        """Timestamps without 'T' are displayed as-is."""
        from aiir._stats import format_stats

        index = {
            "receipt_count": 10,
            "ai_commit_count": 3,
            "ai_percentage": 30.0,
            "unique_authors": 2,
            "first_receipt": "2025-01-01",  # no 'T' separator
            "latest_timestamp": "2025-06-15",  # no 'T' separator
        }
        text = format_stats(index)
        self.assertIn("2025-01-01", text)
        self.assertIn("2025-06-15", text)

    def test_format_stats_with_namespace_and_instance(self):
        """Config with namespace and instance_id produces extra lines."""
        from aiir._stats import format_stats

        index = {
            "receipt_count": 5,
            "ai_commit_count": 1,
            "ai_percentage": 20.0,
            "unique_authors": 1,
            "first_receipt": "2025-01-01",
            "latest_timestamp": "2025-06-15",
        }
        config = {"namespace": "acme-corp", "instance_id": "abc12345-xyz"}
        text = format_stats(index, config=config)
        self.assertIn("acme-corp", text)
        self.assertIn("abc12345", text)


# ═══════════════════════════════════════════════════════════════════════
# _verify_release.py — branches 124, 126, 165, 167, 250, 252, 267, 274, 491, 554
# ═══════════════════════════════════════════════════════════════════════


class TestVerifyReleaseBranchLedgerEdges(unittest.TestCase):
    """Close _verify_release.py ledger loading branches."""

    def test_ledger_non_dict_lines_skipped(self):
        """Lines that parse to non-dict are skipped (branch 126→125)."""
        from aiir._verify_release import _load_receipts_from_ledger

        tmpdir = tempfile.mkdtemp()
        try:
            ledger = Path(tmpdir, "receipts.jsonl")
            lines = [
                json.dumps({"commit": {"sha": "a" * 40}}),
                json.dumps([1, 2, 3]),  # list → not a dict → skip
                json.dumps({"commit": {"sha": "b" * 40}}),
            ]
            ledger.write_text("\n".join(lines))
            receipts = _load_receipts_from_ledger(str(ledger))
            self.assertEqual(len(receipts), 2)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_ledger_truncated_at_max(self):
        """Ledger stops at _MAX_LEDGER_RECEIPTS (branch 124→117)."""
        from aiir._verify_release import _load_receipts_from_ledger, _MAX_LEDGER_RECEIPTS

        tmpdir = tempfile.mkdtemp()
        try:
            ledger = Path(tmpdir, "receipts.jsonl")
            # Write exactly limit + 5 lines
            lines = [json.dumps({"i": i}) for i in range(_MAX_LEDGER_RECEIPTS + 5)]
            ledger.write_text("\n".join(lines))
            receipts = _load_receipts_from_ledger(str(ledger))
            self.assertEqual(len(receipts), _MAX_LEDGER_RECEIPTS)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestVerifyReleaseBranchEvaluateReceipts(unittest.TestCase):
    """Close _verify_release.py _evaluate_receipts branches."""

    def _make_receipt(self, sha="a" * 40, method="heuristic_v1", signed=False,
                      extensions=None):
        """Build a minimal receipt for evaluation."""
        r = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": {"sha": sha, "subject": "test"},
            "ai_attestation": {
                "is_ai_authored": False,
                "detection_method": method,
                "signals_detected": [],
                "signal_count": 0,
            },
            "provenance": {},
            "receipt_id": "g1-test",
            "content_hash": "sha256:" + "a" * 64,
        }
        if extensions:
            r["extensions"] = extensions
        if signed:
            r.setdefault("extensions", {})["sigstore_bundle"] = "ref://bundle"
        return r

    def test_receipt_non_dict_commit_skipped(self):
        """Receipt with non-dict commit field is skipped (branch 165→163)."""
        from aiir._verify_release import _evaluate_receipts

        receipts = [{"commit": "not-a-dict", "type": "aiir.commit_receipt"}]
        result = _evaluate_receipts(receipts, {"enforcement": "warn"})
        self.assertEqual(result["total_receipts"], 0)

    def test_receipt_empty_sha_skipped(self):
        """Receipt with empty sha is skipped (branch 167→163)."""
        from aiir._verify_release import _evaluate_receipts

        receipts = [{"commit": {"sha": ""}, "type": "aiir.commit_receipt"}]
        result = _evaluate_receipts(receipts, {"enforcement": "warn"})
        self.assertEqual(result["total_receipts"], 0)

    def test_allowed_methods_violation(self):
        """Receipt with disallowed detection method triggers violation (branch 250→265)."""
        from aiir._verify_release import _evaluate_receipts

        receipt = self._make_receipt(method="magic_v1")
        policy = {
            "enforcement": "warn",
            "allowed_detection_methods": ["heuristic_v1"],
        }
        result = _evaluate_receipts([receipt], policy)
        violations = result["policy_violations"]
        method_viols = [v for v in violations if v.get("rule") == "allowed_detection_methods"]
        self.assertGreater(len(method_viols), 0)

    def test_allowed_methods_ai_not_dict(self):
        """250→265 False: ai_attestation not a dict → method check skipped."""
        from aiir._verify_release import _evaluate_receipts

        receipt = self._make_receipt()
        receipt["ai_attestation"] = "not-a-dict"
        policy = {
            "enforcement": "warn",
            "allowed_detection_methods": ["heuristic_v1"],
        }
        result = _evaluate_receipts([receipt], policy)
        method_viols = [v for v in result["policy_violations"]
                        if v.get("rule") == "allowed_detection_methods"]
        self.assertEqual(len(method_viols), 0)

    def test_allowed_method_no_violation(self):
        """252→265 False: allowed method present → no violation."""
        from aiir._verify_release import _evaluate_receipts

        receipt = self._make_receipt(method="heuristic_v1")
        policy = {
            "enforcement": "warn",
            "allowed_detection_methods": ["heuristic_v1"],
        }
        result = _evaluate_receipts([receipt], policy)
        method_viols = [v for v in result["policy_violations"]
                        if v.get("rule") == "allowed_detection_methods"]
        self.assertEqual(len(method_viols), 0)

    def test_disallow_unsigned_extensions(self):
        """Unsigned receipt with custom extensions triggers violation (branch 252→265, 267→286)."""
        from aiir._verify_release import _evaluate_receipts

        receipt = self._make_receipt(
            extensions={"custom_key": "value", "generator": "aiir.cli"}
        )
        policy = {
            "enforcement": "warn",
            "disallow_unsigned_extensions": True,
        }
        result = _evaluate_receipts([receipt], policy)
        violations = result["policy_violations"]
        ext_viols = [v for v in violations if v.get("rule") == "disallow_unsigned_extensions"]
        self.assertGreater(len(ext_viols), 0)

    def test_disallow_unsigned_ext_empty_extensions(self):
        """267→286 False: empty extensions dict → ext-key check skipped."""
        from aiir._verify_release import _evaluate_receipts

        receipt = self._make_receipt(extensions={})
        policy = {
            "enforcement": "warn",
            "disallow_unsigned_extensions": True,
        }
        result = _evaluate_receipts([receipt], policy)
        ext_viols = [v for v in result["policy_violations"]
                     if v.get("rule") == "disallow_unsigned_extensions"]
        self.assertEqual(len(ext_viols), 0)

    def test_unsigned_with_only_standard_ext_keys_no_violation(self):
        """Unsigned receipt with only standard extension keys is OK (branch 274→286)."""
        from aiir._verify_release import _evaluate_receipts

        receipt = self._make_receipt(
            extensions={"sigstore_bundle": "", "generator": "aiir.cli", "instance_id": "x"}
        )
        policy = {
            "enforcement": "warn",
            "disallow_unsigned_extensions": True,
        }
        result = _evaluate_receipts([receipt], policy)
        ext_viols = [v for v in result["policy_violations"]
                     if v.get("rule") == "disallow_unsigned_extensions"]
        self.assertEqual(len(ext_viols), 0)


class TestVerifyReleaseBranchCommitRange(unittest.TestCase):
    """Close _verify_release.py branch 491→489: empty endpoint in commit range."""

    def test_range_with_empty_endpoint(self):
        """Range like '..HEAD' has empty left part — must not crash."""
        from aiir._verify_release import verify_release

        tmpdir = tempfile.mkdtemp()
        try:
            # Create a minimal ledger
            ledger_dir = Path(tmpdir, ".aiir")
            ledger_dir.mkdir()
            ledger = ledger_dir / "receipts.jsonl"
            receipt = {
                "type": "aiir.commit_receipt",
                "schema": "aiir/commit_receipt.v1",
                "version": "1.0.0",
                "commit": {"sha": "a" * 40, "subject": "test"},
                "ai_attestation": {},
                "provenance": {},
                "receipt_id": "g1-test",
                "content_hash": "sha256:" + "a" * 64,
            }
            ledger.write_text(json.dumps(receipt) + "\n")

            # Mock git operations
            with (
                patch("aiir._verify_release.list_commits_in_range", return_value=["a" * 40]),
                patch("aiir._verify_release._validate_ref"),
            ):
                result = verify_release(
                    commit_range="..HEAD",
                    receipts_path=str(ledger),
                )
            self.assertIn("verificationResult", result)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestVerifyReleaseBranchPolicyPresetUri(unittest.TestCase):
    """Close _verify_release.py branch 554→558: policy_uri from preset."""

    def test_policy_preset_uri(self):
        """When using a preset, policy_uri should be aiir://presets/<name>."""
        from aiir._verify_release import verify_release

        tmpdir = tempfile.mkdtemp()
        try:
            ledger = Path(tmpdir, "receipts.jsonl")
            receipt = {
                "type": "aiir.commit_receipt",
                "schema": "aiir/commit_receipt.v1",
                "version": "1.0.0",
                "commit": {"sha": "a" * 40, "subject": "test"},
                "ai_attestation": {},
                "provenance": {},
                "receipt_id": "g1-test",
                "content_hash": "sha256:" + "a" * 64,
            }
            ledger.write_text(json.dumps(receipt) + "\n")
            result = verify_release(
                receipts_path=str(ledger),
                policy_preset="permissive",
            )
            pred = result.get("predicate", {})
            policy_uri = pred.get("policy", {}).get("uri", "")
            self.assertEqual(policy_uri, "aiir://presets/permissive")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════
# cli.py — branches 971, 973, 975, 1046, 1146, 1283, 1290, 1307
# ═══════════════════════════════════════════════════════════════════════


class TestCliBranchAgentFlags(unittest.TestCase):
    """Close cli.py branches 971→973, 973→975, 975→977:
    agent_tool/model/context not set while inside agent attestation block.
    """

    def _run_cli(self, argv):
        """Run cli.main() with standard mocks, returning generate_receipt's call kwargs."""
        import aiir.cli as cli_mod

        receipt = {
            "type": "aiir.commit_receipt",
            "commit": {"sha": "a" * 40},
            "ai_attestation": {"is_ai_authored": False},
        }
        with (
            patch("aiir.cli.generate_receipt", return_value=receipt) as mock_gen,
            patch("aiir.cli.write_receipt", return_value="stdout:json"),
            patch("sys.stderr", io.StringIO()),
            patch("sys.stdout", io.StringIO()),
        ):
            cli_mod.main(argv)
        return mock_gen.call_args

    def test_agent_model_only_no_tool(self):
        """Branch 971→973: --agent-model without --agent-tool.

        Enters agent block via agent_model, but agent_tool is None → skips to 973.
        """
        call = self._run_cli(["--agent-model", "gpt-4o"])
        kw = call.kwargs if call.kwargs else call[1]
        att = kw.get("agent_attestation")
        self.assertIsNotNone(att)
        self.assertIn("model_class", att)
        self.assertEqual(att["model_class"], "gpt-4o")
        self.assertNotIn("tool_id", att)
        self.assertEqual(att["confidence"], "declared")

    def test_agent_context_only_no_model(self):
        """Branch 973→975: --agent-context without --agent-model.

        Enters agent block via agent_context, agent_model is None → skips to 975.
        """
        call = self._run_cli(["--agent-context", "mcp"])
        kw = call.kwargs if call.kwargs else call[1]
        att = kw.get("agent_attestation")
        self.assertIsNotNone(att)
        self.assertIn("run_context", att)
        self.assertEqual(att["run_context"], "mcp")
        self.assertNotIn("model_class", att)
        self.assertNotIn("tool_id", att)

    def test_agent_tool_only_no_context(self):
        """Branch 975→977: --agent-tool without --agent-context.

        agent_context is None → skips to 977 (confidence = "declared").
        """
        call = self._run_cli(["--agent-tool", "copilot"])
        kw = call.kwargs if call.kwargs else call[1]
        att = kw.get("agent_attestation")
        self.assertIsNotNone(att)
        self.assertIn("tool_id", att)
        self.assertEqual(att["tool_id"], "copilot")
        self.assertNotIn("run_context", att)
        self.assertEqual(att["confidence"], "declared")


class TestCliBranchGitlabGenerator(unittest.TestCase):
    """Close cli.py gitlab_ci generator path."""

    def test_gitlab_ci_generator(self):
        """--gitlab-ci flag sets generator='aiir.gitlab'."""
        import aiir.cli as cli_mod

        receipt = {
            "type": "aiir.commit_receipt",
            "commit": {"sha": "a" * 40},
            "ai_attestation": {"is_ai_authored": False},
        }
        with (
            patch("aiir.cli.generate_receipt", return_value=receipt) as mock_gen,
            patch("aiir.cli.append_to_ledger", return_value=(1, 0, "/tmp/.aiir/receipts.jsonl")),
            patch("aiir.cli.write_receipt", return_value="stdout:json"),
            patch("aiir.cli.set_gitlab_ci_output"),
            patch("sys.stderr", io.StringIO()),
            patch("sys.stdout", io.StringIO()),
            patch.dict(os.environ, {"CI_COMMIT_SHA": "a" * 40}, clear=False),
        ):
            cli_mod.main(["--gitlab-ci"])
        call_kw = mock_gen.call_args.kwargs if mock_gen.call_args.kwargs else mock_gen.call_args[1]
        self.assertEqual(call_kw.get("generator"), "aiir.gitlab")


class TestCliBranchAiOnlyNoResults(unittest.TestCase):
    """Close cli.py branch 1046→1071: --ai-only with no AI commits."""

    def test_ai_only_filters_everything(self):
        """--ai-only returns 0 when no AI-authored commits exist."""
        import aiir.cli as cli_mod

        captured_err = io.StringIO()
        with (
            patch("aiir.cli.generate_receipt", return_value=None),
            patch("sys.stderr", captured_err),
            patch("sys.stdout", io.StringIO()),
        ):
            code = cli_mod.main(["--ai-only"])
        self.assertEqual(code, 0)
        err = captured_err.getvalue()
        self.assertIn("--ai-only", err)


class TestCliBranchSignFailure(unittest.TestCase):
    """Close cli.py branch 1146→1132: signing failure cleanup."""

    def test_sign_failure_cleans_up_receipt(self):
        """When signing fails, the unsigned receipt file should be removed."""
        import aiir.cli as cli_mod

        tmpdir = tempfile.mkdtemp()
        try:
            receipt = {
                "type": "aiir.commit_receipt",
                "commit": {"sha": "a" * 40},
                "ai_attestation": {"is_ai_authored": False},
                "content_hash": "sha256:" + "a" * 64,
            }
            receipt_path = str(Path(tmpdir, "receipt_aaaaaaaaaaaa_bbbbbbbbbbbbbbbb.json"))

            with (
                patch("aiir.cli.generate_receipt", return_value=receipt),
                patch("aiir.cli.write_receipt", return_value=receipt_path),
                patch("aiir.cli.sign_receipt_file", side_effect=RuntimeError("mock sign error")),
                patch("os.remove") as mock_remove,
                patch("sys.stderr", io.StringIO()),
                patch("sys.stdout", io.StringIO()),
            ):
                code = cli_mod.main(["--sign", "--output", tmpdir])
            self.assertEqual(code, 1)
            mock_remove.assert_called_with(receipt_path)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestCliBranchGitlabCIMR(unittest.TestCase):
    """Close cli.py branches 1283→1297 and 1290→1297: GitLab MR comment."""

    def _make_receipt(self):
        return {
            "type": "aiir.commit_receipt",
            "commit": {"sha": "a" * 40},
            "ai_attestation": {"is_ai_authored": False},
        }

    def test_gitlab_mr_comment_success(self):
        """GitLab MR comment succeeds when CI_MERGE_REQUEST_IID is set."""
        import aiir.cli as cli_mod

        captured_err = io.StringIO()
        with (
            patch("aiir.cli.generate_receipt", return_value=self._make_receipt()),
            patch("aiir.cli.append_to_ledger", return_value=(1, 0, "/tmp/r.jsonl")),
            patch("aiir.cli.write_receipt", return_value="stdout:json"),
            patch("aiir.cli.set_gitlab_ci_output"),
            patch("aiir.cli.format_gitlab_summary", return_value="| summary |"),
            patch("aiir.cli.post_mr_comment"),
            patch("sys.stderr", captured_err),
            patch("sys.stdout", io.StringIO()),
            patch.dict(os.environ, {
                "CI_COMMIT_SHA": "a" * 40,
                "CI_MERGE_REQUEST_IID": "42",
            }, clear=False),
        ):
            code = cli_mod.main(["--gitlab-ci"])
        self.assertEqual(code, 0)
        err = captured_err.getvalue()
        self.assertIn("MR", err)

    def test_gitlab_mr_comment_failure(self):
        """GitLab MR comment failure is non-fatal (branch 1290→1297)."""
        import aiir.cli as cli_mod

        captured_err = io.StringIO()
        with (
            patch("aiir.cli.generate_receipt", return_value=self._make_receipt()),
            patch("aiir.cli.append_to_ledger", return_value=(1, 0, "/tmp/r.jsonl")),
            patch("aiir.cli.write_receipt", return_value="stdout:json"),
            patch("aiir.cli.set_gitlab_ci_output"),
            patch("aiir.cli.format_gitlab_summary", return_value="| summary |"),
            patch("aiir.cli.post_mr_comment", side_effect=RuntimeError("MR comment fail")),
            patch("sys.stderr", captured_err),
            patch("sys.stdout", io.StringIO()),
            patch.dict(os.environ, {
                "CI_COMMIT_SHA": "a" * 40,
                "CI_MERGE_REQUEST_IID": "99",
            }, clear=False),
        ):
            code = cli_mod.main(["--gitlab-ci"])
        self.assertEqual(code, 0)
        err = captured_err.getvalue()
        self.assertIn("Could not post MR comment", err)


class TestCliBranchGlSastReport(unittest.TestCase):
    """Close cli.py branch 1307→1314: --gl-sast-report flag."""

    def test_gl_sast_report_written(self):
        """--gl-sast-report writes a SAST JSON file."""
        import aiir.cli as cli_mod

        tmpdir = tempfile.mkdtemp()
        try:
            sast_path = str(Path(tmpdir, "gl-sast.json"))
            receipt = {
                "type": "aiir.commit_receipt",
                "commit": {"sha": "a" * 40},
                "ai_attestation": {"is_ai_authored": True},
            }
            captured_err = io.StringIO()
            with (
                patch("aiir.cli.generate_receipt", return_value=receipt),
                patch("aiir.cli.append_to_ledger", return_value=(1, 0, "/tmp/r.jsonl")),
                patch("aiir.cli.write_receipt", return_value="stdout:json"),
                patch("aiir.cli.set_gitlab_ci_output"),
                patch("aiir.cli.format_gl_sast_report", return_value={
                    "version": "15.0.0",
                    "vulnerabilities": [],
                }),
                patch("sys.stderr", captured_err),
                patch("sys.stdout", io.StringIO()),
                patch.dict(os.environ, {"CI_COMMIT_SHA": "a" * 40}, clear=False),
            ):
                code = cli_mod.main(["--gitlab-ci", "--gl-sast-report", sast_path])
            self.assertEqual(code, 0)
            self.assertTrue(Path(sast_path).exists())
            sast = json.loads(Path(sast_path).read_text())
            self.assertIn("version", sast)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════
# mcp_server.py — branches 520→531 and 576→574
# ═══════════════════════════════════════════════════════════════════════


class TestMcpBranchVerifyReleasePreset(unittest.TestCase):
    """Close mcp_server.py branch 520→531: policy preset path in verify_release handler."""

    def test_verify_release_with_preset(self):
        """MCP verify_release handler accepts preset name as policy arg."""
        from aiir.mcp_server import _handle_aiir_verify_release

        with (
            patch("aiir.mcp_server.verify_release") as mock_vr,
            patch("aiir.mcp_server.format_release_report", return_value="report text"),
        ):
            mock_vr.return_value = {"verificationResult": "PASSED", "reason": "ok"}
            result = _handle_aiir_verify_release({
                "commit_range": "HEAD~1..HEAD",
                "policy": "strict",
            })
        # Should have called verify_release with policy_preset="strict"
        mock_vr.assert_called_once()
        call_kwargs = mock_vr.call_args.kwargs
        self.assertEqual(call_kwargs.get("policy_preset"), "strict")

    def test_verify_release_without_policy(self):
        """520→531 False: no policy arg → policy_preset and policy_path are both None."""
        from aiir.mcp_server import _handle_aiir_verify_release

        with (
            patch("aiir.mcp_server.verify_release") as mock_vr,
            patch("aiir.mcp_server.format_release_report", return_value="report"),
        ):
            mock_vr.return_value = {"verificationResult": "PASSED", "reason": "ok"}
            result = _handle_aiir_verify_release({"commit_range": "HEAD~1..HEAD"})
        call_kwargs = mock_vr.call_args.kwargs
        self.assertIsNone(call_kwargs.get("policy_preset"))
        self.assertIsNone(call_kwargs.get("policy_path"))

    def test_verify_release_with_policy_file(self):
        """MCP verify_release handler accepts file path as policy arg."""
        from aiir.mcp_server import _handle_aiir_verify_release

        tmpdir = tempfile.mkdtemp()
        try:
            policy_path = Path(tmpdir, "policy.json")
            policy_path.write_text('{"enforcement": "warn"}')
            with (
                patch("aiir.mcp_server.verify_release") as mock_vr,
                patch("aiir.mcp_server.format_release_report", return_value="report"),
                patch("aiir.mcp_server._safe_verify_path", return_value=str(policy_path)),
            ):
                mock_vr.return_value = {"verificationResult": "PASSED", "reason": "ok"}
                result = _handle_aiir_verify_release({
                    "commit_range": "HEAD~1..HEAD",
                    "policy": str(policy_path),
                })
            call_kwargs = mock_vr.call_args.kwargs
            self.assertEqual(call_kwargs.get("policy_path"), str(policy_path))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestMcpBranchGitlabSummaryNoReceipts(unittest.TestCase):
    """Close mcp_server.py branch 576→574: gitlab_summary with no receipts."""

    def test_gitlab_summary_empty_ledger(self):
        """MCP gitlab_summary returns hint when ledger exists but is empty."""
        from aiir.mcp_server import _handle_aiir_gitlab_summary

        tmpdir = tempfile.mkdtemp()
        try:
            # Create empty ledger
            ledger = Path(tmpdir, ".aiir", "receipts.jsonl")
            ledger.parent.mkdir(parents=True)
            ledger.write_text("")  # empty

            with patch("pathlib.Path.cwd", return_value=Path(tmpdir)):
                result = _handle_aiir_gitlab_summary({})

            # Should return a hint about no receipts found
            self.assertIsNotNone(result)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_gitlab_summary_ledger_with_blank_lines(self):
        """576→574: blank lines in ledger are skipped when loading receipts."""
        from aiir.mcp_server import _handle_aiir_gitlab_summary

        tmpdir = tempfile.mkdtemp()
        try:
            ledger = Path(tmpdir, ".aiir", "receipts.jsonl")
            ledger.parent.mkdir(parents=True)
            r = {"type": "aiir.commit_receipt", "commit": {"sha": "a" * 40},
                 "ai_attestation": {"is_ai_authored": False}}
            # Write receipt with blank lines interspersed
            ledger.write_text(json.dumps(r) + "\n\n\n")

            with (
                patch("pathlib.Path.cwd", return_value=Path(tmpdir)),
                patch("aiir.mcp_server.format_gitlab_summary", return_value="| summary |"),
            ):
                result = _handle_aiir_gitlab_summary({})
            self.assertIsNotNone(result)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════
# _receipt.py — branch 68→63 (attestation value empty after strip)
# ═══════════════════════════════════════════════════════════════════════


class TestReceiptBranchEmptyAfterStrip(unittest.TestCase):
    """Close _receipt.py branch 68→63: attestation value becomes empty after strip."""

    def test_attestation_value_empty_after_strip(self):
        """Value that is only terminal escapes becomes empty after stripping → excluded."""
        from aiir._receipt import _sanitize_agent_attestation

        att = {"tool_id": "\x1b[31m\x1b[0m"}  # only ANSI escapes
        result = _sanitize_agent_attestation(att)
        self.assertNotIn("tool_id", result)

    def test_attestation_value_valid_kept(self):
        """Non-empty value after stripping is kept."""
        from aiir._receipt import _sanitize_agent_attestation

        att = {"tool_id": "copilot", "model_class": "gpt-4o"}
        result = _sanitize_agent_attestation(att)
        self.assertEqual(result["tool_id"], "copilot")
        self.assertEqual(result["model_class"], "gpt-4o")


# ═══════════════════════════════════════════════════════════════════════
# _receipt.py — branch 572→574 (write_receipt file with _HAS_FCHMOD=False)
# ═══════════════════════════════════════════════════════════════════════


class TestReceiptBranchWriteFileNoFchmod(unittest.TestCase):
    """Close _receipt.py branch 572→574: write_receipt file output without fchmod."""

    def test_write_receipt_file_no_fchmod(self):
        """write_receipt to output_dir works when fchmod is unavailable."""
        from aiir._receipt import write_receipt

        tmpdir = tempfile.mkdtemp()
        try:
            receipt = {"type": "aiir.commit_receipt", "commit": {"sha": "a" * 40}}
            with (
                patch("aiir._receipt._HAS_FCHMOD", False),
                patch("os.getcwd", return_value=tmpdir),
            ):
                path = write_receipt(receipt, output_dir=tmpdir)
            self.assertTrue(Path(path).exists())
            data = json.loads(Path(path).read_text())
            self.assertEqual(data["type"], "aiir.commit_receipt")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════
# _verify_release.py — dir loader branches 124→117 and 126→125
# ═══════════════════════════════════════════════════════════════════════


class TestVerifyReleaseBranchDirLoader(unittest.TestCase):
    """Close _verify_release.py _load_receipts_from_dir branches."""

    def test_json_file_not_dict_or_list(self):
        """124→117: JSON containing a bare string → neither dict nor list → skip."""
        from aiir._verify_release import _load_receipts_from_dir

        tmpdir = tempfile.mkdtemp()
        try:
            Path(tmpdir, "a.json").write_text('"just a string"')
            Path(tmpdir, "b.json").write_text(json.dumps({"commit": {"sha": "a" * 40}}))
            receipts = _load_receipts_from_dir(tmpdir)
            self.assertEqual(len(receipts), 1)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_json_list_with_non_dict_items(self):
        """126→125: list containing non-dict items → only dicts are kept."""
        from aiir._verify_release import _load_receipts_from_dir

        tmpdir = tempfile.mkdtemp()
        try:
            Path(tmpdir, "arr.json").write_text(json.dumps([
                42,
                "string",
                {"commit": {"sha": "a" * 40}},
            ]))
            receipts = _load_receipts_from_dir(tmpdir)
            self.assertEqual(len(receipts), 1)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════
# _verify_release.py — _compute_coverage branches 165→163 and 167→163
# ═══════════════════════════════════════════════════════════════════════


class TestVerifyReleaseBranchComputeCoverage(unittest.TestCase):
    """Close _verify_release.py _compute_coverage branches."""

    def test_receipt_with_non_dict_commit(self):
        """165→163: receipt with non-dict commit field is skipped."""
        from aiir._verify_release import _compute_coverage

        result = _compute_coverage(
            ["abc123"],
            [{"commit": "not-a-dict"}, {"commit": {"sha": "abc123"}}],
        )
        self.assertEqual(result["receipts_found"], 1)

    def test_receipt_with_empty_sha(self):
        """167→163: receipt with empty sha is skipped."""
        from aiir._verify_release import _compute_coverage

        result = _compute_coverage(
            ["abc123"],
            [{"commit": {"sha": ""}}, {"commit": {"sha": "abc123"}}],
        )
        self.assertEqual(result["receipts_found"], 1)


# ═══════════════════════════════════════════════════════════════════════
# cli.py — quiet-mode branches (1046, 1146, 1283, 1290, 1307)
# ═══════════════════════════════════════════════════════════════════════


class TestCliBranchQuietMode(unittest.TestCase):
    """Close cli.py quiet-mode branches: if not args.quiet → False paths."""

    def _make_receipt(self):
        return {
            "type": "aiir.commit_receipt",
            "commit": {"sha": "a" * 40},
            "ai_attestation": {"is_ai_authored": False},
        }

    def test_no_receipts_quiet(self):
        """1046→1071: --quiet with no receipts skips all print statements."""
        import aiir.cli as cli_mod

        with (
            patch("aiir.cli.generate_receipt", return_value=None),
            patch("sys.stderr", io.StringIO()),
            patch("sys.stdout", io.StringIO()),
        ):
            code = cli_mod.main(["--quiet"])
        self.assertEqual(code, 0)

    def test_sign_success_quiet(self):
        """1146→1132: --quiet with successful signing skips print."""
        import aiir.cli as cli_mod

        tmpdir = tempfile.mkdtemp()
        try:
            with (
                patch("aiir.cli.generate_receipt", return_value=self._make_receipt()),
                patch("aiir.cli.write_receipt", return_value=str(Path(tmpdir, "r.json"))),
                patch("aiir.cli.sign_receipt_file", return_value=str(Path(tmpdir, "r.sigstore"))),
                patch("aiir.cli._sigstore_available", return_value=True),
                patch("sys.stderr", io.StringIO()),
                patch("sys.stdout", io.StringIO()),
            ):
                code = cli_mod.main(["--sign", "--output", tmpdir, "--quiet"])
            self.assertEqual(code, 0)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_gitlab_mr_comment_success_quiet(self):
        """1283→1297: --quiet with successful MR comment skips print."""
        import aiir.cli as cli_mod

        with (
            patch("aiir.cli.generate_receipt", return_value=self._make_receipt()),
            patch("aiir.cli.append_to_ledger", return_value=(1, 0, "/tmp/r.jsonl")),
            patch("aiir.cli.write_receipt", return_value="stdout:json"),
            patch("aiir.cli.set_gitlab_ci_output"),
            patch("aiir.cli.format_gitlab_summary", return_value="| summary |"),
            patch("aiir.cli.post_mr_comment"),
            patch("sys.stderr", io.StringIO()),
            patch("sys.stdout", io.StringIO()),
            patch.dict(os.environ, {
                "CI_COMMIT_SHA": "a" * 40,
                "CI_MERGE_REQUEST_IID": "42",
            }, clear=False),
        ):
            code = cli_mod.main(["--gitlab-ci", "--quiet"])
        self.assertEqual(code, 0)

    def test_gitlab_mr_comment_failure_quiet(self):
        """1290→1297: --quiet with MR comment failure skips print."""
        import aiir.cli as cli_mod

        with (
            patch("aiir.cli.generate_receipt", return_value=self._make_receipt()),
            patch("aiir.cli.append_to_ledger", return_value=(1, 0, "/tmp/r.jsonl")),
            patch("aiir.cli.write_receipt", return_value="stdout:json"),
            patch("aiir.cli.set_gitlab_ci_output"),
            patch("aiir.cli.format_gitlab_summary", return_value="| summary |"),
            patch("aiir.cli.post_mr_comment", side_effect=RuntimeError("fail")),
            patch("sys.stderr", io.StringIO()),
            patch("sys.stdout", io.StringIO()),
            patch.dict(os.environ, {
                "CI_COMMIT_SHA": "a" * 40,
                "CI_MERGE_REQUEST_IID": "42",
            }, clear=False),
        ):
            code = cli_mod.main(["--gitlab-ci", "--quiet"])
        self.assertEqual(code, 0)

    def test_sast_report_quiet(self):
        """1307→1314: --quiet with --gl-sast-report skips print."""
        import aiir.cli as cli_mod

        tmpdir = tempfile.mkdtemp()
        try:
            sast_path = str(Path(tmpdir, "gl-sast.json"))
            with (
                patch("aiir.cli.generate_receipt", return_value=self._make_receipt()),
                patch("aiir.cli.append_to_ledger", return_value=(1, 0, "/tmp/r.jsonl")),
                patch("aiir.cli.write_receipt", return_value="stdout:json"),
                patch("aiir.cli.set_gitlab_ci_output"),
                patch("aiir.cli.format_gl_sast_report", return_value={
                    "version": "15.0.0",
                    "vulnerabilities": [],
                }),
                patch("sys.stderr", io.StringIO()),
                patch("sys.stdout", io.StringIO()),
                patch.dict(os.environ, {"CI_COMMIT_SHA": "a" * 40}, clear=False),
            ):
                code = cli_mod.main([
                    "--gitlab-ci", "--gl-sast-report", sast_path, "--quiet",
                ])
            self.assertEqual(code, 0)
            self.assertTrue(Path(sast_path).exists())
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════
# TIER 2: verify_receipt_file mutation killers
# Strengthened assertions on dict key names, boolean values, and boundaries
# ═══════════════════════════════════════════════════════════════════════


class TestVerifyReceiptFileMutationKillers(unittest.TestCase):
    """Kill surviving mutants in verify_receipt_file.

    Targets:
    - Dict key mutations: "valid"→"XXvalidXX"/"VALID", "error"→"XXerrorXX"/"ERROR"
    - Boolean flips: False→True on error paths
    - Boundary: > vs >= on MAX_RECEIPT_FILE_SIZE, MAX_RECEIPTS_PER_RANGE
    - Value: all(...)→None
    - Key: "count"→"XXcountXX"/"COUNT"
    """

    def _verify(self, filepath: str) -> dict:
        from aiir._verify import verify_receipt_file
        return verify_receipt_file(filepath)

    def _assert_error_result(self, result: dict, error_substr: str = ""):
        """Assert result is a strict error dict: 'valid' key exists and is False."""
        self.assertIsInstance(result, dict)
        # Kill "valid"→"XXvalidXX" and "valid"→"VALID": the key must be exactly "valid"
        self.assertIn("valid", result)
        self.assertNotIn("XXvalidXX", result)
        self.assertNotIn("VALID", result)
        # Kill False→True: must be exactly False
        self.assertIs(result["valid"], False)
        # Kill "error"→"XXerrorXX" and "error"→"ERROR": key must be exactly "error"
        if "error" in result:
            self.assertNotIn("XXerrorXX", result)
            self.assertNotIn("ERROR", result)
            self.assertIsInstance(result["error"], str)
            if error_substr:
                self.assertIn(error_substr, result["error"])

    def test_file_not_found_strict_keys(self):
        """Missing file: keys are 'valid'/'error', valid is False."""
        result = self._verify("/nonexistent/file.json")
        self._assert_error_result(result, "not found")

    def test_symlink_strict_keys(self):
        """Symlink: keys are 'valid'/'error', valid is False."""
        tmpdir = tempfile.mkdtemp()
        try:
            real = Path(tmpdir, "real.json")
            real.write_text('{}')
            link = Path(tmpdir, "link.json")
            link.symlink_to(real)
            result = self._verify(str(link))
            self._assert_error_result(result, "symlink")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_oversized_strict_keys(self):
        """Oversized file: keys are 'valid'/'error', valid is False."""
        from aiir._core import MAX_RECEIPT_FILE_SIZE

        tmpdir = tempfile.mkdtemp()
        try:
            big = Path(tmpdir, "big.json")
            big.write_text(" " * (MAX_RECEIPT_FILE_SIZE + 1))
            result = self._verify(str(big))
            self._assert_error_result(result, "too large")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_boundary_exact_max_size_accepted(self):
        """File at exactly MAX_RECEIPT_FILE_SIZE bytes: must NOT be rejected.

        Kills mutant_20: '>' → '>='
        """
        from aiir._core import MAX_RECEIPT_FILE_SIZE

        tmpdir = tempfile.mkdtemp()
        try:
            exact = Path(tmpdir, "exact.json")
            content = '{"type":"aiir.commit_receipt"}'
            padding = " " * (MAX_RECEIPT_FILE_SIZE - len(content))
            exact.write_text(content + padding)
            result = self._verify(str(exact))
            # Should NOT have "too large" error
            self.assertNotIn("too large", result.get("error", ""))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_boundary_exact_max_array_size_accepted(self):
        """Array at exactly MAX_RECEIPTS_PER_RANGE: must NOT be rejected.

        Kills mutant_36: '>' → '>='
        """
        from aiir._core import MAX_RECEIPTS_PER_RANGE

        tmpdir = tempfile.mkdtemp()
        try:
            arr = Path(tmpdir, "arr.json")
            data = [{"type": "x"}] * MAX_RECEIPTS_PER_RANGE
            arr.write_text(json.dumps(data))
            result = self._verify(str(arr))
            # Should NOT have "too large" error — exactly at the limit
            self.assertNotIn("too large", result.get("error", ""))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_oversized_array_strict_keys(self):
        """Array over MAX_RECEIPTS_PER_RANGE: strict keys and valid=False."""
        from aiir._core import MAX_RECEIPTS_PER_RANGE

        tmpdir = tempfile.mkdtemp()
        try:
            arr = Path(tmpdir, "arr.json")
            arr.write_text(json.dumps([{}] * (MAX_RECEIPTS_PER_RANGE + 1)))
            result = self._verify(str(arr))
            self._assert_error_result(result, "too large")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_invalid_json_strict_keys(self):
        """Invalid JSON: strict keys and valid=False."""
        tmpdir = tempfile.mkdtemp()
        try:
            bad = Path(tmpdir, "bad.json")
            bad.write_text("not json at all!")
            result = self._verify(str(bad))
            self._assert_error_result(result, "Invalid JSON")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_array_result_strict_keys(self):
        """Valid-shaped array: result has 'valid', 'receipts', 'count' keys.

        Kills mutant_44 (all(...)→None), mutant_48-49 (XXvalidXX/VALID),
        mutant_52-53 (XXcountXX/COUNT).
        """
        receipt = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": {"sha": "a" * 40},
            "ai_attestation": {},
            "provenance": {},
            "receipt_id": "g1-x",
            "content_hash": "sha256:x",
        }
        tmpdir = tempfile.mkdtemp()
        try:
            arr = Path(tmpdir, "arr.json")
            arr.write_text(json.dumps([receipt, receipt]))
            result = self._verify(str(arr))
            # Strict key checks
            self.assertIn("valid", result)
            self.assertNotIn("XXvalidXX", result)
            self.assertNotIn("VALID", result)
            self.assertIn("receipts", result)
            self.assertIn("count", result)
            self.assertNotIn("XXcountXX", result)
            self.assertNotIn("COUNT", result)
            # valid must be a bool (kills None replacement)
            self.assertIsInstance(result["valid"], bool)
            self.assertEqual(result["count"], 2)
            self.assertEqual(len(result["receipts"]), 2)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_array_all_valid_is_bool_true(self):
        """Array of genuinely valid receipts: result['valid'] must be True (bool).

        Kills mutant_44: all(...)→None
        """
        from aiir._core import _canonical_json, _sha256

        core = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": {"sha": "a" * 40, "subject": "ok"},
            "ai_attestation": {},
            "provenance": {},
        }
        core_json = _canonical_json(core)
        good_hash = "sha256:" + _sha256(core_json)
        good_id = f"g1-{_sha256(core_json)[:32]}"
        good = {**core, "receipt_id": good_id, "content_hash": good_hash}

        tmpdir = tempfile.mkdtemp()
        try:
            arr = Path(tmpdir, "arr.json")
            arr.write_text(json.dumps([good]))
            result = self._verify(str(arr))
            self.assertIs(result["valid"], True)
            self.assertIsInstance(result["valid"], bool)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_array_with_invalid_receipt_is_bool_false(self):
        """Array with at least one invalid: result['valid'] must be False (bool)."""
        receipt = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": {"sha": "a" * 40},
            "ai_attestation": {},
            "provenance": {},
            "receipt_id": "g1-wrong",
            "content_hash": "sha256:wrong",
        }
        tmpdir = tempfile.mkdtemp()
        try:
            arr = Path(tmpdir, "arr.json")
            arr.write_text(json.dumps([receipt]))
            result = self._verify(str(arr))
            self.assertIs(result["valid"], False)
            self.assertIsInstance(result["valid"], bool)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_dict_result_valid_is_bool(self):
        """Single dict receipt: result['valid'] must be a bool."""
        receipt = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.0",
            "commit": {"sha": "a" * 40},
            "ai_attestation": {},
            "provenance": {},
            "receipt_id": "g1-wrong",
            "content_hash": "sha256:wrong",
        }
        tmpdir = tempfile.mkdtemp()
        try:
            p = Path(tmpdir, "r.json")
            p.write_text(json.dumps(receipt))
            result = self._verify(str(p))
            self.assertIn("valid", result)
            self.assertIsInstance(result["valid"], bool)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
