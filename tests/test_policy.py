"""
Tests for aiir._policy — policy engine.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from aiir._policy import (
    POLICY_PRESETS,
    ENFORCEMENT_LEVELS,
    load_policy,
    save_policy,
    init_policy,
    evaluate_receipt_policy,
    evaluate_ledger_policy,
    format_policy_report,
    PolicyViolation,
)


class TestPolicyPresets(unittest.TestCase):
    """Test that presets are well-formed."""

    def test_all_presets_exist(self):
        self.assertIn("strict", POLICY_PRESETS)
        self.assertIn("balanced", POLICY_PRESETS)
        self.assertIn("permissive", POLICY_PRESETS)

    def test_presets_have_required_keys(self):
        required = {"enforcement", "max_ai_percent", "require_signing"}
        for name, preset in POLICY_PRESETS.items():
            for key in required:
                self.assertIn(key, preset, f"Preset '{name}' missing key '{key}'")

    def test_enforcement_levels_valid(self):
        for name, preset in POLICY_PRESETS.items():
            self.assertIn(
                preset["enforcement"], ENFORCEMENT_LEVELS,
                f"Preset '{name}' has invalid enforcement level",
            )

    def test_strict_requires_signing(self):
        self.assertTrue(POLICY_PRESETS["strict"]["require_signing"])

    def test_permissive_no_signing(self):
        self.assertFalse(POLICY_PRESETS["permissive"]["require_signing"])


class TestLoadPolicy(unittest.TestCase):
    """Test policy loading."""

    def test_load_by_preset_name(self):
        policy = load_policy(preset="strict")
        self.assertTrue(policy["require_signing"])
        self.assertEqual(policy["preset"], "strict")

    def test_load_unknown_preset_raises(self):
        with self.assertRaises(ValueError):
            load_policy(preset="nonexistent")

    def test_default_is_balanced(self):
        with tempfile.TemporaryDirectory() as td:
            policy = load_policy(ledger_dir=td)
            self.assertEqual(policy["preset"], "balanced")

    def test_load_from_file(self):
        with tempfile.TemporaryDirectory() as td:
            policy_path = Path(td) / "policy.json"
            policy_path.write_text(json.dumps({
                "enforcement": "hard-fail",
                "require_signing": True,
                "max_ai_percent": 25.0,
            }))
            policy = load_policy(ledger_dir=td)
            self.assertEqual(policy["enforcement"], "hard-fail")
            self.assertTrue(policy["require_signing"])
            self.assertEqual(policy["max_ai_percent"], 25.0)

    def test_load_file_with_preset_overlay(self):
        with tempfile.TemporaryDirectory() as td:
            policy_path = Path(td) / "policy.json"
            policy_path.write_text(json.dumps({
                "preset": "strict",
                "max_ai_percent": 30.0,  # override strict's 50%
            }))
            policy = load_policy(ledger_dir=td)
            self.assertTrue(policy["require_signing"])  # from strict
            self.assertEqual(policy["max_ai_percent"], 30.0)  # overridden

    def test_load_invalid_json_raises(self):
        with tempfile.TemporaryDirectory() as td:
            policy_path = Path(td) / "policy.json"
            policy_path.write_text("not json{{{")
            with self.assertRaises(ValueError):
                load_policy(ledger_dir=td)


class TestSavePolicy(unittest.TestCase):
    def test_save_and_reload(self):
        with tempfile.TemporaryDirectory() as td:
            policy = {"enforcement": "warn", "max_ai_percent": 90.0}
            path = save_policy(policy, ledger_dir=td)
            self.assertTrue(Path(path).exists())
            loaded = json.loads(Path(path).read_text())
            self.assertEqual(loaded["enforcement"], "warn")


class TestInitPolicy(unittest.TestCase):
    def test_init_creates_file(self):
        with tempfile.TemporaryDirectory() as td:
            policy, path = init_policy(preset="strict", ledger_dir=td)
            self.assertTrue(Path(path).exists())
            self.assertEqual(policy["preset"], "strict")

    def test_init_unknown_preset_raises(self):
        with self.assertRaises(ValueError):
            init_policy(preset="imaginary")


class TestEvaluateReceiptPolicy(unittest.TestCase):
    """Test per-receipt policy evaluation."""

    def _make_receipt(self, **overrides):
        r = {
            "type": "aiir.commit_receipt",
            "schema": "aiir/commit_receipt.v1",
            "version": "1.0.12",
            "commit": {"sha": "a" * 40},
            "ai_attestation": {
                "is_ai_authored": False,
                "authorship_class": "human",
            },
            "provenance": {
                "repository": "https://github.com/example/repo",
                "tool": "https://github.com/invariant-systems-ai/aiir@1.0.12",
                "generator": "aiir.cli",
            },
            "extensions": {},
        }
        r.update(overrides)
        return r

    def test_strict_unsigned_fails(self):
        policy = POLICY_PRESETS["strict"]
        r = self._make_receipt()
        violations = evaluate_receipt_policy(r, policy, is_signed=False)
        rules = [v.rule for v in violations]
        self.assertIn("require_signing", rules)

    def test_strict_signed_passes_signing(self):
        policy = POLICY_PRESETS["strict"]
        r = self._make_receipt()
        violations = evaluate_receipt_policy(r, policy, is_signed=True)
        rules = [v.rule for v in violations]
        self.assertNotIn("require_signing", rules)

    def test_strict_no_repo_fails(self):
        policy = POLICY_PRESETS["strict"]
        r = self._make_receipt(provenance={"repository": None, "tool": "x", "generator": "y"})
        violations = evaluate_receipt_policy(r, policy, is_signed=True)
        rules = [v.rule for v in violations]
        self.assertIn("require_provenance_repo", rules)

    def test_disallowed_authorship_class(self):
        policy = {**POLICY_PRESETS["strict"]}
        r = self._make_receipt(ai_attestation={
            "authorship_class": "ai_generated",
            "is_ai_authored": True,
        })
        violations = evaluate_receipt_policy(r, policy, is_signed=True)
        rules = [v.rule for v in violations]
        self.assertIn("allowed_authorship_classes", rules)

    def test_permissive_allows_everything(self):
        policy = POLICY_PRESETS["permissive"]
        r = self._make_receipt(ai_attestation={
            "authorship_class": "ai_generated",
            "is_ai_authored": True,
        })
        violations = evaluate_receipt_policy(r, policy, is_signed=False)
        self.assertEqual(violations, [])

    def test_schema_validity_required(self):
        policy = {**POLICY_PRESETS["strict"]}
        r = self._make_receipt()
        violations = evaluate_receipt_policy(
            r, policy, is_signed=True,
            schema_errors=["some error"],
        )
        rules = [v.rule for v in violations]
        self.assertIn("require_schema_valid", rules)


class TestEvaluateLedgerPolicy(unittest.TestCase):
    """Test aggregate ledger-level policy evaluation."""

    def test_ai_percent_exceeded_strict(self):
        index = {"receipt_count": 100, "ai_commit_count": 60, "ai_percentage": 60.0}
        policy = {**POLICY_PRESETS["strict"]}  # max_ai_percent = 50
        passed, msg, violations = evaluate_ledger_policy(index, policy)
        self.assertFalse(passed)
        self.assertIn("FAIL", msg)

    def test_ai_percent_within_threshold(self):
        index = {"receipt_count": 100, "ai_commit_count": 30, "ai_percentage": 30.0}
        policy = {**POLICY_PRESETS["strict"]}
        passed, msg, violations = evaluate_ledger_policy(index, policy)
        self.assertTrue(passed)
        self.assertIn("PASS", msg)

    def test_warn_enforcement_passes_with_violations(self):
        index = {"receipt_count": 100, "ai_commit_count": 90, "ai_percentage": 90.0}
        policy = {**POLICY_PRESETS["permissive"]}  # enforcement=warn, max_ai_percent=100
        # Manually lower threshold to trigger violation
        policy["max_ai_percent"] = 50.0
        passed, msg, violations = evaluate_ledger_policy(index, policy)
        # warn mode: violations exist but still passes
        self.assertTrue(passed)
        self.assertIn("WARN", msg)


class TestFormatPolicyReport(unittest.TestCase):
    def test_no_violations(self):
        text = format_policy_report([], enforcement="strict")
        self.assertIn("passed", text)

    def test_with_violations(self):
        violations = [
            PolicyViolation("test_rule", "test message", "error", "fix it"),
        ]
        text = format_policy_report(violations, enforcement="hard-fail")
        self.assertIn("test_rule", text)
        self.assertIn("test message", text)
        self.assertIn("fix it", text)

    def test_violation_to_dict(self):
        v = PolicyViolation("r1", "msg", "error", "fix")
        d = v.to_dict()
        self.assertEqual(d["rule"], "r1")
        self.assertEqual(d["remediation"], "fix")


if __name__ == "__main__":
    unittest.main()
