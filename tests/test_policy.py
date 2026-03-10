"""
Tests for aiir._policy — policy engine.

Copyright 2025-2026 Invariant Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
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
                preset["enforcement"],
                ENFORCEMENT_LEVELS,
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
            policy_path.write_text(
                json.dumps(
                    {
                        "enforcement": "hard-fail",
                        "require_signing": True,
                        "max_ai_percent": 25.0,
                    }
                )
            )
            policy = load_policy(ledger_dir=td)
            self.assertEqual(policy["enforcement"], "hard-fail")
            self.assertTrue(policy["require_signing"])
            self.assertEqual(policy["max_ai_percent"], 25.0)

    def test_load_file_with_preset_overlay(self):
        with tempfile.TemporaryDirectory() as td:
            policy_path = Path(td) / "policy.json"
            policy_path.write_text(
                json.dumps(
                    {
                        "preset": "strict",
                        "max_ai_percent": 30.0,  # override strict's 50%
                    }
                )
            )
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
        r = self._make_receipt(
            provenance={"repository": None, "tool": "x", "generator": "y"}
        )
        violations = evaluate_receipt_policy(r, policy, is_signed=True)
        rules = [v.rule for v in violations]
        self.assertIn("require_provenance_repo", rules)

    def test_disallowed_authorship_class(self):
        policy = {**POLICY_PRESETS["strict"]}
        r = self._make_receipt(
            ai_attestation={
                "authorship_class": "ai_generated",
                "is_ai_authored": True,
            }
        )
        violations = evaluate_receipt_policy(r, policy, is_signed=True)
        rules = [v.rule for v in violations]
        self.assertIn("allowed_authorship_classes", rules)

    def test_permissive_allows_everything(self):
        policy = POLICY_PRESETS["permissive"]
        r = self._make_receipt(
            ai_attestation={
                "authorship_class": "ai_generated",
                "is_ai_authored": True,
            }
        )
        violations = evaluate_receipt_policy(r, policy, is_signed=False)
        self.assertEqual(violations, [])

    def test_schema_validity_required(self):
        policy = {**POLICY_PRESETS["strict"]}
        r = self._make_receipt()
        violations = evaluate_receipt_policy(
            r,
            policy,
            is_signed=True,
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
        policy = {
            **POLICY_PRESETS["permissive"]
        }  # enforcement=warn, max_ai_percent=100
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


# ---------------------------------------------------------------------------
# Mutation-killing tests
# ---------------------------------------------------------------------------


class TestPolicyMutationKillers(unittest.TestCase):
    """Tests targeting specific surviving mutants in _policy.py.

    Each test kills one or more mutant classes that line-coverage
    tests miss due to weak or missing assertions.
    """

    # ------------------------------------------------------------------
    # load_policy: directory name, filename, encoding, error messages
    # ------------------------------------------------------------------

    def test_load_default_dir_is_dotaiir(self):
        """Default ledger_dir must be '.aiir' (not '.AIIR' or 'XX.aiirXX')."""
        with tempfile.TemporaryDirectory() as td:
            aiir_dir = Path(td) / ".aiir"
            aiir_dir.mkdir()
            policy = {"enforcement": "hard-fail"}
            (aiir_dir / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
            loaded = load_policy(ledger_dir=str(aiir_dir))
            self.assertEqual(loaded["enforcement"], "hard-fail")

    def test_load_unknown_preset_error_message_exact(self):
        """Error message must contain the exact preset name and list."""
        with self.assertRaises(ValueError) as cm:
            load_policy(preset="nonexistent")
        err = str(cm.exception)
        self.assertIn("nonexistent", err)
        self.assertIn("strict", err)
        self.assertIn("balanced", err)
        self.assertIn("permissive", err)
        # Separator must be ", " not "XX, XX"
        self.assertIn(", ", err)
        self.assertNotIn("XX", err)

    def test_load_reads_utf8_encoding(self):
        """Policy file must be read with utf-8 encoding specifically."""
        with tempfile.TemporaryDirectory() as td:
            policy_path = Path(td) / "policy.json"
            # Write a policy with a non-ASCII char to verify encoding works
            policy = {"description": "Richtlinie — strict"}
            policy_path.write_text(json.dumps(policy, ensure_ascii=False), encoding="utf-8")
            loaded = load_policy(ledger_dir=td)
            self.assertIn("Richtlinie", loaded["description"])

    def test_load_nondict_raises(self):
        """Policy file containing a non-dict must raise ValueError."""
        with tempfile.TemporaryDirectory() as td:
            policy_path = Path(td) / "policy.json"
            policy_path.write_text(json.dumps([1, 2, 3]))
            with self.assertRaises(ValueError) as cm:
                load_policy(ledger_dir=td)
            self.assertIn(str(policy_path), str(cm.exception))

    def test_load_invalid_json_error_includes_path(self):
        """ValueError from bad JSON must mention the file path."""
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "policy.json").write_text("{bad json")
            with self.assertRaises(ValueError) as cm:
                load_policy(ledger_dir=td)
            self.assertIn("Invalid policy file", str(cm.exception))

    def test_load_and_vs_or_file_check(self):
        """load_policy must require BOTH exists() AND is_file()."""
        with tempfile.TemporaryDirectory() as td:
            # Create policy.json as a directory (not a file)
            (Path(td) / "policy.json").mkdir()
            # Should NOT try to read it, should fall back to balanced
            policy = load_policy(ledger_dir=td)
            self.assertEqual(policy.get("preset"), "balanced")

    # ------------------------------------------------------------------
    # save_policy: directory name, filename, encoding, mkdir params
    # ------------------------------------------------------------------

    def test_save_creates_exact_filename(self):
        """save_policy must write to 'policy.json' (not 'POLICY.JSON')."""
        with tempfile.TemporaryDirectory() as td:
            path = save_policy({"enforcement": "warn"}, ledger_dir=td)
            self.assertTrue(path.endswith("policy.json"))
            self.assertTrue(Path(path).is_file())

    def test_save_creates_parent_dirs(self):
        """save_policy must create parent dirs with parents=True."""
        with tempfile.TemporaryDirectory() as td:
            nested = str(Path(td) / "a" / "b" / "c")
            path = save_policy({"x": 1}, ledger_dir=nested)
            self.assertTrue(Path(path).is_file())

    def test_save_writes_utf8(self):
        """save_policy must write UTF-8, preserving non-ASCII chars."""
        with tempfile.TemporaryDirectory() as td:
            save_policy({"note": "Schöne Grüße"}, ledger_dir=td)
            raw = (Path(td) / "policy.json").read_bytes()
            self.assertIn("Schöne".encode("utf-8"), raw)

    def test_save_default_ledger_dir_is_dotaiir(self):
        """Default ledger_dir must be '.aiir' (not '.AIIR')."""
        import inspect
        sig = inspect.signature(save_policy)
        self.assertEqual(sig.parameters["ledger_dir"].default, ".aiir")

    # ------------------------------------------------------------------
    # init_policy: preset default, save delegation, error message
    # ------------------------------------------------------------------

    def test_init_default_preset_is_balanced(self):
        """Default preset must be 'balanced' (not 'BALANCED')."""
        import inspect
        sig = inspect.signature(init_policy)
        self.assertEqual(sig.parameters["preset"].default, "balanced")

    def test_init_default_ledger_dir_is_dotaiir(self):
        """Default ledger_dir must be '.aiir'."""
        import inspect
        sig = inspect.signature(init_policy)
        self.assertEqual(sig.parameters["ledger_dir"].default, ".aiir")

    def test_init_saves_policy_correctly(self):
        """init_policy must pass (policy, ledger_dir) to save_policy."""
        with tempfile.TemporaryDirectory() as td:
            policy, path = init_policy(preset="strict", ledger_dir=td)
            # The file must exist and contain the strict preset
            loaded = json.loads(Path(path).read_text())
            self.assertEqual(loaded["preset"], "strict")
            self.assertTrue(loaded["require_signing"])

    def test_init_unknown_preset_error_message(self):
        """Error must list all valid presets."""
        with self.assertRaises(ValueError) as cm:
            init_policy(preset="fantasy")
        err = str(cm.exception)
        self.assertIn("fantasy", err)
        self.assertIn(", ", err)
        self.assertNotIn("XX", err)

    def test_init_returns_path(self):
        """init_policy must return both the policy dict and the path."""
        with tempfile.TemporaryDirectory() as td:
            policy, path = init_policy(preset="permissive", ledger_dir=td)
            self.assertIsInstance(policy, dict)
            self.assertTrue(Path(path).exists())

    # ------------------------------------------------------------------
    # evaluate_ledger_policy: enforcement default, index keys, boundaries
    # ------------------------------------------------------------------

    def test_ledger_enforcement_default_is_warn(self):
        """Missing enforcement key must default to 'warn' (not 'WARN')."""
        index = {"receipt_count": 10, "ai_commit_count": 8, "ai_percentage": 80.0}
        policy = {"max_ai_percent": 50.0}  # No enforcement key
        passed, msg, violations = evaluate_ledger_policy(index, policy)
        # warn mode: passes even with violations
        self.assertTrue(passed)
        self.assertIn("WARN", msg)

    def test_ledger_ai_percentage_key_exact(self):
        """Index key must be 'ai_percentage' (not 'AI_PERCENTAGE')."""
        index = {"receipt_count": 10, "ai_percentage": 90.0}
        policy = {"max_ai_percent": 50.0, "enforcement": "hard-fail"}
        passed, _, violations = evaluate_ledger_policy(index, policy)
        self.assertFalse(passed)
        self.assertTrue(len(violations) > 0)

    def test_ledger_receipt_count_key_exact(self):
        """Index key must be 'receipt_count' (not 'RECEIPT_COUNT')."""
        index = {"receipt_count": 10, "ai_percentage": 90.0}
        policy = {"max_ai_percent": 50.0, "enforcement": "hard-fail"}
        passed, _, violations = evaluate_ledger_policy(index, policy)
        self.assertFalse(passed)

    def test_ledger_zero_receipts_no_violation(self):
        """Zero receipts must NOT trigger a violation (boundary: > 0)."""
        index = {"receipt_count": 0, "ai_percentage": 100.0}
        policy = {"max_ai_percent": 50.0, "enforcement": "hard-fail"}
        passed, msg, violations = evaluate_ledger_policy(index, policy)
        self.assertTrue(passed)
        self.assertEqual(violations, [])

    def test_ledger_one_receipt_triggers_violation(self):
        """One receipt with high AI% must trigger violation (boundary: > 0)."""
        index = {"receipt_count": 1, "ai_percentage": 100.0, "ai_commit_count": 1}
        policy = {"max_ai_percent": 50.0, "enforcement": "hard-fail"}
        passed, _, violations = evaluate_ledger_policy(index, policy)
        self.assertFalse(passed)
        self.assertTrue(len(violations) > 0)

    def test_ledger_ai_pct_equal_to_max_passes(self):
        """AI% == max_ai_percent must pass (boundary: > not >=)."""
        index = {"receipt_count": 10, "ai_percentage": 50.0}
        policy = {"max_ai_percent": 50.0, "enforcement": "hard-fail"}
        passed, msg, violations = evaluate_ledger_policy(index, policy)
        self.assertTrue(passed)
        self.assertEqual(violations, [])

    def test_ledger_and_not_or_logic(self):
        """Both total > 0 AND ai_pct > max must hold (not OR)."""
        # ai_pct > max but total == 0 → no violation (AND logic)
        index = {"receipt_count": 0, "ai_percentage": 100.0}
        policy = {"max_ai_percent": 10.0, "enforcement": "hard-fail"}
        passed, _, violations = evaluate_ledger_policy(index, policy)
        self.assertTrue(passed)
        self.assertEqual(violations, [])

    def test_ledger_violation_rule_name(self):
        """Violation rule must be 'max_ai_percent' exactly."""
        index = {"receipt_count": 10, "ai_percentage": 90.0, "ai_commit_count": 9}
        policy = {"max_ai_percent": 50.0, "enforcement": "hard-fail"}
        _, _, violations = evaluate_ledger_policy(index, policy)
        self.assertEqual(violations[0].rule, "max_ai_percent")

    def test_ledger_violation_severity_is_error(self):
        """Violation severity must be 'error' (not 'XXerrorXX')."""
        index = {"receipt_count": 10, "ai_percentage": 90.0}
        policy = {"max_ai_percent": 50.0, "enforcement": "hard-fail"}
        _, _, violations = evaluate_ledger_policy(index, policy)
        self.assertEqual(violations[0].severity, "error")

    def test_ledger_violation_message_has_counts(self):
        """Violation message must include ai_commit_count and total."""
        index = {"receipt_count": 42, "ai_percentage": 90.0, "ai_commit_count": 38}
        policy = {"max_ai_percent": 50.0, "enforcement": "hard-fail"}
        _, _, violations = evaluate_ledger_policy(index, policy)
        msg = violations[0].message
        self.assertIn("38", msg)  # ai_commit_count
        self.assertIn("42", msg)  # total
        self.assertIn("90.0", msg)  # ai_pct
        self.assertIn("50.0", msg)  # max_ai

    def test_ledger_ai_commit_count_key_exact(self):
        """ai_commit_count key in message must match exactly."""
        index = {"receipt_count": 5, "ai_percentage": 100.0, "ai_commit_count": 5}
        policy = {"max_ai_percent": 10.0, "enforcement": "hard-fail"}
        _, _, violations = evaluate_ledger_policy(index, policy)
        self.assertIn("5/5", violations[0].message)

    def test_ledger_missing_ai_commit_count_defaults_zero(self):
        """Missing ai_commit_count should default to 0 in the message."""
        index = {"receipt_count": 5, "ai_percentage": 100.0}
        policy = {"max_ai_percent": 10.0, "enforcement": "hard-fail"}
        _, _, violations = evaluate_ledger_policy(index, policy)
        self.assertIn("0/5", violations[0].message)

    def test_ledger_soft_fail_enforcement(self):
        """soft-fail must return passed=False with SOFT-FAIL in message."""
        index = {"receipt_count": 10, "ai_percentage": 90.0}
        policy = {"max_ai_percent": 50.0, "enforcement": "soft-fail"}
        passed, msg, violations = evaluate_ledger_policy(index, policy)
        self.assertFalse(passed)
        self.assertIn("SOFT-FAIL", msg)

    def test_ledger_none_max_ai_skips_check(self):
        """Policy with no max_ai_percent must skip the AI% check."""
        index = {"receipt_count": 100, "ai_percentage": 100.0}
        policy = {"enforcement": "hard-fail"}  # no max_ai_percent
        passed, msg, violations = evaluate_ledger_policy(index, policy)
        self.assertTrue(passed)
        self.assertEqual(violations, [])

    def test_ledger_non_numeric_max_ai_coercion(self):
        """Non-numeric max_ai_percent must be coerced to None (skip)."""
        index = {"receipt_count": 100, "ai_percentage": 100.0}
        policy = {"max_ai_percent": "not-a-number", "enforcement": "hard-fail"}
        passed, msg, violations = evaluate_ledger_policy(index, policy)
        # Should skip the check, not crash
        self.assertTrue(passed)
        self.assertEqual(violations, [])

    # ------------------------------------------------------------------
    # format_policy_report: enumeration, icons, exact text
    # ------------------------------------------------------------------

    def test_report_no_violations_exact_text(self):
        """Empty violations must return exact sentence."""
        text = format_policy_report([])
        self.assertEqual(text, "All policy checks passed.")

    def test_report_enumeration_starts_at_one(self):
        """Violations numbering must start at 1."""
        violations = [
            PolicyViolation("rule_a", "msg a", "error"),
            PolicyViolation("rule_b", "msg b", "warning"),
        ]
        text = format_policy_report(violations)
        lines = text.split("\n")
        # Both rules must appear
        self.assertTrue(any("rule_a" in l for l in lines))
        self.assertTrue(any("rule_b" in l for l in lines))

    def test_report_error_icon_is_exclamation(self):
        """Error severity must use '!' icon (not '~' or None)."""
        violations = [PolicyViolation("r", "m", "error")]
        text = format_policy_report(violations, enforcement="hard-fail")
        self.assertIn("[!]", text)
        self.assertNotIn("[~]", text)

    def test_report_warning_icon_is_tilde(self):
        """Non-error severity must use '~' icon."""
        violations = [PolicyViolation("r", "m", "warning")]
        text = format_policy_report(violations, enforcement="warn")
        self.assertIn("[~]", text)
        self.assertNotIn("[!]", text)

    def test_report_enforcement_default_is_warn(self):
        """Default enforcement param must be 'warn'."""
        import inspect
        sig = inspect.signature(format_policy_report)
        self.assertEqual(sig.parameters["enforcement"].default, "warn")

    def test_report_includes_enforcement_label(self):
        """Report must include the enforcement mode."""
        violations = [PolicyViolation("r", "m", "error")]
        text = format_policy_report(violations, enforcement="hard-fail")
        self.assertIn("hard-fail", text)

    def test_report_remediation_displayed(self):
        """Remediation text must appear if provided."""
        violations = [PolicyViolation("r", "m", "error", "do this fix")]
        text = format_policy_report(violations)
        self.assertIn("do this fix", text)
        self.assertIn("Fix:", text)

    # ------------------------------------------------------------------
    # PolicyViolation.to_dict: key names, optional remediation
    # ------------------------------------------------------------------

    def test_to_dict_exact_keys(self):
        """to_dict must have exactly 'rule', 'message', 'severity' keys."""
        v = PolicyViolation("r1", "msg1", "error")
        d = v.to_dict()
        self.assertIn("rule", d)
        self.assertIn("message", d)
        self.assertIn("severity", d)
        # No remediation if empty
        self.assertNotIn("remediation", d)

    def test_to_dict_with_remediation(self):
        """to_dict must include 'remediation' when non-empty."""
        v = PolicyViolation("r2", "msg2", "warning", "fix it")
        d = v.to_dict()
        self.assertEqual(d["remediation"], "fix it")

    def test_to_dict_key_names_lowercase(self):
        """Dict keys must be lowercase (not 'RULE', 'MESSAGE', etc.)."""
        v = PolicyViolation("r", "m", "error", "fix")
        d = v.to_dict()
        for key in ("rule", "message", "severity", "remediation"):
            self.assertIn(key, d)
            self.assertNotIn(key.upper(), d)

    def test_to_dict_no_remediation_excluded(self):
        """Empty remediation must NOT appear in dict."""
        v = PolicyViolation("r", "m", "error", "")
        d = v.to_dict()
        self.assertEqual(set(d.keys()), {"rule", "message", "severity"})


if __name__ == "__main__":
    unittest.main()
