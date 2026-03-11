"""Tests for the Enterprise Protected Branch Profile — schemas, validator, and
cross-references.

These are intentionally *self-healing*: they assert structural invariants so
that any future schema edit, rule rename, or doc drift breaks the right tests
immediately and tells you exactly what to fix.

Copyright 2025-2026 Invariant Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""
from __future__ import annotations

import copy
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"
DOCS = ROOT / "docs"
SCRIPTS = ROOT / "scripts"


# ── Fixtures ──────────────────────────────────────────────────────────

def _minimal_profile(*, enabled: bool = True) -> dict:
    """Return a minimal valid profile configuration."""
    rules = {}
    for i in range(1, 13):
        rid = f"EPB-{i:03d}"
        rules[rid] = {"enabled": enabled}
    # Add required parameters for conditionally-required rules
    rules["EPB-004"]["min_trust_tier"] = 2
    rules["EPB-005"]["require_dag_binding"] = True
    rules["EPB-006"]["min_coverage_percent"] = 100
    rules["EPB-007"]["max_ai_percent"] = 50
    rules["EPB-011"]["expected_policy_digest"] = "a" * 64
    rules["EPB-012"]["trusted_verifiers"] = [
        "https://example.com/verifier"
    ]
    return {
        "profile": "aiir/enterprise_protected_branch.v1",
        "version": "1.0.0",
        "rules": rules,
    }


def _minimal_commit_receipt(
    *,
    sha: str = "a" * 40,
    is_ai: bool = False,
    tool: str = "https://github.com/invariant-systems-ai/aiir",
) -> dict:
    """Return a commit receipt with valid core fields."""
    receipt = {
        "type": "aiir.commit_receipt",
        "schema": "aiir/commit_receipt.v1",
        "version": "1.2.5",
        "commit": {
            "sha": sha,
            "author": {"name": "Test", "email": "test@example.com"},
            "committer": {"name": "Test", "email": "test@example.com"},
        },
        "ai_attestation": {
            "authorship_class": "ai_assisted" if is_ai else "human",
            "is_bot_authored": False,
            "bot_signals_detected": [],
        },
        "provenance": {
            "tool": tool,
            "generator": "aiir.cli",
        },
    }
    # Compute content_hash + receipt_id so EPB-003 passes
    import hashlib

    from scripts.validate_profile import _canonical_json

    core_keys = {"type", "schema", "version", "commit", "ai_attestation", "provenance"}
    core = {k: v for k, v in receipt.items() if k in core_keys}
    h = hashlib.sha256(_canonical_json(core).encode()).hexdigest()
    receipt["content_hash"] = f"sha256:{h}"
    receipt["receipt_id"] = f"g1-{h[:32]}"
    receipt["timestamp"] = "2026-01-01T00:00:00Z"
    receipt["extensions"] = {}
    return receipt


def _minimal_review_receipt(
    *,
    commit_sha: str = "a" * 40,
    outcome: str = "approved",
    reviewer_email: str = "reviewer@example.com",
) -> dict:
    """Return a review receipt with valid core fields."""
    import hashlib

    from scripts.validate_profile import _canonical_json

    receipt = {
        "type": "aiir.review_receipt",
        "schema": "aiir/review_receipt.v1",
        "version": "1.2.5",
        "reviewed_commit": {"sha": commit_sha},
        "reviewer": {"name": "Reviewer", "email": reviewer_email},
        "review_outcome": outcome,
        "comment": "Looks good",
        "provenance": {
            "tool": "https://github.com/invariant-systems-ai/aiir",
            "generator": "aiir.cli",
        },
    }
    core_keys = {
        "type", "schema", "version", "reviewed_commit", "reviewer",
        "review_outcome", "comment", "provenance",
    }
    core = {k: v for k, v in receipt.items() if k in core_keys}
    h = hashlib.sha256(_canonical_json(core).encode()).hexdigest()
    receipt["content_hash"] = f"sha256:{h}"
    receipt["receipt_id"] = f"g1-{h[:32]}"
    receipt["timestamp"] = "2026-01-01T00:00:00Z"
    receipt["extensions"] = {}
    return receipt


# ═══════════════════════════════════════════════════════════════════════
#  1. Schema structural health
# ═══════════════════════════════════════════════════════════════════════

class TestSchemaFiles(unittest.TestCase):
    """All schema files parse as valid JSON and contain expected fields."""

    EXPECTED_SCHEMAS = {
        "enterprise_profile.v1.schema.json",
        "decision_receipt.v1.schema.json",
        "commit_receipt.v1.schema.json",
        "commit_receipt.v2.schema.json",
        "review_receipt.v1.schema.json",
        "verification_summary.v1.schema.json",
    }

    def test_schema_files_exist(self):
        for name in self.EXPECTED_SCHEMAS:
            path = SCHEMAS / name
            self.assertTrue(path.exists(), f"Missing schema: {name}")

    def test_schema_files_parse_as_json(self):
        for name in self.EXPECTED_SCHEMAS:
            path = SCHEMAS / name
            if not path.exists():
                continue
            with self.subTest(schema=name):
                data = json.loads(path.read_text("utf-8"))
                self.assertIn("$schema", data)
                self.assertIn("$id", data)

    def test_enterprise_profile_schema_requires_all_12_rules(self):
        data = json.loads(
            (SCHEMAS / "enterprise_profile.v1.schema.json").read_text("utf-8")
        )
        ruleset = data["$defs"]["RuleSet"]
        required = set(ruleset["required"])
        expected = {f"EPB-{i:03d}" for i in range(1, 13)}
        self.assertEqual(required, expected)

    def test_decision_receipt_schema_structure(self):
        data = json.loads(
            (SCHEMAS / "decision_receipt.v1.schema.json").read_text("utf-8")
        )
        self.assertEqual(data["properties"]["type"]["const"], "aiir.decision_receipt")
        self.assertEqual(
            data["properties"]["schema"]["const"], "aiir/decision_receipt.v1"
        )
        # Must have decision, subject, policy as required
        for key in ("decision", "subject", "policy"):
            self.assertIn(key, data["required"])
        # Decision result must be enum of PASS/FAIL/SKIP
        results = data["properties"]["decision"]["properties"]["result"]["enum"]
        self.assertEqual(sorted(results), ["FAIL", "PASS", "SKIP"])


# ═══════════════════════════════════════════════════════════════════════
#  2. Doc ↔ Schema cross-reference parity
# ═══════════════════════════════════════════════════════════════════════

class TestDocSchemaParity(unittest.TestCase):
    """Rule IDs in the doc must match the schema, and vice versa."""

    def setUp(self):
        self.doc_text = (DOCS / "enterprise-profile-v1.md").read_text("utf-8")
        self.schema = json.loads(
            (SCHEMAS / "enterprise_profile.v1.schema.json").read_text("utf-8")
        )
        # Only match rule IDs in rule definition headings (#### Rule EPB-NNN),
        # not future-work prose references like "EPB-013".
        self.doc_rules = set(re.findall(r"####\s+Rule\s+(EPB-\d{3})", self.doc_text))
        self.schema_rules = set(
            self.schema["$defs"]["RuleSet"]["required"]
        )

    def test_doc_rules_subset_of_schema(self):
        """No rule mentioned in the doc is missing from the schema."""
        missing = self.doc_rules - self.schema_rules
        self.assertFalse(missing, f"Doc mentions rules not in schema: {missing}")

    def test_schema_rules_subset_of_doc(self):
        """No rule required by the schema is missing from the doc."""
        missing = self.schema_rules - self.doc_rules
        self.assertFalse(missing, f"Schema requires rules not in doc: {missing}")

    def test_doc_links_to_schema_file(self):
        """The doc must reference the schema filename."""
        self.assertIn(
            "enterprise_profile.v1.schema.json",
            self.doc_text,
        )


# ═══════════════════════════════════════════════════════════════════════
#  3. Conformance manifest includes new schemas
# ═══════════════════════════════════════════════════════════════════════

class TestConformanceManifest(unittest.TestCase):
    """The conformance manifest must register all published schemas."""

    def setUp(self):
        self.manifest = json.loads(
            (SCHEMAS / "conformance-manifest.json").read_text("utf-8")
        )
        self.registered_files = {
            s["file"] for s in self.manifest["schemas"]
        }

    def test_enterprise_profile_registered(self):
        self.assertIn(
            "schemas/enterprise_profile.v1.schema.json",
            self.registered_files,
        )

    def test_decision_receipt_registered(self):
        self.assertIn(
            "schemas/decision_receipt.v1.schema.json",
            self.registered_files,
        )

    def test_all_schema_files_on_disk_are_registered(self):
        """Every .schema.json file in schemas/ should appear in the manifest."""
        on_disk = {
            f"schemas/{p.name}"
            for p in SCHEMAS.glob("*.schema.json")
        }
        unregistered = on_disk - self.registered_files
        # Exclude receipt.cddl and conformance-manifest.json (they aren't schemas in the manifest sense)
        self.assertFalse(
            unregistered,
            f"Schema files on disk but not in conformance manifest: {unregistered}",
        )


# ═══════════════════════════════════════════════════════════════════════
#  4. Validator — schema path
# ═══════════════════════════════════════════════════════════════════════

class TestValidateProfileSchema(unittest.TestCase):
    """Test the lightweight schema validator in validate_profile.py."""

    def setUp(self):
        # Import from scripts — add to sys.path if needed
        import sys

        scripts_dir = str(SCRIPTS)
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        from validate_profile import validate_profile_schema

        self.validate = validate_profile_schema

    def test_valid_profile_passes(self):
        errors = self.validate(_minimal_profile())
        self.assertEqual(errors, [])

    def test_wrong_profile_id(self):
        p = _minimal_profile()
        p["profile"] = "wrong"
        errors = self.validate(p)
        self.assertTrue(any("profile" in e for e in errors))

    def test_bad_version(self):
        p = _minimal_profile()
        p["version"] = "abc"
        errors = self.validate(p)
        self.assertTrue(any("version" in e.lower() or "semver" in e.lower() for e in errors))

    def test_missing_rule(self):
        p = _minimal_profile()
        del p["rules"]["EPB-007"]
        errors = self.validate(p)
        self.assertTrue(any("EPB-007" in e for e in errors))

    def test_invalid_trust_tier(self):
        p = _minimal_profile()
        p["rules"]["EPB-004"]["min_trust_tier"] = 99
        errors = self.validate(p)
        self.assertTrue(any("EPB-004" in e for e in errors))

    def test_coverage_percent_out_of_range(self):
        p = _minimal_profile()
        p["rules"]["EPB-006"]["min_coverage_percent"] = 200
        errors = self.validate(p)
        self.assertTrue(any("EPB-006" in e for e in errors))

    def test_ai_cap_out_of_range(self):
        p = _minimal_profile()
        p["rules"]["EPB-007"]["max_ai_percent"] = -1
        errors = self.validate(p)
        self.assertTrue(any("EPB-007" in e for e in errors))

    def test_bad_policy_digest(self):
        p = _minimal_profile()
        p["rules"]["EPB-011"]["expected_policy_digest"] = "not-hex"
        errors = self.validate(p)
        self.assertTrue(any("EPB-011" in e for e in errors))

    def test_empty_trusted_verifiers(self):
        p = _minimal_profile()
        p["rules"]["EPB-012"]["trusted_verifiers"] = []
        errors = self.validate(p)
        self.assertTrue(any("EPB-012" in e for e in errors))

    def test_disabled_rules_skip_param_validation(self):
        """When a rule is disabled, its parameters aren't checked."""
        p = _minimal_profile(enabled=False)
        # Remove optional params — should still pass since rules are disabled
        del p["rules"]["EPB-011"]["expected_policy_digest"]
        del p["rules"]["EPB-012"]["trusted_verifiers"]
        errors = self.validate(p)
        self.assertEqual(errors, [])


# ═══════════════════════════════════════════════════════════════════════
#  5. Validator — rule evaluators
# ═══════════════════════════════════════════════════════════════════════

class TestRuleEvaluators(unittest.TestCase):
    """Test individual EPB rule evaluators."""

    def setUp(self):
        import sys

        scripts_dir = str(SCRIPTS)
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        import validate_profile as vp

        self.vp = vp

    # ── EPB-001: Commit receipt schema ───────────────────────────────
    def test_epb001_pass(self):
        r = self.vp.evaluate_epb001([_minimal_commit_receipt()], True)
        self.assertEqual(r["result"], "PASS")

    def test_epb001_fail_bad_type(self):
        cr = _minimal_commit_receipt()
        cr["type"] = "wrong"
        r = self.vp.evaluate_epb001([cr], True)
        self.assertEqual(r["result"], "FAIL")

    def test_epb001_skip_disabled(self):
        r = self.vp.evaluate_epb001([], False)
        self.assertEqual(r["result"], "SKIP")

    # ── EPB-002: Review receipt schema ───────────────────────────────
    def test_epb002_pass(self):
        r = self.vp.evaluate_epb002([_minimal_review_receipt()], True)
        self.assertEqual(r["result"], "PASS")

    def test_epb002_fail_bad_outcome(self):
        rr = _minimal_review_receipt()
        rr["review_outcome"] = "invalid"
        r = self.vp.evaluate_epb002([rr], True)
        self.assertEqual(r["result"], "FAIL")

    # ── EPB-003: Content hash integrity ──────────────────────────────
    def test_epb003_pass(self):
        cr = _minimal_commit_receipt()
        r = self.vp.evaluate_epb003([cr], True)
        self.assertEqual(r["result"], "PASS")

    def test_epb003_fail_tampered_hash(self):
        cr = _minimal_commit_receipt()
        cr["content_hash"] = "sha256:" + "0" * 64
        r = self.vp.evaluate_epb003([cr], True)
        self.assertEqual(r["result"], "FAIL")

    # ── EPB-006: Receipt coverage ────────────────────────────────────
    def test_epb006_pass_full_coverage(self):
        sha = "a" * 40
        cr = _minimal_commit_receipt(sha=sha)
        r = self.vp.evaluate_epb006([sha], [cr], True)
        self.assertEqual(r["result"], "PASS")

    def test_epb006_fail_missing_coverage(self):
        sha1 = "a" * 40
        sha2 = "b" * 40
        cr = _minimal_commit_receipt(sha=sha1)
        r = self.vp.evaluate_epb006([sha1, sha2], [cr], True, 100)
        self.assertEqual(r["result"], "FAIL")

    def test_epb006_pass_partial_coverage_with_low_threshold(self):
        sha1 = "a" * 40
        sha2 = "b" * 40
        cr = _minimal_commit_receipt(sha=sha1)
        r = self.vp.evaluate_epb006([sha1, sha2], [cr], True, 50)
        self.assertEqual(r["result"], "PASS")

    # ── EPB-007: AI authorship cap ───────────────────────────────────
    def test_epb007_pass_under_cap(self):
        cr1 = _minimal_commit_receipt(sha="a" * 40, is_ai=False)
        cr2 = _minimal_commit_receipt(sha="b" * 40, is_ai=True)
        r = self.vp.evaluate_epb007([cr1, cr2], True, 50)
        self.assertEqual(r["result"], "PASS")

    def test_epb007_fail_over_cap(self):
        cr1 = _minimal_commit_receipt(sha="a" * 40, is_ai=True)
        cr2 = _minimal_commit_receipt(sha="b" * 40, is_ai=True)
        r = self.vp.evaluate_epb007([cr1, cr2], True, 50)
        self.assertEqual(r["result"], "FAIL")

    # ── EPB-009: Human review for AI changes ─────────────────────────
    def test_epb009_pass_ai_with_review(self):
        sha = "a" * 40
        cr = _minimal_commit_receipt(sha=sha, is_ai=True)
        rr = _minimal_review_receipt(
            commit_sha=sha,
            outcome="approved",
            reviewer_email="reviewer@other.com",
        )
        r = self.vp.evaluate_epb009([cr], [rr], True)
        self.assertEqual(r["result"], "PASS")

    def test_epb009_fail_ai_without_review(self):
        sha = "a" * 40
        cr = _minimal_commit_receipt(sha=sha, is_ai=True)
        r = self.vp.evaluate_epb009([cr], [], True)
        self.assertEqual(r["result"], "FAIL")

    def test_epb009_fail_self_review(self):
        """Author reviewing their own AI-assisted commit must FAIL."""
        sha = "a" * 40
        cr = _minimal_commit_receipt(sha=sha, is_ai=True)
        rr = _minimal_review_receipt(
            commit_sha=sha,
            outcome="approved",
            reviewer_email="test@example.com",  # Same as commit author
        )
        r = self.vp.evaluate_epb009([cr], [rr], True)
        self.assertEqual(r["result"], "FAIL")

    # ── EPB-010: Bot commit provenance ───────────────────────────────
    def test_epb010_pass_no_bots(self):
        r = self.vp.evaluate_epb010([_minimal_commit_receipt()], True)
        self.assertEqual(r["result"], "PASS")

    # ── EPB-011: Policy digest binding ───────────────────────────────
    def test_epb011_pass(self):
        digest = "abc123" + "0" * 58
        vsa = {"policy": {"digest": {"sha256": digest}}}
        r = self.vp.evaluate_epb011(vsa, True, digest)
        self.assertEqual(r["result"], "PASS")

    def test_epb011_fail_mismatch(self):
        vsa = {"policy": {"digest": {"sha256": "a" * 64}}}
        r = self.vp.evaluate_epb011(vsa, True, "b" * 64)
        self.assertEqual(r["result"], "FAIL")

    # ── EPB-012: Verifier identity ───────────────────────────────────
    def test_epb012_pass(self):
        verifier = "https://example.com/verifier"
        vsa = {
            "verifier": {"id": verifier},
            "verificationResult": "PASSED",
        }
        r = self.vp.evaluate_epb012(vsa, True, [verifier])
        self.assertEqual(r["result"], "PASS")

    def test_epb012_fail_untrusted(self):
        vsa = {
            "verifier": {"id": "https://untrusted.com"},
            "verificationResult": "PASSED",
        }
        r = self.vp.evaluate_epb012(vsa, True, ["https://example.com/verifier"])
        self.assertEqual(r["result"], "FAIL")


# ═══════════════════════════════════════════════════════════════════════
#  6. Full profile evaluation
# ═══════════════════════════════════════════════════════════════════════

class TestFullEvaluation(unittest.TestCase):
    """End-to-end profile evaluation with the validator."""

    def setUp(self):
        import sys

        scripts_dir = str(SCRIPTS)
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        from validate_profile import evaluate_profile

        self.evaluate = evaluate_profile

    def test_all_enabled_happy_path(self):
        """A profile with valid receipts and VSA should have no FAILs."""
        sha_ai = "a" * 40
        sha_human = "b" * 40
        cr_ai = _minimal_commit_receipt(sha=sha_ai, is_ai=True)
        cr_human = _minimal_commit_receipt(sha=sha_human, is_ai=False)
        rr = _minimal_review_receipt(
            commit_sha=sha_ai, outcome="approved", reviewer_email="r@other.com"
        )
        digest = "a" * 64
        vsa = {
            "evaluation": {"invalidReceipts": 0, "policyViolations": 0},
            "policy": {"digest": {"sha256": digest}},
            "verifier": {"id": "https://v.example.com"},
            "verificationResult": "PASSED",
        }
        p = _minimal_profile()
        p["rules"]["EPB-011"]["expected_policy_digest"] = digest
        p["rules"]["EPB-012"]["trusted_verifiers"] = ["https://v.example.com"]
        results = self.evaluate(
            p,
            commit_receipts=[cr_ai, cr_human],
            review_receipts=[rr],
            commit_shas=[sha_ai, sha_human],
            vsa=vsa,
        )
        fails = [r for r in results if r["result"] == "FAIL"]
        self.assertEqual(fails, [], f"Unexpected failures: {fails}")

    def test_all_disabled(self):
        """All rules disabled → all SKIP, no FAIL."""
        p = _minimal_profile(enabled=False)
        results = self.evaluate(p)
        for r in results:
            self.assertIn(
                r["result"],
                ("SKIP",),
                f"{r['rule_id']} should be SKIP but got {r['result']}",
            )

    def test_schema_failure_short_circuits(self):
        """If EPB-001 fails, all downstream rules are FAIL (short-circuit)."""
        p = _minimal_profile()
        bad_cr = _minimal_commit_receipt()
        bad_cr["type"] = "wrong"
        results = self.evaluate(p, commit_receipts=[bad_cr])
        r001 = results[0]
        self.assertEqual(r001["result"], "FAIL")
        # Everything after 001/002 should be FAIL (short-circuited)
        for r in results[2:]:
            self.assertEqual(
                r["result"],
                "FAIL",
                f"{r['rule_id']} should be short-circuit FAIL",
            )


# ═══════════════════════════════════════════════════════════════════════
#  7. CLI entry point
# ═══════════════════════════════════════════════════════════════════════

class TestCLI(unittest.TestCase):
    """Test the CLI interface of validate_profile.py."""

    def setUp(self):
        import sys
        import tempfile

        scripts_dir = str(SCRIPTS)
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        from validate_profile import main

        self.main = main
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_help_flag(self):
        rc = self.main(["--help"])
        self.assertEqual(rc, 0)

    def test_valid_profile_schema_only(self):
        path = self.tmpdir / "profile.json"
        path.write_text(json.dumps(_minimal_profile()), "utf-8")
        rc = self.main([str(path)])
        self.assertEqual(rc, 0)

    def test_invalid_profile_fails(self):
        path = self.tmpdir / "bad.json"
        path.write_text(json.dumps({"profile": "wrong"}), "utf-8")
        rc = self.main([str(path)])
        self.assertEqual(rc, 1)

    def test_file_not_found(self):
        rc = self.main(["/nonexistent/profile.json"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
